# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""VPC Service Controls Coverage (v17.1): is a stolen token stopped at Google's APIs?

A bearer token taken from a workload can be replayed from anywhere unless the
project sits inside an enforced VPC Service Controls perimeter that restricts
the services the token would be used against — the credential and data APIs
first (``REPLAY_SERVICES``). A perimeter does not protect a Kubernetes API
endpoint; *GKE Control Plane Exposure* covers that.

The perimeters come from the Access Context Manager API: the access policies
of the organization the scanned scope belongs to (``accessPolicies.list``,
scoped policies included), then each policy's ``servicePerimeters.list`` — two
permissions ``roles/iam.securityReviewer`` carries. The scanned projects come
from one resource search, which also names the organization for a folder or
project scan. (Asset Inventory's ``ACCESS_POLICY`` content type was tried
first: it lagged behind new policies by more than the scan could wait.)

Rows: no perimeter in the organization; projects outside every enforced regular
perimeter; enforced perimeters that leave replay services unrestricted;
dry-run-only perimeters. *Investigation Recommended* throughout — a perimeter
is an architectural decision — with an all-clear row when every scanned project
is covered.
"""
import logging

from app.config import SCOPES
from app.services import gcp

VPC_SC_CHECK = "VPC Service Controls Coverage"
PROJECT_ASSET = "cloudresourcemanager.googleapis.com/Project"
ACM_API = "accesscontextmanager.googleapis.com"
REPLAY_SERVICES = ("iamcredentials.googleapis.com", "storage.googleapis.com", "secretmanager.googleapis.com", "container.googleapis.com",
                   "sqladmin.googleapis.com", "compute.googleapis.com")


def perimeter_facts(perimeter):
    """``{"name", "title", "regular", "enforced_resources", "restricted", "dry_run_resources"}`` of a ``ServicePerimeter``
    as the API returns it: ``status`` is the enforced configuration, ``spec`` the dry-run one when
    ``useExplicitDryRunSpec`` is set."""
    if not perimeter:
        return None
    status, spec = perimeter.get("status") or {}, perimeter.get("spec") or {}
    kind = perimeter.get("perimeterType") or "PERIMETER_TYPE_REGULAR"
    name = (perimeter.get("name") or "").rsplit("/", 1)[-1]
    return {
        "name": name,
        "title": perimeter.get("title") or name,
        "regular": kind == "PERIMETER_TYPE_REGULAR",
        "enforced_resources": {str(r) for r in status.get("resources") or []},
        "restricted": {str(s) for s in status.get("restrictedServices") or []},
        "dry_run_resources": {str(r) for r in spec.get("resources") or []} if perimeter.get("useExplicitDryRunSpec") else set(),
    }


def coverage_rows(projects, perimeters, organization):
    """``projects`` are ``(project_id, project_number)`` pairs; ``perimeters`` the facts of :func:`perimeter_facts`."""
    rows = []
    numbers = {f"projects/{number}": project_id for project_id, number in projects}
    enforced = [p for p in perimeters if p and p["regular"] and p["enforced_resources"]]
    if not enforced:
        rows.append({"Project": f"organizations/{organization}" if organization else "(scope)", "Perimeter": "none", "Projects": sorted(numbers.values()),
                     "Issue": f"No enforced VPC Service Controls perimeter protects the {len(numbers)} scanned projects: a token stolen from any of them "
                              f"can be replayed against Google APIs from anywhere.",
                     "Fix": "gcloud access-context-manager perimeters create <name> --title=<title> --resources=projects/<number>,... "
                            f"--restricted-services={','.join(REPLAY_SERVICES)} --policy=<policy>"})
        return rows
    covered = {}
    for perimeter in enforced:
        for resource in perimeter["enforced_resources"]:
            if resource in numbers:
                covered.setdefault(numbers[resource], []).append(perimeter)
    outside = sorted(project_id for project_id in numbers.values() if project_id not in covered)
    if outside:
        rows.append({"Project": "(outside)", "Perimeter": "none", "Projects": outside,
                     "Issue": f"{len(outside)} of {len(numbers)} scanned projects are outside every enforced perimeter.",
                     "Fix": "gcloud access-context-manager perimeters update <name> --add-resources=projects/<number> --policy=<policy>"})
    for perimeter in enforced:
        missing = [service for service in REPLAY_SERVICES if service not in perimeter["restricted"]]
        inside = sorted(project_id for project_id, resource in ((pid, f"projects/{num}") for pid, num in projects) if resource in perimeter["enforced_resources"])
        if missing and inside:
            rows.append({"Project": "(inside)", "Perimeter": perimeter["title"], "Projects": inside,
                         "Issue": f"Restricts {len(perimeter['restricted'])} services but not {', '.join(missing)}.",
                         "Fix": f"gcloud access-context-manager perimeters update {perimeter['name']} --add-restricted-services={','.join(missing)} --policy=<policy>"})
    for perimeter in perimeters:
        if perimeter and perimeter["regular"] and not perimeter["enforced_resources"] and perimeter["dry_run_resources"]:
            inside = sorted(numbers[r] for r in perimeter["dry_run_resources"] if r in numbers)
            if inside:
                rows.append({"Project": "(dry run)", "Perimeter": perimeter["title"], "Projects": inside,
                             "Issue": "Dry-run perimeter only: violations are logged, nothing is blocked.",
                             "Fix": f"gcloud access-context-manager perimeters dry-run enforce {perimeter['name']} --policy=<policy>"})
    return rows


def list_perimeters(service, organization):
    """Every service perimeter of every access policy of ``organization`` (the organization-level policy and the scoped ones)."""
    perimeters = []
    policies = service.accessPolicies()
    request = policies.list(parent=f"organizations/{organization}")
    while request is not None:
        response = request.execute()
        for policy in response.get("accessPolicies", []):
            inner = policies.servicePerimeters().list(parent=policy["name"])
            while inner is not None:
                page = inner.execute()
                perimeters.extend(page.get("servicePerimeters", []))
                inner = policies.servicePerimeters().list_next(previous_request=inner, previous_response=page)
        request = policies.list_next(previous_request=request, previous_response=response)
    return perimeters


def check_vpc_sc_coverage(scope, scope_id, job_id, *, sink):
    """The scanned projects' VPC Service Controls coverage (v17.1; scope-level)."""
    print(f"🧱 [{job_id}] Checking {VPC_SC_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        found = list(asset_client.search_all_resources(request={"scope": parent, "asset_types": [PROJECT_ASSET], "query": "state:ACTIVE"}))
        projects = [((getattr(r, "name", "") or "").rsplit("/", 1)[-1], (getattr(r, "project", "") or "").split("/", 1)[-1]) for r in found]
        organization = scope_id if scope == "organization" else ""
        if not organization:
            for result in found:
                org = getattr(result, "organization", "") or ""
                if org:
                    organization = org.split("/", 1)[-1]
                    break
        perimeters = []
        if organization:
            service = gcp.api_build("accesscontextmanager", "v1", credentials=credentials)
            perimeters = [perimeter_facts(p) for p in list_perimeters(service, organization)]
    except Exception as e:
        logging.error(f"[{job_id}] {VPC_SC_CHECK}: could not read the perimeters for {parent}: {e}")
        sink.write_finding(job_id, VPC_SC_CHECK.replace(" ", "_"), {"Check": VPC_SC_CHECK, "Status": "Error", "Finding": [
            {"Error": f"Could not read the access policies ({ACM_API} must be enabled in the project CloudGauge runs in). Details: {e}"}]})
        return
    if not organization:
        sink.write_finding(job_id, VPC_SC_CHECK.replace(" ", "_"), {"Check": VPC_SC_CHECK, "Status": "Informational", "Finding": [
            {"Status": "The scanned projects' organization could not be determined, so their perimeters were not read."}]})
        return
    rows = coverage_rows(projects, perimeters, organization)
    if rows:
        result = {"Check": VPC_SC_CHECK, "Finding": rows, "Status": "Investigation Recommended"}
    else:
        result = {"Check": VPC_SC_CHECK, "Status": "Compliant", "Finding": [
            {"Status": f"Every scanned project ({len(projects)}) is inside an enforced perimeter that restricts the token-replay services."}]}
    sink.write_finding(job_id, VPC_SC_CHECK.replace(" ", "_"), result)
