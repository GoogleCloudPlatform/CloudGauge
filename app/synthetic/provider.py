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
"""The synthetic Google Cloud provider: answers every data-plane API the checks
call from a :class:`~app.synthetic.world.SyntheticOrg`, with simulated latency,
optional 429s, and call metrics.

Installed through ``app.services.gcp.install_provider``. It stands in for:

- Discovery clients (``gcp.api_build``): Resource Manager, Compute, IAM, SQL
  Admin, GKE, Recommender (REST), Monitoring, Logging, SCC, Essential Contacts,
  Advisory Notifications and Org Policy calls. Unknown methods answer ``{}`` and
  are counted, so a new check degrades to "nothing found" instead of failing.
  The Cloud Run Admin API (``run``) is passed through to the real library: it
  is infrastructure (worker URL discovery), not scan data.
- Cloud Asset Inventory, Recommender (gRPC), OS Config, per-project Storage and
  the plain HTTP GETs: the best-practices CSV and the Service Health events of a
  project (``servicehealth.googleapis.com/v1/projects/{id}/locations/global/events``).

Every API call goes through :meth:`SyntheticGcp.call`, which records it,
raises for denied projects or an injected 429, then sleeps for a log-normal
latency around ``latency_ms`` (scaled per API, and per page for list calls).
The same request always gets the same data; only latency and injected errors
are random.
"""
import json
import logging
import math
import random
import re
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import google.auth
import google.auth.exceptions
import httplib2
from google.api_core import exceptions as core_exceptions
from google.cloud import recommender_v1
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from app.checks.cost import COST_RECOMMENDERS
from app.checks.network import NETWORK_INSIGHT_TYPES
from app.synthetic.world import (ADVISORY_TYPES, BEST_PRACTICES_CSV, GKE_CHANNEL_MINORS, GKE_MINORS, GKE_VERSIONS, HOST_PROJECT,
                                 INCIDENTS, ORG_ADVISORIES, ORG_IAM_RECOMMENDATION, PROJECT_ADVISORY, QUOTA_METRICS, REGIONS,
                                 SyntheticOrg, gke_version)

# Median latency of each API relative to ``latency_ms``.
API_LATENCY_SCALE = {
    "cloudresourcemanager": 0.8, "compute": 1.0, "iam": 1.0, "sqladmin": 1.2, "container": 1.5,
    "recommender": 1.6, "monitoring": 1.2, "logging": 1.0, "securitycenter": 1.0, "essentialcontacts": 1.0,
    "asset": 2.0, "osconfig": 0.8, "storage": 0.8, "http": 1.0, "servicehealth": 1.2, "advisorynotifications": 1.0,
    "accesscontextmanager": 1.0, "bigquery": 2.5, "vpcaccess": 1.0,  # v18.8
}
LATENCY_SIGMA = 0.45  # log-normal spread: p95 is about 2x the median
PASSTHROUGH_SERVICES = (("run", "v1"),)  # infrastructure APIs the synthetic provider never fakes (v18.6: Cloud Run v2 is faked for the serverless checks)
PAGE_SIZE = 100
SYNTHETIC_CUSTOM_ROLE = "deployer"  # v18.7: the project-level custom role the world draws (with or without IAM powers, retired or not)
SYNTHETIC_EXPORT_TABLE = "gcp_billing_export_v1_SYNTH00_000000_000000"  # v18.8: the one standard export table of the synthetic billing dataset
COST_RECOMMENDER_IDS = {rec_id: check for check, (rec_id, _) in COST_RECOMMENDERS.items()}
NETWORK_INSIGHT_IDS = {insight_id: check for check, insight_id in NETWORK_INSIGHT_TYPES.items()}
UNATTENDED_RECOMMENDER = "google.resourcemanager.projectUtilization.Recommender"
RECENT_CHANGE_INSIGHT = "google.cloud.RecentChangeInsight"
# v17
IAM_RECOMMENDER = "google.iam.policy.Recommender"
QUOTA_RECOMMENDER = "google.resourcemanager.serviceLimit.Recommender"
MACHINE_TYPE_URL = "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/machineTypes/{machine_type}"


class CallMetrics:
    """Thread-safe counters for the synthetic API calls."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.calls = Counter()  # (api, method) -> count
            self.errors = Counter()  # (api, status) -> count
            self.pages = 0
            self.slept_seconds = 0.0
            self.in_flight = 0
            self.max_in_flight = 0
            self.started_at = time.monotonic()

    def start(self, api, method, pages):
        with self._lock:
            self.calls[(api, method)] += 1
            self.pages += pages
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)

    def finish(self, slept):
        with self._lock:
            self.in_flight -= 1
            self.slept_seconds += slept

    def error(self, api, status):
        with self._lock:
            self.errors[(api, status)] += 1

    def snapshot(self):
        """A plain-dict summary: totals, per-API and per-method counts, errors, concurrency."""
        with self._lock:
            by_api = Counter()
            for (api, _), count in self.calls.items():
                by_api[api] += count
            return {
                "total_calls": sum(self.calls.values()),
                "total_pages": self.pages,
                "by_api": dict(by_api.most_common()),
                "by_method": {f"{api}.{method}": count for (api, method), count in self.calls.most_common()},
                "errors": {f"{api}:{status}": count for (api, status), count in self.errors.most_common()},
                "simulated_wait_seconds": round(self.slept_seconds, 3),
                "max_in_flight": self.max_in_flight,
                "elapsed_seconds": round(time.monotonic() - self.started_at, 1),
            }


class SyntheticCredentials:
    """Stands in for ADC. Never sent anywhere: every API that would use it is synthetic."""

    token = "synthetic-access-token"

    def refresh(self, request):
        pass


def _http_error(status, message, uri="https://synthetic.googleapis.com/"):
    content = json.dumps({"error": {"code": status, "message": message, "status": {403: "PERMISSION_DENIED", 404: "NOT_FOUND", 429: "RESOURCE_EXHAUSTED"}.get(status, "ERROR")}}).encode()
    return HttpError(httplib2.Response({"status": status, "reason": message}), content, uri=uri)


def _grpc_error(status, message):
    if status == 403:
        return core_exceptions.PermissionDenied(message)
    if status == 404:
        return core_exceptions.NotFound(message)
    if status == 429:
        return core_exceptions.ResourceExhausted(message)
    return core_exceptions.GoogleAPICallError(message)


def _project_of(resource_name):
    """The project ID in ``projects/<id>/...`` or ``//.../projects/<id>/...``, else ``None``."""
    parts = resource_name.split("/")
    return parts[parts.index("projects") + 1] if "projects" in parts else None


def _iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class SyntheticGcp:
    """The provider installed by the synthetic profile. See the module docstring."""

    name = "synthetic"

    def __init__(self, n_projects, seed=42, latency_ms=150.0, error_rate=0.0, denied_fraction=0.02):
        self.world = SyntheticOrg(n_projects, seed=seed, denied_fraction=denied_fraction)
        self.latency_ms = float(latency_ms)
        self.error_rate = float(error_rate)
        self.metrics = CallMetrics()
        self._random = random.Random(seed)  # latency and injected errors; data never depends on it
        self._unknown = set()
        self._credentials = None
        self._credentials_lock = threading.Lock()

    def describe(self):
        return {"projects": self.world.n_projects, "seed": self.world.seed, "latency_ms": self.latency_ms,
                "error_rate": self.error_rate, "denied_fraction": self.world.denied_fraction}

    # --- the one place every call goes through ---

    def call(self, api, method, project_id=None, pages=1, style="grpc"):
        """Records the call, raises injected errors, then waits the simulated latency."""
        self.metrics.start(api, method, pages)
        slept = 0.0
        try:
            if project_id is not None:
                profile = self.world.project(project_id)
                if profile is None:
                    self.metrics.error(api, 404)
                    raise self._error(style, 404, f"Project {project_id} not found")
                if profile.denied:
                    self.metrics.error(api, 403)
                    raise self._error(style, 403, f"Permission denied on project {project_id} (synthetic)")
            if self.error_rate and self._random.random() < self.error_rate:
                self.metrics.error(api, 429)
                raise self._error(style, 429, f"Quota exceeded for {api}.{method} (synthetic)")
            if self.latency_ms > 0:
                median = self.latency_ms / 1000.0 * API_LATENCY_SCALE.get(api, 1.0)
                slept = sum(self._random.lognormvariate(math.log(median), LATENCY_SIGMA) for _ in range(pages))
                time.sleep(slept)
        finally:
            self.metrics.finish(slept)

    @staticmethod
    def _error(style, status, message):
        return _http_error(status, message) if style == "http" else _grpc_error(status, message)

    # --- gcp provider interface ---

    def auth_default(self, scopes=None, **kwargs):
        """Real Application Default Credentials when they exist, synthetic ones otherwise.

        The provider fakes *data*, not identity: the calls that pass through
        (Cloud Run Admin for the worker URL, IAM signing for the CSV link) need
        real credentials on a deployed synthetic revision. Offline (the harness,
        tests) nothing consumes them, so a stand-in is enough. Resolved once:
        the checks ask for credentials per project, and ``google.auth.default``
        probes the environment every time.
        """
        if self._credentials is None:
            with self._credentials_lock:
                if self._credentials is None:
                    try:
                        self._credentials, _ = google.auth.default(scopes=scopes, **kwargs)
                    except google.auth.exceptions.DefaultCredentialsError:
                        logging.info("Synthetic provider: no Application Default Credentials; using synthetic credentials")
                        self._credentials = SyntheticCredentials()
        return self._credentials, HOST_PROJECT

    def api_build(self, serviceName, version, **kwargs):
        if (serviceName, version) in PASSTHROUGH_SERVICES:
            return discovery.build(serviceName, version, **kwargs)
        return _DiscoveryStub(self, serviceName, version)

    def project_storage_client(self, project_id):
        return _StorageStub(self, project_id)

    def asset_client(self, credentials=None):
        return _AssetStub(self)

    def recommender_client(self, credentials=None):
        return _RecommenderStub(self)

    def osconfig_client(self):
        return _OsConfigStub(self)

    def policy_table(self):
        """The synthetic organization's small policy table (v18.1: what the bundled table is in a real deployment)."""
        self.call("policy_table", "read", style="http")
        return BEST_PRACTICES_CSV

    def http_get(self, url, **kwargs):
        if "servicehealth.googleapis.com/" in url:
            return self._service_health_events(url, kwargs.get("params") or {})
        if "securitycenter.googleapis.com/v2/" in url:  # v19
            return self._scc_v2(url, kwargs.get("params") or {})
        if "securitycentermanagement.googleapis.com/v1/" in url:  # v19
            return self._scc_management(url)
        self.call("http", "GET", style="http")
        text = BEST_PRACTICES_CSV if url.lower().endswith(".csv") else "{}"
        return _HttpResponse(200, text)

    def _service_health_events(self, url, params):
        """``GET .../v1/projects/{id}/locations/global/events``: the project's view of the organization's incidents."""
        project_id = _project_of(url.split("?")[0])
        try:
            self.call("servicehealth", "events.list", project_id=project_id, style="http")
        except HttpError as e:  # a denied project or an injected 429, as requests would deliver it
            return _HttpResponse(e.resp.status, e.content.decode() if isinstance(e.content, bytes) else str(e.content))
        profile = self.world.project(project_id)
        if profile.servicehealth_disabled:
            message = (f"Service Health API has not been used in project {project_id} before or it is disabled. Enable it by visiting "
                       f"https://console.developers.google.com/apis/api/servicehealth.googleapis.com/overview?project={project_id} then retry.")
            return _HttpResponse(403, json.dumps({"error": {"code": 403, "message": message, "status": "PERMISSION_DENIED"}}))
        match = re.search(r'update_time\s*>=\s*"([^"]+)"', str(params.get("filter", "")))
        since = match.group(1) if match else ""
        events = []
        for incident_id, title, product, location, state, started, ended in INCIDENTS:
            relevance = profile.incident_relevance.get(incident_id)
            updated = _iso(ended if ended is not None else 0)
            if relevance is None or updated < since:
                continue
            events.append({
                "name": f"projects/{project_id}/locations/global/events/{incident_id}", "title": title,
                "category": "INCIDENT", "detailedCategory": "CONFIRMED_INCIDENT", "state": state,
                "detailedState": "CONFIRMED" if state == "ACTIVE" else "RESOLVED", "relevance": relevance,
                "eventImpacts": [{"product": {"productName": product, "id": product.lower().replace(" ", "-")},
                                  "location": {"locationName": location}}],
                "updateTime": updated, "startTime": _iso(started), **({"endTime": _iso(ended)} if ended is not None else {}),
            })
        return _HttpResponse(200, json.dumps({"events": events}))

    # --- Discovery API handlers: "service.resource.method" -> response dict ---

    def dispatch(self, service, path, kwargs):
        method = ".".join(path)
        handler = getattr(self, "_h_" + f"{service}.{method}".replace(".", "_"), None)
        project_id = kwargs.get("project") or kwargs.get("projectId")
        if project_id is None:
            for key in ("name", "parent"):  # projects/<id>/..., as in GKE's parent=projects/<id>/locations/-
                value = str(kwargs.get(key, ""))
                if value.startswith("projects/"):
                    project_id = _project_of(value)
                    break
        if project_id is None and "resource" in kwargs and not str(kwargs["resource"]).count("/"):
            project_id = kwargs["resource"]
        if project_id is not None and str(project_id).isdigit():  # addressed by number (Advisory Notifications)
            project_id = self.world.project_id_for_number(project_id) or project_id
        if project_id == HOST_PROJECT:
            project_id = None
        if handler is None:
            key = f"{service}.{method}"
            if key not in self._unknown:
                self._unknown.add(key)
                logging.warning(f"Synthetic provider: no handler for {key}; answering {{}}")
            self.call(service, method + "?", project_id=project_id, style="http")
            return {}
        return handler(kwargs, project_id)

    def _h_cloudresourcemanager_projects_get(self, kw, project_id):
        self.call("cloudresourcemanager", "projects.get", style="http")
        profile = self.world.project(kw["projectId"])
        if profile is None:
            raise _http_error(404, f"Project {kw['projectId']} not found")
        return {"projectId": profile.project_id, "name": profile.display_name, "lifecycleState": "ACTIVE",
                "projectNumber": profile.project_number, "labels": dict(profile.labels)}

    def _h_cloudresourcemanager_projects_getIamPolicy(self, kw, project_id):
        self.call("cloudresourcemanager", "projects.getIamPolicy", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        policy = {"bindings": self._project_policy_bindings(profile), "etag": "synthetic"}
        if profile.data_access_logs:  # v17.1
            policy["auditConfigs"] = [{"service": "container.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]
        if profile.project_audit_configs:  # v18.1: the project turns the three Data Access log types on for every service
            policy.setdefault("auditConfigs", []).append({"service": "allServices", "auditLogConfigs": [{"logType": t} for t in ("ADMIN_READ", "DATA_READ", "DATA_WRITE")]})
        return policy

    def _project_policy_bindings(self, profile):
        """A project's IAM bindings: a reader group, the primitive bindings and (v17.1) the impersonation table's project-level
        entries, the custom roles, the privileged node account and a Google-managed service agent."""
        bindings = [{"role": "roles/viewer", "members": ["group:readers@example.com"]}]
        by_role = {}
        for role, member in profile.primitive_bindings:
            by_role.setdefault(role, []).append(member)
        bindings += [{"role": role, "members": members} for role, members in by_role.items()]
        return bindings + self._project_level_impersonation(profile) + self._posture_bindings(profile) + self._privilege_bindings(profile)

    @staticmethod
    def _privilege_bindings(profile):
        """v18.7: the bindings the folder, grant, secret and custom-role rules read — resource-wide secret roles, the holder of the project's
        custom role (``powers-held`` / ``retired-bound``), and the standing grant that duplicates the project's entitlement."""
        privileges = profile.privileges
        if privileges is None:
            return []
        by_role = {}
        for role, member in privileges.secret_roles:
            by_role.setdefault(role, []).append(member)
        if privileges.custom_role in ("powers-held", "retired-bound"):
            by_role.setdefault(f"projects/{profile.project_id}/roles/{SYNTHETIC_CUSTOM_ROLE}", []).append(f"serviceAccount:ci@{profile.project_id}.iam.gserviceaccount.com")
        if privileges.pam == "unapproved-standing":
            by_role.setdefault("roles/compute.admin", []).append("user:oncall@example.com")
        return [{"role": role, "members": members} for role, members in by_role.items()]

    @staticmethod
    def _posture_bindings(profile):
        """v18.5: the bindings the identity rules read — administrative roles on service accounts, one principal with both
        iam.serviceAccountAdmin and iam.serviceAccountUser, principals outside the organization."""
        posture = profile.posture
        if posture is None:
            return []
        by_role = {}
        for role, member in posture.admin_sa_roles + posture.external_members:
            by_role.setdefault(role, []).append(member)
        if posture.separation_member:
            by_role.setdefault("roles/iam.serviceAccountAdmin", []).append(posture.separation_member)
            by_role.setdefault("roles/iam.serviceAccountUser", []).append(posture.separation_member)
        return [{"role": role, "members": members} for role, members in by_role.items()]

    def _project_level_impersonation(self, profile):
        """v17.1: the project-level bindings of the impersonation table, the custom roles, the privileged node account."""
        extra = {}
        for level, resource, role, member in profile.impersonation_bindings:
            if level == "project":
                extra.setdefault(role, []).append(member)
        for role, member in profile.custom_role_bindings:
            extra.setdefault(role, []).append(member)
        if any(h.privileged_node_account and not h.autopilot for h in profile.gke_hardening.values()):
            extra.setdefault("roles/editor", []).append(f"serviceAccount:{profile.project_number}-compute@developer.gserviceaccount.com")
        extra.setdefault("roles/compute.serviceAgent", []).append(f"serviceAccount:service-{profile.project_number}@compute-system.iam.gserviceaccount.com")
        return [{"role": role, "members": members} for role, members in extra.items()]

    def _h_cloudresourcemanager_projects_getAncestry(self, kw, project_id):
        self.call("cloudresourcemanager", "projects.getAncestry", style="http")
        pid = kw["projectId"]
        ancestors = [{"resourceId": {"type": "project", "id": pid}}]
        profile = self.world.project(pid)
        if profile is not None:
            ancestors.append({"resourceId": {"type": "folder", "id": profile.folder_id}})
        ancestors.append({"resourceId": {"type": "organization", "id": self.world.org_id}})
        return {"ancestor": ancestors}

    def _h_cloudresourcemanager_organizations_getIamPolicy(self, kw, project_id):
        self.call("cloudresourcemanager", "organizations.getIamPolicy", style="http")
        # v18.1: a partial Data Access configuration at the organization (ADMIN_READ and DATA_WRITE for all services).
        return {"bindings": self.world.org_iam_bindings(),
                "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}, {"logType": "DATA_WRITE"}]}]}

    def _list_org_policies(self, kw, project_id):
        self.call("cloudresourcemanager", "listOrgPolicies", project_id=project_id, style="http")
        return {"policies": self.world.org_policies(kw["resource"])}

    _h_cloudresourcemanager_organizations_listOrgPolicies = _list_org_policies
    _h_cloudresourcemanager_folders_listOrgPolicies = _list_org_policies
    _h_cloudresourcemanager_projects_listOrgPolicies = _list_org_policies

    def _h_cloudresourcemanager_folders_get(self, kw, project_id):
        self.call("cloudresourcemanager", "folders.get", style="http")
        return {"name": kw["name"], "parent": f"organizations/{self.world.org_id}", "displayName": self._folder_display(kw["name"].rsplit("/", 1)[-1])}

    def _folder_display(self, folder_id):
        return f"Synthetic folder {self.world.folder_ids.index(folder_id)}" if folder_id in self.world.folder_ids else "Synthetic folder"

    def _h_cloudresourcemanager_projects_list(self, kw, project_id):
        """v3 ``projects.list``: a folder's direct children (the world has one level of folders). The folder
        scan's membership check compares them with Asset Search, and finds them the same."""
        self.call("cloudresourcemanager", "projects.list", style="http")
        parent = str(kw.get("parent", ""))
        if not parent.startswith("folders/"):
            return {}
        return {"projects": [{"name": f"projects/{p.project_number}", "parent": parent, "projectId": p.project_id,
                              "displayName": p.display_name, "state": "ACTIVE"}
                             for p in self.world.projects(parent.split("/", 1)[1])]}

    def _h_compute_instances_aggregatedList(self, kw, project_id):
        self.call("compute", "instances.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        running_only = 'RUNNING' in str(kw.get("filter", ""))
        for index, vm in enumerate(profile.vms):
            stopped = vm.name in profile.stopped_vms  # v18: a stopped VM keeps its access config, not its ephemeral address
            if stopped and running_only:
                continue
            access = [{"name": "External NAT", "type": "ONE_TO_ONE_NAT", **({} if stopped else {"natIP": "203.0.113.10"})}] if vm.external_ip else None
            instance = {
                "name": vm.name, "id": str(self._instance_id(profile, index)), "status": "TERMINATED" if stopped else "RUNNING",
                "zone": f"https://www.googleapis.com/compute/v1/projects/{project_id}/zones/{vm.zone}",
                "machineType": MACHINE_TYPE_URL.format(project=project_id, zone=vm.zone, machine_type=vm.machine_type),
                "networkInterfaces": [{"name": "nic0", "network": "vpc-main", **({"accessConfigs": access} if access else {})}],
                **self._instance_posture_fields(profile, index, vm),  # v18.5: labels, metadata, service account, Shielded settings
            }
            items.setdefault(f"zones/{vm.zone}", {"instances": []})["instances"].append(instance)
        return {"items": items}

    @staticmethod
    def _instance_id(profile, index):
        """A VM's numeric ID, as Compute Engine and the OS inventory name it."""
        return 7000000000000000000 + int(profile.project_number) * 1000 + index

    # --- v17: reservations, commitments and the capacity log ---

    def _h_compute_reservations_aggregatedList(self, kw, project_id):
        self.call("compute", "reservations.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        for i, (zone, machine_type, count, in_use) in enumerate(profile.reservations):
            items.setdefault(f"zones/{zone}", {"reservations": []})["reservations"].append({
                "name": f"reservation-{i}", "zone": f"https://www.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}", "status": "READY",
                "specificReservation": {"count": str(count), "inUseCount": str(in_use),
                                        "instanceProperties": {"machineType": machine_type}}})
        return {"items": items}

    def _h_compute_futureReservations_aggregatedList(self, kw, project_id):
        self.call("compute", "futureReservations.aggregatedList", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        if not profile.future_reservation:
            return {"items": {}}
        zone = profile.zones[0]
        return {"items": {f"zones/{zone}": {"futureReservations": [{
            "name": "future-0", "zone": zone, "status": {"procurementStatus": "APPROVED"},
            "timeWindow": {"startTime": _iso(-30), "endTime": _iso(-395)},
            "specificSkuProperties": {"totalCount": "8", "instanceProperties": {"machineType": "a2-highgpu-1g",
                                                                                 "guestAccelerators": [{"acceleratorType": "nvidia-tesla-a100", "acceleratorCount": 1}]}}}]}}}

    def _h_compute_regionCommitments_aggregatedList(self, kw, project_id):
        self.call("compute", "regionCommitments.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        for i, (region, plan, vcpus, memory_gb, days_left, auto_renew) in enumerate(profile.commitments):
            items.setdefault(f"regions/{region}", {"commitments": []})["commitments"].append({
                "name": f"commitment-{i}", "region": region, "plan": plan, "status": "ACTIVE", "autoRenew": auto_renew,
                "startTimestamp": _iso(365 - days_left), "endTimestamp": _iso(-days_left),
                "resources": [{"type": "VCPU", "amount": str(vcpus)}, {"type": "MEMORY", "amount": str(memory_gb * 1024)}]})
        return {"items": items}

    def _h_logging_entries_list(self, kw, project_id):
        """``entries.list``: the Compute Engine operations that failed for capacity or quota (v17) over one project; v19.1: the week's
        GKE control-plane and service-account Admin Activity entries under the organization, a folder or a project, by the filter."""
        body = kw.get("body") or {}
        log_filter = str(body.get("filter") or "")
        if 'resource.type="k8s_cluster"' in log_filter or "CreateServiceAccountKey" in log_filter:
            return self._detection_entries(body, log_filter)
        names = [name for name in body.get("resourceNames", []) if str(name).startswith("projects/")]
        project_id = names[0].split("/", 1)[1] if names else None
        self.call("logging", "entries.list", project_id=project_id, style="http")
        profile = self.world.project(project_id) if project_id else None
        entries = []
        for zone, machine_type, kind, days_ago, count in (profile.capacity_events if profile else ()):
            message = (f"ZONE_RESOURCE_POOL_EXHAUSTED: The zone '{zone}' does not have enough resources available to fulfill the request."
                       if kind == "stockout" else f"QUOTA_EXCEEDED: Quota 'CPUS' exceeded in region {'-'.join(zone.split('-')[:-1])}.")
            for n in range(count):
                entries.append({
                    "timestamp": _iso(days_ago + n / 24), "logName": f"projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity",
                    "resource": {"type": "gce_instance", "labels": {"project_id": project_id, "zone": zone}},
                    "protoPayload": {"methodName": "v1.compute.instances.insert", "status": {"code": 8, "message": message},
                                     "resourceName": f"projects/{project_id}/zones/{zone}/instances/vm-new-{n}",
                                     "request": {"machineType": MACHINE_TYPE_URL.format(project=project_id, zone=zone, machine_type=machine_type)}}})
        return {"entries": entries}

    def _detection_entries(self, body, log_filter):
        """v19.1: the Admin Activity entries of the scope's projects in the drawn shapes — the customer's and Google's own, which the rules leave out."""
        names = [str(n) for n in body.get("resourceNames", [])]
        scope = names[0] if names else f"organizations/{self.world.org_id}"
        project_id = scope.split("/", 1)[1] if scope.startswith("projects/") else None
        folder_id = scope.split("/", 1)[1] if scope.startswith("folders/") else None
        try:
            self.call("logging", "entries.list", project_id=project_id, style="http")
        except HttpError:
            raise
        profiles = [self.world.project(project_id)] if project_id else self.world.projects(folder_id)
        gke = 'resource.type="k8s_cluster"' in log_filter
        entries = []
        for profile in profiles:
            d, pid, number = profile.detection, profile.project_id, profile.project_number
            if d is None:
                continue
            log_name = f"projects/{pid}/logs/cloudaudit.googleapis.com%2Factivity"

            def entry(method, principal, ip, resource_name, resource_type, labels, days, request=None):
                entries.append({"timestamp": _iso(days), "logName": log_name, "resource": {"type": resource_type, "labels": {"project_id": pid, **labels}},
                                "protoPayload": {"methodName": method, "authenticationInfo": {"principalEmail": principal}, "requestMetadata": {"callerIp": ip},
                                                 "resourceName": resource_name, **({"request": request} if request else {})}})
            if gke:
                for cluster in profile.gke_clusters[:1]:
                    labels = {"cluster_name": cluster.name, "location": cluster.location}
                    for n in range(d.user_exec):
                        entry("io.k8s.core.v1.pods.exec.create", "ops@example.com", "203.0.113.7", f"core/v1/namespaces/default/pods/web-{n}/exec", "k8s_cluster", labels, 1 + n * 0.3)
                    for n in range(d.sa_exec):
                        entry("io.k8s.core.v1.pods.exec.create", f"ci@{pid}.iam.gserviceaccount.com", "198.51.100.9", "core/v1/namespaces/default/pods/api-0/exec", "k8s_cluster", labels, 2)
                    if d.admin_binding == "user":
                        entry("io.k8s.authorization.rbac.v1.clusterrolebindings.create", "ops@example.com", "10.0.0.5", "rbac.authorization.k8s.io/v1/clusterrolebindings/cg-admin", "k8s_cluster", labels, 3,
                              request={"roleRef": {"name": "cluster-admin"}})
                    elif d.admin_binding == "sa":
                        entry("io.k8s.authorization.rbac.v1.clusterrolebindings.create", f"ci@{pid}.iam.gserviceaccount.com", "198.51.100.9", "rbac.authorization.k8s.io/v1/clusterrolebindings/cg-admin", "k8s_cluster", labels, 3,
                              request={"roleRef": {"name": "cluster-admin"}})
                    if d.google_daemonset:
                        entry("io.k8s.apps.v1.daemonsets.create", f"service-project-{number}@gcp-sa-ktd-hpsa.iam.gserviceaccount.com", "127.0.0.1", "apps/v1/namespaces/kube-system/daemonsets/container-watcher", "k8s_cluster", labels, 4)
                        entry("io.k8s.authorization.rbac.v1.clusterrolebindings.patch", "system:addon-manager", "172.16.0.5", "rbac.authorization.k8s.io/v1/clusterrolebindings/system:controller", "k8s_cluster", labels, 0.5)
            else:
                for n in range(d.sa_key):
                    entry("google.iam.admin.v1.CreateServiceAccountKey", f"deployer@{pid}.iam.gserviceaccount.com", "198.51.100.20", f"projects/-/serviceAccounts/deployer@{pid}.iam.gserviceaccount.com", "service_account", {}, 1 + n)
                for n in range(d.factory_iam):
                    entry("SetIamPolicy", "project-factory@tooling.iam.gserviceaccount.com", "private", f"projects/{pid}", "project", {}, 2 + n)
                for n in range(d.google_churn):
                    entry("SetIamPolicy", "service-agent-manager@system.gserviceaccount.com", "private", f"projects/{pid}", "project", {}, n / 4)
        if not gke and not project_id and not folder_id:  # the organization's own churn (Google's)
            for n in range(3):
                entries.append({"timestamp": _iso(n), "logName": f"organizations/{self.world.org_id}/logs/cloudaudit.googleapis.com%2Factivity", "resource": {"type": "organization", "labels": {}},
                                "protoPayload": {"methodName": "google.cloud.resourcemanager.v3.Organizations.SetIamPolicy", "authenticationInfo": {"principalEmail": "latchkey-multiorg-ephemeral-iam-automation@system.gserviceaccount.com"},
                                                 "requestMetadata": {"callerIp": "private"}, "resourceName": f"organizations/{self.world.org_id}"}})
        entries.sort(key=lambda e: e["timestamp"], reverse=True)
        return {"entries": entries}

    def _h_compute_addresses_aggregatedList(self, kw, project_id):
        self.call("compute", "addresses.aggregatedList", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": {f"regions/{r}": {"addresses": [{"name": f"ip-{r}", "status": "RESERVED"}]} for r in profile.addresses_regions}}

    def _h_compute_forwardingRules_aggregatedList(self, kw, project_id):
        self.call("compute", "forwardingRules.aggregatedList", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": {f"regions/{r}": {"forwardingRules": [{"name": f"lb-{r}"}]} for r in profile.forwarding_rule_regions}}

    def _h_compute_firewalls_list(self, kw, project_id):
        self.call("compute", "firewalls.list", project_id=project_id, style="http")
        return {"items": self._firewall_rules(self.world.project(project_id))}

    @staticmethod
    def _firewall_rules(profile):
        project_id = profile.project_id
        rules = [{"name": name, "network": f"projects/{project_id}/global/networks/vpc-main", "direction": "INGRESS", "priority": 1000,
                  "sourceRanges": ["0.0.0.0/0"] if open_rule else ["10.0.0.0/8"], "disabled": disabled,
                  "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}] if open_rule else [{"IPProtocol": "tcp", "ports": ["8080"]}]}
                 for name, open_rule, disabled in profile.firewall_rules]
        # v18: the hardening pattern every network should have — a deny-all from the internet — is never a finding.
        rules.append({"name": "deny-all-ingress", "network": f"projects/{project_id}/global/networks/vpc-main", "direction": "INGRESS", "priority": 65000,
                      "sourceRanges": ["0.0.0.0/0"], "disabled": False, "denied": [{"IPProtocol": "all"}]})
        return rules

    def _h_compute_networks_list(self, kw, project_id):
        self.call("compute", "networks.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": "vpc-main", "selfLink": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/vpc-main"}]
                + ([{"name": "default", "selfLink": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/default", "autoCreateSubnetworks": True}] if profile.has_default_vpc else [])}

    def _h_compute_regions_list(self, kw, project_id):
        self.call("compute", "regions.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": region, "quotas": self._region_quotas(profile, region)} for region in REGIONS]}

    @staticmethod
    def _region_quotas(profile, region):
        hot = {metric: (usage, limit) for r, metric, usage, limit in profile.hot_quotas if r == region}
        quotas = [{"metric": m, "usage": float(hot.get(m, (3, 100))[0]), "limit": float(hot.get(m, (3, 100))[1])} for m in QUOTA_METRICS]
        quotas += [{"metric": metric, "usage": float(usage), "limit": float(limit)} for r, metric, usage, limit in profile.gpu_quota if r == region]
        quotas.append({"metric": "COMMITTED_CPUS", "usage": 64.0, "limit": 64.0})  # v18: consumed by the commitments, never a row
        return quotas

    def _h_compute_regions_get(self, kw, project_id):
        self.call("compute", "regions.get", project_id=project_id, style="http")
        profile, region = self.world.project(project_id), kw["region"]
        return {"name": region, "quotas": self._region_quotas(profile, region)}

    def _h_compute_subnetworks_list(self, kw, project_id):
        self.call("compute", "subnetworks.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": name, "region": region, "privateIpGoogleAccess": pga}
                          for name, region, pga in profile.subnets if region == kw["region"]]}

    def _h_compute_subnetworks_aggregatedList(self, kw, project_id):
        """Every subnet of the project in one call (v18.1), with ``purpose`` and ``network``; a proxy-only subnet for some projects; v18.8: the
        flow-log configuration (sampling, metadata, interval) the log-cost rules read."""
        self.call("compute", "subnetworks.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        for position, (name, region, pga) in enumerate(profile.subnets):
            items.setdefault(f"regions/{region}", {"subnetworks": []})["subnetworks"].append(
                {"name": name, "region": f"https://www.googleapis.com/compute/v1/projects/{project_id}/regions/{region}", "privateIpGoogleAccess": pga,
                 "purpose": "PRIVATE", "network": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/vpc-main",
                 **self._subnet_log_config(profile, position)})
        if profile.proxy_subnet and profile.subnets:
            region = profile.subnets[0][1]
            items.setdefault(f"regions/{region}", {"subnetworks": []})["subnetworks"].append(
                {"name": "proxy-only", "region": f"https://www.googleapis.com/compute/v1/projects/{project_id}/regions/{region}", "privateIpGoogleAccess": False,
                 "purpose": "REGIONAL_MANAGED_PROXY", "role": "ACTIVE", "network": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/vpc-main"})
        if profile.has_default_vpc and profile.subnets:
            region = profile.subnets[0][1]
            items.setdefault(f"regions/{region}", {"subnetworks": []})["subnetworks"].append(
                {"name": "default", "region": f"https://www.googleapis.com/compute/v1/projects/{project_id}/regions/{region}", "privateIpGoogleAccess": False,
                 "purpose": "PRIVATE", "network": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/default"})
        return {"items": items}

    def _h_compute_projects_get(self, kw, project_id):
        """The project's global Compute quotas (v18.1): FIREWALLS near its limit for the projects with many rules; v18.5: the common
        instance metadata the VM Hardening check reads from the API (the inventory omits ssh-keys)."""
        self.call("compute", "projects.get", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        rules = len(profile.firewall_rules) + 1
        return {"name": project_id, "quotas": [{"metric": "FIREWALLS", "usage": float(rules), "limit": 200.0},
                                               {"metric": "NETWORKS", "usage": 2.0, "limit": 15.0}, {"metric": "IMAGES", "usage": 3.0, "limit": 2000.0}],
                "commonInstanceMetadata": {"items": self._project_metadata_items(profile)}}

    @staticmethod
    def _project_metadata_items(profile):
        """v18.5: the project's common instance metadata as the Compute API (and, without ssh-keys, the inventory) shows it."""
        posture = profile.posture
        if posture is None:
            return []
        items = [{"key": "enable-oslogin", "value": "TRUE" if posture.project_oslogin else "FALSE"}]
        if posture.project_ssh_keys:
            items.append({"key": "ssh-keys", "value": "ops:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTheSyntheticWorld ops@example.com"})
        return items

    # --- v18.8: the cost levers ---

    @staticmethod
    def _subnet_log_config(profile, position):
        """``enableFlowLogs`` and ``logConfig`` of the subnet at ``position`` (flow logs from the network edge, sampling from the cost levers)."""
        edge, levers = profile.network_edge, profile.cost_levers
        on = bool(edge and position < len(edge.flow_logs) and edge.flow_logs[position])
        sampling = levers.flow_sampling[position] if levers and position < len(levers.flow_sampling) else 0.5
        verbose = bool(levers and levers.flow_verbose and sampling >= 1.0)
        config = {"enable": on, "flowSampling": sampling, "metadata": "INCLUDE_ALL_METADATA" if verbose else "EXCLUDE_ALL_METADATA",
                  "aggregationInterval": "INTERVAL_5_SEC" if verbose else "INTERVAL_5_MIN"} if on else {"enable": False}
        return {"enableFlowLogs": on, "logConfig": config}

    def _h_logging_projects_locations_buckets_list(self, kw, project_id):
        """The project's log buckets: ``_Required`` (400 days, locked), ``_Default`` at the drawn retention (v18.9: with Log Analytics where drawn),
        an optional locked audit bucket, and (v18.9) the destinations of the project's customer sink and of the first folder's aggregated sink."""
        self.call("logging", "buckets.list", project_id=project_id, style="http")
        return {"buckets": self._log_buckets(self.world.project(project_id))}

    def _log_buckets(self, profile):
        levers, observability = profile.cost_levers, profile.observability
        prefix = f"projects/{profile.project_id}/locations"
        buckets = [{"name": f"{prefix}/global/buckets/_Required", "retentionDays": 400, "locked": True, "lifecycleState": "ACTIVE"},
                   {"name": f"{prefix}/global/buckets/_Default", "retentionDays": levers.log_retention if levers else 30, "lifecycleState": "ACTIVE",
                    **({"analyticsEnabled": True} if observability and observability.analytics else {})}]
        if (levers and levers.audit_bucket) or (observability and observability.sink == "complete"):
            buckets.append({"name": f"{prefix}/asia-south1/buckets/audit", "retentionDays": 400, "locked": True, "lifecycleState": "ACTIVE"})
        if observability and observability.sink == "narrow":
            buckets.append({"name": f"{prefix}/global/buckets/audit-short", "retentionDays": 30, "lifecycleState": "ACTIVE"})
        if self._folder_sink_host(profile.folder_id) is profile:
            buckets.append({"name": f"{prefix}/global/buckets/folder-archive", "retentionDays": 400, "lifecycleState": "ACTIVE"})
        return buckets

    def _h_logging_projects_locations_buckets_get(self, kw, project_id):
        """v18.9: one bucket by name; 404 for a name the project's listing does not have."""
        self.call("logging", "buckets.get", project_id=project_id, style="http")
        name = str(kw.get("name") or "")
        bucket = next((b for b in self._log_buckets(self.world.project(project_id)) if b["name"] == name), None)
        if bucket is None:
            raise _http_error(404, f"Bucket {name} not found")
        return bucket

    def _h_logging_projects_locations_buckets_views_list(self, kw, project_id):
        """v18.9: a bucket's views — ``_AllLogs`` and ``_Default``, the latter excluding the Data Access logs unless the world opened it."""
        self.call("logging", "views.list", project_id=project_id, style="http")
        parent, observability = str(kw.get("parent") or ""), self.world.project(project_id).observability
        default_filter = "" if observability and observability.open_view else 'NOT LOG_ID("cloudaudit.googleapis.com/data_access") AND NOT LOG_ID("externalaudit.googleapis.com/data_access")'
        return {"views": [{"name": f"{parent}/views/_AllLogs"}, {"name": f"{parent}/views/_Default", "filter": default_filter}]}

    def _folder_sink_host(self, folder_id):
        """v18.9: the project whose bucket the first folder's aggregated sink writes into (its first project), or None."""
        if folder_id != self.world.folder_ids[0]:
            return None
        profiles = self.world.projects(folder_id)
        return profiles[0] if profiles else None

    def _h_logging_folders_sinks_list(self, kw, project_id):
        """v18.9: the first folder has an aggregated sink of every log into a bucket of its first project (the duplicate-routing case, and
        the _Required streams stored again); the other folders have none."""
        self.call("logging", "sinks.list", style="http")
        folder_id = str(kw.get("parent") or "").split("/", 1)[-1]
        host = self._folder_sink_host(folder_id)
        if host is None:
            return {}
        return {"sinks": [{"name": "folder-archive", "destination": f"logging.googleapis.com/projects/{host.project_id}/locations/global/buckets/folder-archive", "filter": "",
                           "includeChildren": True, "writerIdentity": f"serviceAccount:service-folder-{folder_id}@gcp-sa-logging.iam.gserviceaccount.com"}]}

    def _h_logging_projects_sinks_list(self, kw, project_id):
        """The project's sinks: ``_Required``, ``_Default`` (with a DEBUG exclusion where drawn; v18.9: disabled where drawn), one per bucket the
        world marks as a sink destination, and (v18.9) the project's customer sink in the drawn shape."""
        self.call("logging", "sinks.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        levers, observability = profile.cost_levers, profile.observability
        buckets = f"logging.googleapis.com/projects/{project_id}/locations"
        default = {"name": "_Default", "destination": f"{buckets}/global/buckets/_Default", "filter": "NOT LOG_ID(\"cloudaudit.googleapis.com/activity\")"}
        if levers and levers.debug_exclusion:
            default["exclusions"] = [{"name": "drop-debug", "filter": "severity=DEBUG"}]
        if observability and observability.default_disabled:
            default["disabled"] = True
        sinks = [{"name": "_Required", "destination": f"{buckets}/global/buckets/_Required", "filter": "LOG_ID(\"cloudaudit.googleapis.com/activity\")"}, default]
        sinks += [{"name": f"sink-{i}", "destination": f"storage.googleapis.com/{bucket}", "filter": "severity>=ERROR"} for i, bucket in enumerate(profile.sink_buckets)]
        writer = f"serviceAccount:service-{profile.project_number}@gcp-sa-logging.iam.gserviceaccount.com"
        shape = observability.sink if observability else ""
        if shape == "narrow":
            sinks.append({"name": "audit-activity", "destination": f"{buckets}/global/buckets/audit-short", "filter": 'LOG_ID("cloudaudit.googleapis.com/activity")', "writerIdentity": writer})
        elif shape == "complete":
            sinks.append({"name": "audit-archive", "destination": f"{buckets}/asia-south1/buckets/audit", "filter": 'logName:"cloudaudit.googleapis.com"', "writerIdentity": writer})
        elif shape == "topic":
            sinks.append({"name": "audit-stream", "destination": f"pubsub.googleapis.com/projects/{project_id}/topics/audit-stream", "filter": 'logName:"cloudaudit.googleapis.com"', "writerIdentity": writer})
        elif shape == "dataset-gone":
            sinks.append({"name": "audit-bq", "destination": f"bigquery.googleapis.com/projects/{project_id}/datasets/audit_gone", "filter": 'logName:"cloudaudit.googleapis.com"', "writerIdentity": writer})
        return {"sinks": sinks}

    def _h_monitoring_projects_timeSeries_list(self, kw, project_id):
        """``byte_count`` summed by severity over the window: the drawn 30-day volume split DEBUG / INFO / ERROR."""
        self.call("monitoring", "timeSeries.list", project_id=project_id, style="http")
        if "logging.googleapis.com/byte_count" not in str(kw.get("filter") or ""):
            return {}
        levers = self.world.project(project_id).cost_levers
        if levers is None:
            return {}
        total = int(levers.log_volume_gib * 1024 ** 3)
        debug = int(total * levers.debug_share)
        info = int((total - debug) * 0.6)
        series = []
        for severity, value in (("DEBUG", debug), ("INFO", info), ("ERROR", total - debug - info)):
            series.append({"metric": {"type": "logging.googleapis.com/byte_count", "labels": {"severity": severity}}, "resource": {"type": "global"},
                           "points": [{"interval": {"startTime": kw.get("interval_startTime"), "endTime": kw.get("interval_endTime")}, "value": {"int64Value": str(value)}}]})
        return {"timeSeries": series}

    def _connector_record(self, profile, by_number=False):
        """The project's Serverless VPC Access connector (``conn-main`` in the serverless region) as the API shows it — or, ``by_number``, as the
        inventory does (named by project number, like API keys and secrets) — or None."""
        levers = profile.cost_levers
        if levers is None or not levers.connector:
            return None
        project_id, number, region = profile.project_id, profile.project_number, self._serverless_region(profile)
        return {"name": f"projects/{number if by_number else project_id}/locations/{region}/connectors/conn-main", "network": "vpc-main", "ipCidrRange": "10.8.0.0/28", "state": "READY",
                "minInstances": 2, "maxInstances": 3, "machineType": "e2-micro", "connectedProjects": [project_id]}

    def _h_vpcaccess_projects_locations_connectors_list(self, kw, project_id):
        parent = str(kw.get("parent") or "")
        self.call("vpcaccess", "connectors.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        connector = self._connector_record(profile)
        return {"connectors": [connector]} if connector and parent.endswith(f"/locations/{self._serverless_region(profile)}") else {}

    def _h_bigquery_tables_list(self, kw, project_id):
        """The billing export dataset's tables: one standard export table, ingestion-time partitioned."""
        self.call("bigquery", "tables.list", style="http")
        reference = {"projectId": kw.get("projectId"), "datasetId": kw.get("datasetId"), "tableId": SYNTHETIC_EXPORT_TABLE}
        return {"tables": [{"tableReference": reference, "type": "TABLE", "timePartitioning": {"type": "DAY"}}]}

    def _spend_scope(self, scope_id):
        """The profiles the spend queries cover: the organization's, a folder's or one project's."""
        if scope_id == self.world.org_id:
            return self.world.projects()
        if scope_id in self.world.folder_ids:
            return self.world.projects(scope_id)
        profile = self.world.project(scope_id)
        return [profile] if profile else []

    def _h_bigquery_jobs_query(self, kw, project_id):
        """The two spend queries (``app.checks.spend``) answered from ``SyntheticOrg.daily_spend`` the way BigQuery would: the briefing's
        ``(kind, item, value, value2)`` rows, or the anomaly rows the rule leaves — as a finished ``jobs.query`` response."""
        self.call("bigquery", "jobs.query", style="http")
        body = kw.get("body") or {}
        params = {p["name"]: p.get("parameterValue") or {} for p in body.get("queryParameters") or []}
        scalar = {name: value.get("value") for name, value in params.items() if "value" in value}
        today = datetime.strptime(scalar.get("today") or datetime.now(timezone.utc).strftime("%Y-%m-%d"), "%Y-%m-%d").date()
        profiles = self._spend_scope(str(scalar.get("scope_id") or ""))
        query = str(body.get("query") or "")

        def response(fields, rows):
            return {"jobComplete": True, "schema": {"fields": [{"name": f} for f in fields]}, "rows": [{"f": [{"v": None if v is None else str(v)} for v in row]} for row in rows],
                    "totalRows": str(len(rows)), "jobReference": {"projectId": kw.get("projectId"), "jobId": "synthetic", "location": "US"}}

        if '"day" AS kind' in query:
            days, projects, services, credits = {}, {}, {}, {}
            eligible_cost = eligible_cud = 0.0
            eligible = {v["value"] for v in (params.get("eligible") or {}).get("arrayValues") or []}
            for profile in profiles:
                for offset in range(1, 96):
                    day = (today - timedelta(days=offset)).isoformat()
                    for service, cost, credit, cud in self.world.daily_spend(profile, offset):
                        net = cost + credit
                        days[day] = days.get(day, 0.0) + net
                        bucket = 0 if offset <= 30 else (1 if offset <= 60 else None)
                        if bucket is not None:
                            for table, key in ((projects, profile.project_id), (services, service)):
                                now, before = table.get(key, (0.0, 0.0))
                                table[key] = (now + net, before) if bucket == 0 else (now, before + net)
                        if offset <= 30:
                            if credit:
                                kind = "COMMITTED_USAGE_DISCOUNT" if cud else "SUSTAINED_USAGE_DISCOUNT"
                                credits[kind] = credits.get(kind, 0.0) + credit
                            if service in eligible:
                                eligible_cost += cost
                                eligible_cud += cud
            rows = [("day", day, net, 0.0) for day, net in sorted(days.items())]
            rows += [("project", name, now, before) for name, (now, before) in sorted(projects.items())]
            rows += [("service", name, now, before) for name, (now, before) in sorted(services.items())]
            rows += [("credit", kind, amount, 0.0) for kind, amount in sorted(credits.items())]
            rows += [("eligible", "commitment-eligible", eligible_cost, eligible_cud), ("currency", "USD", sum(len(p.vms) + 1 for p in profiles), 0.0),
                     ("freshness", (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"), 0.0, 0.0), ("unattributed", "", 0.0, 0.0)]
            return response(("kind", "item", "value", "value2"), rows)
        floor, ratio = float(scalar.get("floor") or 0), float(scalar.get("ratio") or 1.5)
        weekly = {}
        for profile in profiles:
            for offset in range(1, 29):
                for service, cost, credit, _ in self.world.daily_spend(profile, offset):
                    this_week, before = weekly.get((profile.project_id, service), (0.0, 0.0))
                    weekly[(profile.project_id, service)] = (this_week + cost + credit, before) if offset <= 7 else (this_week, before + cost + credit)
        flagged = [(pid, service, this_week, before / 3) for (pid, service), (this_week, before) in weekly.items()
                   if this_week >= floor and (before <= 0 or this_week >= ratio * before / 3)]
        flagged.sort(key=lambda row: (-row[2], row[0], row[1]))
        return response(("project_id", "service", "this_week", "weekly_mean_before"), flagged[:200])

    def _h_iam_projects_serviceAccounts_list(self, kw, project_id):
        self.call("iam", "serviceAccounts.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"accounts": [{"name": f"projects/{project_id}/serviceAccounts/{sa.email}", "email": sa.email}
                             for sa in profile.service_accounts]}

    def _h_iam_projects_serviceAccounts_keys_list(self, kw, project_id):
        self.call("iam", "serviceAccounts.keys.list", project_id=project_id, style="http")
        profile, email = self.world.project(project_id), kw["name"].rsplit("/", 1)[-1]
        for sa in profile.service_accounts:
            if sa.email == email:
                oldest = max(sa.key_ages_days) if sa.key_ages_days else None
                return {"keys": [{"name": f"{kw['name']}/keys/{i}", "validAfterTime": _iso(age), "validBeforeTime": "9999-12-31T23:59:59Z",
                                  "keyType": "USER_MANAGED", "keyOrigin": "GOOGLE_PROVIDED",
                                  **({"disabled": True} if (age == oldest and email in profile.disabled_key_accounts) else {})}
                                 for i, age in enumerate(sa.key_ages_days)]}
        return {"keys": []}

    def _h_sqladmin_instances_list(self, kw, project_id):
        self.call("sqladmin", "instances.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": sql.name, "databaseVersion": sql.database_version, "instanceType": "CLOUD_SQL_INSTANCE",
                           "settings": {"ipConfiguration": {
                               "ipv4Enabled": sql.public_ip, "requireSsl": False,
                               "sslMode": "ENCRYPTED_ONLY" if sql.require_ssl else "ALLOW_UNENCRYPTED_AND_ENCRYPTED",  # v18: the field that decides
                               "authorizedNetworks": [{"value": "0.0.0.0/0", "name": "everywhere"}] if sql.name in profile.sql_open_networks else []}}}
                          for sql in profile.sql_instances]}

    def _h_container_projects_locations_clusters_list(self, kw, project_id):
        self.call("container", "clusters.list", project_id=project_id, style="http")
        profile, clusters = self.world.project(project_id), []
        for cluster in profile.gke_clusters:
            # v18.2: the GKE API and the inventory show the same cluster (the API adds auto-repair and the node version).
            entry = dict(self._cluster_asset(profile, cluster).resource.data)
            entry["currentNodeVersion"] = cluster.node_pools[0][2]
            repairs = profile.gke_auto_repair.get(cluster.name, (True,) * len(cluster.node_pools))
            entry["nodePools"] = [{**pool, "management": {**pool.get("management", {}), "autoRepair": repair}} for pool, repair in zip(entry["nodePools"], repairs)]
            clusters.append(entry)
        return {"clusters": clusters}

    def _h_container_projects_locations_getServerConfig(self, kw, project_id):
        """The versions GKE offers in a location (the same everywhere): the static lists and the REGULAR channel's."""
        self.call("container", "projects.locations.getServerConfig", project_id=project_id, style="http")
        channel_versions = [v for v in GKE_VERSIONS if v.rsplit(".", 2)[0] in GKE_CHANNEL_MINORS]
        return {"defaultClusterVersion": gke_version(GKE_MINORS[1]),
                "validMasterVersions": list(GKE_VERSIONS), "validNodeVersions": list(GKE_VERSIONS),
                "channels": [{"channel": "REGULAR", "defaultVersion": gke_version(GKE_MINORS[1]), "validVersions": channel_versions}]}

    def _h_recommender_projects_locations_recommenders_recommendations_list(self, kw, project_id):
        parent = kw["parent"]
        project_id = _project_of(parent)
        self.call("recommender", "recommendations.list(rest)", project_id=project_id, style="http")
        profile, location = self.world.project(project_id), parent.split("/locations/")[1].split("/")[0]
        recos = [{"name": f"{parent}/recommendations/{i}", "description": text, "stateInfo": {"state": "ACTIVE"},
                  "targetResources": [f"//container.googleapis.com/projects/{project_id}/locations/{location}/clusters/{cluster.name}"]}
                 for cluster in profile.gke_clusters if cluster.location == location
                 for i, text in enumerate(cluster.recommendations)]
        return {"recommendations": recos}

    def _h_monitoring_projects_alertPolicies_list(self, kw, project_id):
        self.call("monitoring", "alertPolicies.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        # v18: filters as Cloud Monitoring writes them (the legacy world's filters contained the check's own needles).
        filters = {"serviceruntime.googleapis.com/quota": 'metric.type="serviceruntime.googleapis.com/quota/allocation/usage" AND resource.type="consumer_quota"',
                   "cloud_sql": 'metric.type="cloudsql.googleapis.com/database/cpu/utilization" AND resource.type="cloudsql_database"',
                   "gke_cluster": 'metric.type="kubernetes.io/container/restart_count" AND resource.type="k8s_container"'}
        o, prefix = profile.observability, f"projects/{project_id}"
        channels = [f"{prefix}/notificationChannels/{j}" for j in range(len(o.channels))] if o else []
        policies = []
        for i, f in enumerate(profile.alert_filters):  # v18.9: the channels each policy notifies, an MQL condition on the first where drawn
            text = filters.get(f, f'metric.type="{f}"')
            condition = {"conditionMonitoringQueryLanguage": {"query": f"fetch global | {text} | condition val() > 0.9"}} if o and o.mql and i == 0 \
                else {"conditionThreshold": {"filter": text}}
            refs = [channels[j] for j in (o.policy_channels[i] if o and i < len(o.policy_channels) else ())]
            policies.append({"name": f"{prefix}/alertPolicies/{i}", "displayName": f"alert-{i}", "enabled": True, "conditions": [condition], "notificationChannels": refs})
        working = [channels[j] for j, kind in enumerate(o.channels if o else ()) if kind in ("email", "pubsub")][:1]
        if o and o.uptime == "alerted":  # v18.9: the uptime check's policy
            policies.append({"name": f"{prefix}/alertPolicies/uptime", "displayName": "edge uptime", "enabled": True, "notificationChannels": working,
                             "conditions": [{"conditionThreshold": {"filter": 'metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND metric.labels.check_id="edge-uptime" AND resource.type="uptime_url"'}}]})
        if o and o.slo == "alerted":  # v18.9: the SLO's burn-rate policy
            policies.append({"name": f"{prefix}/alertPolicies/burn", "displayName": "web availability burn rate", "enabled": True, "notificationChannels": working,
                             "conditions": [{"conditionThreshold": {"filter": f'select_slo_burn_rate("{prefix}/services/svc-web/serviceLevelObjectives/availability", "60m")'}}]})
        return {"alertPolicies": policies}

    def _h_monitoring_projects_notificationChannels_list(self, kw, project_id):
        """v18.9: the project's channels in the drawn states — verified and unverified email, a disabled Slack channel, Pub/Sub channels whose
        topic exists with or without the notification agent's grant, or does not exist."""
        self.call("monitoring", "notificationChannels.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        o, prefix = profile.observability, f"projects/{project_id}"
        channels = []
        for j, kind in enumerate(o.channels if o else ()):
            channel = {"name": f"{prefix}/notificationChannels/{j}", "enabled": True, "verificationStatus": "VERIFICATION_STATUS_UNSPECIFIED"}
            if kind.startswith("email"):
                channel.update(type="email", displayName="ops mail", labels={"email_address": "ops@example.com"}, verificationStatus="UNVERIFIED" if kind == "email-unverified" else "VERIFIED")
            elif kind == "disabled":
                channel.update(type="slack", displayName="ops slack", labels={"channel_name": "#ops"}, enabled=False)
            else:
                topic = {"pubsub": "alerts", "pubsub-ungranted": "alerts-ungranted", "pubsub-gone": "alerts-gone"}[kind]
                channel.update(type="pubsub", displayName=f"topic {topic}", labels={"topic": f"projects/{project_id}/topics/{topic}"})
            channels.append(channel)
        return {"notificationChannels": channels}

    @staticmethod
    def _lb_address(profile):
        return f"34.120.{profile.index % 256}.{(profile.index * 7 + 1) % 256}"

    def _h_monitoring_projects_uptimeCheckConfigs_list(self, kw, project_id):
        """v18.9: an uptime check on the external load balancer's address where drawn."""
        self.call("monitoring", "uptimeCheckConfigs.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        o = profile.observability
        if not o or not o.uptime:
            return {}
        return {"uptimeCheckConfigs": [{"name": f"projects/{project_id}/uptimeCheckConfigs/edge-uptime", "displayName": "edge uptime",
                                        "monitoredResource": {"type": "uptime_url", "labels": {"host": self._lb_address(profile), "project_id": project_id}},
                                        "httpCheck": {"path": "/", "port": 443, "useSsl": True}, "period": "60s", "timeout": "10s"}]}

    def _h_monitoring_services_list(self, kw, project_id):
        """v18.9: a Cloud Run service entry in Monitoring where the world drew an SLO."""
        self.call("monitoring", "services.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        o = profile.observability
        if not o or not o.slo:
            return {}
        return {"services": [{"name": f"projects/{project_id}/services/svc-web", "displayName": "web",
                              "cloudRun": {"serviceName": "web", "location": self._serverless_region(profile)}}]}

    def _h_monitoring_services_serviceLevelObjectives_list(self, kw, project_id):
        self.call("monitoring", "serviceLevelObjectives.list", project_id=project_id, style="http")
        parent = str(kw.get("parent") or "")
        return {"serviceLevelObjectives": [{"name": f"{parent}/serviceLevelObjectives/availability", "displayName": "availability", "goal": 0.995, "rollingPeriod": "2592000s"}]}

    def _observability_assets(self, profile, asset_types):
        """v18.9: the project's Pub/Sub topics as the inventory lists them — the alert channels' topics that exist, the audit sink's."""
        if "pubsub.googleapis.com/Topic" not in asset_types or profile.observability is None:
            return []
        o = profile.observability
        topics = sorted({{"pubsub": "alerts", "pubsub-ungranted": "alerts-ungranted"}[kind] for kind in o.channels if kind in ("pubsub", "pubsub-ungranted")})
        if o.sink == "topic":
            topics.append("audit-stream")
        return [SimpleNamespace(name=f"//pubsub.googleapis.com/projects/{profile.project_id}/topics/{topic}", asset_type="pubsub.googleapis.com/Topic",
                                resource=SimpleNamespace(data={"name": f"projects/{profile.project_id}/topics/{topic}"}, parent=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_number}"))
                for topic in topics]

    def _agent_policy_results(self, profiles, email):
        """v18.9: the IAM-policy search results for a Google-managed agent — the Monitoring notification agent's publisher role on the ``alerts``
        topic of its project, the first folder's sink writer's bucketWriter role on the project that hosts its bucket; nothing for the projects'
        own sink writers (the topic shape has no grant)."""
        results = []
        for profile in profiles:
            common = {"project": f"projects/{profile.project_number}", "organization": f"organizations/{self.world.org_id}", "folders": [f"folders/{profile.folder_id}"]}
            o = profile.observability
            if email == f"service-{profile.project_number}@gcp-sa-monitoring-notification.iam.gserviceaccount.com" and o and "pubsub" in o.channels:
                results.append(SimpleNamespace(asset_type="pubsub.googleapis.com/Topic", resource=f"//pubsub.googleapis.com/projects/{profile.project_id}/topics/alerts",
                                               policy=SimpleNamespace(bindings=[SimpleNamespace(role="roles/pubsub.publisher", members=[f"serviceAccount:{email}"])]), **common))
            if email == f"service-folder-{profile.folder_id}@gcp-sa-logging.iam.gserviceaccount.com" and self._folder_sink_host(profile.folder_id) is profile:
                results.append(SimpleNamespace(asset_type="cloudresourcemanager.googleapis.com/Project", resource=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_id}",
                                               policy=SimpleNamespace(bindings=[SimpleNamespace(role="roles/logging.bucketWriter", members=[f"serviceAccount:{email}"])]), **common))
        return results

    def _h_logging_organizations_sinks_list(self, kw, project_id):
        self.call("logging", "sinks.list", style="http")
        return {"sinks": [{"name": "org-audit-sink", "destination": f"bigquery.googleapis.com/projects/{HOST_PROJECT}/datasets/audit_logs"}]}

    def _h_securitycenter_projects_locations_clusters_containerThreatDetectionSettings_calculate(self, kw, project_id):
        self.call("securitycenter", "containerThreatDetectionSettings.calculate", project_id=project_id, style="http")
        profile, cluster_name = self.world.project(project_id), kw["name"].split("/clusters/", 1)[1].split("/", 1)[0]
        hardening = profile.gke_hardening.get(cluster_name)
        return {"name": kw["name"], "serviceEnablementState": "ENABLED" if (hardening is None or hardening.ctd_enabled) else "DISABLED"}

    def _h_securitycenter_projects_eventThreatDetectionSettings_calculate(self, kw, project_id):
        self.call("securitycenter", "eventThreatDetectionSettings.calculate", project_id=project_id, style="http")
        return {"name": kw["name"], "serviceEnablementState": "ENABLED" if self.world.project(project_id).etd_enabled else "DISABLED"}

    def _h_iam_projects_roles_get(self, kw, project_id):
        self.call("iam", "roles.get", project_id=project_id, style="http")
        return {"name": kw["name"], "includedPermissions": ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.get"]}

    def _h_accesscontextmanager_accessPolicies_list(self, kw, project_id):
        self.call("accesscontextmanager", "accessPolicies.list", style="http")
        return {"accessPolicies": [{"name": "accessPolicies/100", "parent": kw.get("parent", ""), "title": "synthetic policy"}]}

    def _h_accesscontextmanager_accessPolicies_servicePerimeters_list(self, kw, project_id):
        self.call("accesscontextmanager", "servicePerimeters.list", style="http")
        perimeters = []
        for p in self.world.perimeters():
            config = {"resources": list(p["resources"]), "restrictedServices": list(p["restricted"])}
            entry = {"name": f"{kw.get('parent', 'accessPolicies/100')}/servicePerimeters/{p['name']}", "title": p["title"],
                     "perimeterType": "PERIMETER_TYPE_REGULAR" if p["regular"] else "PERIMETER_TYPE_BRIDGE"}
            if p["dry_run"]:
                entry.update(spec=config, useExplicitDryRunSpec=True)
            else:
                entry["status"] = config
            perimeters.append(entry)
        return {"servicePerimeters": perimeters}

    def _h_securitycenter_organizations_getOrganizationSettings(self, kw, project_id):
        self.call("securitycenter", "getOrganizationSettings", style="http")
        return {"name": kw["name"], "enableAssetDiscovery": False, "assetDiscoveryConfig": {}}  # no tier here (v18)

    def _h_securitycenter_organizations_getSubscription(self, kw, project_id):
        """``v1beta2 organizations.getSubscription``: the organization's tier (v18)."""
        self.call("securitycenter", "getSubscription", style="http")
        return {"name": kw["name"], "tier": "STANDARD", "details": {"type": "STANDARD"}}

    def _h_cloudresourcemanager_organizations_get(self, kw, project_id):
        self.call("cloudresourcemanager", "organizations.get", style="http")
        return {"name": kw["name"], "displayName": "example.com", "lifecycleState": "ACTIVE"}

    def _h_cloudresourcemanager_projects_getEffectiveOrgPolicy(self, kw, project_id):
        """The effective policy of one constraint on a project (v18: storage.publicAccessPrevention, read for public buckets)."""
        self.call("cloudresourcemanager", "projects.getEffectiveOrgPolicy", project_id=project_id, style="http")
        return {"constraint": (kw.get("body") or {}).get("constraint", ""), "booleanPolicy": {"enforced": False}}

    ORG_CONTACTS = [{"email": "security@example.com", "notificationCategorySubscriptions": ["SECURITY"], "validationState": "VALID"},
                    {"email": "ops@example.com", "notificationCategorySubscriptions": ["TECHNICAL"], "validationState": "VALID"},
                    {"email": "legal-old@example.com", "notificationCategorySubscriptions": ["LEGAL"], "validationState": "INVALID"}]  # v18.1: bounced

    def _h_essentialcontacts_organizations_contacts_list(self, kw, project_id):
        self.call("essentialcontacts", "contacts.list", style="http")
        return {"contacts": list(self.ORG_CONTACTS)}

    def _h_essentialcontacts_projects_contacts_compute(self, kw, project_id):
        """The effective contacts of a project (v18.1): the organization's, plus the project's own when it has one."""
        self.call("essentialcontacts", "contacts.compute(project)", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        own = [{"email": f"owner@{profile.project_id}.example.com", "notificationCategorySubscriptions": ["SUSPENSION", "LEGAL"], "validationState": "VALID"}] if profile.project_contact else []
        return {"contacts": list(self.ORG_CONTACTS) + own}

    def _h_essentialcontacts_folders_contacts_compute(self, kw, project_id):
        self.call("essentialcontacts", "contacts.compute(folder)", style="http")
        return {"contacts": list(self.ORG_CONTACTS)}

    def _h_cloudresourcemanager_folders_getIamPolicy(self, kw, project_id):
        """A folder's IAM policy (v3; v18.1): no audit configuration; v18.7: the folder's own bindings (``world.folder_iam_bindings``)."""
        self.call("cloudresourcemanager", "folders.getIamPolicy", style="http")
        return {"bindings": self.world.folder_iam_bindings(str(kw.get("resource", "")).rsplit("/", 1)[-1]), "etag": "synthetic"}

    # --- v18.7: custom roles, Privileged Access Manager, deny policies ---

    def _h_iam_organizations_roles_list(self, kw, project_id):
        self.call("iam", "organizations.roles.list", style="http")
        return {"roles": self.world.org_custom_roles()}

    def _h_iam_projects_roles_list(self, kw, project_id):
        """The project's custom roles (``view=FULL``): the v17.1 token-minting role when the impersonation table binds it, and the v18.7 role."""
        self.call("iam", "projects.roles.list", project_id=project_id, style="http")
        profile, roles = self.world.project(project_id), []
        if profile.custom_role_bindings:
            roles.append({"name": f"projects/{project_id}/roles/tokenMinter", "title": "token minter", "stage": "GA", "includedPermissions": ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.get"]})
        kind = profile.privileges.custom_role if profile.privileges else ""
        if kind in ("powers-held", "powers-dormant"):
            roles.append({"name": f"projects/{project_id}/roles/{SYNTHETIC_CUSTOM_ROLE}", "title": "deployer", "stage": "GA", "includedPermissions": ["resourcemanager.projects.setIamPolicy", "run.services.update"]})
        elif kind == "retired-bound":
            roles.append({"name": f"projects/{project_id}/roles/{SYNTHETIC_CUSTOM_ROLE}", "title": "deployer", "stage": "DISABLED", "includedPermissions": ["run.services.update"]})
        return {"roles": roles}

    def _entitlement(self, profile):
        kind = profile.privileges.pam if profile.privileges else ""
        if not kind:
            return None
        body = {"name": f"projects/{profile.project_id}/locations/global/entitlements/jit-compute-admin", "state": "AVAILABLE", "maxRequestDuration": "3600s",
                "eligibleUsers": [{"principals": ["user:oncall@example.com"]}], "requesterJustificationConfig": {"unstructured": {}},
                "privilegedAccess": {"gcpIamAccess": {"resource": f"//cloudresourcemanager.googleapis.com/projects/{profile.project_id}", "resourceType": "cloudresourcemanager.googleapis.com/Project",
                                                      "roleBindings": [{"role": "roles/compute.admin"}]}}}
        if kind == "approved":
            body["approvalWorkflow"] = {"manualApprovals": {"requireApproverJustification": True, "steps": [{"approvers": [{"principals": ["group:cloud-admins@example.com"]}], "approvalsNeeded": 1}]}}
        return body

    def _h_privilegedaccessmanager_projects_locations_entitlements_list(self, kw, project_id):
        """A project's entitlements; where the world draws none, the API is not enabled (the real API's SERVICE_DISABLED answer)."""
        self.call("privilegedaccessmanager", "projects.locations.entitlements.list", project_id=project_id, style="http")
        entitlement = self._entitlement(self.world.project(project_id))
        if entitlement is None:
            raise _http_error(403, f"Privileged Access Manager API has not been used in project {project_id} before or it is disabled. SERVICE_DISABLED")
        return {"entitlements": [entitlement]}

    def _h_privilegedaccessmanager_organizations_locations_entitlements_list(self, kw, project_id):
        self.call("privilegedaccessmanager", "organizations.locations.entitlements.list", style="http")
        return {}

    def _h_privilegedaccessmanager_folders_locations_entitlements_list(self, kw, project_id):
        self.call("privilegedaccessmanager", "folders.locations.entitlements.list", style="http")
        return {}

    def _h_iam_policies_listPolicies(self, kw, project_id):
        """No IAM deny policy is attached to the synthetic organization (the Informational row)."""
        self.call("iam", "policies.listPolicies", style="http")
        return {}

    # --- Advisory Notifications ---

    @staticmethod
    def _notification(parent, index, advisory):
        kind, subject, days_ago, body, attachments = advisory
        return {
            "name": f"{parent}/notifications/syn-notification-{index}", "notificationType": kind, "createTime": _iso(days_ago),
            "subject": {"text": {"enText": subject, "localizedText": subject, "localizationState": "LOCALIZATION_STATE_NOT_APPLICABLE"}},
            "messages": [{
                "createTime": _iso(days_ago), "localizationTime": _iso(days_ago),
                "body": {"text": {"enText": body, "localizedText": body, "localizationState": "LOCALIZATION_STATE_NOT_APPLICABLE"}},
                "attachments": [{"displayName": name, "csv": {"headers": list(headers), "dataRows": [{"entries": list(row)} for row in rows]}}
                                for name, headers, rows in attachments],
            }],
        }

    def _h_advisorynotifications_organizations_locations_notifications_list(self, kw, project_id):
        self.call("advisorynotifications", "notifications.list(organization)", style="http")
        parent = kw["parent"]
        return {"notifications": [self._notification(parent, i, advisory) for i, advisory in enumerate(ORG_ADVISORIES)]}

    def _h_advisorynotifications_organizations_locations_getSettings(self, kw, project_id):
        self.call("advisorynotifications", "getSettings(organization)", style="http")
        return {"name": kw["name"], "etag": "synthetic", "notificationSettings": {kind: {"enabled": True} for kind in ADVISORY_TYPES}}

    def _h_advisorynotifications_projects_locations_notifications_list(self, kw, project_id):
        self.call("advisorynotifications", "notifications.list(project)", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"notifications": [self._notification(kw["parent"], 0, PROJECT_ADVISORY)] if profile.has_project_advisory else []}

    def _h_advisorynotifications_projects_locations_getSettings(self, kw, project_id):
        self.call("advisorynotifications", "getSettings(project)", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"name": kw["name"], "etag": "synthetic",
                "notificationSettings": {kind: {"enabled": kind not in profile.advisory_types_disabled} for kind in ADVISORY_TYPES}}

    # --- v19: Security Command Center (REST) and VM Manager ---

    def _finding_results(self, profile):
        """The project's active SCC findings as ``ListFindingsResult`` objects, in the drawn shape; the muted ones carry ``mute: MUTED``."""
        f, project_id, number = profile.findings, profile.project_id, profile.project_number
        if f is None or not f.scc:
            return []
        org = f"organizations/{self.world.org_id}"
        results = []

        def add(cls, category, severity, resource_name, display, source, days=3, mute="UNDEFINED", recommendation="", explanation=""):
            results.append({"finding": {"name": f"{org}/sources/1/locations/global/findings/{len(results)}", "findingClass": cls, "category": category, "severity": severity, "state": "ACTIVE",
                                        "mute": mute, "eventTime": _iso(days), "createTime": _iso(days + 10), "resourceName": resource_name, "parentDisplayName": source,
                                        "sourceProperties": {"Recommendation": recommendation, "Explanation": explanation} if recommendation else {}},
                            "resource": {"name": resource_name, "displayName": display, "gcpMetadata": {"project": f"projects/{number}", "projectDisplayName": project_id}}})
        sha = "Security Health Analytics"
        if f.scc in ("misconfig", "critical", "mixed"):
            for vm in profile.vms[:2]:
                add("MISCONFIGURATION", "COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED", "MEDIUM", f"//compute.googleapis.com/projects/{project_id}/zones/{vm.zone}/instances/{vm.name}", vm.name, sha,
                    recommendation="Go to the instance's details page and block project-wide SSH keys.", explanation="Project-wide SSH keys are allowed on this instance.")
            for bucket in profile.buckets[:3]:
                add("MISCONFIGURATION", "BUCKET_LOGGING_DISABLED", "LOW", f"//storage.googleapis.com/{bucket.name}", bucket.name, sha,
                    recommendation="Set up logging for the bucket.", explanation="Storage logging is not enabled for this bucket.")
            for sql in profile.sql_instances[:1]:
                add("MISCONFIGURATION", "SQL_PUBLIC_IP", "MEDIUM", f"//cloudsql.googleapis.com/projects/{project_id}/instances/{sql.name}", sql.name, sha,
                    recommendation="Remove the public IP from the instance.", explanation="The Cloud SQL instance has a public IP address.")
        if f.scc in ("critical", "mixed"):
            add("VULNERABILITY", "GEMINI_MODEL_NOT_PROTECTED_BY_MODEL_ARMOR", "CRITICAL", f"//cloudresourcemanager.googleapis.com/projects/{number}", project_id, "Model Armor", days=1)
        if f.scc in ("threats", "mixed"):
            add("THREAT", "Persistence: New API Method", "LOW", f"//cloudresourcemanager.googleapis.com/projects/{number}", project_id, "Event Threat Detection", days=12)
            add("THREAT", "Persistence: New API Method", "LOW", f"//cloudresourcemanager.googleapis.com/projects/{number}", project_id, "Event Threat Detection", days=5)
            if profile.vms:
                add("THREAT", "Malware: Bad IP", "HIGH", f"//compute.googleapis.com/projects/{project_id}/zones/{profile.vms[0].zone}/instances/{profile.vms[0].name}", profile.vms[0].name, "Event Threat Detection", days=2)
        if f.scc == "mixed":
            add("SCC_ERROR", "API_DISABLED", "HIGH", f"//cloudresourcemanager.googleapis.com/projects/{number}", project_id, "Security Command Center", days=4)
            add("OBSERVATION", "Impact: GPU Instance Created", "LOW", f"//cloudresourcemanager.googleapis.com/projects/{number}", project_id, "Sensitive Actions Service", days=30)
        for i in range(f.muted):
            add("MISCONFIGURATION", "BUCKET_LOGGING_DISABLED", "LOW", f"//storage.googleapis.com/muted-{i}", f"muted-{i}", sha, mute="MUTED")
        return results

    def _scc_v2(self, url, params):
        """``GET /v2/{parent}/sources/-/locations/global/findings`` for the organization or a project (a folder answers 400, as the Standard tier
        does); the organization's ``notificationConfigs`` and ``bigQueryExports`` (none)."""
        path = url.split("/v2/", 1)[1]
        if path.endswith("/notificationConfigs") or path.endswith("/bigQueryExports"):
            self.call("securitycenter", path.rsplit("/", 1)[-1] + ".list", style="http")
            return _HttpResponse(200, "{}")
        if path.startswith("folders/"):
            self.call("securitycenter", "findings.list?", style="http")
            return _HttpResponse(400, json.dumps({"error": {"code": 400, "message": "Security Command Center Legacy has been permanently disabled as of June 7, 2021. Migrate to Security Command Center's Standard tier or Premium tier.", "status": "FAILED_PRECONDITION"}}))
        project_id = _project_of(path) if path.startswith("projects/") else None
        try:
            self.call("securitycenter", "findings.list", project_id=project_id, style="http")
        except HttpError as e:
            return _HttpResponse(e.resp.status, e.content.decode() if isinstance(e.content, bytes) else str(e.content))
        profiles = [self.world.project(project_id)] if project_id else self.world.projects()
        exclude_muted = 'mute!="MUTED"' in str(params.get("filter") or "")
        results = [r for p in profiles for r in self._finding_results(p) if not (exclude_muted and r["finding"]["mute"] == "MUTED")]
        return _HttpResponse(200, json.dumps({"listFindingsResults": results, "totalSize": len(results)}))

    def _scc_management(self, url):
        """``GET /v1/{parent}/locations/global/securityCenterServices``: the effective states by the project's drawn profile; the organization
        and the folders inherit-off everything (as the real organization does)."""
        path = url.split("/v1/", 1)[1]
        project_id = _project_of(path) if path.startswith("projects/") else None
        try:
            self.call("securitycentermanagement", "securityCenterServices.list", project_id=project_id, style="http")
        except HttpError as e:
            return _HttpResponse(e.resp.status, e.content.decode() if isinstance(e.content, bytes) else str(e.content))
        profile = self.world.project(project_id) if project_id else None
        detectors = profile.findings.detectors if profile and profile.findings else "inherited"
        threat = ("EVENT_THREAT_DETECTION", "CONTAINER_THREAT_DETECTION", "VM_THREAT_DETECTION", "CLOUD_RUN_THREAT_DETECTION", "WEB_SECURITY_SCANNER")
        services = []
        for name in ("SECURITY_HEALTH_ANALYTICS",) + threat + ("VM_MANAGER",):
            on = detectors == "premium" or (detectors == "standard" and name == "SECURITY_HEALTH_ANALYTICS")
            modules = {f"MODULE_{i}": {"effectiveEnablementState": "ENABLED" if on and i % 2 == 0 else "DISABLED"} for i in range(4)} if name != "VM_MANAGER" else {}
            services.append({"name": f"{path}/{name.lower().replace('_', '-')}", "intendedEnablementState": "ENABLED" if on else "INHERITED",
                             "effectiveEnablementState": "ENABLED" if on else "DISABLED", "modules": modules})
        return _HttpResponse(200, json.dumps({"securityCenterServices": services}))

    def _h_osconfig_projects_locations_instances_vulnerabilityReports_list(self, kw, project_id):
        """VM Manager's vulnerability reports of a zone's instances, or the precondition error of a project without full VM Manager."""
        self.call("osconfig", "vulnerabilityReports.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        f = profile.findings
        if f is None or not f.vm_manager:
            raise _http_error(400, "Vulnerability reports are disabled in this project. To view these reports, enable full VM Manager functionality.")
        zone = str(kw.get("parent") or "").split("/locations/")[1].split("/")[0]
        reports = []
        for index, vm in enumerate(profile.vms):
            if vm.zone != zone or vm.name in profile.stopped_vms or vm.gke:
                continue
            critical, high, other = f.cves[index] if index < len(f.cves) else (0, 0, 0)
            vulns = [{"details": {"cve": f"CVE-2026-{1000 + n}", "severity": "CRITICAL", "cvssV3": {"baseScore": 9.8}}, "availableInventoryItemIds": ["pkg-1"], "installedInventoryItemIds": ["pkg-0"]} for n in range(critical)]
            vulns += [{"details": {"cve": f"CVE-2026-{2000 + n}", "severity": "HIGH", "cvssV3": {"baseScore": 7.5}}, "availableInventoryItemIds": ["pkg-2"]} for n in range(high)]
            vulns += [{"details": {"cve": f"CVE-2026-{3000 + n}", "severity": "MEDIUM", "cvssV3": {"baseScore": 5.3}}} for n in range(other)]
            reports.append({"name": f"projects/{project_id}/locations/{zone}/instances/{self._instance_id(profile, index)}/vulnerabilityReport", "vulnerabilities": vulns, "updateTime": _iso(0)})
        return {"vulnerabilityReports": reports}

    def _firewall_assets(self, profile, asset_types):
        """The project's VPC firewall rules as the inventory lists them (v19: the same rules ``firewalls.list`` answers)."""
        if "compute.googleapis.com/Firewall" not in asset_types:
            return []
        rules = self._firewall_rules(profile)
        return [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/global/firewalls/{rule['name']}",
                                resource=SimpleNamespace(data=rule, parent=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_number}")) for rule in rules]

    # --- Asset Inventory ---

    def search_all_resources(self, request):
        # The picker's ``query`` ("state:ACTIVE", v15.6) is accepted: nothing synthetic is pending deletion.
        scope, asset_types = request["scope"], request.get("asset_types", [])
        folder_id = scope.split("/")[1] if scope.startswith("folders/") else None
        results = []
        if not asset_types or "versionedResources" in str(request.get("read_mask") or ""):  # v19.1: the footprint's all-types and content searches
            project_id = scope.split("/", 1)[1] if scope.startswith("projects/") else None
            profiles = [self.world.project(project_id)] if project_id else self.world.projects(folder_id)
            results = self._footprint_results(profiles, set(asset_types), "versionedResources" in str(request.get("read_mask") or ""))
            self.call("asset", "searchAllResources", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
            return results
        if "cloudresourcemanager.googleapis.com/Folder" in asset_types:
            folder_ids = [folder_id] if folder_id else ([] if scope.startswith("projects/") else list(self.world.folder_ids))  # v18.7: a folder scope includes itself
            results += [SimpleNamespace(name=f"//cloudresourcemanager.googleapis.com/folders/{fid}", display_name=self._folder_display(fid),
                                        asset_type="cloudresourcemanager.googleapis.com/Folder", project="", state="ACTIVE",
                                        parent_full_resource_name=f"//cloudresourcemanager.googleapis.com/organizations/{self.world.org_id}")
                        for fid in folder_ids]
        if "cloudresourcemanager.googleapis.com/Project" in asset_types:
            results += [SimpleNamespace(name=f"//cloudresourcemanager.googleapis.com/projects/{p.project_id}", display_name=p.display_name,
                                        asset_type="cloudresourcemanager.googleapis.com/Project", project=f"projects/{p.project_number}",
                                        parent_full_resource_name=f"//cloudresourcemanager.googleapis.com/folders/{p.folder_id}",
                                        folders=[f"folders/{p.folder_id}"], organization=f"organizations/{self.world.org_id}")
                        for p in ([self.world.project(scope.split("/", 1)[1])] if scope.startswith("projects/") else self.world.projects(folder_id))]
        if "iam.googleapis.com/ServiceAccount" in asset_types:  # v17.1: the accounts in scope, the default compute account included
            project_id = scope.split("/", 1)[1] if scope.startswith("projects/") else None
            for p in ([self.world.project(project_id)] if project_id else self.world.projects(folder_id)):
                emails = [sa.email for sa in p.service_accounts] + [f"{p.project_number}-compute@developer.gserviceaccount.com"]
                results += [SimpleNamespace(name=f"//iam.googleapis.com/projects/{p.project_id}/serviceAccounts/{e}", display_name=e.split("@")[0],
                                            asset_type="iam.googleapis.com/ServiceAccount", project=f"projects/{p.project_number}",
                                            folders=[f"folders/{p.folder_id}"], organization=f"organizations/{self.world.org_id}",
                                            parent_full_resource_name=f"//cloudresourcemanager.googleapis.com/projects/{p.project_id}") for e in emails]
        if "artifactregistry.googleapis.com/Repository" in asset_types or "serviceusage.googleapis.com/Service" in asset_types:  # v18.6
            project_id = scope.split("/", 1)[1] if scope.startswith("projects/") else None
            profiles = [self.world.project(project_id)] if project_id else self.world.projects(folder_id)
            if "artifactregistry.googleapis.com/Repository" in asset_types:
                results += self._repository_results(profiles)
            if "serviceusage.googleapis.com/Service" in asset_types:
                results += self._enabled_service_results(profiles, str(request.get("query") or ""))
        if "secretmanager.googleapis.com/Secret" in asset_types:  # v18.7: the secrets and their versions
            project_id = scope.split("/", 1)[1] if scope.startswith("projects/") else None
            results += self._secret_results([self.world.project(project_id)] if project_id else self.world.projects(folder_id))
        if "vpcaccess.googleapis.com/Connector" in asset_types:  # v18.8: the connectors, with their content
            project_id = scope.split("/", 1)[1] if scope.startswith("projects/") else None
            for p in ([self.world.project(project_id)] if project_id else self.world.projects(folder_id)):
                connector = self._connector_record(p, by_number=True)
                if connector:
                    results.append(SimpleNamespace(name=f"//vpcaccess.googleapis.com/{connector['name']}", asset_type="vpcaccess.googleapis.com/Connector",
                                                   project=f"projects/{p.project_number}", folders=[f"folders/{p.folder_id}"], organization=f"organizations/{self.world.org_id}",
                                                   parent_full_resource_name=f"//cloudresourcemanager.googleapis.com/projects/{p.project_number}",
                                                   versioned_resources=[{"version": "v1", "resource": connector}]))
        self.call("asset", "searchAllResources", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
        return results

    def _secret_results(self, profiles):
        """``secretmanager.googleapis.com/Secret`` and ``SecretVersion`` search results, named by project number, with the folder and the
        resource content the index carries: replication, rotation; a version's state and creation time."""
        results, now = [], datetime.now(timezone.utc)
        for p in profiles:
            privileges = p.privileges
            for name, kind in (privileges.secrets if privileges else ()):
                secret_name = f"projects/{p.project_number}/secrets/{name}"
                common = {"project": f"projects/{p.project_number}", "folders": [f"folders/{p.folder_id}"], "organization": f"organizations/{self.world.org_id}"}
                data = {"name": secret_name, "replication": {"userManaged": {"replicas": [{"location": "us-central1"}]}} if kind == "regional" else {"automatic": {}},
                        "createTime": _iso(400), "etag": "s"}
                if kind == "rotated":
                    data["rotation"] = {"nextRotationTime": (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"), "rotationPeriod": "7776000s"}
                results.append(SimpleNamespace(name=f"//secretmanager.googleapis.com/{secret_name}", asset_type="secretmanager.googleapis.com/Secret", create_time=now - timedelta(days=400),
                                               versioned_resources=[{"version": "v1", "resource": data}], **common))
                age, state = {"fresh": 20, "stale": 200, "rotated": 300, "regional": 200, "empty": 10}[kind], "DESTROYED" if kind == "empty" else "ENABLED"
                version = {"name": f"{secret_name}/versions/1", "state": state, "createTime": _iso(age)}
                results.append(SimpleNamespace(name=f"//secretmanager.googleapis.com/{secret_name}/versions/1", asset_type="secretmanager.googleapis.com/SecretVersion", create_time=now - timedelta(days=age),
                                               versioned_resources=[{"version": "v1", "resource": version}], **common))
        return results

    def list_assets(self, request):
        """The assets of the requested types under ``projects/``, ``folders/`` (its projects) or the organization (every project)."""
        parent, asset_types = request["parent"], set(request.get("asset_types", []))
        if parent.startswith("projects/"):
            project_id = parent.split("/", 1)[1]
            self.call("asset", "listAssets(project)", project_id=project_id)
            profile = self.world.project(project_id)
            found = self._resilience_assets(profile, asset_types)
            if "container.googleapis.com/Cluster" in asset_types:
                found += [self._cluster_asset(profile, c) for c in profile.gke_clusters]
            if "logging.googleapis.com/LogSink" in asset_types:
                found += self._sink_assets(profile)
            if "policy.k8s.io/PodDisruptionBudget" in asset_types:
                found += [a for c in profile.gke_clusters for a in self._pdb_assets(profile, c)]
            found += self._edge_assets(profile, asset_types)
            found += self._governance_assets(profile, asset_types)
            found += self._posture_assets(profile, asset_types)
            found += self._serverless_assets(profile, asset_types)
            found += self._observability_assets(profile, asset_types)
            found += self._firewall_assets(profile, asset_types)
            return found
        # Folder- or organization-wide listing: one pass over the projects in scope.
        folder_id = parent.split("/", 1)[1] if parent.startswith("folders/") else None
        found = []
        for profile in self.world.projects(folder_id):
            found += self._resilience_assets(profile, asset_types)
            if "container.googleapis.com/Cluster" in asset_types:
                found += [self._cluster_asset(profile, c) for c in profile.gke_clusters]
            if "logging.googleapis.com/LogSink" in asset_types:
                found += self._sink_assets(profile)
            if "policy.k8s.io/PodDisruptionBudget" in asset_types:
                found += [a for c in profile.gke_clusters for a in self._pdb_assets(profile, c)]
            found += self._edge_assets(profile, asset_types)
            found += self._governance_assets(profile, asset_types)
            found += self._posture_assets(profile, asset_types)
            found += self._serverless_assets(profile, asset_types)
            found += self._observability_assets(profile, asset_types)
            found += self._firewall_assets(profile, asset_types)
        self.call("asset", "listAssets(folder)" if folder_id else "listAssets(org)", pages=max(1, math.ceil(len(found) / PAGE_SIZE)))
        return found

    def _policy_results(self, scope, asset_types):
        """v18.5: the IAM policies under ``scope`` as the IAM-policy search returns them (an empty query): projects named by ID, each
        result with its project number, folders and organization; the folder(s) with empty policies; the organization's own policy in an
        organization search."""
        org = f"organizations/{self.world.org_id}"

        def result(name, asset_type, bindings, project="", folders=()):
            return SimpleNamespace(resource=f"//cloudresourcemanager.googleapis.com/{name}", asset_type=f"cloudresourcemanager.googleapis.com/{asset_type}",
                                   project=project, folders=list(folders), organization=org,
                                   policy=SimpleNamespace(bindings=[SimpleNamespace(role=b["role"], members=list(b["members"]), condition=None) for b in bindings]))
        if scope.startswith("projects/"):
            profiles, folders, with_org = [self.world.project(scope.split("/", 1)[1])], [], False
        else:
            folder_id = scope.split("/", 1)[1] if scope.startswith("folders/") else None
            profiles = self.world.projects(folder_id)
            folders, with_org = ([folder_id] if folder_id else list(self.world.folder_ids)), folder_id is None
        found = []
        if with_org and "cloudresourcemanager.googleapis.com/Organization" in asset_types:
            found.append(result(org, "Organization", self.world.org_iam_bindings()))
        if "cloudresourcemanager.googleapis.com/Folder" in asset_types:
            found += [result(f"folders/{fid}", "Folder", self.world.folder_iam_bindings(fid), folders=[f"folders/{fid}"]) for fid in folders]  # v18.7: the folders' own bindings
        if "cloudresourcemanager.googleapis.com/Project" in asset_types:
            found += [result(f"projects/{p.project_id}", "Project", self._project_policy_bindings(p), project=f"projects/{p.project_number}", folders=[f"folders/{p.folder_id}"])
                      for p in profiles]
        return found

    @staticmethod
    def _instance_posture_fields(profile, index, vm):
        """v18.5: what the VM checks read of an instance — labels (GKE nodes labelled), metadata items, the service account and its scopes,
        IP forwarding, the Shielded settings — the same from the inventory and from ``instances.aggregatedList``."""
        posture, project_id, number = profile.posture, profile.project_id, profile.project_number
        items = [{"key": "created-by", "value": f"projects/{project_id}/zones/{vm.zone}/instanceGroupManagers/mig-{vm.zone}"}] if vm.in_mig else []
        if posture is None:
            return {"labels": {"goog-gke-node": ""} if vm.gke else {}, "metadata": {"items": items}}
        account, loose = posture.vm_accounts[index], posture.vm_loose[index]
        email = f"{number}-compute@developer.gserviceaccount.com" if account.startswith("default") else f"vm-{index}@{project_id}.iam.gserviceaccount.com"
        scopes = ["https://www.googleapis.com/auth/cloud-platform"] if account in ("default-full", "dedicated") else [
            "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write"]
        if "serial" in loose:
            items.append({"key": "serial-port-enable", "value": "TRUE"})
        if "oslogin-off" in loose:
            items.append({"key": "enable-oslogin", "value": "FALSE"})
        shielded = {} if "no-shielded" in loose else {"enableSecureBoot": "no-secure-boot" not in loose, "enableVtpm": True, "enableIntegrityMonitoring": True}
        return {"labels": {"goog-gke-node": ""} if vm.gke else {}, "serviceAccounts": [{"email": email, "scopes": scopes}], "metadata": {"items": items},
                "canIpForward": vm.gke or "ipfwd" in loose, "shieldedInstanceConfig": shielded}

    def _posture_assets(self, profile, asset_types):
        """v18.5: the project's instances (as the VM checks read them: service accounts and scopes, metadata, IP forwarding, Shielded
        settings; GKE nodes labelled as such) and its compute project (the common instance metadata)."""
        posture, project_id, number = profile.posture, profile.project_id, profile.project_number
        if posture is None:
            return []
        found = []
        if "compute.googleapis.com/Instance" in asset_types:
            for index, vm in enumerate(profile.vms):
                stopped = vm.name in profile.stopped_vms
                access = [{"name": "External NAT", "type": "ONE_TO_ONE_NAT", **({} if stopped else {"natIP": "203.0.113.10"})}] if vm.external_ip else None
                found.append(SimpleNamespace(name=f"//compute.googleapis.com/projects/{project_id}/zones/{vm.zone}/instances/{vm.name}", resource=SimpleNamespace(data={
                    "name": vm.name, "status": "TERMINATED" if stopped else "RUNNING", "tags": {"items": ["web"]} if index == 0 else {},
                    "networkInterfaces": [{"name": "nic0", "network": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/vpc-main", **({"accessConfigs": access} if access else {})}],  # v19
                    "zone": f"https://www.googleapis.com/compute/v1/projects/{project_id}/zones/{vm.zone}", **self._instance_posture_fields(profile, index, vm)})))
        if "compute.googleapis.com/Project" in asset_types:  # the inventory's copy: without the ssh-keys item, as the real one
            items = [i for i in self._project_metadata_items(profile) if i["key"] != "ssh-keys"]
            found.append(SimpleNamespace(name=f"//compute.googleapis.com/projects/{project_id}", resource=SimpleNamespace(data={
                "name": project_id, "defaultServiceAccount": f"{number}-compute@developer.gserviceaccount.com", "commonInstanceMetadata": {"items": items}})))
        return found

    # --- v18.6: serverless and edge exposure ---

    @staticmethod
    def _serverless_region(profile):
        return profile.subnets[0][1] if profile.subnets else "us-central1"

    def _service_record(self, profile, name, exposure, account, v2=False):
        """A Cloud Run service as the inventory (Knative v1) or the v2 API shows it."""
        project_id, number, region = profile.project_id, profile.project_number, self._serverless_region(profile)
        email = f"{number}-compute@developer.gserviceaccount.com" if account == "default" else f"{name}@{project_id}.iam.gserviceaccount.com"
        ingress = "internal" if exposure == "internal" else "internal-and-cloud-load-balancing" if exposure == "behind-lb-locked" else "all"
        levers = profile.cost_levers
        first = bool(profile.serverless and profile.serverless.services and profile.serverless.services[0][0] == name)
        connector = f"projects/{project_id}/locations/{region}/connectors/conn-main" if first and levers and levers.connector == "used" else ""
        other_region = next(r for r in REGIONS if r != region)
        sql_instance = f"{project_id}:{other_region}:sql-0" if first and levers and levers.cross_region_sql else ""
        if v2:
            data = {"name": f"projects/{project_id}/locations/{region}/services/{name}", "uri": f"https://{name}-{number}.{region}.run.app",
                    "ingress": {"all": "INGRESS_TRAFFIC_ALL", "internal": "INGRESS_TRAFFIC_INTERNAL_ONLY", "internal-and-cloud-load-balancing": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"}[ingress],
                    "template": {"serviceAccount": email}, "labels": {}}
            if exposure == "iap":
                data["iapEnabled"] = True
            if exposure == "public-setting":
                data["invokerIamDisabled"] = True
            if connector:  # v18.8
                data["template"]["vpcAccess"] = {"connector": connector, "egress": "PRIVATE_RANGES_ONLY"}
            if sql_instance:
                data["template"]["volumes"] = [{"name": "cloudsql", "cloudSqlInstance": {"instances": [sql_instance]}}]
            return data
        annotations = {"run.googleapis.com/ingress": ingress, "run.googleapis.com/ingress-status": ingress}
        if exposure == "iap":
            annotations["run.googleapis.com/iap-enabled"] = "true"
        if exposure == "public-setting":
            annotations["run.googleapis.com/invoker-iam-disabled"] = "true"
        template_annotations = {}  # v18.8: the revision template's annotations, where the connector and the Cloud SQL instances live
        if connector:
            template_annotations["run.googleapis.com/vpc-access-connector"] = "conn-main"
            template_annotations["run.googleapis.com/vpc-access-egress"] = "private-ranges-only"
        if sql_instance:
            template_annotations["run.googleapis.com/cloudsql-instances"] = sql_instance
        return {"apiVersion": "serving.knative.dev/v1", "kind": "Service", "metadata": {"name": name, "namespace": number, "annotations": annotations, "labels": {"cloud.googleapis.com/location": region}},
                "spec": {"template": {"metadata": {"annotations": template_annotations}, "spec": {"serviceAccountName": email, "containers": [{"image": f"gcr.io/{project_id}/{name}"}]}}},
                "status": {"url": f"https://{name}-{number}.{region}.run.app"}}

    def _function_record(self, profile, v2=False):
        """The project's Cloud Function (gen 1: a flat ``CloudFunction``; gen 2: ``serviceConfig`` naming its Cloud Run service) or ``None``."""
        s, project_id, region = profile.serverless, profile.project_id, self._serverless_region(profile)
        if s is None or s.function == "none":
            return None
        name = f"projects/{project_id}/locations/{region}/functions/fn-main"
        if s.function == "gen2":
            return {"name": name, "environment": "GEN_2", "state": "ACTIVE", "serviceConfig": {"service": f"projects/{project_id}/locations/{region}/services/fn-main",
                                                                                               "serviceAccountEmail": f"{profile.project_number}-compute@developer.gserviceaccount.com", "ingressSettings": "ALLOW_ALL"}}
        ingress = "ALLOW_ALL" if s.function == "gen1-public" else "ALLOW_INTERNAL_ONLY"
        email = f"{project_id}@appspot.gserviceaccount.com"
        if v2:
            return {"name": name, "environment": "GEN_1", "state": "ACTIVE", "serviceConfig": {"ingressSettings": ingress, "serviceAccountEmail": email, "uri": f"https://{region}-{project_id}.cloudfunctions.net/fn-main"}}
        return {"name": name, "status": "ACTIVE", "ingressSettings": ingress, "serviceAccountEmail": email, "httpsTrigger": {"url": f"https://{region}-{project_id}.cloudfunctions.net/fn-main"}, "runtime": "python312"}

    @staticmethod
    def _armor_rules(armor):
        default = {"priority": 2147483647, "action": "allow", "preview": False, "match": {"versionedExpr": "SRC_IPS_V1", "config": {"srcIpRanges": ["*"]}}}
        waf = {"legacy": [{"priority": 1000, "action": "deny-403", "preview": False, "match": {"expr": {"expression": "evaluatePreconfiguredExpr('sqli-stable', ['owasp-crs-v030001-id942110-sqli'])"}}}],
               "empty": [], "preview": [{"priority": 1000, "action": "deny-403", "preview": True, "match": {"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v422-stable')"}}}],
               "modern": [{"priority": 1000, "action": "deny-403", "preview": False, "match": {"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v422-stable') || evaluatePreconfiguredWaf('xss-v422-stable')"}}}]}
        return waf[armor] + [default]

    def _certificate_record(self, profile):
        s, project_id = profile.serverless, profile.project_id
        if s is None or s.certificate == "none":
            return None
        data = {"name": "edge-cert", "selfLink": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/sslCertificates/edge-cert", "creationTimestamp": _iso(40)}
        if s.certificate == "managed-failed":
            return {**data, "type": "MANAGED", "managed": {"domains": [f"www.{project_id}.example"], "status": "PROVISIONING_FAILED", "domainStatus": {f"www.{project_id}.example": "FAILED_NOT_VISIBLE"}}}
        days = {"fine": -300, "expiring": -12, "expired": 4}[s.certificate]  # _iso counts days ago: negative = in the future
        return {**data, "type": "SELF_MANAGED", "subjectAlternativeNames": [f"www.{project_id}.example"], "expireTime": _iso(days)}

    def _serverless_assets(self, profile, asset_types):
        """The project's serverless and edge-security assets (v18.6): Cloud Run services and a job, a function, the serverless NEG and the
        external backend service of the services behind a load balancer, the edge policy's content, the edge certificate."""
        s, project_id, number, region = profile.serverless, profile.project_id, profile.project_number, self._serverless_region(profile)
        if s is None:
            return []
        compute = f"https://www.googleapis.com/compute/v1/projects/{project_id}"
        found = []

        def asset(service, path, data):
            found.append(SimpleNamespace(name=f"//{service}.googleapis.com/projects/{project_id}/{path}",
                                         resource=SimpleNamespace(data=data, parent=f"//cloudresourcemanager.googleapis.com/projects/{number}")))

        if "run.googleapis.com/Service" in asset_types:
            for name, exposure, account in s.services:
                asset("run", f"locations/{region}/services/{name}", self._service_record(profile, name, exposure, account))
            if s.function == "gen2":
                record = self._service_record(profile, "fn-main", "public-binding", "default")
                record["metadata"]["labels"]["goog-managed-by"] = "cloudfunctions"
                asset("run", f"locations/{region}/services/fn-main", record)
        if "run.googleapis.com/Job" in asset_types and s.job_account:
            email = f"{number}-compute@developer.gserviceaccount.com" if s.job_account == "default" else f"nightly@{project_id}.iam.gserviceaccount.com"
            asset("run", f"locations/{region}/jobs/nightly", {"apiVersion": "run.googleapis.com/v1", "kind": "Job", "metadata": {"name": "nightly", "namespace": number},
                                                             "spec": {"template": {"spec": {"template": {"spec": {"serviceAccountName": email, "containers": [{"image": "gcr.io/x/nightly"}]}}}}}})
        function = self._function_record(profile)
        if function and (("cloudfunctions.googleapis.com/Function" in asset_types) if s.function == "gen2" else ("cloudfunctions.googleapis.com/CloudFunction" in asset_types)):
            asset("cloudfunctions", f"locations/{region}/functions/fn-main", function)
        fronted = [name for name, exposure, _ in s.services if exposure.startswith("behind-lb")]
        if fronted and "compute.googleapis.com/NetworkEndpointGroup" in asset_types:
            for name in fronted:
                asset("compute", f"regions/{region}/networkEndpointGroups/neg-{name}", {"name": f"neg-{name}", "networkEndpointType": "SERVERLESS", "region": f"{compute}/regions/{region}",
                                                                                       "selfLink": f"{compute}/regions/{region}/networkEndpointGroups/neg-{name}", "cloudRun": {"service": name}})
        if fronted and "compute.googleapis.com/BackendService" in asset_types:
            asset("compute", "global/backendServices/run-bes", {"name": "run-bes", "loadBalancingScheme": "EXTERNAL_MANAGED", "protocol": "HTTPS", "logConfig": {"enable": True},
                                                                "selfLink": f"{compute}/global/backendServices/run-bes", "securityPolicy": f"{compute}/global/securityPolicies/edge",
                                                                "backends": [{"group": f"{compute}/regions/{region}/networkEndpointGroups/neg-{name}"} for name in fronted]})
        edge = profile.network_edge
        armored = fronted or (edge is not None and edge.lb == "https-modern")  # the policy is attached: by run-bes or by the armored edge-bes
        if armored and "compute.googleapis.com/SecurityPolicy" in asset_types:
            asset("compute", "global/securityPolicies/edge", {"name": "edge", "type": "CLOUD_ARMOR", "selfLink": f"{compute}/global/securityPolicies/edge", "rules": self._armor_rules(s.armor)})
        certificate = self._certificate_record(profile)
        if certificate and edge is not None and edge.lb.startswith("https") and "compute.googleapis.com/SslCertificate" in asset_types:
            asset("compute", "global/sslCertificates/edge-cert", certificate)
        connector = self._connector_record(profile, by_number=True)  # v18.8: the inventory names it by project number
        if connector and "vpcaccess.googleapis.com/Connector" in asset_types:
            found.append(SimpleNamespace(name=f"//vpcaccess.googleapis.com/{connector['name']}",
                                         resource=SimpleNamespace(data=connector, parent=f"//cloudresourcemanager.googleapis.com/projects/{number}")))
        return found

    def _h_run_projects_locations_services_list(self, kw, project_id):
        self.call("run", "services.list", project_id=project_id, style="http")
        profile, s = self.world.project(project_id), self.world.project(project_id).serverless
        services = [self._service_record(profile, name, exposure, account, v2=True) for name, exposure, account in (s.services if s else ())]
        if s and s.function == "gen2":
            record = self._service_record(profile, "fn-main", "public-binding", "default", v2=True)
            record["labels"]["goog-managed-by"] = "cloudfunctions"
            services.append(record)
        return {"services": services}

    def _h_run_projects_locations_services_getIamPolicy(self, kw, project_id):
        resource = str(kw.get("resource", ""))
        project_id = _project_of(resource)
        self.call("run", "services.getIamPolicy", project_id=project_id, style="http")
        s, name = self.world.project(project_id).serverless, resource.rsplit("/", 1)[-1]
        public = name == "fn-main" or any(n == name and exposure in ("public-binding", "behind-lb-locked") for n, exposure, _ in (s.services if s else ()))
        return {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}], "etag": "synthetic"} if public else {"etag": "synthetic"}

    def _h_run_projects_locations_jobs_list(self, kw, project_id):
        self.call("run", "jobs.list", project_id=project_id, style="http")
        profile, s = self.world.project(project_id), self.world.project(project_id).serverless
        if not (s and s.job_account):
            return {}
        email = f"{profile.project_number}-compute@developer.gserviceaccount.com" if s.job_account == "default" else f"nightly@{project_id}.iam.gserviceaccount.com"
        return {"jobs": [{"name": f"projects/{project_id}/locations/{self._serverless_region(profile)}/jobs/nightly", "template": {"template": {"serviceAccount": email}}}]}

    def _h_cloudfunctions_projects_locations_functions_list(self, kw, project_id):
        self.call("cloudfunctions", "functions.list", project_id=project_id, style="http")
        function = self._function_record(self.world.project(project_id), v2=True)
        return {"functions": [function]} if function else {}

    def _h_compute_securityPolicies_aggregatedList(self, kw, project_id):
        self.call("compute", "securityPolicies.aggregatedList", project_id=project_id, style="http")
        policies = [a.resource.data for a in self._serverless_assets(self.world.project(project_id), {"compute.googleapis.com/SecurityPolicy"})]
        return {"items": {"global": {"securityPolicies": policies}}} if policies else {"items": {}}

    def _h_compute_sslCertificates_aggregatedList(self, kw, project_id):
        self.call("compute", "sslCertificates.aggregatedList", project_id=project_id, style="http")
        certificates = [a.resource.data for a in self._serverless_assets(self.world.project(project_id), {"compute.googleapis.com/SslCertificate"})]
        return {"items": {"global": {"sslCertificates": certificates}}} if certificates else {"items": {}}

    def _repository_results(self, profiles):
        """``artifactregistry.googleapis.com/Repository`` search results: Docker repositories, named by project ID, with the project number."""
        results = []
        for p in profiles:
            s = p.serverless
            for i in range(s.repositories if s else 0):
                name = f"//artifactregistry.googleapis.com/projects/{p.project_id}/locations/us/repositories/images-{i}"
                results.append(SimpleNamespace(name=name, asset_type="artifactregistry.googleapis.com/Repository", project=f"projects/{p.project_number}",
                                               versioned_resources=[{"version": "v1", "resource": {"name": name.split("//artifactregistry.googleapis.com/")[1], "format": "DOCKER", "mode": "STANDARD_REPOSITORY"}}]))
        return results

    COMMON_SERVICES = ("compute.googleapis.com", "storage.googleapis.com", "logging.googleapis.com", "monitoring.googleapis.com", "iam.googleapis.com", "cloudresourcemanager.googleapis.com",
                       "serviceusage.googleapis.com", "bigquery.googleapis.com", "pubsub.googleapis.com", "cloudasset.googleapis.com")

    def _enabled_service_results(self, profiles, query):
        """``serviceusage.googleapis.com/Service`` search results for ``name:<service>``: one per project where the world has the service on;
        without a query (v19.1, the footprint) the common services of every project plus the ones the project's workloads imply."""
        def result(p, service):
            return SimpleNamespace(name=f"//serviceusage.googleapis.com/projects/{p.project_number}/services/{service}", asset_type="serviceusage.googleapis.com/Service",
                                   project=f"projects/{p.project_number}", state="ENABLED", location="global")
        if not query:
            results = []
            for p in profiles:
                services = list(self.COMMON_SERVICES) + (["container.googleapis.com"] if p.gke_clusters else []) + (["sqladmin.googleapis.com"] if p.sql_instances else []) + \
                           (["run.googleapis.com"] if p.serverless and p.serverless.services else []) + (["containerscanning.googleapis.com"] if p.serverless and p.serverless.scanning else [])
                results += [result(p, service) for service in services]
            return results
        service = query.split("name:", 1)[-1].strip()
        return [result(p, service) for p in profiles if service == "containerscanning.googleapis.com" and p.serverless and p.serverless.scanning]

    def _footprint_results(self, profiles, asset_types, with_content):
        """v19.1: the all-types search (names, types, locations, projects) over the world's inventory, or — with ``versionedResources`` in the
        read mask — the content of the versioned types (GKE clusters, Cloud SQL and Compute instances)."""
        org = f"organizations/{self.world.org_id}"
        results = []

        def add(asset_type, name, location, p, data=None):
            if asset_types and asset_type not in asset_types:
                return
            results.append(SimpleNamespace(name=name, asset_type=asset_type, location=location, project=f"projects/{p.project_number}", state="ACTIVE", organization=org,
                                           folders=[f"folders/{p.folder_id}"], versioned_resources=[{"version": "v1", "resource": data}] if with_content and data is not None else []))
        for p in profiles:
            pid, region = p.project_id, self._serverless_region(p)
            if not with_content:
                add("cloudresourcemanager.googleapis.com/Project", f"//cloudresourcemanager.googleapis.com/projects/{pid}", "global", p)
            for index, vm in enumerate(p.vms):
                stopped = vm.name in p.stopped_vms
                add("compute.googleapis.com/Instance", f"//compute.googleapis.com/projects/{pid}/zones/{vm.zone}/instances/{vm.name}", vm.zone, p,
                    {"machineType": MACHINE_TYPE_URL.format(project=pid, zone=vm.zone, machine_type=vm.machine_type), "status": "TERMINATED" if stopped else "RUNNING"})
                if not with_content:
                    add("compute.googleapis.com/Disk", f"//compute.googleapis.com/projects/{pid}/zones/{vm.zone}/disks/{vm.name}", vm.zone, p)
            for cluster in p.gke_clusters:
                add("container.googleapis.com/Cluster", f"//container.googleapis.com/projects/{pid}/locations/{cluster.location}/clusters/{cluster.name}", cluster.location, p,
                    {"currentMasterVersion": cluster.master_version, "releaseChannel": {"channel": "REGULAR"} if cluster.release_channel else {}, "currentNodeCount": 3 * len(cluster.node_pools)})
            for sql in p.sql_instances:
                add("sqladmin.googleapis.com/Instance", f"//cloudsql.googleapis.com/projects/{pid}/instances/{sql.name}", region, p, {"databaseVersion": sql.database_version, "settings": {"tier": "db-custom-2-7680"}})
            if not with_content:
                for bucket in p.buckets:
                    add("storage.googleapis.com/Bucket", f"//storage.googleapis.com/{bucket.name}", region, p)
                for name, _, _ in (p.serverless.services if p.serverless else ()):
                    add("run.googleapis.com/Service", f"//run.googleapis.com/projects/{pid}/locations/{region}/services/{name}", region, p)
                for sa in p.service_accounts:
                    add("iam.googleapis.com/ServiceAccount", f"//iam.googleapis.com/projects/{pid}/serviceAccounts/{sa.email}", "global", p)
                for name, _, _ in p.firewall_rules:
                    add("compute.googleapis.com/Firewall", f"//compute.googleapis.com/projects/{pid}/global/firewalls/{name}", "global", p)
                add("compute.googleapis.com/Network", f"//compute.googleapis.com/projects/{pid}/global/networks/vpc-main", "global", p)
                for name, subnet_region, _ in p.subnets:
                    add("compute.googleapis.com/Subnetwork", f"//compute.googleapis.com/projects/{pid}/regions/{subnet_region}/subnetworks/{name}", subnet_region, p)
                for i in range(p.single_region_snapshots + p.multi_region_snapshots):
                    add("compute.googleapis.com/Snapshot", f"//compute.googleapis.com/projects/{pid}/global/snapshots/snap-{i}", "us", p)
                for dataset_id, _, _ in (p.data_governance.datasets if p.data_governance else ()):
                    add("bigquery.googleapis.com/Dataset", f"//bigquery.googleapis.com/projects/{pid}/datasets/{dataset_id}", "US", p)
                for i in range(2):
                    add("datalineage.googleapis.com/Process", f"//datalineage.googleapis.com/projects/{p.project_number}/locations/{region}/processes/p{i}", region, p)
                add("logging.googleapis.com/LogBucket", f"//logging.googleapis.com/projects/{pid}/locations/global/buckets/_Default", "global", p)
                add("orgpolicy.googleapis.com/Policy", f"//orgpolicy.googleapis.com/projects/{pid}/policies/compute.vmExternalIpAccess", "global", p)
                add("appengine.googleapis.com/Version", f"//appengine.googleapis.com/apps/{pid}/services/default/versions/v1", region, p)  # an "Other" type
        return results

    @staticmethod
    def _sink_assets(profile):
        """The project's log sinks (v18.1): one per bucket the world marks as a sink destination."""
        return [SimpleNamespace(name=f"//logging.googleapis.com/projects/{profile.project_id}/sinks/sink-{i}",
                                resource=SimpleNamespace(data={"name": f"sink-{i}", "destination": f"storage.googleapis.com/{bucket}"}))
                for i, bucket in enumerate(profile.sink_buckets)]

    def _edge_assets(self, profile, asset_types):
        """The project's network-edge assets (v18.3) for the asset types asked: its ``vpc-main`` network and subnets, a legacy network,
        a Cloud Router with a NAT, HA or Classic VPN, Interconnect attachments, an external load balancer, DNS zones and policies, a
        firewall policy — as Asset Inventory shows them (``NetworkEdge``). ``ForwardingRule`` assets double as the Incident Exposure
        footprint of earlier releases (``forwarding_rule_regions``)."""
        edge, project_id, number = profile.network_edge, profile.project_id, profile.project_number
        if edge is None:
            return []
        compute = f"https://www.googleapis.com/compute/v1/projects/{project_id}"
        region = profile.subnets[0][1] if profile.subnets else "us-central1"
        found = []

        def asset(service, path, data):
            found.append(SimpleNamespace(name=f"//{service}.googleapis.com/projects/{project_id}/{path}",
                                         resource=SimpleNamespace(data=data, parent=f"//cloudresourcemanager.googleapis.com/projects/{number}")))

        if "compute.googleapis.com/Network" in asset_types:
            peerings = []
            if edge.peer_index >= 0:
                peer_id = self.world.project_id(edge.peer_index)
                peerings.append({"name": f"to-{peer_id}", "network": f"https://www.googleapis.com/compute/v1/projects/{peer_id}/global/networks/vpc-main",
                                 "state": "ACTIVE" if edge.peering_active else "INACTIVE"})
            peerings.append({"name": "servicenetworking-googleapis-com", "network": "https://www.googleapis.com/compute/v1/projects/p-google/global/networks/sn", "state": "ACTIVE"})
            asset("compute", "global/networks/vpc-main", {"name": "vpc-main", "selfLink": f"{compute}/global/networks/vpc-main", "mtu": edge.mtu, "peerings": peerings})
            if edge.legacy_network:
                asset("compute", "global/networks/legacy-net", {"name": "legacy-net", "selfLink": f"{compute}/global/networks/legacy-net", "IPv4Range": "10.240.0.0/16"})
        if "compute.googleapis.com/Subnetwork" in asset_types:
            for position, (name, subnet_region, pga) in enumerate(profile.subnets):
                asset("compute", f"regions/{subnet_region}/subnetworks/{name}",
                      {"name": name, "region": f"{compute}/regions/{subnet_region}", "network": f"{compute}/global/networks/vpc-main", "purpose": "PRIVATE",
                       "privateIpGoogleAccess": pga, **self._subnet_log_config(profile, position)})
            if profile.proxy_subnet and profile.subnets:
                asset("compute", f"regions/{region}/subnetworks/proxy-only", {"name": "proxy-only", "region": f"{compute}/regions/{region}", "purpose": "REGIONAL_MANAGED_PROXY",
                                                                             "network": f"{compute}/global/networks/vpc-main", "enableFlowLogs": False})
        if "compute.googleapis.com/Router" in asset_types and (edge.nat != "none" or edge.vpn.startswith("ha") or edge.interconnect != "none"):
            nats = [] if edge.nat == "none" else [{"name": "nat-main", "natIpAllocateOption": "AUTO_ONLY", "logConfig": {"enable": edge.nat == "tuned", "filter": "ERRORS_ONLY"},
                                                   **({"enableDynamicPortAllocation": True, "minPortsPerVm": 64, "maxPortsPerVm": 4096} if edge.nat == "tuned" else {})}]
            if edge.nat != "none":
                nats.append({"name": "swg-autogen-nat", "natIpAllocateOption": "AUTO_ONLY", "logConfig": {"enable": True, "filter": "ERRORS_ONLY"}})
            peers = [{"name": "peer-0", "enable": "TRUE"}] + ([{"name": "peer-1", "enable": "TRUE"}] if edge.vpn == "ha-two" or edge.interconnect == "redundant" else [])
            asset("compute", f"regions/{region}/routers/router-main", {"name": "router-main", "region": f"{compute}/regions/{region}", "network": f"{compute}/global/networks/vpc-main",
                                                                        "selfLink": f"{compute}/regions/{region}/routers/router-main", "bgp": {"asn": 65001}, "bgpPeers": peers, "nats": nats})
        router = f"{compute}/regions/{region}/routers/router-main"
        if "compute.googleapis.com/VpnGateway" in asset_types and edge.vpn.startswith("ha"):
            asset("compute", f"regions/{region}/vpnGateways/vpn-gw", {"name": "vpn-gw", "region": f"{compute}/regions/{region}", "network": f"{compute}/global/networks/vpc-main",
                                                                       "selfLink": f"{compute}/regions/{region}/vpnGateways/vpn-gw", "vpnInterfaces": [{"id": 0}, {"id": 1}]})
        if "compute.googleapis.com/VpnTunnel" in asset_types and edge.vpn.startswith("ha"):
            for interface in ([0] if edge.vpn == "ha-one" else [0, 1]):
                asset("compute", f"regions/{region}/vpnTunnels/tunnel-{interface}",
                      {"name": f"tunnel-{interface}", "region": f"{compute}/regions/{region}", "vpnGateway": f"{compute}/regions/{region}/vpnGateways/vpn-gw",
                       "vpnGatewayInterface": interface, "router": router, **self._tunnel_state(edge, interface)})
        if "compute.googleapis.com/TargetVpnGateway" in asset_types and edge.vpn == "classic":
            asset("compute", f"regions/{region}/targetVpnGateways/classic-gw", {"name": "classic-gw", "region": f"{compute}/regions/{region}", "network": f"{compute}/global/networks/vpc-main"})
        if "compute.googleapis.com/InterconnectAttachment" in asset_types and edge.interconnect != "none":
            for n, domain in enumerate(["AVAILABILITY_DOMAIN_1"] + (["AVAILABILITY_DOMAIN_2"] if edge.interconnect == "redundant" else [])):
                asset("compute", f"regions/{region}/interconnectAttachments/attach-{n}", {"name": f"attach-{n}", "region": f"{compute}/regions/{region}", "router": router,
                                                                                         "edgeAvailabilityDomain": domain, "operationalStatus": "OS_ACTIVE", "type": "DEDICATED"})
        if "compute.googleapis.com/ForwardingRule" in asset_types:
            for r in profile.forwarding_rule_regions:  # the Incident Exposure footprint: internal passthrough rules, no edge rows
                asset("compute", f"regions/{r}/forwardingRules/lb-{r}", {"name": f"lb-{r}", "loadBalancingScheme": "INTERNAL", "region": f"{compute}/regions/{r}"})
        if edge.lb != "none" and "compute.googleapis.com/GlobalForwardingRule" in asset_types:
            proxy_kind = "targetHttpProxies" if edge.lb == "http" else "targetHttpsProxies"
            asset("compute", "global/forwardingRules/edge-fr", {"name": "edge-fr", "loadBalancingScheme": "EXTERNAL", "portRange": "80-80" if edge.lb == "http" else "443-443",
                                                               "IPProtocol": "TCP", "IPAddress": self._lb_address(profile), "target": f"{compute}/global/{proxy_kind}/edge-proxy"})
        if edge.lb == "http" and "compute.googleapis.com/TargetHttpProxy" in asset_types:
            asset("compute", "global/targetHttpProxies/edge-proxy", {"name": "edge-proxy", "selfLink": f"{compute}/global/targetHttpProxies/edge-proxy", "urlMap": f"{compute}/global/urlMaps/edge-map"})
        if edge.lb.startswith("https") and "compute.googleapis.com/TargetHttpsProxy" in asset_types:
            certificate = profile.serverless.certificate if profile.serverless else "none"  # v18.6
            asset("compute", "global/targetHttpsProxies/edge-proxy", {"name": "edge-proxy", "selfLink": f"{compute}/global/targetHttpsProxies/edge-proxy", "urlMap": f"{compute}/global/urlMaps/edge-map",
                                                                     **({"sslPolicy": f"{compute}/global/sslPolicies/modern-tls"} if edge.lb == "https-modern" else {}),
                                                                     **({"sslCertificates": [f"{compute}/global/sslCertificates/edge-cert"]} if certificate != "none" else {})})
        if edge.lb == "https-modern" and "compute.googleapis.com/SslPolicy" in asset_types:
            asset("compute", "global/sslPolicies/modern-tls", {"name": "modern-tls", "selfLink": f"{compute}/global/sslPolicies/modern-tls", "profile": "MODERN", "minTlsVersion": "TLS_1_2"})
        if edge.lb != "none" and "compute.googleapis.com/BackendService" in asset_types:
            armored = edge.lb == "https-modern"
            asset("compute", "global/backendServices/edge-bes", {"name": "edge-bes", "loadBalancingScheme": "EXTERNAL", "protocol": "HTTP", "logConfig": {"enable": armored},
                                                                **({"securityPolicy": f"{compute}/global/securityPolicies/edge"} if armored else {})})
        if edge.dns_zone != "none" and "dns.googleapis.com/ManagedZone" in asset_types:
            config = {"none": {}, "plain": {"state": "off"}, "signed": {"state": "on", "defaultKeySpecs": [{"algorithm": "ecdsap256sha256", "keyType": "keySigning"}]},
                      "rsasha1": {"state": "on", "defaultKeySpecs": [{"algorithm": "rsasha1", "keyType": "keySigning"}, {"algorithm": "rsasha1", "keyType": "zoneSigning"}]}}[edge.dns_zone]
            asset("dns", "managedZones/public-zone", {"name": "public-zone", "dnsName": f"{project_id}.example.", "visibility": "public", "dnssecConfig": config})
        if edge.dns_logging and "dns.googleapis.com/Policy" in asset_types:
            asset("dns", "policies/dns-logging", {"name": "dns-logging", "enableLogging": True, "networks": [{"networkUrl": f"{compute}/global/networks/vpc-main"}]})
        if edge.firewall_policy and "compute.googleapis.com/FirewallPolicy" in asset_types:
            asset("compute", "global/firewallPolicies/900001", {"name": "900001", "displayName": "edge-policy", "shortName": "edge-policy",
                                                              "associations": [{"name": "vpc-main", "attachmentTarget": f"projects/{project_id}/global/networks/vpc-main"}],
                                                              "rules": [{"priority": 100, "direction": "INGRESS", "action": "allow", "disabled": False,
                                                                         "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}},
                                                                        {"priority": 2147483647, "direction": "INGRESS", "action": "goto_next", "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "all"}]}}]})
        return found

    @staticmethod
    def _tunnel_state(edge, interface):
        """The state of a synthetic tunnel: established on an ``ha-two`` gateway, waiting on an ``ha-one`` one."""
        if edge.vpn == "ha-two":
            return {"status": "ESTABLISHED", "detailedStatus": "Tunnel is up and running."}
        return {"status": "NO_INCOMING_PACKETS", "detailedStatus": "No incoming packets from peer"}

    def _h_compute_vpnTunnels_aggregatedList(self, kw, project_id):
        """The tunnels' current state (v18.3: *Hybrid Connectivity* re-reads it from the API; the synthetic world agrees with its inventory)."""
        self.call("compute", "vpnTunnels.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        edge = profile.network_edge
        if edge and edge.vpn.startswith("ha"):
            region = profile.subnets[0][1] if profile.subnets else "us-central1"
            items[f"regions/{region}"] = {"vpnTunnels": [{"name": f"tunnel-{i}", **self._tunnel_state(edge, i)} for i in ([0] if edge.vpn == "ha-one" else [0, 1])]}
        return {"items": items}

    def _governance_assets(self, profile, asset_types):
        """The project's data-governance assets (v18.4): BigQuery datasets, an AlloyDB cluster and instance, KMS keys, API keys."""
        g, project_id, number = profile.data_governance, profile.project_id, profile.project_number
        if g is None:
            return []
        region = profile.subnets[0][1] if profile.subnets else "us-central1"
        found = []

        def asset(service, path, data):
            found.append(SimpleNamespace(name=f"//{service}.googleapis.com/projects/{project_id}/{path}",
                                         resource=SimpleNamespace(data=data, parent=f"//cloudresourcemanager.googleapis.com/projects/{number}")))

        if "bigquery.googleapis.com/Dataset" in asset_types:
            for dataset_id, hours, public in g.datasets:
                access = [{"role": "OWNER", "specialGroup": "projectOwners"}, {"role": "READER", "specialGroup": "projectReaders"}]
                if public:
                    access.append({"role": "READER", "specialGroup": "allAuthenticatedUsers"})
                asset("bigquery", f"datasets/{dataset_id}", {"datasetReference": {"datasetId": dataset_id, "projectId": project_id}, "access": access,
                                                             **({"maxTimeTravelHours": str(hours)} if hours != 168 else {}), "location": "US"})
        if g.alloydb != "none":
            good = g.alloydb == "regional-good"
            if "alloydb.googleapis.com/Cluster" in asset_types:
                asset("alloydb", f"locations/{region}/clusters/alloy-main", {"name": f"projects/{project_id}/locations/{region}/clusters/alloy-main",
                                                                           "automatedBackupPolicy": {"enabled": good}, "continuousBackupConfig": {"enabled": good}})
            if "alloydb.googleapis.com/Instance" in asset_types:
                asset("alloydb", f"locations/{region}/clusters/alloy-main/instances/alloy-primary",
                      {"name": f"projects/{project_id}/locations/{region}/clusters/alloy-main/instances/alloy-primary", "instanceType": "PRIMARY",
                       "availabilityType": "REGIONAL" if good else "ZONAL", "networkConfig": {"enablePublicIp": not good},
                       "clientConnectionConfig": {"sslConfig": {"sslMode": "ENCRYPTED_ONLY" if good else "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}},
                       "databaseFlags": {"log_connections": "on", "log_disconnections": "on"} if good else {}})
        if g.kms != "none" and "cloudkms.googleapis.com/CryptoKey" in asset_types:
            asset("cloudkms", f"locations/{region}/keyRings/ring-main/cryptoKeys/data-key",
                  {"name": f"projects/{project_id}/locations/{region}/keyRings/ring-main/cryptoKeys/data-key", "purpose": "ENCRYPT_DECRYPT", "primary": {"state": "ENABLED"},
                   **({"rotationPeriod": "7776000s", "nextRotationTime": _iso(-30)} if g.kms == "rotated" else {})})
            asset("cloudkms", f"locations/{region}/keyRings/ring-main/cryptoKeys/signing-key",
                  {"name": f"projects/{project_id}/locations/{region}/keyRings/ring-main/cryptoKeys/signing-key", "purpose": "ASYMMETRIC_SIGN", "primary": {"state": "ENABLED"}})
        if "apikeys.googleapis.com/Key" in asset_types:
            for i, (display, restricted, age) in enumerate(g.api_keys):  # the inventory names API keys by project number
                found.append(SimpleNamespace(name=f"//apikeys.googleapis.com/projects/{number}/locations/global/keys/{project_id}-k{i}",
                                             resource=SimpleNamespace(parent=f"//cloudresourcemanager.googleapis.com/projects/{number}", data={
                                                 "name": f"projects/{number}/locations/global/keys/{project_id}-k{i}", "uid": f"{project_id}-k{i}", "displayName": display, "createTime": _iso(age),
                                                 "restrictions": ({"apiTargets": [{"service": "storage.googleapis.com"}], "serverKeyRestrictions": {"allowedIps": ["203.0.113.0/24"]}} if restricted else {})})))
        return found

    @staticmethod
    def _pdb_assets(profile, cluster):
        """The cluster's ``policy.k8s.io/PodDisruptionBudget`` assets (v18.2), as the inventory shows Kubernetes objects: spec and status."""
        o = profile.gke_operations.get(cluster.name)
        # Numbers as the inventory delivers them: protobuf Struct floats (the first v18.2 canary read none of the budgets for that).
        shapes = {"system": ({"maxUnavailable": 1.0}, {"disruptionsAllowed": 1.0, "currentHealthy": 2.0, "desiredHealthy": 1.0, "expectedPods": 2.0}),
                  "blocking": ({"maxUnavailable": 0.0}, {"disruptionsAllowed": 0.0, "currentHealthy": 2.0, "desiredHealthy": 2.0, "expectedPods": 2.0}),
                  "exhausted": ({"minAvailable": 2.0}, {"disruptionsAllowed": 0.0, "currentHealthy": 2.0, "desiredHealthy": 2.0, "expectedPods": 3.0}),
                  "healthy": ({"maxUnavailable": "25%"}, {"disruptionsAllowed": 1.0, "currentHealthy": 4.0, "desiredHealthy": 3.0, "expectedPods": 4.0})}
        assets = []
        for namespace, name, kind in (o.pdbs if o else ()):
            spec, status = shapes[kind]
            assets.append(SimpleNamespace(
                name=f"//container.googleapis.com/projects/{profile.project_id}/locations/{cluster.location}/clusters/{cluster.name}/k8s/namespaces/{namespace}/policy/poddisruptionbudgets/{name}",
                resource=SimpleNamespace(data={"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": {"name": name, "namespace": namespace},
                                               "spec": {**spec, "selector": {"matchLabels": {"app": name.rsplit("-", 1)[0]}}}, "status": status},
                                         parent=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_number}")))
        return assets

    def _cluster_asset(self, profile, cluster):
        """A ``container.googleapis.com/Cluster`` asset with the fields the v17.1 checks read, from the cluster's GkeHardening."""
        h = profile.gke_hardening.get(cluster.name)
        o = profile.gke_operations.get(cluster.name)  # v18.2
        project_id = profile.project_id
        scopes = ["https://www.googleapis.com/auth/cloud-platform"] if (h and h.cloud_platform_scope) else [
            "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring"]
        pools = []
        for i, (name, auto, version) in enumerate(cluster.node_pools):
            gke_metadata = bool(h and i < len(h.gke_metadata_pools) and h.gke_metadata_pools[i])
            config = {"serviceAccount": "default" if (h is None or h.default_service_account) else f"gke-nodes@{project_id}.iam.gserviceaccount.com",
                      "oauthScopes": scopes, "metadata": {"disable-legacy-endpoints": "true"},
                      "imageType": "COS_CONTAINERD" if (h is None or h.cos_image) else "UBUNTU_CONTAINERD",
                      "shieldedInstanceConfig": {"enableSecureBoot": bool(h and h.secure_boot), "enableIntegrityMonitoring": o is None or o.integrity_monitoring}}
            if gke_metadata:
                config["workloadMetadataConfig"] = {"mode": "GKE_METADATA"}
            zones = (profile.gke_pool_zones.get(cluster.name) or ())
            if o and o.lagging_pool and i == 0:  # v18.2: two minors behind the control plane
                major, minor, rest = cluster.master_version.split(".", 2)
                version = f"{major}.{int(minor) - 2}.{rest}"
            unavailable = o.max_unavailable[i] if (o and i < len(o.max_unavailable)) else 0
            pools.append({"name": name, "version": version, "config": config, "management": {"autoUpgrade": auto},
                          **({"locations": list(zones[i])} if i < len(zones) else {}),  # v17.3
                          "upgradeSettings": {"strategy": "SURGE", "maxSurge": 1, **({"maxUnavailable": unavailable} if unavailable else {})},  # v18.2
                          "networkConfig": {"enablePrivateNodes": bool(h and h.private_nodes)}})
        data = {"name": cluster.name, "location": cluster.location, "status": "RUNNING", "currentMasterVersion": cluster.master_version,
                "nodePools": pools, "legacyAbac": {"enabled": bool(h and h.legacy_abac)}, "masterAuth": {"clusterCaCertificate": "c3ludGhldGlj"},
                "loggingConfig": {"componentConfig": {"enableComponents": ["SYSTEM_COMPONENTS"] + (["WORKLOADS"] if (h is None or h.workload_logs) else [])}},
                "databaseEncryption": {"state": "ENCRYPTED" if (h and h.secrets_encryption) else "DECRYPTED"},
                "securityPostureConfig": {"mode": "BASIC" if (h is None or h.security_posture) else "DISABLED",
                                          "vulnerabilityMode": "VULNERABILITY_BASIC" if (h and h.vulnerability_scanning) else "VULNERABILITY_DISABLED"},
                "shieldedNodes": {"enabled": h is None or h.shielded_nodes}, "anonymousAuthenticationConfig": {"mode": "LIMITED"},
                "privateClusterConfig": {"enablePrivateNodes": bool(h and h.private_nodes), "enablePrivateEndpoint": not (h is None or h.public_endpoint)},
                "masterAuthorizedNetworksConfig": {"enabled": bool(h and h.authorized_networks),
                                                   "cidrBlocks": ([{"cidrBlock": "0.0.0.0/0"}] if (h and h.open_authorized_networks) else [{"cidrBlock": "10.0.0.0/8"}])}}
        if cluster.release_channel:
            data["releaseChannel"] = {"channel": "REGULAR"}
        if h and h.autopilot:
            data["autopilot"] = {"enabled": True}
        if h and h.workload_identity:
            data["workloadIdentityConfig"] = {"workloadPool": f"{project_id}.svc.id.goog"}
        if h and h.client_certificate:
            data["masterAuth"]["clientCertificateConfig"] = {"issueClientCertificate": True}
        if h and h.network_policy:
            data["networkConfig"] = {"datapathProvider": "ADVANCED_DATAPATH"}
        if h and h.binary_authorization:
            data["binaryAuthorization"] = {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"}
        # v18.2: what the upgrade-readiness, observability and the three new hardening rules read.
        data["ipAllocationPolicy"] = {"useIpAliases": True}
        data.setdefault("networkConfig", {})["enableIntraNodeVisibility"] = bool(h and h.autopilot) or (o is None or o.intranode_visibility)
        components = (["SYSTEM_COMPONENTS"] if (o is None or o.system_metrics) else []) + (["APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"] if (o and o.control_plane_metrics) else [])
        data["monitoringConfig"] = {"componentConfig": {"enableComponents": components},
                                    "managedPrometheusConfig": {"enabled": bool(h and h.autopilot) or (o is None or o.managed_prometheus)}}
        data["addonsConfig"] = {"dnsCacheConfig": {"enabled": o is None or o.dns_cache}, "gcePersistentDiskCsiDriverConfig": {"enabled": True}}
        policy = {"resourceVersion": "e3b0c442"}
        if o and o.maintenance_window:
            policy["window"] = {"recurringWindow": {"window": {"startTime": "2026-01-03T18:00:00Z", "endTime": "2026-01-03T22:00:00Z"}, "recurrence": "FREQ=WEEKLY;BYDAY=SA,SU"}}
        if o and o.exclusion:
            policy.setdefault("window", {})["maintenanceExclusions"] = {"change-freeze": {
                "startTime": _iso(1), "endTime": _iso(-14), "maintenanceExclusionOptions": {"scope": "NO_MINOR_OR_NODE_UPGRADES"}}}
        data["maintenancePolicy"] = policy
        notifications = o.notifications if o else "on"
        data["notificationConfig"] = {"pubsub": {"enabled": True, "topic": f"projects/{project_id}/topics/gke-notifications",
                                                 **({"filter": {"eventType": ["UPGRADE_AVAILABLE_EVENT"]}} if notifications == "partial" else {})}
                                      if notifications != "off" else {}}
        return SimpleNamespace(name=f"//container.googleapis.com/projects/{project_id}/locations/{cluster.location}/clusters/{cluster.name}",
                               resource=SimpleNamespace(data=data, parent=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_number}"),
                               ancestors=[f"projects/{profile.project_number}", f"folders/{profile.folder_id}", f"organizations/{self.world.org_id}"])

    def search_all_iam_policies(self, request):
        """v17.1: the IAM policies that mention a service account (``policy:\"email\"``) or that open an impersonation path."""
        scope, query = request["scope"], request.get("query", "")
        folder_id = scope.split("/")[1] if scope.startswith("folders/") else None
        profiles = [self.world.project(scope.split("/", 1)[1])] if scope.startswith("projects/") else self.world.projects(folder_id)
        email = query.split('"')[1] if query.startswith('policy:"') else None
        results = []
        if email and (email.endswith("@gcp-sa-monitoring-notification.iam.gserviceaccount.com") or email.endswith("@gcp-sa-logging.iam.gserviceaccount.com")):  # v18.9
            results = self._agent_policy_results(profiles, email)
            self.call("asset", "searchAllIamPolicies", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
            return results
        if not query and any(t.startswith("cloudresourcemanager.googleapis.com/") for t in request.get("asset_types") or []):  # v18.5: every policy under the scope
            results = self._policy_results(scope, set(request.get("asset_types") or []))
            self.call("asset", "searchAllIamPolicies", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
            return results
        if query.startswith("roles:(roles/secretmanager") or query.startswith('roles:("'):  # v18.7: the secret roles; the holders of named custom roles
            wanted = set(re.findall(r'"([^"]+)"', query)) if query.startswith('roles:("') else None
            results = []
            for fact in self._policy_results(scope, {"cloudresourcemanager.googleapis.com/Organization", "cloudresourcemanager.googleapis.com/Folder", "cloudresourcemanager.googleapis.com/Project"}):
                kept = [b for b in fact.policy.bindings if (b.role in wanted if wanted is not None else b.role.startswith("roles/secretmanager."))]
                if kept:
                    results.append(SimpleNamespace(**{**vars(fact), "policy": SimpleNamespace(bindings=kept)}))
            self.call("asset", "searchAllIamPolicies", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
            return results
        if query.startswith("memberTypes:") or query.startswith("roles:(roles/cloudkms"):  # v18.4: public access; KMS separation of duties
            for profile in profiles:
                g = profile.data_governance
                if g is None:
                    continue
                common = {"project": f"projects/{profile.project_number}", "organization": f"organizations/{self.world.org_id}", "folders": [f"folders/{profile.folder_id}"]}
                if query.startswith("memberTypes:") and "run.googleapis.com/Service" in (request.get("asset_types") or []):  # v18.6: public invokers
                    s, region = profile.serverless, self._serverless_region(profile)
                    public_services = [n for n, exposure, _ in (s.services if s else ()) if exposure in ("public-binding", "behind-lb-locked")] + (["fn-main"] if s and s.function == "gen2" else [])
                    for name in public_services:
                        results.append(SimpleNamespace(asset_type="run.googleapis.com/Service", resource=f"//run.googleapis.com/projects/{profile.project_id}/locations/{region}/services/{name}",
                                                       policy=SimpleNamespace(bindings=[SimpleNamespace(role="roles/run.invoker", members=["allUsers"])]), **common))
                    continue
                if query.startswith("memberTypes:"):
                    for dataset_id, hours, public in g.datasets:
                        if public and "bigquery.googleapis.com/Dataset" in (request.get("asset_types") or ["bigquery.googleapis.com/Dataset"]):
                            results.append(SimpleNamespace(asset_type="bigquery.googleapis.com/Dataset", resource=f"//bigquery.googleapis.com/projects/{profile.project_id}/datasets/{dataset_id}",
                                                           policy=SimpleNamespace(bindings=[SimpleNamespace(role="roles/bigquery.dataViewer", members=["allAuthenticatedUsers"])]), **common))
                elif g.kms_role_separation:
                    results.append(SimpleNamespace(asset_type="cloudresourcemanager.googleapis.com/Project", resource=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_id}",
                                                   policy=SimpleNamespace(bindings=[SimpleNamespace(role="roles/cloudkms.admin", members=["user:dba@example.com"]),
                                                                                    SimpleNamespace(role="roles/cloudkms.cryptoKeyEncrypterDecrypter", members=["user:dba@example.com", "serviceAccount:app@x.iam.gserviceaccount.com"])]), **common))
            self.call("asset", "searchAllIamPolicies", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
            return results
        for profile in profiles:
            project_bindings = self._project_policy_bindings(profile)
            common = {"project": f"projects/{profile.project_number}", "organization": f"organizations/{self.world.org_id}", "folders": [f"folders/{profile.folder_id}"]}
            if email is None:
                wanted = [b for b in project_bindings if b["role"] in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser", "roles/compute.serviceAgent")
                          or "/roles/" in b["role"]]
            else:
                wanted = [b for b in project_bindings if f"serviceAccount:{email}" in b["members"]]
            if wanted:
                results.append(SimpleNamespace(asset_type="cloudresourcemanager.googleapis.com/Project", resource=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_id}",
                                               policy=SimpleNamespace(bindings=[SimpleNamespace(role=b["role"], members=list(b["members"])) for b in wanted]), **common))
            by_target = {}
            for level, resource, role, member in profile.impersonation_bindings:
                if level == "service account" and (email is None or email == resource):
                    by_target.setdefault(resource, []).append(SimpleNamespace(role=role, members=[member]))
            for target, bindings in by_target.items():
                results.append(SimpleNamespace(asset_type="iam.googleapis.com/ServiceAccount", resource=f"//iam.googleapis.com/projects/{profile.project_id}/serviceAccounts/{target}",
                                               policy=SimpleNamespace(bindings=bindings), **common))
        self.call("asset", "searchAllIamPolicies", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
        return results

    def _resilience_assets(self, profile, asset_types):
        """A project's Cloud SQL instances, managed instance groups, snapshots (single-region and, since v16.1,
        multi-region; v17: old and orphaned ones too) and disks (v17), as Asset Inventory lists them."""
        found = []
        if "sqladmin.googleapis.com/Instance" in asset_types:
            found += [self._sql_asset(profile, sql) for sql in profile.sql_instances]
        if "compute.googleapis.com/InstanceGroupManager" in asset_types:
            found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/zones/{zone}/instanceGroupManagers/mig-{zone}",
                                      resource=SimpleNamespace(data={"name": f"mig-{zone}", "zone": zone})) for zone in profile.mig_zones]
        if "compute.googleapis.com/Snapshot" in asset_types:
            # (name, storage location, age in days, source disk): the source is the project's first VM's boot disk,
            # or a disk that no longer exists for an orphan.
            disk = self._disk_url(profile, profile.vms[0]) if profile.vms else ""
            snapshots = [(f"snap-{i}", "us-central1", 10 + i, disk) for i in range(profile.single_region_snapshots)]
            snapshots += [(f"snap-mr-{i}", ("asia", "us", "eu")[i % 3], 20 + i, disk) for i in range(profile.multi_region_snapshots)]
            snapshots += [(name, "us", age, disk) for name, age in profile.old_snapshots]
            snapshots += [(name, "us", 30, f"https://www.googleapis.com/compute/v1/projects/{profile.project_id}/zones/{profile.zones[0]}/disks/deleted-disk")
                          for name in profile.orphan_snapshots]
            found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/global/snapshots/{name}",
                                      resource=SimpleNamespace(data={"name": name, "storageLocations": [location], "creationTimestamp": _iso(age),
                                                                     "diskSizeGb": "50", "sourceDisk": source, "status": "READY"}))
                      for name, location, age, source in snapshots]
        if "compute.googleapis.com/Disk" in asset_types:
            found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/zones/{vm.zone}/disks/{vm.name}",
                                      resource=SimpleNamespace(data={"name": vm.name, "selfLink": self._disk_url(profile, vm), "sizeGb": "50"}))
                      for vm in profile.vms]
        return found

    @staticmethod
    def _disk_url(profile, vm):
        return f"https://www.googleapis.com/compute/v1/projects/{profile.project_id}/zones/{vm.zone}/disks/{vm.name}"

    @staticmethod
    def _sql_asset(profile, sql):
        region = profile.subnets[0][1] if profile.subnets else "us-central1"  # v17.3: the instance's region, as the API reports it
        data = {"name": sql.name, "databaseVersion": sql.database_version, "region": region, "settings": {
            "availabilityType": "ZONAL" if sql.zonal else "REGIONAL",
            "backupConfiguration": {"enabled": sql.backups, "pointInTimeRecoveryEnabled": sql.pitr, "retainedBackupsCount": sql.retained_backups}}}
        governance = profile.data_governance  # v18.4: the CIS flag pack, or the engine defaults
        if governance and governance.sql_flags == "pack":
            packs = {"POSTGRES": [("log_connections", "on"), ("log_disconnections", "on"), ("log_statement", "ddl"), ("cloudsql.enable_pgaudit", "on")],
                     "MYSQL": [("local_infile", "off"), ("skip_show_database", "on")],
                     "SQLSERVER": [("remote access", "off"), ("3625", "on")]}
            engine = next((e for e in packs if sql.database_version.upper().startswith(e)), "POSTGRES")
            data["settings"]["databaseFlags"] = [{"name": n, "value": v} for n, v in packs[engine]]
        return SimpleNamespace(name=f"//cloudsql.googleapis.com/projects/{profile.project_id}/instances/{sql.name}",
                               resource=SimpleNamespace(data=data))

    # --- Recommender (gRPC) ---

    def list_recommendations(self, parent=None, filter=None, request=None):
        parent = parent or (request or {}).get("parent")
        project_id = _project_of(parent)
        self.call("recommender", "recommendations.list", project_id=project_id)
        recommender_id = parent.rsplit("/recommenders/", 1)[-1]
        if recommender_id == IAM_RECOMMENDER:
            return self._iam_recommendations(parent, project_id)
        if project_id is None:
            if recommender_id != UNATTENDED_RECOMMENDER:
                return []
            return [recommender_v1.Recommendation({
                "name": f"{parent}/recommendations/{i}", "recommender_subtype": "CLEANUP_PROJECT", "state_info": {"state": "ACTIVE"},
                "description": f"Project `{pid}` has been unattended for 90 days. Consider cleaning it up.",
                "target_resources": [f"//cloudresourcemanager.googleapis.com/projects/{pid}"],
                "content": {"operation_groups": [{"operations": [{"action": "remove", "resource": f"//cloudresourcemanager.googleapis.com/projects/{pid}"}]}]},
            }) for i, pid in enumerate(self.world.unattended_project_ids())]
        profile = self.world.project(project_id)
        if recommender_id == QUOTA_RECOMMENDER:
            if not profile.quota_recommendation:
                return []
            return [recommender_v1.Recommendation({"name": f"{parent}/recommendations/0", "recommender_subtype": "REVIEW_HIGH_QUOTA_UTILIZATION",
                                                   "description": f"Increase the CPUS quota in {REGIONS[0]} from 100 to 200: usage is approaching the limit.",
                                                   "content": {"overview": {"serviceName": "compute.googleapis.com", "quotaName": "CPUS",
                                                                            "metric": "compute.googleapis.com/cpus", "currentLimit": 100,
                                                                            "dimensions": f"region:{REGIONS[0]}", "allowsQuotaIncreaseRequest": True}}})]
        check = COST_RECOMMENDER_IDS.get(recommender_id)
        location = parent.split("/locations/")[1].split("/")[0]
        recos = profile.cost_recommendations.get((check, location), []) if check else []
        return [recommender_v1.Recommendation({
            "name": f"{parent}/recommendations/{i}", "description": description, "recommender_subtype": subtype,
            "priority": "P2" if usd >= 50 else "P4", "state_info": {"state": "ACTIVE"},  # v18.1: the priority decides the verdict
            "primary_impact": {"category": "COST", "cost_projection": {"cost": {"currency_code": "USD", "units": -usd, "nanos": 0}}},
            "content": {"overview": {"resourceName": resource},
                        "operation_groups": [{"operations": [{"action": "replace", "resource": f"//compute.googleapis.com/projects/{project_id}/zones/{location}/instances/{resource}"}]}]},
        }) for i, (resource, subtype, description, usd) in enumerate(recos)]

    def _iam_recommendations(self, parent, project_id):
        """The IAM recommender's recommendations (v17): the project's unused primitive roles; one at the organization; none for a folder."""
        if project_id is not None:
            resource, items = f"//cloudresourcemanager.googleapis.com/projects/{project_id}", self.world.project(project_id).iam_recommendations
        elif parent.startswith("organizations/"):
            resource, items = f"//cloudresourcemanager.googleapis.com/organizations/{self.world.org_id}", (ORG_IAM_RECOMMENDATION,)
        else:
            return []
        recommendations = []
        for i, (member, role, replacement) in enumerate(items):
            operations = [{"action": "remove", "resource_type": "cloudresourcemanager.googleapis.com/Project", "resource": resource,
                           "path": "/iamPolicy/bindings/*/members/*",
                           "path_filters": {"/iamPolicy/bindings/*/role": role, "/iamPolicy/bindings/*/members/*": member}}]
            if replacement:
                operations.append({"action": "add", "resource_type": "cloudresourcemanager.googleapis.com/Project", "resource": resource,
                                   "path": "/iamPolicy/bindings/*/members/-", "value": member,
                                   "path_filters": {"/iamPolicy/bindings/*/role": replacement}})
            description = (f"Replace the current role {role} with a smaller role {replacement} to cover the permissions needed by {member}."
                           if replacement else f"Remove the role {role} from {member}: no permission of it was used in the last 90 days.")
            recommendations.append(recommender_v1.Recommendation({
                "name": f"{parent}/recommendations/{i}", "recommender_subtype": "REPLACE_ROLE" if replacement else "REMOVE_ROLE",
                "description": description, "content": {"operation_groups": [{"operations": operations}]}}))
        return recommendations

    def list_insights(self, parent=None, filter=None, request=None):
        parent = parent or (request or {}).get("parent")
        project_id = _project_of(parent)
        self.call("recommender", "insights.list", project_id=project_id)
        insight_type = parent.rsplit("/insightTypes/", 1)[-1]
        location = parent.split("/locations/")[1].split("/")[0]
        if project_id is None:
            if insight_type != RECENT_CHANGE_INSIGHT:
                return []
            return [recommender_v1.Insight({"name": f"{parent}/insights/1", "description": "Organization IAM policy changed: added roles/owner for group:cloud-admins@example.com"})]
        profile = self.world.project(project_id)
        if insight_type == RECENT_CHANGE_INSIGHT:
            return [recommender_v1.Insight({"name": f"{parent}/insights/{i}", "description": text}) for i, text in enumerate(profile.recent_changes)]
        if insight_type == "google.iam.serviceAccount.Insight":  # v18.5: the accounts nobody authenticated as in the window
            return [recommender_v1.Insight({"name": f"{parent}/insights/{i}", "description": f"Service account {email} was inactive.", "insight_subtype": "SERVICE_ACCOUNT_USAGE",
                                            "severity": "LOW", "state_info": {"state": "ACTIVE"},
                                            "content": {"email": email, **({"lastAuthenticatedTime": _iso(days)} if days is not None else {})}})
                    for i, (email, days) in enumerate(profile.posture.unused_accounts if profile.posture else ())]
        check = NETWORK_INSIGHT_IDS.get(insight_type)
        insights = []
        for i, (kind, payload) in enumerate(profile.network_insights.get((check, location), []) if check else []):
            if kind == "ip":
                insights.append(recommender_v1.Insight({
                    "name": f"{parent}/insights/{i}", "description": f"Subnet range {payload['prefix']} is {payload['ratio']:.0%} allocated.",
                    "severity": "HIGH" if payload["ratio"] >= 0.9 else "MEDIUM", "state_info": {"state": "ACTIVE"},
                    "target_resources": [f"//compute.googleapis.com/{payload['subnet']}"],
                    "content": {"ipUtilizationSummaryInfo": [{"networkStats": [{"networkUri": payload["network"], "subnetStats": [
                        {"subnetUri": payload["subnet"], "subnetRangeStats": [{"subnetRangePrefix": payload["prefix"], "allocationRatio": payload["ratio"]}]}]}]}]}}))
            elif kind == "sa":
                insights.append(recommender_v1.Insight({
                    "name": f"{parent}/insights/{i}", "description": "GKE node service account has the Editor role.", "severity": "MEDIUM", "state_info": {"state": "ACTIVE"},
                    "target_resources": [f"//container.googleapis.com/{payload['cluster_uri']}"],
                    "content": {"nodeServiceAccountInsight": {"clusterUri": payload["cluster_uri"], "serviceAccount": "default"}}}))
            else:
                insights.append(recommender_v1.Insight({"name": f"{parent}/insights/{i}", "description": payload["description"], "severity": "LOW", "state_info": {"state": "ACTIVE"}}))
        return insights

    # --- OS Config ---

    def list_inventories(self, request):
        """``OsConfigZonalServiceClient.list_inventories`` (v18): the inventories of one zone, named by instance ID; FailedPrecondition
        when the project has OS inventory management off."""
        parent = request["parent"]
        if not parent.endswith("/instances/-"):  # the API's pattern: projects/{project}/locations/{zone}/instances/-
            raise core_exceptions.InvalidArgument("Violation in ListInventoriesRequest.parent: The 'parent' field does not match the expected pattern.")
        project_id, zone = _project_of(parent), parent.rsplit("/locations/", 1)[-1].split("/", 1)[0]
        self.call("osconfig", "listInventories", project_id=project_id)
        profile = self.world.project(project_id)
        if profile.osconfig_disabled:
            raise core_exceptions.FailedPrecondition("OS inventory management has been disabled in this project.")
        return [SimpleNamespace(name=f"projects/{profile.project_number}/locations/{zone}/instances/{self._instance_id(profile, index)}/inventory",
                                os_info=SimpleNamespace(hostname=vm.name))
                for index, vm in enumerate(profile.vms) if vm.zone == zone and vm.os_reporting and vm.name not in profile.stopped_vms]

    def get_inventory(self, request):
        name = request["name"]
        project_id, instance = _project_of(name), name.split("/instances/")[1].split("/")[0]
        self.call("osconfig", "getInventory", project_id=project_id)
        profile = self.world.project(project_id)
        if profile.osconfig_disabled:
            raise core_exceptions.FailedPrecondition("OS inventory management is disabled for this project")
        for vm in profile.vms:
            if vm.name == instance:
                if vm.os_reporting:
                    return SimpleNamespace(name=name)
                break
        raise core_exceptions.NotFound(f"Inventory not found for {name}")

    # --- Storage (per-project) ---

    def list_buckets(self, project_id):
        self.call("storage", "buckets.list", project_id=project_id)
        return [_BucketStub(self, project_id, bucket) for bucket in self.world.project(project_id).buckets]

    def bucket_iam_policy(self, project_id, bucket):
        self.call("storage", "buckets.getIamPolicy", project_id=project_id)
        if bucket.public:
            return SimpleNamespace(bindings=[{"role": "roles/storage.objectViewer", "members": {"allUsers"}}])
        return SimpleNamespace(bindings=[{"role": "roles/storage.admin", "members": {f"projectOwner:{project_id}"}}])


# --- client stand-ins -------------------------------------------------------

class _DiscoveryStub:
    """What ``api_build`` returns: ``service.resource().method(**kw).execute()`` chains."""

    def __init__(self, provider, service, version):
        self._provider, self._service, self._version = provider, service, version

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return _ResourceCall(self._provider, self._service, (name,))


class _ResourceCall:
    """``service.resource`` or ``...method`` before it is called."""

    def __init__(self, provider, service, path):
        self._provider, self._service, self._path = provider, service, path

    def __call__(self, **kwargs):
        if self._path[-1].endswith("_next"):  # list_next / aggregatedList_next: single page, no next request
            return None
        return _Request(self._provider, self._service, self._path, kwargs)


class _Request:
    """A resource (``projects()``) or a prepared method call (``...list(project=...)``)."""

    def __init__(self, provider, service, path, kwargs):
        self._provider, self._service, self._path, self._kwargs = provider, service, path, kwargs

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return _ResourceCall(self._provider, self._service, self._path + (name,))

    def execute(self, num_retries=0, **kwargs):
        return self._provider.dispatch(self._service, self._path, self._kwargs)


class _AssetStub:
    def __init__(self, provider):
        self._p = provider

    def search_all_resources(self, request):
        return self._p.search_all_resources(request)

    def list_assets(self, request):
        return self._p.list_assets(request)

    def search_all_iam_policies(self, request):
        return self._p.search_all_iam_policies(request)


class _RecommenderStub:
    def __init__(self, provider):
        self._p = provider

    def list_recommendations(self, parent=None, filter=None, request=None):
        return self._p.list_recommendations(parent, filter=filter, request=request)

    def list_insights(self, parent=None, filter=None, request=None):
        return self._p.list_insights(parent, filter=filter, request=request)


class _OsConfigStub:
    def __init__(self, provider):
        self._p = provider

    def get_inventory(self, request):
        return self._p.get_inventory(request)

    def list_inventories(self, request):
        return self._p.list_inventories(request)


class _StorageStub:
    def __init__(self, provider, project_id):
        self._p, self.project = provider, project_id

    def list_buckets(self):
        return self._p.list_buckets(self.project)


class _BucketStub:
    def __init__(self, provider, project_id, bucket):
        self._p, self._project, self._bucket = provider, project_id, bucket
        self.name = bucket.name
        self.versioning_enabled = bucket.versioning
        self.iam_configuration = SimpleNamespace(uniform_bucket_level_access_enabled=bucket.ubla,
                                                 public_access_prevention="enforced" if bucket.name in provider.world.project(project_id).pap_enforced_buckets else "inherited")
        # v17: lifecycle rules and Autoclass, as google-cloud-storage exposes them
        self.lifecycle_rules = [{"action": {"type": "SetStorageClass", "storageClass": "NEARLINE"}, "condition": {"age": 30}}] if bucket.lifecycle else []
        self.autoclass_enabled = bucket.autoclass
        self.storage_class = "STANDARD"
        # v18.1: soft delete (the 7-day default, or off for the unprotected buckets) and a retention policy on some
        profile = provider.world.project(project_id)
        if profile.cost_levers and bucket.name in profile.cost_levers.pruned_buckets:  # v18.8: the versioned buckets that prune their history
            self.lifecycle_rules.append({"action": {"type": "Delete"}, "condition": {"numNewerVersions": 3}})
        self.soft_delete_policy = SimpleNamespace(retention_duration_seconds=0 if bucket.name in profile.unprotected_buckets else 604800)
        self.retention_period = 86400 * 30 if bucket.name in profile.retention_buckets else None

    def get_iam_policy(self, requested_policy_version=None):
        return self._p.bucket_iam_policy(self._project, self._bucket)


class _HttpResponse:
    def __init__(self, status_code, text):
        self.status_code, self.text = status_code, text

    def json(self):
        return json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")
