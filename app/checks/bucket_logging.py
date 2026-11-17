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
"""Bucket Logging (v19.3): whether anyone could tell who read or wrote a bucket's objects.

Security Health Analytics' ``BUCKET_LOGGING_DISABLED`` reads one fact — the bucket's legacy **usage logging** (``logging.logBucket``)
— and the report named it as a gap ("—" in SCC Active Findings' *CloudGauge check* column). The honest rule reads two: usage logging,
and the **Data Access audit logs** for ``storage.googleapis.com`` (or ``allServices``), ``DATA_READ`` and ``DATA_WRITE``, effective at the
project — set on the project or inherited from a folder or the organization — which is the modern path and the one *Data Access Audit
Logs* (v18.1) judges for the scanned resource. One row per project with buckets: neither usage logging on its buckets nor Data Access
logs for storage → *Investigation Recommended* (no record of who read what); usage logging absent but Data Access logs on → Informational
(covered; SHA's detector only knows the legacy path, the row says so); every bucket with usage logging → no row.

Reads, all Asset Inventory (``roles/cloudasset.viewer``): the buckets under the scope (content RESOURCE), the projects under it (their
ancestors), and the IAM policies of the projects, folders and organization under the scope (content IAM_POLICY — the audit
configurations ride on the policy). Scope-level; rows per project, deterministic across shards.
"""
import logging

from google.cloud import asset_v1

from app.checks.gke_operations import INFORMATIONAL, INVESTIGATION, write_rows
from app.config import SCOPES
from app.services import gcp

BUCKET_LOGGING_CHECK = "Bucket Logging"
BUCKET_TYPE = "storage.googleapis.com/Bucket"
PROJECT_TYPE = "cloudresourcemanager.googleapis.com/Project"
CONTAINER_TYPES = [PROJECT_TYPE, "cloudresourcemanager.googleapis.com/Folder", "cloudresourcemanager.googleapis.com/Organization"]
STORAGE = "storage.googleapis.com"
DATA_TYPES = ("DATA_READ", "DATA_WRITE")
LOG_TYPE_NAMES = {1: "ADMIN_READ", 2: "DATA_WRITE", 3: "DATA_READ"}
TOP = 3
ALL_CLEAR = "Every bucket under the scope has usage logging, or sits in a project where Data Access logs (DATA_READ and DATA_WRITE) are on for Cloud Storage."


def tail(name):
    return str(name or "").rsplit("/", 1)[-1]


def log_type_name(value):
    name = getattr(value, "name", None)
    if name:
        return str(name)
    try:
        return LOG_TYPE_NAMES.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value).upper()


def audit_data_types(iam_policy):
    """The Data Access log types on for Cloud Storage in one IAM policy's audit configurations (``allServices`` counts), as a set of names."""
    found = set()
    for config in (getattr(iam_policy, "audit_configs", None) or getattr(iam_policy, "auditConfigs", None) or []):
        service = str(getattr(config, "service", None) or (config.get("service") if isinstance(config, dict) else "") or "")
        if service not in (STORAGE, "allServices"):
            continue
        entries = getattr(config, "audit_log_configs", None) or (config.get("auditLogConfigs") if isinstance(config, dict) else None) or []
        for entry in entries:
            log_type = getattr(entry, "log_type", None) or (entry.get("logType") if isinstance(entry, dict) else None)
            found.add(log_type_name(log_type))
    return found & set(DATA_TYPES)


def container_of(asset_name):
    """``projects/123``, ``folders/456`` or ``organizations/789`` from an IAM-policy asset's name."""
    path = str(asset_name or "").split("//cloudresourcemanager.googleapis.com/", 1)[-1]
    return path if path.split("/", 1)[0] in ("projects", "folders", "organizations") else ""


def bucket_facts(bucket_assets):
    """``{project id or number: [(bucket name, usage logging on)]}`` from the Bucket assets (the project from ``ancestors`` when present, else the name)."""
    by_project = {}
    for asset in bucket_assets:
        data = getattr(getattr(asset, "resource", None), "data", None) or {}
        ancestors = [str(a) for a in (getattr(asset, "ancestors", None) or [])]
        project = next((tail(a) for a in ancestors if a.startswith("projects/")), "") or str(data.get("projectNumber") or "")
        name = str(data.get("name") or tail(getattr(asset, "name", "")))
        logging_on = bool((data.get("logging") or {}).get("logBucket"))
        by_project.setdefault(project, []).append((name, logging_on))
    return by_project


def project_facts(project_assets):
    """``{project number: (project id, [ancestor container names top-down])}``."""
    facts = {}
    for asset in project_assets:
        data = getattr(getattr(asset, "resource", None), "data", None) or {}
        ancestors = [str(a) for a in (getattr(asset, "ancestors", None) or [])]
        number = tail(ancestors[0]) if ancestors else tail(getattr(asset, "name", ""))
        facts[number] = (str(data.get("projectId") or number), list(reversed(ancestors)))
    return facts


def data_access_by_container(policy_assets):
    """``{container name: {log types on for storage}}`` from the IAM-policy assets."""
    return {container_of(getattr(asset, "name", "")): audit_data_types(getattr(asset, "iam_policy", None)) for asset in policy_assets}


def effective_data_access(path, by_container):
    """The union of the log types on along ``path`` (the organization first, the project last)."""
    on = set()
    for container in path:
        on |= by_container.get(container, set())
    return on


def logging_rows(buckets_by_project, projects, by_container):
    rows = []
    for number, (project_id, path) in sorted(projects.items(), key=lambda kv: kv[1][0]):
        buckets = buckets_by_project.get(number) or buckets_by_project.get(project_id) or []
        unlogged = sorted(name for name, on in buckets if not on)
        if not unlogged:
            continue
        on = effective_data_access(path, by_container)
        covered = set(DATA_TYPES) <= on
        names = ", ".join(unlogged[:TOP]) + (f" +{len(unlogged) - TOP}" if len(unlogged) > TOP else "")
        where = ", ".join(sorted(on)) if on else "off"
        rows.append({"Project": project_id, "Buckets": f"{len(unlogged)} of {len(buckets)} without usage logging", "Usage logging": "off", "Data Access logs": "on" if covered else where,
                     "Issue": "Nobody could say who read or wrote these objects." if not covered else "Usage logging off; Data Access logs cover it.",
                     "Detail": (f"{names}: no usage logging, and Data Access logs for Cloud Storage are {where} at the project and above — no record of who read or wrote their objects."
                                if not covered else f"{names}: no usage logging, but Data Access logs (DATA_READ, DATA_WRITE) are on for Cloud Storage at the project or above — the modern record; "
                                "Security Health Analytics' BUCKET_LOGGING_DISABLED reads the legacy path alone."),
                     "Fix": (f"gcloud projects set-iam-policy {project_id} <policy.yaml>  # with auditConfigs: [{{service: storage.googleapis.com, auditLogConfigs: [{{logType: DATA_READ}}, {{logType: DATA_WRITE}}]}}] "
                             f"(or an organization-wide default audit config); per bucket: gcloud storage buckets update gs://{unlogged[0]} --log-bucket=<log-sink-bucket>"
                             if not covered else f"gcloud storage buckets update gs://{unlogged[0]} --log-bucket=<log-sink-bucket>  # only if the legacy usage logs are wanted as well"),
                     "_status": INVESTIGATION if not covered else INFORMATIONAL})
    return rows


def check_bucket_logging(scope, scope_id, job_id, *, sink):
    """Writes *Bucket Logging* (module docstring)."""
    print(f"🪣 [{job_id}] Checking {BUCKET_LOGGING_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        buckets = list(asset_client.list_assets(request={"parent": parent, "asset_types": [BUCKET_TYPE], "content_type": asset_v1.ContentType.RESOURCE}))
        projects = list(asset_client.list_assets(request={"parent": parent, "asset_types": [PROJECT_TYPE], "content_type": asset_v1.ContentType.RESOURCE}))
        policies = list(asset_client.list_assets(request={"parent": parent, "asset_types": CONTAINER_TYPES, "content_type": asset_v1.ContentType.IAM_POLICY}))
        if scope != "organization":  # the folders and the organization above the scanned resource set audit configurations too: one listing at the organization
            org_ids = {tail(a) for asset in projects for a in (getattr(asset, "ancestors", None) or []) if str(a).startswith("organizations/")}
            for org_id in sorted(org_ids):
                policies += list(asset_client.list_assets(request={"parent": f"organizations/{org_id}", "asset_types": CONTAINER_TYPES[1:], "content_type": asset_v1.ContentType.IAM_POLICY}))
    except Exception as e:
        logging.error(f"[{job_id}] {BUCKET_LOGGING_CHECK}: the read under {parent} failed: {e}")
        sink.write_finding(job_id, BUCKET_LOGGING_CHECK.replace(" ", "_"), {"Check": BUCKET_LOGGING_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    write_rows(sink, job_id, BUCKET_LOGGING_CHECK, logging_rows(bucket_facts(buckets), project_facts(projects), data_access_by_container(policies)), ALL_CLEAR)
