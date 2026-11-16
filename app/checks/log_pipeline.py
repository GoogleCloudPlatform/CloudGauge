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
"""The logging pipeline (v18.9): where the logs go, whether they arrive, and what is stored twice.

Three records from the Logging API (sinks, exclusions, buckets, views — ``roles/logging.viewer``),
the inventory (the destinations of sinks, the projects and folders in scope — ``roles/cloudasset.viewer``)
and one Monitoring metric:

- **Audit Log Pipeline** (Operational Excellence, scope-level): the scanned resource's own customer
  sinks — the organization's in an organization scan, a folder's or a project's otherwise; the
  built-in ``_Required`` and ``_Default`` left out, as *Organization Log Sink* leaves them. That
  check asks whether an aggregated audit export exists (CIS 2.2); this one asks whether it is
  complete and durable: an audit filter that admits only some of ``activity`` / ``system_event`` /
  ``data_access`` / ``policy`` or an exclusion that drops audit entries (Investigation), a folder
  sink without ``includeChildren`` (Investigation), a log-bucket destination kept under 365 days
  (Investigation) or unlocked (Informational), a destination that is gone or not ``ACTIVE``
  (**Action Required**), a writer identity without the destination role (**Action Required**; a
  sink into a log bucket of its own project needs none), export errors in the last week (**Action
  Required**), a destination outside the scanned scope (Informational: not verifiable from inside).
  A scope with no customer sink writes one Informational note.
- **Duplicate Log Routing** (Cost Optimization, scope-level): an aggregated sink at the
  organization or a folder in scope into a **log bucket**, admitting what ``_Default`` stores, while
  the projects below keep their ``_Default`` sinks enabled — every entry stored twice, ingestion
  billed twice (Investigation, one row per aggregated sink); a sink into a user bucket admitting the
  ``_Required`` streams, which ``_Required`` already keeps 400 days free (Informational).
- **Project Log Routing** (Operational Excellence, per project): the project's ``_Default`` sink
  disabled, or excluding everything, with no other bucket sink — its logs are discarded
  (**Action Required**); Data Access logs effective for the project (its own or the organization's
  configuration) while the ``_Default`` view of the ``_Default`` bucket does not exclude them
  (Informational); the ``_Default`` bucket without Log Analytics (Informational — turning it on is
  irreversible, the row says so).
"""
import logging
import re
from datetime import timedelta

from app.checks.gke_operations import ACTION_REQUIRED, INFORMATIONAL, INVESTIGATION, write_rows
from app.checks.network_edge import list_assets
from app.checks.not_checked import NotChecked
from app.checks.operations import audit_config_assessment
from app.checks.privileges import search_folders, search_projects
from app.config import SCOPES, get_settings
from app.services import gcp
from app.utils import utcnow

AUDIT_PIPELINE_CHECK = "Audit Log Pipeline"
DUPLICATE_ROUTING_CHECK = "Duplicate Log Routing"
PROJECT_ROUTING_CHECK = "Project Log Routing"
LOG_PIPELINE_CHECKS = (AUDIT_PIPELINE_CHECK, DUPLICATE_ROUTING_CHECK, PROJECT_ROUTING_CHECK)

BUILTIN_SINKS = ("_Required", "_Default")
AUDIT_TYPES = ("activity", "system_event", "data_access", "policy")
REQUIRED_STREAMS = ("activity", "system_event", "access_transparency")  # what _Required keeps 400 days, free
MIN_AUDIT_RETENTION_DAYS = 365
EXPORT_ERROR_METRIC = "logging.googleapis.com/exports/error_count"
EXPORT_ERROR_DAYS = 7
SHARED_WRITER = "cloud-logs@system.gserviceaccount.com"  # the pre-2019 shared identity: its grants are Google's, not in any policy
DATASET_TYPE, GCS_BUCKET_TYPE, TOPIC_TYPE = "bigquery.googleapis.com/Dataset", "storage.googleapis.com/Bucket", "pubsub.googleapis.com/Topic"
# The role the sink's writer identity needs on each destination kind, and the roles that include it.
WRITER_ROLES = {
    "bucket": ("roles/logging.bucketWriter", "roles/logging.admin", "roles/editor", "roles/owner"),
    "bigquery": ("roles/bigquery.dataEditor", "roles/bigquery.dataOwner", "roles/bigquery.admin", "roles/editor", "roles/owner"),
    "storage": ("roles/storage.objectCreator", "roles/storage.objectAdmin", "roles/storage.objectUser", "roles/storage.admin", "roles/storage.legacyBucketWriter", "roles/editor", "roles/owner"),
    "pubsub": ("roles/pubsub.publisher", "roles/pubsub.editor", "roles/pubsub.admin", "roles/editor", "roles/owner"),
}
DESTINATION_KIND_NAMES = {"bucket": "log bucket", "bigquery": "BigQuery dataset", "storage": "Cloud Storage bucket", "pubsub": "Pub/Sub topic", "project": "project", "other": "destination"}
AUDIT_FILTER = 'logName:"cloudaudit.googleapis.com"'
AUDIT_PIPELINE_ALL_CLEAR = ("Every customer log sink of the scanned resource exports the audit logs it names completely, writes into a destination that exists "
                            "and is kept at least a year, and reported no export error in the last week.")
DUPLICATE_ALL_CLEAR = "No log entry is stored twice by an aggregated sink and a project's _Default sink."
PROJECT_ROUTING_ALL_CLEAR = "Every project stores its logs and reads them through a default view that fits its audit configuration."

_AUDIT_TYPE = re.compile(r"cloudaudit\.googleapis\.com(?:%2f|/)(activity|system_event|data_access|policy|access_transparency)", re.I)
_GENERIC_AUDIT = re.compile(r"cloudaudit\.googleapis\.com(?![%/])|google\.cloud\.audit\.AuditLog", re.I)
_NEGATED = re.compile(r"(?:\bnot\s*(?:\(\s*)?|-)(?:log_id\s*\(|logname\s*[:=~]+\s*\(?)\s*[\"']?\s*(?:projects/[^\"']*/logs/)?cloudaudit", re.I)
_VIEW_HIDES_DATA_ACCESS = re.compile(r"(?:\bnot\s*(?:\(\s*)?|-)(?:log_id\s*\(|logname\s*[:=~]+\s*\(?)\s*[\"']?\s*(?:projects/[^\"']*/logs/)?cloudaudit\.googleapis\.com(?:%2f|/)data_access", re.I)


# --- reads ------------------------------------------------------------------------------------------------------------

def _collection(logging_api, parent):
    kind = parent.split("/", 1)[0]
    return {"organizations": logging_api.organizations(), "folders": logging_api.folders(), "projects": logging_api.projects()}[kind]


def list_sinks(logging_api, parent):
    found, collection = [], _collection(logging_api, parent).sinks()
    request = collection.list(parent=parent)
    while request:
        response = request.execute() or {}
        found += response.get("sinks") or []
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def list_buckets(logging_api, parent):
    found, collection = [], _collection(logging_api, parent).locations().buckets()
    request = collection.list(parent=f"{parent}/locations/-")
    while request:
        response = request.execute() or {}
        found += response.get("buckets") or []
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def get_bucket(logging_api, bucket_name):
    """``buckets.get`` by full name (``projects/p/locations/l/buckets/b``, or a folder's or organization's)."""
    return _collection(logging_api, bucket_name).locations().buckets().get(name=bucket_name).execute() or {}


def list_views(logging_api, bucket_name):
    collection = _collection(logging_api, bucket_name).locations().buckets().views()
    return (collection.list(parent=bucket_name).execute() or {}).get("views") or []


# --- facts ------------------------------------------------------------------------------------------------------------

def short_name(sink):
    return str(sink.get("name") or "").rsplit("/", 1)[-1]


def is_builtin(sink):
    return short_name(sink) in BUILTIN_SINKS


def parent_flag(parent):
    """The gcloud flag that names ``organizations/o`` / ``folders/f`` / ``projects/p``."""
    kind, _, ident = str(parent).partition("/")
    return {"organizations": f"--organization={ident}", "folders": f"--folder={ident}", "projects": f"--project={ident}"}.get(kind, f"--project={ident}")


def admitted_audit_types(filter_text):
    """Which of ``AUDIT_TYPES`` a sink filter admits, and how: ``(types, kind)`` — ``kind`` ``"all"`` (an empty filter: everything), ``"audit"``
    (the filter names audit logs: all four for a generic ``cloudaudit.googleapis.com`` or ``AuditLog`` match, the named ones for log-ID or
    ``logName`` matches), ``"other"`` (no audit log named, or every mention negated — a ``_Default``-shaped filter)."""
    text = (filter_text or "").strip()
    if not text:
        return set(AUDIT_TYPES), "all"
    named = {m.lower() for m in _AUDIT_TYPE.findall(text)}
    mentions = len(_AUDIT_TYPE.findall(text)) + len(_GENERIC_AUDIT.findall(text))
    if mentions and len(_NEGATED.findall(text)) >= mentions:
        return set(), "other"
    if _GENERIC_AUDIT.search(text):
        return set(AUDIT_TYPES), "audit"
    if named & set(AUDIT_TYPES):
        return named & set(AUDIT_TYPES), "audit"
    return set(), "other"


def admits_required_streams(filter_text):
    """Whether a sink filter lets the ``_Required`` streams through: an empty filter, a generic audit match, or ``activity`` /
    ``system_event`` / ``access_transparency`` named."""
    types, kind = admitted_audit_types(filter_text)
    if kind == "all":
        return True
    if kind == "other":
        return False
    named = {m.lower() for m in _AUDIT_TYPE.findall(filter_text or "")}
    return bool((types | named) & set(REQUIRED_STREAMS))


def admits_default_streams(filter_text):
    """Whether a sink filter lets what ``_Default`` stores through: anything that is not an audit-only filter."""
    return admitted_audit_types(filter_text)[1] != "audit"


def audit_exclusions(sink):
    """The enabled exclusions of a sink whose filter names audit logs (they drop audit entries on the way out)."""
    return [e.get("name") or "?" for e in sink.get("exclusions") or [] if not e.get("disabled") and admitted_audit_types(e.get("filter"))[1] == "audit"]


def destination_facts(destination):
    """``{kind, name, short, project, parent}`` of a sink destination: ``logging.googleapis.com/projects/p/locations/l/buckets/b`` (``bucket``;
    the parent may be a folder or organization), ``bigquery.googleapis.com/projects/p/datasets/d``, ``storage.googleapis.com/b``,
    ``pubsub.googleapis.com/projects/p/topics/t``, ``logging.googleapis.com/projects/p`` (``project``); ``project`` is the owning project
    ID or number (``""`` for a folder's or organization's bucket or a Cloud Storage bucket), ``parent`` the owner's ``projects/p`` /
    ``folders/f`` / ``organizations/o``."""
    text = str(destination or "")
    service, _, path = text.partition("/")
    parts = path.split("/")
    project = parts[1] if len(parts) > 1 and parts[0] == "projects" else ""
    parent = "/".join(parts[:2]) if len(parts) > 1 and parts[0] in ("projects", "folders", "organizations", "billingAccounts") else ""
    if service == "logging.googleapis.com" and "/buckets/" in path:
        return {"kind": "bucket", "name": path, "short": parts[-1], "project": project, "parent": parent}
    if service == "logging.googleapis.com":
        return {"kind": "project", "name": path, "short": path, "project": project, "parent": parent}
    if service == "bigquery.googleapis.com":
        return {"kind": "bigquery", "name": path, "short": parts[-1], "project": project, "parent": parent}
    if service == "storage.googleapis.com":
        return {"kind": "storage", "name": path, "short": path, "project": "", "parent": ""}
    if service == "pubsub.googleapis.com":
        return {"kind": "pubsub", "name": path, "short": parts[-1], "project": project, "parent": parent}
    return {"kind": "other", "name": path or text, "short": path or text, "project": project, "parent": ""}


def scope_members(asset_client, parent):
    """``{"projects": {ids and numbers}, "folders": {ids}, "aliases": {id: number, number: id}}`` under ``parent`` from the search index
    (a project scope: the project alone)."""
    projects = search_projects(asset_client, parent)
    if parent.startswith("projects/") and not projects:
        projects = [{"id": parent.split("/", 1)[1], "number": ""}]
    aliases = {}
    for p in projects:
        if p.get("number"):
            aliases[p["id"]], aliases[p["number"]] = p["number"], p["id"]
    return {"projects": {p["id"] for p in projects} | {p["number"] for p in projects if p.get("number")},
            "folders": set() if parent.startswith("projects/") else set(search_folders(asset_client, parent)), "aliases": aliases}


def in_scope(facts, scope, scope_id, members):
    """Whether a destination belongs to the scanned scope: its project among the scope's (by ID or number), or its parent the scope itself
    or a folder under it. A Cloud Storage bucket's project is not in its name: ``None`` (unknown)."""
    if facts["kind"] == "storage":
        return None
    if facts["project"]:
        return facts["project"] in members["projects"]
    parent = facts["parent"]
    if parent == f"{scope}s/{scope_id}":
        return True
    if parent.startswith("folders/"):
        return parent.split("/", 1)[1] in members["folders"]
    return False


def writer_grant_found(policies, facts, aliases=None):
    """Whether the IAM-policy search results for a writer identity hold one of ``WRITER_ROLES[kind]`` on the destination, its project
    (by ID or number — ``aliases`` maps one to the other), or a folder or organization (inherited: the search is scoped to the scan, so a
    folder's or the organization's grant to the writer is taken as the destination's)."""
    wanted = set(WRITER_ROLES.get(facts["kind"], ()))
    aliases = aliases or {}
    owners = {facts["project"], aliases.get(facts["project"], "")} - {""}
    for result in policies:
        resource = str(getattr(result, "resource", "") or "")
        bindings = getattr(getattr(result, "policy", None), "bindings", None) or []
        if not {str(getattr(b, "role", "") or "") for b in bindings} & wanted:
            continue
        tail = resource.split("//", 1)[-1].split("/", 1)[-1] if "//" in resource else resource  # "//logging.googleapis.com/projects/p/…" → "projects/p/…"
        if facts["name"] and (tail.endswith(facts["name"]) or facts["name"].endswith(tail) or resource.endswith("/" + facts["short"])):
            return True
        if resource.startswith("//cloudresourcemanager.googleapis.com/"):
            if tail.startswith(("folders/", "organizations/")) or any(tail == f"projects/{owner}" for owner in owners):
                return True
    return False


def export_errors(series):
    """``{sink name: errors}`` over ``exports/error_count`` time series (every point summed)."""
    found = {}
    for entry in series or []:
        name = str(((entry.get("resource") or {}).get("labels") or {}).get("name") or "")
        total = 0
        for point in entry.get("points") or []:
            value = point.get("value") or {}
            try:
                total += int(float(value.get("int64Value") if value.get("int64Value") is not None else value.get("doubleValue") or 0))
            except (TypeError, ValueError):
                continue
        if name and total:
            found[name] = found.get(name, 0) + total
    return found


# --- Audit Log Pipeline --------------------------------------------------------------------------------------------------

def sink_update_line(parent, sink_name):
    return f"gcloud logging sinks update {sink_name} {parent_flag(parent)}"


def bucket_update_line(facts):
    location = facts["name"].split("/locations/")[1].split("/")[0] if "/locations/" in facts["name"] else "global"
    return f"gcloud logging buckets update {facts['short']} --location={location} {parent_flag(facts['parent'])}"


def pipeline_rows(parent, sinks, scope, scope_id, members, bucket_reader=None, destination_exists=None, writer_policies=None, errors=None):
    """The Audit Log Pipeline rows of the customer sinks at ``parent``. ``bucket_reader(bucket name)`` returns the bucket or raises;
    ``destination_exists(kind, facts)`` says whether a dataset / Cloud Storage bucket / topic is in the inventory (None: unknown);
    ``writer_policies(writer email)`` returns the IAM-policy search results for the writer identity; ``errors`` maps sink names to
    export errors."""
    rows = []
    errors = errors or {}
    for sink in sinks:
        if is_builtin(sink):
            continue
        name = short_name(sink)
        facts = destination_facts(sink.get("destination"))
        update = sink_update_line(parent, name)
        base = {"Resource": parent, "Sink": name, "Destination": f"{DESTINATION_KIND_NAMES[facts['kind']]} {facts['short']}"}
        types, kind = admitted_audit_types(sink.get("filter"))
        if sink.get("disabled"):
            rows.append({**base, "Issue": "Sink disabled.", "Detail": "Nothing is exported while it stays off.", "Fix": f"{update} --no-disabled", "_status": INVESTIGATION})
        if kind == "audit" and set(AUDIT_TYPES) - types:
            rows.append({**base, "Issue": "Audit export incomplete.",
                         "Detail": f"The filter admits {', '.join(t for t in AUDIT_TYPES if t in types)} and leaves out {', '.join(t for t in AUDIT_TYPES if t not in types)}: "
                                   "those audit logs are not exported.",
                         "Fix": f"{update} --log-filter='{AUDIT_FILTER}'", "_status": INVESTIGATION})
        dropped = audit_exclusions(sink)
        if dropped:
            rows.append({**base, "Issue": "Exclusion drops audit entries.", "Detail": f"Exclusion{'s' if len(dropped) != 1 else ''} {', '.join(dropped)} on the sink filter audit logs out on the way.",
                         "Fix": f"{update} --remove-exclusions={','.join(dropped)}", "_status": INVESTIGATION})
        if parent.startswith("folders/") and not sink.get("includeChildren"):
            rows.append({**base, "Issue": "Folder sink without children.", "Detail": "The sink exports the folder resource's own logs only; the projects below are not covered.",
                         "Fix": f"{update} --include-children", "_status": INVESTIGATION})
        scoped = in_scope(facts, scope, scope_id, members)
        if scoped is False:
            rows.append({**base, "Issue": "Destination outside the scanned scope.", "Detail": "The destination's retention, existence and the writer's grant cannot be verified from inside the scanned scope.",
                         "Fix": "Verify in the destination project that the sink's writer identity holds the destination role and that the destination keeps the logs long enough.", "_status": INFORMATIONAL})
            continue
        if facts["kind"] == "bucket" and bucket_reader is not None:
            try:
                bucket = bucket_reader(facts["name"])
            except Exception as e:  # noqa: BLE001 — a 404 is the finding, anything else a note
                status = getattr(getattr(e, "resp", None), "status", None)
                if status == 404 or "404" in str(e):
                    rows.append({**base, "Issue": "Destination bucket gone.", "Detail": "The sink writes into a log bucket that no longer exists: every exported entry is lost.",
                                 "Fix": f"gcloud logging buckets create {facts['short']} --location=global {parent_flag(facts['parent'])} --retention-days={MIN_AUDIT_RETENTION_DAYS}  # or point the sink elsewhere", "_status": ACTION_REQUIRED})
                else:
                    rows.append({**base, "Issue": "Destination bucket not readable.", "Detail": f"The bucket could not be read: {str(e)[:160]}",
                                 "Fix": "Grant the scanner roles/logging.viewer on the destination's parent, or verify the bucket by hand.", "_status": INFORMATIONAL})
                bucket = None
            if bucket:
                state = str(bucket.get("lifecycleState") or "ACTIVE")
                days = int(bucket.get("retentionDays") or 30)
                if state != "ACTIVE":
                    rows.append({**base, "Issue": "Destination bucket not active.", "Detail": f"The log bucket is {state}: the sink has nowhere to write.",
                                 "Fix": f"Create a new bucket and point the sink at it: {update} --log-filter=… # destination logging.googleapis.com/<bucket>", "_status": ACTION_REQUIRED})
                elif kind in ("audit", "all"):
                    if days < MIN_AUDIT_RETENTION_DAYS:
                        rows.append({**base, "Issue": "Audit retention under a year.", "Detail": f"The destination bucket keeps {days} days; an audit archive is expected to keep at least {MIN_AUDIT_RETENTION_DAYS}.",
                                     "Fix": f"{bucket_update_line(facts)} --retention-days={MIN_AUDIT_RETENTION_DAYS}", "_status": INVESTIGATION})
                    if not bucket.get("locked"):
                        rows.append({**base, "Issue": "Audit bucket not locked.",
                                     "Detail": f"The destination bucket's retention ({days} days) can be shortened and its entries deleted; a lock makes the archive immutable until they expire — and is irreversible.",
                                     "Fix": f"{bucket_update_line(facts)} --locked  # irreversible", "_status": INFORMATIONAL})
        elif facts["kind"] in ("bigquery", "storage", "pubsub") and destination_exists is not None:
            if destination_exists(facts["kind"], facts) is False:
                if facts["kind"] == "storage":  # a bucket's project is not in its name: absent from the scope's inventory may mean elsewhere
                    rows.append({**base, "Issue": "Destination bucket not in the scanned scope.", "Detail": "No Cloud Storage bucket of that name is in the scanned scope's inventory: it lives in another project, or is gone.",
                                 "Fix": f"gcloud storage buckets describe gs://{facts['short']}  # verify it exists and that the writer identity can create objects in it", "_status": INFORMATIONAL})
                else:
                    rows.append({**base, "Issue": f"Destination {DESTINATION_KIND_NAMES[facts['kind']]} gone.", "Detail": "The sink's destination is not in the inventory: every exported entry is lost.",
                                 "Fix": f"Recreate the destination or point the sink elsewhere ({update} …).", "_status": ACTION_REQUIRED})
                continue
        writer = str(sink.get("writerIdentity") or "").split(":", 1)[-1]
        same_project_bucket = facts["kind"] == "bucket" and facts["parent"] == parent  # a project's sink into its own bucket needs no grant
        if writer and writer != SHARED_WRITER and writer_policies is not None and facts["kind"] in WRITER_ROLES and not same_project_bucket:
            try:
                policies = list(writer_policies(writer))
            except Exception as e:  # noqa: BLE001
                policies = None
                logging.info(f"{AUDIT_PIPELINE_CHECK}: the IAM-policy search for {writer} failed: {e}")
            if policies is not None and not writer_grant_found(policies, facts, members.get("aliases")):
                role = WRITER_ROLES[facts["kind"]][0]
                member = f"serviceAccount:{writer}"
                grant = {"bucket": f"gcloud projects add-iam-policy-binding {facts['project'] or '<project>'} --member={member} --role={role}  # or on the bucket's folder / organization",
                         "bigquery": f"bq add-iam-policy-binding --member={member} --role={role} {facts['project']}:{facts['short']}",
                         "storage": f"gcloud storage buckets add-iam-policy-binding gs://{facts['short']} --member={member} --role={role}",
                         "pubsub": f"gcloud pubsub topics add-iam-policy-binding {facts['short']} --project={facts['project']} --member={member} --role={role}"}[facts["kind"]]
                rows.append({**base, "Issue": "Writer without the destination role.", "Detail": f"{writer} holds no {role} on the destination or its project: the sink cannot write, and every entry is dropped.",
                             "Fix": grant, "_status": ACTION_REQUIRED})
        if errors.get(name):
            rows.append({**base, "Issue": "Export errors.", "Detail": f"{errors[name]:,} entries failed to export in the last {EXPORT_ERROR_DAYS} days ({EXPORT_ERROR_METRIC}).",
                         "Fix": f"gcloud logging read 'logName:\"logging.googleapis.com%2Fsink_error\" AND resource.labels.name=\"{name}\"' --limit=20  # the sink's error log names the cause", "_status": ACTION_REQUIRED})
    return rows


def no_sink_note(scope, scope_id):
    if scope == "organization":
        return {"Summary": f"No customer log sink at organizations/{scope_id}: nothing to judge here — Organization Log Sink says what that means."}
    return {"Summary": f"No customer log sink at {scope}s/{scope_id}; the organization's aggregated sink, if any, covers it — judged in an organization scan."}


def read_export_errors(credentials, project_id):
    """``{sink name: errors}`` from ``exports/error_count`` over the last week in ``project_id``'s Monitoring."""
    monitoring = gcp.api_build("monitoring", "v3", credentials=credentials)
    now = utcnow()
    response = monitoring.projects().timeSeries().list(
        name=f"projects/{project_id}", filter=f'metric.type = "{EXPORT_ERROR_METRIC}"',
        interval_startTime=(now - timedelta(days=EXPORT_ERROR_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ"), interval_endTime=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        aggregation_alignmentPeriod=f"{EXPORT_ERROR_DAYS * 86400}s", aggregation_perSeriesAligner="ALIGN_SUM", view="FULL").execute() or {}
    return export_errors(response.get("timeSeries"))


def check_audit_pipeline(scope, scope_id, job_id, *, sink):
    """Writes *Audit Log Pipeline* for the scanned resource's own customer sinks (module docstring)."""
    print(f"📮 [{job_id}] Checking {AUDIT_PIPELINE_CHECK} for {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        logging_api = gcp.api_build("logging", "v2", credentials=credentials)
        sinks = list_sinks(logging_api, parent)
    except Exception as e:
        logging.error(f"[{job_id}] {AUDIT_PIPELINE_CHECK}: could not list the sinks of {parent}: {e}")
        sink.write_finding(job_id, AUDIT_PIPELINE_CHECK.replace(" ", "_"), {"Check": AUDIT_PIPELINE_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    customer = [s for s in sinks if not is_builtin(s)]
    if not customer:
        sink.write_finding(job_id, AUDIT_PIPELINE_CHECK.replace(" ", "_"), {"Check": AUDIT_PIPELINE_CHECK, "Finding": [no_sink_note(scope, scope_id)], "Status": INFORMATIONAL})
        return
    skipped = NotChecked(AUDIT_PIPELINE_CHECK)
    asset_client = gcp.asset_client(credentials)
    try:
        members = scope_members(asset_client, parent)
    except Exception as e:
        members = {"projects": {scope_id} if scope == "project" else set(), "folders": set(), "aliases": {}}
        skipped.add(parent, e, detail="the project search failed; destinations are judged as in scope only when they name the scanned resource")
    inventory = {}

    def destination_exists(kind, facts):
        asset_type = {"bigquery": DATASET_TYPE, "storage": GCS_BUCKET_TYPE, "pubsub": TOPIC_TYPE}[kind]
        if asset_type not in inventory:
            try:
                inventory[asset_type] = {str(getattr(a, "name", "") or "") for a in list_assets(asset_client, parent, [asset_type])}
            except Exception as e:  # noqa: BLE001
                skipped.add(parent, e, detail=f"the {DESTINATION_KIND_NAMES[kind]} listing failed; destinations of that kind are not verified")
                inventory[asset_type] = None
        names = inventory[asset_type]
        if names is None:
            return None
        return any(n.endswith("/" + facts["name"]) or n.endswith("/" + facts["short"]) for n in names)

    def writer_policies(writer):
        return asset_client.search_all_iam_policies(request={"scope": parent, "query": f'policy:"{writer}"', "page_size": 500})

    errors = {}
    try:
        project_for_metric = scope_id if scope == "project" else (get_settings().project_id or "")
        if project_for_metric:
            errors = read_export_errors(credentials, project_for_metric)
    except Exception as e:  # noqa: BLE001 — the metric is a bonus; organization and folder sinks rarely have it anywhere (D6)
        logging.info(f"[{job_id}] {AUDIT_PIPELINE_CHECK}: export errors not read: {e}")
    rows = pipeline_rows(parent, customer, scope, scope_id, members, bucket_reader=lambda name: get_bucket(logging_api, name), destination_exists=destination_exists,
                         writer_policies=writer_policies, errors=errors)
    write_rows(sink, job_id, AUDIT_PIPELINE_CHECK, rows, AUDIT_PIPELINE_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- Duplicate Log Routing -------------------------------------------------------------------------------------------------

def aggregated_bucket_sinks(sinks_by_parent):
    """The aggregated sinks into log buckets that admit what ``_Default`` stores: ``[(parent, sink)]`` over ``{parent: [sinks]}``."""
    found = []
    for parent, sinks in sinks_by_parent.items():
        if parent.startswith("projects/"):
            continue
        for sink in sinks:
            if is_builtin(sink) or sink.get("disabled") or not sink.get("includeChildren"):
                continue
            if destination_facts(sink.get("destination"))["kind"] == "bucket" and admits_default_streams(sink.get("filter")):
                found.append((parent, sink))
    return found


def default_sink_enabled(sink):
    """Whether a project's ``_Default`` sink still stores: not disabled, and no enabled exclusion that drops everything."""
    if sink.get("disabled"):
        return False
    for exclusion in sink.get("exclusions") or []:
        if not exclusion.get("disabled") and str(exclusion.get("filter") or "").strip().strip('"').lower() in ("*", "true"):
            return False
    return True


def duplicate_rows(aggregated, projects, default_sinks):
    """One row per aggregated bucket sink naming the projects below it whose ``_Default`` sink still stores: ``projects`` as
    :func:`search_projects` returns them, ``default_sinks`` ``{project id: the _Default sink}`` (a project absent is taken as storing)."""
    rows = []
    for parent, sink in aggregated:
        if parent.startswith("folders/"):
            folder_id = parent.split("/", 1)[1]
            below = [p for p in projects if folder_id in (p.get("folders") or [])]
        else:
            below = list(projects)
        doubled = sorted(p["id"] for p in below if default_sink_enabled(default_sinks.get(p["id"], {})))
        if not doubled:
            continue
        facts = destination_facts(sink.get("destination"))
        rows.append({"Resource": parent, "Sink": short_name(sink), "Destination": f"log bucket {facts['short']}", "Projects": len(doubled),
                     "Issue": "Logs stored twice.",
                     "Detail": f"The aggregated sink stores the logs of {len(doubled)} project{'s' if len(doubled) != 1 else ''} ({', '.join(doubled[:5])}{', …' if len(doubled) > 5 else ''}) in {facts['short']} "
                               f"while their own _Default sinks store them again: ingestion is billed in both buckets.",
                     "Fix": f"gcloud logging sinks update _Default --project={doubled[0]} --disabled  # per project, once the aggregated bucket is where they are read; or narrow the aggregated sink's filter",
                     "_status": INVESTIGATION})
    return rows


def required_stream_rows(sinks_by_parent):
    """Informational rows for customer sinks into log buckets whose filter admits the ``_Required`` streams."""
    rows = []
    for parent, sinks in sinks_by_parent.items():
        for sink in sinks:
            if is_builtin(sink) or sink.get("disabled"):
                continue
            facts = destination_facts(sink.get("destination"))
            if facts["kind"] != "bucket" or not admits_required_streams(sink.get("filter")):
                continue
            name = short_name(sink)
            rows.append({"Resource": parent, "Sink": name, "Destination": f"log bucket {facts['short']}", "Projects": "",
                         "Issue": "_Required streams stored again.",
                         "Detail": "Admin Activity and System Event audit logs are kept 400 days in _Required at no charge; this sink stores them a second time, billed — on purpose for a longer or locked archive, otherwise avoidable.",
                         "Fix": f"{sink_update_line(parent, name)} --log-filter='<the filter> AND NOT LOG_ID(\"cloudaudit.googleapis.com/activity\") AND NOT LOG_ID(\"cloudaudit.googleapis.com/system_event\")'",
                         "_status": INFORMATIONAL})
    return rows


def check_duplicate_routing(scope, scope_id, job_id, *, sink):
    """Writes *Duplicate Log Routing*: the aggregated bucket sinks of the organization and the folders in scope against the projects' ``_Default`` sinks."""
    print(f"🪣 [{job_id}] Checking {DUPLICATE_ROUTING_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    skipped = NotChecked(DUPLICATE_ROUTING_CHECK)
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        logging_api = gcp.api_build("logging", "v2", credentials=credentials)
        asset_client = gcp.asset_client(credentials)
        parents, projects = [parent], []
        if scope != "project":
            projects = search_projects(asset_client, parent)
            parents += [f"folders/{f}" for f in search_folders(asset_client, parent) if f"folders/{f}" != parent]
    except Exception as e:
        logging.error(f"[{job_id}] {DUPLICATE_ROUTING_CHECK}: could not list under {parent}: {e}")
        sink.write_finding(job_id, DUPLICATE_ROUTING_CHECK.replace(" ", "_"), {"Check": DUPLICATE_ROUTING_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    sinks_by_parent = {}
    for p in parents:
        try:
            sinks_by_parent[p] = list_sinks(logging_api, p)
        except Exception as e:
            skipped.add(p, e, detail="the sinks could not be listed")
    aggregated = aggregated_bucket_sinks(sinks_by_parent)
    default_sinks = {}
    if aggregated:
        for project in projects:
            try:
                default_sinks[project["id"]] = next((s for s in list_sinks(logging_api, f"projects/{project['id']}") if short_name(s) == "_Default"), {})
            except Exception as e:
                skipped.add(project["id"], e, detail="the project's _Default sink could not be read; counted as storing")
    rows = duplicate_rows(aggregated, projects, default_sinks) + required_stream_rows(sinks_by_parent)
    write_rows(sink, job_id, DUPLICATE_ROUTING_CHECK, rows, DUPLICATE_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- Project Log Routing -----------------------------------------------------------------------------------------------------

def view_excludes_data_access(view):
    """Whether a log view's filter leaves the Data Access audit logs out (the ``_Default`` view's filter as Logging creates it)."""
    return bool(_VIEW_HIDES_DATA_ACCESS.search(str(view.get("filter") or "")))


def bucket_location(bucket):
    name = str(bucket.get("name") or "")
    return name.split("/locations/")[1].split("/")[0] if "/locations/" in name else "global"


def project_routing_rows(project_id, sinks, buckets, views, data_access_on):
    """The rows of one project: its ``_Default`` sink, bucket and view. Another enabled customer sink into a log bucket stands in for a dead
    ``_Default`` only when its filter admits what ``_Default`` stores — an audit-only sink keeps the audit trail, not the project's logs
    (the sandbox probe: an activity-only sink beside a disabled ``_Default``, and the logs were discarded all the same)."""
    rows = []
    default_sink = next((s for s in sinks if short_name(s) == "_Default"), None)
    other_bucket_sinks = [s for s in sinks if not is_builtin(s) and not s.get("disabled") and destination_facts(s.get("destination"))["kind"] == "bucket"
                          and admits_default_streams(s.get("filter"))]
    if default_sink is not None and not default_sink_enabled(default_sink) and not other_bucket_sinks:
        disabled = bool(default_sink.get("disabled"))
        rows.append({"Project": project_id, "Resource": "sink _Default", "Issue": "Logs discarded.",
                     "Detail": f"The _Default sink is {'disabled' if disabled else 'excluding everything'} and no other sink stores the project's logs into a log bucket (an audit-only sink does not): "
                               "they are dropped as they arrive, the _Required audit streams excepted.",
                     "Fix": f"gcloud logging sinks update _Default --project={project_id} {'--no-disabled' if disabled else '--clear-exclusions'}",
                     "_status": ACTION_REQUIRED})
    default_bucket = next((b for b in buckets if str(b.get("name") or "").endswith("/buckets/_Default")), None)
    if default_bucket is not None:
        location = bucket_location(default_bucket)
        if data_access_on:
            default_view = next((v for v in views if str(v.get("name") or "").endswith("/views/_Default")), None)
            if default_view is not None and not view_excludes_data_access(default_view):
                rows.append({"Project": project_id, "Resource": "view _Default", "Issue": "Data Access logs in the default view.",
                             "Detail": "Data Access audit logs are on for the project and the _Default view no longer excludes them: everyone with roles/logging.viewer reads who accessed what.",
                             "Fix": f"gcloud logging views update _Default --bucket=_Default --location={location} --project={project_id} --log-filter='NOT LOG_ID(\"cloudaudit.googleapis.com/data_access\") AND NOT LOG_ID(\"externalaudit.googleapis.com/data_access\")'",
                             "_status": INFORMATIONAL})
        if not default_bucket.get("analyticsEnabled"):
            rows.append({"Project": project_id, "Resource": "bucket _Default", "Issue": "Log Analytics off.",
                         "Detail": "The _Default bucket is not upgraded to Log Analytics: no SQL over its logs in the console or BigQuery. Upgrading is free and irreversible.",
                         "Fix": f"gcloud logging buckets update _Default --location={location} --project={project_id} --enable-analytics  # irreversible", "_status": INFORMATIONAL})
    return rows


def check_project_routing(scope_id, all_projects, job_id, *, sink):
    """Writes *Project Log Routing* for every project (module docstring). The effective Data Access configuration is the project's own
    and the organization's (read once); a folder's configuration is not consulted."""
    print(f"🧭 [{job_id}] Checking {PROJECT_ROUTING_CHECK} in {len(all_projects)} projects...")
    skipped, rows = NotChecked(PROJECT_ROUTING_CHECK), []
    org_configs = None
    for project in all_projects:
        project_id = project["projectId"]
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            logging_api = gcp.api_build("logging", "v2", credentials=credentials)
            parent = f"projects/{project_id}"
            sinks = list_sinks(logging_api, parent)
            buckets = list_buckets(logging_api, parent)
        except Exception as e:
            skipped.add(project_id, e)
            continue
        views, data_access_on = [], False
        default_bucket = next((b for b in buckets if str(b.get("name") or "").endswith("/buckets/_Default")), None)
        try:
            crm = gcp.api_build("cloudresourcemanager", "v1", credentials=credentials)
            own = crm.projects().getIamPolicy(resource=project_id, body={}).execute().get("auditConfigs", [])
            if org_configs is None:
                try:
                    ancestry = crm.projects().getAncestry(projectId=project_id, body={}).execute()
                    org = next((a["resourceId"]["id"] for a in ancestry.get("ancestor", []) if a["resourceId"]["type"] == "organization"), None)
                    org_configs = crm.organizations().getIamPolicy(resource=f"organizations/{org}", body={}).execute().get("auditConfigs", []) if org else []
                except Exception as e:  # noqa: BLE001 — the organization's configuration is a bonus
                    logging.info(f"[{job_id}] {PROJECT_ROUTING_CHECK}: organization audit configuration not read: {e}")
                    org_configs = []
            assessment = audit_config_assessment([("organization", org_configs), (parent, own)])
            data_access_on = bool(assessment["types"] or assessment["services"])
            if data_access_on and default_bucket is not None:
                views = list_views(logging_api, default_bucket["name"])
        except Exception as e:
            skipped.add(project_id, e, detail="the audit configuration or the views could not be read; the view rule was not applied")
        rows += project_routing_rows(project_id, sinks, buckets, views, data_access_on)
    write_rows(sink, job_id, PROJECT_ROUTING_CHECK, rows, PROJECT_ROUTING_ALL_CLEAR)
    skipped.write(sink, job_id)
