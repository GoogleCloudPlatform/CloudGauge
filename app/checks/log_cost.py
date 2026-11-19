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
"""Log Cost Levers (v18.8): the three settings that decide most of a Cloud Logging bill, per project.

Cost Optimization. Everything comes from reads the scanner's roles already allow:

- **Retention beyond 30 days** (Informational — compliance may want it; the row says
  how many days are paid): a log bucket other than ``_Required`` with ``retentionDays``
  over the 30 included with ingestion, from ``projects.locations.buckets.list``
  (Logging API). A locked bucket cannot be shortened; its row says so.
- **Flow-log sampling above 0.5** (*Investigation Recommended*): a subnet with VPC
  flow logs on and ``flowSampling`` over the console's default of 0.5 — 1.0 doubles the
  volume — from ``subnetworks.aggregatedList`` (the call *VPC Configuration* makes);
  all metadata and the 5-second aggregation interval, when set on top, go into the
  fix.
- **DEBUG logs ingested at volume** (*Investigation Recommended*): DEBUG entries at
  ``DEBUG_SHARE`` (10 %) or more of a project's 30-day log volume, the volume above
  the 50 GiB a month the free tier covers, and no enabled exclusion on the ``_Default``
  sink that drops them — the volume from Cloud Monitoring
  (``logging.googleapis.com/byte_count`` summed by severity), the sinks from
  ``projects.sinks.list``. ``_Required`` streams, Data Access logs and the severities
  above DEBUG are never proposed for exclusion.

Projects whose reads fail are reported under *Projects not checked*, the row naming the
step (buckets, subnets, log volume); a project without the Compute Engine API has no
subnets to read.
"""
from datetime import timedelta

from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp
from app.utils import utcnow

LOG_COST_CHECK = "Log Cost Levers"
INFORMATIONAL, INVESTIGATION, COMPLIANT = "Informational", "Investigation Recommended", "Compliant"
INCLUDED_RETENTION_DAYS = 30  # storage up to 30 days is included with ingestion; beyond it is billed per GiB-month
FREE_TIER_GIB = 50  # the first 50 GiB of log ingestion per project and month are free
DEBUG_SHARE = 0.10
FLOW_SAMPLING_TARGET = 0.5
VOLUME_DAYS = 30
REQUIRED_BUCKET = "_Required"
DEFAULT_SINK = "_Default"
COMPUTE_API = "compute.googleapis.com"
BYTE_COUNT_METRIC = "logging.googleapis.com/byte_count"
GIB = 1024 ** 3
ALL_CLEAR = (f"No log bucket keeps logs beyond the {INCLUDED_RETENTION_DAYS} included days, no subnet samples more than half its flows, and no project "
             f"above the free tier ingests DEBUG logs at volume without an exclusion.")


# --- facts and rules ---------------------------------------------------------------------------------------------------

def bucket_id(name):
    """``_Default`` and ``global`` of ``projects/p/locations/global/buckets/_Default``: ``(bucket, location)``."""
    parts = str(name or "").split("/")
    bucket = parts[parts.index("buckets") + 1] if "buckets" in parts and parts.index("buckets") + 1 < len(parts) else str(name or "")
    location = parts[parts.index("locations") + 1] if "locations" in parts and parts.index("locations") + 1 < len(parts) else "global"
    return bucket, location


def bucket_rows(project_id, buckets):
    """The retention rows of a project's log buckets (Informational): every active bucket but ``_Required`` kept beyond the included days."""
    rows = []
    for bucket in buckets:
        name, location = bucket_id(bucket.get("name"))
        days = int(bucket.get("retentionDays") or 0)
        if name == REQUIRED_BUCKET or days <= INCLUDED_RETENTION_DAYS or str(bucket.get("lifecycleState") or "ACTIVE") != "ACTIVE":
            continue
        paid = days - INCLUDED_RETENTION_DAYS
        if bucket.get("locked"):
            fix = (f"The bucket is locked: its retention cannot be shortened. Route less into it instead — exclusions on the sinks that feed it "
                   f"(gcloud logging sinks update {DEFAULT_SINK} --project={project_id} --add-exclusion='name=<name>,filter=<what to drop>').")
        else:
            fix = f"gcloud logging buckets update {name} --location={location} --project={project_id} --retention-days={INCLUDED_RETENTION_DAYS}"
        rows.append({"Project": project_id, "Resource": f"log bucket {name} ({location})", "Issue": f"Retention beyond {INCLUDED_RETENTION_DAYS} days.",
                     "Detail": f"Keeps {days} days: the {paid} beyond the {INCLUDED_RETENTION_DAYS} included with ingestion are billed storage, per GiB and month"
                               + (", and the bucket is locked" if bucket.get("locked") else "") + ". Keep it where a policy requires the history.",
                     "Fix": fix, "_status": INFORMATIONAL})
    return rows


def subnet_region(subnet):
    return str(subnet.get("region") or "").rstrip("/").rsplit("/", 1)[-1]


def flow_log_rows(project_id, subnets):
    """The sampling rows (Investigation): subnets with flow logs on and a sampling rate above ``FLOW_SAMPLING_TARGET``."""
    rows = []
    for subnet in subnets:
        config = subnet.get("logConfig") or {}
        if not (config.get("enable") or subnet.get("enableFlowLogs")):
            continue
        try:
            sampling = float(config.get("flowSampling", 0.5) if config.get("flowSampling") is not None else 0.5)
        except (TypeError, ValueError):
            sampling = 0.5
        if sampling <= FLOW_SAMPLING_TARGET:
            continue
        region = subnet_region(subnet)
        all_metadata = str(config.get("metadata") or "").upper() == "INCLUDE_ALL_METADATA"
        fast = str(config.get("aggregationInterval") or "").upper() == "INTERVAL_5_SEC"
        extras = []
        if all_metadata:
            extras.append("--logging-metadata=exclude-all")
        if fast:
            extras.append("--logging-aggregation-interval=interval-5-min")
        detail = (f"Samples {sampling * 100:.0f} % of flows (the console default is {FLOW_SAMPLING_TARGET * 100:.0f} %; the log volume, and its ingestion "
                  f"bill, scale with the rate)" + (", with all metadata" if all_metadata else "") + (", aggregated every 5 seconds" if fast else "") + ".")
        rows.append({"Project": project_id, "Resource": f"subnet {subnet.get('name')} ({region})", "Issue": f"Flow log sampling above {FLOW_SAMPLING_TARGET}.", "Detail": detail,
                     "Fix": f"gcloud compute networks subnets update {subnet.get('name')} --region={region} --project={project_id} --logging-flow-sampling={FLOW_SAMPLING_TARGET}"
                            + (f"  # and {' '.join(extras)} to cut the volume further" if extras else ""), "_status": INVESTIGATION})
    return rows


def debug_excluded(sinks):
    """Whether an enabled exclusion on the ``_Default`` sink (or any sink into the ``_Default`` bucket) drops DEBUG entries."""
    for sink in sinks:
        name = str(sink.get("name") or "").rsplit("/", 1)[-1]
        if name != DEFAULT_SINK and not str(sink.get("destination") or "").endswith(f"/buckets/{DEFAULT_SINK}"):
            continue
        for exclusion in sink.get("exclusions") or []:
            if exclusion.get("disabled"):
                continue
            text = "".join(str(exclusion.get("filter") or "").split()).upper()
            if "SEVERITY=DEBUG" in text or "SEVERITY<=DEBUG" in text or "SEVERITY<INFO" in text or "SEVERITY=\"DEBUG\"" in text:
                return True
    return False


def severity_volume(series):
    """``{severity: bytes}`` over Monitoring time series of ``byte_count`` reduced by severity (every point summed)."""
    volume = {}
    for entry in series or []:
        severity = str(((entry.get("metric") or {}).get("labels") or {}).get("severity") or "DEFAULT").upper()
        total = 0
        for point in entry.get("points") or []:
            value = point.get("value") or {}
            try:
                total += int(float(value.get("int64Value") if value.get("int64Value") is not None else value.get("doubleValue") or 0))
            except (TypeError, ValueError):
                continue
        volume[severity] = volume.get(severity, 0) + total
    return volume


def debug_rows(project_id, volume, excluded):
    """The DEBUG row (Investigation) when DEBUG is ``DEBUG_SHARE`` of a project's volume above the free tier and nothing excludes it."""
    total = sum(volume.values())
    debug = volume.get("DEBUG", 0)
    if total <= FREE_TIER_GIB * GIB or debug < DEBUG_SHARE * total or excluded:
        return []
    return [{"Project": project_id, "Resource": "log ingestion", "Issue": "DEBUG logs ingested at volume.",
             "Detail": f"DEBUG entries were {debug / total * 100:.0f} % of the {total / GIB:,.1f} GiB ingested in {VOLUME_DAYS} days (the first {FREE_TIER_GIB} GiB a month are "
                       f"free, the rest is billed per GiB), and no exclusion on the {DEFAULT_SINK} sink drops them.",
             "Fix": f"gcloud logging sinks update {DEFAULT_SINK} --project={project_id} --add-exclusion='name=drop-debug,filter=severity=DEBUG'", "_status": INVESTIGATION}]


# --- reads -----------------------------------------------------------------------------------------------------------------

def list_buckets(logging_api, project_id):
    found, collection = [], logging_api.projects().locations().buckets()
    request = collection.list(parent=f"projects/{project_id}/locations/-")
    while request:
        response = request.execute() or {}
        found += response.get("buckets") or []
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def list_sinks(logging_api, project_id):
    found, collection = [], logging_api.projects().sinks()
    request = collection.list(parent=f"projects/{project_id}")
    while request:
        response = request.execute() or {}
        found += response.get("sinks") or []
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def list_subnets(compute, project_id):
    found, collection = [], compute.subnetworks()
    request = collection.aggregatedList(project=project_id)
    while request:
        response = request.execute() or {}
        for entry in (response.get("items") or {}).values():
            found += entry.get("subnetworks") or []
        request = collection.aggregatedList_next(previous_request=request, previous_response=response)
    return found


def volume_request(project_id, now):
    """The ``timeSeries.list`` arguments: ``byte_count`` over the last ``VOLUME_DAYS`` days, one aligned sum per severity."""
    start = now - timedelta(days=VOLUME_DAYS)
    return {"name": f"projects/{project_id}", "filter": f'metric.type = "{BYTE_COUNT_METRIC}"',
            "interval_startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "interval_endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "aggregation_alignmentPeriod": f"{VOLUME_DAYS * 86400}s", "aggregation_perSeriesAligner": "ALIGN_SUM",
            "aggregation_crossSeriesReducer": "REDUCE_SUM", "aggregation_groupByFields": ["metric.label.severity"], "view": "FULL"}


def list_volume(monitoring, project_id, now):
    found, collection = [], monitoring.projects().timeSeries()
    request = collection.list(**volume_request(project_id, now))
    while request:
        response = request.execute() or {}
        found += response.get("timeSeries") or []
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


# --- the check ----------------------------------------------------------------------------------------------------------

def check_log_cost(scope_id, all_projects, job_id, *, sink):
    """Writes *Log Cost Levers* for every project (module docstring)."""
    print(f"🧾 [{job_id}] Checking {LOG_COST_CHECK} in {len(all_projects)} projects...")
    skipped, rows, now = NotChecked(LOG_COST_CHECK), [], utcnow()
    for project in all_projects:
        project_id = project["projectId"]
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            logging_api = gcp.api_build("logging", "v2", credentials=credentials)
            compute = gcp.api_build("compute", "v1", credentials=credentials)
            monitoring = gcp.api_build("monitoring", "v3", credentials=credentials)
        except Exception as e:
            skipped.add(project_id, e)
            continue
        try:
            rows += bucket_rows(project_id, list_buckets(logging_api, project_id))
        except Exception as e:
            skipped.add(project_id, e, detail="log buckets")
        try:
            rows += flow_log_rows(project_id, list_subnets(compute, project_id))
        except Exception as e:
            skipped.add(project_id, e, detail="flow-log sampling", resource_apis=(COMPUTE_API,))
        try:
            volume = severity_volume(list_volume(monitoring, project_id, now))
            excluded = debug_excluded(list_sinks(logging_api, project_id)) if volume else False
            rows += debug_rows(project_id, volume, excluded)
        except Exception as e:
            skipped.add(project_id, e, detail="log volume by severity")
    statuses = {row.pop("_status", INFORMATIONAL) for row in rows}
    if rows:
        status = INVESTIGATION if INVESTIGATION in statuses else INFORMATIONAL
        result = {"Check": LOG_COST_CHECK, "Finding": rows, "Status": status}
    else:
        result = {"Check": LOG_COST_CHECK, "Finding": [{"Status": ALL_CLEAR}], "Status": COMPLIANT}
    sink.write_finding(job_id, LOG_COST_CHECK.replace(" ", "_"), result)
    skipped.write(sink, job_id)
