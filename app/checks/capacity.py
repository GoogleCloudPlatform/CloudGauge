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
"""Capacity checks (v17): what is reserved and committed, what runs without a reservation,
and where Compute Engine has been short of capacity or quota.

Two checks, four names in the report:

- ``check_capacity_commitments`` reads every project's reservations, future
  reservations and committed use discounts (three Compute Engine aggregated
  listings) and its running instances, and writes

  - **Capacity Commitments** (Reliability, a briefing: *Informational*, never
    scored): one row per reservation, future reservation and commitment —
    what, where, how much, in use, status, when it ends;
  - **Reservation Coverage** (Reliability): a project running
    ``RESERVATION_COVERAGE_MIN_VCPUS`` or more vCPUs in one zone with fewer
    reserved there — steady compute a zonal stockout or a maintenance event
    would have nowhere to put; *Investigation Recommended* with the
    ``gcloud compute reservations create`` line for the zone's most common
    machine type;
  - **Commitments Expiring** (Cost Optimization): active commitments that end
    within ``COMMITMENT_EXPIRY_DAYS`` and do not renew on their own —
    *Investigation Recommended* with the ``--auto-renew`` line.

- ``check_capacity_signals`` asks Cloud Logging, per project, for the Compute
  Engine operations of the last ``CAPACITY_SIGNAL_WINDOW_DAYS`` that failed
  for want of capacity (``ZONE_RESOURCE_POOL_EXHAUSTED``, "does not have
  enough resources available") or of quota (``QUOTA_EXCEEDED``), and writes
  **Capacity Signals** (Reliability): one row per project, zone, resource and
  kind of signal with the event count and when it was last seen; *Action
  Required* when a signal is younger than ``CAPACITY_SIGNAL_URGENT_DAYS``,
  *Investigation Recommended* otherwise.

Every name ends the scan with a verdict or an all-clear row (the briefing with
a note). Projects whose listings fail are reported under *Projects not
checked* for the scored names (``app.checks.not_checked``).
"""
import re
from collections import Counter
from datetime import timedelta

from app.checks.not_checked import NotChecked
from app.config import SCOPES, get_settings
from app.services import gcp
from app.utils import days_between, parse_timestamp, utcnow

COMMITMENTS_BRIEFING = "Capacity Commitments"
COVERAGE_CHECK = "Reservation Coverage"
EXPIRING_CHECK = "Commitments Expiring"
SIGNALS_CHECK = "Capacity Signals"
# The scored names this module writes (the briefing is Informational); tests/test_category_consistency.py reads it.
CAPACITY_CHECKS = (COVERAGE_CHECK, EXPIRING_CHECK, SIGNALS_CHECK)
COMPUTE_API = "compute.googleapis.com"
# A commitment ending within this many days is listed (the plan is to renew it, replace it, or let it lapse knowingly).
COMMITMENT_EXPIRY_DAYS = 90
# How far back Capacity Signals looks, and how recent a signal must be to be Action Required.
CAPACITY_SIGNAL_WINDOW_DAYS = 30
CAPACITY_SIGNAL_URGENT_DAYS = 7
# One Cloud Logging page per project is read (the newest entries first); the count is then "N+" when a page was full.
LOG_PAGE_SIZE = 500
STOCKOUT, QUOTA = "Stockout", "Quota"
# vCPUs of the machine types whose name does not end in the count.
VCPUS_BY_TYPE = {
    "e2-micro": 2, "e2-small": 2, "e2-medium": 2, "f1-micro": 1, "g1-small": 1,
    "a2-highgpu-1g": 12, "a2-highgpu-2g": 24, "a2-highgpu-4g": 48, "a2-highgpu-8g": 96, "a2-megagpu-16g": 96,
    "a2-ultragpu-1g": 12, "a2-ultragpu-2g": 24, "a2-ultragpu-4g": 48, "a2-ultragpu-8g": 96,
    "a3-highgpu-1g": 26, "a3-highgpu-2g": 52, "a3-highgpu-4g": 104, "a3-highgpu-8g": 208, "a3-megagpu-8g": 208,
    "a3-edgegpu-8g": 208, "a3-ultragpu-8g": 224, "a4-highgpu-8g": 224,
}


def machine_type_vcpus(machine_type):
    """The vCPUs of a machine type given by name or URL (``n2-standard-8`` → 8, ``n2-custom-4-16384`` → 4,
    ``e2-medium`` → 2, ``a2-highgpu-1g`` → 12), or ``None`` when the name says nothing about it."""
    name = str(machine_type or "").rsplit("/", 1)[-1].lower()
    if not name:
        return None
    if name in VCPUS_BY_TYPE:
        return VCPUS_BY_TYPE[name]
    parts = name.split("-")
    if "custom" in parts:
        index = parts.index("custom")
        return int(parts[index + 1]) if index + 1 < len(parts) and parts[index + 1].isdigit() else None
    return int(parts[-1]) if parts[-1].isdigit() else None


def short_name(url):
    """The last segment of a resource URL (``.../zones/us-central1-a`` → ``us-central1-a``); ``""`` for none."""
    return str(url or "").rstrip("/").rsplit("/", 1)[-1]


def _date(timestamp):
    """``2026-10-01`` of an API timestamp, or ``""``."""
    parsed = parse_timestamp(timestamp)
    return parsed.date().isoformat() if parsed else ""


def _aggregated(compute, collection, project_id, key, **kwargs):
    """Every item of ``collection().aggregatedList(project=...)`` under its scope key: ``[(scope, item), ...]``."""
    found, request = [], getattr(compute, collection)().aggregatedList(project=project_id, **kwargs)
    while request:
        response = request.execute()
        for scope, entry in (response.get("items") or {}).items():
            for item in entry.get(key) or []:
                found.append((scope.split("/", 1)[-1], item))
        request = getattr(compute, collection)().aggregatedList_next(previous_request=request, previous_response=response)
    return found


def describe_resources(resources):
    """``"16 vCPU, 64 GB, 2 NVIDIA_TESLA_T4"`` of a commitment's ``resources`` list."""
    parts = []
    for resource in resources or []:
        kind, amount = str(resource.get("type", "")).upper(), resource.get("amount", "")
        if kind == "VCPU":
            parts.append(f"{amount} vCPU")
        elif kind == "MEMORY":
            parts.append(f"{int(int(amount) / 1024) if str(amount).isdigit() else amount} GB")
        elif kind == "ACCELERATOR":
            parts.append(f"{amount} {short_name(resource.get('acceleratorType')) or 'accelerators'}")
        else:
            parts.append(f"{amount} {kind.lower()}")
    return ", ".join(parts)


def describe_instances(count, properties):
    """``"4 × e2-medium (4 × NVIDIA_TESLA_T4)"`` of a reservation's count and instance properties."""
    properties = properties or {}
    text = f"{count} × {short_name(properties.get('machineType')) or 'instances'}"
    accelerators = [f"{a.get('acceleratorCount', 1) * int(count or 0)} × {short_name(a.get('acceleratorType'))}"
                    for a in properties.get("guestAccelerators") or []]
    return text + (f" ({', '.join(accelerators)})" if accelerators else "")


def reservation_rows(project_id, zone, reservation):
    """The briefing row of a reservation and its reserved vCPUs: ``(row, (zone, vcpus))``."""
    specific = reservation.get("specificReservation") or {}
    count = int(specific.get("count") or 0)
    properties = specific.get("instanceProperties") or {}
    row = {"Project": project_id, "Kind": "Reservation", "Name": reservation.get("name"), "Location": zone,
           "Resources": describe_instances(count, properties), "In Use": specific.get("inUseCount", ""),
           "Status": reservation.get("status", ""), "Ends": ""}
    vcpus = machine_type_vcpus(properties.get("machineType"))
    return row, (zone, count * vcpus if vcpus and reservation.get("status", "READY") == "READY" else 0)


def future_reservation_row(project_id, zone, reservation):
    properties = reservation.get("specificSkuProperties") or {}
    window = reservation.get("timeWindow") or {}
    return {"Project": project_id, "Kind": "Future reservation", "Name": reservation.get("name"), "Location": zone,
            "Resources": describe_instances(int(properties.get("totalCount") or 0), properties.get("instanceProperties")),
            "In Use": "", "Status": (reservation.get("status") or {}).get("procurementStatus", ""),
            "Ends": f"{_date(window.get('startTime'))} → {_date(window.get('endTime'))}".strip(" →")}


def commitment_row(project_id, region, commitment):
    return {"Project": project_id, "Kind": "Commitment", "Name": commitment.get("name"), "Location": region,
            "Resources": describe_resources(commitment.get("resources")), "In Use": "",
            "Status": f"{commitment.get('status', '')}{' · auto-renew' if commitment.get('autoRenew') else ''}".strip(),
            "Ends": _date(commitment.get("endTimestamp"))}


def expiring_row(project_id, region, commitment, now, within_days=COMMITMENT_EXPIRY_DAYS):
    """The Commitments Expiring row of an active, non-renewing commitment ending within ``within_days``; else ``None``."""
    if commitment.get("status", "ACTIVE") != "ACTIVE" or commitment.get("autoRenew"):
        return None
    end = parse_timestamp(commitment.get("endTimestamp"))
    if end is None:
        return None
    days = days_between(now, end)
    if days < 0 or days > within_days:
        return None
    name = commitment.get("name")
    return {"Project": project_id, "Commitment": name, "Region": region, "Plan": commitment.get("plan", ""),
            "Resources": describe_resources(commitment.get("resources")), "Ends": end.date().isoformat(), "Days Left": days,
            "Issue": f"Ends in {days} days and does not renew: the discount stops and the capacity it backs becomes on-demand.",
            "Fix": f"gcloud compute commitments update {name} --project={project_id} --region={region} --auto-renew"}


def running_vcpus_by_zone(instances):
    """``{zone: (vCPUs running, Counter of machine types)}`` over ``(zone, instance)`` pairs of RUNNING instances."""
    by_zone = {}
    for zone, instance in instances:
        if instance.get("status", "RUNNING") != "RUNNING":
            continue
        machine_type = short_name(instance.get("machineType"))
        vcpus = machine_type_vcpus(machine_type) or 0
        total, types = by_zone.setdefault(zone, (0, Counter()))
        types[machine_type] += 1
        by_zone[zone] = (total + vcpus, types)
    return by_zone


def coverage_rows(project_id, instances, reserved, minimum):
    """The Reservation Coverage rows of a project: zones running ``minimum``+ vCPUs with fewer reserved."""
    rows = []
    for zone, (running, types) in sorted(running_vcpus_by_zone(instances).items()):
        covered = reserved.get(zone, 0)
        if running < minimum or covered >= running:
            continue
        machine_type, count = types.most_common(1)[0]
        rows.append({"Project": project_id, "Zone": zone, "Running vCPUs": running, "Reserved vCPUs": covered,
                     "Issue": f"{running} vCPUs run in {zone} with {covered} reserved: a stockout or a maintenance event in the zone "
                              f"has nowhere to put them.",
                     "Fix": f"gcloud compute reservations create {project_id}-{zone}-reserved --project={project_id} --zone={zone} "
                            f"--vm-count={count} --machine-type={machine_type} --require-specific-reservation"})
    return rows


def check_capacity_commitments(scope_id, all_projects, job_id, *, sink):
    """Writes Capacity Commitments, Reservation Coverage and Commitments Expiring for every project (module docstring)."""
    print(f"📦 [{job_id}] Checking {COMMITMENTS_BRIEFING}, {COVERAGE_CHECK} and {EXPIRING_CHECK} in {len(all_projects)} projects...")
    minimum, now = get_settings().reservation_coverage_min_vcpus, utcnow()
    coverage_skipped = NotChecked(COVERAGE_CHECK, resource_apis=(COMPUTE_API,))
    expiring_skipped = NotChecked(EXPIRING_CHECK, resource_apis=(COMPUTE_API,))
    briefing, coverage, expiring = [], [], []
    for project in all_projects:
        project_id = project["projectId"]
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build("compute", "v1", credentials=credentials)
            reserved = Counter()
            for zone, reservation in _aggregated(compute, "reservations", project_id, "reservations"):
                row, (reserved_zone, vcpus) = reservation_rows(project_id, zone, reservation)
                briefing.append(row)
                reserved[reserved_zone] += vcpus
            for zone, reservation in _aggregated(compute, "futureReservations", project_id, "futureReservations"):
                briefing.append(future_reservation_row(project_id, zone, reservation))
            for region, commitment in _aggregated(compute, "regionCommitments", project_id, "commitments"):
                briefing.append(commitment_row(project_id, region, commitment))
                row = expiring_row(project_id, region, commitment, now)
                if row:
                    expiring.append(row)
            instances = _aggregated(compute, "instances", project_id, "instances", filter='status = "RUNNING"')
            coverage.extend(coverage_rows(project_id, instances, reserved, minimum))
        except Exception as e:
            coverage_skipped.add(project_id, e)
            expiring_skipped.add(project_id, e)
    rows = briefing or [{"Summary": "No reservations, future reservations or commitments in the scanned projects."}]
    sink.write_finding(job_id, COMMITMENTS_BRIEFING.replace(" ", "_"), {"Check": COMMITMENTS_BRIEFING, "Finding": rows, "Status": "Informational"})
    _write(sink, job_id, COVERAGE_CHECK, coverage, "Investigation Recommended",
           f"No project runs {minimum} or more vCPUs in a zone without reservations covering them.")
    coverage_skipped.write(sink, job_id)
    expiring.sort(key=lambda row: (row["Days Left"], row["Project"], row["Commitment"]))
    _write(sink, job_id, EXPIRING_CHECK, expiring, "Investigation Recommended",
           f"No commitment ends within the next {COMMITMENT_EXPIRY_DAYS} days without renewing.")
    expiring_skipped.write(sink, job_id)


def _write(sink, job_id, check, rows, status, all_clear):
    if rows:
        result = {"Check": check, "Finding": rows, "Status": status}
    else:
        result = {"Check": check, "Finding": [{"Status": all_clear}], "Status": "Compliant"}
    sink.write_finding(job_id, check.replace(" ", "_"), result)


# --- Capacity Signals -------------------------------------------------------------------------------------------

STOCKOUT_MARKERS = ("ZONE_RESOURCE_POOL_EXHAUSTED", "does not have enough resources available", "resource pool exhausted")
QUOTA_MARKERS = ("QUOTA_EXCEEDED", "Quota exceeded", "quotaExceeded")


def signals_filter(since):
    """The Cloud Logging filter: Compute Engine operations since ``since`` (RFC 3339) that failed for capacity or quota."""
    return (f'timestamp >= "{since}" AND ('
            'protoPayload.status.message:("ZONE_RESOURCE_POOL_EXHAUSTED" OR "does not have enough resources available" OR "QUOTA_EXCEEDED") '
            'OR protoPayload.response.error.errors.reason="quotaExceeded")')


def classify_signal(message):
    """``STOCKOUT``, ``QUOTA`` or ``None`` for a log entry's status message."""
    text = str(message or "")
    if any(marker.lower() in text.lower() for marker in STOCKOUT_MARKERS):
        return STOCKOUT
    if any(marker.lower() in text.lower() for marker in QUOTA_MARKERS):
        return QUOTA
    return None


def signal_of(entry):
    """``(zone, resource, kind, timestamp)`` of a log entry, or ``None`` when it is not a capacity or quota signal."""
    payload = entry.get("protoPayload") or {}
    status = payload.get("status") or {}
    message = status.get("message") or ""
    reasons = [e.get("reason") for e in ((payload.get("response") or {}).get("error") or {}).get("errors", [])]
    kind = classify_signal(message) or (QUOTA if "quotaExceeded" in reasons else None)
    if kind is None:
        return None
    labels = (entry.get("resource") or {}).get("labels") or {}
    zone = labels.get("zone") or labels.get("location") or ""
    if not zone:
        match = re.search(r"/(?:zones|regions)/([a-z0-9-]+)", str(payload.get("resourceName") or ""))
        zone = match.group(1) if match else "global"
    request = payload.get("request") or {}
    accelerators = request.get("guestAccelerators") or []
    if accelerators:
        resource = short_name(accelerators[0].get("acceleratorType")) or "accelerators"
    elif request.get("machineType"):
        resource = short_name(request.get("machineType"))
    else:
        resource = str(payload.get("methodName") or "").split(".")[-2] if "." in str(payload.get("methodName") or "") else "instances"
    return zone, resource, kind, entry.get("timestamp") or ""


def check_capacity_signals(scope_id, all_projects, job_id, *, sink):
    """Writes Capacity Signals for every project (module docstring)."""
    print(f"📉 [{job_id}] Checking {SIGNALS_CHECK} in {len(all_projects)} projects...")
    now = utcnow()
    since = (now - timedelta(days=CAPACITY_SIGNAL_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    skipped = NotChecked(SIGNALS_CHECK)
    rows = []
    for project in all_projects:
        project_id = project["projectId"]
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            logging_api = gcp.api_build("logging", "v2", credentials=credentials)
            body = {"resourceNames": [f"projects/{project_id}"], "filter": signals_filter(since), "orderBy": "timestamp desc",
                    "pageSize": LOG_PAGE_SIZE}
            response = logging_api.entries().list(body=body).execute() or {}
        except Exception as e:
            skipped.add(project_id, e)
            continue
        entries = response.get("entries") or []
        grouped = {}
        for entry in entries:
            signal = signal_of(entry)
            if signal is None:
                continue
            zone, resource, kind, timestamp = signal
            count, last = grouped.get((zone, resource, kind), (0, ""))
            grouped[(zone, resource, kind)] = (count + 1, max(last, timestamp))
        more = bool(response.get("nextPageToken"))
        for (zone, resource, kind), (count, last) in sorted(grouped.items()):
            seen = parse_timestamp(last)
            age = days_between(seen, now) if seen else None
            what = "Compute Engine could not find capacity" if kind == STOCKOUT else "the project hit a quota"
            rows.append({"Project": project_id, "Zone": zone, "Resource": resource, "Signal": kind,
                         "Events": f"{count}+" if more else count,
                         "Last Seen": seen.strftime("%Y-%m-%d %H:%M UTC") if seen else "",
                         "Issue": f"{what} for {resource} in {zone}" + (f", last {age} days ago." if age is not None else "."),
                         "_age": age if age is not None else CAPACITY_SIGNAL_WINDOW_DAYS})
    ages = [row.pop("_age") for row in rows]
    urgent = any(age <= CAPACITY_SIGNAL_URGENT_DAYS for age in ages)
    _write(sink, job_id, SIGNALS_CHECK, rows, "Action Required" if urgent else "Investigation Recommended",
           f"No stockout or quota errors in Compute Engine operations in the last {CAPACITY_SIGNAL_WINDOW_DAYS} days.")
    skipped.write(sink, job_id)
