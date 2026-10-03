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
"""Maps check result names to report categories.

``CATEGORY_MAP`` started as the legacy ``_read_all_findings_from_gcs`` map. Its
keys are the ``"Check"`` values that checks write. Findings whose name is not a
key are left out of the report, so every name a check can write must be here,
including the names of error results (B1/B2; enforced by
``tests/test_category_consistency.py``).
"""
import json


CATEGORY_MAP = {
    # Security & Identity
    "Critical Org-Level Roles": "Security & Identity", "Public Org-Level Access": "Security & Identity",
    "Organization IAM Policy": "Security & Identity", "Security Command Center Status": "Security & Identity",
    "Project IAM Hygiene": "Security & Identity", "Service Account Key Rotation": "Security & Identity",
    "Public GCS Buckets": "Security & Identity", "Open Firewall Rules": "Security & Identity",
    "Primitive Roles (Owner or Editor)": "Security & Identity",
    # Added with the upstream beta v1 checks (beta v1 itself left them out of this map,
    # so its reports silently dropped their findings).
    "Cloud SQL Security": "Security & Identity", "VPC Configuration": "Security & Identity",
    "GCS Uniform Bucket-Level Access": "Security & Identity", "VM External IPs": "Security & Identity",

    # Cost Optimization
    "Idle Cloud SQL Instances": "Cost Optimization", "Low Utilization VMs": "Cost Optimization",
    "VM Rightsizing": "Cost Optimization", "Unassociated IPs": "Cost Optimization",
    "Idle Load Balancers": "Cost Optimization", "Idle Persistent Disks": "Cost Optimization",
    "Underutilized Reservations": "Cost Optimization", "Idle Reservations": "Cost Optimization",

    # Reliability & Resilience
    "Cloud Storage Versioning": "Reliability & Resilience", "GKE Hygiene": "Reliability & Resilience",
    "Essential Contacts": "Reliability & Resilience",
    "Cloud SQL High Availability": "Reliability & Resilience", "Cloud SQL Automated Backups": "Reliability & Resilience",
    "Cloud SQL Backup Retention": "Reliability & Resilience", "Cloud SQL PITR": "Reliability & Resilience",
    "MIG Resilience (Zonal)": "Reliability & Resilience", "Disk Snapshot Resilience": "Reliability & Resilience",

    # Operational Excellence & Observability
    "Organization Log Sink": "Operational Excellence & Observability",
    "OS Config Agent Coverage": "Operational Excellence & Observability", "Monitoring Alert Coverage": "Operational Excellence & Observability",
    "Standalone VMs (Not in MIGs)": "Operational Excellence & Observability",
    "VPC IP Address Utilization": "Operational Excellence & Observability", "VPC Connectivity": "Operational Excellence & Observability",
    "Load Balancer Health": "Operational Excellence & Observability", "GKE IP Address Utilization": "Operational Excellence & Observability",
    "GKE Connectivity": "Operational Excellence & Observability", "GKE Service Account": "Operational Excellence & Observability",
    "Dynamic Route Health": "Operational Excellence & Observability", "Cloud SQL Connectivity": "Operational Excellence & Observability",
    "VPC Firewall Complexity (>150 Rules)": "Operational Excellence & Observability",
    "Recent Changes (Org & Project)": "Operational Excellence & Observability", "Unattended Projects": "Operational Excellence & Observability",
    "Quota Utilization (>80%)": "Operational Excellence & Observability",

    # B2: error results. These names are only written when a check fails; the
    # legacy map left them out, so failures silently disappeared from the report.
    "Organization Policies": "Security & Identity",  # policy data couldn't be fetched
    "Organization IAM Policy Check": "Security & Identity",
    "Resilience Asset Checks": "Reliability & Resilience",
    "Log Sink Check": "Operational Excellence & Observability",

    # B2: display names from app.checks.registry. When a check raises, the runner
    # records the error under this name. Names already mapped above aren't repeated;
    # test_category_consistency.py checks every registry name maps to its category.
    "Cost-Saving Recommendations": "Cost Optimization",
    "GCS Bucket Versioning": "Reliability & Resilience",
    "Resilience of Critical Assets": "Reliability & Resilience",
    "Standalone VMs": "Operational Excellence & Observability",
    "Network Insights": "Operational Excellence & Observability",
    "Miscellaneous Checks": "Operational Excellence & Observability",
    "Service Quota Limits": "Operational Excellence & Observability",
    "Organization Audit Logging": "Operational Excellence & Observability",

    # v14: the briefings (always Informational; outside the score) and their scored companions.
    "Service Health Incidents": "Reliability & Resilience",
    "Personalized Service Health API Coverage": "Reliability & Resilience",
    "Advisory Notifications": "Security & Identity",
    "Advisory Notifications Settings": "Security & Identity",
}


# Report and CSV section order: first appearance in CATEGORY_MAP. The legacy code
# built the dict from a set(), so its order depended on the hash seed.
CATEGORY_ORDER = tuple(dict.fromkeys(CATEGORY_MAP.values()))


def categorize_findings(findings):
    """
    Groups finding records by category, in ``CATEGORY_ORDER``.
    This is the categorization half of the legacy ``_read_all_findings_from_gcs``:
    every category is present (possibly empty), findings keep their input order,
    and findings whose check name is not in ``CATEGORY_MAP`` are dropped.

    A record that carries its own ``"Category"`` goes there instead: the
    ``"Projects not checked"`` record (``app.checks.not_checked``) is written
    under that one name in whichever category the skipped check belongs to.
    """
    categorized_results = {cat: [] for cat in CATEGORY_ORDER}
    for data in findings:
        # The check name is stored inside the JSON object itself
        check_name = data.get("Check")
        category = data.get("Category") or CATEGORY_MAP.get(check_name)
        if category in categorized_results:
            categorized_results[category].append(data)
    return categorized_results


def merge_shard_findings(findings):
    """
    Merges the finding records of several shards into what one scan would have written.

    A single scan writes one record per check and status (``{"Check", "Status",
    "Finding": [row, ...]}``) covering every project. Shards each write their
    own, covering their projects only, so the merge, per check name:

    - drops the "all clear" records (``Status: Compliant``, e.g.
      ``[{"Status": "No firewall rules found open to 0.0.0.0/0."}]``) of a check
      that has findings in another shard (rendered together, the placeholder
      would become a bogus table column: the report takes its headers from the
      first row);
    - collapses identical records into one (the placeholders of a check that is
      compliant in every shard);
    - joins the records that share a check name and status into one, with the
      rows of every shard in shard order, so a check that found something in
      several shards is one item with one table in the report, as in one scan.

    Records keep their input order (a joined record sits where its first part
    was) and are never shared with the input (the join copies the rows). A
    single shard's findings pass through unchanged. Records that carry their
    own ``"Category"`` (``"Projects not checked"``) join only within it.

    Rows that describe the same thing from several shards are then folded
    (``ROW_FOLDS``): an incident is listed by every project it impacted, so the
    Service Health Incidents rows of one incident become one row naming all the
    projects, as in one scan.
    """
    checks_with_findings = {f.get("Check") for f in findings if f.get("Status") != "Compliant"}
    merged, by_key, seen = [], {}, set()
    for finding in findings:
        check_name, status = finding.get("Check"), finding.get("Status")
        if status == "Compliant" and check_name in checks_with_findings:
            continue
        identity = json.dumps(finding, sort_keys=True, default=str)
        if identity in seen:
            continue
        seen.add(identity)
        key = (check_name, status, finding.get("Category"))
        rows, first = finding.get("Finding"), by_key.get(key)
        if first is not None and isinstance(rows, list) and isinstance(first.get("Finding"), list):
            first["Finding"].extend(rows)
            continue
        if isinstance(rows, list):
            finding = {**finding, "Finding": list(rows)}
            by_key.setdefault(key, finding)
        merged.append(finding)
    for finding in merged:
        fold = ROW_FOLDS.get(finding.get("Check"))
        if fold and isinstance(finding.get("Finding"), list):
            finding["Finding"] = fold(finding["Finding"])
    return merged


# --- Briefing rows folded across projects and shards -------------------------------------
# The briefings (Service Health Incidents, Advisory Notifications) list one row per incident
# or notification, naming every project it reached. A shard only sees its own projects, so
# the same incident comes back from several shards; the folds below rebuild one row from
# them, as a single scan would have written. When a briefing has nothing in its window the
# check writes one note row instead (``{"Summary": ...}``); a note from one shard is dropped
# when another shard had rows, and kept once when none did.
# The checks (app.checks.service_health, app.checks.advisories) write these columns.
INCIDENT_ID = "Incident ID"
INCIDENT_STATE = "State"
INCIDENT_STARTED = "Started"
INCIDENT_PROJECT_COUNT = "Impacted projects"
INCIDENT_PROJECTS = "Project IDs"
INCIDENT_RELEVANCE = "Relevance"
ACTIVE_INCIDENT = "Active"
# Highest first; a folded row shows the highest relevance any of its projects had.
RELEVANCE_ORDER = ("Impacted", "Related", "Partially related", "Unknown", "Not impacted")
ADVISORY_DATE = "Date"
ADVISORY_TYPE = "Type"
ADVISORY_SUBJECT = "Subject"
ADVISORY_PROJECTS = "Projects"  # folder/project scans only; an organization's notifications have no project


def _split_list(text):
    return [part.strip() for part in str(text or "").split(",") if part.strip()]


def _union(*texts):
    return ", ".join(dict.fromkeys(part for text in texts for part in _split_list(text)))


def _fold(rows, key_of, merge):
    """Rows with the same ``key_of(row)`` become one (``merge(kept, row)`` in place); rows without a key are the notes."""
    folded, order, notes = {}, [], []
    for row in rows:
        key = key_of(row)
        if not key:
            notes.append(dict(row))
        elif key in folded:
            merge(folded[key], row)
        else:
            folded[key] = dict(row)
            order.append(key)
    return [folded[key] for key in order], notes


def is_active_incident(row):
    """Whether an incident row is active (its state is "Active" or "Active (confirmed)" and the like)."""
    return str(row.get(INCIDENT_STATE) or "").startswith(ACTIVE_INCIDENT)


def fold_incident_rows(rows):
    """Folds rows with the same incident ID into one: the union of their projects, products and locations,
    the highest relevance, active if any part was active. Active incidents come first, then the most recent."""
    def merge(kept, row):
        kept[INCIDENT_PROJECTS] = _union(kept.get(INCIDENT_PROJECTS), row.get(INCIDENT_PROJECTS))
        kept[INCIDENT_PROJECT_COUNT] = len(_split_list(kept[INCIDENT_PROJECTS]))
        for column in ("Products", "Locations"):
            if column in kept or column in row:
                kept[column] = _union(kept.get(column), row.get(column))
        if is_active_incident(row) and not is_active_incident(kept):
            kept[INCIDENT_STATE] = row[INCIDENT_STATE]
            kept["Ended"] = row.get("Ended", "")
        relevances = _split_list(kept.get(INCIDENT_RELEVANCE)) + _split_list(row.get(INCIDENT_RELEVANCE))
        kept[INCIDENT_RELEVANCE] = min(relevances, key=lambda r: RELEVANCE_ORDER.index(r) if r in RELEVANCE_ORDER else len(RELEVANCE_ORDER))

    folded, notes = _fold(rows, lambda row: row.get(INCIDENT_ID), merge)
    return sort_incident_rows(folded) if folded else notes[:1]


def sort_incident_rows(rows):
    """Active incidents first, then by start time, newest first."""
    active = [r for r in rows if is_active_incident(r)]
    closed = [r for r in rows if not is_active_incident(r)]
    active.sort(key=lambda r: str(r.get(INCIDENT_STARTED) or ""), reverse=True)
    closed.sort(key=lambda r: str(r.get(INCIDENT_STARTED) or ""), reverse=True)
    return active + closed


def fold_advisory_rows(rows):
    """Folds the rows of one notification (same type, subject and date) into one naming every project; newest first."""
    def merge(kept, row):
        if ADVISORY_PROJECTS in kept or ADVISORY_PROJECTS in row:
            kept[ADVISORY_PROJECTS] = _union(kept.get(ADVISORY_PROJECTS), row.get(ADVISORY_PROJECTS))

    def key_of(row):
        key = tuple(row.get(column) for column in (ADVISORY_TYPE, ADVISORY_SUBJECT, ADVISORY_DATE))
        return key if all(key) else None

    folded, notes = _fold(rows, key_of, merge)
    folded.sort(key=lambda r: str(r.get(ADVISORY_DATE) or ""), reverse=True)
    return folded if folded else notes[:1]


ROW_FOLDS = {"Service Health Incidents": fold_incident_rows, "Advisory Notifications": fold_advisory_rows}
