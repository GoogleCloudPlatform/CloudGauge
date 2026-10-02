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
    "Essential Contacts": "Reliability & Resilience", "Personalized Service Health": "Reliability & Resilience",
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
    return merged
