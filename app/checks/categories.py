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

``CATEGORY_MAP`` is moved unchanged from the legacy ``_read_all_findings_from_gcs``.
Its keys are the ``"Check"`` values that checks write. Findings whose name is
not a key are left out of the report.
"""


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
    "Quota Utilization (>80%)": "Operational Excellence & Observability"
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
    """
    categorized_results = {cat: [] for cat in CATEGORY_ORDER}
    for data in findings:
        # The check name is stored inside the JSON object itself
        check_name = data.get("Check")
        category = CATEGORY_MAP.get(check_name)
        if category:
            categorized_results[category].append(data)
    return categorized_results
