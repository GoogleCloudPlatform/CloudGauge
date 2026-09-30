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
"""Sample scan results, shaped like what the checks write, for the worker and reporting tests."""

# Organization policies: best practices by category, and the effective policies.
BEST_PRACTICES = {
    'Security': [
        {'policyId': 'iam.disableServiceAccountKeyCreation', 'displayName': 'Disable service account key creation', 'expectedValue': 'True'},
        {'policyId': 'iam.allowedPolicyMemberDomains', 'displayName': 'Domain restricted sharing', 'expectedValue': 'True'},
    ],
    'Networking': [
        {'policyId': 'compute.skipDefaultNetworkCreation', 'displayName': 'Skip default network creation', 'expectedValue': 'True'},
        {'policyId': 'compute.vmExternalIpAccess', 'displayName': 'Restrict VM external IPs', 'expectedValue': 'True'},
    ],
    'Storage': [],  # a category without policies is left out
}
CURRENT_POLICIES = {
    'iam.disableServiceAccountKeyCreation': {'booleanPolicy': {'enforced': True}},  # Compliant
    'iam.allowedPolicyMemberDomains': {'listPolicy': {'allowedValues': ['C0abc123']}},  # Unsupported
    'compute.skipDefaultNetworkCreation': {'booleanPolicy': {}},  # enforced defaults to False: Non-compliant
    # compute.vmExternalIpAccess is not set: Not Configured
}
# The CSV rows for these policies: categories sorted, empty ones skipped.
ORG_POLICY_CSV_ROWS = [
    ['Networking', 'Skip default network creation', 'True', 'False', 'Non-compliant'],
    ['Networking', 'Restrict VM external IPs', 'True', 'N/A', 'Not Configured'],
    ['Security', 'Disable service account key creation', 'True', 'True', 'Compliant'],
    ['Security', 'Domain restricted sharing', 'True', 'List Policy/Other', 'Unsupported'],
]

# Findings by category. They cover: two records for one check (details merged,
# most severe status kept), table details with a missing key, text details,
# empty details, an error finding, and characters that are special in HTML.
FINDINGS = {
    'Security & Identity': [
        {'Check': 'Project IAM Hygiene', 'Status': 'Investigation Recommended',
         'Finding': [{'Project': 'web-prod', 'Member': 'user:alice@example.com', 'Role': 'roles/owner'}]},
        {'Check': 'Project IAM Hygiene', 'Status': 'Action Required',
         'Finding': [{'Project': 'data-lake', 'Member': 'allUsers', 'Role': 'roles/viewer'}]},
        {'Check': 'Public GCS Buckets', 'Status': 'Compliant', 'Finding': 'No public buckets found.'},
        {'Check': 'Open Firewall Rules', 'Status': 'Error', 'Finding': [{'Error': '403 compute.firewalls.list denied'}]},
    ],
    'Cost Optimization': [
        {'Check': 'Idle Persistent Disks', 'Status': 'Investigation Recommended', 'Finding': [
            {'Project': 'data-lake', 'Disk': 'orphan-disk', 'Monthly Savings': 12.4},
            {'Project': 'web-prod', 'Disk': 'old-boot-disk'},
        ]},
        {'Check': 'VM Rightsizing', 'Status': 'Compliant', 'Finding': []},
    ],
    'Reliability & Resilience': [
        {'Check': 'GKE Hygiene', 'Status': 'Compliant', 'Finding': 'All clusters use release channels.'},
        {'Check': 'Essential Contacts', 'Status': 'Action Required', 'Finding': ['No security contact', 'No billing contact']},
    ],
    'Operational Excellence & Observability': [
        {'Check': 'Unattended Projects', 'Status': 'Informational', 'Finding': ['sandbox-1', 'sandbox-2']},
        {'Check': 'Quota Utilization (>80%)', 'Status': 'Action Required',
         'Finding': [{'Project': 'web-prod', 'Quota': 'CPUS', 'Usage': '92%'}]},
    ],
}


def all_findings():
    """Every finding in FINDINGS, in category order: what a scan writes to the bucket."""
    return [finding for findings in FINDINGS.values() for finding in findings]
