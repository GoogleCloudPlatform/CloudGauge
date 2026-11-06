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
"""Network Analyzer insights.

Moved from ``cloudgauge.py`` (Phase 2) with mechanical changes only: each
check takes a keyword-only ``sink`` (a ``GcsResultsStore``) and writes
through ``sink.write_finding(...)``, and GCP auth and discovery calls go
through ``app.services.gcp``.

The insight parser that was nested in ``run_network_insights`` is now the
module-level ``parse_network_insight_content`` (unchanged).
"""
import re

from google.cloud.recommender_v1.types import Insight

from app.checks.not_checked import (LOCATION_DISCOVERY_APIS, NotChecked, describe_parts, failures_by_reason, is_request_error,
                                    location_detail)
from app.services import gcp
from app.utils import call_api_with_backoff


# Report name -> Network Analyzer insight type. The names are the "Check" values
# the findings are written under; each must be a key of CATEGORY_MAP.
NETWORK_INSIGHT_TYPES = {
    "VPC IP Address Utilization": "google.networkanalyzer.vpcnetwork.ipAddressInsight",
    "VPC Connectivity": "google.networkanalyzer.vpcnetwork.connectivityInsight",
    "Load Balancer Health": "google.networkanalyzer.networkservices.loadBalancerInsight",
    "GKE IP Address Utilization": "google.networkanalyzer.container.ipAddressInsight",
    "GKE Connectivity": "google.networkanalyzer.container.connectivityInsight",
    "GKE Service Account": "google.networkanalyzer.container.serviceAccountInsight",
    "Dynamic Route Health": "google.networkanalyzer.hybridconnectivity.dynamicRouteInsight",
    "Cloud SQL Connectivity": "google.networkanalyzer.managedservices.cloudSqlInsight",
}


# --- THIS HELPER FUNCTION DOES ALL THE PARSING ---
def parse_network_insight_content(insight_dict, description, project_id, check_name):
    """
    Helper to parse raw insight data into a structured dictionary. This version includes
    the corrected logic for extracting the GKE cluster name for serviceAccountInsight.
    """
    parsed_findings_list = []
    content_dict = insight_dict.get('content', {})
    
    if check_name == "GKE Service Account":
        resource_name = "N/A"  # Default value

        # Method 1 (Most Reliable): Use the specific, nested clusterUri from your log data.
        try:
            # Path: content -> nodeServiceAccountInsight -> clusterUri
            cluster_uri = content_dict.get('nodeServiceAccountInsight', {}).get('clusterUri')
            if cluster_uri and isinstance(cluster_uri, str):
                resource_name = cluster_uri.split('/')[-1]
        except Exception:
            pass # Failsafe

        # Method 2 (Excellent Fallback): Use the top-level 'target_resources' field.
        if resource_name == "N/A":
            target_resources = insight_dict.get('target_resources', [])
            if target_resources and isinstance(target_resources[0], str):
                resource_name = target_resources[0].split('/')[-1]

        # Method 3 (Final Fallback): Regex on the description string.
        if resource_name == "N/A":
            match = re.search(r"GKE cluster '([^']+)'", description)
            if match:
                resource_name = match.group(1)

        # Append the finding once, after all attempts are complete.
        parsed_findings_list.append({
            "Project": project_id,
            "Finding Type": "GKE Service Account",
            "Resource": f"Cluster: {resource_name}",
            "Detail": description,
            "Value": "Compute Engine default service account"
        })

# --- END OF GKE PARSER ---

    # --- END OF MODIFICATION ---
    
    # --- EXISTING PARSERS FOR OTHER INSIGHT TYPES ---
    elif 'Utilization' in check_name:
        # For Subnet IP Utilization
        if 'ipUtilizationSummaryInfo' in content_dict:
            for info in content_dict.get('ipUtilizationSummaryInfo', []):
                for net_stat in info.get('networkStats', []):
                    network = net_stat.get('networkUri', 'N/A').split('/')[-1]
                    for sub_stat in net_stat.get('subnetStats', []):
                        subnet = sub_stat.get('subnetUri', 'N/A').split('/')[-1]
                        for range_stat in sub_stat.get('subnetRangeStats', []):
                            parsed_findings_list.append({
                                "Project": project_id,
                                "Finding Type": "Subnet Utilization",
                                "Resource": f"Subnet: {subnet} (Network: {network})",
                                "Detail": f"Range: {range_stat.get('subnetRangePrefix', 'N/A')}",
                                "Value": f"{range_stat.get('allocationRatio', 0) * 100:.2f}% Allocation"
                            })
            
        # For PSA IP Utilization
        if 'psaIpUtilizationSummaryInfo' in content_dict:
            for info in content_dict.get('psaIpUtilizationSummaryInfo', []):
                for net_stat in info.get('networkStats', []):
                    network = net_stat.get('networkUri', 'N/A').split('/')[-1]
                    for psa_stat in net_stat.get('psaStats', []):
                        parsed_findings_list.append({
                            "Project": project_id,
                            "Finding Type": "PSA Utilization",
                            "Resource": f"Network: {network}",
                            "Detail": f"PSA Range: {psa_stat.get('psaRangePrefix', 'N/A')}",
                            "Value": f"{psa_stat.get('allocationRatio', 0) * 100:.2f}% Allocation"
                        })

        # For GKE IP Utilization
        if 'gkeIpUtilizationSummaryInfo' in content_dict:
            for info in content_dict.get('gkeIpUtilizationSummaryInfo', []):
                for cluster_stat in info.get('clusterStats', []):
                    parsed_findings_list.append({
                        "Project": project_id,
                        "Finding Type": "GKE Utilization",
                        "Resource": f"Cluster: {cluster_stat.get('clusterUri', 'N/A').split('/')[-1]}",
                        "Detail": f"Pod Range Usage: {cluster_stat.get('podRangesAllocationRatio', 0) * 100:.2f}%",
                        "Value": f"Service Range Usage: {cluster_stat.get('serviceRangesAllocationRatio', 0) * 100:.2f}%"
                    })

        # For Unassigned External IPs
        if 'overallStats' in content_dict:
            stats = content_dict['overallStats']
            parsed_findings_list.append({
                    "Project": project_id,
                    "Finding Type": "Unassigned IPs",
                    "Resource": "Organization (Overall)",
                    "Detail": f"Total Reserved: {stats.get('reservedCount', 0):.0f}",
                    "Value": f"Unassigned Count: {stats.get('unassignedCount', 0):.0f} ({stats.get('unassignedRatio', 0) * 100:.2f}%)"
            })

    # --- Fallback for any other insight types remains the same ---
    if not parsed_findings_list:
        # This block now also handles cases where an error might occur in a specific parser
        parsed_findings_list.append({
            "Project": project_id,
            "Finding Type": "General Insight",
            "Resource": description,
            "Detail": "(No structured data)",
            "Value": "See finding"
        })
        
    return parsed_findings_list


# v18: insights by severity. Network Analyzer rates every insight; an informational one is not a verdict against Operations.
SEVERITY_STATUS = {"CRITICAL": "Action Required", "HIGH": "Action Required", "MEDIUM": "Investigation Recommended",
                   "LOW": "Informational", "SEVERITY_UNSPECIFIED": "Investigation Recommended", "": "Investigation Recommended"}
STATUS_RANK = {"Action Required": 3, "Investigation Recommended": 2, "Informational": 1, "Compliant": 0}
NOTHING_FOUND = {name: f"No active {name} insights from Network Analyzer." for name in NETWORK_INSIGHT_TYPES}
ACTIVE_INSIGHTS = "stateInfo.state = ACTIVE"


def insight_locations(active_regions):
    """Where Network Analyzer is asked (v18): ``global`` (VPC, hybrid and managed-service insights) plus the active regions
    (GKE insights live at the cluster's region); never zones, which answer nothing."""
    regions = [region for region in active_regions if region and region != "global"]
    return ["global"] + sorted(set(regions))


def insight_severity(insight_dict):
    """The insight's severity name (``CRITICAL`` … ``LOW``), ``""`` when it has none."""
    severity = insight_dict.get("severity")
    return str(getattr(severity, "name", severity) or "").upper()


def is_active_insight(insight_dict):
    """Whether an insight is still ACTIVE (a dismissed or accepted one is not a finding)."""
    state = (insight_dict.get("state_info") or insight_dict.get("stateInfo") or {}).get("state")
    return str(getattr(state, "name", state) or "ACTIVE").upper() in ("ACTIVE", "STATE_UNSPECIFIED", "0")


def run_network_insights(scope_id, all_projects, active_zones, active_regions, job_id, location_errors=None, *, sink):
    """
    Fetches and parses Network Analyzer insights across all projects.
    Normalizes various insight types into a consistent, table-friendly format.

    v18: asked at ``global`` and the active regions only (``insight_locations``), ACTIVE insights
    only, every row carries the insight's ``Severity`` and the record's status follows the worst of
    them (``SEVERITY_STATUS``: an informational insight no longer reads *Action Required*), and an
    insight type that answered everywhere with nothing writes its Compliant row instead of nothing.

    Args:
        scope_id (str): The organization, folder, or project ID being scanned.
        all_projects (list): A list of project dictionaries.
        active_zones (list): A list of active GCP zones (no longer queried).
        active_regions (list): A list of active GCP regions.
        location_errors (dict): Project ID -> the error that stopped location discovery
            for it (``get_active_compute_locations``); such a project is reported as
            not checked, having been queried only at other projects' locations.
    """
    print("🌐 Performing Network Insights checks (Final Normalized Parser)...")
    if not all_projects: return []

    all_locations = insight_locations(active_regions)
    location_errors = location_errors or {}

    insight_type_map = NETWORK_INSIGHT_TYPES
    # Skips are reported under the check's display name (app.checks.registry); the
    # rows say which insight types could not be queried for the project.
    skipped = NotChecked("Network Insights")
    answered = set()  # insight types that completed a listing somewhere: the ones that reached a verdict

    def check_project(project):
        project_id = project['projectId']
        project_findings_map = {}
        failed = {}  # insight name -> the first error that stopped it in this project

        def note_failure(check_name, error):
            # Every insight type is queried at global and every region; an invalid
            # argument or not-found there is a location mismatch, not a skipped project.
            if not is_request_error(error):
                failed.setdefault(check_name, error)

        try:
            client = gcp.recommender_client()
            for loc in all_locations:
                for check_name, insight_type_id in insight_type_map.items():
                    parent = f"projects/{project_id}/locations/{loc}/insightTypes/{insight_type_id}"
                    try:
                        errors = []
                        api_call = lambda: client.list_insights(request={"parent": parent, "filter": ACTIVE_INSIGHTS})
                        context = f"'{check_name}' in {project_id} at {loc}"
                        on_error = lambda error, name=check_name: (errors.append(error), note_failure(name, error))
                        for insight in call_api_with_backoff(api_call, context_message=context, on_error=on_error):
                            parsed_data_list = []
                            try:
                                insight_dict = Insight.to_dict(insight, use_integers_for_enums=False)  # severity and state by name
                                if not is_active_insight(insight_dict):
                                    continue
                                parsed_data_list = parse_network_insight_content(insight_dict, insight.description, project_id, check_name)
                                severity = insight_severity(insight_dict)
                            except Exception as e:
                                parsed_data_list = [{"Project": project_id, "Finding Type": "Top-level Parse Error", "Resource": insight.description, "Detail": str(e), "Value": "N/A"}]
                                severity = ""
                            for row in parsed_data_list:
                                row["Severity"] = severity.capitalize() if severity else "Unrated"
                                row["_status"] = SEVERITY_STATUS.get(severity, "Investigation Recommended")
                            project_findings_map.setdefault(check_name, []).extend(parsed_data_list)
                        if not errors:
                            answered.add(check_name)
                    except Exception as e:
                        note_failure(check_name, e)
        except Exception as e:
            skipped.add(project_id, e)
            return project_findings_map
        for error, names in failures_by_reason(failed):
            skipped.add(project_id, error, detail=describe_parts(names, len(insight_type_map), "insight type"))
        # A project whose locations could not be discovered, unless every insight type
        # failed for it anyway (the rows above already say it was not checked).
        if project_id in location_errors and len(failed) < len(insight_type_map):
            skipped.add(project_id, location_errors[project_id], resource_apis=LOCATION_DISCOVERY_APIS,
                        detail=location_detail(bool(all_locations), len(insight_type_map), "insight type"))
        return project_findings_map


    project_results_list = []
    for project in all_projects:
        project_results_list.append(check_project(project))


    # Aggregate results from all projects
    final_findings_by_check = {}
    for project_map in project_results_list:
        for check_name, findings in project_map.items():
            final_findings_by_check.setdefault(check_name, []).extend(findings)

    # Write one file per insight type: its rows under the worst severity, or its all-clear row when it answered with none.
    for check_name in insight_type_map:
        all_findings = final_findings_by_check.get(check_name)
        if all_findings:
            statuses = [row.pop("_status", "Investigation Recommended") for row in all_findings]
            status = max(statuses, key=lambda s: STATUS_RANK.get(s, 0))
            result = {"Check": check_name, "Finding": all_findings, "Status": status}
        elif check_name in answered:
            result = {"Check": check_name, "Finding": [{"Status": NOTHING_FOUND[check_name]}], "Status": "Compliant"}
        else:
            continue  # no verdict: nothing to write
        sink.write_finding(job_id, check_name.replace(" ", "_"), result)
    skipped.write(sink, job_id)
