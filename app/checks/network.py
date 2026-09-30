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
import logging
import re

from google.cloud import recommender_v1
from google.cloud.recommender_v1.types import Insight

from app.utils import call_api_with_backoff


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


def run_network_insights(scope_id, all_projects, active_zones, active_regions, job_id, *, sink):
    """
    Fetches and parses Network Analyzer insights across all projects.
    Normalizes various insight types into a consistent, table-friendly format.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.
        active_zones (list): A list of active GCP zones.
        active_regions (list): A list of active GCP regions.

    Returns:
        list: A list of finding dictionaries, grouped by insight type.
    """
    print("🌐 Performing Network Insights checks (Final Normalized Parser)...")
    if not all_projects: return []
    
    all_locations = active_zones + active_regions

    insight_type_map = {
        "VPC IP Address Utilization": "google.networkanalyzer.vpcnetwork.ipAddressInsight",
        "VPC Connectivity": "google.networkanalyzer.vpcnetwork.connectivityInsight",
        "Load Balancer Health": "google.networkanalyzer.networkservices.loadBalancerInsight",
        "GKE IP Address Utilization": "google.networkanalyzer.container.ipAddressInsight",
        "GKE Connectivity": "google.networkanalyzer.container.connectivityInsight",
        "GKE Service Account": "google.networkanalyzer.container.serviceAccountInsight",
        "Dynamic Route Health": "google.networkanalyzer.hybridconnectivity.dynamicRouteInsight",
        "Cloud SQL Connectivity": "google.networkanalyzer.managedservices.cloudSqlInsight",
    }

    def check_project(project):
        project_id = project['projectId']
        project_findings_map = {} 
        try:
            client = recommender_v1.RecommenderClient()
            for loc in all_locations:
                for check_name, insight_type_id in insight_type_map.items(): 
                    parent = f"projects/{project_id}/locations/{loc}/insightTypes/{insight_type_id}"
                    try:
                        api_call = lambda: client.list_insights(parent=parent)
                        context = f"'{check_name}' in {project_id} at {loc}"
                        for insight in call_api_with_backoff(api_call,context_message=context):
                            parsed_data_list = []
                            try:
                                insight_dict = Insight.to_dict(insight)
                                
                                # --- MODIFIED CALL ---
                                # Pass the check_name INTO the parser so it knows what it's parsing.
                                parsed_data_list = parse_network_insight_content(insight_dict, insight.description, project_id, check_name)

                            except Exception as e:
                                parsed_data_list = [{"Project": project_id, "Finding Type": "Top-level Parse Error", "Resource": insight.description, "Detail": str(e), "Value": "N/A"}]
                            
                            if check_name not in project_findings_map:
                                project_findings_map[check_name] = []

                            project_findings_map[check_name].extend(parsed_data_list)
                            
                    except Exception:
                        pass 
        except Exception as e:
            logging.warning(f"Could not check network insights for {project_id}: {e}")
        return project_findings_map
        

    project_results_list = []
    for project in all_projects:
        project_results_list.append(check_project(project))

    
    # Aggregate results from all projects
    final_findings_by_check = {}
    for project_map in project_results_list:
        for check_name, findings in project_map.items():
            if check_name not in final_findings_by_check:
                final_findings_by_check[check_name] = []
            final_findings_by_check[check_name].extend(findings)


    # Write one file per insight type
    for check_name, all_findings in final_findings_by_check.items():
        if all_findings:
            result = {"Check": check_name, "Finding": all_findings, "Status": "Action Required"}
            sink.write_finding(job_id, check_name.replace(" ", "_"), result)
