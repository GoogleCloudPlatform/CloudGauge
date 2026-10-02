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
"""Cost Optimization checks (Recommender API).

Moved from ``cloudgauge.py`` (Phase 2) with mechanical changes only: each
check takes a keyword-only ``sink`` (a ``GcsResultsStore``) and writes
through ``sink.write_finding(...)``, and GCP auth and discovery calls go
through ``app.services.gcp``.

The recommendation parser that was nested in ``run_cost_recommendations``
is now the module-level ``parse_recommendation`` (unchanged).
"""
import logging

from google.api_core import exceptions as core_exceptions
from google.api_core.exceptions import PermissionDenied
from app.services import gcp
from app.utils import call_api_with_backoff


# --- Cost Optimization Checks ---

# Report name -> (Recommender ID, location type). The names are the "Check" values
# the findings are written under; each must be a key of CATEGORY_MAP.
COST_RECOMMENDERS = {
    "Idle Cloud SQL Instances": ("google.cloudsql.instance.IdleRecommender", "region"),
    "Low Utilization VMs": ("google.compute.instance.IdleResourceRecommender", "zone"),
    "VM Rightsizing": ("google.compute.instance.MachineTypeRecommender", "zone"),
    "Unassociated IPs": ("google.compute.address.IdleResourceRecommender", "region"),
    "Idle Load Balancers": ("google.compute.loadBalancer.IdleResourceRecommender", "region"),
    "Idle Persistent Disks": ("google.compute.disk.IdleResourceRecommender", "zone"),
    "Underutilized Reservations": ("google.compute.RightSizeResourceRecommender", "zone"),
    "Idle Reservations": ("google.compute.IdleResourceRecommender", "zone"),
}


def parse_recommendation(reco, project_id):
    """Safely parses a recommendation proto to extract resource name and savings."""
    resource_name = "N/A"
    cost_savings = "N/A"
    
    try:
        # Attempt to get resource name from various possible fields
        if hasattr(reco.content, 'overview'):
            overview_struct = reco.content.overview 
            if 'resourceName' in overview_struct:
                resource_name = overview_struct['resourceName']
            elif 'resource' in overview_struct:
                resource_name = overview_struct['resource'].split('/')[-1]

    
        if resource_name == "N/A":
            if (hasattr(reco.content, 'operation_groups') and 
                reco.content.operation_groups and 
                reco.content.operation_groups[0].operations and
                reco.content.operation_groups[0].operations[0].resource):
                
                # Get the full resource path, e.g., //compute.googleapis.com/.../disks/disk-1
                full_resource_path = reco.content.operation_groups[0].operations[0].resource
                resource_name = full_resource_path.split('/')[-1]

        # If both fail, check targetResources (camelCase, for Reservations etc.) ---
        if resource_name == "N/A":
            if hasattr(reco, 'targetResources') and reco.targetResources:
                target_list = reco.targetResources
                if target_list and isinstance(target_list[0], str):
                    resource_name = target_list[0].split('/')[-1]

    except Exception as e:
        logging.warning(f"Failed to parse resource name for {reco.name}: {e}")
        pass # If any error, resource_name remains "N/A"

    # Safely get cost savings
    try:
        cost = reco.primary_impact.cost_projection.cost
        savings_value = -cost.units - (cost.nanos / 1e9)
        cost_savings = f"{savings_value:,.2f} {cost.currency_code}"
    except AttributeError:
        pass

    # Build the final description string
    detail = reco.description
    if "CHANGE_MACHINE_TYPE" in reco.recommender_subtype:
        detail = f"For VM '{resource_name}', {reco.description}"
        
    return {
        "Project": project_id, 
        "Resource Name": resource_name,  # This column should now populate correctly
        "Recommendation": detail, 
        "Est. Monthly Saving": cost_savings
    }


def run_cost_recommendations(scope_id, all_projects, active_zones, active_regions, job_id, *, sink):
    """
    Fetches cost-saving recommendations from the Recommender API for all projects.
    Covers idle resources, rightsizing, and underutilized reservations.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.
        active_zones (list): A list of active GCP zones.
        active_regions (list): A list of active GCP regions.

    Returns:
        list: A list of finding dictionaries detailing cost recommendations.
    """
    print("💰 Performing Cost Recommendation checks in parallel...")
    if not all_projects: return []
    
    #active_zones, active_regions = get_active_compute_locations(org_id, all_projects)

    def check_project(project):
        project_id = project['projectId']
        findings_map = {}
        recommender_map = COST_RECOMMENDERS
        try:
            client = gcp.recommender_client()
            for check, (rec_id, loc_type) in recommender_map.items():
                locations = active_zones if loc_type == "zone" else active_regions
                for loc in locations:
                    if loc_type in ['region', 'zone'] and loc == 'global':
                        continue
                    parent = f"projects/{project_id}/locations/{loc}/recommenders/{rec_id}"
                    try:
                        api_call = lambda: client.list_recommendations(parent=parent)
                        context = f"'{check}' in {project_id} at {loc}"
                        for reco in call_api_with_backoff(api_call, context_message=context):
                            finding = parse_recommendation(reco, project_id)
                            if check not in findings_map:
                                findings_map[check] = []
                            findings_map[check].append(finding)
                    except (PermissionDenied, core_exceptions.FailedPrecondition):
                        logging.warning(f"Skipping '{check}' for {project_id} in {loc} due to permissions or disabled API.")
                        break 
                    except Exception as e:
                        logging.error(f"An unexpected API error occurred (or parser failed) for '{check}' in {project_id} at {loc}: {e}")
        except Exception as e:
            logging.error(f"CRITICAL: Cost check failed for project {project_id}. Error: {e}")
        
        return findings_map

    project_results_list = []
    for project in all_projects:
        project_results_list.append(check_project(project))
    
    final_findings_by_check = {}
    for project_map in project_results_list:
        for check_name, findings in project_map.items():
            if check_name not in final_findings_by_check:
                final_findings_by_check[check_name] = []
            final_findings_by_check[check_name].extend(findings)

    for check_name, all_findings in final_findings_by_check.items():
        if all_findings:
            result = {"Check": check_name, "Finding": all_findings, "Status": "Action Required"}
            # Use the check_name as the unique identifier for the filename
            sink.write_finding(job_id, check_name.replace(" ", "_"), result)
