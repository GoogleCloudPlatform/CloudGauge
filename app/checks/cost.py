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
from app.checks.not_checked import (LOCATION_DISCOVERY_APIS, NotChecked, describe_parts, failures_by_reason, is_request_error,
                                    location_detail)
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

# What a recommender's Compliant row says when it answered and had nothing to recommend (v15.2).
# The other checks word their all-clear rows the same way ("No public buckets found.").
NOTHING_FOUND = {
    "Idle Cloud SQL Instances": "No idle Cloud SQL instances found.",
    "Low Utilization VMs": "No low-utilization VMs found.",
    "VM Rightsizing": "No VM rightsizing recommendations found.",
    "Unassociated IPs": "No unassociated IP addresses found.",
    "Idle Load Balancers": "No idle load balancers found.",
    "Idle Persistent Disks": "No idle persistent disks found.",
    "Underutilized Reservations": "No underutilized reservations found.",
    "Idle Reservations": "No idle reservations found.",
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


def run_cost_recommendations(scope_id, all_projects, active_zones, active_regions, job_id, location_errors=None, *, sink):
    """
    Fetches cost-saving recommendations from the Recommender API for all projects.
    Covers idle resources, rightsizing, and underutilized reservations.

    Each recommender is one check of the report. It writes an Action Required
    record with its recommendations, or a Compliant record (``NOTHING_FOUND``)
    when it answered in at least one project and had none - the verdict the
    score counts (app.reporting.scoring). A recommender nobody could ask (no
    zones or regions to query, every call failed, or every location answered
    that it is not offered there) writes nothing: it reached no verdict, and the
    failures are on the *Projects not checked* rows.

    Args:
        scope_id (str): The organization, folder, or project ID being scanned.
        all_projects (list): A list of project dictionaries.
        active_zones (list): A list of active GCP zones.
        active_regions (list): A list of active GCP regions.
        location_errors (dict): Project ID -> the error that stopped location discovery
            for it (``get_active_compute_locations``). Such a project is reported as
            not checked: nothing was queried for it when no other project supplied
            locations, and only other projects' locations otherwise.

    Returns:
        list: A list of finding dictionaries detailing cost recommendations.
    """
    print("💰 Performing Cost Recommendation checks in parallel...")
    if not all_projects: return []
    
    #active_zones, active_regions = get_active_compute_locations(org_id, all_projects)
    location_errors = location_errors or {}

    # Skips are reported under the check's display name (app.checks.registry); the
    # rows say which recommenders could not be queried for the project. A disabled
    # Recommender API is reported too: the project may well have idle resources.
    skipped = NotChecked("Cost-Saving Recommendations")
    answered = set()  # recommenders that completed a query somewhere: the ones that reached a verdict

    def check_project(project):
        project_id = project['projectId']
        findings_map = {}
        recommender_map = COST_RECOMMENDERS
        failed = {}  # recommender name -> the first error that stopped it in this project
        queried = False  # whether any recommender was queried for the project at all

        def note_failure(check, error):
            # An invalid argument or not-found means the recommender is not offered in
            # that location (asia-south1 answers 400 for Idle Load Balancers), not that
            # the project could not be checked.
            if not is_request_error(error):
                failed.setdefault(check, error)

        try:
            client = gcp.recommender_client()
            for check, (rec_id, loc_type) in recommender_map.items():
                locations = active_zones if loc_type == "zone" else active_regions
                for loc in locations:
                    if loc_type in ['region', 'zone'] and loc == 'global':
                        continue
                    queried = True
                    parent = f"projects/{project_id}/locations/{loc}/recommenders/{rec_id}"
                    try:
                        errors = []
                        api_call = lambda: client.list_recommendations(parent=parent)
                        context = f"'{check}' in {project_id} at {loc}"
                        on_error = lambda error, name=check: (errors.append(error), note_failure(name, error))
                        for reco in call_api_with_backoff(api_call, context_message=context, on_error=on_error):
                            finding = parse_recommendation(reco, project_id)
                            if check not in findings_map:
                                findings_map[check] = []
                            findings_map[check].append(finding)
                        if not errors:
                            answered.add(check)
                    except (PermissionDenied, core_exceptions.FailedPrecondition) as e:
                        logging.warning(f"Skipping '{check}' for {project_id} in {loc} due to permissions or disabled API.")
                        note_failure(check, e)
                        break 
                    except Exception as e:
                        logging.error(f"An unexpected API error occurred (or parser failed) for '{check}' in {project_id} at {loc}: {e}")
                        note_failure(check, e)
        except Exception as e:
            logging.error(f"CRITICAL: Cost check failed for project {project_id}. Error: {e}")
            skipped.add(project_id, e)
            return findings_map
        for error, names in failures_by_reason(failed):
            skipped.add(project_id, error, detail=describe_parts(names, len(recommender_map), "recommender"))
        # A project whose locations could not be discovered, unless every recommender
        # failed for it anyway (the rows above already say it was not checked).
        if project_id in location_errors and len(failed) < len(recommender_map):
            skipped.add(project_id, location_errors[project_id], resource_apis=LOCATION_DISCOVERY_APIS,
                        detail=location_detail(queried, len(recommender_map), "recommender"))
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

    for check_name in COST_RECOMMENDERS:
        all_findings = final_findings_by_check.get(check_name)
        if all_findings:
            result = {"Check": check_name, "Finding": all_findings, "Status": "Action Required"}
        elif check_name in answered:
            result = {"Check": check_name, "Finding": [{"Status": NOTHING_FOUND[check_name]}], "Status": "Compliant"}
        else:
            continue  # no verdict: nothing to write
        # Use the check_name as the unique identifier for the filename
        sink.write_finding(job_id, check_name.replace(" ", "_"), result)
    skipped.write(sink, job_id)
