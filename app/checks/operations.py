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
"""Operational Excellence & Observability checks.

Moved from ``cloudgauge.py`` (Phase 2) with mechanical changes only: each
check takes a keyword-only ``sink`` (a ``GcsResultsStore``) and writes
through ``sink.write_finding(...)``, and GCP auth and discovery calls go
through ``app.services.gcp``.
"""
import concurrent.futures
import logging
import re

from google.api_core import exceptions as core_exceptions

from app.config import SCOPES
from app.services import gcp
from app.utils import call_api_with_backoff


# --- Operational Excellence Checks ---

def check_audit_logging(org_id, job_id, *, sink):
    """
    Verifies if an organization-level log sink is configured for centralized audit logging.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries.
    """
    CHECK_NAME = "Organization Log Sink"
    print(f"📜 [{job_id}] Checking for {CHECK_NAME}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('logging', 'v2', credentials=credentials)
        sinks = service.organizations().sinks().list(parent=f'organizations/{org_id}').execute().get('sinks', [])
        if sinks:
            finding_data = [{"Sink Name": s['name'], "Destination": s['destination']} for s in sinks]
            result = {"Check": CHECK_NAME, "Finding": finding_data, "Status": "Compliant"}
        else:
            result = {"Check": CHECK_NAME, "Finding": [{"Issue": "No organization-level log sink configured."}], "Status": "Action Required"}
    except Exception as e:
        result = {"Check": "Log Sink Check", "Finding": [{"Error": str(e)}], "Status": "Error"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_os_config_coverage(scope_id, all_projects, job_id, *, sink):
    """
    Checks VM instances across all projects to identify those not reporting to OS Config.
    This helps ensure patch management and inventory visibility. Excludes GKE and Dataproc VMs.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries listing VMs without OS Config agent coverage.
    """
    CHECK_NAME = "OS Config Agent Coverage"
    print(f"🤖 [{job_id}] Checking for {CHECK_NAME} in parallel...")
    if not all_projects: return []

    def check_single_project(project):
        project_id = project['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            osconfig = gcp.osconfig_client()
            vms, req = [], compute.instances().aggregatedList(project=project_id, filter='status = "RUNNING"')
            while req:
                resp = req.execute(); req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)
                for res in resp.get('items', {}).values():
                    if 'instances' in res: vms.extend(res['instances'])
            if not vms: return None

            # --- FIX: Added a filter to exclude Dataproc VMs by label ---
            missing = [
                vm['name'] for vm in vms
                if not vm['name'].startswith('gke-')
                and 'goog-dataproc-cluster-name' not in vm.get('labels', {})
                and not any(item.get('key') == 'gke-cluster-name' for item in vm.get('metadata', {}).get('items', []))
                and not _is_os_reporting(osconfig, project_id, vm)
            ]

            if missing: return {"Project": project_id, "VMs Not Reporting": ", ".join(sorted(missing))}
        except core_exceptions.FailedPrecondition:
            return {"Project": project_id, "Issue": "OS inventory management disabled."}
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return None

    def _is_os_reporting(client, project, vm):
        try:
            path = f"projects/{project}/locations/{vm['zone'].split('/')[-1]}/instances/{vm['name']}/inventory"
            client.get_inventory(request={"name": path})
            return True
        except core_exceptions.NotFound:
            return False
        except Exception:
            return False

    results = []
    for project in all_projects:
        # check_single_project returns a single dictionary or None
        finding = check_single_project(project)
        if finding:
            # We append the single dictionary to our list of results
            results.append(finding)

    if not results:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All unmanaged VMs appear to have OS Config agent."}], "Status": "Compliant"}
    else:
        result = {"Check": CHECK_NAME, "Finding": results, "Status": "Action Required"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_monitoring_coverage(scope_id, all_projects, job_id, *, sink):
    """
    Scans projects for key monitoring alert policies (e.g., for Cloud SQL, GKE, Quotas).

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for projects missing essential alerts.
    """
    CHECK_NAME = "Monitoring Alert Coverage"
    print(f"📊 [{job_id}] Checking {CHECK_NAME} in parallel...")
    if not all_projects: return []
    
    def check_project(project):
        project_id, issues = project['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            monitor = gcp.api_build('monitoring', 'v3', credentials=credentials)
            asset = gcp.asset_client(credentials)
            policies = monitor.projects().alertPolicies().list(name=f"projects/{project_id}").execute().get('alertPolicies', [])
            filters = " ".join(c.get('conditionThreshold', {}).get('filter', '') for p in policies for c in p.get('conditions', [])).lower()
            
            asset_map = {'sqladmin.googleapis.com/Instance': 'Cloud SQL', 'container.googleapis.com/Cluster': 'GKE Cluster', 'compute.googleapis.com/ForwardingRule': 'Load Balancer'}
            for asset_type, name in asset_map.items():
                if list(asset.list_assets(request={"parent": f"projects/{project_id}", "asset_types": [asset_type]})) and name.lower().replace(" ", "_") not in filters:
                    issues.append({"Project": project_id, "Issue": f"Missing alert policy for {name}"})
            if "serviceruntime.googleapis.com/quota" not in filters:
                issues.append({"Project": project_id, "Issue": "Missing Quota alerting policy"})
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return issues
        
    results = []
    for project in all_projects:
        # check_project returns a list of findings for the project
        findings = check_project(project)
        if findings:
            # We extend the main results list with the items from the findings list
            results.extend(findings)

    if not results:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All projects appear to have key alert policies."}], "Status": "Compliant"}
    else:
        result = {"Check": CHECK_NAME, "Finding": results, "Status": "Action Required"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_standalone_vms(scope_id, all_projects, job_id, *, sink):
    """
    Identifies standalone VMs that are not managed by a Managed Instance Group (MIG).
    Excludes GKE and Dataproc VMs.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for standalone VMs.
    """
    CHECK_NAME = "Standalone VMs (Not in MIGs)"
    print(f"🖥️  [{job_id}] Checking for {CHECK_NAME}...")

    def check_project(p):
        project_id = p['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            vms, req = [], compute.instances().aggregatedList(project=project_id, filter='status = "RUNNING"')
            while req:
                resp = req.execute(); req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)
                for res in resp.get('items', {}).values():
                    if 'instances' in res: vms.extend(res['instances'])

            # --- FIX: Added a filter to exclude Dataproc VMs by label and GKE by name ---
            standalone = [
                vm['name'] for vm in vms
                if not any(item.get('key') == 'created-by' for item in vm.get('metadata', {}).get('items', []))
                and not vm['name'].startswith('gke-')
                and 'goog-dataproc-cluster-name' not in vm.get('labels', {})
            ]
            
            if standalone:
                return {"Project": project_id, "Standalone VMs": ", ".join(sorted(standalone))}
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return None

    all_findings = []
    for project in all_projects:
        finding = check_project(project)
        if finding:
            all_findings.append(finding)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Investigation Recommended"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No running standalone, unmanaged VMs found."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def run_miscellaneous_checks_refactored(scope, scope_id, all_projects, job_id, *, sink):
    """
    Runs a series of miscellaneous operational checks, such as firewall complexity,
    recent changes, and unattended projects, respecting the scan scope.
    """
    print("🔍 Performing Miscellaneous checks...")
    if not all_projects:
        return []

    # Initialize lists to hold structured data for each finding type
    firewall_findings = []
    recent_change_findings = []
    unattended_findings = []


    # --- Check 1: Firewall Rules (Runs for all scopes) ---
    def check_firewall_rules_count(project):
        project_id = project['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute_service = gcp.api_build('compute', 'v1', credentials=credentials)
            rules = compute_service.firewalls().list(project=project_id).execute().get('items', [])
            if len(rules) > 150:
                return {"Project": project_id, "Rule Count": len(rules), "Recommendation": f"Project has {len(rules)} firewall rules."}
        except Exception as e: logging.warning(f"Could not check firewall_rule_count for {project_id}: {e}")
        return None

    firewall_findings = []
    for project in all_projects:
        finding = check_firewall_rules_count(project)
        if finding:
            firewall_findings.append(finding)

    if firewall_findings:
        result = {"Check": "VPC Firewall Complexity (>150 Rules)", "Finding": firewall_findings, "Status": "Investigation Recommended"}
        sink.write_finding(job_id, "VPC_Firewall_Complexity", result)

    # --- Org-Level Recommender/Insight Checks (Run ONLY for organization scope) ---
    if scope == 'organization':
        print("   -> Checking for organization-level insights...")
        try:
            recommender_client = gcp.recommender_client()
            
            # Check for Org-Level Recent Changes
            parent_recent = f"organizations/{scope_id}/locations/global/insightTypes/google.cloud.RecentChangeInsight"
            api_call_recent = lambda: recommender_client.list_insights(parent=parent_recent)
            for insight in call_api_with_backoff(api_call_recent, context_message="Org-Level Recent Changes"):
                recent_change_findings.append({
                    "Project": f"Org-Level ({scope_id})",
                    "Insight": insight.description
                })

            # Check for Unattended Project Recommendations
            parent_unattended = f"organizations/{scope_id}/locations/global/recommenders/google.resourcemanager.projectUtilization.Recommender"
            api_call_unattended = lambda: recommender_client.list_recommendations(parent=parent_unattended)
            for reco in call_api_with_backoff(api_call_unattended, context_message="Unattended Projects"):
                project_id_from_reco = "Unknown"
                # Method 1: Try the structured targetResources field (camelCase)
                if hasattr(reco, 'targetResources') and reco.targetResources:
                    project_id_from_reco = reco.targetResources[0].split('/')[-1]

                # Method 2: Try the operation_groups field (snake_case)
                elif (hasattr(reco.content, 'operation_groups') and reco.content.operation_groups and
                      reco.content.operation_groups[0].operations and reco.content.operation_groups[0].operations[0].resource):
                    project_id_from_reco = reco.content.operation_groups[0].operations[0].resource.split('/')[-1]

                # Method 3: As a final fallback, parse the description string
                elif reco.description:
                    match = re.search(r"Project `([^`]+)`", reco.description)
                    if match:
                        project_id_from_reco = match.group(1)
                        
                unattended_findings.append({"Project": project_id_from_reco, "Recommendation": reco.description})
        except Exception as e:
            # Add a single error message if the org-level API calls fail
            error_finding = {"Project": scope_id, "Insight": f"Could not retrieve organization-level insights. Error: {e}"}
            recent_change_findings.append(error_finding)
            unattended_findings.append(error_finding)


    # --- Project-Level Recent Changes Check (Runs for all scopes) ---
    print("   -> Checking for project-level recent changes...")
    def check_project_for_iam_changes(project):
        project_id = project['projectId']
        project_findings_list = []
        try:
            recommender_client = gcp.recommender_client()
            parent = f"projects/{project_id}/locations/global/insightTypes/google.cloud.RecentChangeInsight"
            insights = recommender_client.list_insights(parent=parent)
            for insight in insights:
                project_findings_list.append({
                    "Project": project_id,
                    "Insight": insight.description
                })
        except Exception:
            pass 
        return project_findings_list

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_project_for_iam_changes, all_projects)
        for res_list in results:
            recent_change_findings.extend(res_list)

    # --- Final Assembly ---
    if recent_change_findings:
        result = {"Check": "Recent Changes (Org & Project)", "Finding": recent_change_findings, "Status": "Informational"}
        sink.write_finding(job_id, "Recent_Changes", result)
    
    if unattended_findings:
        result = {"Check": "Unattended Projects", "Finding": unattended_findings, "Status": "Action Required"}
        sink.write_finding(job_id, "Unattended_Projects", result)

    print("✅ Miscellaneous checks complete.")


def run_service_limit_checks_refactored(scope_id, all_projects, job_id, *, sink):
    """
    Checks regional compute quotas for all projects to identify any approaching their limit (>80%).

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for quotas with high utilization.
    """
    CHECK_NAME = "Quota Utilization (>80%)"
    print(f"🚦 [{job_id}] Performing Service Limit (Quota) checks...")
    
    def check_project_quotas(project):
        project_id = project['projectId']
        exceeded_quotas = [] # Store findings for this project here
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute_service = gcp.api_build('compute', 'v1', credentials=credentials)
            regions = [r['name'] for r in compute_service.regions().list(project=project_id).execute().get('items', [])]
            
            for region in regions:
                quotas = compute_service.regions().get(project=project_id, region=region).execute().get('quotas', [])
                for quota in quotas:
                    usage = quota.get('usage', 0.0)
                    limit = quota.get('limit', 0.0)
                    if limit > 0 and (usage / limit) > 0.8: # Check if usage > 80%
                        # Add the structured data to our list
                        exceeded_quotas.append({
                            "Project": project_id,
                            "Region": region,
                            "Metric": quota['metric'],
                            "Usage": f"{usage/limit:.1%}",
                            "Details": f"{int(usage)}/{int(limit)}"
                        })
        except Exception:
            pass 
        return exceeded_quotas # Return the list of findings (will be empty if none)

    all_findings = []
    for project in all_projects:
        # check_project_quotas returns a list of findings for the project
        findings = check_project_quotas(project)
        if findings:
            # We extend the main list with the items from the returned list
            all_findings.extend(findings)

    print("✅ Service Limit checks complete.")
    
    # Wrap the final list in our standard check group format
    if not all_findings:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No quotas found over 80% utilization."}], "Status": "Compliant"}
    else:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    sink.write_finding(job_id, "Quota_Utilization", result)
