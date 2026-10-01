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
"""Security & Identity checks.

Moved from ``cloudgauge.py`` (Phase 2) with mechanical changes only: each
check takes a keyword-only ``sink`` (a ``GcsResultsStore``) and writes
through ``sink.write_finding(...)``, and GCP auth and discovery calls go
through ``app.services.gcp``.
"""
import logging
from datetime import datetime, timezone

from google.cloud import storage
from googleapiclient.errors import HttpError

from app.config import SCOPES
from app.services import gcp
from app.services.org_policies import fetch_best_practices, get_effective_org_policies


# --- Security & Identity Checks ---

def check_org_iam_policy(org_id, job_id, *, sink):
    """
    Checks the organization-level IAM policy for critical and public role bindings.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries.
    """
    CHECK_NAME_CRITICAL = "Critical Org-Level Roles"
    CHECK_NAME_PUBLIC = "Public Org-Level Access"
    print(f"🕵️  [{job_id}] Checking for {CHECK_NAME_CRITICAL} and {CHECK_NAME_PUBLIC}...")

    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
        policy = service.organizations().getIamPolicy(resource=f'organizations/{org_id}', body={}).execute()
        
        critical_roles = ['roles/owner', 'roles/resourcemanager.organizationAdmin']
        public_principals = ['allUsers', 'allAuthenticatedUsers']

        # --- Check 1: Critical Org-Level Roles ---
        crit_role_findings = [{"Role": b.get('role'), "Principal": m} 
                              for b in policy.get('bindings', []) 
                              if b.get('role') in critical_roles 
                              for m in b.get('members', [])]
        
        if crit_role_findings:
            result_crit = {"Check": CHECK_NAME_CRITICAL, "Finding": crit_role_findings, "Status": "Action Required"}
        else:
            result_crit = {"Check": CHECK_NAME_CRITICAL, "Finding": [{"Status": "No principals found with Owner or Org Admin roles."}], "Status": "Compliant"}
        sink.write_finding(job_id, CHECK_NAME_CRITICAL.replace(" ", "_"), result_crit)

        # --- Check 2: Public Org-Level Access ---
        public_access_findings = [{"Role": b.get('role'), "Principal": m} 
                                  for b in policy.get('bindings', []) 
                                  for m in b.get('members', []) 
                                  if m in public_principals]
        
        if public_access_findings:
            result_public = {"Check": CHECK_NAME_PUBLIC, "Finding": public_access_findings, "Status": "Action Required"}
        else:
            result_public = {"Check": CHECK_NAME_PUBLIC, "Finding": [{"Status": "No public access found at the organization level."}], "Status": "Compliant"}
        sink.write_finding(job_id, CHECK_NAME_PUBLIC.replace(" ", "_"), result_public)

    except Exception as e:
        # If the entire check fails, write a single error file.
        error_result = {"Check": "Organization IAM Policy Check", "Finding": [{"Error": str(e)}], "Status": "Error"}
        sink.write_finding(job_id, "Organization_IAM_Policy_Check_Error", error_result)


def check_scc_status(org_id, job_id, *, sink):
    """
    Checks the status and tier of Security Command Center (SCC) for the organization.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries. Recommends 'PREMIUM' tier.
    """
    CHECK_NAME = "Security Command Center Status"
    print(f"🛡️  [{job_id}] Checking {CHECK_NAME}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('securitycenter', 'v1', credentials=credentials)
        settings = service.organizations().getOrganizationSettings(name=f"organizations/{org_id}/organizationSettings").execute()
        tier = settings.get('tier', 'STANDARD')
        status = "Compliant" if tier == "PREMIUM" else "Action Required"
        finding = {"Tier": tier, "Recommendation": "Premium tier provides advanced threat detection." if status == "Action Required" else "N/A"}
        result = {"Check": CHECK_NAME, "Finding": [finding], "Status": status}
    except HttpError as e:
        if "API has not been used" in str(e) or e.resp.status == 404:
            result = {"Check": CHECK_NAME, "Finding": [{"Issue": "Security Command Center is not enabled for this organization."}], "Status": "Action Required"}
        else:
            result = {"Check": CHECK_NAME, "Finding": [{"Error": str(e)}], "Status": "Error"}
    except Exception as e:
        result = {"Check": CHECK_NAME, "Finding": [{"Error": str(e)}], "Status": "Error"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_project_iam_policy(scope_id, projects, job_id, *, sink):
    """
    Scans all projects in parallel for the use of primitive roles (Owner/Editor).

    Args:
        org_id (str): The organization ID.
        projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries detailing primitive role usage.
    """
    CHECK_NAME = "Primitive Roles (Owner or Editor)"
    print(f"🕵️  [{job_id}] Checking for {CHECK_NAME} in parallel...")
    if not projects: 
        result = {"Check": "Project IAM Hygiene", "Finding": [{"Error": "Could not list projects."}], "Status": "Error"}
        sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)
        return
    
    def check_single_project(p):
        project_id, findings = p['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            service = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for b in policy.get('bindings', []):
                if b.get('role') in ['roles/owner', 'roles/editor']:
                    for member in b.get('members', []):
                        findings.append({'Project': project_id, 'Principal': member, 'Role': b.get('role')})
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return findings

    all_findings = []
    for project in projects:
        all_findings.extend(check_single_project(project))
    
    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No projects found with Owner or Editor roles."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_sa_key_rotation(scope_id, all_projects, job_id, *, sink):
    """
    Scans ALL projects and ALL service account keys for user-managed keys older than 90 days.
    This version corrects the pagination logic for listing keys.
    """
    CHECK_NAME = "Service Account Key Rotation"
    print(f"🔑 [{job_id}] Checking for {CHECK_NAME}...")

    all_findings = []

    for project in all_projects:
        project_id = project['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            iam_service = gcp.api_build('iam', 'v1', credentials=credentials)

            # This pagination loop for service accounts is correct and remains unchanged.
            s_accounts = []
            request = iam_service.projects().serviceAccounts().list(name=f'projects/{project_id}')
            while request:
                response = request.execute()
                s_accounts.extend(response.get('accounts', []))
                request = iam_service.projects().serviceAccounts().list_next(previous_request=request, previous_response=response)

            for sa in s_accounts:
                keys = []
                # --- CORRECTED: Start of manual pagination for keys ---
                # Make the initial request to list keys
                key_request = iam_service.projects().serviceAccounts().keys().list(name=sa['name'], keyTypes=['USER_MANAGED'])

                # Loop until there are no more pages
                while True:
                    key_response = key_request.execute()
                    keys.extend(key_response.get('keys', []))
                    
                    next_page_token = key_response.get('nextPageToken')
                    if next_page_token:
                        # If a next page token exists, prepare the next request
                        key_request = iam_service.projects().serviceAccounts().keys().list(
                            name=sa['name'],
                            keyTypes=['USER_MANAGED'],
                            pageToken=next_page_token
                        )
                    else:
                        # If there's no token, we've retrieved all keys, so break the loop
                        break
                # --- END of corrected manual pagination ---

                for key in keys:
                    created_time = datetime.fromisoformat(key['validAfterTime'].replace('Z', '+00:00'))
                    if (datetime.now(timezone.utc) - created_time).days > 90:
                        all_findings.append({
                            "Project": project_id,
                            "Service Account": sa['email'],
                            "Issue": f"Key is older than 90 days (created {created_time.strftime('%Y-%m-%d')})."
                        })

        except Exception as e:
            logging.error(f"Failed SA key check for project {project_id}: {e}")
            all_findings.append({
                "Project": project_id,
                "Service Account": "N/A",
                "Issue": f"Error scanning project for SA keys: {e}"
            })

    # Final reporting logic remains the same.
    if all_findings:
        result = {
            "Check": CHECK_NAME,
            "Finding": all_findings,
            "Status": "Action Required"
        }
    else:
        result = {
            "Check": CHECK_NAME,
            "Finding": [{"Status": "No user-managed service account keys older than 90 days were found."}],
            "Status": "Compliant"
        }

    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_public_buckets(scope_id, all_projects, job_id, *, sink):
    """Scans for public GCS buckets and writes findings to a temp file."""
    """
     Scans all projects for Cloud Storage buckets that are publicly accessible.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for any public buckets found.
    """
    CHECK_NAME = "Public GCS Buckets"
    print(f"🪣 [{job_id}] Checking for {CHECK_NAME}...")
    
    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            # Using a project-specific client can be more reliable at scale
            storage_client_local = storage.Client(project=project_id)
            for bucket in storage_client_local.list_buckets():
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                        findings.append({"Project": project_id, "Bucket": bucket.name, "Issue": f"Publicly accessible via role {binding['role']}."})
                        break # No need to check other bindings for this bucket
        except Exception:
            pass # Silently fail for projects where API is disabled or permissions lack
        return findings

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No publicly accessible buckets found."}], "Status": "Compliant"}
    
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_organization_policies(scope, scope_id, job_id, *, sink):
    """Fetches Org Policies and writes the raw data to temp files."""
    CHECK_NAME = "Organization_Policies_Data"
    print(f"📜 [{job_id}] Checking for {CHECK_NAME}...")
    best_practices = fetch_best_practices()
    
   
    # Call the function that manually traverses the hierarchy
    current_policies = get_effective_org_policies(scope, scope_id)
    
    
    if isinstance(best_practices, dict) and isinstance(current_policies, dict):
        sink.write_org_policies(job_id, best_practices, current_policies)
    else:
        err_msg = f"Best practices error: {best_practices}" if not isinstance(best_practices, dict) else f"Policies error: {current_policies}"
        result = {"Check": "Organization Policies", "Finding": [{"Error": f"Could not fetch policy data for {scope} '{scope_id}'. Details: {err_msg}"}], "Status": "Error"}
        sink.write_finding(job_id, "Organization_Policies_Check", result)


def check_open_firewall_rules(scope_id, all_projects, job_id, *, sink):
    """
    Scans all projects for VPC firewall rules open to the internet (0.0.0.0/0).

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for open firewall rules.
    """
    CHECK_NAME = "Open Firewall Rules"
    print(f"🔥 [{job_id}] Checking for Open Firewall Rules in parallel...")
    
    def check_project(p):
        project_id, open_rules = p['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            for rule in compute.firewalls().list(project=project_id).execute().get('items', []):
                if not rule.get('disabled', False) and '0.0.0.0/0' in rule.get('sourceRanges', []):
                    open_rules.append({"Project": project_id, "Rule Name": rule['name'], "VPC": rule['network'].split('/')[-1]})
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return open_rules

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No firewall rules found open to 0.0.0.0/0."}], "Status": "Compliant"}
    sink.write_finding(job_id, "Open_Firewall_Rules", result) # Using a simplified filename


# --- Checks added in upstream beta v1 ---
# Ported from the upstream beta branch (cloudgauge_beta_v1.py) with the same
# mechanical changes as the checks above.

def check_cloud_sql_security(scope_id, all_projects, job_id, *, sink):
    """
    Checks Cloud SQL instances for Public IPs and SSL enforcement.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
        job_id (str): The job ID.
    """
    CHECK_NAME = "Cloud SQL Security"
    print(f"🛡️  [{job_id}] Checking {CHECK_NAME}...")
    
    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            # Use Asset API for efficiency if possible, or SQL Admin API
            # Using SQL Admin API for direct configuration check
            service = gcp.api_build('sqladmin', 'v1beta4', credentials=credentials)
            instances = service.instances().list(project=project_id).execute().get('items', [])
            
            for instance in instances:
                name = instance.get('name')
                settings = instance.get('settings', {})
                ip_config = settings.get('ipConfiguration', {})
                
                # Check 1: Public IP
                if ip_config.get('ipv4Enabled', False):
                     findings.append({"Project": project_id, "Instance": name, "Issue": "Public IP enabled."})
                
                # Check 2: SSL Enforcement
                if not ip_config.get('requireSsl', False):
                    findings.append({"Project": project_id, "Instance": name, "Issue": "SSL not enforced."})

        except Exception as e:
            logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return findings

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All Cloud SQL instances have Public IP disabled and SSL enforced."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_vpc_configuration(scope_id, all_projects, job_id, *, sink):
    """
    Checks for 'default' VPC usage and subnets without Private Google Access.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
        job_id (str): The job ID.
    """
    CHECK_NAME = "VPC Configuration"
    print(f"🕸️  [{job_id}] Checking {CHECK_NAME}...")

    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            
            # Check 1: Default VPC
            networks = compute.networks().list(project=project_id).execute().get('items', [])
            for net in networks:
                if net.get('name') == 'default':
                    findings.append({"Project": project_id, "Network": "default", "Issue": "Default VPC network exists."})

            # Check 2: Private Google Access
            regions = compute.regions().list(project=project_id).execute().get('items', [])
            for region in regions:
                subnets = compute.subnetworks().list(project=project_id, region=region['name']).execute().get('items', [])
                for subnet in subnets:
                    if not subnet.get('privateIpGoogleAccess', False):
                        findings.append({"Project": project_id, "Subnet": subnet['name'], "Issue": "Private Google Access disabled."})

        except Exception as e:
            logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return findings

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No default VPCs found and all subnets have Private Google Access."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_storage_ubla(scope_id, all_projects, job_id, *, sink):
    """
    Checks if Uniform Bucket-Level Access (UBLA) is enabled on GCS buckets.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
        job_id (str): The job ID.
    """
    CHECK_NAME = "GCS Uniform Bucket-Level Access"
    print(f"🪣 [{job_id}] Checking {CHECK_NAME}...")

    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            storage_client_local = storage.Client(project=project_id)
            for bucket in storage_client_local.list_buckets():
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    findings.append({"Project": project_id, "Bucket": bucket.name, "Issue": "UBLA not enabled."})
        except Exception as e:
            logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return findings

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All buckets have Uniform Bucket-Level Access enabled."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_vm_external_ips(scope_id, all_projects, job_id, *, sink):
    """
    Checks for VM instances with external IP addresses.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
        job_id (str): The job ID.
    """
    CHECK_NAME = "VM External IPs"
    print(f"🖥️  [{job_id}] Checking {CHECK_NAME}...")

    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            
            req = compute.instances().aggregatedList(project=project_id)
            while req:
                resp = req.execute()
                for scope, result in resp.get('items', {}).items():
                    if 'instances' in result:
                        for instance in result['instances']:
                            for interface in instance.get('networkInterfaces', []):
                                if 'accessConfigs' in interface: # accessConfigs implies external IP
                                    findings.append({"Project": project_id, "VM": instance['name'], "Issue": "Has external IP address."})
                req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)

        except Exception as e:
            logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return findings

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No VMs with external IP addresses found."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)
