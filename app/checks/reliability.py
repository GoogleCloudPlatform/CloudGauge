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
"""Reliability & Resilience checks.

Moved from ``cloudgauge.py`` (Phase 2) with mechanical changes only: each
check takes a keyword-only ``sink`` (a ``GcsResultsStore``) and writes
through ``sink.write_finding(...)``, and GCP auth and discovery calls go
through ``app.services.gcp``.
"""
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.cloud import asset_v1
from googleapiclient.errors import HttpError

from app.config import SCOPES
from app.checks.not_checked import NotChecked
from app.services import gcp


def check_service_health_status(org_id, job_id, *, sink):
    """
    Verifies if the Personalized Service Health API is enabled and accessible.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries indicating the status.
    """
    CHECK_NAME = "Personalized Service Health"
    print(f"❤️‍🩹 [{job_id}] Checking {CHECK_NAME}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        credentials.refresh(GoogleAuthRequest())
        headers = {"Authorization": f"Bearer {credentials.token}"}
        url = f"https://servicehealth.googleapis.com/v1beta/organizations/{org_id}/locations/global/organizationEvents?filter=state=ACTIVE%20category=INCIDENT"
        response = gcp.http_get(url, headers=headers)
        if response.status_code == 200:
            result = {"Check": CHECK_NAME, "Finding": [{"Status": "Enabled"}], "Status": "Compliant"}
        elif response.status_code == 403:
            error = response.json().get('error', {}).get('message', 'Permission denied.')
            result = {"Check": CHECK_NAME, "Finding": [{"Error": error}], "Status": "Error"}
        else:
            response.raise_for_status()
            result = {"Check": CHECK_NAME, "Finding": [{"Status": "Enabled"}], "Status": "Compliant"} # Should not be reached on error
    except Exception as e:
        result = {"Check": CHECK_NAME, "Finding": [{"Error": str(e)}], "Status": "Error"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_essential_contacts(org_id, job_id, *, sink):
    """
    Checks if Essential Contacts are configured for key notification categories.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries indicating missing contact categories.
    """
    CHECK_NAME = "Essential Contacts"
    print(f"📞 [{job_id}] Checking for {CHECK_NAME}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('essentialcontacts', 'v1', credentials=credentials)
        contacts = service.organizations().contacts().list(parent=f"organizations/{org_id}").execute().get('contacts', [])
        found = {c.get('notificationCategorySubscriptions', [])[0] for c in contacts if c.get('notificationCategorySubscriptions')}
        missing = sorted(list({"SECURITY", "TECHNICAL", "LEGAL"} - found))
        
        if not missing:
            result = {"Check": CHECK_NAME, "Finding": [{"Status": "All key contact categories are configured."}], "Status": "Compliant"}
        else:
            result = {"Check": CHECK_NAME, "Finding": [{"Missing Categories": ", ".join(missing)}], "Status": "Action Required"}
    except HttpError as e:
        if "API has not been used" in str(e) or "service is disabled" in str(e):
             result = {"Check": CHECK_NAME, "Finding": [{"Error": "The Essential Contacts API is not enabled. Please enable it to run this check."}], "Status": "Error"}
        else:
            result = {"Check": CHECK_NAME, "Finding": [{"Error": str(e)}], "Status": "Error"}
    except Exception as e:
        result = {"Check": CHECK_NAME, "Finding": [{"Error": str(e)}], "Status": "Error"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_storage_versioning(scope_id, all_projects, job_id, *, sink):
    """
    Checks if Object Versioning is enabled on all Cloud Storage buckets.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for buckets without versioning.
    """
    CHECK_NAME = "Cloud Storage Versioning"
    print(f"🔄 [{job_id}] Checking for {CHECK_NAME}...")
    skipped = NotChecked(CHECK_NAME)

    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            storage_client = gcp.project_storage_client(project_id)
            for bucket in storage_client.list_buckets():
                if not bucket.versioning_enabled:
                    findings.append({"Project": project_id, "Bucket": bucket.name, "Issue": "Object versioning is not enabled."})
        except Exception as e: skipped.add(project_id, e)
        return findings

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "Object versioning is enabled on all buckets."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)
    skipped.write(sink, job_id)


def check_gke_hygiene(scope_id, all_projects, job_id, *, sink):
    """
    Checks GKE clusters for best practices like using release channels and auto-upgrades.
    Also fetches active recommendations for the clusters.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for GKE hygiene issues.
    """
    CHECK_NAME = "GKE Hygiene"
    print(f"🚢 [{job_id}] Checking {CHECK_NAME} in parallel...")
    skipped = NotChecked(CHECK_NAME, resource_apis=("container.googleapis.com",))
    
    def check_project(p):
        project_id, issues = p['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            container = gcp.api_build('container', 'v1', credentials=credentials)
            recommender = gcp.api_build('recommender', 'v1', credentials=credentials)
            
            for cluster in container.projects().locations().clusters().list(parent=f"projects/{project_id}/locations/-").execute().get('clusters', []):
                name, location = cluster.get('name'), cluster.get('location')

                if not cluster.get('releaseChannel'):
                    issues.append({"Project": project_id, "Cluster": name, "Issue": "Not on a release channel."})
                
                for pool in cluster.get('nodePools', []):
                    if not pool.get('management', {}).get('autoUpgrade', False):
                        issues.append({"Project": project_id, "Cluster": name, "Node Pool": pool.get('name'), "Issue": "Auto-upgrades disabled."})

                
                reco_parent = f"projects/{project_id}/locations/{location}/recommenders/google.container.DiagnosisRecommender"
                reco_req = recommender.projects().locations().recommenders().recommendations().list(parent=reco_parent, filter='stateInfo.state="ACTIVE"')
                for reco in reco_req.execute().get('recommendations', []):
                    issues.append({"Project": project_id, "Cluster": name, "Recommendation": reco.get('description')})
        except Exception as e:
            skipped.add(project_id, e)
        return issues

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All checked GKE clusters seem to follow best practices."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)
    skipped.write(sink, job_id)


def check_resilience_assets(org_id, job_id, *, sink):
    """
    Checks organization-wide assets for resilience best practices, including
    Cloud SQL HA, backups, MIGs, and disk snapshot storage redundancy.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries for resilience issues.
    """
    print("🏗️  Checking resilience assets (SQL, MIGs, Snapshots)...")
    all_findings = []
    
    def get_project_from_asset_name(asset_name):
        parts = asset_name.split('/'); return parts[parts.index('projects') + 1] if 'projects' in parts else 'unknown'

    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        parent = f"organizations/{org_id}"

        # Cloud SQL Checks
        sql_req = {"parent": parent, "asset_types": ["sqladmin.googleapis.com/Instance"], "content_type": asset_v1.ContentType.RESOURCE}
        non_ha, no_backup, bad_retention, no_pitr = [], [], [], []
        for asset in asset_client.list_assets(request=sql_req):
            s, name, proj = asset.resource.data.get("settings", {}), asset.resource.data.get('name'), get_project_from_asset_name(asset.name)
            if s.get("availabilityType") == "ZONAL": non_ha.append({"Project": proj, "Instance": name})
            backup_conf = s.get("backupConfiguration", {})
            if not backup_conf.get("enabled"): no_backup.append({"Project": proj, "Instance": name})
            elif not backup_conf.get("pointInTimeRecoveryEnabled"): no_pitr.append({"Project": proj, "Instance": name})
            if backup_conf.get("retainedBackupsCount", 0) < 30 : bad_retention.append({"Project": proj, "Instance": name, "Retention": backup_conf.get("retainedBackupsCount", "N/A")})

        if non_ha:
            sink.write_finding(job_id, "Cloud_SQL_High_Availability", {"Check": "Cloud SQL High Availability", "Finding": non_ha, "Status": "Action Required"})
        if no_backup:
            sink.write_finding(job_id, "Cloud_SQL_Automated_Backups", {"Check": "Cloud SQL Automated Backups", "Finding": no_backup, "Status": "Action Required"})
        if bad_retention:
            sink.write_finding(job_id, "Cloud_SQL_Backup_Retention", {"Check": "Cloud SQL Backup Retention", "Finding": bad_retention, "Status": "Action Required"})
        if no_pitr:
            sink.write_finding(job_id, "Cloud_SQL_PITR", {"Check": "Cloud SQL PITR", "Finding": no_pitr, "Status": "Action Required"})

        # Zonal MIGs Check
        mig_req = {"parent": parent, "asset_types": ["compute.googleapis.com/InstanceGroupManager"], "content_type": asset_v1.ContentType.RESOURCE}
        zonal_migs = [{"Project": get_project_from_asset_name(a.name), "MIG Name": a.resource.data.get('name')} for a in asset_client.list_assets(request=mig_req) if 'zone' in a.resource.data and not a.resource.data.get('name', '').startswith('gke-')]
        if zonal_migs:
            sink.write_finding(job_id, "MIG_Resilience_(Zonal)", {"Check": "MIG Resilience (Zonal)", "Finding": zonal_migs, "Status": "Action Required"})
        
        # Disk Snapshots Check
        snap_req = {"parent": parent, "asset_types": ["compute.googleapis.com/Snapshot"], "content_type": asset_v1.ContentType.RESOURCE}
        single_region = len([a for a in asset_client.list_assets(request=snap_req) if len(a.resource.data.get("storageLocations", [])) <= 1])
        if single_region > 0:
            sink.write_finding(job_id, "Disk_Snapshot_Resilience", {"Check": "Disk Snapshot Resilience", "Finding": [{"Issue": f"Found {single_region} snapshots stored in only one region."}], "Status": "Action Required"})

    except Exception as e:
        error_result = {"Check": "Resilience Asset Checks", "Finding": [{"Error": str(e)}], "Status": "Error"}
        sink.write_finding(job_id, "Resilience_Asset_Checks_Error", error_result)
