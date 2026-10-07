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

The organization-level "Personalized Service Health" probe that lived here
(an HTTP GET to see whether the Service Health API answered) is retired in
v14: ``app.checks.service_health`` reads the incidents of every project and
reports the projects in which the API is not enabled.
"""
from google.cloud import asset_v1
from googleapiclient.errors import HttpError

from app.config import SCOPES
from app.checks.not_checked import NotChecked
from app.services import gcp

# The Essential Contacts categories every organization should have someone subscribed to:
# security incidents, technical issues and outages, legal notices, and account suspension warnings.
REQUIRED_CONTACT_CATEGORIES = ("SECURITY", "TECHNICAL", "LEGAL", "SUSPENSION")


def missing_contact_categories(contacts):
    """The required categories no contact in ``contacts`` is subscribed to, in required order.

    Every subscription of every contact counts (a contact subscribed to several
    categories covers them all), and ``ALL`` covers every category.
    """
    found = set()
    for contact in contacts:
        found.update(contact.get('notificationCategorySubscriptions') or [])
    if "ALL" in found:
        return []
    return [category for category in REQUIRED_CONTACT_CATEGORIES if category not in found]


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
        missing = missing_contact_categories(contacts)

        if not missing:
            result = {"Check": CHECK_NAME, "Finding": [{"Status": f"A contact is subscribed to every key category ({', '.join(REQUIRED_CONTACT_CATEGORIES)})."}], "Status": "Compliant"}
        else:
            result = {"Check": CHECK_NAME, "Finding": [{
                "Missing Categories": ", ".join(missing),
                "Issue": "Nobody in the organization receives Google's notifications in these categories.",
                "Fix": (f"gcloud essential-contacts create --organization={org_id} --email=<address> "
                        f"--notification-categories={','.join(missing)}"),
            }], "Status": "Action Required"}
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


# Resilience of Critical Assets: the check names its three Asset Inventory listings write under, in report order.
# Each name is a key of CATEGORY_MAP and ends every scan with a verdict (or an Error row when its listing failed).
SQL_RESILIENCE_CHECKS = ("Cloud SQL High Availability", "Cloud SQL Automated Backups", "Cloud SQL Backup Retention", "Cloud SQL PITR")
MIG_RESILIENCE_CHECK = "MIG Resilience (Zonal)"
SNAPSHOT_RESILIENCE_CHECK = "Disk Snapshot Resilience"
RESILIENCE_CHECKS = SQL_RESILIENCE_CHECKS + (MIG_RESILIENCE_CHECK, SNAPSHOT_RESILIENCE_CHECK)
# Automated backups should keep at least this many: the "Backup Retention" rule.
MIN_RETAINED_BACKUPS = 30
# What a resilience check's Compliant row says when its listing answered and flagged nothing (v15.6),
# worded like the cost checks' all-clear rows (app.checks.cost.NOTHING_FOUND).
RESILIENCE_NOTHING_FOUND = {
    "Cloud SQL High Availability": "No zonal (non-HA) Cloud SQL instances found.",
    "Cloud SQL Automated Backups": "No Cloud SQL instances without automated backups found.",
    "Cloud SQL Backup Retention": f"No Cloud SQL instances retaining fewer than {MIN_RETAINED_BACKUPS} backups found.",
    "Cloud SQL PITR": "No Cloud SQL instances with backups but without point-in-time recovery found.",
    "MIG Resilience (Zonal)": "No zonal managed instance groups found.",
    "Disk Snapshot Resilience": "No single-region disk snapshots found.",
}
# The multi-region storage locations Compute Engine offers for snapshots. A snapshot has one storage location,
# a region ("asia-south1") or one of these; a multi-region is geo-redundant by construction (v16.1 — before, the
# rule counted the locations, and one location is all a snapshot ever has, so every snapshot was flagged).
MULTI_REGIONS = ("asia", "eu", "us")


def is_single_region(storage_locations):
    """Whether a snapshot's ``storageLocations`` keep it in a single region: none of them is a multi-region.

    An empty or missing list counts as single-region (the conservative reading; it should not occur).
    """
    return not any(str(location).lower() in MULTI_REGIONS for location in storage_locations or ())


def project_of_asset(asset_name):
    """The project ID in an asset name (``//compute.googleapis.com/projects/p1/zones/…``), or ``'unknown'``."""
    parts = asset_name.split('/')
    return parts[parts.index('projects') + 1] if 'projects' in parts else 'unknown'


def check_resilience_assets(scope, scope_id, job_id, *, sink):
    """
    Checks the Cloud SQL instances, managed instance groups and disk snapshots under the scanned
    scope for resilience best practices: Cloud SQL high availability, automated backups, backup
    retention and point-in-time recovery; zonal (single-zone) MIGs; snapshots kept in a single region
    (a multi-region storage location — ``MULTI_REGIONS`` — passes).

    The three Asset Inventory listings run under ``organizations/``, ``folders/`` or
    ``projects/<scope_id>`` (v15.6; before, under the organization only, so the check was
    organization-only). Each of the six check names (``RESILIENCE_CHECKS``) ends the scan with a
    verdict: Action Required with the rows that need work, or Compliant with one all-clear row
    (``RESILIENCE_NOTHING_FOUND``) so the Stability score counts it. A listing that fails writes an
    Error row under each check name it served (the Cloud SQL listing serves four), which the report
    counts as coverage ("could not be checked"), never as a verdict.

    Args:
        scope (str): ``'organization'``, ``'folder'`` or ``'project'``.
        scope_id (str): The organization ID, folder ID or project ID.
        job_id (str): The scan's job ID.
    """
    print(f"🏗️  Checking resilience assets (SQL, MIGs, Snapshots) under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"

    def write(check, rows):
        """Action Required with ``rows``, or the check's all-clear row when there are none."""
        if rows:
            result = {"Check": check, "Finding": rows, "Status": "Action Required"}
        else:
            result = {"Check": check, "Finding": [{"Status": RESILIENCE_NOTHING_FOUND[check]}], "Status": "Compliant"}
        sink.write_finding(job_id, check.replace(" ", "_"), result)

    def write_errors(checks, error):
        for check in checks:
            sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(error)}], "Status": "Error"})

    def list_assets(asset_client, asset_type):
        request = {"parent": parent, "asset_types": [asset_type], "content_type": asset_v1.ContentType.RESOURCE}
        return list(asset_client.list_assets(request=request))

    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
    except Exception as e:
        write_errors(RESILIENCE_CHECKS, e)
        return

    # Cloud SQL: one listing, four verdicts.
    try:
        non_ha, no_backup, bad_retention, no_pitr = [], [], [], []
        for asset in list_assets(asset_client, "sqladmin.googleapis.com/Instance"):
            s, name, proj = asset.resource.data.get("settings", {}), asset.resource.data.get('name'), project_of_asset(asset.name)
            if s.get("availabilityType") == "ZONAL":
                non_ha.append({"Project": proj, "Instance": name})
            backup_conf = s.get("backupConfiguration", {})
            if not backup_conf.get("enabled"):
                no_backup.append({"Project": proj, "Instance": name})
            elif not backup_conf.get("pointInTimeRecoveryEnabled"):
                no_pitr.append({"Project": proj, "Instance": name})
            if backup_conf.get("retainedBackupsCount", 0) < MIN_RETAINED_BACKUPS:
                bad_retention.append({"Project": proj, "Instance": name, "Retention": backup_conf.get("retainedBackupsCount", "N/A")})
    except Exception as e:
        write_errors(SQL_RESILIENCE_CHECKS, e)
    else:
        for check, rows in zip(SQL_RESILIENCE_CHECKS, (non_ha, no_backup, bad_retention, no_pitr)):
            write(check, rows)

    # Managed instance groups: a zonal MIG lives in one zone (GKE's node-pool MIGs are the cluster's concern).
    try:
        zonal_migs = [{"Project": project_of_asset(a.name), "MIG Name": a.resource.data.get('name')}
                      for a in list_assets(asset_client, "compute.googleapis.com/InstanceGroupManager")
                      if 'zone' in a.resource.data and not a.resource.data.get('name', '').startswith('gke-')]
    except Exception as e:
        write_errors((MIG_RESILIENCE_CHECK,), e)
    else:
        write(MIG_RESILIENCE_CHECK, zonal_migs)

    # Disk snapshots: one row per snapshot kept in a single region (v15.6: one row per snapshot, a count row before;
    # v16.1: a multi-region location passes — the rule read the number of locations until then).
    try:
        single_region = [{"Project": project_of_asset(a.name), "Snapshot": a.resource.data.get('name'),
                          "Location": ", ".join(a.resource.data.get("storageLocations", [])) or "unknown"}
                         for a in list_assets(asset_client, "compute.googleapis.com/Snapshot")
                         if is_single_region(a.resource.data.get("storageLocations"))]
    except Exception as e:
        write_errors((SNAPSHOT_RESILIENCE_CHECK,), e)
    else:
        write(SNAPSHOT_RESILIENCE_CHECK, single_region)
