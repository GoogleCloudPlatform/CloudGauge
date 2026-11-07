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
from app.utils import parse_timestamp, utcnow

# The Essential Contacts categories every organization should have someone subscribed to:
# security incidents, technical issues and outages, legal notices, and account suspension warnings.
REQUIRED_CONTACT_CATEGORIES = ("SECURITY", "TECHNICAL", "LEGAL", "SUSPENSION")


CONTACTS_CHECK = "Essential Contacts"


def valid_contacts(contacts):
    """The contacts Google can actually reach: a contact whose address bounced (``validationState: INVALID``) counts for nothing (v18.1)."""
    return [contact for contact in contacts if str(contact.get('validationState') or '').upper() != 'INVALID']


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


def contacts_by_category(contacts):
    """``"SECURITY: a@x, b@x · TECHNICAL: ops@x"`` — who receives each required category (``ALL`` subscribers count for every one)."""
    parts = []
    for category in REQUIRED_CONTACT_CATEGORIES:
        emails = sorted({c.get('email', '') for c in contacts if category in (c.get('notificationCategorySubscriptions') or []) or 'ALL' in (c.get('notificationCategorySubscriptions') or [])})
        parts.append(f"{category}: {', '.join(e for e in emails if e)}")
    return " · ".join(parts)


def check_essential_contacts(scope, scope_id, job_id, *, sink):
    """
    Checks if Essential Contacts are configured for key notification categories.

    v18.1: runs in every scope — an organization's own contacts, a folder's or a project's
    *effective* contacts (``contacts.compute``, inherited ones included); a contact whose
    address bounced (``INVALID``) does not count; the Compliant row names who receives what.

    Args:
        scope (str): ``organization``, ``folder`` or ``project``.
        scope_id (str): The scope ID.
    """
    print(f"📞 [{job_id}] Checking for {CONTACTS_CHECK}...")
    parent, flag = f"{scope}s/{scope_id}", {"organization": "--organization", "folder": "--folder", "project": "--project"}.get(scope, "--organization")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('essentialcontacts', 'v1', credentials=credentials)
        resource = getattr(service, {"organization": "organizations", "folder": "folders", "project": "projects"}.get(scope, "organizations"))()
        if scope == "organization":
            contacts = resource.contacts().list(parent=parent).execute().get('contacts', [])
        else:
            contacts = resource.contacts().compute(parent=parent, notificationCategories=list(REQUIRED_CONTACT_CATEGORIES)).execute().get('contacts', [])
        invalid = len(contacts) - len(valid_contacts(contacts))
        contacts = valid_contacts(contacts)
        missing = missing_contact_categories(contacts)

        if not missing:
            result = {"Check": CONTACTS_CHECK, "Finding": [{"Status": f"A valid contact is subscribed to every key category ({', '.join(REQUIRED_CONTACT_CATEGORIES)}).",
                                                          "Contacts": contacts_by_category(contacts)}], "Status": "Compliant"}
        else:
            issue = f"Nobody in the {scope} receives Google's notifications in these categories."
            if invalid:
                issue += f" ({invalid} contact{'s' if invalid != 1 else ''} with a bounced address not counted.)"
            result = {"Check": CONTACTS_CHECK, "Finding": [{
                "Missing Categories": ", ".join(missing),
                "Issue": issue,
                "Fix": (f"gcloud essential-contacts create {flag}={scope_id} --email=<address> "
                        f"--notification-categories={','.join(missing)}"),
            }], "Status": "Action Required"}
    except HttpError as e:
        if "API has not been used" in str(e) or "service is disabled" in str(e):
             result = {"Check": CONTACTS_CHECK, "Finding": [{"Error": "The Essential Contacts API is not enabled. Please enable it to run this check."}], "Status": "Error"}
        else:
            result = {"Check": CONTACTS_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"}
    except Exception as e:
        result = {"Check": CONTACTS_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"}
    sink.write_finding(job_id, CONTACTS_CHECK.replace(" ", "_"), result)


# Cloud Storage Versioning (v18.1): what protects a bucket's objects from an accidental delete or overwrite, and which
# buckets must have versioning itself — log-sink destinations (CIS 2.3, SHA OBJECT_VERSIONING_DISABLED). Soft delete (on by
# default since 2024, 7 days), a lifecycle rule or a retention policy covers the accidental-deletion case elsewhere; a
# retention policy and versioning are mutually exclusive, so a retention bucket is never asked for versioning.
VERSIONING_CHECK = "Cloud Storage Versioning"
LOG_SINK_ASSET = "logging.googleapis.com/LogSink"
SOFT_DELETE_MIN_SECONDS = 7 * 24 * 3600
VERSIONING_ALL_CLEAR = ("Every log-sink destination bucket has versioning, and every other bucket is protected by versioning, "
                        "soft delete, a lifecycle rule or a retention policy.")


def sink_destination_buckets(assets):
    """The bucket names that log sinks write to, from the ``LOG_SINK_ASSET`` assets of the scope (``storage.googleapis.com/<bucket>``)."""
    buckets = set()
    for asset in assets:
        data = getattr(getattr(asset, "resource", None), "data", None) or {}
        destination = str(data.get("destination", "") if hasattr(data, "get") else "")
        if destination.startswith("storage.googleapis.com/"):
            buckets.add(destination.split("/", 1)[1].split("/", 1)[0])
    return buckets


def bucket_protection(bucket):
    """``(versioning, soft delete seconds or None, lifecycle rules?, retention policy?)`` as the storage client reports them."""
    versioning = bool(getattr(bucket, "versioning_enabled", False))
    policy = getattr(bucket, "soft_delete_policy", None)
    soft_delete = getattr(policy, "retention_duration_seconds", None) if policy is not None else None
    try:
        lifecycle = bool(list(getattr(bucket, "lifecycle_rules", None) or []))
    except Exception:
        lifecycle = False
    retention = bool(getattr(bucket, "retention_period", None))
    return versioning, soft_delete, lifecycle, retention


def versioning_row(project_id, bucket, sink_buckets):
    """The row of a bucket without versioning, or ``None`` when it needs none.

    Action Required for a log-sink destination; Investigation Recommended when nothing at all protects the bucket
    (versioning off, soft delete off, no lifecycle rule, no retention policy); nothing otherwise.
    """
    versioning, soft_delete, lifecycle, retention = bucket_protection(bucket)
    if versioning:
        return None
    name = bucket.name
    if name in sink_buckets:
        return {"Project": project_id, "Bucket": name, "Protection": "versioning off on a log-sink destination bucket",
                "Fix": f"gcloud storage buckets update gs://{name} --versioning", "_status": "Action Required"}
    if (soft_delete or 0) >= SOFT_DELETE_MIN_SECONDS or lifecycle or retention:
        return None
    return {"Project": project_id, "Bucket": name, "Protection": "none: versioning off, soft delete off, no lifecycle rule, no retention policy",
            "Fix": f"gcloud storage buckets update gs://{name} --versioning --soft-delete-duration=7d", "_status": "Investigation Recommended"}


def check_storage_versioning(scope, scope_id, all_projects, job_id, *, sink):
    """
    Checks the buckets of every project for the protection object versioning gives (``versioning_row``).

    v18.1: the rule asks for versioning where CIS and Security Health Analytics ask for it — log-sink
    destinations (one Asset Inventory listing of the scope's sinks) — and otherwise only that *something*
    protects the bucket; before, every bucket without versioning was Action Required, soft delete notwithstanding.

    Args:
        scope (str): ``organization``, ``folder`` or ``project`` (the sinks are listed under it).
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
    """
    print(f"🗂️  [{job_id}] Checking {VERSIONING_CHECK}...")
    skipped = NotChecked(VERSIONING_CHECK)
    sink_buckets = set()
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        request = {"parent": f"{scope}s/{scope_id}", "asset_types": [LOG_SINK_ASSET], "content_type": asset_v1.ContentType.RESOURCE}
        sink_buckets = sink_destination_buckets(gcp.asset_client(credentials).list_assets(request=request))
    except Exception as e:
        skipped.add(f"{scope}s/{scope_id}", e, detail="log-sink destinations (the sink-bucket rule could not be applied)")

    all_findings = []
    for project in all_projects:
        project_id = project['projectId']
        try:
            storage_client_local = gcp.project_storage_client(project_id)
            for bucket in storage_client_local.list_buckets():
                row = versioning_row(project_id, bucket, sink_buckets)
                if row:
                    all_findings.append(row)
        except Exception as e:
            skipped.add(project_id, e)

    if all_findings:
        statuses = {row.pop("_status") for row in all_findings}
        result = {"Check": VERSIONING_CHECK, "Finding": all_findings, "Status": "Action Required" if "Action Required" in statuses else "Investigation Recommended"}
    else:
        result = {"Check": VERSIONING_CHECK, "Finding": [{"Status": VERSIONING_ALL_CLEAR}], "Status": "Compliant"}
    sink.write_finding(job_id, VERSIONING_CHECK.replace(" ", "_"), result)
    skipped.write(sink, job_id)


GKE_HYGIENE_CHECK = "GKE Hygiene"
GKE_DIAGNOSIS_RECOMMENDER = "google.container.DiagnosisRecommender"
GKE_ACTIVE_FILTER = 'stateInfo.state="ACTIVE"'  # the REST form the check has always sent
GKE_HYGIENE_ALL_CLEAR = "Every GKE cluster is on a release channel with auto-upgrade and auto-repair on, and Active Assist has no diagnosis for it."


def cluster_channel(cluster):
    """The cluster's release channel name, or ``""`` for a static-version cluster (``releaseChannel`` absent, empty or UNSPECIFIED)."""
    channel = str((cluster.get('releaseChannel') or {}).get('channel') or "")
    return "" if channel.upper() in ("", "UNSPECIFIED") else channel


def gke_hygiene_rows(project_id, cluster):
    """A cluster's own rows: no release channel, node pools without auto-upgrade — each with its fix and ``_status``."""
    name, location = cluster.get('name'), cluster.get('location')
    rows = []
    if not cluster_channel(cluster):
        rows.append({"Project": project_id, "Cluster": name, "Issue": "Not on a release channel.",
                     "Fix": f"gcloud container clusters update {name} --location={location} --project={project_id} --release-channel=regular", "_status": "Action Required"})
    for pool in cluster.get('nodePools', []):
        management = pool.get('management') or {}
        if not management.get('autoUpgrade', False):
            rows.append({"Project": project_id, "Cluster": name, "Node Pool": pool.get('name'), "Issue": "Auto-upgrades disabled.",
                         "Fix": f"gcloud container node-pools update {pool.get('name')} --cluster={name} --location={location} --project={project_id} --enable-autoupgrade",
                         "_status": "Action Required"})
        if not management.get('autoRepair', False):  # v18.1: SHA AUTO_REPAIR_DISABLED
            rows.append({"Project": project_id, "Cluster": name, "Node Pool": pool.get('name'), "Issue": "Auto-repair disabled.",
                         "Fix": f"gcloud container node-pools update {pool.get('name')} --cluster={name} --location={location} --project={project_id} --enable-autorepair",
                         "_status": "Action Required"})
    return rows


def recommendation_rows(project_id, location, clusters, recommendations):
    """The diagnosis recommendations of one location attributed to their clusters by ``targetResources`` (v18: before, every
    recommendation of the location was listed under every cluster of it); one not naming a cluster is ``(location-wide)``."""
    names = {c.get('name') for c in clusters}
    rows = []
    for reco in recommendations:
        targets = [str(t).rsplit('/', 1)[-1] for t in (reco.get('targetResources') or [])]
        matched = [t for t in targets if t in names] or ["(location-wide)"]
        for cluster in matched:
            rows.append({"Project": project_id, "Cluster": cluster, "Recommendation": reco.get('description'), "_status": "Investigation Recommended"})
    return rows


def check_gke_hygiene(scope_id, all_projects, job_id, *, sink):
    """
    Checks GKE clusters for best practices like using release channels and auto-upgrades.
    Also fetches active recommendations for the clusters.

    v18: the Diagnosis recommender is asked once per location and its recommendations are
    attributed by ``targetResources`` (``recommendation_rows``); a Recommender failure costs the
    project its recommendation rows, not its cluster rows; recommendations are *Investigation
    Recommended*; the channel test treats ``UNSPECIFIED`` as no channel; the rows carry fixes.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
    """
    print(f"🚢 [{job_id}] Checking {GKE_HYGIENE_CHECK} in parallel...")
    skipped = NotChecked(GKE_HYGIENE_CHECK, resource_apis=("container.googleapis.com",))

    def check_project(p):
        project_id, rows = p['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            container = gcp.api_build('container', 'v1', credentials=credentials)
            clusters = container.projects().locations().clusters().list(parent=f"projects/{project_id}/locations/-").execute().get('clusters', [])
        except Exception as e:
            skipped.add(project_id, e)
            return []
        for cluster in clusters:
            rows.extend(gke_hygiene_rows(project_id, cluster))
        by_location = {}
        for cluster in clusters:
            by_location.setdefault(cluster.get('location'), []).append(cluster)
        try:
            recommender = gcp.api_build('recommender', 'v1', credentials=credentials)
            for location, located in by_location.items():
                reco_parent = f"projects/{project_id}/locations/{location}/recommenders/{GKE_DIAGNOSIS_RECOMMENDER}"
                recommendations, request = [], recommender.projects().locations().recommenders().recommendations().list(parent=reco_parent, filter=GKE_ACTIVE_FILTER)
                while request:
                    response = request.execute()
                    recommendations.extend(response.get('recommendations', []))
                    request = recommender.projects().locations().recommenders().recommendations().list_next(previous_request=request, previous_response=response)
                rows.extend(recommendation_rows(project_id, location, located, recommendations))
        except Exception as e:
            if clusters:
                skipped.add(project_id, e, detail="Active Assist recommendations", resource_apis=())
        return rows

    all_findings = []
    for project in all_projects:
        all_findings.extend(check_project(project))

    if all_findings:
        statuses = {row.pop("_status") for row in all_findings}
        result = {"Check": GKE_HYGIENE_CHECK, "Finding": all_findings, "Status": "Action Required" if "Action Required" in statuses else "Investigation Recommended"}
    else:
        result = {"Check": GKE_HYGIENE_CHECK, "Finding": [{"Status": GKE_HYGIENE_ALL_CLEAR}], "Status": "Compliant"}
    sink.write_finding(job_id, GKE_HYGIENE_CHECK.replace(" ", "_"), result)
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


def zone_name(zone):
    """``https://www.googleapis.com/compute/v1/projects/p/zones/asia-south1-c`` or ``asia-south1-c`` -> ``asia-south1-c``."""
    return str(zone or "").rstrip("/").rsplit("/", 1)[-1]


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
                # The region (v17.3): what Incident Exposure meets a Cloud SQL incident's locations with.
                non_ha.append({"Project": proj, "Instance": name, "Region": asset.resource.data.get("region") or ""})
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
    # The zone (v17.3) is what Incident Exposure meets a Compute Engine incident's locations with.
    try:
        zonal_migs = [{"Project": project_of_asset(a.name), "MIG Name": a.resource.data.get('name'), "Zone": zone_name(a.resource.data.get('zone'))}
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


# --- Cloud SQL Extended Support (v17) ---------------------------------------------------------------------------
SQL_VERSIONS_CHECK = "Cloud SQL Extended Support"
# Major version -> (extended support from, end of extended support), per the Cloud SQL version policies published at
# release time; the API does not carry the dates, so the table is static and revised with each release. MySQL and
# PostgreSQL instances pay the extended-support fee from the first date and are deprecated on the second; SQL Server
# follows Microsoft's lifecycle (end of mainstream support -> end of extended support) without a Cloud SQL fee.
EXTENDED_SUPPORT = {
    "MYSQL_5_6": ("2025-02-01", "2028-02-01"),
    "MYSQL_5_7": ("2025-02-01", "2028-02-01"),
    "MYSQL_8_0": ("2027-01-01", "2029-07-01"),
    "POSTGRES_9_6": ("2025-02-01", "2028-02-01"),
    "POSTGRES_10": ("2025-02-01", "2028-02-01"),
    "POSTGRES_11": ("2025-02-01", "2028-02-01"),
    "POSTGRES_12": ("2025-02-01", "2028-02-01"),
    "POSTGRES_13": ("2026-02-01", "2029-02-01"),
    "POSTGRES_14": ("2027-02-01", "2030-02-01"),
    "POSTGRES_15": ("2028-02-01", "2031-02-01"),
    "SQLSERVER_2014": ("2019-07-09", "2024-07-09"),
    "SQLSERVER_2016": ("2021-07-13", "2026-07-14"),
    "SQLSERVER_2017": ("2022-10-11", "2027-10-12"),
    "SQLSERVER_2019": ("2025-02-28", "2030-01-08"),
    "SQLSERVER_2022": ("2028-01-11", "2033-01-11"),
}
# Where an upgrade should go, per engine: the newest major Cloud SQL offers (SQL Server keeps its edition).
UPGRADE_TARGET = {"MYSQL": "MYSQL_8_4", "POSTGRES": "POSTGRES_17", "SQLSERVER": "SQLSERVER_2022"}
# A version that enters extended support within this many days is Investigation Recommended.
EXTENDED_SUPPORT_WARNING_DAYS = 180


def major_version(database_version):
    """``"MYSQL_8_0"`` of ``"MYSQL_8_0_31"``, ``"POSTGRES_15"`` of ``"POSTGRES_15"`` (``"POSTGRES_9_6"`` keeps its minor: the last 9.x),
    ``"SQLSERVER_2019"`` of ``"SQLSERVER_2019_STANDARD"``."""
    parts = str(database_version or "").upper().split("_")
    if not parts or not parts[0]:
        return ""
    three_parts = parts[0] == "MYSQL" or (parts[0] == "POSTGRES" and len(parts) > 1 and parts[1] == "9")
    return "_".join(parts[:3] if three_parts else parts[:2])


def upgrade_target(database_version):
    """The database version an instance should move to, or ``""`` when the engine is unknown."""
    parts = str(database_version or "").upper().split("_")
    target = UPGRADE_TARGET.get(parts[0] if parts else "")
    if not target:
        return ""
    if parts[0] == "SQLSERVER" and len(parts) > 2:
        target += "_" + "_".join(parts[2:])  # the edition: STANDARD, ENTERPRISE, EXPRESS, WEB
    return target


def assess_sql_version(database_version, today):
    """``(status, issue, extended support from, until)`` for an instance on ``database_version`` on ``today`` (a date), or ``None`` when it is fine.

    *Action Required* once the version is in extended support (or past its end), *Investigation
    Recommended* within ``EXTENDED_SUPPORT_WARNING_DAYS`` of entering it; a version not in the table
    (a current major) is never flagged.
    """
    dates = EXTENDED_SUPPORT.get(major_version(database_version))
    if not dates:
        return None
    start, end = (parse_timestamp(d).date() for d in dates)
    if today >= end:
        return "Action Required", f"Past the end of extended support ({end.isoformat()}): no further fixes or security patches.", start.isoformat(), end.isoformat()
    if today >= start:
        fee = "" if major_version(database_version).startswith("SQLSERVER") else " and pays the extended-support fee"
        return "Action Required", f"In extended support since {start.isoformat()}{fee}; deprecated on {end.isoformat()}.", start.isoformat(), end.isoformat()
    days = (start - today).days
    if days <= EXTENDED_SUPPORT_WARNING_DAYS:
        return "Investigation Recommended", f"Enters extended support on {start.isoformat()}, in {days} days.", start.isoformat(), end.isoformat()
    return None


def check_cloud_sql_versions(scope, scope_id, job_id, *, sink):
    """Cloud SQL instances on a database version in, or about to enter, extended support (v17).

    One Asset Inventory listing of the Cloud SQL instances under the scanned organization,
    folder or project (a scope-level check, like Resilience of Critical Assets), judged
    against ``EXTENDED_SUPPORT``. One row per instance with the dates and the ``gcloud sql
    instances patch --database-version`` line (an in-place major version upgrade; take a
    backup first). Compliant with an all-clear row when no instance is close; an Error row
    when the listing fails.
    """
    print(f"🐘 [{job_id}] Checking {SQL_VERSIONS_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        request = {"parent": parent, "asset_types": ["sqladmin.googleapis.com/Instance"], "content_type": asset_v1.ContentType.RESOURCE}
        instances = list(asset_client.list_assets(request=request))
    except Exception as e:
        sink.write_finding(job_id, SQL_VERSIONS_CHECK.replace(" ", "_"), {"Check": SQL_VERSIONS_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    today, rows = utcnow().date(), []
    for asset in instances:
        data = asset.resource.data
        version = data.get("databaseVersion", "")
        verdict = assess_sql_version(version, today)
        if verdict is None:
            continue
        status, issue, start, end = verdict
        project_id, name = project_of_asset(asset.name), data.get("name")
        target = upgrade_target(version)
        rows.append({"Project": project_id, "Instance": name, "Version": version, "Extended Support From": start, "Until": end,
                     "Issue": issue, "Fix": f"gcloud sql instances patch {name} --project={project_id} --database-version={target}" if target else "",
                     "_status": status})
    statuses = {row.pop("_status") for row in rows}
    if "Action Required" in statuses:
        result = {"Check": SQL_VERSIONS_CHECK, "Finding": rows, "Status": "Action Required"}
    elif rows:
        result = {"Check": SQL_VERSIONS_CHECK, "Finding": rows, "Status": "Investigation Recommended"}
    else:
        result = {"Check": SQL_VERSIONS_CHECK, "Finding": [{"Status": f"No Cloud SQL instance runs a version in or within "
                                                                    f"{EXTENDED_SUPPORT_WARNING_DAYS} days of extended support."}], "Status": "Compliant"}
    sink.write_finding(job_id, SQL_VERSIONS_CHECK.replace(" ", "_"), result)
