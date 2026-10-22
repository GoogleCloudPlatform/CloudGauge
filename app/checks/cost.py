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
"""Cost Optimization checks (Recommender API, and since v17 the FinOps checks).

Moved from ``cloudgauge.py`` (Phase 2) with mechanical changes only: each
check takes a keyword-only ``sink`` (a ``GcsResultsStore``) and writes
through ``sink.write_finding(...)``, and GCP auth and discovery calls go
through ``app.services.gcp``.

The recommendation parser that was nested in ``run_cost_recommendations``
is now the module-level ``parse_recommendation`` (unchanged).

v17 (FinOps) adds six recommenders to ``COST_RECOMMENDERS`` (resource-based
commitments, overprovisioned Cloud SQL, Cloud Run cost, BigQuery slot
commitments, idle images, Cloud Storage soft delete), the cost-allocation
labels every project must carry (``check_cost_allocation_labels``), buckets
that never tier or expire
their objects (``check_storage_lifecycle``) and snapshot sprawl
(``check_snapshot_sprawl``). Every one of them reaches a verdict or writes an
all-clear row; the label check is *Informational* until ``COST_ALLOCATION_LABELS``
names the keys, so an unconfigured check never moves the Efficiency score.
"""
import logging

from google.api_core import exceptions as core_exceptions
from google.api_core.exceptions import PermissionDenied
from google.cloud import asset_v1

from app.checks.not_checked import (LOCATION_DISCOVERY_APIS, NotChecked, describe_parts, failures_by_reason, is_request_error,
                                    location_detail)
from app.config import SCOPES, get_settings
from app.services import gcp
from app.utils import call_api_with_backoff, days_between, parse_timestamp, utcnow


# --- Cost Optimization Checks ---

# Report name -> (Recommender ID, location type). The names are the "Check" values
# the findings are written under; each must be a key of CATEGORY_MAP. The location
# type says where a recommender is asked: at every active zone or region of the
# scanned projects, at ``global`` (v17: images, soft delete), or at the BigQuery
# multi-regions plus the active regions (v17: slot commitments).
GLOBAL, BIGQUERY = "global", "bigquery"
BIGQUERY_MULTI_REGIONS = ("US", "EU")
COST_RECOMMENDERS = {
    "Idle Cloud SQL Instances": ("google.cloudsql.instance.IdleRecommender", "region"),
    "Low Utilization VMs": ("google.compute.instance.IdleResourceRecommender", "zone"),
    "VM Rightsizing": ("google.compute.instance.MachineTypeRecommender", "zone"),
    "Unassociated IPs": ("google.compute.address.IdleResourceRecommender", "region"),
    "Idle Load Balancers": ("google.compute.loadBalancer.IdleResourceRecommender", "region"),
    "Idle Persistent Disks": ("google.compute.disk.IdleResourceRecommender", "zone"),
    "Underutilized Reservations": ("google.compute.RightSizeResourceRecommender", "zone"),
    "Idle Reservations": ("google.compute.IdleResourceRecommender", "zone"),
    # v17 (FinOps)
    "Resource-Based Commitment Recommendations": ("google.compute.commitment.UsageCommitmentRecommender", "region"),
    "Overprovisioned Cloud SQL Instances": ("google.cloudsql.instance.OverprovisionedRecommender", "region"),
    "Cloud Run Cost": ("google.run.service.CostRecommender", "region"),
    "BigQuery Slot Commitments": ("google.bigquery.capacityCommitments.Recommender", BIGQUERY),
    "Idle Images": ("google.compute.image.IdleResourceRecommender", GLOBAL),
    "Cloud Storage Soft Delete": ("google.storage.bucket.SoftDeleteRecommender", GLOBAL),
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
    "Resource-Based Commitment Recommendations": "No resource-based commitment recommendations found.",
    "Overprovisioned Cloud SQL Instances": "No overprovisioned Cloud SQL instances found.",
    "Cloud Run Cost": "No Cloud Run cost recommendations found.",
    "BigQuery Slot Commitments": "No BigQuery slot commitment recommendations found.",
    "Idle Images": "No idle images found.",
    "Cloud Storage Soft Delete": "No Cloud Storage soft-delete recommendations found.",
}

# v17: the checks of this module that are not recommenders (their names are keys of CATEGORY_MAP too).
LABELS_CHECK = "Cost Allocation Labels"
LIFECYCLE_CHECK = "Cloud Storage Lifecycle"
SNAPSHOT_SPRAWL_CHECK = "Snapshot Sprawl"
FINOPS_CHECKS = (LABELS_CHECK, LIFECYCLE_CHECK, SNAPSHOT_SPRAWL_CHECK)
# The cost rows' saving column, as parse_recommendation writes it ("1,234.56 USD"); the Scorecard sums it.
SAVING_COLUMN = "Est. Monthly Saving"


def recommender_locations(loc_type, active_zones, active_regions):
    """Where a recommender of ``loc_type`` is asked (``COST_RECOMMENDERS``), from the scan's active locations.

    ``global`` never counts as a zone or a region; a global recommender is asked at ``global`` alone.
    """
    regions = [region for region in active_regions if region != GLOBAL]
    if loc_type == "zone":
        return [zone for zone in active_zones if zone != GLOBAL]
    if loc_type == "region":
        return regions
    if loc_type == BIGQUERY:
        return list(BIGQUERY_MULTI_REGIONS) + regions
    return [GLOBAL]


def location_bound_recommenders(recommenders=None):
    """The recommenders that are asked at discovered zones or regions only (not at ``global`` or a BigQuery multi-region)."""
    return [name for name, (_, loc_type) in (recommenders or COST_RECOMMENDERS).items() if loc_type in ("zone", "region")]


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
        queried = False  # whether any recommender was queried at a discovered zone or region of the project

        def note_failure(check, error):
            # An invalid argument or not-found means the recommender is not offered in
            # that location (asia-south1 answers 400 for Idle Load Balancers), not that
            # the project could not be checked.
            if not is_request_error(error):
                failed.setdefault(check, error)

        try:
            client = gcp.recommender_client()
            for check, (rec_id, loc_type) in recommender_map.items():
                for loc in recommender_locations(loc_type, active_zones, active_regions):
                    if loc_type in ('region', 'zone'):
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
        # failed for it anyway (the rows above already say it was not checked). The
        # global and BigQuery recommenders were asked regardless (v17), so the row
        # names the ones that depend on discovered zones and regions.
        if project_id in location_errors and len(failed) < len(recommender_map):
            if queried:
                detail = location_detail(True, len(recommender_map), "recommender")
            else:
                detail = (f"{describe_parts(location_bound_recommenders(recommender_map), len(recommender_map), 'recommender')}: "
                          f"no zones or regions were discovered to query")
            skipped.add(project_id, location_errors[project_id], resource_apis=LOCATION_DISCOVERY_APIS, detail=detail)
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


# --- v17: FinOps -----------------------------------------------------------------------------------------------

def _write(sink, job_id, check, rows, status, all_clear):
    """One record: ``status`` with ``rows``, or Compliant with the check's all-clear row when there are none."""
    if rows:
        result = {"Check": check, "Finding": rows, "Status": status}
    else:
        result = {"Check": check, "Finding": [{"Status": all_clear}], "Status": "Compliant"}
    sink.write_finding(job_id, check.replace(" ", "_"), result)


def _write_error(sink, job_id, check, error):
    sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(error)}], "Status": "Error"})


def missing_labels(labels, keys):
    """The cost-allocation ``keys`` that ``labels`` (a project's labels) lacks or leaves empty, in configured order."""
    labels = labels or {}
    return [key for key in keys if not str(labels.get(key, "") or "").strip()]


def label_fix(project_id, keys):
    """The ``gcloud`` command that adds the missing label keys to a project (the values are the owner's to fill in)."""
    return f"gcloud projects update {project_id} --update-labels={','.join(f'{key}=<value>' for key in keys)}"


def check_cost_allocation_labels(scope_id, all_projects, job_id, *, sink):
    """Projects missing one of the cost-allocation labels (v17).

    ``COST_ALLOCATION_LABELS`` names the keys every project must carry so that billing
    exports can be sliced by them (``cost-center,environment,owner``). Unset, the check
    is *Informational* — it says how to configure it and stays out of the Efficiency
    score. Configured, it reads each project's labels (Resource Manager) and lists the
    projects that lack a key or leave it empty, with the ``gcloud projects update``
    line that adds them; Compliant with an all-clear row when every project carries them.
    """
    print(f"🏷️  [{job_id}] Checking {LABELS_CHECK}...")
    keys = get_settings().cost_allocation_labels
    if not keys:
        note = ("Not configured: set COST_ALLOCATION_LABELS to the label keys every project must carry "
                "(for example cost-center,environment,owner) and this check lists the projects missing any of them.")
        sink.write_finding(job_id, LABELS_CHECK.replace(" ", "_"), {"Check": LABELS_CHECK, "Finding": [{"Summary": note}], "Status": "Informational"})
        return
    skipped = NotChecked(LABELS_CHECK)
    rows = []
    for project in all_projects:
        project_id = project['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            service = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
            labels = service.projects().get(projectId=project_id).execute().get('labels') or {}
        except Exception as e:
            skipped.add(project_id, e)
            continue
        missing = missing_labels(labels, keys)
        if missing:
            rows.append({"Project": project_id, "Missing Labels": ", ".join(missing), "Fix": label_fix(project_id, missing)})
    _write(sink, job_id, LABELS_CHECK, rows, "Action Required",
           f"Every project carries the cost-allocation labels {', '.join(keys)}.")
    skipped.write(sink, job_id)


def bucket_tiers_or_expires(bucket):
    """Whether a bucket moves or expires its objects on its own: Autoclass on, or at least one lifecycle rule."""
    if getattr(bucket, "autoclass_enabled", False):
        return True
    try:
        return bool(list(getattr(bucket, "lifecycle_rules", None) or []))
    except Exception:
        return False


def check_storage_lifecycle(scope_id, all_projects, job_id, *, sink):
    """Buckets with neither lifecycle rules nor Autoclass (v17).

    Such a bucket keeps every object in its default class for ever: nothing is tiered to
    Nearline, Coldline or Archive and nothing expires, which is where storage bills grow
    unnoticed. One row per bucket with the ``gcloud storage buckets update --enable-autoclass``
    line (a lifecycle rule is the alternative when the access pattern is known).
    *Investigation Recommended*: a bucket may need to stay as it is.
    """
    print(f"🗄️  [{job_id}] Checking {LIFECYCLE_CHECK}...")
    skipped = NotChecked(LIFECYCLE_CHECK)
    rows = []
    for project in all_projects:
        project_id = project['projectId']
        try:
            for bucket in gcp.project_storage_client(project_id).list_buckets():
                if not bucket_tiers_or_expires(bucket):
                    rows.append({"Project": project_id, "Bucket": bucket.name, "Storage Class": getattr(bucket, "storage_class", "") or "",
                                 "Issue": "No lifecycle rules and Autoclass off: objects never move to a colder storage class or expire.",
                                 "Fix": f"gcloud storage buckets update gs://{bucket.name} --enable-autoclass"})
        except Exception as e:
            skipped.add(project_id, e)
    _write(sink, job_id, LIFECYCLE_CHECK, rows, "Investigation Recommended", "Every bucket has lifecycle rules or Autoclass.")
    skipped.write(sink, job_id)


def disk_path(url):
    """``projects/p/zones/z/disks/d`` of a disk URL or self link (``""`` for none), so snapshots and disks compare."""
    text = str(url or "")
    return text.split("/projects/", 1)[1].lstrip("/").removeprefix("projects/") if "/projects/" in text else text.removeprefix("projects/")


def snapshot_issues(snapshot, disks, now, max_age_days):
    """``(age in days, [issues])`` of a snapshot's Asset Inventory data against the set of existing disk paths.

    Issues: older than ``max_age_days``; a source disk that no longer exists (an empty
    ``sourceDisk`` counts: the snapshot has nothing to go back to). Age is ``None`` when the
    creation time does not parse.
    """
    created = parse_timestamp(snapshot.get("creationTimestamp"))
    age = days_between(created, now) if created else None
    issues = []
    if age is not None and age > max_age_days:
        issues.append(f"Older than {max_age_days} days.")
    source = disk_path(snapshot.get("sourceDisk"))
    if source not in disks:
        issues.append("Source disk no longer exists.")
    return age, issues


def check_snapshot_sprawl(scope, scope_id, job_id, *, sink):
    """Disk snapshots older than ``SNAPSHOT_MAX_AGE_DAYS`` or whose source disk is gone (v17).

    Two Asset Inventory listings under the scanned organization, folder or project (a
    scope-level check, like Resilience of Critical Assets): the snapshots, and the disks
    they could have come from. One row per snapshot that is old, orphaned or both, with its
    age and size and the ``gcloud compute snapshots delete`` line; *Investigation
    Recommended* — a snapshot may be a kept baseline. Compliant with an all-clear row when
    none is; an Error row when a listing fails.
    """
    print(f"📸 [{job_id}] Checking {SNAPSHOT_SPRAWL_CHECK} under {scope} {scope_id}...")
    max_age = get_settings().snapshot_max_age_days
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)

        def list_assets(asset_type):
            request = {"parent": parent, "asset_types": [asset_type], "content_type": asset_v1.ContentType.RESOURCE}
            return list(asset_client.list_assets(request=request))

        snapshots = list_assets("compute.googleapis.com/Snapshot")
        disks = {disk_path(asset.resource.data.get("selfLink") or asset.name.removeprefix("//compute.googleapis.com/"))
                 for asset in list_assets("compute.googleapis.com/Disk")}
    except Exception as e:
        _write_error(sink, job_id, SNAPSHOT_SPRAWL_CHECK, e)
        return
    now, rows = utcnow(), []
    for asset in snapshots:
        data = asset.resource.data
        project_id = asset.name.split("/projects/", 1)[-1].split("/", 1)[0] if "/projects/" in asset.name else "unknown"
        age, issues = snapshot_issues(data, disks, now, max_age)
        if issues:
            rows.append({"Project": project_id, "Snapshot": data.get("name"), "Age (days)": "" if age is None else age,
                         "Size (GB)": data.get("diskSizeGb", ""), "Issue": " ".join(issues),
                         "Fix": f"gcloud compute snapshots delete {data.get('name')} --project={project_id}"})
    rows.sort(key=lambda row: (-(row["Age (days)"] if isinstance(row["Age (days)"], int) else -1), row["Project"], str(row["Snapshot"])))
    _write(sink, job_id, SNAPSHOT_SPRAWL_CHECK, rows, "Investigation Recommended",
           f"No snapshots older than {max_age} days or without a source disk found.")
