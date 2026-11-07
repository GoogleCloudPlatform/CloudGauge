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

v18 revalidated the legacy checks of this module (see RELEASE_NOTES.md): the
rules are pure functions over the APIs' own JSON, errors reach *Projects not
checked* or an Error row instead of becoming findings, and a check that answered
and found nothing says so.
"""
import concurrent.futures
import re

from google.api_core import exceptions as core_exceptions

from app.config import SCOPES
from app.checks.not_checked import NotChecked, disabled_api, is_request_error
from app.services import gcp
from app.utils import call_api_with_backoff


ACTION_REQUIRED, INVESTIGATION, INFORMATIONAL, COMPLIANT = "Action Required", "Investigation Recommended", "Informational", "Compliant"
# Recommender listings ask for the recommendations still standing (v18): a dismissed or applied one is not a finding.
ACTIVE_RECOMMENDATIONS = "stateInfo.state = ACTIVE"


# --- Operational Excellence Checks ---

LOG_SINK_CHECK = "Organization Log Sink"
# Every organization has these two sinks (its own _Required and _Default log buckets); they are not the aggregated export
# CIS 2.2 asks for, so they are never the evidence (v18.1).
BUILTIN_SINKS = ("_Required", "_Default")
SINK_FIX = "gcloud logging sinks create <sink> <destination> --organization={org} --include-children --log-filter='logName:\"cloudaudit.googleapis.com\"'"


def sink_shortcomings(sink_entry):
    """What keeps a customer sink from being the organization's audit export: ``[]`` when nothing does."""
    lacks = []
    if sink_entry.get("disabled"):
        lacks.append("disabled")
    if not sink_entry.get("includeChildren"):
        lacks.append("covers the organization resource only (no --include-children)")
    log_filter = str(sink_entry.get("filter") or "").strip()
    if log_filter and ("cloudaudit.googleapis.com" not in log_filter or log_filter.upper().startswith("NOT ")):
        lacks.append("filter leaves the audit logs out")
    return lacks


def log_sink_rows(org_id, sinks):
    """One row per customer sink (the built-ins left out) with its assessment, and the record's status (v18.1).

    A qualifying sink → Compliant; customer sinks that all fall short → Investigation Recommended; none → Action Required.
    """
    rows = []
    for entry in sinks:
        if entry.get("name") in BUILTIN_SINKS:
            continue
        lacks = sink_shortcomings(entry)
        rows.append({"Sink Name": entry.get("name"), "Destination": entry.get("destination"), "Filter": str(entry.get("filter") or "")[:160] or "(all logs)",
                     "Children": "yes" if entry.get("includeChildren") else "no", "State": "disabled" if entry.get("disabled") else "enabled",
                     "Assessment": "qualifies as the organization's audit export" if not lacks else "; ".join(lacks)})
    if not rows:
        return [{"Issue": "No organization-level log sink besides the built-in _Required and _Default: audit logs are not exported anywhere.",
                 "Fix": SINK_FIX.format(org=org_id)}], ACTION_REQUIRED
    if any(row["Assessment"].startswith("qualifies") for row in rows):
        return rows, COMPLIANT
    for row in rows:
        row["Fix"] = SINK_FIX.format(org=org_id)
    return rows, INVESTIGATION


def check_audit_logging(org_id, job_id, *, sink):
    """
    Verifies that an organization-level log sink exports the audit logs of the whole organization.

    v18: a failure is an Error row under the check's own name (``Log Sink Check`` is retired).
    v18.1: the built-in ``_Required`` and ``_Default`` sinks no longer count (every organization has
    them, so the check could never fail); a sink qualifies when it is enabled, includes children and
    its filter admits the audit logs (``sink_shortcomings``).

    Args:
        org_id (str): The organization ID.
    """
    print(f"📜 [{job_id}] Checking for {LOG_SINK_CHECK}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('logging', 'v2', credentials=credentials)
        sinks, request = [], service.organizations().sinks().list(parent=f'organizations/{org_id}')
        while request:
            response = request.execute()
            sinks.extend(response.get('sinks', []))
            request = service.organizations().sinks().list_next(previous_request=request, previous_response=response)
        rows, status = log_sink_rows(org_id, sinks)
        result = {"Check": LOG_SINK_CHECK, "Finding": rows, "Status": status}
    except Exception as e:
        result = {"Check": LOG_SINK_CHECK, "Finding": [{"Error": f"Could not list the organization's log sinks: {e}"}], "Status": "Error"}
    sink.write_finding(job_id, LOG_SINK_CHECK.replace(" ", "_"), result)


# Data Access Audit Logs (v18.1): CIS 2.1 / SHA AUDIT_LOGGING_DISABLED — whether the IAM policies of the scanned resource and
# its ancestors turn on the three Data Access log types for every service, with nobody exempted.
DATA_ACCESS_CHECK = "Data Access Audit Logs"
AUDIT_LOG_TYPES = ("ADMIN_READ", "DATA_READ", "DATA_WRITE")
ALL_SERVICES = "allServices"
DATA_ACCESS_COST_NOTE = ("DATA_READ for every service can produce significant log volume and cost; CIS recommends it all the same — "
                         "exempt high-volume services deliberately rather than leave the logs off.")
DATA_ACCESS_FIX = ("Add to the IAM policy of {resource} (gcloud {kind} get-iam-policy {id} --format=yaml > policy.yaml; append; "
                   "gcloud {kind} set-iam-policy {id} policy.yaml): auditConfigs: [{{service: allServices, auditLogConfigs: "
                   "[{{logType: ADMIN_READ}}, {{logType: DATA_READ}}, {{logType: DATA_WRITE}}]}}]  # console: IAM & Admin → Audit Logs → Default audit config")
GCLOUD_KIND = {"organization": "organizations", "folder": "resource-manager folders", "project": "projects"}


def audit_config_assessment(configs_by_resource):
    """What the Data Access configuration of a resource amounts to, from its own and its ancestors' ``auditConfigs``.

    ``configs_by_resource`` is ``[(resource name, auditConfigs list)]``, the organization first. The effective configuration
    is the union: a log type is on for all services when any level turns it on for ``allServices``; an exemption anywhere
    leaves those members out. Returns a dict: ``types`` (on for all services), ``missing``, ``exemptions``
    (``{type: [members]}``), ``services`` (``{service: [types]}`` configured individually), ``configured_at`` (resources
    with any configuration), ``status``.
    """
    on, exemptions, services, configured_at = set(), {}, {}, []
    for resource, configs in configs_by_resource:
        if configs:
            configured_at.append(resource)
        for config in configs or []:
            service = config.get("service", "")
            for log_config in config.get("auditLogConfigs", []):
                log_type = str(log_config.get("logType", "")).upper()
                if service == ALL_SERVICES:
                    on.add(log_type)
                    for member in log_config.get("exemptedMembers", []) or []:
                        exemptions.setdefault(log_type, []).append(member)
                elif log_type:
                    services.setdefault(service, []).append(log_type)
    missing = [t for t in AUDIT_LOG_TYPES if t not in on]
    if not configured_at:
        status = ACTION_REQUIRED
    elif missing or exemptions:
        status = INVESTIGATION
    else:
        status = COMPLIANT
    return {"types": [t for t in AUDIT_LOG_TYPES if t in on], "missing": missing, "exemptions": exemptions, "services": services,
            "configured_at": configured_at, "status": status}


def data_access_row(scope, scope_id, assessment):
    """The check's one row: what is on, what is missing, who is exempted, where it is configured, and the fix."""
    kind = GCLOUD_KIND.get(scope, "organizations")
    resource = f"{scope}s/{scope_id}"
    row = {"Resource": resource,
           "Log types on for all services": ", ".join(assessment["types"]) or "none",
           "Missing": ", ".join(assessment["missing"]) or "none",
           "Exemptions": "; ".join(f"{t}: {len(m)} member{'s' if len(m) != 1 else ''}" for t, m in assessment["exemptions"].items()) or "none",
           "Configured at": ", ".join(assessment["configured_at"]) or "nowhere",
           "Services configured individually": ", ".join(f"{s} ({', '.join(sorted(set(t)))})" for s, t in sorted(assessment["services"].items())) or "none"}
    if assessment["status"] == ACTION_REQUIRED:
        row["Issue"] = f"No Data Access audit logs are configured on {resource} or above: reads and writes of data leave no audit trail. {DATA_ACCESS_COST_NOTE}"
    elif assessment["status"] == INVESTIGATION:
        row["Issue"] = f"Data Access audit logs are partly configured. {DATA_ACCESS_COST_NOTE}"
    if assessment["status"] != COMPLIANT:
        row["Fix"] = DATA_ACCESS_FIX.format(resource=resource, kind=kind, id=scope_id)
    return row


def check_data_access_audit_logs(scope, scope_id, job_id, *, sink):
    """
    Checks whether Data Access audit logs are on for every service of the scanned resource (v18.1).

    An organization scan reads the organization's IAM policy; a folder or project scan reads the
    scanned resource's and its ancestors' (the effective configuration is their union).

    Args:
        scope (str): ``organization``, ``folder`` or ``project``.
        scope_id (str): The scope ID.
    """
    print(f"📜 [{job_id}] Checking {DATA_ACCESS_CHECK} for {scope} {scope_id}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        crm_v1 = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
        crm_v3 = gcp.api_build('cloudresourcemanager', 'v3', credentials=credentials)
        lineage = []  # resource names, the organization first
        if scope == "organization":
            lineage = [f"organizations/{scope_id}"]
        elif scope == "project":
            ancestry = crm_v1.projects().getAncestry(projectId=scope_id, body={}).execute()
            lineage = [f"{a['resourceId']['type']}s/{a['resourceId']['id']}" for a in reversed(ancestry.get("ancestor", []))]
            if f"projects/{scope_id}" not in lineage:
                lineage.append(f"projects/{scope_id}")
        else:
            current, chain = f"folders/{scope_id}", []
            while current and current.startswith("folders/"):
                chain.append(current)
                current = crm_v3.folders().get(name=current).execute().get("parent")
            if current:
                chain.append(current)
            lineage = list(reversed(chain))
        configs_by_resource = []
        for resource in lineage:
            kind, identifier = resource.split("/", 1)
            if kind == "organizations":
                policy = crm_v1.organizations().getIamPolicy(resource=resource, body={}).execute()
            elif kind == "folders":
                policy = crm_v3.folders().getIamPolicy(resource=resource, body={}).execute()
            else:
                policy = crm_v1.projects().getIamPolicy(resource=identifier, body={}).execute()
            configs_by_resource.append((resource, policy.get("auditConfigs", [])))
        assessment = audit_config_assessment(configs_by_resource)
        result = {"Check": DATA_ACCESS_CHECK, "Finding": [data_access_row(scope, scope_id, assessment)], "Status": assessment["status"]}
    except Exception as e:
        result = {"Check": DATA_ACCESS_CHECK, "Finding": [{"Error": f"Could not read the IAM policies that carry the audit configuration: {e}"}], "Status": "Error"}
    sink.write_finding(job_id, DATA_ACCESS_CHECK.replace(" ", "_"), result)


# OS Config Agent Coverage (v18): the running VMs without an OS inventory, from one inventory listing per zone.
OS_CONFIG_CHECK = "OS Config Agent Coverage"
# Fleets that never run VM Manager by design: GKE and Autopilot nodes, Dataproc, Dataflow and Batch workers.
MANAGED_FLEET_PREFIXES = ("gke-", "gk3-")
MANAGED_FLEET_LABELS = ("goog-dataproc-cluster-name", "dataflow_job_id", "goog-dataflow-job-id", "batch-job-id", "goog-batch-job-id")
OS_CONFIG_ALL_CLEAR = "Every running VM outside the managed fleets (GKE, Dataproc, Dataflow, Batch) reports an OS inventory."
OS_INVENTORY_DISABLED = ("OS inventory management is disabled in this project: no VM reports to VM Manager "
                         "(patching, inventory and vulnerability reports are off).")


def is_managed_fleet_vm(instance):
    """Whether a VM belongs to a fleet that does not run the OS Config agent by design (``MANAGED_FLEET_*``)."""
    name, labels = str(instance.get("name", "")), instance.get("labels") or {}
    metadata = {item.get("key") for item in (instance.get("metadata") or {}).get("items", [])}
    return (name.startswith(MANAGED_FLEET_PREFIXES) or any(label in labels for label in MANAGED_FLEET_LABELS)
            or "cluster-name" in metadata)


def inventory_instance_ids(inventories):
    """The instance IDs (and hostnames) an inventory listing covers: ``.../instances/<id>/inventory`` plus ``osInfo.hostname``."""
    covered = set()
    for inventory in inventories:
        name = str(getattr(inventory, "name", "") or (inventory.get("name", "") if isinstance(inventory, dict) else ""))
        if "/instances/" in name:
            covered.add(name.split("/instances/", 1)[1].split("/", 1)[0])
        os_info = getattr(inventory, "os_info", None) or (inventory.get("osInfo") if isinstance(inventory, dict) else None)
        hostname = getattr(os_info, "hostname", None) or (os_info.get("hostname") if isinstance(os_info, dict) else None)
        if hostname:
            covered.add(str(hostname))
    return covered


def os_config_fix(project_id, instance=None):
    """The metadata line that turns the OS Config agent on: for one VM, or project-wide when VM Manager is off."""
    if instance is None:
        return (f"gcloud services enable osconfig.googleapis.com --project={project_id} && "
                f"gcloud compute project-info add-metadata --project={project_id} --metadata=enable-osconfig=TRUE,enable-guest-attributes=TRUE")
    zone = str(instance.get("zone", "")).rsplit("/", 1)[-1]
    return f"gcloud compute instances add-metadata {instance.get('name')} --zone={zone} --project={project_id} --metadata=enable-osconfig=TRUE"


def os_config_rows(project_id, instances, covered):
    """One row per running VM outside the managed fleets whose ID or hostname is not in ``covered`` (the inventories' IDs)."""
    rows = []
    for instance in instances:
        if is_managed_fleet_vm(instance) or str(instance.get("status", "RUNNING")) != "RUNNING":
            continue
        if str(instance.get("id", "")) in covered or str(instance.get("name", "")) in covered:
            continue
        rows.append({"Project": project_id, "VM": instance.get("name"), "Zone": str(instance.get("zone", "")).rsplit("/", 1)[-1],
                     "Issue": "No OS inventory: the OS Config agent is not reporting.", "Fix": os_config_fix(project_id, instance)})
    return rows


def check_os_config_coverage(scope_id, all_projects, job_id, *, sink):
    """
    Checks VM instances across all projects to identify those not reporting to OS Config.
    This helps ensure patch management and inventory visibility. Excludes GKE and Dataproc VMs.

    v18: one ``list_inventories`` per zone with candidate VMs instead of one ``get_inventory`` per VM
    (``osconfig.inventories.list`` is what ``roles/iam.securityReviewer`` grants; ``.get`` is not), and
    the errors are routed: ``FailedPrecondition`` is the project's one *OS inventory management is
    disabled* row, a permission or API error puts the project under *Projects not checked* — before
    v18 both listed every VM as not reporting. Autopilot nodes (``gk3-``), Dataflow and Batch workers
    are excluded like GKE and Dataproc; the rows are one per VM, with the zone and the fix.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
    """
    print(f"🤖 [{job_id}] Checking for {OS_CONFIG_CHECK} in parallel...")
    if not all_projects: return []
    skipped = NotChecked(OS_CONFIG_CHECK, resource_apis=("compute.googleapis.com",))

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
            candidates = [vm for vm in vms if not is_managed_fleet_vm(vm)]
            if not candidates:
                return []
        except Exception as e:
            skipped.add(project_id, e)
            return []
        covered = set()
        for zone in sorted({str(vm.get("zone", "")).rsplit("/", 1)[-1] for vm in candidates}):
            try:
                # The inventories of every instance of the zone: the parent names the instance collection with the wildcard.
                inventories = osconfig.list_inventories(request={"parent": f"projects/{project_id}/locations/{zone}/instances/-", "view": "BASIC"})
                covered |= inventory_instance_ids(inventories)
            except core_exceptions.FailedPrecondition:
                return [{"Project": project_id, "Issue": OS_INVENTORY_DISABLED, "Fix": os_config_fix(project_id)}]
            except Exception as e:
                if disabled_api(e) in ("osconfig.googleapis.com", ""):  # the API itself is off: VM Manager cannot run
                    return [{"Project": project_id, "Issue": "The OS Config API is not enabled in this project: " + OS_INVENTORY_DISABLED,
                             "Fix": os_config_fix(project_id)}]
                skipped.add(project_id, e, resource_apis=())  # a 403, a 429: the project was not checked
                return []
        return os_config_rows(project_id, candidates, covered)

    results = []
    for project in all_projects:
        results.extend(check_single_project(project))

    if not results:
        result = {"Check": OS_CONFIG_CHECK, "Finding": [{"Status": OS_CONFIG_ALL_CLEAR}], "Status": "Compliant"}
    else:
        result = {"Check": OS_CONFIG_CHECK, "Finding": results, "Status": "Action Required"}
    sink.write_finding(job_id, OS_CONFIG_CHECK.replace(" ", "_"), result)
    skipped.write(sink, job_id)


# Monitoring Alert Coverage (v18): whether a project that runs Cloud SQL, GKE or load balancers has an enabled alert
# policy about them — matched on what Cloud Monitoring filters actually say, across every kind of condition.
MONITORING_CHECK = "Monitoring Alert Coverage"
MONITORED_ASSETS = {'sqladmin.googleapis.com/Instance': 'Cloud SQL', 'container.googleapis.com/Cluster': 'GKE Cluster',
                    'compute.googleapis.com/ForwardingRule': 'Load Balancer'}
ALERT_NEEDLES = {
    'Cloud SQL': ("cloudsql_database", "cloudsql.googleapis.com"),
    'GKE Cluster': ("k8s_", "kubernetes.io/", "gke_", "container.googleapis.com", "prometheus"),
    'Load Balancer': ("loadbalancing.googleapis.com", "_lb_rule"),
    'Quota': ("serviceruntime.googleapis.com/quota", "consumer_quota"),
}
ALERT_CONDITION_FIELDS = (("conditionThreshold", "filter"), ("conditionAbsent", "filter"), ("conditionMatchedLog", "filter"),
                          ("conditionMonitoringQueryLanguage", "query"), ("conditionPrometheusQueryLanguage", "query"), ("conditionSql", "query"))
MONITORING_ALL_CLEAR = "Every project running Cloud SQL, GKE or load balancers has an enabled alert policy about them, and one about quota."
ALERT_FIX = {
    'Cloud SQL': 'metric.type="cloudsql.googleapis.com/database/cpu/utilization" AND resource.type="cloudsql_database"',
    'GKE Cluster': 'metric.type="kubernetes.io/container/restart_count" AND resource.type="k8s_container"',
    'Load Balancer': 'metric.type="loadbalancing.googleapis.com/https/backend_request_count" AND resource.type="https_lb_rule" AND metric.labels.response_code_class="500"',
    'Quota': 'metric.type="serviceruntime.googleapis.com/quota/allocation/usage" AND resource.type="consumer_quota"',
}


def alert_policy_text(policies):
    """The condition filters and queries of the *enabled* policies, lower-cased and joined, plus a marker per PromQL condition."""
    parts = []
    for policy in policies:
        if policy.get("enabled") is False:
            continue
        for condition in policy.get("conditions", []):
            for kind, field in ALERT_CONDITION_FIELDS:
                text = (condition.get(kind) or {}).get(field)
                if text:
                    parts.append(str(text).lower())
            if condition.get("conditionPrometheusQueryLanguage"):
                parts.append("prometheus")  # Managed Prometheus alerting is GKE alerting
    return " ".join(parts)


def missing_alert_rows(project_id, present_assets, policy_text):
    """The rows of a project: one per asset family it runs without an alert policy about it, plus quota when it runs any.

    *Investigation Recommended*: alerting is operational readiness, not a posture fact.
    """
    rows = []
    families = [name for asset_type, name in MONITORED_ASSETS.items() if asset_type in present_assets]
    for name in families + (['Quota'] if families else []):
        if any(needle in policy_text for needle in ALERT_NEEDLES[name]):
            continue
        rows.append({"Project": project_id, "Issue": f"No enabled alert policy for {name.lower() if name == 'Quota' else name}.",
                     "Fix": f"gcloud alpha monitoring policies create --project={project_id} --policy-from-file=<policy.json>  "
                            f"# a condition on {ALERT_FIX[name]}"})
    return rows


def check_monitoring_coverage(scope_id, all_projects, job_id, *, sink):
    """
    Scans projects for alert policies about the critical resources they run (Cloud SQL, GKE, load balancers) and quota.

    v18: the match is on what Monitoring filters say (``ALERT_NEEDLES``: ``cloudsql_database``,
    ``k8s_``, ``_lb_rule`` …) across every kind of condition — threshold, absence, log match, MQL,
    PromQL, SQL — over the enabled policies, every page; the legacy needles (``cloud_sql``,
    ``gke_cluster``, ``load_balancer``) never occur in a real filter, so every project with those
    assets was flagged on every scan. The verdict is *Investigation Recommended*; the quota row
    only for projects running one of the three asset families. Alert policies kept in a metrics
    scoping project are not seen (the row says the project itself has none).

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
    """
    print(f"📊 [{job_id}] Checking {MONITORING_CHECK} in parallel...")
    if not all_projects: return []
    skipped = NotChecked(MONITORING_CHECK)

    def check_project(project):
        project_id = project['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            monitor = gcp.api_build('monitoring', 'v3', credentials=credentials)
            asset = gcp.asset_client(credentials)
            policies, request = [], monitor.projects().alertPolicies().list(name=f"projects/{project_id}")
            while request:
                response = request.execute()
                policies.extend(response.get('alertPolicies', []))
                request = monitor.projects().alertPolicies().list_next(previous_request=request, previous_response=response)
            present = {asset_type for asset_type in MONITORED_ASSETS
                       if list(asset.list_assets(request={"parent": f"projects/{project_id}", "asset_types": [asset_type]}))}
            return missing_alert_rows(project_id, present, alert_policy_text(policies))
        except Exception as e:
            skipped.add(project_id, e)
            return []

    results = []
    for project in all_projects:
        results.extend(check_project(project))

    if not results:
        result = {"Check": MONITORING_CHECK, "Finding": [{"Status": MONITORING_ALL_CLEAR}], "Status": "Compliant"}
    else:
        result = {"Check": MONITORING_CHECK, "Finding": results, "Status": INVESTIGATION}
    sink.write_finding(job_id, MONITORING_CHECK.replace(" ", "_"), result)
    skipped.write(sink, job_id)


STANDALONE_VMS_CHECK = "Standalone VMs (Not in MIGs)"


def check_standalone_vms(scope_id, all_projects, job_id, *, sink):
    """
    Identifies standalone VMs that are not managed by a Managed Instance Group (MIG).
    Excludes GKE and Dataproc VMs.

    v18: *Informational* — a standalone VM is a design choice (a bastion, a licence-bound
    database, a workstation), so the list is an inventory for review, outside the score.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
    """
    print(f"🖥️  [{job_id}] Checking for {STANDALONE_VMS_CHECK}...")
    skipped = NotChecked(STANDALONE_VMS_CHECK, resource_apis=("compute.googleapis.com",))

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

            standalone = [
                vm['name'] for vm in vms
                if not any(item.get('key') == 'created-by' for item in vm.get('metadata', {}).get('items', []))
                and not vm['name'].startswith(MANAGED_FLEET_PREFIXES)
                and 'goog-dataproc-cluster-name' not in vm.get('labels', {})
            ]
            
            if standalone:
                return {"Project": project_id, "Standalone VMs": ", ".join(sorted(standalone))}
        except Exception as e: skipped.add(project_id, e)
        return None

    all_findings = []
    for project in all_projects:
        finding = check_project(project)
        if finding:
            all_findings.append(finding)

    if all_findings:
        result = {"Check": STANDALONE_VMS_CHECK, "Finding": all_findings, "Status": INFORMATIONAL}
    else:
        result = {"Check": STANDALONE_VMS_CHECK, "Finding": [{"Status": "No running standalone, unmanaged VMs found."}], "Status": "Compliant"}
    sink.write_finding(job_id, STANDALONE_VMS_CHECK.replace(" ", "_"), result)
    skipped.write(sink, job_id)


# Miscellaneous (v18): the names it writes, each with a verdict or a note; errors as Error rows or Projects not checked.
# v18.1: *VPC Firewall Complexity (>150 Rules)* retired — the FIREWALLS project quota in Quota Utilization measures the same
# thing against the project's actual limit.
RECENT_CHANGES_CHECK = "Recent Changes (Org & Project)"
UNATTENDED_CHECK = "Unattended Projects"
RECENT_CHANGE_INSIGHT = "google.cloud.RecentChangeInsight"
UNATTENDED_RECOMMENDER = "google.resourcemanager.projectUtilization.Recommender"
NO_RECENT_CHANGES = "No recent-change insights (IAM policy, firewall or organization changes Active Assist flags) in the scanned scope."


def active_recommendations(recommendations):
    """The recommendations (or insights) still ACTIVE: the server filter asks for them, this keeps a client that ignores it honest."""
    kept = []
    for item in recommendations:
        state = getattr(getattr(item, "state_info", None), "state", None)
        name = getattr(state, "name", state)
        if name in (None, "", 0, "ACTIVE", "STATE_UNSPECIFIED"):
            kept.append(item)
    return kept


def unattended_project(reco):
    """The project an unattended-project recommendation is about: its ``target_resources`` (a project ID or number),
    else the resource of its first operation, else the project named in its description."""
    targets = list(getattr(reco, "target_resources", None) or [])
    if targets:
        return str(targets[0]).rsplit("/", 1)[-1]
    try:
        operation = reco.content.operation_groups[0].operations[0]
        if operation.resource:
            return str(operation.resource).rsplit("/", 1)[-1]
    except (AttributeError, IndexError):
        pass
    match = re.search(r"Project `([^`]+)`", getattr(reco, "description", "") or "")
    return match.group(1) if match else "Unknown"


def run_miscellaneous_checks_refactored(scope, scope_id, all_projects, job_id, *, sink, org_insights=True, project_checks=True):
    """
    Runs a series of miscellaneous operational checks, such as firewall complexity,
    recent changes, and unattended projects, respecting the scan scope.

    Sharded scans (``app.fanout``) split the work so the organization-level
    insights are fetched once rather than once per shard: project shards call
    this with ``org_insights=False``, the scope shard with ``project_checks=False``
    (and no projects). With both flags on (the default) the behavior is the legacy one.

    v18: the organization-level insights' failures are Error rows under their own names (before,
    one error row was appended to both records, and *Unattended Projects* read Action
    Required with an error as its only row); a project whose recent changes could not be
    read is under *Projects not checked*; unattended projects are *Investigation Recommended*
    (a hygiene prompt), named by the recommendation's target project, ACTIVE ones only; the
    recent-changes briefing says when there were none.
    """
    print("🔍 Performing Miscellaneous checks...")
    if project_checks and not all_projects:
        return []

    recent_change_findings, unattended_findings = [], []
    org_errors = {}  # check name -> the error that stopped its organization-level listing

    # --- Org-Level Recommender/Insight Checks (Run ONLY for organization scope) ---
    if scope == 'organization' and org_insights:
        print("   -> Checking for organization-level insights...")
        try:
            recommender_client = gcp.recommender_client()
        except Exception as e:
            org_errors[RECENT_CHANGES_CHECK] = org_errors[UNATTENDED_CHECK] = e
        else:
            parent_recent = f"organizations/{scope_id}/locations/global/insightTypes/{RECENT_CHANGE_INSIGHT}"
            errors = []
            insights = call_api_with_backoff(lambda: recommender_client.list_insights(request={"parent": parent_recent, "filter": ACTIVE_RECOMMENDATIONS}),
                                             context_message="Org-Level Recent Changes", on_error=errors.append)
            if errors:
                org_errors[RECENT_CHANGES_CHECK] = errors[0]
            for insight in active_recommendations(insights):
                recent_change_findings.append({"Project": f"Org-Level ({scope_id})", "Insight": insight.description})

            parent_unattended = f"organizations/{scope_id}/locations/global/recommenders/{UNATTENDED_RECOMMENDER}"
            errors = []
            recommendations = call_api_with_backoff(lambda: recommender_client.list_recommendations(parent=parent_unattended, filter=ACTIVE_RECOMMENDATIONS),
                                                    context_message="Unattended Projects", on_error=errors.append)
            if errors:
                org_errors[UNATTENDED_CHECK] = errors[0]
            for reco in active_recommendations(recommendations):
                unattended_findings.append({"Project": unattended_project(reco), "Recommendation": reco.description})

    # --- Project-Level Recent Changes Check (Runs for all scopes) ---
    print("   -> Checking for project-level recent changes...")
    recent_skipped = NotChecked(RECENT_CHANGES_CHECK)

    def check_project_for_iam_changes(project):
        project_id = project['projectId']
        try:
            recommender_client = gcp.recommender_client()
            parent = f"projects/{project_id}/locations/global/insightTypes/{RECENT_CHANGE_INSIGHT}"
            insights = recommender_client.list_insights(request={"parent": parent, "filter": ACTIVE_RECOMMENDATIONS})
            return [{"Project": project_id, "Insight": insight.description} for insight in active_recommendations(insights)]
        except Exception as e:
            if not is_request_error(e):
                recent_skipped.add(project_id, e)
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_project_for_iam_changes, all_projects if project_checks else [])
        for res_list in results:
            recent_change_findings.extend(res_list)

    # --- Final Assembly ---
    if RECENT_CHANGES_CHECK in org_errors:
        result = {"Check": RECENT_CHANGES_CHECK, "Finding": [{"Error": f"Could not list the organization's recent-change insights: {org_errors[RECENT_CHANGES_CHECK]}"}], "Status": "Error"}
    elif recent_change_findings:
        result = {"Check": RECENT_CHANGES_CHECK, "Finding": recent_change_findings, "Status": INFORMATIONAL}
    else:
        result = {"Check": RECENT_CHANGES_CHECK, "Finding": [{"Summary": NO_RECENT_CHANGES}], "Status": INFORMATIONAL}
    sink.write_finding(job_id, "Recent_Changes", result)
    recent_skipped.write(sink, job_id)

    if UNATTENDED_CHECK in org_errors:
        result = {"Check": UNATTENDED_CHECK, "Finding": [{"Error": f"Could not list the unattended-project recommendations: {org_errors[UNATTENDED_CHECK]}"}], "Status": "Error"}
        sink.write_finding(job_id, "Unattended_Projects", result)
    elif unattended_findings:
        result = {"Check": UNATTENDED_CHECK, "Finding": unattended_findings, "Status": INVESTIGATION}
        sink.write_finding(job_id, "Unattended_Projects", result)
    elif scope == 'organization' and org_insights:
        result = {"Check": UNATTENDED_CHECK, "Finding": [{"Status": "Active Assist flags no project as unattended."}], "Status": "Compliant"}
        sink.write_finding(job_id, "Unattended_Projects", result)

    print("✅ Miscellaneous checks complete.")


def run_service_limit_checks_refactored(scope_id, all_projects, job_id, *, sink):
    """
    Checks regional compute quotas for all projects to identify any approaching their limit.

    v18.1: the project-global quotas (``projects.get().quotas``) join the regional ones under Region
    ``global``; the FIREWALLS quota among them retires the separate firewall count.

    v17: two thresholds instead of one — a quota at ``QUOTA_CRITICAL_RATIO`` (95 %) or more is
    *Action Required*, one at ``QUOTA_WARN_RATIO`` (80 %) *Investigation Recommended* — and
    every row says which ``Family`` the metric belongs to (*Accelerator* for GPU and TPU
    quotas, *Compute* otherwise) and how much ``Headroom`` is left, so the accelerator
    quotas a capacity plan depends on can be read off the table. The check's name keeps
    the 80 % it has always had; the rows changed shape (app.reporting.changes.RESHAPED_CHECKS).

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for quotas with high utilization.
    """
    CHECK_NAME = "Quota Utilization (>80%)"
    print(f"🚦 [{job_id}] Performing Service Limit (Quota) checks...")
    skipped = NotChecked(CHECK_NAME, resource_apis=("compute.googleapis.com",))
    
    def check_project_quotas(project):
        project_id = project['projectId']
        exceeded_quotas = [] # Store findings for this project here
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute_service = gcp.api_build('compute', 'v1', credentials=credentials)
            # v18: regions.list already carries every region's quotas; one call instead of one per region.
            regions, request = [], compute_service.regions().list(project=project_id)
            while request:
                response = request.execute()
                regions.extend(response.get('items', []))
                request = compute_service.regions().list_next(previous_request=request, previous_response=response)
            for region in regions:
                quotas = region.get('quotas')
                if quotas is None:  # a client that lists names only (the fakes of older tests): ask for the region
                    quotas = compute_service.regions().get(project=project_id, region=region['name']).execute().get('quotas', [])
                for quota in quotas:
                    row = quota_row(project_id, region['name'], quota)
                    if row:
                        exceeded_quotas.append(row)
            # v18.1: the project-global Compute quotas (FIREWALLS, NETWORKS, ROUTES, IMAGES, SNAPSHOTS, ...), Region "global".
            for quota in compute_service.projects().get(project=project_id).execute().get('quotas', []):
                row = quota_row(project_id, GLOBAL_REGION, quota)
                if row:
                    exceeded_quotas.append(row)
        except Exception as e:
            skipped.add(project_id, e)
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
    severities = {row.pop("_status") for row in all_findings}
    if not all_findings:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No quotas found over 80% utilization."}], "Status": "Compliant"}
    else:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required" if "Action Required" in severities else "Investigation Recommended"}
    sink.write_finding(job_id, "Quota_Utilization", result)
    skipped.write(sink, job_id)


# --- Quotas (v17) -------------------------------------------------------------------------------------------------
# A quota at QUOTA_WARN_RATIO of its limit is listed (Investigation Recommended); at QUOTA_CRITICAL_RATIO it is
# Action Required: the next scale-out fails.
QUOTA_WARN_RATIO = 0.80
QUOTA_CRITICAL_RATIO = 0.95
ACCELERATOR, COMPUTE_FAMILY = "Accelerator", "Compute"
ACCELERATOR_METRIC = re.compile(r"GPU|TPU|NVIDIA|AMD_|_VWS_", re.I)
# v18: COMMITTED_* quotas are consumed by the commitments themselves — a project that committed exactly its quota sits at
# 100 % by construction, with nothing to fix; the commitment side is Capacity Commitments' and the recommender's.
EXCLUDED_QUOTA_PREFIXES = ("COMMITTED_",)
GLOBAL_REGION = "global"  # v18.1: the Region of a project-global quota row
QUOTA_RECOMMENDATIONS_CHECK = "Quota Increase Recommendations"
QUOTA_RECOMMENDER = "google.resourcemanager.serviceLimit.Recommender"


def quota_family(metric):
    """``Accelerator`` for a GPU or TPU quota metric (``NVIDIA_T4_GPUS``, ``PREEMPTIBLE_NVIDIA_L4_GPUS``, ``TPUS``), else ``Compute``."""
    return ACCELERATOR if ACCELERATOR_METRIC.search(str(metric or "")) else COMPUTE_FAMILY


def quota_row(project_id, region, quota):
    """The row of a regional quota at or over ``QUOTA_WARN_RATIO`` (with its ``_status``), or ``None`` below it or for an excluded metric."""
    usage, limit = float(quota.get('usage', 0.0) or 0), float(quota.get('limit', 0.0) or 0)
    if str(quota.get('metric', '')).startswith(EXCLUDED_QUOTA_PREFIXES):
        return None
    if limit <= 0 or usage / limit <= QUOTA_WARN_RATIO:  # over 80 %, as the check's name says
        return None
    ratio = usage / limit
    return {
        "Project": project_id,
        "Region": region,
        "Metric": quota['metric'],
        "Family": quota_family(quota['metric']),
        "Usage": f"{ratio:.1%}",
        "Details": f"{int(usage)}/{int(limit)}",
        "Headroom": int(limit - usage),
        "_status": "Action Required" if ratio >= QUOTA_CRITICAL_RATIO else "Investigation Recommended",
    }


def quota_recommendation_row(project_id, reco):
    """The quota a recommendation is about: the recommender's ``content.overview`` names the service, the quota and
    its current limit (``serviceName``, ``quotaName`` or ``metric``, ``currentLimit``); the description says why."""
    overview = getattr(reco.content, "overview", None) or {}

    def field(key):
        try:
            return overview[key] if key in overview else ""
        except (KeyError, TypeError, ValueError):
            return ""

    limit = field("currentLimit")
    try:
        limit_text = f"{int(limit):,}" if float(limit) == int(float(limit)) else f"{float(limit):g}"
    except (TypeError, ValueError):
        limit_text = str(limit) if limit not in ("", None) else "unknown"
    return {"Project": project_id, "Service": str(field("serviceName") or "unknown"),
            "Quota": str(field("quotaName") or field("metric") or "unknown"), "Current Limit": limit_text,
            "Recommendation": reco.description}


def check_quota_recommendations(scope_id, all_projects, job_id, *, sink):
    """The quota increases Active Assist recommends (v17): one row per recommendation of the quota recommender,
    asked at ``global`` for every project, naming the service, the quota and its current limit. *Investigation
    Recommended*: a quota that is about to run out is a plan, not an incident; Compliant with an all-clear row
    when there is none."""
    print(f"📈 [{job_id}] Checking {QUOTA_RECOMMENDATIONS_CHECK}...")
    skipped = NotChecked(QUOTA_RECOMMENDATIONS_CHECK)
    rows = []
    client = gcp.recommender_client()
    for project in all_projects:
        project_id = project['projectId']
        parent = f"projects/{project_id}/locations/global/recommenders/{QUOTA_RECOMMENDER}"
        errors = []
        recommendations = call_api_with_backoff(lambda: client.list_recommendations(parent=parent),
                                                context_message=f"'{QUOTA_RECOMMENDATIONS_CHECK}' in {project_id}", on_error=errors.append)
        if errors:
            if not is_request_error(errors[0]):  # a recommender not offered here is not a skipped project
                skipped.add(project_id, errors[0])
            continue
        for reco in recommendations:
            rows.append(quota_recommendation_row(project_id, reco))
    if rows:
        result = {"Check": QUOTA_RECOMMENDATIONS_CHECK, "Finding": rows, "Status": "Investigation Recommended"}
    else:
        result = {"Check": QUOTA_RECOMMENDATIONS_CHECK, "Finding": [{"Status": "No quota increase recommendations."}], "Status": "Compliant"}
    sink.write_finding(job_id, QUOTA_RECOMMENDATIONS_CHECK.replace(" ", "_"), result)
    skipped.write(sink, job_id)
