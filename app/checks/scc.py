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
"""Security Command Center, read (v19): what it says about the scope, and whether it looks at every project.

Two records through plain authorized REST (the image's static discovery documents have no SCC v2, and the Security
Center Management API serves no discovery document at all — both go the way Service Health does, with the client
identifier on the request), under ``roles/iam.securityReviewer``:

- **SCC Active Findings** (Security & Identity, scope-level): the active, unmuted findings under the scope — SCC v2
  ``findings.list`` at the organization or the project; a folder scan lists at the organization and keeps the findings
  whose resource belongs to one of the folder's projects (the folder parent is refused at the Standard tier). One row
  per class × category × severity with the count, the first resources, the newest event time, the **CloudGauge record
  that judges the same fact** (``COVERAGE_MAP``; "—" marks a fact this report has no check for) and SHA's own
  recommendation. SCC's severity is the verdict: CRITICAL **Action Required**, HIGH and MEDIUM Investigation, LOW and
  observations Informational; an ``SCC_ERROR`` finding (SCC itself misconfigured) Investigation. An organization scan
  adds a row when findings are exported nowhere (no notification config, no BigQuery export): Informational at the
  Standard tier, Investigation at Premium or Enterprise. The record is one check in the score whatever it lists.
- **SCC Detector Coverage** (Security & Identity, per project): the *effective* enablement of the detector services at
  each project (``securityCenterServices.list`` — the organization's own list says *inherited → disabled* while a
  project may have five services on). Security Health Analytics off → **Action Required** (the project is never
  scanned); a threat detector off → Investigation where the project runs another threat detector (the Premium or
  Enterprise services are on for it, this one was left off), Informational otherwise (the project is on Standard: the
  detector needs a higher tier). Judged per project alone, so a sharded scan reads the same as a single one. Module
  states are counted, not judged.
"""
import logging
import time

from google.auth.transport.requests import Request as GoogleAuthRequest

from app.checks.gke_operations import ACTION_REQUIRED, INFORMATIONAL, INVESTIGATION, write_rows
from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp

SCC_FINDINGS_CHECK = "SCC Active Findings"
DETECTOR_CHECK = "SCC Detector Coverage"
SCC_CHECKS = (SCC_FINDINGS_CHECK, DETECTOR_CHECK)

SCC_V2 = "https://securitycenter.googleapis.com/v2"
SCM_V1 = "https://securitycentermanagement.googleapis.com/v1"
FINDINGS_FILTER = 'state="ACTIVE" AND mute!="MUTED"'
PAGE_SIZE = 1000
CATEGORY_CAP = 200
REQUEST_TIMEOUT_SECONDS = 60
RETRIED_STATUSES = (429, 500, 502, 503, 504)
RETRY_DELAYS = (2, 5, 10)
PROJECT_TYPE = "cloudresourcemanager.googleapis.com/Project"

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SEVERITY_UNSPECIFIED")
SEVERITY_STATUS = {"CRITICAL": ACTION_REQUIRED, "HIGH": INVESTIGATION, "MEDIUM": INVESTIGATION, "LOW": INFORMATIONAL, "SEVERITY_UNSPECIFIED": INFORMATIONAL}
INFORMATIONAL_CLASSES = ("OBSERVATION",)
ERROR_CLASS = "SCC_ERROR"
PREMIUM_TIERS = ("PREMIUM", "ENTERPRISE")
SHA_SERVICE = "SECURITY_HEALTH_ANALYTICS"
THREAT_SERVICES = {"EVENT_THREAT_DETECTION": "Event Threat Detection", "CONTAINER_THREAT_DETECTION": "Container Threat Detection",
                   "VM_THREAT_DETECTION": "VM Threat Detection", "CLOUD_RUN_THREAT_DETECTION": "Cloud Run Threat Detection", "WEB_SECURITY_SCANNER": "Web Security Scanner"}
SERVICE_NAMES = {SHA_SERVICE: "Security Health Analytics", **THREAT_SERVICES}
SERVICE_FLAGS = {SHA_SERVICE: "security-health-analytics", "EVENT_THREAT_DETECTION": "event-threat-detection", "CONTAINER_THREAT_DETECTION": "container-threat-detection",
                 "VM_THREAT_DETECTION": "vm-threat-detection", "CLOUD_RUN_THREAT_DETECTION": "cloud-run-threat-detection", "WEB_SECURITY_SCANNER": "web-security-scanner"}
# The CloudGauge record that judges the same fact as an SCC category — where both looked, the rows should agree; "—" is a gap of this report.
COVERAGE_MAP = {
    "CLUSTER_SECRETS_ENCRYPTION_DISABLED": "GKE Node Hardening", "BUCKET_LOGGING_DISABLED": "Bucket Logging",  # v19.3: the first was a mapping gap, the second a new record
    "SQL_PUBLIC_IP": "Cloud SQL Security", "SSL_NOT_ENFORCED": "Cloud SQL Security", "SQL_NO_ROOT_PASSWORD": "Cloud SQL Security", "SQL_WEAK_ROOT_PASSWORD": "Cloud SQL Security",
    "AUTO_BACKUP_DISABLED": "Cloud SQL Automated Backups", "SQL_INSTANCE_NOT_MONITORED": "Monitoring Alert Coverage",
    "PRIMITIVE_ROLES_USED": "Primitive Roles (Owner or Editor)", "ADMIN_SERVICE_ACCOUNT": "Service Account Privileges", "KMS_ROLE_SEPARATION": "KMS Keys",
    "SERVICE_ACCOUNT_ROLE_SEPARATION": "Service Account Privileges", "SERVICE_ACCOUNT_KEY_NOT_ROTATED": "Service Account Key Rotation",
    "USER_MANAGED_SERVICE_ACCOUNT_KEY": "User-Managed Keys", "DEFAULT_SERVICE_ACCOUNT_USED": "VM Service Accounts", "FULL_API_ACCESS": "VM Service Accounts",
    "COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED": "VM Hardening", "COMPUTE_SERIAL_PORTS_ENABLED": "VM Hardening", "OS_LOGIN_DISABLED": "VM Hardening",
    "IP_FORWARDING_ENABLED": "VM Hardening", "SHIELDED_VM_DISABLED": "VM Hardening", "CONFIDENTIAL_COMPUTING_DISABLED": "VM Hardening",
    "PUBLIC_IP_ADDRESS": "VM External IPs", "FLOW_LOGS_DISABLED": "VPC Flow Logs", "DEFAULT_NETWORK": "VPC Configuration", "LEGACY_NETWORK": "VPC Configuration",
    "DNSSEC_DISABLED": "DNS Posture", "RSASHA1_FOR_SIGNING": "DNS Posture", "OPEN_FIREWALL": "Open Firewall Rules", "FIREWALL_RULE_LOGGING_DISABLED": "Open Firewall Rules",
    "OPEN_SSH_PORT": "Open Firewall Rules", "OPEN_RDP_PORT": "Open Firewall Rules", "OPEN_MYSQL_PORT": "Open Firewall Rules", "OPEN_POSTGRESQL_PORT": "Open Firewall Rules",
    "OPEN_REDIS_PORT": "Open Firewall Rules", "OPEN_MONGODB_PORT": "Open Firewall Rules", "OPEN_ELASTICSEARCH_PORT": "Open Firewall Rules",
    "OPEN_TELNET_PORT": "Open Firewall Rules", "OPEN_FTP_PORT": "Open Firewall Rules", "OPEN_SMTP_PORT": "Open Firewall Rules", "OPEN_CASSANDRA_PORT": "Open Firewall Rules",
    "OPEN_MEMCACHED_PORT": "Open Firewall Rules", "OPEN_ORACLEDB_PORT": "Open Firewall Rules", "OPEN_NETBIOS_PORT": "Open Firewall Rules", "OPEN_LDAP_PORT": "Open Firewall Rules",
    "OPEN_DNS_PORT": "Open Firewall Rules", "OPEN_POP3_PORT": "Open Firewall Rules", "OPEN_DIRECTORY_SERVICES_PORT": "Open Firewall Rules",
    "OPEN_CISCOSECURE_WEBSM_PORT": "Open Firewall Rules", "OPEN_HTTP_PORT": "Open Firewall Rules",
    "PUBLIC_BUCKET_ACL": "Public GCS Buckets", "BUCKET_POLICY_ONLY_DISABLED": "GCS Uniform Bucket-Level Access", "OBJECT_VERSIONING_DISABLED": "Cloud Storage Versioning",
    "PUBLIC_DATASET": "BigQuery Governance", "BIGQUERY_TABLE_CMEK_DISABLED": "BigQuery Governance", "DATASET_CMEK_DISABLED": "BigQuery Governance",
    "SQL_LOG_CHECKPOINTS_DISABLED": "Cloud SQL Flags", "SQL_LOG_CONNECTIONS_DISABLED": "Cloud SQL Flags", "SQL_LOG_DISCONNECTIONS_DISABLED": "Cloud SQL Flags",
    "SQL_LOG_DURATION_DISABLED": "Cloud SQL Flags", "SQL_LOG_LOCK_WAITS_DISABLED": "Cloud SQL Flags", "SQL_LOG_STATEMENT": "Cloud SQL Flags",
    "SQL_LOG_TEMP_FILES": "Cloud SQL Flags", "SQL_LOG_MIN_ERROR_STATEMENT": "Cloud SQL Flags", "SQL_LOG_MIN_ERROR_STATEMENT_SEVERITY": "Cloud SQL Flags",
    "SQL_LOG_MIN_MESSAGES": "Cloud SQL Flags", "SQL_LOG_MIN_DURATION_STATEMENT_ENABLED": "Cloud SQL Flags", "SQL_LOG_ERROR_VERBOSITY": "Cloud SQL Flags",
    "SQL_LOG_EXECUTOR_STATS_ENABLED": "Cloud SQL Flags", "SQL_LOG_PARSER_STATS_ENABLED": "Cloud SQL Flags", "SQL_LOG_PLANNER_STATS_ENABLED": "Cloud SQL Flags",
    "SQL_LOG_STATEMENT_STATS_ENABLED": "Cloud SQL Flags", "SQL_CONTAINED_DATABASE_AUTHENTICATION": "Cloud SQL Flags", "SQL_CROSS_DB_OWNERSHIP_CHAINING": "Cloud SQL Flags",
    "SQL_EXTERNAL_SCRIPTS_ENABLED": "Cloud SQL Flags", "SQL_LOCAL_INFILE": "Cloud SQL Flags", "SQL_REMOTE_ACCESS_ENABLED": "Cloud SQL Flags",
    "SQL_SKIP_SHOW_DATABASE_DISABLED": "Cloud SQL Flags", "SQL_TRACE_FLAG_3625": "Cloud SQL Flags", "SQL_USER_CONNECTIONS_CONFIGURED": "Cloud SQL Flags",
    "SQL_USER_OPTIONS_CONFIGURED": "Cloud SQL Flags",
    "ALLOYDB_AUTO_BACKUP_DISABLED": "AlloyDB Posture", "ALLOYDB_BACKUPS_DISABLED": "AlloyDB Posture", "ALLOYDB_PUBLIC_IP": "AlloyDB Posture", "ALLOYDB_SSL_NOT_ENFORCED": "AlloyDB Posture",
    "KMS_KEY_NOT_ROTATED": "KMS Keys", "KMS_PUBLIC_KEY": "KMS Keys", "KMS_PROJECT_HAS_OWNER": "KMS Keys", "TOO_MANY_KMS_USERS": "KMS Keys",
    "API_KEY_EXISTS": "API Keys", "API_KEY_APIS_UNRESTRICTED": "API Keys", "API_KEY_APPS_UNRESTRICTED": "API Keys", "API_KEY_NOT_ROTATED": "API Keys",
    "OVER_PRIVILEGED_ACCOUNT": "GKE Credential Exposure", "OVER_PRIVILEGED_SCOPES": "GKE Credential Exposure", "OVER_PRIVILEGED_SERVICE_ACCOUNT_USER": "GKE Credential Exposure",
    "WORKLOAD_IDENTITY_DISABLED": "GKE Credential Exposure", "LEGACY_METADATA_ENABLED": "GKE Credential Exposure", "LEGACY_AUTHORIZATION_ENABLED": "GKE Control Plane Exposure",
    "MASTER_AUTHORIZED_NETWORKS_DISABLED": "GKE Control Plane Exposure", "PRIVATE_CLUSTER_DISABLED": "GKE Control Plane Exposure", "CLIENT_CERT_AUTHENTICATION_DISABLED": "GKE Control Plane Exposure",
    "NETWORK_POLICY_DISABLED": "GKE Node Hardening", "INTRANODE_VISIBILITY_DISABLED": "GKE Node Hardening", "BINARY_AUTHORIZATION_DISABLED": "GKE Node Hardening",
    "COS_NOT_USED": "GKE Node Hardening", "NODEPOOL_SECURE_BOOT_DISABLED": "GKE Node Hardening", "INTEGRITY_MONITORING_DISABLED": "GKE Node Hardening",
    "AUTO_REPAIR_DISABLED": "GKE Hygiene", "AUTO_UPGRADE_DISABLED": "GKE Hygiene", "RELEASE_CHANNEL_DISABLED": "GKE Hygiene", "GKE_SECURITY_BULLETIN": "GKE Supported Versions",
    "CLUSTER_LOGGING_DISABLED": "GKE Observability", "CLUSTER_MONITORING_DISABLED": "GKE Observability", "POD_SECURITY_POLICY_DISABLED": "GKE Node Hardening",
    "CONTAINER_THREAT_DETECTION_DISABLED": "GKE Threat Detection",
    "AUDIT_LOGGING_DISABLED": "Data Access Audit Logs", "LOG_NOT_EXPORTED": "Organization Log Sink", "AUDIT_CONFIG_NOT_MONITORED": "Monitoring Alert Coverage",
    "BUCKET_IAM_NOT_MONITORED": "Monitoring Alert Coverage", "FIREWALL_NOT_MONITORED": "Monitoring Alert Coverage", "NETWORK_NOT_MONITORED": "Monitoring Alert Coverage",
    "ROUTE_NOT_MONITORED": "Monitoring Alert Coverage", "OWNER_NOT_MONITORED": "Monitoring Alert Coverage", "CUSTOM_ROLE_NOT_MONITORED": "Monitoring Alert Coverage",
    "PUBLIC_COMPUTE_IMAGE": "External Principals", "NON_ORG_IAM_MEMBER": "External Principals", "REDIS_ROLE_USED_ON_ORG": "Critical Org-Level Roles",
    "ESSENTIAL_CONTACTS_NOT_CONFIGURED": "Essential Contacts",
    "HTTP_LOAD_BALANCER": "Load Balancer Edge", "WEAK_SSL_POLICY": "Load Balancer Edge", "ORG_POLICY_CONFIDENTIAL_VM_POLICY": "Organization Policies",
    "ORG_POLICY_LOCATION_RESTRICTION": "Organization Policies", "PUBLIC_LOG_BUCKET": "Public GCS Buckets",
    "VPC_FLOW_LOGS_SETTINGS_NOT_RECOMMENDED": "Log Cost Levers", "LOAD_BALANCER_LOGGING_DISABLED": "Load Balancer Edge",
}
FINDINGS_ALL_CLEAR = "Security Command Center reports no active, unmuted finding under the scope."
DETECTOR_ALL_CLEAR = "Security Health Analytics and the threat detectors available to the tier are on in every project."
NOT_ACTIVATED_WORDS = ("not been activated", "not activated", "legacy", "has not been", "is not enabled for")


class RestError(Exception):
    """A non-2xx answer of a Google REST API: ``status`` and the API's message."""

    def __init__(self, status, message):
        super().__init__(f"{status} {message}")
        self.status = status
        self.message = message


# --- REST -------------------------------------------------------------------------------------------------------------

def bearer_headers(credentials):
    if not getattr(credentials, "token", None) or getattr(credentials, "expired", False):
        credentials.refresh(GoogleAuthRequest())
    return {"Authorization": f"Bearer {credentials.token}"}


def _error_message(response):
    try:
        error = response.json().get("error", {})
        return error.get("message") or response.text
    except Exception:  # noqa: BLE001
        return getattr(response, "text", "") or f"HTTP {response.status_code}"


def get_json(url, headers, params=None):
    """GET ``url`` as JSON through the provider (the client identifier on it), retrying 429 and 5xx answers; :class:`RestError` otherwise."""
    for attempt, delay in enumerate((*RETRY_DELAYS, None)):
        response = gcp.http_get(url, headers=headers, params=params or {}, timeout=REQUEST_TIMEOUT_SECONDS)
        if response.status_code == 200:
            return response.json() or {}
        if response.status_code in RETRIED_STATUSES and delay is not None:
            logging.warning(f"{url} answered {response.status_code}; retrying in {delay}s (attempt {attempt + 1})")
            time.sleep(delay)
            continue
        raise RestError(response.status_code, _error_message(response))


def list_pages(url, key, headers, params=None, cap=None):
    """Every item of a paged list endpoint (``pageToken`` / ``nextPageToken``), ``cap`` items at most."""
    items, token = [], None
    while True:
        page = get_json(url, headers, {**(params or {}), **({"pageToken": token} if token else {})})
        items += page.get(key) or []
        token = page.get("nextPageToken")
        if not token or (cap is not None and len(items) >= cap):
            return items


def not_activated(error):
    """A 4xx that says Security Command Center is not usable at this parent (never activated, the legacy tier, a folder at Standard) —
    not a permission error, which stays an Error of the scanner's."""
    text = str(getattr(error, "message", error) or "").lower()
    return getattr(error, "status", None) in (400, 403, 404) and any(word in text for word in NOT_ACTIVATED_WORDS)


# --- SCC Active Findings ---------------------------------------------------------------------------------------------------

def tail(name):
    return str(name or "").rsplit("/", 1)[-1]


def first_sentence(text, limit=200):
    text = " ".join(str(text or "").split())
    if not text:
        return ""
    for mark in (". ", ".\n"):
        if mark in text:
            text = text.split(mark, 1)[0] + "."
            break
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def finding_facts(result):
    """What the rules read of one ``ListFindingsResult``: class, category, severity, the resource and its project (ID or number — the
    v2 ``gcpMetadata`` names projects by number), the newest event time, SHA's explanation and recommendation."""
    finding, resource = result.get("finding") or {}, result.get("resource") or {}
    metadata = resource.get("gcpMetadata") or {}
    properties = finding.get("sourceProperties") or {}
    project = tail(metadata.get("project") or resource.get("projectName") or "")
    return {"class": str(finding.get("findingClass") or "FINDING_CLASS_UNSPECIFIED"), "category": str(finding.get("category") or "?"),
            "severity": str(finding.get("severity") or "SEVERITY_UNSPECIFIED").upper(), "mute": str(finding.get("mute") or ""), "state": str(finding.get("state") or ""),
            "resource": str(resource.get("displayName") or tail(finding.get("resourceName")) or "?"), "project": project,
            "project_display": str(metadata.get("projectDisplayName") or resource.get("projectDisplayName") or project),
            "event_time": str(finding.get("eventTime") or finding.get("createTime") or ""),
            "explanation": str(properties.get("Explanation") or finding.get("description") or ""), "recommendation": str(properties.get("Recommendation") or finding.get("nextSteps") or ""),
            "external_uri": str(finding.get("externalUri") or ""), "source": str(finding.get("parentDisplayName") or "")}


def finding_status(fact):
    if fact["class"] == ERROR_CLASS:
        return INVESTIGATION
    if fact["class"] in INFORMATIONAL_CLASSES:
        return INFORMATIONAL
    return SEVERITY_STATUS.get(fact["severity"], INFORMATIONAL)


DETECTION_SOURCES = ("Threat Detection", "Sensitive Actions Service", "Anomaly Detection")  # SCC's built-in detectors: Event/Container/VM/Cloud Run Threat Detection, the Sensitive Actions Service, Anomaly Detection


def detected(cls, source):
    """A finding a *detector* raised — the THREAT class, or any class from one of SCC's detection sources (the Sensitive Actions Service files
    "Impact: GPU Instance Created" under OBSERVATION) — is Security Command Center's own domain, not a gap of this report."""
    return cls == "THREAT" or str(source or "").endswith(DETECTION_SOURCES)


def finding_rows(facts, org_id=""):
    """One row per class × category × severity, the worst severity first, then the most numerous."""
    groups = {}
    for fact in facts:
        if fact["mute"] == "MUTED" or (fact["state"] and fact["state"] != "ACTIVE"):
            continue
        groups.setdefault((fact["class"], fact["category"], fact["severity"]), []).append(fact)
    ordered = sorted(groups.items(), key=lambda kv: (SEVERITY_ORDER.index(kv[0][2]) if kv[0][2] in SEVERITY_ORDER else len(SEVERITY_ORDER), -len(kv[1]), kv[0][1]))
    rows = []
    for (cls, category, severity), members in ordered[:CATEGORY_CAP]:
        names = []
        for fact in members:
            if fact["resource"] not in names:
                names.append(fact["resource"])
        shown = ", ".join(names[:3]) + (f" +{len(names) - 3}" if len(names) > 3 else "")
        latest = max((fact["event_time"] for fact in members), default="")
        sample = next((fact for fact in members if fact["recommendation"]), members[0])
        where = f"--organization={org_id}" if org_id else "--project=<project>"
        listing = f"gcloud scc findings list {where} --location=global --filter='category=\"{category}\" AND state=\"ACTIVE\"'"
        fix = (first_sentence(sample["recommendation"]) + "  " if sample["recommendation"] else "") + listing
        issue = first_sentence(sample["explanation"]) or f"{SERVICE_NAMES.get(cls, cls.replace('_', ' ').title())} finding."
        rows.append({"Severity": severity.replace("_", " ").title() if severity != "SEVERITY_UNSPECIFIED" else "Unspecified", "Class": cls.replace("_", " ").title(),
                     "Category": category, "Count": len(members), "Resources": shown, "Latest": latest[:10],
                     "CloudGauge check": COVERAGE_MAP.get(category, "SCC (threat detection)" if detected(cls, sample["source"]) else "—"),  # v19.3: a detected event is SCC's own domain, not a gap of this report
                     "Issue": issue, "Detail": f"{len(members)} active finding{'s' if len(members) != 1 else ''} from {sample['source'] or 'Security Command Center'}"
                                               f"{'; ' + str(len(names)) + ' resources' if len(names) > 1 else ''}; newest {latest[:10] or '?'}.",
                     "Fix": fix, "_status": finding_status(sample)})
    return rows


def export_row(org_id, tier, notification_configs, bigquery_exports):
    """The organization-scan row when findings leave SCC nowhere; None when a continuous export exists."""
    if notification_configs or bigquery_exports:
        return None
    premium = str(tier or "").upper() in PREMIUM_TIERS
    return {"Severity": "—", "Class": "Export", "Category": "No findings export", "Count": 0, "Resources": f"organizations/{org_id}", "Latest": "", "CloudGauge check": "Security Command Center Status",
            "Issue": "Findings leave Security Command Center nowhere.",
            "Detail": f"No notification config and no BigQuery export at the organization ({str(tier or 'unknown').title()} tier): nothing downstream — a SIEM, a ticket queue, a dashboard — sees a new finding.",
            "Fix": f"gcloud scc notifications create cg-findings --organization={org_id} --location=global --pubsub-topic=projects/<project>/topics/<topic> --filter='state=\"ACTIVE\"'  "
                   f"# or gcloud scc bqexports create cg-findings --organization={org_id} --location=global --dataset=projects/<project>/datasets/<dataset>",
            "_status": INVESTIGATION if premium else INFORMATIONAL}


def scope_projects(asset_client, parent):
    """``(organization id, {project ids and numbers})`` under ``parent`` from the search index (the findings name projects by number)."""
    org_id, members = "", set()
    for result in asset_client.search_all_resources(request={"scope": parent, "asset_types": [PROJECT_TYPE], "read_mask": "name,project,organization,state,additionalAttributes", "page_size": 500}):
        state = str(getattr(result, "state", "") or "")
        if state and state != "ACTIVE":
            continue
        attributes = getattr(result, "additional_attributes", None)
        try:
            attributes = dict(attributes) if attributes else {}
        except (TypeError, ValueError):
            attributes = {}
        members.add(str(attributes.get("projectId") or tail(getattr(result, "name", ""))))
        number = tail(getattr(result, "project", ""))
        if number:
            members.add(number)
        org_id = org_id or tail(getattr(result, "organization", ""))
    return org_id, members


def list_findings(parent, headers):
    return [finding_facts(r) for r in list_pages(f"{SCC_V2}/{parent}/sources/-/locations/global/findings", "listFindingsResults", headers, {"filter": FINDINGS_FILTER, "pageSize": PAGE_SIZE})]


def check_scc_findings(scope, scope_id, job_id, *, sink):
    """Writes *SCC Active Findings* (module docstring)."""
    print(f"🛡️  [{job_id}] Checking {SCC_FINDINGS_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    skipped = NotChecked(SCC_FINDINGS_CHECK)
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        headers = bearer_headers(credentials)
        asset_client = gcp.asset_client(credentials)
        facts, org_id = None, scope_id if scope == "organization" else ""
        if scope != "folder":
            try:
                facts = list_findings(parent, headers)
            except RestError as e:
                if scope == "organization" or not not_activated(e):
                    raise
                logging.info(f"[{job_id}] {SCC_FINDINGS_CHECK}: {parent} answered {e}; reading the organization's findings instead")
        if facts is None:  # a folder, or a project SCC does not serve directly: the organization's findings, the scope's projects kept
            org_id, members = scope_projects(asset_client, parent)
            if not org_id:
                raise LookupError(f"no organization found above {parent}")
            facts = [f for f in list_findings(f"organizations/{org_id}", headers) if f["project"] in members or f["project_display"] in members]
    except RestError as e:
        if not_activated(e):
            sink.write_finding(job_id, SCC_FINDINGS_CHECK.replace(" ", "_"), {"Check": SCC_FINDINGS_CHECK, "Status": INFORMATIONAL,
                                                                             "Finding": [{"Summary": f"Security Command Center is not activated for {parent} ({e.status}: {first_sentence(e.message)}); Security Command Center Status says what that means."}]})
            return
        logging.error(f"[{job_id}] {SCC_FINDINGS_CHECK}: {e}")
        sink.write_finding(job_id, SCC_FINDINGS_CHECK.replace(" ", "_"), {"Check": SCC_FINDINGS_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    except Exception as e:
        logging.error(f"[{job_id}] {SCC_FINDINGS_CHECK}: {e}")
        sink.write_finding(job_id, SCC_FINDINGS_CHECK.replace(" ", "_"), {"Check": SCC_FINDINGS_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    rows = finding_rows(facts, org_id)
    if scope == "organization":
        try:
            tier = str((gcp.api_build("securitycenter", "v1beta2", credentials=credentials).organizations().getSubscription(name=f"organizations/{scope_id}/subscription").execute() or {}).get("tier") or "")
            configs = list_pages(f"{SCC_V2}/organizations/{scope_id}/locations/global/notificationConfigs", "notificationConfigs", headers, {"pageSize": 100})
            exports = list_pages(f"{SCC_V2}/organizations/{scope_id}/locations/global/bigQueryExports", "bigQueryExports", headers, {"pageSize": 100})
            row = export_row(scope_id, tier, configs, exports)
            if row:
                rows.append(row)
        except Exception as e:  # noqa: BLE001 — the export rule is a bonus
            skipped.add(parent, e, detail="the findings-export rule: the notification configs or BigQuery exports could not be read")
    write_rows(sink, job_id, SCC_FINDINGS_CHECK, rows, FINDINGS_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- SCC Detector Coverage ---------------------------------------------------------------------------------------------------

def service_facts(services):
    """``{service: {effective, intended, modules_on, modules}}`` over a ``securityCenterServices.list`` answer."""
    facts = {}
    for service in services:
        name = tail(service.get("name")).upper().replace("-", "_")
        modules = service.get("modules") or {}
        facts[name] = {"effective": str(service.get("effectiveEnablementState") or "").upper(), "intended": str(service.get("intendedEnablementState") or "").upper(),
                       "modules_on": sum(1 for m in modules.values() if str((m or {}).get("effectiveEnablementState") or "").upper() == "ENABLED"), "modules": len(modules)}
    return facts


def detector_rows(project_id, facts):
    rows = []
    premium_available = any(facts.get(service, {}).get("effective") == "ENABLED" for service in THREAT_SERVICES)
    sha = facts.get(SHA_SERVICE)
    if sha is not None and sha["effective"] != "ENABLED":
        rows.append({"Project": project_id, "Service": SERVICE_NAMES[SHA_SERVICE], "State": sha["effective"].lower() or "unknown",
                     "Issue": "Not scanned by Security Health Analytics.",
                     "Detail": f"The service is {sha['effective'].lower() or 'off'} for the project ({sha['intended'].lower() or 'inherited'} setting): no misconfiguration finding will ever appear for it in Security Command Center.",
                     "Fix": f"gcloud scc manage services update {SERVICE_FLAGS[SHA_SERVICE]} --project={project_id} --enablement-state=ENABLED  "
                            f"# effective once Security Command Center is activated for the project (console: Security Command Center → Activate, free at Standard) or the organization",
                     "_status": ACTION_REQUIRED})
    for service, label in THREAT_SERVICES.items():
        fact = facts.get(service)
        if fact is None or fact["effective"] == "ENABLED":
            continue
        rows.append({"Project": project_id, "Service": label, "State": fact["effective"].lower() or "unknown",
                     "Issue": f"{label} off.",
                     "Detail": (f"The detector is {fact['effective'].lower() or 'off'} for the project; " +
                                ("the project runs other Premium-tier detectors, so this one was left off." if premium_available else "it needs the Premium or Enterprise tier, which the project is not on.")),
                     "Fix": f"gcloud scc manage services update {SERVICE_FLAGS[service]} --project={project_id} --enablement-state=ENABLED  # effective where the project or the organization is on Premium or Enterprise",
                     "_status": INVESTIGATION if premium_available else INFORMATIONAL})
    return rows


def check_detector_coverage(scope_id, all_projects, job_id, *, sink):
    """Writes *SCC Detector Coverage* for every project (module docstring)."""
    print(f"🔎 [{job_id}] Checking {DETECTOR_CHECK} in {len(all_projects)} projects...")
    skipped, rows = NotChecked(DETECTOR_CHECK), []
    credentials = None
    for project in all_projects:
        project_id = project["projectId"]
        try:
            if credentials is None or getattr(credentials, "expired", False):
                credentials, _ = gcp.auth_default(scopes=SCOPES)
            headers = bearer_headers(credentials)
            services = list_pages(f"{SCM_V1}/projects/{project_id}/locations/global/securityCenterServices", "securityCenterServices", headers, {"pageSize": 50})
        except Exception as e:
            skipped.add(project_id, e)
            continue
        rows += detector_rows(project_id, service_facts(services))
    write_rows(sink, job_id, DETECTOR_CHECK, rows, DETECTOR_ALL_CLEAR)
    skipped.write(sink, job_id)
