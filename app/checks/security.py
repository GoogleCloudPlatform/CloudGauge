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

v18 revalidated the legacy checks of this module against today's APIs: each
one now has a pure rule over the API's own JSON (``*_rows`` / ``*_row``
functions, unit-tested on fixtures of the real shapes), a verdict that
distinguishes what is wrong from what deserves a look, and the exact ``Fix``
line for every row. What each rule changed, and why, is in RELEASE_NOTES.md.
"""
import logging
import re
from datetime import datetime, timezone

from googleapiclient.errors import HttpError

from app.config import SCOPES
from app.checks.not_checked import NotChecked, is_api_disabled, is_request_error
from app.services import gcp
from app.services.org_policies import fetch_best_practices, get_effective_org_policies
from app.utils import call_api_with_backoff


ACTION_REQUIRED, INVESTIGATION, INFORMATIONAL, COMPLIANT = "Action Required", "Investigation Recommended", "Informational", "Compliant"
# The order the verdicts rank in: a record's status is the worst of its rows'.
SEVERITY_RANK = {ACTION_REQUIRED: 3, INVESTIGATION: 2, INFORMATIONAL: 1, COMPLIANT: 0}


def worst_status(rows, default=COMPLIANT):
    """The record status of ``rows`` that each carry a ``_status`` (the worst), ``default`` when there are none."""
    statuses = [row.get("_status", default) for row in rows]
    return max(statuses, key=lambda s: SEVERITY_RANK.get(s, 0)) if statuses else default


def strip_statuses(rows):
    """``rows`` without their ``_status`` key (the report shows one status per record)."""
    return [{k: v for k, v in row.items() if k != "_status"} for row in rows]


def result_record(check_name, rows, all_clear, status=None):
    """A finding record: ``rows`` under their worst status, or the one all-clear row when there are none."""
    if rows:
        return {"Check": check_name, "Finding": strip_statuses(rows), "Status": status or worst_status(rows)}
    return {"Check": check_name, "Finding": [{"Status": all_clear}], "Status": COMPLIANT}


# --- Principals (v18) ------------------------------------------------------------------------------------------------
# The kinds of IAM member the identity checks tell apart. Google-managed service agents hold their roles by design (the
# Google APIs service agent is Editor in every project) and are never findings.
PUBLIC, DELETED, GOOGLE_MANAGED, DEFAULT_SA, SERVICE_ACCOUNT = "public", "deleted", "Google-managed service agent", "default service account", "service account"
USER, EXTERNAL_USER, CONSUMER_ACCOUNT, GROUP, DOMAIN, OTHER_PRINCIPAL = ("user", "user (outside the primary domain)", "consumer account", "group", "domain",
                                                                         "other principal")
PUBLIC_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")
GOOGLE_MANAGED_AGENT = re.compile(
    r"^serviceAccount:(?:\d+@cloudservices\.gserviceaccount\.com|service-\d+@[^@]+\.iam\.gserviceaccount\.com|"
    r"[^@]+@gcp-sa-[^@]+\.iam\.gserviceaccount\.com|[^@]+@system\.gserviceaccount\.com|[^@]+@containerregistry\.iam\.gserviceaccount\.com)$")
DEFAULT_SERVICE_ACCOUNT = re.compile(r"^serviceAccount:(?:\d+-compute@developer\.gserviceaccount\.com|[^@]+@appspot\.gserviceaccount\.com)$")
CONSUMER_DOMAINS = ("gmail.com", "googlemail.com", "hotmail.com", "outlook.com", "yahoo.com", "icloud.com", "protonmail.com")


def principal_kind(member, org_domains=()):
    """What kind of principal an IAM member is (one of the constants above).

    ``org_domains`` are the organization's domains, lower-case; a ``user:`` outside them is
    ``EXTERNAL_USER`` (an acquired company's domain as often as a stranger, hence not a verdict
    on its own), one at a consumer mail provider ``CONSUMER_ACCOUNT``.
    """
    if member in PUBLIC_PRINCIPALS:
        return PUBLIC
    if member.startswith("deleted:"):
        return DELETED
    if GOOGLE_MANAGED_AGENT.match(member):
        return GOOGLE_MANAGED
    if DEFAULT_SERVICE_ACCOUNT.match(member):
        return DEFAULT_SA
    kind, _, name = member.partition(":")
    if kind == "serviceAccount":
        return SERVICE_ACCOUNT
    if kind == "user":
        domain = name.rsplit("@", 1)[-1].lower()
        if domain in CONSUMER_DOMAINS:
            return CONSUMER_ACCOUNT
        return EXTERNAL_USER if org_domains and domain not in org_domains else USER
    return {"group": GROUP, "domain": DOMAIN}.get(kind, OTHER_PRINCIPAL)


def condition_text(binding):
    """The title (or expression) of a conditional binding, ``""`` for an unconditional one."""
    condition = binding.get("condition") or {}
    return condition.get("title") or condition.get("expression") or ""


def condition_flag(binding):
    """The ``--condition`` flag that names a binding's condition in ``gcloud ... remove-iam-policy-binding``."""
    condition = binding.get("condition") or {}
    if not condition:
        return ""
    parts = [f"expression={condition.get('expression', '')}", f"title={condition.get('title', '')}"]
    return " --condition='" + ",".join(parts) + "'"


def organization_domains(crm_service, project_id):
    """The primary domain of the organization ``project_id`` belongs to, as a one-element tuple; ``()`` when it cannot be read.

    Resource Manager names an organization by its primary domain (``displayName``); secondary domains are
    not listed, which is why a user outside it is only *Investigation Recommended*.
    """
    try:
        ancestry = crm_service.projects().getAncestry(projectId=project_id, body={}).execute()
        org_ids = [a["resourceId"]["id"] for a in ancestry.get("ancestor", []) if a.get("resourceId", {}).get("type") == "organization"]
        if not org_ids:
            return ()
        organization = crm_service.organizations().get(name=f"organizations/{org_ids[0]}").execute()
        name = str(organization.get("displayName") or "").lower()
        return (name,) if "." in name else ()
    except Exception as e:
        logging.info(f"Could not determine the organization's domain for {project_id}: {e}")
        return ()


# --- Security & Identity Checks ---

# Critical Org-Level Roles (v18): the roles that control the organization, and how each kind of holder rates.
# A group is the recommended practice (an inventory row, Informational); a person is a look; an account that can be
# impersonated, a consumer account or the public are findings.
CRITICAL_ROLES_CHECK = "Critical Org-Level Roles"
PUBLIC_ORG_CHECK = "Public Org-Level Access"
ORG_CRITICAL_ROLES = ("roles/owner", "roles/resourcemanager.organizationAdmin", "roles/editor", "roles/billing.admin",
                      "roles/iam.securityAdmin", "roles/iam.organizationRoleAdmin", "roles/resourcemanager.folderAdmin")
ORG_HOLDER_STATUS = {GROUP: INFORMATIONAL, USER: INVESTIGATION, EXTERNAL_USER: INVESTIGATION, DELETED: INVESTIGATION, DOMAIN: ACTION_REQUIRED,
                     CONSUMER_ACCOUNT: ACTION_REQUIRED, SERVICE_ACCOUNT: ACTION_REQUIRED, DEFAULT_SA: ACTION_REQUIRED, PUBLIC: ACTION_REQUIRED,
                     OTHER_PRINCIPAL: INVESTIGATION}
ORG_ROLES_ALL_CLEAR = "The organization's critical roles are held by groups only."


def org_role_fix(org_id, member, role, binding, kind):
    """The ``gcloud`` line that removes an organization-level grant, with the practice to replace it."""
    line = f"gcloud organizations remove-iam-policy-binding {org_id} --member={member} --role={role}{condition_flag(binding)}"
    if kind in (USER, EXTERNAL_USER):
        return f"{line}  # grant the role to a group with few members first"
    if kind == SERVICE_ACCOUNT:
        return f"{line}  # a service account that administers the organization is a standing target; use a narrower role"
    return line


def critical_role_rows(org_id, policy, org_domains=()):
    """The holders of the organization's critical roles: one row per (principal, role) with its kind, condition, fix and ``_status``.

    Google-managed service agents are left out. The record is Compliant when every holder is a group.
    """
    rows = []
    for binding in policy.get("bindings", []):
        role = binding.get("role")
        if role not in ORG_CRITICAL_ROLES:
            continue
        for member in binding.get("members", []):
            kind = principal_kind(member, org_domains)
            if kind == GOOGLE_MANAGED:
                continue
            rows.append({"Principal": member, "Type": kind, "Role": role, "Condition": condition_text(binding),
                         "Fix": org_role_fix(org_id, member, role, binding, kind), "_status": ORG_HOLDER_STATUS[kind]})
    return rows


def public_org_rows(org_id, policy):
    """The public principals (``allUsers``, ``allAuthenticatedUsers``) in the organization's own policy, on any role."""
    return [{"Principal": member, "Role": binding.get("role"), "Condition": condition_text(binding),
             "Fix": f"gcloud organizations remove-iam-policy-binding {org_id} --member={member} --role={binding.get('role')}{condition_flag(binding)}",
             "_status": ACTION_REQUIRED}
            for binding in policy.get("bindings", []) for member in binding.get("members", []) if member in PUBLIC_PRINCIPALS]


def check_org_iam_policy(org_id, job_id, *, sink):
    """
    Checks the organization-level IAM policy for critical and public role bindings.

    v18: the critical roles (``ORG_CRITICAL_ROLES``) are read with policy version 3 (conditions
    shown), Google-managed agents are left out, and the verdict follows the kind of holder
    (``ORG_HOLDER_STATUS``): groups are the practice and make a Compliant inventory, a person is a
    look, a service account or the public a finding. Each record writes its own Error row when the
    policy cannot be read (the legacy ``Organization IAM Policy Check`` name is retired).

    Args:
        org_id (str): The organization ID.
    """
    print(f"🕵️  [{job_id}] Checking for {CRITICAL_ROLES_CHECK} and {PUBLIC_ORG_CHECK}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
        policy = service.organizations().getIamPolicy(resource=f'organizations/{org_id}', body={"options": {"requestedPolicyVersion": 3}}).execute()
        org_domains = ()
        try:
            name = str(service.organizations().get(name=f"organizations/{org_id}").execute().get("displayName") or "").lower()
            org_domains = (name,) if "." in name else ()
        except Exception as e:
            logging.info(f"Could not read the organization's display name: {e}")
        rows = critical_role_rows(org_id, policy, org_domains)
        status = worst_status(rows)
        if status == INFORMATIONAL:  # groups only: the practice, listed
            status = COMPLIANT
        result_crit = result_record(CRITICAL_ROLES_CHECK, rows, ORG_ROLES_ALL_CLEAR, status=status)
        result_public = result_record(PUBLIC_ORG_CHECK, public_org_rows(org_id, policy), "No public access found at the organization level.")
    except Exception as e:
        error = [{"Error": f"Could not read the organization's IAM policy: {e}"}]
        result_crit = {"Check": CRITICAL_ROLES_CHECK, "Finding": error, "Status": "Error"}
        result_public = {"Check": PUBLIC_ORG_CHECK, "Finding": error, "Status": "Error"}
    sink.write_finding(job_id, CRITICAL_ROLES_CHECK.replace(" ", "_"), result_crit)
    sink.write_finding(job_id, PUBLIC_ORG_CHECK.replace(" ", "_"), result_public)


# Security Command Center Status (v18): the organization's subscription tier, from the Settings API that carries it.
SCC_CHECK = "Security Command Center Status"
SCC_PAID_TIERS = ("PREMIUM", "ENTERPRISE")
SCC_STANDARD_NOTE = ("Standard tier: Security Health Analytics' built-in detectors and basic threat detection only. Premium and "
                     "Enterprise add Event and Container Threat Detection, compliance reporting and attack-path simulation; "
                     "evaluate the tier against your requirements.")
SCC_NOT_ACTIVATED = ("Security Command Center is not activated for this organization. Activate it (the Standard tier is free) "
                     "in the console: Security Command Center → Get started.")


def scc_tier_row(subscription):
    """The row of an SCC subscription (``v1beta2 organizations.getSubscription``): tier, kind, end, and its ``_status``.

    Premium and Enterprise are Compliant; Standard is *Investigation Recommended* — a tier is a purchasing decision,
    not a misconfiguration, so the row says what the paid tiers add and leaves the evaluation to the reader.
    """
    tier = str(subscription.get("tier") or "").upper()
    details = subscription.get("details") or {}
    row = {"Tier": tier.capitalize() if tier and tier != "TIER_UNSPECIFIED" else "Unknown",
           "Subscription": str(details.get("type") or "").replace("_", " ").lower() or "n/a"}
    if details.get("endTime"):
        row["Ends"] = str(details["endTime"])[:10]
    if tier in SCC_PAID_TIERS:
        return {**row, "_status": COMPLIANT}
    return {**row, "Note": SCC_STANDARD_NOTE, "_status": INVESTIGATION}


def check_scc_status(org_id, job_id, *, sink):
    """
    Checks the tier of Security Command Center (SCC) for the organization.

    v18: reads ``securitycenter v1beta2 organizations.getSubscription`` — the resource that carries
    the tier (the v1 ``organizationSettings`` the check read before has no ``tier`` field, so every
    organization read as Standard). A 404 means SCC was never activated (Action Required); the API
    being disabled in the project CloudGauge runs in is the scanner's problem and an Error, not the
    organization's.

    Args:
        org_id (str): The organization ID.
    """
    print(f"🛡️  [{job_id}] Checking {SCC_CHECK}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('securitycenter', 'v1beta2', credentials=credentials)
        subscription = service.organizations().getSubscription(name=f"organizations/{org_id}/subscription").execute()
        row = scc_tier_row(subscription)
        result = {"Check": SCC_CHECK, "Finding": strip_statuses([row]), "Status": row["_status"]}
    except HttpError as e:
        if e.resp.status == 404:
            result = {"Check": SCC_CHECK, "Finding": [{"Issue": SCC_NOT_ACTIVATED}], "Status": ACTION_REQUIRED}
        elif is_api_disabled(e):
            result = {"Check": SCC_CHECK, "Finding": [{"Error": f"securitycenter.googleapis.com is not enabled in the project CloudGauge runs in: {e}"}], "Status": "Error"}
        else:
            result = {"Check": SCC_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"}
    except Exception as e:
        result = {"Check": SCC_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"}
    sink.write_finding(job_id, SCC_CHECK.replace(" ", "_"), result)


# Primitive Roles (v18): who holds Owner or Editor on a project, by kind of principal, plus public principals on any role.
PRIMITIVE_ROLES_CHECK = "Primitive Roles (Owner or Editor)"
PRIMITIVE_ROLES = ("roles/owner", "roles/editor")
PRIMITIVE_HOLDER_STATUS = {PUBLIC: ACTION_REQUIRED, SERVICE_ACCOUNT: ACTION_REQUIRED, CONSUMER_ACCOUNT: ACTION_REQUIRED, DOMAIN: ACTION_REQUIRED,
                           USER: INVESTIGATION, EXTERNAL_USER: INVESTIGATION, GROUP: INVESTIGATION, DEFAULT_SA: INVESTIGATION,
                           DELETED: INVESTIGATION, OTHER_PRINCIPAL: INVESTIGATION}
PRIMITIVE_ROLES_ALL_CLEAR = ("No user, group or service account holds Owner or Editor on a project, and no project grants a role to "
                             "the public (Google-managed service agents, which hold Editor by design, are not counted).")


def primitive_role_fix(project_id, member, role, binding, kind):
    """The ``gcloud`` line that removes a project's basic-role grant, with what to do instead."""
    line = f"gcloud projects remove-iam-policy-binding {project_id} --member={member} --role={role}{condition_flag(binding)}"
    if kind == DEFAULT_SA:
        return f"{line}  # and enforce iam.automaticIamGrantsForDefaultServiceAccounts so new projects stop granting it"
    if kind == PUBLIC:
        return line
    return f"{line}  # grant a predefined role for the work first (the IAM Least Privilege rows name one when the recommender has it)"


def primitive_role_rows(project_id, policy, org_domains=()):
    """The rows of a project's IAM policy: every Owner or Editor holder that is not a Google-managed agent, and every public
    principal on any role; each with its kind, condition, fix and ``_status`` (``PRIMITIVE_HOLDER_STATUS``)."""
    rows = []
    for binding in policy.get("bindings", []):
        role = binding.get("role")
        for member in binding.get("members", []):
            kind = principal_kind(member, org_domains)
            if kind == GOOGLE_MANAGED or (role not in PRIMITIVE_ROLES and kind != PUBLIC):
                continue
            rows.append({"Project": project_id, "Principal": member, "Type": kind, "Role": role, "Condition": condition_text(binding),
                         "Fix": primitive_role_fix(project_id, member, role, binding, kind), "_status": PRIMITIVE_HOLDER_STATUS[kind]})
    return rows


def check_project_iam_policy(scope_id, projects, job_id, *, sink):
    """
    Scans all projects for the use of primitive roles (Owner/Editor).

    v18: the policy is read with version 3 (conditional bindings shown), Google-managed service
    agents are left out (the Google APIs service agent is Editor in every project, so no real
    organization could pass), and the verdict follows the kind of holder: a service account, a
    consumer account, a whole domain or the public is *Action Required*; a person, a group or a
    default service account *Investigation Recommended*. Every row carries its fix.

    Args:
        scope_id (str): The scope ID.
        projects (list): A list of project dictionaries.
    """
    print(f"🕵️  [{job_id}] Checking for {PRIMITIVE_ROLES_CHECK} in parallel...")
    if not projects:
        result = {"Check": PRIMITIVE_ROLES_CHECK, "Finding": [{"Error": "Could not list projects."}], "Status": "Error"}
        sink.write_finding(job_id, PRIMITIVE_ROLES_CHECK.replace(" ", "_"), result)
        return
    skipped = NotChecked(PRIMITIVE_ROLES_CHECK)
    credentials, _ = gcp.auth_default(scopes=SCOPES)
    service = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
    org_domains = organization_domains(service, projects[0]['projectId'])

    all_findings = []
    for project in projects:
        project_id = project['projectId']
        try:
            policy = service.projects().getIamPolicy(resource=project_id, body={"options": {"requestedPolicyVersion": 3}}).execute()
            all_findings.extend(primitive_role_rows(project_id, policy, org_domains))
        except Exception as e:
            skipped.add(project_id, e)

    sink.write_finding(job_id, PRIMITIVE_ROLES_CHECK.replace(" ", "_"), result_record(PRIMITIVE_ROLES_CHECK, all_findings, PRIMITIVE_ROLES_ALL_CLEAR))
    skipped.write(sink, job_id)


# Service Account Key Rotation (v18): user-managed keys that can still authenticate and are older than the rotation period.
SA_KEYS_CHECK = "Service Account Key Rotation"
KEY_MAX_AGE_DAYS = 90
KEY_NEVER_EXPIRES = "9999-12-31"
SA_KEYS_ALL_CLEAR = (f"No user-managed service account key that can still authenticate is older than {KEY_MAX_AGE_DAYS} days "
                     "(disabled and expired keys are not counted; delete them).")


def _parse_time(text):
    try:
        return datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None


def stale_key_row(project_id, account, key, now=None):
    """The row of a user-managed key older than ``KEY_MAX_AGE_DAYS`` that can still authenticate, or ``None``.

    A disabled key, an expired one (``validBeforeTime`` passed) and a key of a disabled account cannot
    authenticate: rotating them changes nothing, deleting them is housekeeping — they are not rows.
    """
    now = now or datetime.now(timezone.utc)
    created = _parse_time(key.get('validAfterTime'))
    expires = _parse_time(key.get('validBeforeTime'))
    if created is None or key.get('disabled') or account.get('disabled') or (expires is not None and expires <= now):
        return None
    age = (now - created).days
    if age <= KEY_MAX_AGE_DAYS:
        return None
    email = account.get('email') or str(account.get('name', '')).rsplit('/', 1)[-1]
    key_id = str(key.get('name', '')).rsplit('/', 1)[-1]
    uploaded = key.get('keyOrigin') == 'USER_PROVIDED'
    return {"Project": project_id, "Service Account": email, "Key ID": key_id, "Created": created.strftime('%Y-%m-%d'), "Age (days)": age,
            "Expires": "never" if expires is None or expires.strftime('%Y-%m-%d') >= KEY_NEVER_EXPIRES else expires.strftime('%Y-%m-%d'),
            "Origin": "uploaded" if uploaded else "created in Google Cloud",
            "Fix": (f"gcloud iam service-accounts keys disable {key_id} --iam-account={email} --project={project_id}  # then delete it once nothing breaks"
                    + ("; an uploaded key is rotated at its source" if uploaded else "")),
            "_status": ACTION_REQUIRED}


def check_sa_key_rotation(scope_id, all_projects, job_id, *, sink):
    """
    Scans every project's user-managed service account keys for keys older than 90 days.

    v18: disabled and expired keys, and the keys of disabled accounts, are no longer rows (they
    cannot authenticate); each row names the key, its age, expiry and origin, and carries the
    ``gcloud`` line that disables it; a project whose keys could not be listed is under
    *Projects not checked* instead of turning the check Action Required with an error row.
    """
    print(f"🔑 [{job_id}] Checking for {SA_KEYS_CHECK}...")
    skipped = NotChecked(SA_KEYS_CHECK)
    all_findings = []
    for project in all_projects:
        project_id = project['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            iam_service = gcp.api_build('iam', 'v1', credentials=credentials)
            accounts, request = [], iam_service.projects().serviceAccounts().list(name=f'projects/{project_id}')
            while request:
                response = request.execute()
                accounts.extend(response.get('accounts', []))
                request = iam_service.projects().serviceAccounts().list_next(previous_request=request, previous_response=response)
            for account in accounts:
                keys = iam_service.projects().serviceAccounts().keys().list(name=account['name'], keyTypes=['USER_MANAGED']).execute().get('keys', [])
                all_findings.extend(row for row in (stale_key_row(project_id, account, key) for key in keys) if row)
        except Exception as e:
            skipped.add(project_id, e)
    sink.write_finding(job_id, SA_KEYS_CHECK.replace(" ", "_"), result_record(SA_KEYS_CHECK, all_findings, SA_KEYS_ALL_CLEAR))
    skipped.write(sink, job_id)


# Public GCS Buckets (v18): public bindings, read together with Public Access Prevention, which makes them dormant.
PUBLIC_BUCKETS_CHECK = "Public GCS Buckets"
PAP_CONSTRAINT = "constraints/storage.publicAccessPrevention"
PUBLIC_BUCKETS_ALL_CLEAR = "No bucket grants a role to allUsers or allAuthenticatedUsers."


def public_access_prevention(bucket):
    """A bucket's Public Access Prevention setting: ``"enforced"``, ``"inherited"`` or ``""`` when the client does not report it."""
    configuration = getattr(bucket, "iam_configuration", None)
    return str(getattr(configuration, "public_access_prevention", "") or "").lower()


def public_bucket_rows(project_id, bucket_name, bindings, pap, org_enforced=False):
    """The rows of one bucket's public bindings: one per public principal, with the roles it holds and whether Public
    Access Prevention blocks them (bucket-enforced, or inherited from an enforced organization policy).

    A binding PAP blocks is dormant — *Investigation Recommended*, remove it; one it does not block is *Action Required*.
    """
    by_principal = {}
    for binding in bindings:
        members, role = binding.get("members", []), binding.get("role")
        for member in PUBLIC_PRINCIPALS:
            if member in members:
                by_principal.setdefault(member, []).append(role)
    if not by_principal:
        return []
    blocked = pap == "enforced" or (pap == "inherited" and org_enforced)
    prevention = "enforced (bucket)" if pap == "enforced" else "enforced (organization policy)" if blocked else "not enforced"
    rows = []
    for member, roles in by_principal.items():
        fix = " && ".join(f"gcloud storage buckets remove-iam-policy-binding gs://{bucket_name} --member={member} --role={role}" for role in sorted(roles))
        if not blocked:
            fix += f" && gcloud storage buckets update gs://{bucket_name} --public-access-prevention"
        rows.append({"Project": project_id, "Bucket": bucket_name, "Principal": member, "Role": ", ".join(sorted(roles)),
                     "Public access prevention": prevention, "Fix": fix, "_status": INVESTIGATION if blocked else ACTION_REQUIRED})
    return rows


def check_public_buckets(scope_id, all_projects, job_id, *, sink):
    """
    Scans all projects for Cloud Storage buckets whose IAM policy grants a role to the public.

    v18: a bucket whose Public Access Prevention is enforced — on the bucket, or through the
    ``storage.publicAccessPrevention`` organization policy the bucket inherits — is not public
    whatever its bindings say; its row is *Investigation Recommended* (remove the dormant binding).
    The organization policy is read once per project, and only for projects with such a bucket.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
    """
    print(f"🪣 [{job_id}] Checking for {PUBLIC_BUCKETS_CHECK}...")
    skipped = NotChecked(PUBLIC_BUCKETS_CHECK)

    def org_policy_enforced(project_id):
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            crm = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
            policy = crm.projects().getEffectiveOrgPolicy(resource=f"projects/{project_id}", body={"constraint": PAP_CONSTRAINT}).execute()
            return bool((policy.get("booleanPolicy") or {}).get("enforced"))
        except Exception as e:
            logging.warning(f"Could not read the effective {PAP_CONSTRAINT} of {project_id}; treating it as not enforced: {e}")
            return False

    def check_project(p):
        project_id, public = p['projectId'], []  # (bucket name, bindings, PAP setting) of the buckets with a public binding
        try:
            storage_client_local = gcp.project_storage_client(project_id)
            for bucket in storage_client_local.list_buckets():
                policy = bucket.get_iam_policy(requested_policy_version=3)
                if public_bucket_rows(project_id, bucket.name, policy.bindings, ""):
                    public.append((bucket.name, policy.bindings, public_access_prevention(bucket)))
        except Exception as e:
            skipped.add(project_id, e)  # API disabled or permissions lacking: reported, not silently dropped
            return []
        # The organization policy matters only for a public bucket that does not enforce PAP itself: one read per project.
        org_enforced = any(pap != "enforced" for _, _, pap in public) and org_policy_enforced(project_id)
        return [row for name, bindings, pap in public for row in public_bucket_rows(project_id, name, bindings, pap, org_enforced)]

    all_findings = []
    for project in all_projects:
        all_findings.extend(check_project(project))
    sink.write_finding(job_id, PUBLIC_BUCKETS_CHECK.replace(" ", "_"), result_record(PUBLIC_BUCKETS_CHECK, all_findings, PUBLIC_BUCKETS_ALL_CLEAR))
    skipped.write(sink, job_id)


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


# Open Firewall Rules (v18): ingress allow rules from the internet, by what they open. Ports with their own
# Security Health Analytics detector (SSH, RDP, databases, caches, directory services, ...) and any range or
# whole protocol are Action Required; a rule that opens only the web ports or ICMP is a tier that may be meant
# to face the internet: Investigation Recommended.
FIREWALL_CHECK = "Open Firewall Rules"
INTERNET_RANGES = ("0.0.0.0/0", "::/0")
IAP_RANGE = "35.235.240.0/20"  # Identity-Aware Proxy TCP forwarding: the source range SSH and RDP rules should allow instead
SENSITIVE_PORTS = frozenset({21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 389, 445, 636, 1433, 1434, 1521, 2049, 2375, 2376,
                             3306, 3389, 5432, 5900, 5901, 6379, 7000, 7001, 8086, 9042, 9092, 9200, 9300, 10250, 11211, 27017, 27018})
WEB_PORTS = frozenset({80, 443, 8080, 8443})
FIREWALL_ALL_CLEAR = "No enabled ingress rule allows traffic from the internet (0.0.0.0/0 or ::/0)."


def rule_protocols(rule):
    """``"tcp:22, udp:53, icmp"`` — what an allow rule opens, from its ``allowed`` entries."""
    parts = []
    for entry in rule.get("allowed", []):
        protocol = str(entry.get("IPProtocol", "")).lower()
        ports = entry.get("ports") or []
        parts.append(f"{protocol}:{','.join(ports)}" if ports else protocol)
    return ", ".join(parts)


def _port_numbers(ports):
    """The port numbers of ``["22", "8080-8081"]`` → ``[22, 8080, 8081]`` (a malformed entry counts as nothing)."""
    numbers = []
    for port in ports:
        text = str(port)
        try:
            if "-" in text:
                low, high = text.split("-", 1)
                numbers.extend(range(int(low), int(high) + 1))
            else:
                numbers.append(int(text))
        except ValueError:
            pass
    return numbers


def open_rule_status(rule):
    """``ACTION_REQUIRED`` or ``INVESTIGATION`` for an ingress allow rule open to the internet, by what it opens.

    Investigation only when every entry is ICMP or web ports (``WEB_PORTS``) over TCP or UDP; a whole protocol,
    a port range beyond them, a sensitive port or any other protocol is Action Required.
    """
    for entry in rule.get("allowed", []):
        protocol = str(entry.get("IPProtocol", "")).lower()
        if protocol == "icmp":
            continue
        if protocol not in ("tcp", "udp"):
            return ACTION_REQUIRED  # all protocols, sctp, esp, ah, gre, a protocol number
        numbers = _port_numbers(entry.get("ports") or [])
        if not numbers or any(n in SENSITIVE_PORTS for n in numbers) or not all(n in WEB_PORTS for n in numbers):
            return ACTION_REQUIRED
    return INVESTIGATION


def firewall_targets(rule):
    """Whom a rule applies to: its target tags or service accounts, or every instance in the network."""
    if rule.get("targetTags"):
        return "tags: " + ", ".join(rule["targetTags"])
    if rule.get("targetServiceAccounts"):
        return "service accounts: " + ", ".join(rule["targetServiceAccounts"])
    return "all instances in the network"


def firewall_fix(project_id, rule):
    """The ``gcloud`` line that closes an open rule: the IAP range for SSH/RDP-only rules, the reader's CIDRs otherwise."""
    name = rule.get("name")
    entries = rule.get("allowed", [])
    numbers = [n for entry in entries for n in _port_numbers(entry.get("ports") or [])]
    only_remote_access = bool(numbers) and all(n in (22, 3389) for n in numbers) and all(
        str(entry.get("IPProtocol", "")).lower() in ("tcp", "udp") and entry.get("ports") for entry in entries)
    if only_remote_access:
        return f"gcloud compute firewall-rules update {name} --project={project_id} --source-ranges={IAP_RANGE}  # Identity-Aware Proxy TCP forwarding instead of the internet"
    if open_rule_status(rule) == INVESTIGATION:
        return (f"gcloud compute firewall-rules update {name} --project={project_id} --source-ranges=<your CIDRs>  "
                "# or front the tier with a load balancer and Cloud Armor and allow the load balancer ranges only")
    return (f"gcloud compute firewall-rules update {name} --project={project_id} --source-ranges=<your CIDRs>  "
            f"# or: gcloud compute firewall-rules delete {name} --project={project_id}")


def open_firewall_rows(project_id, rules):
    """The rows of a project's VPC firewall rules that are enabled, ingress, *allow*, and open to the internet.

    A deny rule from ``0.0.0.0/0`` is the hardening pattern, not a finding; an egress rule's source ranges mean nothing.
    """
    rows = []
    for rule in rules:
        if rule.get("disabled") or str(rule.get("direction", "INGRESS")).upper() != "INGRESS" or not rule.get("allowed"):
            continue
        open_ranges = [r for r in rule.get("sourceRanges", []) if r in INTERNET_RANGES]
        if not open_ranges:
            continue
        rows.append({"Project": project_id, "Rule": rule.get("name"), "VPC": str(rule.get("network", "")).split("/")[-1],
                     "Protocols/Ports": rule_protocols(rule), "Source Ranges": ", ".join(rule.get("sourceRanges", [])),
                     "Targets": firewall_targets(rule), "Priority": rule.get("priority", 1000),
                     "Fix": firewall_fix(project_id, rule), "_status": open_rule_status(rule)})
    return rows


def check_open_firewall_rules(scope_id, all_projects, job_id, *, sink):
    """
    Scans all projects for VPC firewall rules open to the internet.

    v18: only enabled *ingress allow* rules from ``0.0.0.0/0`` or ``::/0`` are findings (deny rules
    were counted before, IPv6 was not), every page of rules is read, the row shows what the rule
    opens and to whom, the verdict depends on the ports (``open_rule_status``), and the fix is the
    IAP range for SSH/RDP rules. Firewall policies (hierarchical and network) are a later release.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
    """
    print(f"🔥 [{job_id}] Checking for {FIREWALL_CHECK} in parallel...")
    skipped = NotChecked(FIREWALL_CHECK, resource_apis=("compute.googleapis.com",))

    def check_project(p):
        project_id = p['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            rules, request = [], compute.firewalls().list(project=project_id)
            while request:
                response = request.execute()
                rules.extend(response.get('items', []))
                request = compute.firewalls().list_next(previous_request=request, previous_response=response)
            return open_firewall_rows(project_id, rules)
        except Exception as e:
            skipped.add(project_id, e)
            return []

    all_findings = []
    for project in all_projects:
        all_findings.extend(check_project(project))
    sink.write_finding(job_id, "Open_Firewall_Rules", result_record(FIREWALL_CHECK, all_findings, FIREWALL_ALL_CLEAR))
    skipped.write(sink, job_id)


# --- Checks added in upstream beta v1 ---
# Ported from the upstream beta branch (cloudgauge_beta_v1.py) with the same
# mechanical changes as the checks above; v18 revalidated Cloud SQL Security and VM External IPs.

# Cloud SQL Security (v18): TLS by ``sslMode`` (the field that replaced ``requireSsl``), the authorized networks, the public IP.
SQL_CHECK = "Cloud SQL Security"
SQL_TLS_OPEN = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
SQL_ALL_CLEAR = "Every Cloud SQL instance enforces TLS, has no public IP, and authorizes no internet range."


def cloud_sql_rows(project_id, instance):
    """The rows of one Cloud SQL instance: *TLS not enforced* (Action Required), *Open to the internet* (an authorized
    network of ``0.0.0.0/0`` or ``::/0``; Action Required), *Public IP* (Investigation Recommended: exposure, not a hole).

    ``sslMode`` decides TLS; ``requireSsl`` only when ``sslMode`` is absent. ``ENCRYPTED_ONLY`` — the recommended
    mode — passes (it reads as ``requireSsl: false``, which the legacy rule flagged). An instance without
    ``settings`` (one the API reports mid-operation) has no rows.
    """
    settings = instance.get("settings")
    if not settings:
        return []
    ip = settings.get("ipConfiguration") or {}
    name, version = instance.get("name"), instance.get("databaseVersion", "")
    replica = instance.get("instanceType") == "READ_REPLICA_INSTANCE"
    kind = "replica" if replica else "primary"
    target = instance.get("masterInstanceName", "").split(":")[-1] if replica and instance.get("masterInstanceName") else name
    patch = f"gcloud sql instances patch {target} --project={project_id}"
    rows = []
    ssl_mode = ip.get("sslMode")
    if (ssl_mode == SQL_TLS_OPEN) if ssl_mode else (ip.get("requireSsl") is not True):
        rows.append({"Issue": "TLS not enforced: unencrypted connections are accepted.", "Fix": f"{patch} --ssl-mode=ENCRYPTED_ONLY", "_status": ACTION_REQUIRED})
    open_ranges = [n.get("value") for n in ip.get("authorizedNetworks", []) if n.get("value") in INTERNET_RANGES]
    if ip.get("ipv4Enabled") and open_ranges:
        rows.append({"Issue": f"Open to the internet: authorized network {', '.join(open_ranges)} on a public IP.",
                     "Fix": f"{patch} --clear-authorized-networks  # then --authorized-networks=<your CIDRs>, or private IP / Private Service Connect", "_status": ACTION_REQUIRED})
    elif ip.get("ipv4Enabled"):
        rows.append({"Issue": "Public IP enabled.", "Fix": f"{patch} --no-assign-ip  # after private IP (--network=projects/{project_id}/global/networks/<vpc>) or Private Service Connect is set up",
                     "_status": INVESTIGATION})
    if replica:
        for row in rows:
            row["Fix"] += "  # a replica's settings follow its primary"
    return [{"Project": project_id, "Instance": name, "Kind": kind, "Version": version, **row} for row in rows]


def check_cloud_sql_security(scope_id, all_projects, job_id, *, sink):
    """
    Checks Cloud SQL instances for TLS enforcement, internet-wide authorized networks and public IPs.

    v18: ``sqladmin v1``, every page; the rules of ``cloud_sql_rows``.

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
        job_id (str): The job ID.
    """
    print(f"🛡️  [{job_id}] Checking {SQL_CHECK}...")
    skipped = NotChecked(SQL_CHECK, resource_apis=("sqladmin.googleapis.com",))

    def check_project(p):
        project_id = p['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            service = gcp.api_build('sqladmin', 'v1', credentials=credentials)
            instances, request = [], service.instances().list(project=project_id)
            while request:
                response = request.execute()
                instances.extend(response.get('items', []))
                request = service.instances().list_next(previous_request=request, previous_response=response)
            return [row for instance in instances for row in cloud_sql_rows(project_id, instance)]
        except Exception as e:
            skipped.add(project_id, e)
            return []

    all_findings = []
    for project in all_projects:
        all_findings.extend(check_project(project))
    sink.write_finding(job_id, SQL_CHECK.replace(" ", "_"), result_record(SQL_CHECK, all_findings, SQL_ALL_CLEAR))
    skipped.write(sink, job_id)


# VPC Configuration (v18.1): the default network, and subnets without Private Google Access where it applies.
VPC_CHECK = "VPC Configuration"
# Subnet purposes that carry no VM: proxy-only subnets of load balancers, Private Service Connect, Private NAT, peer migration.
PGA_EXEMPT_PURPOSES = frozenset({"REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER", "PRIVATE_SERVICE_CONNECT",
                                 "PRIVATE_NAT", "PEER_MIGRATION"})
IPV6_PGA_VALUES = ("ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE", "ENABLE_BIDIRECTIONAL_ACCESS_TO_GOOGLE")
# The subnet GKE creates for a cluster's private control-plane endpoint (``gke-<cluster>-<hash>-pe-subnet``, purpose PRIVATE,
# no PGA): Google's, carries no VM, cannot usefully be changed — never a row. Seen on the v18.1 probe cluster.
GKE_ENDPOINT_SUBNET_DESCRIPTION = "Control Plane Endpoint Subnetwork"
VPC_ALL_CLEAR = "No default VPC network, and every subnet that can have Private Google Access has it."


def subnet_has_private_google_access(subnet):
    """Whether a subnet's VMs reach Google APIs privately: ``privateIpGoogleAccess`` (IPv4), ``privateIpv6GoogleAccess`` for IPv6-only subnets."""
    if str(subnet.get("stackType", "IPV4_ONLY")).upper() == "IPV6_ONLY":
        return str(subnet.get("privateIpv6GoogleAccess", "")).upper() in IPV6_PGA_VALUES
    return bool(subnet.get("privateIpGoogleAccess", False))


def subnet_is_exempt(subnet):
    """A subnet that is never judged for Private Google Access: a ``PGA_EXEMPT_PURPOSES`` purpose, or GKE's control-plane endpoint subnet."""
    purpose = str(subnet.get("purpose") or "PRIVATE").upper()
    name = str(subnet.get("name") or "")
    return (purpose in PGA_EXEMPT_PURPOSES or subnet.get("description") == GKE_ENDPOINT_SUBNET_DESCRIPTION
            or (name.startswith("gke-") and name.endswith("-pe-subnet")))


def vpc_rows(project_id, networks, subnets):
    """The rows of a project's networks and subnets.

    The ``default`` network is **Action Required** (one row; its auto-mode subnets without Private Google Access are
    counted into it rather than listed); any other subnet without Private Google Access is **Investigation Recommended**
    with its region and fix; subnets of ``PGA_EXEMPT_PURPOSES`` (proxy-only, PSC, NAT) and GKE's control-plane endpoint
    subnets are not judged (``subnet_is_exempt``).
    """
    default_networks = {str(n.get("selfLink") or n.get("name")).rsplit("/", 1)[-1] for n in networks if n.get("name") == "default"}
    rows, folded = [], 0
    for subnet in subnets:
        if subnet_is_exempt(subnet) or subnet_has_private_google_access(subnet):
            continue
        network = str(subnet.get("network", "")).rsplit("/", 1)[-1]
        if network in default_networks:
            folded += 1
            continue
        region = str(subnet.get("region", "")).rsplit("/", 1)[-1]
        rows.append({"Project": project_id, "Network / Subnet": f"{network} / {subnet.get('name')}", "Region": region,
                     "Issue": "Private Google Access disabled.",
                     "Fix": f"gcloud compute networks subnets update {subnet.get('name')} --region={region} --project={project_id} --enable-private-ip-google-access",
                     "_status": INVESTIGATION})
    for network in sorted(default_networks):
        issue = "Default VPC network exists."
        if folded:
            issue += f" {folded} of its auto-mode subnets lack Private Google Access (counted here, not listed)."
        rows.insert(0, {"Project": project_id, "Network / Subnet": f"{network} (network)", "Region": "global", "Issue": issue,
                        "Fix": f"gcloud compute networks delete {network} --project={project_id}  # after moving its workloads and deleting its firewall rules",
                        "_status": ACTION_REQUIRED})
    return rows


def check_vpc_configuration(scope_id, all_projects, job_id, *, sink):
    """
    Checks for 'default' VPC usage and subnets without Private Google Access.

    v18.1: one ``subnetworks.aggregatedList`` per project instead of one listing per region; proxy-only
    and PSC subnets are no longer flagged (they cannot have PGA); the default network's auto-subnets
    fold into its row; a PGA row is Investigation Recommended with its region and fix (``vpc_rows``).

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
        job_id (str): The job ID.
    """
    print(f"🕸️  [{job_id}] Checking {VPC_CHECK}...")
    skipped = NotChecked(VPC_CHECK, resource_apis=("compute.googleapis.com",))

    def check_project(p):
        project_id = p['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            networks, request = [], compute.networks().list(project=project_id)
            while request:
                response = request.execute()
                networks.extend(response.get('items', []))
                request = compute.networks().list_next(previous_request=request, previous_response=response)
            subnets, request = [], compute.subnetworks().aggregatedList(project=project_id)
            while request:
                response = request.execute()
                for scoped in response.get('items', {}).values():
                    subnets.extend(scoped.get('subnetworks', []))
                request = compute.subnetworks().aggregatedList_next(previous_request=request, previous_response=response)
            return vpc_rows(project_id, networks, subnets)
        except Exception as e:
            skipped.add(project_id, e)
            return []

    all_findings = []
    for project in all_projects:
        all_findings.extend(check_project(project))
    sink.write_finding(job_id, VPC_CHECK.replace(" ", "_"), result_record(VPC_CHECK, all_findings, VPC_ALL_CLEAR))
    skipped.write(sink, job_id)


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
    skipped = NotChecked(CHECK_NAME)

    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            storage_client_local = gcp.project_storage_client(project_id)
            for bucket in storage_client_local.list_buckets():
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    findings.append({"Project": project_id, "Bucket": bucket.name, "Issue": "UBLA not enabled.",
                                     "Fix": f"gcloud storage buckets update gs://{bucket.name} --uniform-bucket-level-access"})  # v18.1
        except Exception as e:
            skipped.add(project_id, e)
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
    skipped.write(sink, job_id)


# VM External IPs (v18): instances that hold an external address — IPv4 (``natIP``) or IPv6 — by kind of instance.
EXTERNAL_IPS_CHECK = "VM External IPs"
GKE_NODE, MIG_MEMBER, STANDALONE_VM = "GKE node", "MIG member", "standalone"
EXTERNAL_IPS_ALL_CLEAR = "No VM instance holds an external IP address."


def instance_metadata(instance):
    """An instance's metadata items as a dict."""
    return {item.get("key"): item.get("value", "") for item in (instance.get("metadata") or {}).get("items", []) if item.get("key")}


def instance_kind(instance):
    """``GKE node`` (a ``gke-``/``gk3-`` instance or one with GKE's ``cluster-name`` metadata), ``MIG member`` (``created-by``), else ``standalone``."""
    name, metadata = str(instance.get("name", "")), instance_metadata(instance)
    if name.startswith(("gke-", "gk3-")) or "cluster-name" in metadata or "/gke-" in str(metadata.get("created-by", "")):
        return GKE_NODE
    if metadata.get("created-by"):
        return MIG_MEMBER
    return STANDALONE_VM


def external_addresses(instance):
    """``[(interface name, access config name, address)]`` of an instance's external IPv4 and IPv6 addresses."""
    found = []
    for interface in instance.get("networkInterfaces", []):
        nic = interface.get("name", "nic0")
        for config in interface.get("accessConfigs", []) or []:
            if config.get("natIP"):
                found.append((nic, config.get("name", "External NAT"), config["natIP"]))
        for config in interface.get("ipv6AccessConfigs", []) or []:
            if config.get("externalIpv6"):
                found.append((nic, config.get("name", "External IPv6"), config["externalIpv6"]))
    return found


def external_ip_fix(project_id, instance, zone, kind, addresses):
    """The line that removes an instance's external addresses, by kind: the access config, the template, the node pool."""
    name, metadata = instance.get("name"), instance_metadata(instance)
    if kind == GKE_NODE:
        cluster, location = metadata.get("cluster-name", "<cluster>"), metadata.get("cluster-location", "<location>")
        return (f"gcloud container node-pools create <pool> --cluster={cluster} --location={location} --project={project_id} --enable-private-nodes  "
                "# then drain and delete this node's pool: an existing pool's nodes cannot lose their external IPs")
    if kind == MIG_MEMBER:
        return ("Create an instance template without an external IP and roll it out: gcloud compute instance-groups managed rolling-action start-update "
                f"{str(metadata.get('created-by', '')).rsplit('/', 1)[-1] or '<group>'} --version=template=<template> --zone={zone} --project={project_id}")
    lines = []
    for nic, config_name, address in addresses:
        if ":" in address:  # IPv6
            lines.append(f"gcloud compute instances network-interfaces update {name} --zone={zone} --project={project_id} --network-interface={nic} --stack-type=IPV4_ONLY")
        else:
            lines.append(f"gcloud compute instances delete-access-config {name} --zone={zone} --project={project_id} --network-interface={nic} --access-config-name=\"{config_name}\"")
    return " && ".join(dict.fromkeys(lines))


def external_ip_rows(project_id, instances):
    """One row per instance that holds an external address: its zone, status, addresses, kind and fix.

    A stopped instance whose ephemeral address was released has no ``natIP`` and no row; one holding a static
    address keeps it, and the row. GKE nodes are *Investigation Recommended* (the fix is the node pool's, and the
    cluster's exposure has its own checks); other instances *Action Required*.
    """
    rows = []
    for instance in instances:
        addresses = external_addresses(instance)
        if not addresses:
            continue
        zone, kind = str(instance.get("zone", "")).rsplit("/", 1)[-1], instance_kind(instance)
        rows.append({"Project": project_id, "VM": instance.get("name"), "Zone": zone, "Status": instance.get("status", ""),
                     "External IPs": ", ".join(address for _, _, address in addresses), "Kind": kind,
                     "Fix": external_ip_fix(project_id, instance, zone, kind, addresses),
                     "_status": INVESTIGATION if kind == GKE_NODE else ACTION_REQUIRED})
    return rows


def check_vm_external_ips(scope_id, all_projects, job_id, *, sink):
    """
    Checks for VM instances with external IP addresses.

    v18: an instance is a row when it *holds* an address (``natIP`` or ``externalIpv6``), not when it
    has an access config — a stopped instance's released ephemeral address no longer counts; one row
    per instance with its zone, status, addresses, kind and fix (``external_ip_rows``).

    Args:
        scope_id (str): The scope ID.
        all_projects (list): A list of project dictionaries.
        job_id (str): The job ID.
    """
    print(f"🖥️  [{job_id}] Checking {EXTERNAL_IPS_CHECK}...")
    skipped = NotChecked(EXTERNAL_IPS_CHECK, resource_apis=("compute.googleapis.com",))

    def check_project(p):
        project_id, instances = p['projectId'], []
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            request = compute.instances().aggregatedList(project=project_id)
            while request:
                response = request.execute()
                for scoped in response.get('items', {}).values():
                    instances.extend(scoped.get('instances', []))
                request = compute.instances().aggregatedList_next(previous_request=request, previous_response=response)
            return external_ip_rows(project_id, instances)
        except Exception as e:
            skipped.add(project_id, e)
            return []

    all_findings = []
    for project in all_projects:
        all_findings.extend(check_project(project))
    sink.write_finding(job_id, EXTERNAL_IPS_CHECK.replace(" ", "_"), result_record(EXTERNAL_IPS_CHECK, all_findings, EXTERNAL_IPS_ALL_CLEAR))
    skipped.write(sink, job_id)


# --- IAM Least Privilege (v17) ------------------------------------------------------------------------------------
IAM_CHECK = "IAM Least Privilege"
IAM_RECOMMENDER = "google.iam.policy.Recommender"
ROLE_FILTER, MEMBER_FILTER = "/iamPolicy/bindings/*/role", "/iamPolicy/bindings/*/members/*"


def recommendation_dict(reco):
    """A recommendation as a plain dict (``Recommendation.to_dict`` for the proto the client returns; a dict as it is)."""
    if isinstance(reco, dict):
        return reco
    try:
        return type(reco).to_dict(reco)
    except Exception:
        return {"name": getattr(reco, "name", ""), "description": getattr(reco, "description", ""),
                "recommender_subtype": getattr(reco, "recommender_subtype", ""), "content": {}}


def iam_operations(reco):
    """``(removed, added)`` of an IAM recommendation: ``[(role, member)]`` bindings to remove, ``[(role, member)]`` to add.

    The recommender's operation groups carry a ``remove`` of a member from a binding (the role and
    the member in ``path_filters``) and, for a replacement, an ``add`` of that member to another
    role (the role in ``path_filters``, the member as ``value``).
    """
    removed, added = [], []
    for group in (reco.get("content") or {}).get("operation_groups") or []:
        for operation in group.get("operations") or []:
            filters = operation.get("path_filters") or {}
            role, member = filters.get(ROLE_FILTER, ""), filters.get(MEMBER_FILTER) or operation.get("value") or ""
            if operation.get("action") == "remove" and role:
                removed.append((role, member))
            elif operation.get("action") == "add" and role:
                added.append((role, member))
    return removed, added


def iam_fix(resource, removed, added):
    """The ``gcloud`` lines that apply an IAM recommendation on ``resource`` (``projects/p``, ``folders/f``, ``organizations/o``)."""
    kind, name = resource.split("/", 1)
    verb = {"projects": "projects", "folders": "resource-manager folders", "organizations": "organizations"}.get(kind, kind)
    lines = [f"gcloud {verb} add-iam-policy-binding {name} --member={member} --role={role}" for role, member in added if member]
    lines += [f"gcloud {verb} remove-iam-policy-binding {name} --member={member} --role={role}" for role, member in removed if member]
    return " && ".join(lines)


def iam_rows(resource, recommendations):
    """The rows of the IAM recommendations of one resource: the project (or the organization or folder itself), the
    principal, the role it holds, what to do, and the fix."""
    project = resource.split("/", 1)[1] if resource.startswith("projects/") else resource
    rows = []
    for reco in recommendations:
        reco = recommendation_dict(reco)
        removed, added = iam_operations(reco)
        members = sorted({member for _, member in removed if member} or {member for _, member in added if member})
        subtype = str(reco.get("recommender_subtype") or "").replace("_", " ").capitalize()
        for member in members or [""]:
            rows.append({"Project": project, "Principal": member,
                         "Current Role": ", ".join(sorted({role for role, m in removed if m in (member, "")})),
                         "Recommended Role": ", ".join(sorted({role for role, m in added if m in (member, "")})) or "none (remove)",
                         "Recommendation": reco.get("description") or subtype,
                         "Fix": iam_fix(resource, [(r, m) for r, m in removed if m in (member, "")], [(r, m) for r, m in added if m in (member, "")])})
    return rows


def check_iam_recommendations(scope, scope_id, all_projects, job_id, *, sink, scope_level=True, project_level=True):
    """Principals whose roles grant permissions they have not used (v17): the IAM recommender's recommendations.

    Asked at ``global`` for the scanned organization or folder itself and for every project in
    scope. One row per principal and recommendation — the project (or the organization or folder,
    by its resource name), the role held, the role recommended (or *none (remove)*), the
    recommender's own words, and the ``gcloud`` lines that apply it;
    *Action Required*: an unused ``roles/editor`` is the standing risk IAM audits look for.
    Compliant with an all-clear row when nobody holds an unused role; a project whose
    recommendations could not be read is under *Projects not checked*.

    Sharded scans split the work like the miscellaneous checks (``app.checks.registry``):
    the scope shard runs it with ``project_level=False``, the project shards with
    ``scope_level=False``; the all-clear rows are identical so the merge keeps one.
    """
    print(f"🔐 [{job_id}] Checking {IAM_CHECK} for {scope} {scope_id} and {len(all_projects)} projects...")
    skipped = NotChecked(IAM_CHECK)
    client = gcp.recommender_client()
    resources = [f"{scope}s/{scope_id}"] if scope_level and scope in ("organization", "folder") else []
    if project_level:
        resources += [f"projects/{p['projectId']}" for p in all_projects]
    rows, answered, first_error = [], 0, None
    for resource in resources:
        parent = f"{resource}/locations/global/recommenders/{IAM_RECOMMENDER}"
        errors = []
        recommendations = call_api_with_backoff(lambda: client.list_recommendations(parent=parent),
                                                context_message=f"'{IAM_CHECK}' for {resource}", on_error=errors.append)
        if errors:
            first_error = first_error or errors[0]
            if not is_request_error(errors[0]):  # the scanned organization or folder is listed by its resource name
                skipped.add(resource.split("/", 1)[1] if resource.startswith("projects/") else resource, errors[0])
            continue
        answered += 1
        rows.extend(iam_rows(resource, recommendations))
    if resources and not answered:
        result = {"Check": IAM_CHECK, "Finding": [{"Error": f"Could not read the IAM recommendations of any resource in scope: {first_error}"}], "Status": "Error"}
    elif rows:
        result = {"Check": IAM_CHECK, "Finding": rows, "Status": "Action Required"}
    else:
        result = {"Check": IAM_CHECK, "Finding": [{"Status": "No principal holds a role the IAM recommender would remove or replace."}], "Status": "Compliant"}
    sink.write_finding(job_id, IAM_CHECK.replace(" ", "_"), result)
    skipped.write(sink, job_id)


# The legacy checks of this module that write through ``result_record`` (v18); each name is a key of CATEGORY_MAP
# (tests/test_category_consistency.py resolves the ``Check`` values of the shared writer from this table).
REVALIDATED_CHECKS = (CRITICAL_ROLES_CHECK, PUBLIC_ORG_CHECK, PRIMITIVE_ROLES_CHECK, SA_KEYS_CHECK, PUBLIC_BUCKETS_CHECK,
                      FIREWALL_CHECK, SQL_CHECK, EXTERNAL_IPS_CHECK, VPC_CHECK)
