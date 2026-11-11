"""
VM hardening & identities, the IAM half (v18.5).

CIS §1 Level-1 items and the matching Security Health Analytics detectors that
the identity checks of v17.1 and v18 do not cover, from one Cloud Asset
Inventory **IAM-policy search** over the organization, folders and projects
under the scope (the search index reflects a change within minutes, where the
``IAM_POLICY`` listing lagged; it names projects by ID), one more search for
public images, and, per project, the IAM recommender's service-account
insights:

- **Service Account Privileges** (Security): a service account holding a
  predefined administrative role (``roles/*.admin``, ``roles/*Admin``) at
  project, folder or organization level — except what *Primitive Roles* and
  *Critical Org-Level Roles* report already — and one principal holding both
  ``iam.serviceAccountAdmin`` and ``iam.serviceAccountUser`` (or Token Creator)
  on one resource (separation of duties).
- **External Principals** (Security): users, groups and domains outside the
  organization's primary domain and ``TRUSTED_DOMAINS``, consumer accounts,
  deleted principals still bound, public principals on folders, public images.
- **Unused Service Accounts** (Security): the recommender's
  ``SERVICE_ACCOUNT_USAGE`` insights (no authentication in Google's 90-day
  window), one row per account.

Google-managed service agents are never rows (``security.principal_kind``).
"""
import logging

from google.cloud import recommender_v1

from app.checks.data_governance import PUBLIC_QUERY, public_policy_rows
from app.checks.gke_operations import ACTION_REQUIRED, INVESTIGATION, write_rows
from app.checks.not_checked import NotChecked
from app.checks.security import (CONSUMER_ACCOUNT, DEFAULT_SA, DELETED, EXTERNAL_USER, GOOGLE_MANAGED, GROUP, ORG_CRITICAL_ROLES, PRIMITIVE_ROLES, PUBLIC,
                                 SERVICE_ACCOUNT, USER, condition_flag, principal_kind)
from app.config import SCOPES, get_settings
from app.services import gcp

SA_PRIVILEGES_CHECK = "Service Account Privileges"
EXTERNAL_CHECK = "External Principals"
UNUSED_SA_CHECK = "Unused Service Accounts"
IDENTITY_CHECKS = (SA_PRIVILEGES_CHECK, EXTERNAL_CHECK, UNUSED_SA_CHECK)

POLICY_TYPES = ["cloudresourcemanager.googleapis.com/Organization", "cloudresourcemanager.googleapis.com/Folder", "cloudresourcemanager.googleapis.com/Project"]
IMAGE_TYPES = ["compute.googleapis.com/Image"]
INSIGHT_TYPE = "google.iam.serviceAccount.Insight"
UNUSED_SUBTYPE = "SERVICE_ACCOUNT_USAGE"
OBSERVATION_DAYS = 90

SA_ADMIN_ROLE, SA_USER_ROLES = "roles/iam.serviceAccountAdmin", ("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator")
# Administrative roles that confer the power to grant more: a service account holding one is a finding on its own.
ESCALATION_ROLES = frozenset({"roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin", "roles/iam.serviceAccountAdmin", "roles/iam.serviceAccountKeyAdmin",
                              "roles/orgpolicy.policyAdmin", "roles/iam.denyAdmin", "roles/iam.organizationRoleAdmin", "roles/resourcemanager.folderAdmin",
                              "roles/resourcemanager.organizationAdmin", "roles/billing.admin"})

SA_PRIVILEGES_ALL_CLEAR = ("No service account holds an administrative role beyond what Primitive Roles and Critical Org-Level Roles report, and nobody both "
                           "administers and uses service accounts on one resource.")
EXTERNAL_ALL_CLEAR = "Every user, group and domain in the IAM policies under the scope belongs to the organization, nothing bound is deleted, and no folder or image is public."
UNUSED_SA_ALL_CLEAR = f"Every service account has authenticated within the recommender's {OBSERVATION_DAYS}-day window."


# --- the policies -----------------------------------------------------------------------------------------------------

def policy_facts(result):
    """``{resource, level, bindings, ancestors}`` of one IAM-policy search result (or listed asset): ``resource`` is ``projects/my-project``
    / ``folders/456`` / ``organizations/789`` (the search names projects by ID), ``bindings`` ``[(role, [members], condition)]``,
    ``ancestors`` the project, folders and organization of the result."""
    name = str(getattr(result, "resource", "") or getattr(result, "name", "") or "")
    parts = name.split("/")
    level = {"Organization": "organization", "Folder": "folder", "Project": "project"}.get(str(getattr(result, "asset_type", "")).rsplit("/", 1)[-1], parts[-2].rstrip("s") if len(parts) > 1 else "")
    policy = getattr(result, "policy", None) or getattr(result, "iam_policy", None)
    bindings = []
    for binding in getattr(policy, "bindings", None) or []:
        condition = getattr(binding, "condition", None)
        text = {"title": getattr(condition, "title", ""), "expression": getattr(condition, "expression", "")} if condition and (getattr(condition, "expression", "") or getattr(condition, "title", "")) else {}
        bindings.append((str(getattr(binding, "role", "") or ""), [str(m) for m in (getattr(binding, "members", None) or [])], text))
    ancestors = [str(a) for a in (getattr(result, "ancestors", None) or [])]
    if not ancestors:  # a search result: its project, folders and organization
        ancestors = [str(getattr(result, "project", "") or "")] + [str(f) for f in (getattr(result, "folders", None) or [])] + [str(getattr(result, "organization", "") or "")]
        ancestors = [a for a in ancestors if a]
    return {"resource": "/".join(parts[-2:]), "level": level, "bindings": bindings, "ancestors": ancestors}


def organization_of(policies, scope, scope_id):
    """``organizations/N`` of the scanned scope: the scope itself, or the last ancestor of any policy asset."""
    if scope == "organization":
        return f"organizations/{scope_id}"
    for policy in policies:
        for ancestor in reversed(policy["ancestors"]):
            if ancestor.startswith("organizations/"):
                return ancestor
    return ""


def remove_binding(resource, member, role, condition):
    """The ``gcloud … remove-iam-policy-binding`` line for a project, folder or organization binding."""
    kind, target = resource.split("/", 1)
    command = {"projects": "gcloud projects", "folders": "gcloud resource-manager folders", "organizations": "gcloud organizations"}.get(kind, "gcloud projects")
    return f"{command} remove-iam-policy-binding {target} --member={member} --role={role}{condition_flag({'condition': condition})}"


def is_admin_role(role):
    """A predefined role whose name says *admin* (``roles/compute.admin``, ``roles/iam.securityAdmin``, ``roles/storage.objectAdmin``); custom roles are not judged."""
    return role.startswith("roles/") and role.rsplit(".", 1)[-1].lower().endswith("admin")


# --- Service Account Privileges -----------------------------------------------------------------------------------------

def admin_role_rows(policies):
    rows = []
    for policy in policies:
        resource = policy["resource"]
        for role, members, condition in policy["bindings"]:
            if not is_admin_role(role) or role in PRIMITIVE_ROLES or (policy["level"] == "organization" and role in ORG_CRITICAL_ROLES):
                continue
            for member in members:
                kind = principal_kind(member)
                if kind not in (SERVICE_ACCOUNT, DEFAULT_SA):
                    continue
                escalation, default = role in ESCALATION_ROLES, kind == DEFAULT_SA
                detail = ("Grants the power to change who may do what" if escalation else "An administrative role on a non-human identity: every workload and key of the account carries it")
                if default:
                    detail += "; the default account is the identity every VM, function and Cloud Run service gets unless told otherwise"
                rows.append({"Resource": resource, "Principal": member, "Type": kind, "Role": role, "Issue": "Administrative role on a service account.",
                             "Detail": f"{detail} (CIS 1.5).", "Fix": remove_binding(policy["resource"], member, role, condition) + "  # grant a role scoped to the work, on the resource it needs",
                             "_status": ACTION_REQUIRED if (escalation or default) else INVESTIGATION})
    return rows


def role_separation_rows(policies):
    rows = []
    for policy in policies:
        held = {}
        for role, members, _ in policy["bindings"]:
            if role == SA_ADMIN_ROLE or role in SA_USER_ROLES:
                for member in members:
                    held.setdefault(member, set()).add(role)
        for member in sorted(held):
            roles = held[member]
            if SA_ADMIN_ROLE in roles and roles & set(SA_USER_ROLES) and principal_kind(member) != GOOGLE_MANAGED:
                using = sorted(roles & set(SA_USER_ROLES))
                rows.append({"Resource": policy["resource"], "Principal": member, "Type": principal_kind(member), "Role": ", ".join([SA_ADMIN_ROLE] + using),
                             "Issue": "Administers and uses service accounts.", "Detail": "One principal can create a service account, grant it roles and then act as it (CIS 1.8: separation of duties).",
                             "Fix": remove_binding(policy["resource"], member, using[0], {}) + "  # or the admin role; keep one", "_status": INVESTIGATION})
    return rows


# --- External Principals ------------------------------------------------------------------------------------------------

def member_domain(member):
    _, _, name = member.partition(":")
    return name.rsplit("@", 1)[-1].lower() if "@" in name else name.lower()


def external_rows(policies, org_domains, trusted=()):
    """One row per (resource, principal) for the principals that are not the organization's; ``org_domains`` empty means the
    external-domain rule cannot be applied (consumer accounts, deleted principals and public folders are still rows)."""
    rows, known = [], tuple(org_domains) + tuple(trusted)
    for policy in policies:
        resource, per_member = policy["resource"], {}
        for role, members, condition in policy["bindings"]:
            for member in members:
                per_member.setdefault(member, []).append((role, condition))
        for member, grants in per_member.items():
            kind = principal_kind(member, org_domains)
            issue, status, detail = None, INVESTIGATION, ""
            if kind == CONSUMER_ACCOUNT:
                issue, status, detail = "Consumer account in the policy.", ACTION_REQUIRED, "A personal Google account: no organization controls, no offboarding (CIS 1.1)."
            elif kind in (USER, EXTERNAL_USER) and known and member_domain(member) not in known:
                issue, detail = "User outside the organization.", f"{member_domain(member)} is not the organization's domain nor a trusted one (CIS 1.1); an acquired company's domain as often as a stranger."
            elif kind == GROUP and known and member_domain(member) not in known:
                issue, detail = "Group outside the organization.", f"{member_domain(member)} is not the organization's domain nor a trusted one; the organization does not manage who is in it."
            elif member.startswith("domain:") and known and member_domain(member) not in known:
                issue, status, detail = "External domain granted.", ACTION_REQUIRED, f"Every account at {member_domain(member)} holds the role."
            elif kind == DELETED:
                issue, detail = "Deleted principal still bound.", "The binding outlives the identity; it is noise in every review and a slot a recreated identity could inherit."
            elif kind == PUBLIC and policy["level"] == "folder":
                issue, status, detail = "Folder open to the public.", ACTION_REQUIRED, "Every project under the folder inherits the grant."
            if issue is None:
                continue
            roles = sorted({role for role, _ in grants})
            rows.append({"Resource": resource, "Principal": member, "Type": kind, "Roles": ", ".join(roles), "Issue": issue, "Detail": detail,
                         "Fix": "; ".join(remove_binding(policy["resource"], member, role, condition) for role, condition in grants), "_status": status})
    return rows


def public_image_rows(public_policies):
    rows = []
    for resource, grants in sorted(public_policies.items()):
        parts = resource.split("/")
        project_id = parts[parts.index("projects") + 1] if "projects" in parts else ""
        rows.append({"Resource": f"image {parts[-1]} ({project_id})", "Principal": ", ".join(sorted({m for _, m in grants})), "Type": PUBLIC, "Roles": ", ".join(sorted({r for r, _ in grants})),
                     "Issue": "Image open to the public.", "Detail": "Anyone can boot from the image and read what it contains (credentials, code).",
                     "Fix": f"gcloud compute images remove-iam-policy-binding {parts[-1]} --project={project_id} --member={grants[0][1]} --role={grants[0][0]}", "_status": ACTION_REQUIRED})
    return rows


# --- Unused Service Accounts --------------------------------------------------------------------------------------------

def unused_account_rows(project_id, insights):
    """The rows of one project's ``SERVICE_ACCOUNT_USAGE`` insights (active ones)."""
    rows = []
    for insight in insights:
        data = recommender_v1.Insight.to_dict(insight, use_integers_for_enums=False) if not isinstance(insight, dict) else insight
        if str(data.get("insight_subtype") or data.get("insightSubtype") or "") != UNUSED_SUBTYPE:
            continue
        state = str((data.get("state_info") or data.get("stateInfo") or {}).get("state") or "ACTIVE")
        if state not in ("ACTIVE", "STATE_UNSPECIFIED"):
            continue
        content = data.get("content") or {}
        email = str(content.get("email") or "")
        if not email:
            continue
        last = str(content.get("lastAuthenticatedTime") or "")[:10]
        default = principal_kind(f"serviceAccount:{email}") == DEFAULT_SA
        fix = (f"gcloud iam service-accounts disable {email} --project={project_id}  # a default account: detach it from what still names it, disable, never delete" if default
               else f"gcloud iam service-accounts disable {email} --project={project_id}  # then delete it after a quiet period")
        rows.append({"Project": project_id, "Service Account": email, "Last authenticated": last or "never (in the window)",
                     "Issue": f"Unused for {OBSERVATION_DAYS}+ days.", "Detail": "An identity nobody uses is a standing credential waiting for a key or a grant to be abused; the IAM recommender observed no authentication.",
                     "Fix": fix, "_status": INVESTIGATION})
    return rows


# --- the checks -------------------------------------------------------------------------------------------------------

def check_identity_hygiene(scope, scope_id, job_id, *, sink):
    """Writes *Service Account Privileges* and *External Principals* from one IAM-policy search over the scope."""
    print(f"🪪 [{job_id}] Checking {SA_PRIVILEGES_CHECK} and {EXTERNAL_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        policies = [policy_facts(result) for result in asset_client.search_all_iam_policies(request={"scope": parent, "asset_types": POLICY_TYPES, "page_size": 500})]
    except Exception as e:
        logging.error(f"[{job_id}] {SA_PRIVILEGES_CHECK}: could not search the IAM policies under {parent}: {e}")
        for check in (SA_PRIVILEGES_CHECK, EXTERNAL_CHECK):
            sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped, org_domains, public = NotChecked(SA_PRIVILEGES_CHECK), (), {}
    organization = organization_of(policies, scope, scope_id)
    try:
        if not organization:
            raise LookupError("no organization among the policies' ancestors")
        name = str(gcp.api_build("cloudresourcemanager", "v1", credentials=credentials).organizations().get(name=organization).execute().get("displayName") or "").lower()
        org_domains = (name,) if "." in name else ()
    except Exception as e:
        skipped.add(parent, e, detail="external-domain rule: the organization's domain could not be read")
    try:
        public = public_policy_rows(asset_client.search_all_iam_policies(request={"scope": parent, "query": PUBLIC_QUERY, "asset_types": IMAGE_TYPES}))
    except Exception as e:
        skipped.add(parent, e, detail="public images rule: the IAM policy search failed")
    write_rows(sink, job_id, SA_PRIVILEGES_CHECK, admin_role_rows(policies) + role_separation_rows(policies), SA_PRIVILEGES_ALL_CLEAR)
    write_rows(sink, job_id, EXTERNAL_CHECK, external_rows(policies, org_domains, get_settings().trusted_domains) + public_image_rows(public), EXTERNAL_ALL_CLEAR)
    skipped.write(sink, job_id)


def check_unused_service_accounts(scope_id, all_projects, job_id, *, sink):
    """Writes *Unused Service Accounts* from the IAM recommender's service-account insights of every project."""
    print(f"🪪 [{job_id}] Checking {UNUSED_SA_CHECK} in {len(all_projects)} projects...")
    skipped, rows = NotChecked(UNUSED_SA_CHECK), []
    for project in all_projects:
        project_id = project["projectId"]
        try:
            client = gcp.recommender_client()
            insights = list(client.list_insights(request={"parent": f"projects/{project_id}/locations/global/insightTypes/{INSIGHT_TYPE}"}))
            rows.extend(unused_account_rows(project_id, insights))
        except Exception as e:
            skipped.add(project_id, e)
    write_rows(sink, job_id, UNUSED_SA_CHECK, rows, UNUSED_SA_ALL_CLEAR)
    skipped.write(sink, job_id)
