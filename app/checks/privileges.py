"""
Folders, keys and privileged grants — who can grant what (v18.7).

The IAM the report never read: folder-level basic roles, the grants that create
projects and reach billing at the organization, just-in-time elevation paths,
and the custom roles that re-acquire IAM powers. Everything comes from reads the
scanner's roles already allow (``roles/iam.securityReviewer``, the inventory
search) — **fresh** where a fix should show on the next scan (the v18.5 lesson):
folder and organization policies from Resource Manager, custom roles from the
IAM API, entitlements from Privileged Access Manager, deny policies from IAM v2;
the inventory search names the folders and projects, the IAM-policy search the
holders of custom roles.

- **Folder Primitive Roles** (Security, scope-level): Owner or Editor on a
  folder, by kind of holder — the project table of *Primitive Roles*
  (``security.PRIMITIVE_HOLDER_STATUS``) — plus Project Creator on a folder (a
  whole domain Action Required, a person Investigation, a group or an
  automation account the project-factory practice). Every project below the
  folder inherits the grant; the row counts them.
- **Privileged Grants** (Security, a split check): at the organization, Project
  Creator and the billing roles that belong on the billing account, the
  Organization Administrator redundancy WLM asks for, and whether any IAM deny
  policy guards the organization (Informational); under the scope, Privileged
  Access Manager entitlements that hand out administrative roles with nobody
  approving, and standing grants that duplicate an entitlement (a just-in-time
  path exists; the standing grant defeats it). The scope shard reads the
  organization, folders and their entitlements; the project shards the
  projects' entitlements (``SERVICE_DISABLED`` = PAM not used there, no line).
- **Custom Roles With IAM Powers** (Security, a split check): a custom role
  carrying ``*.setIamPolicy``, key creation, impersonation, role administration
  or ``orgpolicy.policy.set`` — Investigation when a principal that is not a
  Google-managed agent holds it, Informational when dormant; a retired
  (disabled, deprecated or deleted) role still bound, Informational.
  Predefined roles are *Service Account Privileges*' and *Critical Org-Level
  Roles*' ground.

Google-managed service agents are never rows (``security.principal_kind``); a
public principal on a folder stays *External Principals*' row.
"""
import logging

from app.checks.gke_operations import ACTION_REQUIRED, INFORMATIONAL, INVESTIGATION, write_rows
from app.checks.identity_hygiene import ESCALATION_ROLES, POLICY_TYPES, is_admin_role, policy_facts, remove_binding
from app.checks.not_checked import NotChecked, is_api_disabled
from app.checks.security import (CONSUMER_ACCOUNT, DEFAULT_SA, DELETED, DOMAIN, EXTERNAL_USER, GOOGLE_MANAGED, GROUP, ORG_CRITICAL_ROLES, OTHER_PRINCIPAL,
                                 PRIMITIVE_HOLDER_STATUS, PRIMITIVE_ROLES, PUBLIC, SERVICE_ACCOUNT, USER, condition_text, principal_kind)
from app.config import SCOPES
from app.services import gcp

FOLDER_ROLES_CHECK = "Folder Primitive Roles"
PRIVILEGED_GRANTS_CHECK = "Privileged Grants"
CUSTOM_ROLES_CHECK = "Custom Roles With IAM Powers"
PRIVILEGE_CHECKS = (FOLDER_ROLES_CHECK, PRIVILEGED_GRANTS_CHECK, CUSTOM_ROLES_CHECK)

FOLDER_TYPE, PROJECT_TYPE = "cloudresourcemanager.googleapis.com/Folder", "cloudresourcemanager.googleapis.com/Project"
PROJECT_CREATOR = "roles/resourcemanager.projectCreator"
BILLING_ROLES = ("roles/billing.creator", "roles/billing.user", "roles/billing.viewer", "roles/billing.costsManager")
ORG_ADMIN = "roles/resourcemanager.organizationAdmin"
MIN_ORG_ADMINS = 2
MAX_JIT_SECONDS = 24 * 3600
POLICY_V3 = {"options": {"requestedPolicyVersion": 3}}
# Project creation: a group or an automation account is the project-factory practice (listed), a person is a look, a whole
# domain or the public opens it to every account.
CREATOR_STATUS = {PUBLIC: ACTION_REQUIRED, DOMAIN: ACTION_REQUIRED, CONSUMER_ACCOUNT: ACTION_REQUIRED, USER: INVESTIGATION, EXTERNAL_USER: INVESTIGATION,
                  DELETED: INVESTIGATION, OTHER_PRINCIPAL: INVESTIGATION, GROUP: INFORMATIONAL, SERVICE_ACCOUNT: INFORMATIONAL, DEFAULT_SA: INFORMATIONAL}
# Billing roles at the organization belong on the billing account: any holder is a look, a domain or the public a finding.
BILLING_STATUS = {PUBLIC: ACTION_REQUIRED, DOMAIN: ACTION_REQUIRED, CONSUMER_ACCOUNT: ACTION_REQUIRED, USER: INVESTIGATION, EXTERNAL_USER: INVESTIGATION,
                  DELETED: INVESTIGATION, OTHER_PRINCIPAL: INVESTIGATION, GROUP: INVESTIGATION, SERVICE_ACCOUNT: INVESTIGATION, DEFAULT_SA: INVESTIGATION}
# The permissions a custom role may carry that change who may do what (the IAM skills' destructive/admin tier), besides any
# ``*.setIamPolicy``.
IAM_POWERS = ("iam.serviceAccountKeys.create", "iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob",
              "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation", "iam.roles.create", "iam.roles.update", "orgpolicy.policy.set")
RETIRED_STAGES = ("DISABLED", "DEPRECATED")
HOLDERS_PER_QUERY = 20

FOLDER_ROLES_ALL_CLEAR = ("No user, group or service account holds Owner or Editor on a folder, and project creation on folders is granted to groups or "
                          "automation only.")
PRIVILEGED_GRANTS_ALL_CLEAR = ("Project creation and billing roles at the organization are held by groups or automation, at least two principals administer "
                               "the organization, every just-in-time entitlement requires approval, and no standing grant duplicates one.")
CUSTOM_ROLES_ALL_CLEAR = "No custom role in use carries a permission that changes who may do what, and no retired custom role is still bound."


# --- the hierarchy -----------------------------------------------------------------------------------------------------

def search_folders(asset_client, parent):
    """``{folder_id: {id, display, parent}}`` of the active folders under ``parent`` from the search index (a folder scope includes
    the folder itself)."""
    folders = {}
    results = asset_client.search_all_resources(request={"scope": parent, "asset_types": [FOLDER_TYPE], "read_mask": "name,displayName,parentFullResourceName,state", "page_size": 500})
    for result in results:
        folder_id = str(getattr(result, "name", "") or "").rsplit("/", 1)[-1]
        state = str(getattr(result, "state", "") or "")
        if not folder_id or (state and state != "ACTIVE"):
            continue
        folders[folder_id] = {"id": folder_id, "display": str(getattr(result, "display_name", "") or ""),
                              "parent": "/".join(str(getattr(result, "parent_full_resource_name", "") or "").split("/")[-2:])}
    return folders


def search_projects(asset_client, parent):
    """``[{id, number, folders}]`` of the active projects under ``parent`` from the search index (projects named by ID, their
    number in ``project``, the folders above them in ``folders``)."""
    projects = []
    results = asset_client.search_all_resources(request={"scope": parent, "asset_types": [PROJECT_TYPE], "read_mask": "name,project,folders,state,additionalAttributes", "page_size": 500})
    for result in results:
        state = str(getattr(result, "state", "") or "")
        if state and state != "ACTIVE":
            continue
        attributes = getattr(result, "additional_attributes", None)
        try:
            attributes = dict(attributes) if attributes else {}
        except (TypeError, ValueError):
            attributes = {}
        project_id = str(attributes.get("projectId") or str(getattr(result, "name", "") or "").rsplit("/", 1)[-1])
        projects.append({"id": project_id, "number": str(getattr(result, "project", "") or "").rsplit("/", 1)[-1],
                         "folders": [str(f).rsplit("/", 1)[-1] for f in (getattr(result, "folders", None) or [])]})
    return projects


def projects_below(projects):
    """``{folder_id: count}`` of the projects under each folder."""
    counts = {}
    for project in projects:
        for folder_id in project["folders"]:
            counts[folder_id] = counts.get(folder_id, 0) + 1
    return counts


def policy_bindings(policy):
    """``[(role, [members], condition)]`` of a policy read from the API — the shape :func:`identity_hygiene.policy_facts` gives a search result."""
    bindings = []
    for binding in policy.get("bindings") or []:
        condition = binding.get("condition") or {}
        text = {"title": str(condition.get("title") or ""), "expression": str(condition.get("expression") or "")} if condition else {}
        bindings.append((str(binding.get("role") or ""), [str(m) for m in binding.get("members") or []], text))
    return bindings


def organization_name_domains(crm, organization):
    """The organization's primary domain as a one-element tuple (``organizations.get`` names it), ``()`` when it cannot be read."""
    name = str(crm.organizations().get(name=organization).execute().get("displayName") or "").lower()
    return (name,) if "." in name else ()


def folder_label(folder):
    return f"{folder['display']} ({folder['id']})" if folder.get("display") else f"folders/{folder['id']}"


# --- Folder Primitive Roles ----------------------------------------------------------------------------------------------

def folder_role_rows(folder, bindings, below, org_domains=()):
    """One row per (principal, role) for Owner, Editor and Project Creator on a folder, with its kind, condition, fix and ``_status``.

    Google-managed agents are never rows; a public principal is *External Principals*' row (Action Required there, any role).
    """
    rows, label, resource = [], folder_label(folder), f"folders/{folder['id']}"
    for role, members, condition in bindings:
        if role not in PRIMITIVE_ROLES and role != PROJECT_CREATOR:
            continue
        for member in members:
            kind = principal_kind(member, org_domains)
            if kind in (GOOGLE_MANAGED, PUBLIC):
                continue
            if role == PROJECT_CREATOR:
                status, note = CREATOR_STATUS[kind], "  # grant it to a project-factory group or service account"
            else:
                status, note = PRIMITIVE_HOLDER_STATUS[kind], "  # grant a predefined role for the work first; every project below inherits this one"
            rows.append({"Folder": label, "Principal": member, "Type": kind, "Role": role, "Projects below": below, "Condition": condition_text({"condition": condition}),
                         "Fix": remove_binding(resource, member, role, condition) + note, "_status": status})
    return rows


def check_folder_roles(scope, scope_id, job_id, *, sink):
    """Writes *Folder Primitive Roles* from the folders under the scope: fresh ``folders.getIamPolicy`` per folder, the IAM-policy
    search's copy when a read is refused (said under *Projects not checked*)."""
    print(f"🗂️  [{job_id}] Checking {FOLDER_ROLES_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    skipped = NotChecked(FOLDER_ROLES_CHECK)
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        folders = search_folders(asset_client, parent) if scope != "project" else {}
        if scope == "folder":
            folders.setdefault(scope_id, {"id": scope_id, "display": "", "parent": ""})
    except Exception as e:
        logging.error(f"[{job_id}] {FOLDER_ROLES_CHECK}: could not list the folders under {parent}: {e}")
        sink.write_finding(job_id, FOLDER_ROLES_CHECK.replace(" ", "_"), {"Check": FOLDER_ROLES_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    below, org_domains, copies = {}, (), {}
    crm = gcp.api_build("cloudresourcemanager", "v3", credentials=credentials)
    if folders:
        try:
            below = projects_below(search_projects(asset_client, parent))
        except Exception as e:
            skipped.add(parent, e, detail="the projects below each folder could not be counted")
        try:
            copies = {fact["resource"].rsplit("/", 1)[-1]: fact["bindings"]
                      for fact in (policy_facts(r) for r in asset_client.search_all_iam_policies(request={"scope": parent, "asset_types": [FOLDER_TYPE], "page_size": 500}))}
        except Exception as e:
            logging.info(f"[{job_id}] {FOLDER_ROLES_CHECK}: no inventory copy of the folder policies ({e})")
        try:
            organization = next((f["parent"] for f in folders.values() if f["parent"].startswith("organizations/")), f"organizations/{scope_id}" if scope == "organization" else "")
            if not organization:
                raise LookupError("no organization among the folders' parents")
            org_domains = organization_name_domains(crm, organization)
        except Exception as e:
            logging.info(f"[{job_id}] {FOLDER_ROLES_CHECK}: the organization's domain could not be read ({e}); external users rate as users")
    rows = []
    for folder_id in sorted(folders):
        folder = folders[folder_id]
        try:
            policy = crm.folders().getIamPolicy(resource=f"folders/{folder_id}", body=POLICY_V3).execute()
            if not folder["display"]:
                folder["display"] = str(crm.folders().get(name=f"folders/{folder_id}").execute().get("displayName") or "")
            bindings = policy_bindings(policy)
        except Exception as e:
            if folder_id in copies:
                bindings = copies[folder_id]
                skipped.add(f"folders/{folder_id}", e, detail="the Resource Manager read failed; the inventory's copy was used, which can lag changes by hours")
            else:
                skipped.add(f"folders/{folder_id}", e)
                continue
        rows += folder_role_rows(folder, bindings, below.get(folder_id, 0), org_domains)
    write_rows(sink, job_id, FOLDER_ROLES_CHECK, rows, FOLDER_ROLES_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- Privileged Grants ----------------------------------------------------------------------------------------------------

def privileged_grant_rows(org_id, bindings, org_domains=()):
    """The organization's project-creation and billing grants by kind of holder, and the Organization Administrator redundancy row."""
    rows, resource, admins = [], f"organizations/{org_id}", {}
    for role, members, condition in bindings:
        for member in members:
            kind = principal_kind(member, org_domains)
            if kind == GOOGLE_MANAGED:
                continue
            if role == ORG_ADMIN and not condition:
                admins[member] = kind
            if role == PROJECT_CREATOR:
                status = CREATOR_STATUS[kind]
                detail = {ACTION_REQUIRED: "Every account in it can create projects: sprawl, unbilled or unlabelled projects, guardrails bypassed by volume.",
                          INVESTIGATION: "A person creating projects by hand; the project-factory practice is a group or an automation account.",
                          INFORMATIONAL: "The project-factory practice, listed for the record."}[status]
                fix = remove_binding(resource, member, role, condition) + "  # grant it to a project-factory group or service account"
                issue = "Project creation granted at the organization."
            elif role in BILLING_ROLES:
                status = BILLING_STATUS[kind]
                detail = ("At the organization the role reaches every billing account the organization can see; grant it on the billing account instead."
                          + (" Every account in the domain holds it." if kind == DOMAIN else ""))
                fix = remove_binding(resource, member, role, condition) + f"  # grant it on the billing account instead: gcloud billing accounts add-iam-policy-binding ACCOUNT --member={member} --role={role}"
                issue = "Billing role granted at the organization."
            else:
                continue
            rows.append({"Resource": resource, "Principal": member, "Type": kind, "Role": role, "Condition": condition_text({"condition": condition}),
                         "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})
    if len(admins) < MIN_ORG_ADMINS:
        fix = f"gcloud organizations add-iam-policy-binding {org_id} --member=group:GROUP --role={ORG_ADMIN}  # a second administrator: a group with few members"
        if not admins:
            rows.append({"Resource": resource, "Principal": "—", "Type": "", "Role": ORG_ADMIN, "Condition": "", "Issue": "No Organization Administrator.",
                         "Detail": "Nobody holds the role without a condition: the organization cannot be administered once the current session or key is gone.", "Fix": fix,
                         "_status": ACTION_REQUIRED})
        else:
            (member, kind), = admins.items()
            if kind == GROUP:
                rows.append({"Resource": resource, "Principal": member, "Type": kind, "Role": ORG_ADMIN, "Condition": "", "Issue": "One Organization Administrator principal.",
                             "Detail": "A single group administers the organization — fine when it has at least two members, which the scanner cannot see.", "Fix": fix,
                             "_status": INFORMATIONAL})
            else:
                rows.append({"Resource": resource, "Principal": member, "Type": kind, "Role": ORG_ADMIN, "Condition": "", "Issue": "Single Organization Administrator.",
                             "Detail": "One departure, one lost key or one suspended account locks the organization (lockout); redundancy takes two.", "Fix": fix,
                             "_status": ACTION_REQUIRED})
    return rows


def deny_policy_row(org_id, count):
    """The Informational row of an organization with no IAM deny policy attached, or ``None``."""
    if count:
        return None
    return {"Resource": f"organizations/{org_id}", "Principal": "—", "Type": "", "Role": "", "Condition": "", "Issue": "No IAM deny policy guards the organization.",
            "Detail": ("Deny policies are evaluated before allow policies: a guardrail that stops even an Owner from, say, deleting projects or custom roles "
                       "outside a break-glass group. None is attached to the organization."),
            "Fix": (f"gcloud iam policies create org-guardrails --attachment-point=cloudresourcemanager.googleapis.com/organizations/{org_id} --kind=denypolicies "
                    "--policy-file=deny.yaml  # e.g. deny iam.googleapis.com/roles.delete and resourcemanager.projects.delete to everyone but a break-glass group"),
            "_status": INFORMATIONAL}


def is_admin_tier(role):
    """A role a just-in-time grant of which should need an approver: the organization's critical roles, the escalation roles, any ``*.admin``."""
    return role in ORG_CRITICAL_ROLES or role in ESCALATION_ROLES or role in PRIMITIVE_ROLES or is_admin_role(role)


def entitlement_facts(entitlement):
    """``{name, short, resource, roles, eligible, approvers, max_seconds, justification_optional, state}`` of one PAM entitlement."""
    name = str(entitlement.get("name") or "")
    access = (entitlement.get("privilegedAccess") or {}).get("gcpIamAccess") or {}
    steps = ((entitlement.get("approvalWorkflow") or {}).get("manualApprovals") or {}).get("steps") or []
    duration = str(entitlement.get("maxRequestDuration") or "0s").rstrip("s")
    try:
        max_seconds = int(float(duration))
    except ValueError:
        max_seconds = 0
    return {"name": name, "short": name.rsplit("/", 1)[-1], "resource": "/".join(name.split("/")[:2]),
            "roles": [str(b.get("role") or "") for b in access.get("roleBindings") or []],
            "eligible": [str(p) for user in entitlement.get("eligibleUsers") or [] for p in user.get("principals") or []],
            "approvers": any(step.get("approvers") for step in steps), "max_seconds": max_seconds,
            "justification_optional": "notMandatory" in (entitlement.get("requesterJustificationConfig") or {}), "state": str(entitlement.get("state") or "")}


def entitlement_fix(fact, verb="add approvalWorkflow.manualApprovals.steps[0].approvers"):
    kind, target = fact["resource"].split("/", 1)
    flag = {"organizations": "--organization", "folders": "--folder", "projects": "--project"}.get(kind, "--project")
    return (f"gcloud pam entitlements export {fact['short']} --location=global {flag}={target} > e.yaml  # {verb}, then: "
            f"gcloud pam entitlements update {fact['short']} --location=global {flag}={target} --entitlement-file=e.yaml")


def entitlement_rows(entitlements):
    """One row per entitlement that hands out an administrative role with nobody approving (Investigation), or that lasts over 24 h or needs
    no justification (Informational); entitlements being created or deleted are skipped."""
    rows = []
    for entitlement in entitlements:
        fact = entitlement_facts(entitlement)
        if fact["state"] and fact["state"] not in ("AVAILABLE", "UPDATING"):
            continue
        admin_roles, hours = [r for r in fact["roles"] if is_admin_tier(r)], fact["max_seconds"] / 3600
        extras = ([f"up to {hours:g} h per request"] if fact["max_seconds"] > MAX_JIT_SECONDS else []) + (["no justification required"] if fact["justification_optional"] else [])
        if admin_roles and not fact["approvers"]:
            status, issue = INVESTIGATION, "Just-in-time grant without approval."
            detail = f"{', '.join(fact['eligible']) or 'nobody yet'} may take {', '.join(admin_roles)} on {fact['resource']} with nobody approving" + (f" ({'; '.join(extras)})" if extras else "") + "."
            fix = entitlement_fix(fact)
        elif extras:
            status, issue = INFORMATIONAL, "Long or unjustified just-in-time grant."
            detail = f"{', '.join(fact['roles'])} on {fact['resource']}: {'; '.join(extras)}."
            fix = entitlement_fix(fact, "set maxRequestDuration to 3600s and requesterJustificationConfig.unstructured")
        else:
            continue
        rows.append({"Resource": fact["resource"], "Principal": ", ".join(fact["eligible"]) or "—", "Type": "PAM entitlement", "Role": ", ".join(fact["roles"]), "Condition": fact["short"],
                     "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})
    return rows


def standing_grant_rows(resource, bindings, entitlements):
    """Unconditional grants of (principal, role) on ``resource`` that an entitlement there also offers: a just-in-time path exists, the standing grant
    defeats it (Action Required). PAM's own grants are conditional bindings and never standing."""
    offered = {}
    for entitlement in entitlements:
        fact = entitlement_facts(entitlement)
        for principal in fact["eligible"]:
            for role in fact["roles"]:
                offered.setdefault((principal, role), fact["short"])
    rows = []
    for role, members, condition in bindings:
        if condition:
            continue
        for member in members:
            short = offered.get((member, role))
            if short:
                rows.append({"Resource": resource, "Principal": member, "Type": principal_kind(member), "Role": role, "Condition": "", "Issue": "Standing grant duplicates a just-in-time entitlement.",
                             "Detail": f"Entitlement {short} grants the role on request, with PAM's audit trail and expiry; the permanent binding makes it standing access.",
                             "Fix": remove_binding(resource, member, role, {}) + f"  # entitlement {short} grants it on request", "_status": ACTION_REQUIRED})
    return rows


def list_entitlements(pam, resource):
    """The entitlements of ``organizations/N``, ``folders/N`` or ``projects/P`` (``global`` location), every page."""
    kind = resource.split("/", 1)[0]
    collection = getattr(pam, kind)().locations().entitlements()
    found, request = [], collection.list(parent=f"{resource}/locations/global")
    while request:
        response = request.execute()
        found += response.get("entitlements") or []
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def deny_policy_count(iam_v2, org_id):
    """How many IAM deny policies are attached to the organization (metadata only: the rules need ``iam.denypolicies.get``)."""
    parent = f"policies/cloudresourcemanager.googleapis.com%2Forganizations%2F{org_id}/denypolicies"
    count, request = 0, iam_v2.policies().listPolicies(parent=parent)
    while request:
        response = request.execute()
        count += len(response.get("policies") or [])
        request = iam_v2.policies().listPolicies_next(previous_request=request, previous_response=response)
    return count


def check_privileged_grants(scope, scope_id, all_projects, job_id, *, sink, scope_level=True, project_level=True):
    """Writes *Privileged Grants*: the organization's grants, redundancy and deny policies plus the entitlements of the organization and its folders
    (``scope_level``), the projects' entitlements and the standing grants that duplicate them (``project_level``)."""
    print(f"🪪 [{job_id}] Checking {PRIVILEGED_GRANTS_CHECK} under {scope} {scope_id}...")
    parent, rows, skipped = f"{scope}s/{scope_id}", [], NotChecked(PRIVILEGED_GRANTS_CHECK)
    credentials, _ = gcp.auth_default(scopes=SCOPES)
    crm = gcp.api_build("cloudresourcemanager", "v1", credentials=credentials)
    clients = {}

    def entitlements_of(resource):
        """The entitlements, or ``None`` when PAM is not enabled there (no line) or the read failed (a line). The PAM client is built on first
        use: its discovery document is not bundled with the client library (``static_discovery=False`` fetches it)."""
        try:
            if "pam" not in clients:
                clients["pam"] = gcp.api_build("privilegedaccessmanager", "v1", credentials=credentials, static_discovery=False)
            return list_entitlements(clients["pam"], resource)
        except Exception as e:
            if is_api_disabled(e):
                return None
            skipped.add(resource.split("/", 1)[1] if resource.startswith("projects/") else resource, e, detail="the Privileged Access Manager entitlements could not be listed")
            return None

    if scope_level:
        if scope == "organization":
            try:
                policy = crm.organizations().getIamPolicy(resource=parent, body=POLICY_V3).execute()
            except Exception as e:
                logging.error(f"[{job_id}] {PRIVILEGED_GRANTS_CHECK}: could not read the organization's IAM policy: {e}")
                sink.write_finding(job_id, PRIVILEGED_GRANTS_CHECK.replace(" ", "_"), {"Check": PRIVILEGED_GRANTS_CHECK, "Finding": [{"Error": f"Could not read the organization's IAM policy: {e}"}], "Status": "Error"})
                return
            try:
                org_domains = organization_name_domains(crm, parent)
            except Exception as e:
                logging.info(f"[{job_id}] {PRIVILEGED_GRANTS_CHECK}: the organization's domain could not be read ({e})")
                org_domains = ()
            bindings = policy_bindings(policy)
            rows += privileged_grant_rows(scope_id, bindings, org_domains)
            entitlements = entitlements_of(parent)
            if entitlements:
                rows += entitlement_rows(entitlements) + standing_grant_rows(parent, bindings, entitlements)
            try:
                rows += [row for row in [deny_policy_row(scope_id, deny_policy_count(gcp.api_build("iam", "v2", credentials=credentials), scope_id))] if row]
            except Exception as e:
                skipped.add(parent, e, detail="the IAM deny policies could not be listed")
        if scope != "project":
            try:
                folders = search_folders(gcp.asset_client(credentials), parent)
            except Exception as e:
                folders = {}
                skipped.add(parent, e, detail="the folders' entitlements: the folder listing failed")
            for folder_id in sorted(folders):
                entitlements = entitlements_of(f"folders/{folder_id}")
                if entitlements:
                    rows += entitlement_rows(entitlements)
    if project_level:
        for project in all_projects:
            resource = f"projects/{project['projectId']}"
            entitlements = entitlements_of(resource)
            if not entitlements:
                continue
            rows += entitlement_rows(entitlements)
            try:
                policy = crm.projects().getIamPolicy(resource=project["projectId"], body=POLICY_V3).execute()
                rows += standing_grant_rows(resource, policy_bindings(policy), entitlements)
            except Exception as e:
                skipped.add(project["projectId"], e, detail="standing grants: the project's IAM policy could not be read")
    write_rows(sink, job_id, PRIVILEGED_GRANTS_CHECK, rows, PRIVILEGED_GRANTS_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- Custom Roles With IAM Powers ----------------------------------------------------------------------------------------

def iam_power(permission):
    """Whether a permission changes who may do what: any ``*.setIamPolicy`` or one of ``IAM_POWERS``."""
    return permission.endswith(".setIamPolicy") or permission in IAM_POWERS


def role_facts(role, parent):
    """``{name, short, parent, stage, deleted, powers}`` of one custom role (``view=FULL``): an unset stage is ALPHA, as the API documents."""
    name = str(role.get("name") or "")
    return {"name": name, "short": name.rsplit("/", 1)[-1], "parent": parent, "stage": str(role.get("stage") or "ALPHA"), "deleted": bool(role.get("deleted")),
            "powers": sorted(p for p in (role.get("includedPermissions") or []) if iam_power(str(p)))}


def list_custom_roles(iam, parent):
    """The custom roles defined on ``organizations/N`` or ``projects/P``, with their permissions, deleted ones included."""
    collection = iam.organizations().roles() if parent.startswith("organizations/") else iam.projects().roles()
    found, request = [], collection.list(parent=parent, view="FULL", showDeleted=True)
    while request:
        response = request.execute()
        found += [role_facts(role, parent) for role in response.get("roles") or []]
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def custom_role_holders(asset_client, parent, role_names):
    """``{role name: [(resource, member)]}`` — who holds the roles on organizations, folders and projects under ``parent`` (one IAM-policy search per
    ``HOLDERS_PER_QUERY`` roles)."""
    holders = {}
    names = list(role_names)
    for start in range(0, len(names), HOLDERS_PER_QUERY):
        chunk = names[start:start + HOLDERS_PER_QUERY]
        query = "roles:(" + " OR ".join(f'"{name}"' for name in chunk) + ")"
        for result in asset_client.search_all_iam_policies(request={"scope": parent, "query": query, "asset_types": POLICY_TYPES, "page_size": 500}):
            fact = policy_facts(result)
            for role, members, _ in fact["bindings"]:
                if role in chunk:
                    holders.setdefault(role, []).extend((fact["resource"], member) for member in members)
    return holders


def role_fix(fact, holders):
    kind, target = fact["parent"].split("/", 1)
    flag = "--organization" if kind == "organizations" else "--project"
    if fact["deleted"] or fact["stage"] in RETIRED_STAGES:
        resource, member = holders[0]
        return remove_binding(resource, member, fact["name"], {}) + "  # per holder; then delete the role"
    if holders:
        return f"gcloud iam roles update {fact['short']} {flag}={target} --remove-permissions={','.join(fact['powers'])}  # grant the predefined role that carries them, deliberately, to the principals that need them"
    return f"gcloud iam roles delete {fact['short']} {flag}={target}  # nobody holds it; or keep it deliberately"


def custom_role_rows(roles, holders):
    """One row per custom role that carries an IAM power (Investigation with a non-Google holder, Informational when dormant) or that is retired but
    still bound (Informational)."""
    rows = []
    for fact in roles:
        bound = holders.get(fact["name"], [])
        human = [(resource, member) for resource, member in bound if principal_kind(member) != GOOGLE_MANAGED]
        retired = fact["deleted"] or fact["stage"] in RETIRED_STAGES
        if retired:
            if not bound:
                continue
            status, issue = INFORMATIONAL, "Retired custom role still bound."
            detail = f"The role is {'deleted' if fact['deleted'] else fact['stage'].lower()} but still granted; the binding grants nothing useful and outlives the role."
        elif fact["powers"]:
            if human:
                status, issue = INVESTIGATION, "Custom role carries IAM powers."
                detail = "The permissions change who may do what (grant roles, mint tokens, create keys, write policies): least privilege silently re-acquired through a custom role."
            else:
                status, issue = INFORMATIONAL, "Dormant custom role carries IAM powers."
                detail = "Defined but held by nobody (or by Google-managed agents only); one binding away from mattering."
        else:
            continue
        shown = "; ".join(f"{member} on {resource}" for resource, member in bound[:5]) + (f" (+{len(bound) - 5} more)" if len(bound) > 5 else "")
        rows.append({"Role": fact["short"], "Defined at": fact["parent"], "Stage": "deleted" if fact["deleted"] else fact["stage"], "Powers": ", ".join(fact["powers"]), "Holders": shown or "none",
                     "Issue": issue, "Detail": detail, "Fix": role_fix(fact, bound), "_status": status})
    return rows


def check_custom_roles(scope, scope_id, all_projects, job_id, *, sink, scope_level=True, project_level=True):
    """Writes *Custom Roles With IAM Powers*: the organization's custom roles in an organization scan (``scope_level``), every project's (``project_level``),
    each with its holders from the IAM-policy search."""
    print(f"🪪 [{job_id}] Checking {CUSTOM_ROLES_CHECK} under {scope} {scope_id}...")
    parent, roles, skipped = f"{scope}s/{scope_id}", [], NotChecked(CUSTOM_ROLES_CHECK)
    credentials, _ = gcp.auth_default(scopes=SCOPES)
    iam = gcp.api_build("iam", "v1", credentials=credentials)
    if scope_level and scope == "organization":
        try:
            roles += list_custom_roles(iam, parent)
        except Exception as e:
            logging.error(f"[{job_id}] {CUSTOM_ROLES_CHECK}: could not list the organization's custom roles: {e}")
            sink.write_finding(job_id, CUSTOM_ROLES_CHECK.replace(" ", "_"), {"Check": CUSTOM_ROLES_CHECK, "Finding": [{"Error": f"Could not list the organization's custom roles: {e}"}], "Status": "Error"})
            return
    if project_level:
        for project in all_projects:
            try:
                roles += list_custom_roles(iam, f"projects/{project['projectId']}")
            except Exception as e:
                skipped.add(project["projectId"], e)
    flagged = [fact for fact in roles if fact["powers"] or fact["deleted"] or fact["stage"] in RETIRED_STAGES]
    holders = {}
    if flagged:
        try:
            holders = custom_role_holders(gcp.asset_client(credentials), parent, [fact["name"] for fact in flagged])
        except Exception as e:
            skipped.add(parent, e, detail="holders: the IAM-policy search failed; the roles are listed as dormant")
    write_rows(sink, job_id, CUSTOM_ROLES_CHECK, custom_role_rows(flagged, holders), CUSTOM_ROLES_ALL_CLEAR)
    skipped.write(sink, job_id)
