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
"""Service Account Impersonation (v17.1): who can become which service account.

One stolen token becomes many when a principal may mint tokens for other
accounts: ``roles/iam.serviceAccountTokenCreator`` (or any role carrying
``iam.serviceAccounts.getAccessToken``, ``implicitDelegation``, ``signBlob``),
``roles/iam.serviceAccountKeyAdmin`` (create a key), ``roles/iam.serviceAccountAdmin``
(grant oneself the rest), ``roles/iam.serviceAccountUser`` (act as, at deploy
time) and ``roles/iam.workloadIdentityUser`` (a Kubernetes service account
mapped to a Google one). Granted on a project, folder or organization, such a
role reaches **every** service account beneath it.

One Cloud Asset Inventory IAM search over the scanned scope finds the bindings;
one resource search counts the service accounts they reach. Rows name the
resource and its level, the principal, the path, the reach (*every service
account under projects/x (27)*; *3 of 27 service accounts in projects/x*), the
targets and their privileged roles, and the fix. Google-managed service agents
and their ``*.serviceAgent`` roles are not listed, nor is an account bound on
itself; primitive roles are *Project IAM Hygiene*'s business. Verdicts (``severity``): token-minting at project,
folder or organization level, service-account-to-service-account chains,
public or domain principals, principals from outside the organization, and
Workload Identity bindings for the ``default`` Kubernetes account are *Action
Required*; a person's grant on one account, or act-as at project level, is
*Investigation Recommended* (CloudGauge's own operator grant shows there, as it
should).
"""
import logging
import re

from app.checks.gke_security import PRIVILEGED_ROLES, RESOURCE_LEVELS, privileged_roles
from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp

IMPERSONATION_CHECK = "Service Account Impersonation"
SERVICE_ACCOUNT_ASSET = "iam.googleapis.com/ServiceAccount"
PROJECT_ASSET = "cloudresourcemanager.googleapis.com/Project"
SERVICE_ACCOUNT_LEVEL = "service account"
PATH_BY_ROLE = {
    "roles/iam.serviceAccountTokenCreator": "token creator", "roles/iam.serviceAccountOpenIdTokenCreator": "token creator",
    "roles/iam.serviceAccountKeyAdmin": "key admin", "roles/iam.serviceAccountAdmin": "account admin",
    "roles/iam.serviceAccountUser": "actAs", "roles/iam.workloadIdentityUser": "workload identity",
}
TOKEN_PERMISSIONS = frozenset({"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.signBlob",
                               "iam.serviceAccounts.signJwt", "iam.serviceAccounts.getOpenIdToken"})
KEY_PERMISSIONS = frozenset({"iam.serviceAccountKeys.create"})
ADMIN_PERMISSIONS = frozenset({"iam.serviceAccounts.setIamPolicy"})
ACT_AS_PERMISSIONS = frozenset({"iam.serviceAccounts.actAs"})
MINTING_PATHS = ("token creator", "key admin", "account admin")
# Primitive roles are Project IAM Hygiene's business; service-agent roles belong to Google-managed agents.
IGNORED_ROLES = frozenset({"roles/owner", "roles/editor", "roles/viewer"})
SEARCH_QUERY = " OR ".join([f"policy:{role}" for role in PATH_BY_ROLE] +
                           [f"policy.role.permissions:{permission}" for permission in sorted(TOKEN_PERMISSIONS | KEY_PERMISSIONS)])
GOOGLE_MANAGED = re.compile(r"^(service-\d+@|\d+@(cloudservices|cloudbuild)\.gserviceaccount\.com$|.*@gcp-sa-[a-z0-9-]+\.iam\.gserviceaccount\.com$"
                            r"|.*@(system\.gserviceaccount\.com|[a-z0-9-]+\.google\.com\.iam\.gserviceaccount\.com|container-engine-robot\.iam\.gserviceaccount\.com"
                            r"|compute-system\.iam\.gserviceaccount\.com|serverless-robot-prod\.iam\.gserviceaccount\.com)$)")
KUBERNETES_MEMBER = re.compile(r"^serviceAccount:(?P<pool>[^\[]+)\[(?P<namespace>[^/\]]+)/(?P<account>[^\]]+)\]$")
SENSITIVE_NAMESPACES = ("kube-system",)
MAX_TARGET_LOOKUPS = 200


def is_google_managed(email):
    return bool(GOOGLE_MANAGED.match(email))


def member_kind(member):
    """``public``, ``domain``, ``human``, ``service account``, ``google``, ``kubernetes``, ``federated``, ``federated pool``, ``deleted`` or ``other``."""
    if member in ("allUsers", "allAuthenticatedUsers"):
        return "public"
    if member.startswith("domain:"):
        return "domain"
    if member.startswith(("user:", "group:")):
        return "human"
    if member.startswith("deleted:"):
        return "deleted"
    if member.startswith("serviceAccount:"):
        email = member.split(":", 1)[1]
        if KUBERNETES_MEMBER.match(member):
            return "kubernetes"
        return "google" if is_google_managed(email) else "service account"
    if member.startswith("principalSet:"):
        return "federated pool"
    if member.startswith("principal:"):
        return "federated"
    return "other"


def path_of_role(role, permissions_of_custom_role):
    """The impersonation path a role opens, or ``None``: predefined roles by name, custom roles by their permissions
    (``permissions_of_custom_role(role)`` returns a set, or ``None`` when the role could not be read)."""
    if role in IGNORED_ROLES or role.endswith(".serviceAgent"):
        return None
    if role in PATH_BY_ROLE:
        return PATH_BY_ROLE[role]
    if "/roles/" not in role:
        return None
    permissions = permissions_of_custom_role(role)
    if permissions is None:
        return "custom role (not read)"
    if permissions & TOKEN_PERMISSIONS:
        return "token creator"
    if permissions & KEY_PERMISSIONS:
        return "key admin"
    if permissions & ADMIN_PERMISSIONS:
        return "account admin"
    if permissions & ACT_AS_PERMISSIONS:
        return "actAs"
    return None


def severity(level, path, kind, *, member="", target_privileged=(), foreign=False, organization_scan=True):
    """``"Action Required"``, ``"Investigation Recommended"`` or ``None`` (not worth a row) for one binding."""
    if kind in ("google", "deleted"):
        return None
    minting = path in MINTING_PATHS or path == "custom role (not read)"
    if level != SERVICE_ACCOUNT_LEVEL:
        if minting:
            return "Action Required"
        if kind in ("public", "domain"):
            return "Action Required"
        return "Investigation Recommended"  # actAs, or workload identity, granted resource-wide
    if kind in ("public", "domain", "federated pool"):
        return "Action Required"
    if foreign:
        return "Action Required" if organization_scan else "Investigation Recommended"
    if kind == "kubernetes":
        match = KUBERNETES_MEMBER.match(member)
        sensitive = bool(match) and (match.group("account") == "default" or match.group("namespace") in SENSITIVE_NAMESPACES)
        if target_privileged and sensitive:
            return "Action Required"
        if target_privileged or sensitive:
            return "Investigation Recommended"
        return None
    if kind == "service account":
        return "Action Required" if minting else "Investigation Recommended"
    if kind == "federated":
        return "Investigation Recommended"
    if path == "actAs":
        return None  # a person acting as one account at deploy time
    return "Investigation Recommended"


def fix_for(level, path, kind, role, principal, target=""):
    if level != SERVICE_ACCOUNT_LEVEL:
        return (f"Remove the {level}-level binding of {role} for {principal} and grant it on the individual service accounts: "
                f"gcloud iam service-accounts add-iam-policy-binding <account> --member={principal} --role={role}")
    if kind == "kubernetes":
        return "Bind a dedicated Kubernetes service account (never default or kube-system) and keep the Google account least-privilege."
    if kind == "service account" and path in MINTING_PATHS:
        return (f"Replace the account-to-account chain with one purpose-built account or Workload Identity Federation: "
                f"gcloud iam service-accounts remove-iam-policy-binding {target} --member={principal} --role={role}")
    return f"gcloud iam service-accounts remove-iam-policy-binding {target} --member={principal} --role={role}  # or justify and document"


def resource_of(result):
    """``(level, resource label)`` of an IAM search result: ``("project", "projects/p1")``, ``("service account", "<email>")``…"""
    asset_type, resource = getattr(result, "asset_type", ""), getattr(result, "resource", "") or ""
    if asset_type in RESOURCE_LEVELS:
        return RESOURCE_LEVELS[asset_type], resource.split("//cloudresourcemanager.googleapis.com/", 1)[-1]
    if asset_type == SERVICE_ACCOUNT_ASSET:
        return SERVICE_ACCOUNT_LEVEL, resource.rsplit("/serviceAccounts/", 1)[-1]
    return "other", resource


def target_project(result):
    """The project number of an IAM search result (``projects/123`` → ``123``)."""
    return (getattr(result, "project", "") or "").split("/", 1)[-1]


def project_id_of(result):
    """The project ID in a service account's resource path (``//iam.googleapis.com/projects/p1/serviceAccounts/…``)."""
    resource = getattr(result, "resource", "") or ""
    return resource.split("/projects/", 1)[1].split("/", 1)[0] if "/projects/" in resource else target_project(result)


def impersonation_rows(results, inventory, permissions_of_custom_role, roles_of_target, *, organization_scan):
    """The check's rows from the IAM search ``results`` and the service-account ``inventory`` (an :class:`Inventory`)."""
    grouped = {}
    for result in results:
        level, resource = resource_of(result)
        if level == "other":
            continue
        project_number = target_project(result)
        if level in ("project", SERVICE_ACCOUNT_LEVEL) and not inventory.is_active(project_number):
            continue  # a project pending deletion is not scanned; its policies are not findings
        for binding in getattr(getattr(result, "policy", None), "bindings", None) or []:
            role = getattr(binding, "role", "") or ""
            path = path_of_role(role, permissions_of_custom_role)
            if path is None:
                continue
            for member in list(getattr(binding, "members", None) or []):
                if level == SERVICE_ACCOUNT_LEVEL and member == f"serviceAccount:{resource}":
                    continue  # an account bound on itself (Cloud Build deploying as itself) reaches nobody else
                kind = member_kind(member)
                foreign = kind == "service account" and not inventory.knows(member.split(":", 1)[1])
                key = (level, resource if level != SERVICE_ACCOUNT_LEVEL else project_id_of(result), member, path, role)
                grouped.setdefault(key, {"targets": [], "foreign": foreign, "result": result, "project_number": project_number})
                if level == SERVICE_ACCOUNT_LEVEL:
                    grouped[key]["targets"].append(resource)
    rows, lookups = [], 0
    order = {"organization": 0, "folder": 1, "project": 2, SERVICE_ACCOUNT_LEVEL: 3}
    for (level, resource, member, path, role), entry in sorted(grouped.items(), key=lambda item: (order.get(item[0][0], 9), item[0])):
        kind = member_kind(member)
        targets = sorted(set(entry["targets"]))
        target_roles = set()
        if level == SERVICE_ACCOUNT_LEVEL and kind in ("kubernetes", "service account", "federated", "federated pool", "public", "domain", "other"):
            for target in targets:
                if lookups >= MAX_TARGET_LOOKUPS:
                    break
                lookups += 1
                target_roles |= set(privileged_roles(roles_of_target(target) or ()))
        status = severity(level, path, kind, member=member, target_privileged=tuple(target_roles), foreign=entry["foreign"], organization_scan=organization_scan)
        if status is None:
            continue
        if level == SERVICE_ACCOUNT_LEVEL:
            total = inventory.count_in_project(entry["project_number"])
            reach = f"{len(targets)} of {total} service accounts in projects/{resource}" if total else f"{len(targets)} service account(s)"
            if entry["foreign"]:
                reach += " — the principal is outside the " + ("organization" if organization_scan else "scanned scope")
            label = f"projects/{resource}"
        else:
            total = inventory.count_under(level, resource, entry["result"])
            reach = f"every service account under {resource}" + (f" ({total} in scope)" if total else "")
            label = resource
        rows.append({"Resource": label, "Level": level, "Principal": member, "Path": path, "Reach": reach, "Targets": targets,
                     "Target Roles": sorted(target_roles), "Fix": fix_for(level, path, kind, role, member, targets[0] if targets else ""),
                     "_status": status})
    return rows


class Inventory:
    """The scope's service accounts from one resource search: emails, counts per project, folder and organization; and,
    when given, the active projects (``projects/<number>``), so policies of projects pending deletion are left out."""

    def __init__(self, results, active_projects=None):
        self.emails, self.by_project, self.by_folder, self.total = set(), {}, {}, 0
        # An empty project search means the projects could not be told apart, not that none is active: keep every row then.
        self.active_projects = {str(p).split("/", 1)[-1] for p in active_projects if p} or None if active_projects else None
        for result in results:
            name = getattr(result, "name", "") or ""
            self.emails.add(name.rsplit("/serviceAccounts/", 1)[-1])
            project = (getattr(result, "project", "") or "").split("/", 1)[-1]
            self.by_project[project] = self.by_project.get(project, 0) + 1
            for folder in getattr(result, "folders", None) or []:
                folder = str(folder).split("/", 1)[-1]
                self.by_folder[folder] = self.by_folder.get(folder, 0) + 1
            self.total += 1

    def knows(self, email):
        return email in self.emails

    def is_active(self, project_number):
        return self.active_projects is None or not project_number or project_number in self.active_projects

    def count_in_project(self, project_number):
        return self.by_project.get(project_number, 0)

    def count_under(self, level, resource, result):
        if level == "organization":
            return self.total
        if level == "folder":
            return self.by_folder.get(resource.split("/", 1)[-1], 0)
        return self.count_in_project(target_project(result))


def check_service_account_impersonation(scope, scope_id, job_id, *, sink):
    """Who can become which service account under the scanned scope (v17.1; scope-level)."""
    print(f"🎭 [{job_id}] Checking {IMPERSONATION_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        results = list(asset_client.search_all_iam_policies(request={"scope": parent, "query": SEARCH_QUERY}))
        accounts = asset_client.search_all_resources(request={"scope": parent, "asset_types": [SERVICE_ACCOUNT_ASSET]})
        active = [getattr(r, "project", "") for r in asset_client.search_all_resources(
            request={"scope": parent, "asset_types": [PROJECT_ASSET], "query": "state:ACTIVE"})]
        inventory = Inventory(accounts, active_projects=active)
    except Exception as e:
        logging.error(f"[{job_id}] {IMPERSONATION_CHECK}: could not search the IAM policies under {parent}: {e}")
        sink.write_finding(job_id, IMPERSONATION_CHECK.replace(" ", "_"), {"Check": IMPERSONATION_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped = NotChecked(IMPERSONATION_CHECK)
    custom_roles, target_roles = {}, {}
    iam = None

    def permissions_of_custom_role(role):
        nonlocal iam
        if role not in custom_roles:
            try:
                if iam is None:
                    iam = gcp.api_build("iam", "v1", credentials=credentials)
                collection = iam.organizations().roles() if role.startswith("organizations/") else iam.projects().roles()
                custom_roles[role] = set(collection.get(name=role).execute().get("includedPermissions", []))
            except Exception as e:
                custom_roles[role] = None
                owner = role.split("/roles/", 1)[0]
                skipped.add(owner.split("/", 1)[1] if owner.startswith("projects/") else owner, e, detail=f"custom role {role}")
        return custom_roles[role]

    def roles_of_target(email):
        if email not in target_roles:
            try:
                roles = set()
                for result in asset_client.search_all_iam_policies(request={"scope": parent, "query": f'policy:"{email}"'}):
                    if getattr(result, "asset_type", "") in RESOURCE_LEVELS:
                        for binding in getattr(getattr(result, "policy", None), "bindings", None) or []:
                            if f"serviceAccount:{email}" in list(getattr(binding, "members", None) or []):
                                roles.add(getattr(binding, "role", ""))
                target_roles[email] = roles
            except Exception as e:
                target_roles[email] = None
                skipped.add(email.split("@", 1)[-1].split(".", 1)[0], e, detail=f"roles of {email}")
        return target_roles[email]

    rows = impersonation_rows(results, inventory, permissions_of_custom_role, roles_of_target, organization_scan=(scope == "organization"))
    statuses = {row.pop("_status") for row in rows}
    if "Action Required" in statuses:
        result = {"Check": IMPERSONATION_CHECK, "Finding": rows, "Status": "Action Required"}
    elif rows:
        result = {"Check": IMPERSONATION_CHECK, "Finding": rows, "Status": "Investigation Recommended"}
    else:
        result = {"Check": IMPERSONATION_CHECK, "Status": "Compliant",
                  "Finding": [{"Status": f"No principal can mint tokens for, act as or map onto service accounts beyond its own, "
                                         f"across the {inventory.total} service accounts in scope."}]}
    sink.write_finding(job_id, IMPERSONATION_CHECK.replace(" ", "_"), result)
    skipped.write(sink, job_id)


__all__ = ["IMPERSONATION_CHECK", "PRIVILEGED_ROLES", "check_service_account_impersonation", "impersonation_rows", "member_kind",
           "path_of_role", "severity", "Inventory"]
