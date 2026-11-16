"""
Folders, keys and privileged grants — the secrets (v18.7).

Secret Manager is where the credentials that cannot be keyless live; two things
about it were never read: who can read **every** secret under a project, folder
or the organization, and whether the secrets themselves are tended. Both come
from the inventory under the scope — one IAM-policy search for the three secret
roles on organizations, folders and projects (grants on a secret are the
practice and are not read), one resource search for the secrets and their
versions (the inventory never carries payloads; the Secret Manager API itself
would need ``roles/secretmanager.viewer``, which the scanner does not hold, so
the inventory copy is the source and the rows say so).

- **Secret Access Scope** (Security): ``secretmanager.admin``,
  ``secretAccessor`` or ``secretVersionManager`` granted resource-wide — to the
  public or a whole domain Action Required; to a service account Investigation
  (every workload and key of the account can read every secret under the
  resource); to a person or a group Investigation with at least one secret in
  reach, Informational with none.
- **Secret Manager Posture** (Security): a secret whose newest enabled version
  is older than 90 days with no rotation schedule (Investigation); user-managed
  replication in one location, a secret with no enabled version (Informational).

Google-managed service agents are never rows (``security.principal_kind``).
"""
import logging
from datetime import datetime, timezone

from google.cloud import asset_v1

from app.checks.gke_operations import ACTION_REQUIRED, INFORMATIONAL, INVESTIGATION, write_rows
from app.checks.identity_hygiene import POLICY_TYPES, organization_of, policy_facts, remove_binding
from app.checks.not_checked import NotChecked
from app.checks.privileges import organization_name_domains, search_projects
from app.checks.security import (CONSUMER_ACCOUNT, DEFAULT_SA, DELETED, DOMAIN, EXTERNAL_USER, GOOGLE_MANAGED, GROUP, OTHER_PRINCIPAL, PUBLIC, SERVICE_ACCOUNT, USER,
                                 condition_text, principal_kind)
from app.config import SCOPES
from app.services import gcp

SECRET_SCOPE_CHECK = "Secret Access Scope"
SECRET_POSTURE_CHECK = "Secret Manager Posture"
SECRET_CHECKS = (SECRET_SCOPE_CHECK, SECRET_POSTURE_CHECK)

SECRET_TYPE, VERSION_TYPE = "secretmanager.googleapis.com/Secret", "secretmanager.googleapis.com/SecretVersion"
SECRET_ROLES = ("roles/secretmanager.admin", "roles/secretmanager.secretAccessor", "roles/secretmanager.secretVersionManager")
SECRET_ROLES_QUERY = "roles:(" + " OR ".join(SECRET_ROLES) + ")"
ROTATION_MAX_AGE_DAYS = 90
# People and groups rate Investigation with a secret in reach, Informational with none (the status is lowered in the rule).
SCOPE_STATUS = {PUBLIC: ACTION_REQUIRED, DOMAIN: ACTION_REQUIRED, CONSUMER_ACCOUNT: ACTION_REQUIRED, SERVICE_ACCOUNT: INVESTIGATION, DEFAULT_SA: INVESTIGATION,
                USER: INVESTIGATION, EXTERNAL_USER: INVESTIGATION, GROUP: INVESTIGATION, DELETED: INVESTIGATION, OTHER_PRINCIPAL: INVESTIGATION}
HUMAN_KINDS = (USER, EXTERNAL_USER, GROUP, DELETED, OTHER_PRINCIPAL)

SECRET_SCOPE_ALL_CLEAR = "No principal can read every secret under a project, folder or the organization; secret access is granted per secret."
SECRET_POSTURE_ALL_CLEAR = ("Every secret has an enabled version newer than 90 days or a rotation schedule (single-location replication and empty "
                            "secrets are listed for information).")


# --- the inventory ----------------------------------------------------------------------------------------------------

def _parse_time(text):
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def search_secrets(asset_client, parent):
    """``(secrets, versions)`` under ``parent`` from the search index: each ``{name, short, project (number), folders, data}``, ``data`` the
    resource as the index carries it (replication, rotation, topics; a version's state and creation time)."""
    secrets, versions = [], []
    results = asset_client.search_all_resources(request={"scope": parent, "asset_types": [SECRET_TYPE, VERSION_TYPE], "read_mask": "*", "page_size": 500})
    for result in results:
        name = str(getattr(result, "name", "") or "")
        parts = name.split("/")
        resource = {"name": name.split("//secretmanager.googleapis.com/")[-1], "short": parts[parts.index("secrets") + 1] if "secrets" in parts else parts[-1],
                    "project": str(getattr(result, "project", "") or "").rsplit("/", 1)[-1], "folders": [str(f).rsplit("/", 1)[-1] for f in (getattr(result, "folders", None) or [])],
                    "create_time": getattr(result, "create_time", None)}
        shown = list(getattr(result, "versioned_resources", None) or [])
        if shown:
            version = shown[0]
            resource["data"] = (version.get("resource") if isinstance(version, dict) else asset_v1.VersionedResource.to_dict(version).get("resource")) or {}
        else:
            resource["data"] = {}
        (versions if str(getattr(result, "asset_type", "")) == VERSION_TYPE or "/versions/" in name else secrets).append(resource)
    return secrets, versions


def secrets_in_reach(secrets, policy):
    """How many of ``secrets`` a resource-wide grant on ``policy['resource']`` reaches: the project's (by number), the folder's descendants', all."""
    level = policy["level"]
    if level == "organization":
        return len(secrets)
    if level == "folder":
        folder_id = policy["resource"].rsplit("/", 1)[-1]
        return sum(1 for secret in secrets if folder_id in secret["folders"])
    numbers = {a.rsplit("/", 1)[-1] for a in policy["ancestors"] if a.startswith("projects/")}
    return sum(1 for secret in secrets if secret["project"] in numbers)


# --- Secret Access Scope ------------------------------------------------------------------------------------------------

def secret_scope_rows(policies, secrets, org_domains=()):
    """One row per (resource, principal, role) for the secret roles granted resource-wide, with the secrets in reach, kind, condition, fix and ``_status``."""
    rows = []
    for policy in policies:
        resource, reach = policy["resource"], secrets_in_reach(secrets, policy)
        kind_, target = resource.split("/", 1)
        for role, members, condition in policy["bindings"]:
            if role not in SECRET_ROLES:
                continue
            for member in members:
                kind = principal_kind(member, org_domains)
                if kind == GOOGLE_MANAGED:
                    continue
                status = SCOPE_STATUS[kind]
                if status == INVESTIGATION and kind in HUMAN_KINDS and reach == 0:
                    status = INFORMATIONAL
                project_flag = f" --project={target}" if kind_ == "projects" else ""
                rows.append({"Resource": resource, "Principal": member, "Type": kind, "Role": role, "Secrets in reach": reach, "Condition": condition_text({"condition": condition}),
                             "Fix": (remove_binding(resource, member, role, condition)
                                     + f" && gcloud secrets add-iam-policy-binding SECRET{project_flag} --member={member} --role={role}  # per secret the principal needs"),
                             "_status": status})
    return rows


# --- Secret Manager Posture ---------------------------------------------------------------------------------------------

def secret_posture_rows(secrets, versions, project_names=None, now=None):
    """The posture rows: stale without a schedule (Investigation), single-location replication and no enabled version (Informational)."""
    now, project_names, rows = now or datetime.now(timezone.utc), project_names or {}, []
    newest = {}
    for version in versions:
        if str(version["data"].get("state") or "") != "ENABLED":
            continue
        secret_name, created = version["name"].rsplit("/versions/", 1)[0], _parse_time(version["data"].get("createTime")) or version["create_time"]
        if created is not None and (secret_name not in newest or created > newest[secret_name]):
            newest[secret_name] = created
    for secret in secrets:
        data, project = secret["data"], project_names.get(secret["project"], secret["project"])
        common = {"Project": project, "Secret": secret["short"]}
        replication = data.get("replication") or {}
        replicas = (replication.get("userManaged") or {}).get("replicas") or []
        latest = newest.get(secret["name"])
        if latest is None:
            rows.append({**common, "Issue": "No enabled version.", "Detail": "The secret exists but nothing can be read from it (no version, or every version disabled or destroyed); housekeeping.",
                         "Fix": f"gcloud secrets delete {secret['short']} --project={project}", "_status": INFORMATIONAL})
        elif not data.get("rotation") and (now - latest).days > ROTATION_MAX_AGE_DAYS:
            age = (now - latest).days
            rows.append({**common, "Issue": "Stale secret without a rotation schedule.",
                         "Detail": f"The newest enabled version is {age} days old and no rotation schedule exists: a static credential whose exposure nobody would notice (from the inventory).",
                         "Fix": (f"gcloud secrets versions add {secret['short']} --project={project} --data-file=/path/to/new-value && gcloud secrets versions disable OLD --secret={secret['short']} --project={project}"
                                 f"  # or schedule it: gcloud secrets update {secret['short']} --project={project} --next-rotation-time=… --rotation-period={ROTATION_MAX_AGE_DAYS}d --topics=projects/{project}/topics/TOPIC"),
                         "_status": INVESTIGATION})
        if "userManaged" in replication and len(replicas) < 2:
            where = ", ".join(str(r.get("location") or "") for r in replicas) or "one location"
            rows.append({**common, "Issue": "Single-location replication.", "Detail": f"Replicated in {where} only: an outage there takes the secret with it (often a residency choice; replication cannot change in place).",
                         "Fix": f"gcloud secrets create {secret['short']}-2 --project={project} --replication-policy=automatic  # add the versions, repoint the readers", "_status": INFORMATIONAL})
    return rows


# --- the check --------------------------------------------------------------------------------------------------------

def check_secret_posture(scope, scope_id, job_id, *, sink, now=None):
    """Writes *Secret Access Scope* and *Secret Manager Posture* from one IAM-policy search and one resource search under the scope."""
    print(f"🔐 [{job_id}] Checking {SECRET_SCOPE_CHECK} and {SECRET_POSTURE_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        secrets, versions = search_secrets(asset_client, parent)
        policies = [policy_facts(result) for result in asset_client.search_all_iam_policies(request={"scope": parent, "query": SECRET_ROLES_QUERY, "asset_types": POLICY_TYPES, "page_size": 500})]
    except Exception as e:
        logging.error(f"[{job_id}] {SECRET_SCOPE_CHECK}: could not read the secrets or their policies under {parent}: {e}")
        for check in SECRET_CHECKS:
            sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped, org_domains, project_names = NotChecked(SECRET_SCOPE_CHECK), (), {}
    if policies:
        try:
            organization = organization_of(policies, scope, scope_id)
            if not organization:
                raise LookupError("no organization among the policies' ancestors")
            org_domains = organization_name_domains(gcp.api_build("cloudresourcemanager", "v1", credentials=credentials), organization)
        except Exception as e:
            skipped.add(parent, e, detail="external-domain rule: the organization's domain could not be read")
    if secrets:
        try:
            project_names = {project["number"]: project["id"] for project in search_projects(asset_client, parent) if project["number"]}
        except Exception as e:
            logging.info(f"[{job_id}] {SECRET_POSTURE_CHECK}: projects named by number ({e})")
    write_rows(sink, job_id, SECRET_SCOPE_CHECK, secret_scope_rows(policies, secrets, org_domains), SECRET_SCOPE_ALL_CLEAR)
    write_rows(sink, job_id, SECRET_POSTURE_CHECK, secret_posture_rows(secrets, versions, project_names, now), SECRET_POSTURE_ALL_CLEAR)
    skipped.write(sink, job_id)
