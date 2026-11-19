"""
VM hardening & identities, the Compute half (v18.5).

CIS §4 Level-1 items and the matching Security Health Analytics detectors. The
scope's instances and compute projects come from Cloud Asset Inventory in one
read (the search index first — v18.5's fresh reads), which says **which
projects have VMs**; the facts the rules judge then come from the **Compute
API** per such project (``instances.aggregatedList``, ``projects.get``): the
inventory reflects a *change* to an instance or to a project's metadata hours
late on either read path, and omits the ``ssh-keys`` metadata item altogether
(measured against the API) — and the project-wide-keys rule needs the keys. The
inventory's copy is the fallback when an API read is refused, noted under
*Projects not checked*.

- **VM Service Accounts** (Security): a VM that runs as the Compute Engine or
  App Engine *default* service account. Action Required when the account holds
  a privileged role (``gke_security.PRIVILEGED_ROLES``, read with the IAM
  search GKE Credential Exposure runs) or the VM has the ``cloud-platform``
  scope; Investigation otherwise. A dedicated account is never a row.
- **VM Hardening** (Security): OS Login off and project-wide SSH keys as one
  row per project; an instance's own OS Login override, serial console, IP
  forwarding, Shielded VM and Secure Boot per instance.

Google-managed fleets — GKE nodes (GKE Credential Exposure and Node Hardening
own them), Dataproc, Dataflow, Vertex Workbench — are not judged
(``MANAGED_FLEET_LABELS``). Stopped instances are: their configuration waits
for the next start, and the row says so.
"""
import logging
import re

from app.checks.gke_operations import ACTION_REQUIRED, INVESTIGATION, write_rows
from app.checks.gke_security import CLOUD_PLATFORM_SCOPE, SCOPE_PREFIX, account_roles, privileged_roles
from app.checks.network_edge import by_kind, list_assets, tail
from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp

VM_SA_CHECK = "VM Service Accounts"
VM_HARDENING_CHECK = "VM Hardening"
VM_CHECKS = (VM_SA_CHECK, VM_HARDENING_CHECK)
VM_TYPES = ["compute.googleapis.com/Instance", "compute.googleapis.com/Project"]

VM_SA_ALL_CLEAR = "No VM runs as the Compute Engine or App Engine default service account (GKE, Dataproc, Dataflow and Workbench fleets aside)."
VM_HARDENING_ALL_CLEAR = ("Every project with VMs enforces OS Login, no project-wide SSH key or serial console is enabled, and every VM is a "
                          "Shielded VM with Secure Boot and without IP forwarding.")

DEFAULT_ACCOUNT = re.compile(r"^(?:\d+-compute@developer\.gserviceaccount\.com|[^@]+@appspot\.gserviceaccount\.com)$")
# Labels Google puts on the instances of the fleets it manages; such an instance is judged by the checks of its product, not here.
MANAGED_FLEET_LABELS = ("goog-gke-node", "goog-dataproc-cluster-name", "goog-dataflow-job-id", "dataflow_job_id", "goog-caip-notebook",
                        "goog-composer-environment")
PROJECT_ROW = "(project)"
TRUE_VALUES = ("true", "1", "y", "yes")


def is_true(value):
    return str(value or "").strip().lower() in TRUE_VALUES


def is_false(value):
    return str(value or "").strip().lower() in ("false", "0", "n", "no")


def metadata_items(block):
    """``{key: value}`` of an instance's ``metadata`` or a project's ``commonInstanceMetadata``."""
    return {str(item.get("key")): str(item.get("value", "")) for item in (block or {}).get("items") or [] if item.get("key")}


def is_default_account(email):
    return bool(DEFAULT_ACCOUNT.match(str(email or "")))


def is_managed_fleet(data):
    labels = data.get("labels") or {}
    return any(label in labels for label in MANAGED_FLEET_LABELS) or str(data.get("name") or "").startswith("gke-")


def instance_facts(fact):
    """What the rules read of one instance: its scopes without the prefix, its metadata as a map, its Shielded settings."""
    data = fact["data"]
    accounts = [(sa.get("email") or "", [str(s).replace(SCOPE_PREFIX, "") for s in (sa.get("scopes") or [])]) for sa in data.get("serviceAccounts") or []]
    metadata = metadata_items(data.get("metadata"))
    shielded = data.get("shieldedInstanceConfig")
    return {"project_id": fact["project_id"], "name": fact["name"], "zone": tail(data.get("zone")) or fact["region"], "status": str(data.get("status") or ""),
            "accounts": accounts, "metadata": metadata, "ip_forwarding": bool(data.get("canIpForward")), "managed": is_managed_fleet(data),
            "shielded": None if shielded is None else {k: bool((shielded or {}).get(k)) for k in ("enableSecureBoot", "enableVtpm", "enableIntegrityMonitoring")},
            "created_by": metadata.get("created-by", "")}


def instance_update(vm, verb, flags):
    return f"gcloud compute instances {verb} {vm['name']} --zone={vm['zone']} --project={vm['project_id']} {flags}"


# --- VM Service Accounts ----------------------------------------------------------------------------------------------

def default_accounts_in_use(vms):
    """The distinct default service accounts the judged instances run as, in first-seen order."""
    seen = []
    for vm in vms:
        for email, _ in vm["accounts"]:
            if is_default_account(email) and email not in seen:
                seen.append(email)
    return seen


def vm_service_account_rows(vms, roles_by_account):
    """The *VM Service Accounts* rows: one per judged instance on a default account. ``roles_by_account`` maps an account to its roles
    at project, folder or organization level, or to ``None`` when they could not be read."""
    rows = []
    for vm in vms:
        if vm["managed"]:
            continue
        for email, scopes in vm["accounts"]:
            if not is_default_account(email):
                continue
            roles = roles_by_account.get(email)
            privileged, full = privileged_roles(roles), CLOUD_PLATFORM_SCOPE in scopes
            if full:
                issue = "Default service account with full API access."
                detail = f"Every role of the account is reachable from the VM (scope cloud-platform); it holds {', '.join(privileged) if privileged else 'no privileged role'} on the project (CIS 4.2)."
            else:
                issue = "Default service account."
                if privileged:
                    detail = f"The account holds {privileged[0]} on the project; the scopes limit a stolen token to {', '.join(scopes) or 'nothing'}, not whose roles it carries (CIS 4.1)."
                elif roles is None:
                    detail = "The account's roles could not be read; the scopes are " + (", ".join(scopes) or "none") + " (CIS 4.1)."
                else:
                    detail = f"The account holds no privileged role; scopes {', '.join(scopes) or 'none'} (CIS 4.1)."
            status = ACTION_REQUIRED if (full or privileged) else INVESTIGATION
            if "/instanceGroupManagers/" in vm["created_by"]:
                fix = (f"the instance was created by {tail(vm['created_by'])}: give its instance template a dedicated service account "
                       f"(gcloud compute instance-templates create … --service-account=<account> --scopes=cloud-platform) and roll the group")
            else:
                fix = (instance_update(vm, "stop", "&& " + instance_update(vm, "set-service-account", "--service-account=<dedicated account> --scopes=cloud-platform"))
                       + "  # create the account with the roles the workload needs first")
            rows.append({"Project": vm["project_id"], "Instance": vm["name"], "Zone": vm["zone"], "Status": vm["status"], "Service Account": email,
                         "Scopes": ", ".join(scopes), "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})
    return rows


# --- VM Hardening -----------------------------------------------------------------------------------------------------

def vm_hardening_rows(vms, projects):
    """The *VM Hardening* rows. ``projects``: ``{project_id: common instance metadata}`` of the compute projects listed."""
    rows = []

    def row(project_id, instance, zone, status, issue, detail, fix):
        rows.append({"Project": project_id, "Instance": instance, "Zone": zone, "Status": status, "Issue": issue, "Detail": detail, "Fix": fix, "_status": INVESTIGATION})

    judged = [vm for vm in vms if not vm["managed"]]
    by_project = {}
    for vm in judged:
        by_project.setdefault(vm["project_id"], []).append(vm)
    for project_id in sorted(by_project):
        metadata, instances = projects.get(project_id, {}), by_project[project_id]
        project_oslogin = is_true(metadata.get("enable-oslogin"))
        project_fix = f"gcloud compute project-info add-metadata --project={project_id} --metadata="
        if not project_oslogin:
            self_enabled = sum(1 for vm in instances if is_true(vm["metadata"].get("enable-oslogin")))
            row(project_id, PROJECT_ROW, "", "", "OS Login off for the project.",
                f"{len(instances)} instance(s); {self_enabled} enable it themselves, the rest authenticate with metadata SSH keys (CIS 4.4).",
                f"{project_fix}enable-oslogin=TRUE")
            if metadata.get("ssh-keys") or metadata.get("sshKeys"):
                keys = [k for k in (metadata.get("ssh-keys") or metadata.get("sshKeys") or "").splitlines() if k.strip()]
                reached = [vm for vm in instances if not is_true(vm["metadata"].get("block-project-ssh-keys")) and not is_true(vm["metadata"].get("enable-oslogin"))]
                row(project_id, PROJECT_ROW, "", "", "Project-wide SSH keys in use.",
                    f"{len(keys)} key(s) in the project metadata reach {len(reached)} instance(s) without block-project-ssh-keys (CIS 4.3).",
                    f"{project_fix}enable-oslogin=TRUE  # or per instance: gcloud compute instances add-metadata <name> --metadata=block-project-ssh-keys=TRUE")
        if is_true(metadata.get("serial-port-enable")):
            row(project_id, PROJECT_ROW, "", "", "Serial console enabled for the project.", "Every instance answers on the interactive serial console (CIS 4.5).",
                f"gcloud compute project-info remove-metadata --project={project_id} --keys=serial-port-enable")
        for vm in instances:
            if project_oslogin and is_false(vm["metadata"].get("enable-oslogin")):
                row(project_id, vm["name"], vm["zone"], vm["status"], "OS Login off on the instance.", "The instance opts out of the project's OS Login and takes metadata SSH keys (CIS 4.4).",
                    instance_update(vm, "remove-metadata", "--keys=enable-oslogin"))
            if is_true(vm["metadata"].get("serial-port-enable")):
                row(project_id, vm["name"], vm["zone"], vm["status"], "Serial console enabled.", "The interactive serial console is reachable with a project SSH key from anywhere (CIS 4.5).",
                    instance_update(vm, "remove-metadata", "--keys=serial-port-enable"))
            if vm["ip_forwarding"]:
                row(project_id, vm["name"], vm["zone"], vm["status"], "IP forwarding on.", "Legitimate for a router or NAT appliance; otherwise a spoofing path (CIS 4.6). canIpForward cannot be changed on an existing instance.",
                    "recreate the instance without --can-ip-forward, or document the appliance")
            shielded = vm["shielded"]
            if shielded is None:
                row(project_id, vm["name"], vm["zone"], vm["status"], "Shielded VM off.", "The image is not Shielded-capable: no vTPM, no integrity monitoring, no Secure Boot (CIS 4.8).",
                    "migrate to a Shielded VM image (every current Google image is one)")
            elif not (shielded["enableVtpm"] and shielded["enableIntegrityMonitoring"]):
                off = [name for key, name in (("enableVtpm", "vTPM"), ("enableIntegrityMonitoring", "integrity monitoring")) if not shielded[key]]
                row(project_id, vm["name"], vm["zone"], vm["status"], "Shielded VM off.", f"{' and '.join(off)} off (CIS 4.8).",
                    instance_update(vm, "update", "--shielded-vtpm --shielded-integrity-monitoring") + "  # the instance must be stopped")
            elif not shielded["enableSecureBoot"]:
                row(project_id, vm["name"], vm["zone"], vm["status"], "Secure Boot off.", "Unsigned kernels and drivers load; some images lack signed bootloaders — then a documented exception.",
                    instance_update(vm, "update", "--shielded-secure-boot") + "  # the instance must be stopped")
    return rows


# --- the check --------------------------------------------------------------------------------------------------------

def api_instances(compute, project_id):
    """Every instance of ``project_id`` from the Compute API (``instances.aggregatedList``, paged), as facts."""
    found, request = [], compute.instances().aggregatedList(project=project_id)
    while request:
        response = request.execute()
        for scoped in (response.get("items") or {}).values():
            for data in scoped.get("instances") or []:
                found.append(instance_facts({"project_id": project_id, "name": data.get("name") or "", "region": "", "data": data}))
        request = compute.instances().aggregatedList_next(previous_request=request, previous_response=response)
    return found


def refresh_from_api(vms, projects, compute, skipped):
    """The instances and the common instance metadata of every project with judged instances, read from the Compute API: the
    inventory told which projects to ask (and serves as the copy of record when a read fails, noted under *Projects not checked*).
    Returns ``(vms, projects)`` with the API's facts replacing the inventory's for the projects read."""
    project_ids = sorted({vm["project_id"] for vm in vms if not vm["managed"]})
    for project_id in project_ids:
        try:
            projects[project_id] = metadata_items(compute.projects().get(project=project_id).execute().get("commonInstanceMetadata"))
        except Exception as e:
            skipped.add(project_id, e, detail="project metadata: the Compute API read failed; the inventory's copy was used, which lags and omits ssh-keys")
        try:
            fresh = api_instances(compute, project_id)
        except Exception as e:
            skipped.add(project_id, e, detail="instances: the Compute API read failed; the inventory's copy was used, which can lag changes by hours")
            continue
        vms = [vm for vm in vms if vm["project_id"] != project_id] + fresh
    return vms, projects


def check_vm_posture(scope, scope_id, job_id, *, sink):
    """Writes *VM Service Accounts* and *VM Hardening*: the scope's instances and compute projects from the inventory (which projects
    have VMs, and the copy of record if the API is refused), then each such project's instances and metadata from the Compute API."""
    print(f"🖥️ [{job_id}] Checking {VM_SA_CHECK} and {VM_HARDENING_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        grouped = by_kind(list_assets(asset_client, parent, VM_TYPES))
    except Exception as e:
        logging.error(f"[{job_id}] {VM_SA_CHECK}: could not list under {parent}: {e}")
        for check in VM_CHECKS:
            sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    vms = [instance_facts(fact) for fact in grouped.get("instances", [])]
    projects = {fact["name"]: metadata_items(fact["data"].get("commonInstanceMetadata")) for fact in grouped.get("projects", [])}  # the fallback
    skipped, hardening_skipped, roles_by_account = NotChecked(VM_SA_CHECK), NotChecked(VM_HARDENING_CHECK), {}
    vms, projects = refresh_from_api(vms, projects, gcp.api_build("compute", "v1", credentials=credentials), hardening_skipped)
    for email in default_accounts_in_use([vm for vm in vms if not vm["managed"]]):
        try:
            roles_by_account[email] = account_roles(asset_client, parent, email)
        except Exception as e:
            roles_by_account[email] = None
            skipped.add(parent, e, detail=f"roles of {email}: the IAM search failed")
    write_rows(sink, job_id, VM_SA_CHECK, vm_service_account_rows(vms, roles_by_account), VM_SA_ALL_CLEAR)
    write_rows(sink, job_id, VM_HARDENING_CHECK, vm_hardening_rows(vms, projects), VM_HARDENING_ALL_CLEAR)
    skipped.write(sink, job_id)
    hardening_skipped.write(sink, job_id)
