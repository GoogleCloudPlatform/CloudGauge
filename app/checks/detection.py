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
"""Detection (v19.1): the detective half of the SSRF chain, over the Admin Activity audit logs of the last seven days.

Two records from ``entries.list`` (``roles/logging.viewer``), newest first, ``ENTRY_CAP`` entries per read at most (a capped
read says so). A read names **one parent**: ``entries.list`` on ``organizations/<id>`` returns the organization's *own* entries,
not its projects' (the sandbox probe proved it — the v19 survey's organization query saw only the organization-level IAM churn),
so the GKE record reads **every project in scope** (the ``k8s_cluster`` audit log is a project's) and the service-account record
reads the organization's or folder's own entries **and** every project's — a split check in a sharded scan
(``registry.SPLIT_CHECKS``: the scope shard reads the parent, the project shards their projects). Google's own principals
(``system:*``, the ``gcp-sa-*`` agents, ``@system.gserviceaccount.com``, the GKE robot) are left out: on the reference
organization every control-plane write of a month and every IAM change of a week was theirs. Caller addresses are
classed internal (``private``, loopback, RFC 1918, link-local) or external.

- **GKE Control Plane Activity** (Security & Identity): exec, attach and port-forward into pods, DaemonSets and
  CronJobs created in ``kube-system``, bindings to ``cluster-admin`` created or changed, admission webhooks created or
  changed — by whom, from where, how often. A user's exec is Informational (operations, named); a service account's is
  Investigation, **Action Required** from an external address; ``cluster-admin`` bindings Investigation by a user,
  **Action Required** by a service account; ``kube-system`` workloads and webhooks Investigation, **Action Required**
  by a service account from outside (an external address escalates service accounts only: people work from laptops). Secrets reads are Data Access logs — not recorded on most
  organizations and not readable by ``roles/logging.viewer`` — and are not judged; the all-clear says so.
- **Service Account Activity Signals** (Security & Identity): service accounts creating keys, changing IAM policies
  (project, folder, organization, service account), writing instance or project metadata — Investigation, **Action
  Required** from an external address; creating service accounts — Informational (a project factory does). Token
  minting (``GenerateAccessToken`` and friends) is Data Access and not read; the all-clear says so.
"""
import concurrent.futures
import ipaddress
import re
from datetime import timedelta

from app.checks.gke_operations import ACTION_REQUIRED, INFORMATIONAL, INVESTIGATION, write_rows
from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp
from app.utils import utcnow

GKE_ACTIVITY_CHECK = "GKE Control Plane Activity"
SA_SIGNALS_CHECK = "Service Account Activity Signals"
DETECTION_CHECKS = (GKE_ACTIVITY_CHECK, SA_SIGNALS_CHECK)

WINDOW_DAYS = 7
PAGE_SIZE = 1000
ENTRY_CAP = 2000
READERS = 10  # parents read at a time
ACTIVITY_LOG = 'logName:"cloudaudit.googleapis.com%2Factivity"'
# An exec over SPDY (classic kubectl) is a POST — ``pods.exec.create``; over WebSockets (kubectl ≥ 1.31, client libraries) a GET — ``pods.exec.get``. Both are the shell.
GKE_METHODS = ('protoPayload.methodName=~"io.k8s.core.v1.pods.(exec|attach|portforward).(create|get)"',
               'protoPayload.methodName=~"io.k8s.apps.v1.daemonsets.create"', 'protoPayload.methodName=~"io.k8s.batch.v1.cronjobs.create"',
               'protoPayload.methodName=~"io.k8s.authorization.rbac.v1.clusterrolebindings.(create|patch|update)"',
               'protoPayload.methodName=~"io.k8s.admissionregistration.k8s.io.v1.(mutating|validating)webhookconfigurations.(create|update|patch)"')
SA_METHODS = ('protoPayload.methodName=~"CreateServiceAccountKey$"', 'protoPayload.methodName=~"SetIamPolicy$"',
              'protoPayload.methodName=~"setCommonInstanceMetadata$"', 'protoPayload.methodName=~"compute.instances.setMetadata$"',
              'protoPayload.methodName=~"CreateServiceAccount$"')
GOOGLE_PRINCIPAL = re.compile(r"^(?:system:|.+@gcp-sa-[^@]+\.iam\.gserviceaccount\.com$|.+@system\.gserviceaccount\.com$|.+@container-engine-robot\.iam\.gserviceaccount\.com$|"
                              r".+@cloudservices\.gserviceaccount\.com$|.+@containerregistry\.iam\.gserviceaccount\.com$)")
NOT_GOOGLE = ("system:anonymous", "system:unauthenticated")  # the unauthenticated caller is nobody's
MANAGED_NAMESPACES = ("kube-system", "kube-public", "kube-node-lease")  # a Kubernetes service account here (or under gke-*, gmp-*) is GKE's own; elsewhere it is a workload
INTERNAL_WORDS = ("private", "gce-internal-ip", "internal")
# RFC 1918, shared address space, loopback, link-local, ULA and IPv6 loopback — spelled out rather than ``is_private``, whose meaning moved between Python releases.
INTERNAL_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"))
GKE_ALL_CLEAR = ("No exec, attach, port-forward, kube-system DaemonSet or CronJob, cluster-admin binding or admission webhook change by a principal other than "
                 "Google's own in the last 7 days (secrets reads are Data Access logs and are not read).")
SA_ALL_CLEAR = ("No service account other than Google's own created a key, changed an IAM policy or wrote instance metadata in the last 7 days "
                "(token minting is a Data Access log and is not read).")


# --- the log reader ------------------------------------------------------------------------------------------------------

def log_filter(since, methods):
    return f'timestamp>="{since}" AND {ACTIVITY_LOG} AND ({" OR ".join(methods)})'


def read_entries(logging_api, parent, log_filter_text, cap=ENTRY_CAP, page_size=PAGE_SIZE):
    """``(entries, capped)`` — the newest entries under ``parent`` matching the filter, ``cap`` at most."""
    entries, token = [], None
    while True:
        body = {"resourceNames": [parent], "filter": log_filter_text, "orderBy": "timestamp desc", "pageSize": min(page_size, cap - len(entries))}
        if token:
            body["pageToken"] = token
        response = logging_api.entries().list(body=body).execute() or {}
        entries += response.get("entries") or []
        token = response.get("nextPageToken")
        if not token:
            return entries, False
        if len(entries) >= cap:
            return entries[:cap], True


def read_parent(parent, prefix, methods, since):
    """``(entries, capped)`` of one parent (``projects/<id>``, ``organizations/<number>``, ``folders/<number>``) for the window and the methods."""
    credentials, _ = gcp.auth_default(scopes=SCOPES)
    logging_api = gcp.api_build("logging", "v2", credentials=credentials)
    return read_entries(logging_api, parent, prefix + log_filter(since, methods), ENTRY_CAP, PAGE_SIZE)


def read_parents(parents, prefix, methods, rows_of, skipped):
    """The rows of every parent, read ``READERS`` at a time; a parent whose read fails is noted under *Projects not checked* and the rest stands."""
    since = (utcnow() - timedelta(days=WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def read(parent):
        try:
            entries, capped = read_parent(parent, prefix, methods, since)
            return rows_of(entries, capped)
        except Exception as e:  # noqa: BLE001 — one parent's failure is one row under Projects not checked
            skipped.add(parent.split("/", 1)[1] if parent.startswith("projects/") else parent, e)
            return []

    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=READERS) as executor:
        for parent_rows in executor.map(read, parents):
            rows.extend(parent_rows)
    return rows


def is_google_principal(email):
    """Google's own principals (module docstring). A Kubernetes service account (``system:serviceaccount:<namespace>:<name>``) is Google's only in
    the GKE-managed namespaces; one in a workload namespace is the workload itself — the very caller the exec rule is for."""
    text = str(email or "")
    if text in NOT_GOOGLE:
        return False
    if text.startswith("system:serviceaccount:"):
        namespace = text.split(":")[2] if text.count(":") >= 3 else ""
        return namespace in MANAGED_NAMESPACES or namespace.startswith(("gke-", "gmp-"))
    return bool(GOOGLE_PRINCIPAL.match(text))


def is_service_account(email):
    return str(email or "").endswith(".gserviceaccount.com") or str(email or "").startswith("system:serviceaccount:")


def ip_class(address):
    """``internal`` for the API's own words (``private``, ``gce-internal-ip``) and ``INTERNAL_NETWORKS``; ``external`` for any other address; ``unknown`` when absent or not an address."""
    text = str(address or "").strip()
    if not text:
        return "unknown"
    if text.lower() in INTERNAL_WORDS:
        return "internal"
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    return "internal" if any(ip in network for network in INTERNAL_NETWORKS) else "external"


def log_parent(entry, labels):
    """Where the entry was written: the project ID from the resource labels or the log name, else the organization or folder (``organizations/<number>``)."""
    if labels.get("project_id"):
        return str(labels["project_id"])
    parent = str(entry.get("logName") or "").split("/logs/")[0]
    return parent.rsplit("/", 1)[-1] if parent.startswith("projects/") else parent


def parent_flag(parent):
    """The ``gcloud logging read`` flag that names ``parent`` — ``--project=<id>``, ``--organization=<number>`` or ``--folder=<number>``."""
    kind, _, number = parent.partition("/")
    return f"--{kind[:-1]}={number}" if number and kind in ("organizations", "folders") else f"--project={parent}"


def entry_facts(entry):
    payload = entry.get("protoPayload") or {}
    labels = (entry.get("resource") or {}).get("labels") or {}
    request_metadata = payload.get("requestMetadata") or {}
    return {"method": str(payload.get("methodName") or ""), "principal": str((payload.get("authenticationInfo") or {}).get("principalEmail") or ""),
            "ip": str(request_metadata.get("callerIp") or ""), "ip_class": ip_class(request_metadata.get("callerIp")), "resource": str(payload.get("resourceName") or ""),
            "project": log_parent(entry, labels), "cluster": str(labels.get("cluster_name") or ""), "email": str(labels.get("email_id") or ""),
            "location": str(labels.get("location") or ""), "timestamp": str(entry.get("timestamp") or ""), "request": payload.get("request") or {},
            "denied": bool((payload.get("status") or {}).get("code"))}  # a non-zero status: the call was refused (IAM, an organization policy) — an attempt, still a signal


def denied_note(group):
    """`` All of them were denied.`` / `` 2 of them were denied.`` — the refused calls of a group; nothing when every call went through."""
    denied, count = group["denied"], group["count"]
    if not denied:
        return ""
    return " All of them were denied." if denied == count else f" {denied} of them {'was' if denied == 1 else 'were'} denied."


# --- GKE Control Plane Activity ---------------------------------------------------------------------------------------------

def gke_action(fact):
    """The action family of an entry, or None when the entry is not one the rules judge (a DaemonSet outside kube-system, a binding to another role)."""
    method, resource, request = fact["method"], fact["resource"], fact["request"]
    if re.search(r"pods\.(exec|attach|portforward)\.(create|get)$", method):
        return "exec"
    if method.endswith("daemonsets.create") or method.endswith("cronjobs.create"):
        return "kube-system workload" if "/namespaces/kube-system/" in resource else None
    if "clusterrolebindings" in method:
        role = str(((request.get("roleRef") or {}).get("name")) or "")
        return "cluster-admin binding" if role == "cluster-admin" or (not role and "cluster-admin" in resource) else None
    if "webhookconfigurations" in method:
        return "webhook change"
    return None


def gke_status(action, service_account, external):
    """The ladder: a user's exec is operations; a service account's is Investigation, Action Required from outside; ``cluster-admin`` granted is Investigation
    by a user, Action Required by a service account; ``kube-system`` workloads and webhooks Investigation, Action Required by a service account from outside.
    An external address escalates service accounts only — people work from laptops, which are outside by nature (the sandbox probe's admin was)."""
    if action == "exec":
        return (ACTION_REQUIRED if external else INVESTIGATION) if service_account else INFORMATIONAL
    if action == "cluster-admin binding":
        return ACTION_REQUIRED if service_account else INVESTIGATION
    return ACTION_REQUIRED if service_account and external else INVESTIGATION


GKE_ISSUE = {"exec": "Shell into a pod.", "kube-system workload": "Workload created in kube-system.", "cluster-admin binding": "cluster-admin granted.", "webhook change": "Admission webhook changed."}


def gke_rows(entries, capped=False):
    groups = {}
    for entry in entries:
        fact = entry_facts(entry)
        if is_google_principal(fact["principal"]):
            continue
        action = gke_action(fact)
        if action is None:
            continue
        key = (fact["project"], fact["cluster"] or "?", action, fact["principal"] or "?", fact["ip_class"])
        group = groups.setdefault(key, {"count": 0, "denied": 0, "latest": "", "resources": [], "ips": set()})
        group["count"] += 1
        group["denied"] += fact["denied"]
        group["latest"] = max(group["latest"], fact["timestamp"])
        if fact["resource"] and fact["resource"] not in group["resources"]:
            group["resources"].append(fact["resource"])
        if fact["ip"]:
            group["ips"].add(fact["ip"])
    rows = []
    for (project, cluster, action, principal, ip_cls), group in sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        service_account, external = is_service_account(principal), ip_cls == "external"
        who = "service account" if service_account else "user"
        where = f"{ip_cls} address{'es' if len(group['ips']) > 1 else ''} ({', '.join(sorted(group['ips'])[:3])})" if group["ips"] else "an unknown address"
        targets = ", ".join(r.split("/", 2)[-1][-80:] for r in group["resources"][:3]) + (f" +{len(group['resources']) - 3}" if len(group["resources"]) > 3 else "")
        rows.append({"Project": project, "Cluster": cluster, "Action": action, "Principal": principal, "From": ip_cls, "Count": group["count"], "Latest": group["latest"][:16].replace("T", " "),
                     "Issue": GKE_ISSUE[action],
                     "Detail": f"{group['count']} {action} event{'s' if group['count'] != 1 else ''} by the {who} {principal} from {where} in the last {WINDOW_DAYS} days: {targets}."
                               + denied_note(group) + (" The read stopped at the cap; older events are not counted." if capped else ""),
                     "Fix": (f"gcloud logging read 'resource.type=\"k8s_cluster\" AND resource.labels.cluster_name=\"{cluster}\" AND protoPayload.authenticationInfo.principalEmail=\"{principal}\"' "
                             f"{parent_flag(project)} --freshness={WINDOW_DAYS}d --limit=50  # then remove the RBAC that allows it, or the principal's access"),
                     "_status": gke_status(action, service_account, external)})
    return rows


def check_gke_activity(scope_id, all_projects, job_id, *, sink):
    """Writes *GKE Control Plane Activity* over every project in scope (module docstring): the ``k8s_cluster`` audit log is a project's."""
    print(f"🕵️  [{job_id}] Checking {GKE_ACTIVITY_CHECK} in {len(all_projects)} projects...")
    skipped = NotChecked(GKE_ACTIVITY_CHECK)
    rows = read_parents([f"projects/{p['projectId']}" for p in all_projects], 'resource.type="k8s_cluster" AND ', GKE_METHODS, gke_rows, skipped)
    write_rows(sink, job_id, GKE_ACTIVITY_CHECK, rows, GKE_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- Service Account Activity Signals -------------------------------------------------------------------------------------------

def sa_action(method):
    if method.endswith("CreateServiceAccountKey"):
        return "key created"
    if method.endswith("SetIamPolicy"):
        return "IAM policy changed"
    if method.endswith("setCommonInstanceMetadata") or method.endswith("compute.instances.setMetadata"):
        return "metadata written"
    if method.endswith("CreateServiceAccount"):
        return "service account created"
    return None


def sa_status(action, external):
    if action == "service account created":
        return INFORMATIONAL
    return ACTION_REQUIRED if external else INVESTIGATION


SA_ISSUE = {"key created": "Key created by a service account.", "IAM policy changed": "IAM changed by a service account.", "metadata written": "Metadata written by a service account.",
            "service account created": "Service account created by a service account."}


def sa_rows(entries, capped=False):
    groups = {}
    for entry in entries:
        fact = entry_facts(entry)
        if not is_service_account(fact["principal"]) or is_google_principal(fact["principal"]):
            continue
        action = sa_action(fact["method"])
        if action is None:
            continue
        key = (fact["project"], fact["principal"], action, fact["ip_class"])
        group = groups.setdefault(key, {"count": 0, "denied": 0, "latest": "", "targets": [], "ips": set()})
        group["count"] += 1
        group["denied"] += fact["denied"]
        group["latest"] = max(group["latest"], fact["timestamp"])
        target = fact["resource"] if action == "IAM policy changed" else (fact["email"] or fact["resource"].rsplit("/", 1)[-1])
        if target and target not in group["targets"]:
            group["targets"].append(target)
        if fact["ip"]:
            group["ips"].add(fact["ip"])
    rows = []
    for (project, principal, action, ip_cls), group in sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        external = ip_cls == "external"
        where = f"{ip_cls} address{'es' if len(group['ips']) > 1 else ''} ({', '.join(sorted(group['ips'])[:3])})" if group["ips"] else "an unknown address"
        targets = ", ".join(t[-80:] for t in group["targets"][:3]) + (f" +{len(group['targets']) - 3}" if len(group["targets"]) > 3 else "")
        binding = f" (gcloud projects remove-iam-policy-binding {project} --member=serviceAccount:{principal} --role=<role>)" if "/" not in project else ""
        rows.append({"Project": project, "Principal": principal, "Action": action, "Target": targets, "From": ip_cls, "Count": group["count"], "Latest": group["latest"][:16].replace("T", " "),
                     "Issue": SA_ISSUE[action],
                     "Detail": f"{group['count']} time{'s' if group['count'] != 1 else ''} in the last {WINDOW_DAYS} days from {where}." + denied_note(group)
                               + (" The read stopped at the cap; older events are not counted." if capped else ""),
                     "Fix": (f"gcloud logging read 'protoPayload.authenticationInfo.principalEmail=\"{principal}\"' {parent_flag(project)} --freshness={WINDOW_DAYS}d --limit=50  "
                             f"# then confirm the automation behind it, or remove the role that lets it{binding}"),
                     "_status": sa_status(action, external)})
    return rows


def check_sa_signals(scope, scope_id, all_projects, job_id, *, sink, scope_level=True, project_level=True):
    """Writes *Service Account Activity Signals* (module docstring): the organization's or folder's own entries (``scope_level`` — an IAM change
    on the organization is written there, not in a project) and every project's (``project_level``). A sharded scan splits the two halves
    (``registry.SPLIT_CHECKS``); a project scan has only the project half."""
    print(f"🔑 [{job_id}] Checking {SA_SIGNALS_CHECK} under {scope} {scope_id} and in {len(all_projects) if project_level else 0} projects...")
    parents = ([f"{scope}s/{scope_id}"] if scope_level and scope in ("organization", "folder") else []) + ([f"projects/{p['projectId']}" for p in all_projects] if project_level else [])
    skipped = NotChecked(SA_SIGNALS_CHECK)
    rows = read_parents(parents, 'protoPayload.authenticationInfo.principalEmail=~"gserviceaccount.com$" AND ', SA_METHODS, sa_rows, skipped)
    write_rows(sink, job_id, SA_SIGNALS_CHECK, rows, SA_ALL_CLEAR)
    skipped.write(sink, job_id)
