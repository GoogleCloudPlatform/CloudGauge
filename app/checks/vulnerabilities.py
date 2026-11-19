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
"""Vulnerabilities and exposure (v19): the CVEs VM Manager knows about, and the VM that combines every leg of a break-in.

- **OS Vulnerabilities** (Security & Identity, per project): per zone with running VMs outside the managed fleets (GKE,
  Dataproc, Dataflow, Batch, Workbench), VM Manager's ``vulnerabilityReports.list``. An instance with **critical** CVEs
  that have a fix available (``availableInventoryItemIds``) is **Action Required**, with **high** ones Investigation;
  the rest are counted. A project where the API answers ``FAILED_PRECONDITION`` (full VM Manager not enabled) gets one
  Informational row: no report exists for its VMs. ``roles/iam.securityReviewer`` carries the permission.
- **Exposed Privileged VMs** (Security & Identity, scope-level): one inventory listing of the scope's instances,
  VPC firewall rules and firewall policies, plus the project IAM policies from the search *Service Account Privileges*
  already makes. A running instance with an **external address**, a **privileged identity** (the default compute
  account with the ``cloud-platform`` scope, or a service account holding Owner, Editor, an ``*.admin`` or an ``iam.*``
  role on the project) and an **open ingress rule** that reaches it (``0.0.0.0/0`` or ``::/0``, enabled, allow, in its
  network, targeting it) is **Action Required** — CloudGauge's own toxic combination, each leg of which has its own
  record. Two legs are not a row.
"""
import logging

from googleapiclient.errors import HttpError

from app.checks.gke_operations import ACTION_REQUIRED, INFORMATIONAL, INVESTIGATION, write_rows
from app.checks.identity_hygiene import POLICY_TYPES, is_admin_role, policy_facts
from app.checks.network_edge import by_kind, list_assets
from app.checks.not_checked import NotChecked
from app.checks.security import INTERNET_RANGES, policy_rule_as_vpc_rule, rule_protocols
from app.checks.gke_security import SCOPE_PREFIX
from app.checks.vm_hardening import is_default_account, is_managed_fleet
from app.config import SCOPES
from app.services import gcp

OS_VULN_CHECK = "OS Vulnerabilities"
EXPOSED_VM_CHECK = "Exposed Privileged VMs"
VULNERABILITY_CHECKS = (OS_VULN_CHECK, EXPOSED_VM_CHECK)

EXPOSURE_TYPES = ["compute.googleapis.com/Instance", "compute.googleapis.com/Firewall", "compute.googleapis.com/FirewallPolicy"]
CLOUD_PLATFORM = "cloud-platform"
PRIMITIVE_ROLES = ("roles/owner", "roles/editor")
TOP_CVES = 3
OS_VULN_ALL_CLEAR = "Every VM with a vulnerability report has no critical or high CVE with a fix available."
EXPOSED_VM_ALL_CLEAR = "No running VM combines an external address, a privileged identity and an ingress rule open to the internet."
PRECONDITION_WORDS = ("vulnerability reports are disabled", "failed_precondition", "enable full vm manager", "os config", "vm manager")


# --- OS Vulnerabilities -------------------------------------------------------------------------------------------------------

def running_zones(response):
    """``{zone: {instance id: name}}`` of the RUNNING instances outside the managed fleets in an ``instances.aggregatedList`` answer."""
    zones = {}
    for scope, data in (response.get("items") or {}).items():
        for instance in data.get("instances") or []:
            if str(instance.get("status") or "") != "RUNNING" or is_managed_fleet(instance):
                continue
            zones.setdefault(scope.rsplit("/", 1)[-1], {})[str(instance.get("id") or instance.get("name"))] = str(instance.get("name") or instance.get("id"))
    return zones


def is_precondition(error):
    status = getattr(getattr(error, "resp", None), "status", None)
    text = str(error).lower()
    return status in (400, 412) and any(word in text for word in PRECONDITION_WORDS)


def report_facts(report, names=None):
    """``{instance, critical, high, other, fixable, top}`` of one vulnerability report: ``top`` the three worst CVEs (CVSS, fix available)."""
    name = str(report.get("name") or "")
    instance = name.split("/instances/")[1].split("/")[0] if "/instances/" in name else "?"
    instance = (names or {}).get(instance, instance)
    critical = high = other = fixable = 0
    cves = []
    for vulnerability in report.get("vulnerabilities") or []:
        details = vulnerability.get("details") or {}
        severity = str(details.get("severity") or "").upper()
        fix = bool(vulnerability.get("availableInventoryItemIds"))
        if severity == "CRITICAL":
            critical += 1
        elif severity == "HIGH":
            high += 1
        else:
            other += 1
        fixable += fix
        score = float(((details.get("cvssV3") or {}).get("baseScore")) or 0)
        cves.append((severity, score, str(details.get("cve") or "?"), fix))
    cves.sort(key=lambda c: (("CRITICAL", "HIGH", "MEDIUM", "LOW").index(c[0]) if c[0] in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else 9, -c[1], c[2]))
    return {"instance": instance, "critical": critical, "high": high, "other": other, "fixable": fixable,
            "critical_fixable": sum(1 for c in cves if c[0] == "CRITICAL" and c[3]), "high_fixable": sum(1 for c in cves if c[0] == "HIGH" and c[3]), "top": cves[:TOP_CVES]}


def vulnerability_rows(project_id, zone, facts):
    rows = []
    for fact in facts:
        if fact["critical_fixable"]:
            status, issue = ACTION_REQUIRED, f"{fact['critical_fixable']} critical CVE{'s' if fact['critical_fixable'] != 1 else ''} with a fix available."
        elif fact["high_fixable"]:
            status, issue = INVESTIGATION, f"{fact['high_fixable']} high CVE{'s' if fact['high_fixable'] != 1 else ''} with a fix available."
        else:
            continue
        top = "; ".join(f"{cve} ({sev.lower()}, CVSS {score:g}{', fix available' if fix else ''})" for sev, score, cve, fix in fact["top"])
        rows.append({"Project": project_id, "Instance": fact["instance"], "Zone": zone, "Critical": fact["critical"], "High": fact["high"], "Fixable": fact["fixable"], "Issue": issue,
                     "Detail": f"VM Manager reports {fact['critical'] + fact['high'] + fact['other']} CVEs ({fact['critical']} critical, {fact['high']} high), {fact['fixable']} with a fix available. Worst: {top}.",
                     "Fix": f"gcloud compute os-config patch-jobs execute --project={project_id} --instance-filter-names=zones/{zone}/instances/{fact['instance']} --reboot-config=default",
                     "_status": status})
    return rows


def precondition_row(project_id, instances):
    return {"Project": project_id, "Instance": f"{instances} VM{'s' if instances != 1 else ''}", "Zone": "—", "Critical": "?", "High": "?", "Fixable": "?",
            "Issue": "VM Manager not fully enabled.",
            "Detail": "The project has no vulnerability reports: full VM Manager (OS inventory, vulnerability reports, patch jobs) is off, so the CVEs on its VMs are unknown to Google Cloud and to this report.",
            "Fix": f"gcloud services enable osconfig.googleapis.com containeranalysis.googleapis.com --project={project_id} && gcloud compute project-info add-metadata --project={project_id} --metadata=enable-osconfig=TRUE  # the OS Config agent is on current Google images",
            "_status": INFORMATIONAL}


def list_reports(osconfig, project_id, zone):
    found, collection = [], osconfig.projects().locations().instances().vulnerabilityReports()
    request = collection.list(parent=f"projects/{project_id}/locations/{zone}/instances/-", pageSize=100)
    while request:
        response = request.execute() or {}
        found += response.get("vulnerabilityReports") or []
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def check_os_vulnerabilities(scope_id, all_projects, job_id, *, sink):
    """Writes *OS Vulnerabilities* for every project (module docstring)."""
    print(f"🩹 [{job_id}] Checking {OS_VULN_CHECK} in {len(all_projects)} projects...")
    skipped, rows = NotChecked(OS_VULN_CHECK, resource_apis=("compute.googleapis.com",)), []
    for project in all_projects:
        project_id = project["projectId"]
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build("compute", "v1", credentials=credentials)
            zones = running_zones(compute.instances().aggregatedList(project=project_id, filter='status = "RUNNING"', maxResults=500).execute() or {})
        except Exception as e:
            skipped.add(project_id, e)
            continue
        if not zones:
            continue
        osconfig = gcp.api_build("osconfig", "v1", credentials=credentials)
        for zone, names in sorted(zones.items()):
            try:
                reports = list_reports(osconfig, project_id, zone)
            except HttpError as e:
                if is_precondition(e):
                    rows.append(precondition_row(project_id, sum(len(n) for n in zones.values())))
                else:
                    skipped.add(project_id, e, detail=f"zone {zone}", resource_apis=("osconfig.googleapis.com",))
                break
            except Exception as e:
                skipped.add(project_id, e, detail=f"zone {zone}")
                break
            rows += vulnerability_rows(project_id, zone, [report_facts(r, names) for r in reports])
    write_rows(sink, job_id, OS_VULN_CHECK, rows, OS_VULN_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- Exposed Privileged VMs -------------------------------------------------------------------------------------------------------

def tail(value):
    return str(value or "").rsplit("/", 1)[-1]


def external_addresses(data):
    """``[(address, access-config name)]`` of an instance's interfaces — the name is what ``delete-access-config`` takes (``External NAT`` from
    the console, ``external-nat`` from gcloud)."""
    found = []
    for nic in data.get("networkInterfaces") or []:
        found += [(str(a.get("natIP")), str(a.get("name") or "External NAT")) for a in nic.get("accessConfigs") or [] if a.get("natIP")]
        found += [(str(a.get("externalIpv6")), str(a.get("name") or "External IPv6")) for a in nic.get("ipv6AccessConfigs") or [] if a.get("externalIpv6")]
    return found


def instance_exposure_facts(fact):
    """What the join reads of one listed instance."""
    data = fact["data"]
    accounts = [(str(sa.get("email") or ""), [str(s).replace(SCOPE_PREFIX, "") for s in (sa.get("scopes") or [])]) for sa in data.get("serviceAccounts") or []]
    return {"project_id": fact["project_id"], "name": fact["name"], "zone": tail(data.get("zone")) or fact["region"], "status": str(data.get("status") or ""),
            "external": external_addresses(data), "accounts": accounts, "tags": [str(t) for t in (data.get("tags") or {}).get("items") or []],
            "networks": [tail(nic.get("network")) for nic in data.get("networkInterfaces") or [] if nic.get("network")], "managed": is_managed_fleet(data)}


def roles_by_member(policies):
    """``{project id: {member email: {roles}}}`` over the project policies' facts (service accounts only)."""
    found = {}
    for policy in policies:
        if policy["level"] != "project":
            continue
        project_id = tail(policy["resource"])
        for role, members, _ in policy["bindings"]:
            for member in members:
                if member.startswith("serviceAccount:"):
                    found.setdefault(project_id, {}).setdefault(member.split(":", 1)[1], set()).add(role)
    return found


def privileged_identity(vm, roles):
    """Why the instance's identity is privileged, or ``""``: the default account with ``cloud-platform``, or roles that administer the project."""
    for email, scopes in vm["accounts"]:
        held = roles.get(email, set())
        strong = sorted(r for r in held if r in PRIMITIVE_ROLES or is_admin_role(r) or r.startswith("roles/iam."))
        if strong:
            return f"{email} holds {', '.join(strong[:3])}{' +' + str(len(strong) - 3) if len(strong) > 3 else ''}"
        if is_default_account(email) and CLOUD_PLATFORM in scopes:
            return f"{email} (default account) with the cloud-platform scope"
    return ""


def open_rules(assets):
    """The enabled ingress allow rules open to the internet among the listed VPC firewall rules and firewall policies, in one shape:
    ``[(network tail or "" for a hierarchical policy, rule)]``."""
    found = []
    for fact in assets.get("firewalls", []):
        rule = fact["data"]
        if _open_ingress(rule):
            found.append((tail(rule.get("network")), {**rule, "name": rule.get("name") or fact["name"]}))
    for fact in assets.get("firewallPolicies", []):
        policy = fact["data"]
        networks = [tail(a.get("attachmentTarget")) for a in policy.get("associations") or []]
        for rule in policy.get("rules") or []:
            shaped = policy_rule_as_vpc_rule(policy, rule)
            if _open_ingress(shaped):
                for network in networks or [""]:
                    found.append((network, shaped))
    return found


def _open_ingress(rule):
    if rule.get("disabled") or str(rule.get("direction") or "INGRESS").upper() != "INGRESS" or not rule.get("allowed"):
        return False
    return any(r in INTERNET_RANGES for r in rule.get("sourceRanges") or [])


def reaching_rule(vm, rules):
    """The first open rule that applies to the instance: its network (a hierarchical policy applies to every network), and its targets
    (none: every instance; tags; service accounts)."""
    emails = {email for email, _ in vm["accounts"]}
    for network, rule in rules:
        if network and network not in vm["networks"] and not any(network.endswith(n) or n.endswith(network) for n in vm["networks"]):
            continue
        tags, accounts = rule.get("targetTags") or [], rule.get("targetServiceAccounts") or []
        if (not tags and not accounts) or set(tags) & set(vm["tags"]) or set(accounts) & emails:
            return rule
    return None


def exposed_vm_rows(vms, rules, roles):
    rows = []
    for vm in vms:
        if vm["status"] != "RUNNING" or vm["managed"] or not vm["external"]:
            continue
        identity = privileged_identity(vm, roles.get(vm["project_id"], {}))
        if not identity:
            continue
        rule = reaching_rule(vm, rules)
        if rule is None:
            continue
        rows.append({"Project": vm["project_id"], "Instance": vm["name"], "Zone": vm["zone"], "External IP": ", ".join(a for a, _ in vm["external"]), "Identity": identity,
                     "Open rule": f"{rule.get('name')} ({rule_protocols(rule)} from {', '.join(r for r in rule.get('sourceRanges') or [] if r in INTERNET_RANGES)})",
                     "Issue": "Exposed privileged VM.",
                     "Detail": "Reachable from the internet, running as an identity that administers the project: one unpatched service or leaked credential on it is the project.",
                     "Fix": f"gcloud compute instances delete-access-config {vm['name']} --zone={vm['zone']} --project={vm['project_id']} --access-config-name=\"{vm['external'][0][1]}\"  "
                            f"# or narrow {rule.get('name')} to your CIDRs / the IAP range, or move the VM to a dedicated, least-privilege service account",
                     "_status": ACTION_REQUIRED})
    return rows


def check_exposed_vms(scope, scope_id, job_id, *, sink):
    """Writes *Exposed Privileged VMs* (module docstring): one listing of instances, firewall rules and policies under the scope, the project
    IAM policies from one search."""
    print(f"🎯 [{job_id}] Checking {EXPOSED_VM_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        grouped = by_kind(list_assets(asset_client, parent, EXPOSURE_TYPES))
    except Exception as e:
        logging.error(f"[{job_id}] {EXPOSED_VM_CHECK}: could not list under {parent}: {e}")
        sink.write_finding(job_id, EXPOSED_VM_CHECK.replace(" ", "_"), {"Check": EXPOSED_VM_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped = NotChecked(EXPOSED_VM_CHECK)
    vms = [instance_exposure_facts(fact) for fact in grouped.get("instances", [])]
    roles = {}
    if any(vm["external"] and vm["status"] == "RUNNING" for vm in vms):
        try:
            roles = roles_by_member([policy_facts(r) for r in asset_client.search_all_iam_policies(request={"scope": parent, "query": "", "asset_types": POLICY_TYPES, "page_size": 500})])
        except Exception as e:
            skipped.add(parent, e, detail="the IAM-policy search failed; only the default account with cloud-platform counts as privileged")
    write_rows(sink, job_id, EXPOSED_VM_CHECK, exposed_vm_rows(vms, open_rules(grouped), roles), EXPOSED_VM_ALL_CLEAR)
    skipped.write(sink, job_id)
