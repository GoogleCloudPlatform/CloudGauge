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
"""Support cases (v19.2): the open support cases under the scope, from the Cloud Support API (``cases.search``, ``state=OPEN``).

Two records from one search, both Operational Excellence & Observability, scope-level:

- **Support Cases** — a briefing, Informational: seven fixed lines (open cases by priority and the oldest; with Google Support;
  waiting on you; solution provided; escalated; by project; by product). Titles and metadata only — a case's description is
  never read into the report.
- **Case Hygiene** — scored: the open cases that need the customer's attention — ``ACTION_REQUIRED`` with no update for more
  than ``WAITING_DAYS`` (Investigation), open beyond the expectation of their priority (``OPEN_EXPECTATION``; Investigation),
  ``SOLUTION_PROVIDED`` for more than ``SOLVED_DAYS`` (Informational), escalated (Informational). Cases but nothing flagged:
  Compliant. **No open case at all: Informational** — nothing was judged, and the support tier is not readable (an
  organization on Basic support has no cases and reads the same).

The read needs ``cloudsupport.techCases.list`` on the scope — which ``roles/iam.securityReviewer`` carries — and the Cloud
Support API enabled in the host project. **Whatever is missing, both records are written with their normal columns**,
Informational and outside the score, never an Error: the API disabled in the host project (``403 SERVICE_DISABLED``), the
permission missing (``testIamPermissions`` on the scope first — without the permission ``cases.search`` answers ``200 {}``,
indistinguishable from "no case"), any other refusal. Only a failure the client could not retry (a 5xx, the network) is an
Error. An organization scan searches the organization (its own and its projects' cases); a project scan the project; a folder
scan the organization, kept to the folder's projects.
"""
import json
import logging
from collections import Counter

from googleapiclient.errors import HttpError

from app.checks.gke_operations import ACTION_REQUIRED, COMPLIANT, INFORMATIONAL, INVESTIGATION
from app.checks.scc import scope_projects
from app.config import SCOPES
from app.services import gcp
from app.utils import days_between, parse_timestamp, utcnow

SUPPORT_BRIEFING = "Support Cases"
CASE_HYGIENE_CHECK = "Case Hygiene"
SUPPORT_CHECKS = (SUPPORT_BRIEFING, CASE_HYGIENE_CHECK)
SUPPORT_API = "cloudsupport.googleapis.com"
LIST_PERMISSION = "cloudsupport.techCases.list"
PAGE_SIZE = 100
CASE_CAP = 500
WAITING_DAYS = 3  # ACTION_REQUIRED with no update for longer: the case waits on the customer
SOLVED_DAYS = 7  # SOLUTION_PROVIDED for longer without closing or reopening
OPEN_EXPECTATION = {"P0": 1, "P1": 7, "P2": 30, "P3": 60, "P4": 90}  # days open beyond which a case of that priority is a row
WITH_GOOGLE = ("NEW", "IN_PROGRESS_GOOGLE_SUPPORT")
TOP = 5
TIER_NOTE = "The support tier is not readable: an organization on Basic support has no cases and reads the same."
HYGIENE_COLUMNS = ("Case", "Title", "Priority", "State", "Project", "Age", "Issue", "Detail", "Fix")
SEVERITY = {ACTION_REQUIRED: 0, INVESTIGATION: 1, INFORMATIONAL: 2}


def tail(name):
    return str(name or "").rsplit("/", 1)[-1]


def search_command(parent, host_project):
    """The authenticated read that reproduces the search (there is no ``gcloud support cases`` yet)."""
    return (f"curl -s -H \"Authorization: Bearer $(gcloud auth print-access-token)\" -H \"x-goog-user-project: {host_project}\" "
            f"\"https://cloudsupport.googleapis.com/v2/{parent}/cases:search?query=state%3DOPEN\"")


def case_command(name, host_project):
    return f"curl -s -H \"Authorization: Bearer $(gcloud auth print-access-token)\" -H \"x-goog-user-project: {host_project}\" \"https://cloudsupport.googleapis.com/v2/{name}\""


def enable_command(host_project):
    return f"gcloud services enable {SUPPORT_API} --project={host_project}"


def grant_command(parent, account):
    kind, _, number = parent.partition("/")
    verb = {"organizations": f"gcloud organizations add-iam-policy-binding {number}", "folders": f"gcloud resource-manager folders add-iam-policy-binding {number}"}.get(kind, f"gcloud projects add-iam-policy-binding {number}")
    return f"{verb} --member=serviceAccount:{account} --role=roles/cloudsupport.techSupportViewer  # or roles/iam.securityReviewer, which carries {LIST_PERMISSION} (README)"


# --- the reads --------------------------------------------------------------------------------------------------------------

def has_list_permission(crm_api, parent):
    """``True``/``False`` whether the caller holds ``LIST_PERMISSION`` on ``parent``; ``None`` when the probe itself failed (the search is tried anyway)."""
    kind = parent.split("/", 1)[0]
    try:
        collection = {"organizations": crm_api.organizations, "folders": crm_api.folders, "projects": crm_api.projects}[kind]()
        response = collection.testIamPermissions(resource=parent, body={"permissions": [LIST_PERMISSION]}).execute() or {}
        return LIST_PERMISSION in (response.get("permissions") or [])
    except Exception as e:  # noqa: BLE001 — the probe is a courtesy; the search decides
        logging.info(f"{SUPPORT_BRIEFING}: testIamPermissions on {parent} failed ({e}); searching anyway")
        return None


def search_cases(support_api, parent, cap=CASE_CAP, page_size=PAGE_SIZE):
    """``(cases, capped)`` — the open cases under ``parent`` (an organization's search returns its projects' cases too), ``cap`` at most."""
    cases, token = [], None
    while True:
        response = support_api.cases().search(parent=parent, query="state=OPEN", pageSize=min(page_size, cap - len(cases)), **({"pageToken": token} if token else {})).execute() or {}
        cases += response.get("cases") or []
        token = response.get("nextPageToken")
        if not token:
            return cases, False
        if len(cases) >= cap:
            return cases[:cap], True


def error_kind(error):
    """``disabled`` (the API is off in the host project), ``refused`` (another 4xx) or ``error`` (anything else)."""
    if not isinstance(error, HttpError):
        return "error"
    status = int(getattr(getattr(error, "resp", None), "status", 0) or 0)
    content = error.content.decode(errors="replace") if isinstance(getattr(error, "content", b""), bytes) else str(getattr(error, "content", ""))
    if status == 403 and ("SERVICE_DISABLED" in content or "has not been used in project" in content):
        return "disabled"
    return "refused" if 400 <= status < 500 else "error"


def error_message(error):
    content = error.content.decode(errors="replace") if isinstance(getattr(error, "content", b""), bytes) else str(getattr(error, "content", ""))
    try:
        return str(json.loads(content)["error"]["message"])
    except (ValueError, KeyError, TypeError):
        return str(error)


# --- the facts and the two records --------------------------------------------------------------------------------------------

def case_facts(case, now):
    """The report's view of one case: its ID, title, priority, state, project (a number or an ID as the API names it; the organization's own
    cases keep ``organizations/<number>``), age and days since the last update, escalation, product (the classification's root)."""
    name = str(case.get("name") or "")
    parent = name.rsplit("/cases/", 1)[0] if "/cases/" in name else ""
    created, updated = parse_timestamp(case.get("createTime")), parse_timestamp(case.get("updateTime"))
    classification = str((case.get("classification") or {}).get("displayName") or "")
    return {"name": name, "id": tail(name) or "?", "title": str(case.get("displayName") or "(untitled)"), "priority": str(case.get("priority") or "—"),
            "state": str(case.get("state") or "—"), "project": parent.split("/", 1)[1] if parent.startswith("projects/") else (parent or "?"),
            "age": days_between(created, now) if created else None, "since_update": days_between(updated, now) if updated else None,
            "escalated": bool(case.get("escalated")), "product": classification.split(" > ")[0].split(" :: ")[0].strip() or "—"}


def mention(fact, when="age"):
    days = fact[when]
    span = (f"{days} d since the last update" if when == "since_update" else f"{days} d open") if days is not None else "age unknown"
    return f"{fact['title']} ({fact['id']}, {fact['priority']}, {span})"


def listed(facts, when="age", reverse=True):
    ordered = sorted(facts, key=lambda f: (f[when] if f[when] is not None else -1), reverse=reverse)
    return "; ".join(mention(f, when) for f in ordered[:TOP]) + (f" +{len(ordered) - TOP} more" if len(ordered) > TOP else "")


def briefing_lines(parent, facts, host_project, capped=False, search_parent=None):
    """The seven lines, zero where nothing — the page reads the same every scan. ``search_parent`` is where the search really ran when it is
    not ``parent`` (a folder scan searches the organization and keeps the folder's projects)."""
    search = search_command(search_parent or parent, host_project) + ("  # then keep the folder's projects" if search_parent and search_parent != parent else "")
    case_fix = search + "  # open a case under Support › Cases in the console"
    by_priority = Counter(f["priority"] for f in facts)
    oldest = max(facts, key=lambda f: f["age"] if f["age"] is not None else -1) if facts else None
    with_google = [f for f in facts if f["state"] in WITH_GOOGLE]
    waiting = [f for f in facts if f["state"] == "ACTION_REQUIRED"]
    solved = [f for f in facts if f["state"] == "SOLUTION_PROVIDED"]
    escalated = [f for f in facts if f["escalated"]]
    by_project = Counter(f["project"] for f in facts)
    by_product = Counter(f["product"] for f in facts)

    def count_line(counter, noun):
        ordered = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))  # ties by name: the same line from every shard
        return "; ".join(f"{key} ×{count}" if count != 1 else str(key) for key, count in ordered[:TOP]) + (f"; +{len(counter) - TOP} more {noun}" if len(counter) > TOP else "")

    open_detail = (", ".join(f"{p} ×{n}" if n != 1 else p for p, n in sorted(by_priority.items())) + f". Oldest: {mention(oldest)}." + (f" The search stopped at {CASE_CAP} cases; the counts are of those." if capped else "")
                   if facts else f"No open support case under {parent}. {TIER_NOTE}")
    return [
        {"Line": "Open cases", "Value": f"{len(facts)} open" + (f" (first {CASE_CAP})" if capped else ""), "Detail": open_detail, "Fix": search},
        {"Line": "With Google Support", "Value": str(len(with_google)), "Detail": ("Newest: " + listed(with_google, "since_update", reverse=False) + ".") if with_google else "None.", "Fix": search},
        {"Line": "Waiting on you", "Value": str(len(waiting)), "Detail": (f"State ACTION_REQUIRED — {listed(waiting, 'since_update')}.") if waiting else "None.", "Fix": case_fix},
        {"Line": "Solution provided", "Value": str(len(solved)), "Detail": (f"Confirm or reopen before they auto-close — {listed(solved, 'since_update')}.") if solved else "None.", "Fix": case_fix},
        {"Line": "Escalated", "Value": str(len(escalated)), "Detail": (listed(escalated) + ".") if escalated else "None.", "Fix": case_fix},
        {"Line": "By project", "Value": f"{len(by_project)} project{'s' if len(by_project) != 1 else ''}", "Detail": (count_line(by_project, "projects") + ".") if by_project else "None.", "Fix": search},
        {"Line": "By product", "Value": f"{len(by_product)} product{'s' if len(by_product) != 1 else ''}", "Detail": (count_line(by_product, "products") + ".") if by_product else "None.", "Fix": search},
    ]


def case_issues(fact):
    """``[(issue, status, detail)]`` of one open case, worst first; empty when the case is simply with Google Support within its expectation."""
    issues = []
    if fact["state"] == "ACTION_REQUIRED" and fact["since_update"] is not None and fact["since_update"] > WAITING_DAYS:
        issues.append(("Waiting on you.", INVESTIGATION, f"No update for {fact['since_update']} days in state ACTION_REQUIRED — Google Support waits for your answer."))
    limit = OPEN_EXPECTATION.get(fact["priority"])
    if limit is not None and fact["age"] is not None and fact["age"] > limit:
        issues.append(("Open beyond its priority's expectation.", INVESTIGATION, f"Open {fact['age']} days as {fact['priority']} (expectation {limit} days): escalate it, or lower the priority."))
    if fact["state"] == "SOLUTION_PROVIDED" and fact["since_update"] is not None and fact["since_update"] > SOLVED_DAYS:
        issues.append(("Solution provided, not confirmed.", INFORMATIONAL, f"A solution was provided {fact['since_update']} days ago: confirm it or reopen before the case auto-closes."))
    if fact["escalated"]:
        issues.append(("Escalated.", INFORMATIONAL, "Escalated to Google Support management."))
    return sorted(issues, key=lambda issue: SEVERITY[issue[1]])


def hygiene_rows(facts, host_project):
    rows = []
    for fact in facts:
        issues = case_issues(fact)
        if not issues:
            continue
        rows.append({"Case": fact["id"], "Title": fact["title"], "Priority": fact["priority"], "State": fact["state"], "Project": fact["project"],
                     "Age": f"{fact['age']} d" if fact["age"] is not None else "?", "Issue": issues[0][0], "Detail": " ".join(detail for _, _, detail in issues),
                     "Fix": case_command(fact["name"], host_project) + "  # then reply, escalate or close it under Support › Cases in the console", "_status": issues[0][1]})
    return sorted(rows, key=lambda r: (SEVERITY[r["_status"]], -(int(r["Age"][:-2]) if r["Age"].endswith(" d") else -1), r["Case"]))


def placeholder_row(issue, detail, fix):
    """A Case Hygiene row with the table's columns when there is no case to list (not configured, nothing to judge)."""
    row = {column: "—" for column in HYGIENE_COLUMNS}
    row.update({"Issue": issue, "Detail": detail, "Fix": fix})
    return row


def write_both(sink, job_id, briefing_rows, briefing_status, hygiene, hygiene_status):
    sink.write_finding(job_id, SUPPORT_BRIEFING.replace(" ", "_"), {"Check": SUPPORT_BRIEFING, "Finding": briefing_rows, "Status": briefing_status})
    sink.write_finding(job_id, CASE_HYGIENE_CHECK.replace(" ", "_"), {"Check": CASE_HYGIENE_CHECK, "Finding": hygiene, "Status": hygiene_status})


def write_not_configured(sink, job_id, reason, fix):
    """Both records, Informational, with their normal columns: the reason and the command that configures it."""
    write_both(sink, job_id, [{"Line": "Support cases", "Value": "not configured", "Detail": reason, "Fix": fix}], INFORMATIONAL,
               [placeholder_row("Not configured.", reason, fix)], INFORMATIONAL)


def check_support_cases(scope, scope_id, job_id, *, sink):
    """Writes *Support Cases* and *Case Hygiene* (module docstring)."""
    print(f"🎫 [{job_id}] Checking {SUPPORT_BRIEFING} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    host_project, account = "<PROJECT_ID>", "<SERVICE_ACCOUNT_EMAIL>"
    try:
        credentials, host_project = gcp.auth_default(scopes=SCOPES)
        host_project = host_project or "<PROJECT_ID>"
        account = str(getattr(credentials, "service_account_email", "") or "") or account
        if has_list_permission(gcp.api_build("cloudresourcemanager", "v3", credentials=credentials), parent) is False:
            write_not_configured(sink, job_id, f"{account} does not hold {LIST_PERMISSION} on {parent}; the support records need it (roles/iam.securityReviewer carries it).",
                                 grant_command(parent, account))
            return
        search_parent, members = parent, None
        if scope == "folder":  # a search runs on an organization or a project: the organization's, kept to the folder's projects
            org_id, members = scope_projects(gcp.asset_client(credentials), parent)
            if not org_id:
                raise LookupError(f"no organization found above {parent}")
            search_parent = f"organizations/{org_id}"
        cases, capped = search_cases(gcp.api_build("cloudsupport", "v2", credentials=credentials), search_parent)
    except HttpError as e:
        kind = error_kind(e)
        if kind == "disabled":
            write_not_configured(sink, job_id, f"The Cloud Support API is not enabled in {host_project}; the support records need it.", enable_command(host_project))
            return
        if kind == "refused":
            write_not_configured(sink, job_id, f"The Cloud Support API refused the read under {parent}: {error_message(e)}", f"{enable_command(host_project)}; {grant_command(parent, account)}")
            return
        logging.error(f"[{job_id}] {SUPPORT_BRIEFING}: the read under {parent} failed: {e}")
        write_both(sink, job_id, [{"Error": str(e)}], "Error", [{"Error": str(e)}], "Error")
        return
    except Exception as e:
        logging.error(f"[{job_id}] {SUPPORT_BRIEFING}: the read under {parent} failed: {e}")
        write_both(sink, job_id, [{"Error": str(e)}], "Error", [{"Error": str(e)}], "Error")
        return
    now = utcnow()
    facts = [case_facts(case, now) for case in cases]
    if members is not None:
        facts = [fact for fact in facts if fact["project"] in members]
    lines = briefing_lines(parent, facts, host_project, capped, search_parent)
    if not facts:
        hygiene, status = [placeholder_row("No open case.", f"No open support case under {parent}; nothing to judge. {TIER_NOTE}", lines[0]["Fix"])], INFORMATIONAL
    else:
        rows = hygiene_rows(facts, host_project)
        status = min((row["_status"] for row in rows), key=SEVERITY.get) if rows else COMPLIANT
        for row in rows:
            row.pop("_status", None)
        hygiene = rows or [{"Status": f"{len(facts)} open case{'s' if len(facts) != 1 else ''}, each with Google Support within the expectation of its priority; none waits on you beyond {WAITING_DAYS} days."}]
    write_both(sink, job_id, lines, INFORMATIONAL, hygiene, status)
