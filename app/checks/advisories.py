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
"""Advisory Notifications: what Google told the customer, and whether it is switched on.

Two records per scan, from the Advisory Notifications API:

- **Advisory Notifications** - a *briefing*: one row per notification created
  in the last ``ADVISORY_WINDOW_DAYS`` (default a year, which is about what
  the API keeps), newest first, with its type spelled out (Mandatory Service
  Announcement, Security & Privacy Advisory, Sensitive Actions, Threat
  Horizons) so the report's filter box lists, say, every MSA. Always
  ``Informational``: these are Google's messages, not the customer's
  configuration, so they never count toward the score.
- **Advisory Notifications Settings** - a scored check: ``Action Required``
  with one row per notification type that is turned off in the Advisory
  Notifications settings (nobody receives those), ``Compliant`` when none is.
  Enabling the *API* in a customer project changes nothing (notifications are
  produced and shown in the console regardless; the API only serves
  programmatic access), so the settings are the thing to score.

An organization scan reads the organization's notifications and settings once
(``organizations/{id}/locations/global``); folder and project scans read each
project's (``projects/{number}/locations/global`` - the API addresses projects
by *number*, which the project list carries as ``projectNumber``) and fold the
same notification seen from several projects into one row. Organization-wide
announcements are only visible in an organization scan; the briefing says so.

Bodies are HTML. They are reduced to text with the standard library's parser
before anything reaches the report (Jinja then escapes it): the Summary column
is the whole message, one line per paragraph (the report shows three lines and
opens the rest on request; a body is only cut at ``MAX_SUMMARY_LENGTH``), and
the Details column carries what a reader would otherwise open the notification
for - the affected resources of an advisory (its CSV attachments) or the
actions and actors of a sensitive-actions digest, one per line.

Failures follow the rest of the checks: an organization-level call that fails
is an ``Error`` record naming the API or permission to fix (both records, since
both need it), a project that fails is reported as "Projects not checked".
"""
import logging
import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser

from app.checks import categories
from app.checks.not_checked import NotChecked, describe_error, disabled_api, disabled_api_elsewhere
from app.config import SCOPES, get_settings
from app.services import gcp

ADVISORIES_CHECK = "Advisory Notifications"
SETTINGS_CHECK = "Advisory Notifications Settings"
ADVISORY_API = "advisorynotifications.googleapis.com"
LIST_PERMISSION = "advisorynotifications.notifications.list"
SETTINGS_PERMISSION = "advisorynotifications.settings.get"
PAGE_SIZE = 50
MAX_SUMMARY_LENGTH = 8000  # a safety cap on the message text in a row; Google's bodies are far shorter
MAX_ATTACHMENT_ROWS = 25  # affected-resource rows quoted in the Details column, one per line; the rest is a count
SENSITIVE_ACTIONS = "NOTIFICATION_TYPE_SENSITIVE_ACTIONS"
TYPE_LABELS = {
    "NOTIFICATION_TYPE_SECURITY_MSA": "Mandatory Service Announcement",
    "NOTIFICATION_TYPE_SECURITY_PRIVACY_ADVISORY": "Security & Privacy Advisory",
    SENSITIVE_ACTIONS: "Sensitive Actions",
    "NOTIFICATION_TYPE_THREAT_HORIZONS": "Threat Horizons",
}
SETTINGS_FIX = ("In the Google Cloud console open Advisory Notifications > Settings and turn the type on "
                "(or PATCH .../locations/global/settings with notificationSettings.<TYPE>.enabled=true).")
ORG_ONLY_NOTE = ("Organization-wide announcements (Mandatory Service Announcements, Threat Horizons reports, "
                 "sensitive-action digests) appear in an organization scan.")

_BLOCK_TAGS = {"p", "br", "div", "li", "ul", "ol", "tr", "table", "h1", "h2", "h3", "h4", "h5", "h6",
               "section", "header", "footer", "blockquote", "pre"}
_SKIPPED_TAGS = {"style", "script", "head", "title"}
_EMAIL = re.compile(r"\bBy:\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_TIMES = re.compile(r"This action was taken (\d+) times?", re.I)
_DETAIL_LINE = re.compile(r"^[A-Za-z][A-Za-z /()-]{0,40}:(\s|$)")  # "Policy: ...", "Policy action: Updated", "By: a@x"


class _TextExtractor(HTMLParser):
    """Collects the text of an HTML fragment, one line per block element; styles and scripts dropped."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self._skipping = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in _SKIPPED_TAGS:
            self._skipping += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in _SKIPPED_TAGS:
            self._skipping = max(0, self._skipping - 1)
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skipping:
            self.parts.append(data)


def html_to_lines(html_text):
    """The text lines of an HTML fragment (plain text passes through), whitespace collapsed, empties dropped."""
    parser = _TextExtractor()
    try:
        parser.feed(str(html_text or ""))
        parser.close()
    except Exception:  # the parser is lenient; be safe with anything it still rejects
        return [" ".join(str(html_text or "").split())] if str(html_text or "").strip() else []
    lines = [" ".join(line.split()) for line in "".join(parser.parts).split("\n")]
    return [line for line in lines if line]


def strip_html(html_text):
    """The text of an HTML fragment as one line."""
    return " ".join(html_to_lines(html_text))


def truncate(text, length=MAX_SUMMARY_LENGTH):
    text = str(text or "")
    return text if len(text) <= length else text[:length - 3].rstrip() + "..."


def summarize_attachments(messages):
    """The affected resources of a notification: its CSV attachments as a count line plus one line per row.

    ``"4 affected resource rows (instances.csv)\\nProject: p-1; Instance: sql-0\\n...\\n(+1 more)"``;
    at most ``MAX_ATTACHMENT_ROWS`` rows are quoted. Empty when there are no attachments.
    """
    total, samples, names = 0, [], []
    for message in messages or []:
        for attachment in message.get("attachments", []) or []:
            csv = attachment.get("csv") or {}
            headers, data_rows = csv.get("headers") or [], csv.get("dataRows") or []
            if attachment.get("displayName"):
                names.append(attachment["displayName"])
            total += len(data_rows)
            for row in data_rows[:max(0, MAX_ATTACHMENT_ROWS - len(samples))]:
                entries = [str(v) for v in (row.get("entries") or [])]
                pairs = [f"{h}: {v}" for h, v in zip(headers, entries)] or entries
                samples.append("; ".join(pairs))
    if not total and not names:
        return ""
    heading = f"{total} affected resource row{'' if total == 1 else 's'}"
    if names:
        heading += f" ({', '.join(dict.fromkeys(names))})"
    lines = [heading, *samples]
    if total > len(samples):
        lines.append(f"(+{total - len(samples)} more)")
    return "\n".join(lines)


def action_heading(lines, index):
    """The heading of the action whose "This action was taken N times" line is ``lines[index]``.

    The nearest preceding line that is not a ``Label: value`` detail ("Policy: ...",
    "Policy action: Updated", "By: a@x") or another count line; ``""`` when there is none.
    """
    for line in reversed(lines[:index]):
        if _DETAIL_LINE.match(line) or _TIMES.search(line):
            continue
        return line.strip()
    return ""


def summarize_sensitive_actions(lines):
    """The actions and actors of a sensitive-actions digest, from its text lines, one per line:
    ``"<action> (x4)\\n<action> (x1)\\nby a@x, b@x"``.

    Best effort over Google's HTML layout (a heading per action, its details as "Label: value"
    lines, "This action was taken N times", and one "By: <email>" per occurrence); an empty
    string when nothing matches.
    """
    actions, actors = [], []
    for index, line in enumerate(lines):
        match = _TIMES.search(line)
        if match:
            heading = action_heading(lines, index)
            if heading and heading not in [a.split(" (x")[0] for a in actions]:
                actions.append(f"{heading} (x{match.group(1)})")
        for email in _EMAIL.findall(line):
            if email not in actors:
                actors.append(email)
    if actors:
        actions.append("by " + ", ".join(actors))
    return "\n".join(actions)


def notification_row(notification):
    """The report row of one notification (without the Projects column of folder/project scans).

    ``Summary`` is the message text, one line per paragraph; ``Details`` one
    item per line (``app.reporting.layouts`` shows them as a clamped message
    and a list; the CSV keeps each as one field).
    """
    messages = notification.get("messages") or []
    body = ((messages[0].get("body") or {}).get("text") or {}).get("enText", "") if messages else ""
    lines = html_to_lines(body)
    kind = notification.get("notificationType") or ""
    details = summarize_attachments(messages)
    if kind == SENSITIVE_ACTIONS:
        details = summarize_sensitive_actions(lines) or details
    return {
        categories.ADVISORY_DATE: str(notification.get("createTime") or "")[:10],
        categories.ADVISORY_TYPE: TYPE_LABELS.get(kind, kind.replace("NOTIFICATION_TYPE_", "").replace("_", " ").title() or "Unknown"),
        categories.ADVISORY_SUBJECT: ((notification.get("subject") or {}).get("text") or {}).get("enText", "") or "(no subject)",
        "Summary": truncate("\n".join(lines)),
        "Details": details,
    }


def notification_identity(notification):
    """What makes two project-level copies of a notification the same one."""
    subject = ((notification.get("subject") or {}).get("text") or {}).get("enText", "")
    return (notification.get("notificationType"), subject, str(notification.get("createTime") or "")[:19])


def settings_rows(settings):
    """One row per notification type that is explicitly turned off in an Advisory Notifications settings resource."""
    by_type = settings.get("notificationSettings") or {}
    rows = []
    for kind, label in TYPE_LABELS.items():
        entry = by_type.get(kind)
        if isinstance(entry, dict) and entry.get("enabled") is False:
            rows.append({"Type": label, "Issue": f"{label} notifications are turned off, so nobody receives them.", "Fix": SETTINGS_FIX})
    return rows


def list_notifications(notifications_resource, parent):
    """Every notification under ``parent`` (full view), all pages."""
    found, page_token = [], None
    while True:
        request = notifications_resource.list(parent=parent, view="FULL", pageSize=PAGE_SIZE, pageToken=page_token)
        page = request.execute() or {}
        found.extend(page.get("notifications", []))
        page_token = page.get("nextPageToken")
        if not page_token:
            return found


def setup_hint(error, permission):
    """``describe_error`` plus what to fix: the API in the CloudGauge project, or the permission."""
    text = describe_error(error)
    if disabled_api(error) is not None:
        return f"{text} Enable the Advisory Notifications API in the CloudGauge project: gcloud services enable {ADVISORY_API}"
    if getattr(getattr(error, "resp", None), "status", None) == 403 or " 403 " in f" {text} " or text.startswith("403"):
        return (f"{text} The scanner's service account needs the {permission} permission on the scanned scope "
                f"(see the CloudGauge Advisory Notifications Viewer custom role in the README).")
    return text


def _since(window_days):
    return (datetime.now(timezone.utc) - timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _within(notification, since):
    return str(notification.get("createTime") or "")[:19] >= since[:19]


def _client():
    credentials, _ = gcp.auth_default(scopes=SCOPES)
    return gcp.api_build("advisorynotifications", "v1", credentials=credentials)


def _write_errors(sink, job_id, message):
    """Both records as ``Error`` with the same message: neither can be produced."""
    sink.write_finding(job_id, "Advisory_Notifications", {"Check": ADVISORIES_CHECK, "Finding": [{"Error": message}], "Status": "Error"})
    sink.write_finding(job_id, "Advisory_Notifications_Settings", {"Check": SETTINGS_CHECK, "Finding": [{"Error": message}], "Status": "Error"})


def check_org_advisories(org_id, job_id, *, sink):
    """Writes the organization's Advisory Notifications briefing and its Advisory Notifications Settings check.

    Args:
        org_id (str): The organization ID.
        job_id (str): The job ID.
    """
    settings = get_settings()
    since = _since(settings.advisory_window_days)
    print(f"📣 [{job_id}] Checking {ADVISORIES_CHECK} for organization {org_id} (since {since[:10]})...")
    parent = f"organizations/{org_id}/locations/global"
    try:
        service = _client()
    except Exception as e:
        logging.warning(f"{ADVISORIES_CHECK}: could not build the Advisory Notifications client: {e}")
        _write_errors(sink, job_id, setup_hint(e, LIST_PERMISSION))
        return

    try:
        notifications = list_notifications(service.organizations().locations().notifications(), parent)
    except Exception as e:
        logging.warning(f"{ADVISORIES_CHECK}: could not list notifications of organization {org_id}: {e}")
        record = {"Check": ADVISORIES_CHECK, "Finding": [{"Error": setup_hint(e, LIST_PERMISSION)}], "Status": "Error"}
    else:
        rows = [notification_row(n) for n in sorted((n for n in notifications if _within(n, since)),
                                                     key=lambda n: str(n.get("createTime") or ""), reverse=True)]
        if not rows:
            rows = [{"Summary": f"No advisory notifications were published for this organization in the last "
                                f"{settings.advisory_window_days} days."}]
        record = {"Check": ADVISORIES_CHECK, "Finding": rows, "Status": "Informational"}
    sink.write_finding(job_id, "Advisory_Notifications", record)

    try:
        current = service.organizations().locations().getSettings(name=f"{parent}/settings").execute() or {}
    except Exception as e:
        logging.warning(f"{SETTINGS_CHECK}: could not read the settings of organization {org_id}: {e}")
        record = {"Check": SETTINGS_CHECK, "Finding": [{"Error": setup_hint(e, SETTINGS_PERMISSION)}], "Status": "Error"}
    else:
        rows = settings_rows(current)
        if rows:
            record = {"Check": SETTINGS_CHECK, "Finding": rows, "Status": "Action Required"}
        else:
            record = {"Check": SETTINGS_CHECK, "Finding": [{"Status": "Every advisory notification type is turned on for this organization."}],
                      "Status": "Compliant"}
    sink.write_finding(job_id, "Advisory_Notifications_Settings", record)


def check_project_advisories(scope_id, all_projects, job_id, *, sink):
    """Writes the Advisory Notifications briefing and Settings check over the projects of a folder or project scan.

    Args:
        scope_id (str): The scanned scope's ID (unused; the checks share one signature).
        all_projects (list): The project dictionaries of the scan (``projectId`` and ``projectNumber`` are used).
        job_id (str): The job ID.
    """
    settings = get_settings()
    since = _since(settings.advisory_window_days)
    print(f"📣 [{job_id}] Checking {ADVISORIES_CHECK} in {len(all_projects)} projects (since {since[:10]})...")
    try:
        service = _client()
    except Exception as e:
        logging.warning(f"{ADVISORIES_CHECK}: could not build the Advisory Notifications client: {e}")
        _write_errors(sink, job_id, setup_hint(e, LIST_PERMISSION))
        return
    skipped, settings_skipped = NotChecked(ADVISORIES_CHECK), NotChecked(SETTINGS_CHECK)
    seen, disabled = {}, []
    for project in all_projects:
        project_id, number = project["projectId"], str(project.get("projectNumber") or "").strip()
        if not number:
            error = ValueError("the project number is not known (the Advisory Notifications API addresses projects by number)")
            skipped.add(project_id, error)
            settings_skipped.add(project_id, error)
            continue
        parent = f"projects/{number}/locations/global"
        try:
            notifications = list_notifications(service.projects().locations().notifications(), parent)
        except Exception as e:
            if disabled_api_elsewhere(e, project_id, number):
                logging.warning(f"{ADVISORIES_CHECK}: the Advisory Notifications API is not enabled for the scanner: {e}")
                _write_errors(sink, job_id, setup_hint(e, LIST_PERMISSION))
                return
            skipped.add(project_id, e)
        else:
            for notification in notifications:
                if not _within(notification, since):
                    continue
                entry = seen.setdefault(notification_identity(notification), {"row": notification_row(notification), "projects": []})
                if project_id not in entry["projects"]:
                    entry["projects"].append(project_id)
        try:
            current = service.projects().locations().getSettings(name=f"{parent}/settings").execute() or {}
        except Exception as e:
            settings_skipped.add(project_id, e)
        else:
            disabled.extend({"Project": project_id, **row} for row in settings_rows(current))

    rows = [{categories.ADVISORY_PROJECTS: ", ".join(entry["projects"]), **entry["row"]}
            for entry in sorted(seen.values(), key=lambda entry: entry["row"][categories.ADVISORY_DATE], reverse=True)]
    if not rows:
        rows = [{"Summary": f"No advisory notifications were published for these projects in the last "
                            f"{settings.advisory_window_days} days. {ORG_ONLY_NOTE}"}]
    sink.write_finding(job_id, "Advisory_Notifications", {"Check": ADVISORIES_CHECK, "Finding": rows, "Status": "Informational"})
    if disabled:
        record = {"Check": SETTINGS_CHECK, "Finding": disabled, "Status": "Action Required"}
    else:
        record = {"Check": SETTINGS_CHECK, "Finding": [{"Status": "Every advisory notification type is turned on in every checked project."}],
                  "Status": "Compliant"}
    sink.write_finding(job_id, "Advisory_Notifications_Settings", record)
    skipped.write(sink, job_id)
    settings_skipped.write(sink, job_id)
