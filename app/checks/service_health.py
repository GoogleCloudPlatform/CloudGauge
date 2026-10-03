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
"""Personalized Service Health (PSH): the Google Cloud incidents that affected the
scanned projects, and the projects that cannot tell.

One check, two records:

- **Service Health Incidents** - a *briefing*: one row per incident, updated in
  the last ``SERVICE_HEALTH_WINDOW_DAYS`` (default 90), whose relevance to at
  least one scanned project is in ``SERVICE_HEALTH_RELEVANCE`` (default
  Impacted and Related; "Impacted" is only computed for some products), active
  and resolved. Always ``Informational``, including the "nothing in the window"
  note: Google-side incidents are not the customer's configuration, so they
  never count toward the score (the report scores Compliant against the failing
  statuses only; Informational is outside both).
- **Personalized Service Health API Coverage** - a scored check: ``Action
  Required`` with one row per project in which the Service Health API is not
  enabled (such a project has no personalized incident view, alerts or
  relevance), ``Compliant`` when every project has it.

The API only reports relevance per *project*: the organization-level listing has
no relevance and shows every incident, so the check queries each project
(``projects/{id}/locations/global/events``). Relevance cannot be filtered
server-side (the API rejects ``relevance=`` in ``filter``); ``update_time >=``
is accepted and bounds the window. The same incident is returned by every
project it touched, under a project-specific name: rows are folded by the
incident ID (the last segment of the name) here, and the aggregation of a
sharded scan folds them again across shards (``categories.ROW_FOLDS``). The
Project IDs column lists every project, so the report's filter box finds an
incident by project ID.

The calls go to the REST endpoint through ``gcp.http_get`` (the client
library's discovery bundle has no Service Health document); a 429 or 5xx is
retried with backoff. A project that answers 403 SERVICE_DISABLED is the
coverage finding; any other failure is reported as "Projects not checked".
"""
import logging
import time
from datetime import datetime, timedelta, timezone

from google.auth.transport.requests import Request as GoogleAuthRequest

from app.checks import categories
from app.checks.not_checked import NotChecked, describe_error, disabled_api, disabled_api_elsewhere
from app.config import SCOPES, get_settings
from app.services import gcp

INCIDENTS_CHECK = "Service Health Incidents"
COVERAGE_CHECK = "Personalized Service Health API Coverage"
SERVICE_HEALTH_API = "servicehealth.googleapis.com"
EVENTS_URL = "https://servicehealth.googleapis.com/v1/projects/{project_id}/locations/global/events"
PAGE_SIZE = 100
REQUEST_TIMEOUT_SECONDS = 60
RETRY_DELAYS = (2, 4, 8)  # seconds before retrying a 429 or 5xx answer; then the error is reported
RETRIED_STATUSES = (429, 500, 502, 503, 504)
MAX_LOCATIONS_LISTED = 10
RELEVANCE_LABELS = {"IMPACTED": "Impacted", "RELATED": "Related", "PARTIALLY_RELATED": "Partially related",
                    "NOT_IMPACTED": "Not impacted", "UNKNOWN": "Unknown"}
DETAILED_STATE_LABELS = {"EMERGING": "Emerging", "CONFIRMED": "Confirmed", "RESOLVED": "Resolved", "MERGED": "Merged",
                         "AUTO_CLOSED": "Auto-closed", "FALSE_POSITIVE": "False positive"}


class ServiceHealthError(Exception):
    """A non-2xx answer of the Service Health API: ``status`` and the API's message."""

    def __init__(self, status, message):
        super().__init__(f"{status} {message}")
        self.status = status
        self.message = message


def _error_message(response):
    try:
        error = response.json().get("error", {})
        return error.get("message") or response.text
    except Exception:
        return getattr(response, "text", "") or f"HTTP {response.status_code}"


def get_json(url, headers, params):
    """GET ``url`` as JSON, retrying 429 and 5xx answers; raises :class:`ServiceHealthError` otherwise."""
    for attempt, delay in enumerate((*RETRY_DELAYS, None)):
        response = gcp.http_get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
        if response.status_code == 200:
            return response.json()
        if response.status_code in RETRIED_STATUSES and delay is not None:
            logging.warning(f"Service Health API answered {response.status_code} for {url}; retrying in {delay}s (attempt {attempt + 1})")
            time.sleep(delay)
            continue
        raise ServiceHealthError(response.status_code, _error_message(response))


def list_events(project_id, since, headers):
    """Every event of ``project_id`` updated at or after ``since`` (RFC 3339), all pages, basic view."""
    events, page_token = [], None
    while True:
        params = {"filter": f'update_time>="{since}"', "view": "EVENT_VIEW_BASIC", "pageSize": PAGE_SIZE}
        if page_token:
            params["pageToken"] = page_token
        page = get_json(EVENTS_URL.format(project_id=project_id), headers, params)
        events.extend(page.get("events", []))
        page_token = page.get("nextPageToken")
        if not page_token:
            return events


def _timestamp(value):
    """``2026-10-01T17:48:21.524Z`` -> ``2026-10-01 17:48``; empty when missing."""
    text = str(value or "")
    return f"{text[:10]} {text[11:16]}".strip() if len(text) >= 16 else text


def _incident_id(event):
    return str(event.get("name") or "").rsplit("/", 1)[-1]


def fold_events(events_by_project):
    """``{project_id: [event, ...]}`` -> ``{incident_id: incident}`` with the projects, products, locations and
    relevances of each incident. Each project's copy of an event lists the impacts relevant to that project,
    so products and locations are merged from every copy; the event fields come from the first copy, or
    from an ``ACTIVE`` copy when one project still sees the incident open."""
    incidents = {}
    for project_id, events in events_by_project.items():
        for event in events:
            key = _incident_id(event)
            incident = incidents.get(key)
            if incident is None:
                incident = incidents[key] = {"id": key, "event": event, "projects": [], "relevances": set(), "products": [], "locations": []}
            elif event.get("state") == "ACTIVE" and incident["event"].get("state") != "ACTIVE":
                incident["event"] = event
            for impact in event.get("eventImpacts", []):
                product = impact.get("product", {})
                name = product.get("displayName") or product.get("productName")
                location = impact.get("location", {}).get("locationName")
                if name and name not in incident["products"]:
                    incident["products"].append(name)
                if location and location not in incident["locations"]:
                    incident["locations"].append(location)
            if project_id not in incident["projects"]:
                incident["projects"].append(project_id)
            incident["relevances"].add(event.get("relevance") or "UNKNOWN")
    return incidents


def incident_row(incident):
    """The report row of a folded incident (column names shared with ``categories.fold_incident_rows``)."""
    event, locations = incident["event"], incident["locations"]
    state = categories.ACTIVE_INCIDENT if event.get("state") == "ACTIVE" else "Resolved"
    detailed = DETAILED_STATE_LABELS.get(event.get("detailedState"))
    if detailed and detailed != state:
        state = f"{state} ({detailed.lower()})"
    if len(locations) > MAX_LOCATIONS_LISTED:
        locations_text = f"{len(locations)} locations: {', '.join(locations[:MAX_LOCATIONS_LISTED])}, ..."
    else:
        locations_text = ", ".join(locations)
    relevance = min((RELEVANCE_LABELS.get(r, "Unknown") for r in incident["relevances"]),
                    key=lambda r: categories.RELEVANCE_ORDER.index(r) if r in categories.RELEVANCE_ORDER else len(categories.RELEVANCE_ORDER))
    return {
        categories.INCIDENT_STATE: state,
        categories.INCIDENT_STARTED: _timestamp(event.get("startTime")),
        "Ended": _timestamp(event.get("endTime")),
        "Incident": event.get("title") or incident["id"],
        "Products": ", ".join(incident["products"]),
        "Locations": locations_text,
        categories.INCIDENT_PROJECT_COUNT: len(incident["projects"]),
        categories.INCIDENT_PROJECTS: ", ".join(incident["projects"]),
        categories.INCIDENT_RELEVANCE: relevance,
        categories.INCIDENT_ID: incident["id"],
    }


def describe_relevance(values):
    """``("IMPACTED", "RELATED")`` -> ``"Impacted or Related"`` for the briefing's note."""
    labels = [RELEVANCE_LABELS.get(v, v.title()) for v in values]
    return " or ".join(labels) if len(labels) <= 2 else ", ".join(labels[:-1]) + f" or {labels[-1]}"


def _write_errors(sink, job_id, message):
    """Both records as ``Error`` with the same message: neither can be produced."""
    sink.write_finding(job_id, "Service_Health_Incidents", {"Check": INCIDENTS_CHECK, "Finding": [{"Error": message}], "Status": "Error"})
    sink.write_finding(job_id, "Personalized_Service_Health_API_Coverage", {"Check": COVERAGE_CHECK, "Finding": [{"Error": message}], "Status": "Error"})


def check_service_health_incidents(scope_id, all_projects, job_id, *, sink):
    """Writes the Service Health Incidents briefing and the Personalized Service Health API Coverage check.

    Args:
        scope_id (str): The scanned scope's ID (unused; the checks share one signature).
        all_projects (list): The project dictionaries of the scan (``projectId`` is used).
        job_id (str): The job ID.
    """
    settings = get_settings()
    wanted = set(settings.service_health_relevance)
    since = (datetime.now(timezone.utc) - timedelta(days=settings.service_health_window_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"❤️‍🩹 [{job_id}] Checking {INCIDENTS_CHECK} ({', '.join(sorted(wanted))}, since {since[:10]}) in {len(all_projects)} projects...")
    skipped = NotChecked(INCIDENTS_CHECK)
    events_by_project, without_api = {}, []
    credentials = None
    for project in all_projects:
        project_id = project["projectId"]
        try:
            if credentials is None or getattr(credentials, "expired", False):
                credentials, _ = gcp.auth_default(scopes=SCOPES)
                credentials.refresh(GoogleAuthRequest())
            headers = {"Authorization": f"Bearer {credentials.token}"}
            events = list_events(project_id, since, headers)
        except Exception as e:
            service = disabled_api(e)
            if service is not None and service in (SERVICE_HEALTH_API, ""):
                if disabled_api_elsewhere(e, project_id, project.get("projectNumber")):
                    logging.warning(f"{INCIDENTS_CHECK}: the Service Health API is not enabled for the scanner: {e}")
                    _write_errors(sink, job_id, f"{describe_error(e)} Enable the Service Health API in the CloudGauge project: "
                                                f"gcloud services enable {SERVICE_HEALTH_API}")
                    return
                logging.info(f"{COVERAGE_CHECK}: {SERVICE_HEALTH_API} is not enabled in {project_id}")
                without_api.append(project_id)
            else:
                skipped.add(project_id, e)
            continue
        events_by_project[project_id] = [e for e in events if (e.get("relevance") or "UNKNOWN") in wanted]

    incidents = fold_events(events_by_project)
    rows = categories.sort_incident_rows([incident_row(incident) for incident in incidents.values()])
    if not rows:
        rows = [{"Summary": f"No Google Cloud incidents with relevance {describe_relevance(settings.service_health_relevance)} "
                            f"to these projects were recorded in the last {settings.service_health_window_days} days."}]
    sink.write_finding(job_id, "Service_Health_Incidents", {"Check": INCIDENTS_CHECK, "Finding": rows, "Status": "Informational"})

    if without_api:
        coverage_rows = [{"Project": project_id,
                          "Issue": "Service Health API not enabled: this project has no personalized incident view, alerts or relevance.",
                          "Fix": f"gcloud services enable {SERVICE_HEALTH_API} --project={project_id}"} for project_id in without_api]
        coverage = {"Check": COVERAGE_CHECK, "Finding": coverage_rows, "Status": "Action Required"}
    else:
        coverage = {"Check": COVERAGE_CHECK, "Finding": [{"Status": "The Service Health API is enabled in every checked project."}], "Status": "Compliant"}
    sink.write_finding(job_id, "Personalized_Service_Health_API_Coverage", coverage)
    skipped.write(sink, job_id)
