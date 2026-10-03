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
"""``app.checks.service_health``: the Service Health Incidents briefing and the
Personalized Service Health API Coverage check (v14).

The check reads each project's events over REST; the tests answer the URL per
project with canned responses and look at the two records it writes plus the
"Projects not checked" record. The cross-shard fold of incident rows lives in
``app.checks.categories`` and is tested here too.
"""
import json
from types import SimpleNamespace

import pytest

from app.checks import categories, service_health
from app.checks.categories import merge_shard_findings
from app.checks.service_health import (COVERAGE_CHECK, INCIDENTS_CHECK, ServiceHealthError, check_service_health_incidents,
                                        describe_relevance, fold_events, incident_row, list_events)

JOB = 'job-14'
PROJECTS = [{'projectId': 'web-prod', 'projectNumber': '111'}, {'projectId': 'data-lake', 'projectNumber': '222'},
            {'projectId': 'no-psh', 'projectNumber': '333'}, {'projectId': 'locked-down', 'projectNumber': '444'}]
DISABLED = ("Service Health API has not been used in project {p} before or it is disabled. Enable it by visiting "
            "https://console.developers.google.com/apis/api/servicehealth.googleapis.com/overview?project={p} then retry.")


def event(incident_id, project, relevance, state='CLOSED', start='2026-09-20T10:00:00Z', end='2026-09-20T12:30:00Z',
          title=None, products=(('Cloud Run', 'us-central1'),)):
    return {
        'name': f'projects/{project}/locations/global/events/{incident_id}', 'title': title or f'Incident {incident_id}',
        'category': 'INCIDENT', 'state': state, 'detailedState': 'CONFIRMED' if state == 'ACTIVE' else 'RESOLVED',
        'relevance': relevance, 'startTime': start, **({'endTime': end} if state != 'ACTIVE' else {}),
        'updateTime': end, 'eventImpacts': [{'product': {'displayName': name}, 'location': {'locationName': loc}} for name, loc in products],
    }


class Response:
    def __init__(self, status, body):
        self.status_code, self.text = status, json.dumps(body)

    def json(self):
        return json.loads(self.text)


def error_response(status, message):
    return Response(status, {'error': {'code': status, 'message': message, 'status': 'PERMISSION_DENIED' if status == 403 else 'ERROR'}})


class FakeServiceHealth:
    """Answers ``gcp.http_get`` for the events URL: a list of responses per project, served in order (the last repeats)."""

    def __init__(self, answers):
        self.answers = {project: list(responses) for project, responses in answers.items()}
        self.requests = []  # (project, params)

    def __call__(self, url, headers=None, params=None, timeout=None):
        project = url.split('/projects/')[1].split('/')[0]
        self.requests.append((project, dict(params or {})))
        assert headers == {'Authorization': 'Bearer fake-access-token'} and timeout
        responses = self.answers[project]
        return responses.pop(0) if len(responses) > 1 else responses[0]


@pytest.fixture
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(service_health.time, 'sleep', slept.append)
    return slept


def run(projects=PROJECTS):
    writes = []
    sink = SimpleNamespace(write_finding=lambda job, name, record: writes.append((name, record)))
    check_service_health_incidents('scope', projects, JOB, sink=sink)
    return dict(writes), writes


# --- Folding events into incidents ---

def test_events_of_several_projects_fold_into_one_incident_row():
    events = {
        'web-prod': [event('A', 'web-prod', 'IMPACTED', state='ACTIVE', start='2026-10-01T08:00:00Z', products=(('Cloud Run', 'us-central1'),)),
                     event('B', 'web-prod', 'RELATED', start='2026-09-01T00:00:00Z', end='2026-09-01T03:00:00Z')],
        'data-lake': [event('A', 'data-lake', 'RELATED', state='CLOSED', products=(('Cloud Run', 'us-central1'), ('Cloud Run', 'us-east1')))],
    }
    incidents = fold_events(events)
    assert list(incidents) == ['A', 'B']
    rows = categories.sort_incident_rows([incident_row(i) for i in incidents.values()])
    assert rows[0] == {
        'State': 'Active (confirmed)', 'Started': '2026-10-01 08:00', 'Ended': '', 'Incident': 'Incident A', 'Products': 'Cloud Run',
        'Locations': 'us-central1, us-east1', 'Impacted projects': 2, 'Project IDs': 'web-prod, data-lake',
        'Relevance': 'Impacted', 'Incident ID': 'A',  # the highest relevance of its projects; active if any copy was
    }
    assert rows[1]['State'] == 'Resolved' and rows[1]['Ended'] == '2026-09-01 03:00' and rows[1]['Relevance'] == 'Related'
    # Every project is named, so the report's filter box finds the incident by project ID.
    assert 'data-lake' in rows[0]['Project IDs']


def test_every_location_is_listed():
    """The row carries every location (the report folds a long list behind a count; the CSV has it all)."""
    many = tuple(('Compute Engine', f'region-{i}') for i in range(14))
    row = incident_row(fold_events({'p': [event('C', 'p', 'IMPACTED', products=many)]})['C'])
    assert row['Locations'] == ', '.join(f'region-{i}' for i in range(14))
    assert describe_relevance(('IMPACTED', 'RELATED')) == 'Impacted or Related'
    assert describe_relevance(('IMPACTED', 'RELATED', 'PARTIALLY_RELATED')) == 'Impacted, Related or Partially related'


# --- The REST call ---

def test_list_events_pages_and_retries_transient_errors(gcp, monkeypatch, no_sleep):
    pages = [error_response(503, 'unavailable'), Response(200, {'events': [event('A', 'p', 'IMPACTED')], 'nextPageToken': 't2'}),
             Response(200, {'events': [event('B', 'p', 'RELATED')]})]
    fake = FakeServiceHealth({'p': pages})
    monkeypatch.setattr(service_health.gcp, 'http_get', fake)
    events = list_events('p', '2026-07-01T00:00:00Z', {'Authorization': 'Bearer fake-access-token'})
    assert [e['name'].rsplit('/', 1)[-1] for e in events] == ['A', 'B']
    assert no_sleep == [2]  # one retry after the 503
    first, second = fake.requests[1][1], fake.requests[2][1]
    assert first == {'filter': 'update_time>="2026-07-01T00:00:00Z"', 'view': 'EVENT_VIEW_BASIC', 'pageSize': 100}
    assert second['pageToken'] == 't2'


def test_list_events_gives_up_after_the_retries(gcp, monkeypatch, no_sleep):
    monkeypatch.setattr(service_health.gcp, 'http_get', FakeServiceHealth({'p': [error_response(429, 'quota')]}))
    with pytest.raises(ServiceHealthError) as info:
        list_events('p', '2026-07-01T00:00:00Z', {'Authorization': 'Bearer fake-access-token'})
    assert (info.value.status, info.value.message, str(info.value)) == (429, 'quota', '429 quota')
    assert no_sleep == [2, 4, 8]


# --- The check ---

def test_check_writes_the_briefing_the_coverage_and_the_skipped_projects(gcp, monkeypatch):
    monkeypatch.setattr(service_health.gcp, 'http_get', FakeServiceHealth({
        'web-prod': [Response(200, {'events': [event('A', 'web-prod', 'IMPACTED', state='ACTIVE'),
                                               event('N', 'web-prod', 'NOT_IMPACTED'), event('P', 'web-prod', 'PARTIALLY_RELATED')]})],
        'data-lake': [Response(200, {'events': [event('A', 'data-lake', 'RELATED', state='ACTIVE')]})],
        'no-psh': [error_response(403, DISABLED.format(p='no-psh'))],
        'locked-down': [error_response(403, 'The caller does not have permission')],
    }))
    records, writes = run(PROJECTS)
    assert [name for name, _ in writes] == ['Service_Health_Incidents', 'Personalized_Service_Health_API_Coverage',
                                            'NOT_CHECKED_Service_Health_Incidents']
    briefing = records['Service_Health_Incidents']
    assert briefing['Check'] == INCIDENTS_CHECK and briefing['Status'] == 'Informational'  # never scored
    assert [(r['Incident ID'], r['Project IDs'], r['Relevance'], r['State']) for r in briefing['Finding']] == \
           [('A', 'web-prod, data-lake', 'Impacted', 'Active (confirmed)')]  # default relevance: Impacted and Related only
    coverage = records['Personalized_Service_Health_API_Coverage']
    assert coverage['Check'] == COVERAGE_CHECK and coverage['Status'] == 'Action Required'
    assert coverage['Finding'] == [{'Project': 'no-psh',
                                    'Issue': 'Service Health API not enabled: this project has no personalized incident view, alerts or relevance.',
                                    'Fix': 'gcloud services enable servicehealth.googleapis.com --project=no-psh'}]
    skipped = records['NOT_CHECKED_Service_Health_Incidents']
    assert skipped['Category'] == 'Reliability & Resilience' and skipped['Status'] == 'Error'
    assert skipped['Finding'] == [{'Project': 'locked-down', 'Skipped check': INCIDENTS_CHECK, 'Reason': '403 The caller does not have permission'}]


def test_nothing_in_the_window_is_a_note_and_full_coverage_is_compliant(gcp, monkeypatch):
    monkeypatch.setattr(service_health.gcp, 'http_get', FakeServiceHealth({'web-prod': [Response(200, {})], 'data-lake': [Response(200, {'events': []})]}))
    records, writes = run(PROJECTS[:2])
    assert len(writes) == 2  # no "Projects not checked"
    assert records['Service_Health_Incidents'] == {'Check': INCIDENTS_CHECK, 'Status': 'Informational', 'Finding': [
        {'Summary': 'No Google Cloud incidents with relevance Impacted or Related to these projects were recorded in the last 90 days.'}]}
    assert records['Personalized_Service_Health_API_Coverage'] == {
        'Check': COVERAGE_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': 'The Service Health API is enabled in every checked project.'}]}


def test_window_and_relevance_come_from_the_settings(gcp, monkeypatch):
    monkeypatch.setenv('SERVICE_HEALTH_WINDOW_DAYS', '30')
    monkeypatch.setenv('SERVICE_HEALTH_RELEVANCE', 'impacted, partially_related')
    fake = FakeServiceHealth({'web-prod': [Response(200, {'events': [event('A', 'web-prod', 'RELATED'), event('P', 'web-prod', 'PARTIALLY_RELATED')]})]})
    monkeypatch.setattr(service_health.gcp, 'http_get', fake)
    records, _ = run(PROJECTS[:1])
    assert [r['Incident ID'] for r in records['Service_Health_Incidents']['Finding']] == ['P']
    since = fake.requests[0][1]['filter']
    assert since.startswith('update_time>="') and since.endswith('Z"')
    with pytest.raises(ValueError, match='SERVICE_HEALTH_RELEVANCE'):
        monkeypatch.setenv('SERVICE_HEALTH_RELEVANCE', 'IMPACTED,SOMETIMES')
        run(PROJECTS[:1])


def test_api_disabled_in_the_scanner_project_is_one_error_not_a_coverage_finding(gcp, monkeypatch):
    """The disabled-API message names the project that must enable it. When that is not the scanned
    project, it is CloudGauge's own, and every project would fail the same way: both records say so once."""
    fake = FakeServiceHealth({p['projectId']: [error_response(403, DISABLED.format(p='cloudgauge-host'))] for p in PROJECTS})
    monkeypatch.setattr(service_health.gcp, 'http_get', fake)
    records, writes = run(PROJECTS)
    assert len(fake.requests) == 1 and len(writes) == 2
    for record in records.values():
        assert record['Status'] == 'Error'
        (row,) = record['Finding']
        assert row['Error'].startswith('403 Service Health API has not been used in project cloudgauge-host')
        assert row['Error'].endswith('Enable the Service Health API in the CloudGauge project: gcloud services enable servicehealth.googleapis.com')


# --- Across shards ---

def test_incident_rows_of_several_shards_fold_into_one():
    """Shard A and shard B each saw incident A from their own projects; the merged report has one row naming all of them.
    A shard with nothing in the window contributes its note only when no shard had rows."""
    note = {'Summary': 'No Google Cloud incidents ... in the last 90 days.'}
    row_a = {'State': 'Resolved', 'Started': '2026-09-20 10:00', 'Ended': '2026-09-20 12:30', 'Incident': 'Incident A', 'Products': 'Cloud Run',
             'Locations': 'us-central1', 'Impacted projects': 1, 'Project IDs': 'p-1', 'Relevance': 'Related', 'Incident ID': 'A'}
    row_b = {**row_a, 'State': 'Active (confirmed)', 'Ended': '', 'Locations': 'us-east1', 'Impacted projects': 2,
             'Project IDs': 'p-7, p-9', 'Relevance': 'Impacted'}
    row_c = {**row_a, 'Incident': 'Incident C', 'Incident ID': 'C', 'Started': '2026-09-25 10:00', 'Project IDs': 'p-7', 'Relevance': 'Related'}
    shards = [
        {'Check': INCIDENTS_CHECK, 'Status': 'Informational', 'Finding': [row_a]},
        {'Check': INCIDENTS_CHECK, 'Status': 'Informational', 'Finding': [note]},
        {'Check': INCIDENTS_CHECK, 'Status': 'Informational', 'Finding': [row_c, row_b]},
    ]
    (merged,) = merge_shard_findings(shards)
    assert merged['Finding'] == [
        {**row_a, 'State': 'Active (confirmed)', 'Ended': '', 'Locations': 'us-central1, us-east1',  # active first, still open
         'Impacted projects': 3, 'Project IDs': 'p-1, p-7, p-9', 'Relevance': 'Impacted'},
        row_c,
    ]
    more = {**row_a, 'Products': 'Cloud SQL, Cloud Run', 'Locations': 'region-1, us-central1, region-0'}
    (merged,) = merge_shard_findings([{**shards[0], 'Finding': [row_a]}, {**shards[0], 'Finding': [more]}])
    assert merged['Finding'][0]['Products'] == 'Cloud Run, Cloud SQL'  # a union, in order of first sight, every item kept
    assert merged['Finding'][0]['Locations'] == 'us-central1, region-1, region-0'
    assert merge_shard_findings(shards[1:2] * 2) == [shards[1]]  # only notes: one note
    # The coverage check merges like any scored check: the Compliant placeholder yields to the findings.
    coverage = [{'Check': COVERAGE_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': 'ok'}]},
                {'Check': COVERAGE_CHECK, 'Status': 'Action Required', 'Finding': [{'Project': 'p-3', 'Issue': 'x', 'Fix': 'y'}]}]
    assert merge_shard_findings(coverage) == coverage[1:]
