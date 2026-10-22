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
"""The history page (v17, ``app.reporting.history`` and ``/history/<scope>/<scope_id>``) and scheduled scans
(v17, ``app.services.schedules`` and the worker's ``/scheduled-scan``)."""
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from app.config import HISTORY_PAGE_SCANS
from app.extensions import EXTENSION_KEY
from app.reporting.history import build_chart, build_entries, build_history, status_flips
from app.services import schedules
from app.services.results_store import GcsResultsStore
from helpers import make_settings

SCOPE, SCOPE_ID = 'organization', '123456789'
SECURITY, COST, RELIABILITY, OPERATIONS = 'Security & Identity', 'Cost Optimization', 'Reliability & Resilience', 'Operational Excellence & Observability'
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def summary(job_id, generated_ts, checks, release='17', requested_by='alice@example.com', total_projects=4):
    """A scan summary as ``app.reporting.changes.summarize`` files it (the fields the page reads)."""
    stamp = datetime.strptime(generated_ts, '%Y%m%dT%H%M%SZ')
    return {'version': 3, 'release': release, 'job_id': job_id, 'scope': SCOPE, 'scope_id': SCOPE_ID,
            'generated_at': stamp.strftime('%Y-%m-%d %H:%M UTC'), 'generated_ts': generated_ts, 'total_projects': total_projects,
            'requested_by': requested_by, 'overview': {}, 'scores': {},
            'checks': {name: {'category': category, 'status': status, 'rows': 1} for name, (category, status) in checks.items()}}


CHECKS_1 = {'Open Firewall Rules': (SECURITY, 'Action Required'), 'Public GCS Buckets': (SECURITY, 'Compliant'),
            'GKE Hygiene': (RELIABILITY, 'Compliant'), 'Service Health Incidents': (RELIABILITY, 'Informational'),
            'VM Rightsizing': (COST, 'Error')}
CHECKS_2 = {'Open Firewall Rules': (SECURITY, 'Compliant'), 'Public GCS Buckets': (SECURITY, 'Action Required'),
            'GKE Hygiene': (RELIABILITY, 'Investigation Recommended'), 'Service Health Incidents': (RELIABILITY, 'Informational'),
            'VM Rightsizing': (COST, 'Compliant'), 'Quota Utilization (>80%)': (OPERATIONS, 'Compliant')}
CHECKS_3 = {**CHECKS_2, 'GKE Hygiene': (RELIABILITY, 'Compliant')}
SUMMARIES = [summary('job-3', '20261020T060000Z', CHECKS_3, requested_by='schedule: weekly-org'),
             summary('job-2', '20261013T060000Z', CHECKS_2),
             summary('job-1', '20261006T060000Z', CHECKS_1, release='16.1', requested_by=None)]  # newest first, as the store lists them


# --- the model ---

def test_status_flips_name_the_checks_whose_status_changed_worst_first():
    assert status_flips(SUMMARIES[1], SUMMARIES[2]) == (
        'Public GCS Buckets: Compliant → Action Required', 'GKE Hygiene: Compliant → Investigation Recommended',
        'Open Firewall Rules: Action Required → Compliant', 'VM Rightsizing: Error → Compliant')
    assert status_flips(SUMMARIES[0], SUMMARIES[1]) == ('GKE Hygiene: Investigation Recommended → Compliant',)
    assert status_flips(SUMMARIES[2], None) == () and status_flips(SUMMARIES[1], SUMMARIES[1]) == ()  # a briefing never flips


def test_entries_recompute_scores_and_counts_under_the_current_rule():
    entries = build_entries(SUMMARIES)
    assert [e.job_id for e in entries] == ['job-3', 'job-2', 'job-1'] and [e.first for e in entries] == [False, False, True]
    first = entries[2]
    assert (first.generated_at, first.release, first.requested_by, first.total_projects) == ('2026-10-06 06:00 UTC', '16.1', '', 4)
    assert first.scores == {'Stability': 100.0, 'Security': 50.0, 'Operations': None, 'Efficiency': None}  # an Error is coverage, not a verdict
    assert (first.action_count, first.investigation_count, first.compliant_count, first.error_count) == (1, 0, 2, 1)
    assert (first.score_text('Security'), first.score_class('Security'), first.score_text('Operations'), first.score_class('Operations')) == ('50%', 'low', 'Not assessed', 'none')
    assert entries[1].flips[:2] == ('Public GCS Buckets: Compliant → Action Required', 'GKE Hygiene: Compliant → Investigation Recommended')
    assert entries[1].inline_flips == entries[1].flips[:3] and entries[1].more_flips == 1
    assert entries[0].requested_by == 'schedule: weekly-org' and entries[0].scores['Stability'] == 100.0 and entries[0].score_class('Stability') == 'high'


def test_the_chart_draws_one_monochrome_line_per_pillar_oldest_left():
    chart = build_chart(build_entries(SUMMARIES))
    assert chart.scans == 3 and chart.view_box == '0 0 720 220'
    lines = {line.pillar: line for line in chart.lines}
    assert list(lines) == ['Stability', 'Security', 'Operations', 'Efficiency']
    assert lines['Stability'].points.split() == ['36.0,12.0', '333.0,192.0', '630.0,12.0'] and lines['Stability'].dash == ''  # 100 %, 0 %, 100 %
    assert lines['Security'].points.split()[0] == '36.0,102.0' and lines['Security'].dash == '6 4' and lines['Security'].last_text == '50%'
    assert lines['Operations'].points.split() == ['333.0,12.0', '630.0,12.0']  # not assessed in the first scan: the line starts at the second
    assert lines['Efficiency'].points.split() == ['333.0,12.0', '630.0,12.0'] and lines['Efficiency'].last_text == '100%'
    # Three lines end at 100 %: their labels are spread 13 units apart instead of being drawn over each other.
    assert [(line.pillar, line.last_y, line.label_y) for line in chart.lines] == [
        ('Stability', 12.0, 12.0), ('Security', 102.0, 102.0), ('Operations', 12.0, 25.0), ('Efficiency', 12.0, 38.0)]
    assert chart.ticks == ((192.0, '0'), (102.0, '50'), (12.0, '100')) and chart.labels == ((36.0, '2026-10-06'), (630.0, '2026-10-20'))
    one = build_chart(build_entries(SUMMARIES[:1]))
    assert one.labels == ((36.0, '2026-10-20'),) and one.lines[0].points == '36.0,12.0'
    never = build_chart(build_entries([summary('j', '20261001T000000Z', {'x': (COST, 'Error')})]))
    assert all(line.points == '' and line.last_text == '\u2014' for line in never.lines)
    assert build_chart(()) is None


def test_the_history_model():
    history = build_history(SCOPE, SCOPE_ID, SUMMARIES)
    assert (history.scope_title, history.count, history.span_text) == ('Organization', 3, '3 scans, 2026-10-06 to 2026-10-20')
    assert history.pillars == ('Stability', 'Security', 'Operations', 'Efficiency')
    empty = build_history('folder', '42', [])
    assert empty.entries == () and empty.chart is None and empty.span_text == ''
    assert build_history(SCOPE, SCOPE_ID, SUMMARIES[:1]).span_text == '1 scan, 2026-10-20 06:00 UTC'


# --- the page ---

def file_summaries(gcp, summaries):
    store = GcsResultsStore('test-bucket', client=gcp.storage)
    for item in summaries:
        store.write_scan_summary(item)
    return store


def test_the_history_page_lists_the_scans_newest_first_with_links_to_their_reports(client, gcp):
    file_summaries(gcp, SUMMARIES)
    page = client.get(f'/history/{SCOPE}/{SCOPE_ID}').get_data(as_text=True)
    assert '<title>Scan history: Organization 123456789</title>' in page and '<h1>Scan history</h1>' in page
    assert '3 scans, 2026-10-06 to 2026-10-20' in page and '<h2>Scores over time</h2>' in page and '<polyline class="line"' in page
    assert re.findall(r'href="/report/(job-\d)/123456789"', page) == ['job-3', 'job-2', 'job-1']
    assert 'schedule: weekly-org · v17 · 4 projects' in page and 'requester unknown · v16.1' in page
    assert 'First scan on record' in page and 'Public GCS Buckets: Compliant → Action Required' in page and '<summary>1 more</summary>' in page
    assert '<span class="score">50%</span>' in page and '<span class="score-none">Not assessed</span>' in page
    assert 'class="btn btn-outline" href="/">Start a scan</a>' in page and 'class="btn btn-primary' not in page  # no primary action: a page to read
    assert 'box-shadow' not in page


def test_the_history_page_without_a_scan_and_with_a_bad_scope(client, gcp):
    page = client.get('/history/folder/42').get_data(as_text=True)
    assert 'No completed scan of this folder is on record yet' in page and 'polyline' not in page
    assert client.get('/history/team/42').status_code == 404
    gcp.bucket.error = RuntimeError('bucket down')
    assert client.get(f'/history/{SCOPE}/{SCOPE_ID}').status_code == 500


def test_the_history_page_reads_the_newest_summaries_only(client, gcp):
    many = [summary(f'job-{i:03d}', (datetime(2026, 1, 1) + timedelta(days=i)).strftime('%Y%m%dT%H%M%SZ'), CHECKS_2) for i in range(HISTORY_PAGE_SCANS + 5)]
    store = file_summaries(gcp, many)
    listed = store.list_summaries(SCOPE, SCOPE_ID, limit=HISTORY_PAGE_SCANS)
    assert len(listed) == HISTORY_PAGE_SCANS and listed[0]['job_id'] == f'job-{HISTORY_PAGE_SCANS + 4:03d}' and listed[-1]['job_id'] == 'job-005'
    assert len(store.list_summaries(SCOPE, SCOPE_ID)) == HISTORY_PAGE_SCANS + 5 and store.list_scopes() == [(SCOPE, SCOPE_ID)]
    gcp.bucket.put(f'scopes/{SCOPE}/{SCOPE_ID}/20270101T000000Z_broken.json', '{not json')
    assert len(store.list_summaries(SCOPE, SCOPE_ID)) == HISTORY_PAGE_SCANS + 5  # the unreadable one is skipped
    page = client.get(f'/history/{SCOPE}/{SCOPE_ID}').get_data(as_text=True)
    assert f'The newest {HISTORY_PAGE_SCANS - 1} scans are listed' in page  # the unreadable summary took one slot of the listing window


def test_the_report_and_the_status_page_link_to_the_history(client, gcp):
    from app.reporting.html_report import generate_html_report

    assert '<dt>History</dt><dd class="history-link"><a href="/history/organization/123456789">every scan of this organization</a></dd>' in \
        generate_html_report(SCOPE, SCOPE_ID, 'job-1')
    status_page = client.get(f'/status/job-1/{SCOPE}/{SCOPE_ID}').get_data(as_text=True)
    assert 'const history_url = `/history/${scope}/${scope_id}`;' in status_page and '>View history</a>' in status_page
    index = client.get('/').get_data(as_text=True)
    assert 'id="history-link"' in index and 'historyLink.href = `/history/${encodeURIComponent(scopeSelect.value)}/${encodeURIComponent(this.value)}`' in index


# --- scheduled scans ---

def test_the_scheduler_body_is_validated():
    assert schedules.validate({'scope': 'organization', 'scope_id': ' 123 ', 'name': 'weekly-org'}) == ('organization', '123', 'weekly-org')
    assert schedules.validate({'scope': 'project', 'scope_id': 'p1'}) == ('project', 'p1', 'unnamed')
    for body in (None, [], {'scope': 'team', 'scope_id': 'x'}, {'scope': 'folder'}, {'scope': 'folder', 'scope_id': ''},
                 {'scope': 'folder', 'scope_id': 'a/b'}, {'scope': 'folder', 'scope_id': '42', 'name': 'bad name'}, {'scope': 'folder', 'scope_id': '42', 'name': 'x' * 65}):
        with pytest.raises(ValueError):
            schedules.validate(body)
    assert schedules.requested_by('weekly-org') == 'schedule: weekly-org'


def test_scan_in_progress_reads_the_locked_jobs_status(gcp):
    store = GcsResultsStore('test-bucket', client=gcp.storage)
    lock = {'job_id': 'job-9', 'scope_id': SCOPE_ID, 'started_at': (NOW - timedelta(hours=1)).isoformat()}
    assert schedules.scan_in_progress(store, None, NOW) is False and schedules.scan_in_progress(store, {}, NOW) is False
    assert schedules.scan_in_progress(store, lock, NOW) is True  # no status file yet: queued
    store.update_status('job-9', SCOPE_ID, 50, 'scanning')
    assert schedules.scan_in_progress(store, lock, NOW) is True
    store.update_status('job-9', SCOPE_ID, 100, 'done', status='completed')
    assert schedules.scan_in_progress(store, lock, NOW) is False
    store.update_status('job-9', SCOPE_ID, 100, 'boom', status='error')
    assert schedules.scan_in_progress(store, lock, NOW) is False
    stale = {**lock, 'started_at': (NOW - timedelta(days=2)).isoformat()}
    store.update_status('job-9', SCOPE_ID, 50, 'scanning')
    assert schedules.scan_in_progress(store, stale, NOW) is False  # older than the lock's maximum age
    assert schedules.scan_in_progress(store, {**lock, 'started_at': 'never'}, NOW) is False
    gcp.bucket.error = RuntimeError('bucket down')
    assert schedules.scan_in_progress(store, lock, NOW) is True  # cannot tell: assume running


@pytest.fixture
def worker(gcp):
    app = create_app(make_settings('testing', CLOUDGAUGE_ROLE='worker', WORKER_URL='https://cloudgauge-worker-123.us-central1.run.app'))
    return app.test_client(), app.extensions[EXTENSION_KEY]


def test_the_scheduled_scan_endpoint_enqueues_a_scan_once_per_running_scope(worker, gcp, monkeypatch):
    client, services = worker
    monkeypatch.setattr(schedules, 'utcnow', lambda: NOW)
    response = client.post('/scheduled-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID, 'name': 'weekly-org'})
    assert response.status_code == 202
    body = response.get_json()
    job_id = body['job_id']
    assert body == {'job_id': job_id, 'scope': SCOPE, 'scope_id': SCOPE_ID, 'schedule': 'weekly-org', 'requested_by': 'schedule: weekly-org',
                    'status_path': f'/status/{job_id}/{SCOPE}/{SCOPE_ID}'}
    ((_, task),) = gcp.tasks.tasks
    assert task['http_request']['url'] == 'https://cloudgauge-worker-123.us-central1.run.app/run-scan'
    assert json.loads(task['http_request']['body']) == {'scope': SCOPE, 'scope_id': SCOPE_ID, 'job_id': job_id, 'requested_by': 'schedule: weekly-org'}
    lock = json.loads(gcp.bucket.objects[f'schedules/{SCOPE}/{SCOPE_ID}.json'][0])
    assert lock == {'job_id': job_id, 'scope': SCOPE, 'scope_id': SCOPE_ID, 'schedule': 'weekly-org', 'requested_by': 'schedule: weekly-org',
                    'started_at': '2026-10-22T12:00:00+00:00'}
    # The job has not reported yet: the next run of the schedule starts nothing.
    again = client.post('/scheduled-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID, 'name': 'weekly-org'})
    assert again.status_code == 409 and again.get_json()['job_id'] == job_id and 'is still running' in again.get_json()['error']
    assert len(gcp.tasks.tasks) == 1
    # Another scope is unaffected; once the job completes, the scope can be scanned again.
    assert client.post('/scheduled-scan', json={'scope': 'project', 'scope_id': 'p1', 'name': 'nightly-p1'}).status_code == 202
    services.results_store.update_status(job_id, SCOPE_ID, 100, 'Scan complete!', status='completed')
    assert client.post('/scheduled-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID, 'name': 'weekly-org'}).status_code == 202
    assert len(gcp.tasks.tasks) == 3


def test_the_scheduled_scan_endpoint_rejects_a_malformed_body(worker, gcp):
    client, _ = worker
    assert client.post('/scheduled-scan', json={'scope': 'team', 'scope_id': 'x'}).status_code == 400
    assert client.post('/scheduled-scan', data='nope', content_type='text/plain').status_code == 400
    assert client.post('/scheduled-scan', json=['organization', SCOPE_ID]).status_code == 400
    assert client.post('/scheduled-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID, 'name': 'no spaces please'}).get_json() == {
        'error': "name must be 1-64 letters, digits, dashes or underscores (the Cloud Scheduler job's name)."}
    assert gcp.tasks.tasks == [] and not any(name.startswith('schedules/') for name in gcp.bucket.objects)


def test_the_web_service_has_no_scheduled_scan_endpoint(gcp):
    http = create_app(make_settings('testing', CLOUDGAUGE_ROLE='web', WORKER_URL='https://w.example')).test_client()
    assert http.post('/scheduled-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID}).status_code == 404
