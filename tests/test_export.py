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
"""The BigQuery export (v17, ``app.services.bigquery_export``): the rows, the load jobs, what the report's header says,
and the hook in the inline and sharded report builds."""
import copy
import json
from types import SimpleNamespace

import httplib2
import pytest
from googleapiclient.errors import HttpError

import samples
from app import scan_job
from app.config import Settings
from app.extensions import EXTENSION_KEY
from app.reporting.html_report import generate_reports
from app.services.bigquery_export import (
    EXPORTED,
    FAILED,
    FINDINGS_SCHEMA,
    RUNNING,
    SCANS_SCHEMA,
    BigQueryExporter,
    ExportResult,
    build_exporter,
    finding_rows,
    scan_row,
    timestamp_of,
)
from app.services.results_store import GcsResultsStore
from fakes import _execute
from helpers import DEPLOYED_ENV, make_settings, set_env

SCOPE, SCOPE_ID, JOB = 'organization', '123456789', 'job-17'


def sample_results():
    return copy.deepcopy(samples.FINDINGS) | {'Organization Policies': (samples.BEST_PRACTICES, samples.CURRENT_POLICIES)}


class FakeBigQuery:
    """``bigquery v2``: ``jobs().insert`` records the load jobs, ``jobs().get`` answers from ``states`` (a list per job
    ID, consumed one per poll; the last repeats), ``jobs().query`` answers the backfill's job-ID query."""

    def __init__(self):
        self.inserted = []  # (projectId, body)
        self.states = {}  # job id -> [status dicts]
        self.insert_error = None
        self.polled = []
        self.query_rows = []
        self.query_error = None

    def jobs(self):
        fake = self

        def insert(projectId, body):
            fake.inserted.append((projectId, body))
            return _execute(fake.insert_error or {'jobReference': body['jobReference']})

        def get(projectId, jobId, location=None):
            fake.polled.append(jobId)
            states = fake.states.get(jobId, [{'state': 'DONE'}])
            status = states.pop(0) if len(states) > 1 else states[0]
            return _execute({'jobReference': {'jobId': jobId}, 'status': status})

        def query(projectId, body):
            fake.queries = getattr(fake, 'queries', []) + [body]
            return _execute(fake.query_error or {'rows': [{'f': [{'v': job_id}]} for job_id in fake.query_rows]})

        return SimpleNamespace(insert=insert, get=get, query=query)


def http_error(status, message):
    return HttpError(httplib2.Response({'status': status, 'reason': message}), json.dumps({'error': {'code': status, 'message': message}}).encode(), uri='x')


@pytest.fixture
def exporter(gcp):
    settings = make_settings(BIGQUERY_DATASET='cloudgauge', BIGQUERY_EXPORT_WAIT_SECONDS='10')
    store = GcsResultsStore(settings.results_bucket)
    bigquery = FakeBigQuery()
    gcp.discovery.apis['bigquery'] = bigquery
    clock = {'now': 0.0}
    exporter = BigQueryExporter(settings, store, clock=lambda: clock['now'], sleep=lambda seconds: clock.__setitem__('now', clock['now'] + seconds))
    exporter.fake, exporter.clock_state = bigquery, clock
    return exporter


# --- the rows ---

def test_the_scan_row_and_the_finding_rows():
    html, csv_text, summary = generate_reports(SCOPE, SCOPE_ID, JOB, sample_results(), total_projects=4, requested_by='alice@example.com')
    assert timestamp_of('20261022T140501Z') == '2026-10-22T14:05:01Z' and timestamp_of('odd') == 'odd' and timestamp_of(None) == ''
    row = scan_row(summary, projects_scanned=4)
    assert (row['job_id'], row['scope'], row['scope_id'], row['release'], row['requested_by'], row['total_projects'], row['projects_scanned']) == \
        (JOB, SCOPE, SCOPE_ID, summary['release'], 'alice@example.com', 4, 4)
    assert row['generated_at'] == timestamp_of(summary['generated_ts']) and row['export_version'] == 1
    assert (row['action_count'], row['investigation_count'], row['compliant_count'], row['error_count']) == (4, 1, 3, 1)
    assert round(row['security_score']) == 42 and round(row['cost_score']) == 50 and row['operations_score'] == 0
    assert {c['check_name']: (c['category'], c['status'], c['rows']) for c in row['checks']}['Project IAM Hygiene'] == ('Security & Identity', 'Action Required', 2)
    assert set(row) == {field['name'] for field in SCANS_SCHEMA}

    rows = finding_rows(summary, sample_results())
    assert all(set(r) == {field['name'] for field in FINDINGS_SCHEMA} for r in rows)
    by_check = {}
    for r in rows:
        by_check.setdefault(r['check_name'], []).append(r)
    iam = by_check['Project IAM Hygiene']
    assert [(r['project'], r['identity'], r['status'], r['new_since_last_scan']) for r in iam] == [
        ('web-prod', 'web-prod · user:alice@example.com · roles/owner', 'Action Required', None),  # the merged group's worst status
        ('data-lake', 'data-lake · allUsers · roles/viewer', 'Action Required', None)]
    assert json.loads(iam[0]['row_json']) == {'Project': 'web-prod', 'Member': 'user:alice@example.com', 'Role': 'roles/owner'}
    assert [r['identity'] for r in by_check['Idle Persistent Disks']] == ['data-lake · orphan-disk', 'web-prod · old-boot-disk']  # the saving is not identity
    assert by_check['Essential Contacts'][0]['row_json'] == '{"text": "No security contact"}' and by_check['Essential Contacts'][0]['project'] is None
    policies = by_check['Organization Policies']
    assert [(r['identity'], r['status']) for r in policies] == [
        ('Networking · Skip default network creation', 'Non-compliant'), ('Networking · Restrict VM external IPs', 'Not Configured'),
        ('Security · Disable service account key creation', 'Compliant'), ('Security · Domain restricted sharing', 'Unsupported')]
    assert 'Public GCS Buckets' in by_check  # a text detail: one row with the text
    assert all(r['job_id'] == JOB and r['scope_id'] == SCOPE_ID and r['generated_at'] == row['generated_at'] for r in rows)


def test_finding_rows_mark_what_the_previous_scan_did_not_have():
    first = generate_reports(SCOPE, SCOPE_ID, 'job-1', sample_results(), total_projects=4)[2]
    results = sample_results()
    results['Security & Identity'][1]['Finding'].append({'Project': 'ml-dev', 'Member': 'serviceAccount:ci@ml-dev.iam.gserviceaccount.com', 'Role': 'roles/editor'})
    captured = {}

    def export(summary, all_results, changes):
        captured['rows'] = finding_rows(summary, all_results, changes)
        return ExportResult(EXPORTED, 'cloudgauge', rows=len(captured['rows']))

    html, _, _ = generate_reports(SCOPE, SCOPE_ID, 'job-2', results, total_projects=4, previous=first, export=export)
    iam = [r for r in captured['rows'] if r['check_name'] == 'Project IAM Hygiene']
    assert [(r['project'], r['new_since_last_scan']) for r in iam] == [('web-prod', False), ('data-lake', False), ('ml-dev', True)]
    assert '<dt>BigQuery export</dt>' in html and 'loaded into cloudgauge.findings and cloudgauge.scans' in html


# --- the loader ---

def test_export_stages_ndjson_and_runs_two_idempotent_load_jobs(exporter, gcp):
    summary = generate_reports(SCOPE, SCOPE_ID, JOB, sample_results(), total_projects=4)[2]
    result = exporter.export(summary, sample_results(), projects_scanned=4)
    assert (result.state, result.dataset, result.rows) == (EXPORTED, 'cloudgauge', len(finding_rows(summary, sample_results())))
    assert result.job_ids == ('cloudgauge-job-17-scans', 'cloudgauge-job-17-findings')
    assert result.header_text.endswith('finding rows and this scan\'s summary loaded into cloudgauge.findings and cloudgauge.scans') and result.dot_class == 'compliant'
    (scans_project, scans_body), (findings_project, findings_body) = exporter.fake.inserted
    assert scans_project == findings_project == 'test-project'
    assert scans_body['jobReference'] == {'projectId': 'test-project', 'jobId': 'cloudgauge-job-17-scans', 'location': 'us-central1'}
    load = findings_body['configuration']['load']
    assert load['sourceUris'] == ['gs://test-bucket/exports/job-17/findings.ndjson'] and load['sourceFormat'] == 'NEWLINE_DELIMITED_JSON'
    assert load['destinationTable'] == {'projectId': 'test-project', 'datasetId': 'cloudgauge', 'tableId': 'findings'}
    assert (load['writeDisposition'], load['createDisposition'], load['schemaUpdateOptions']) == ('WRITE_APPEND', 'CREATE_IF_NEEDED', ['ALLOW_FIELD_ADDITION'])
    assert load['timePartitioning'] == {'type': 'DAY', 'field': 'generated_at'} and load['clustering'] == {'fields': ['scope_id', 'check_name']}
    assert load['schema'] == {'fields': FINDINGS_SCHEMA} and scans_body['configuration']['load']['schema'] == {'fields': SCANS_SCHEMA}
    # The staging files were written as NDJSON, one object per line, and deleted once the jobs were done.
    staged = [(name, data) for name, data, content_type in gcp.bucket.uploads if name.startswith('exports/')]
    assert [name for name, _ in staged] == ['exports/job-17/scans.ndjson', 'exports/job-17/findings.ndjson']
    assert json.loads(staged[0][1].splitlines()[0])['job_id'] == JOB and len(staged[1][1].splitlines()) == result.rows
    assert sorted(name for name in gcp.bucket.deleted if name.startswith('exports/')) == ['exports/job-17/findings.ndjson', 'exports/job-17/scans.ndjson']
    assert not any(name.startswith('exports/') for name in gcp.bucket.objects)
    # A retry: the jobs exist already (409); they are polled, not re-inserted, and the result is the same.
    exporter.fake.insert_error = http_error(409, 'Already Exists: Job cloudgauge-job-17-scans')
    assert exporter.export(summary, sample_results()).state == EXPORTED
    assert exporter.load_job_id('a b/c', 'scans') == 'cloudgauge-a_b_c-scans'


def test_export_reports_a_failed_job_a_slow_job_and_an_api_that_is_down(exporter, gcp):
    summary = generate_reports(SCOPE, SCOPE_ID, JOB, sample_results(), total_projects=4)[2]
    exporter.fake.states['cloudgauge-job-17-findings'] = [{'state': 'DONE', 'errorResult': {'message': 'Access Denied: Dataset cloudgauge'}}]
    result = exporter.export(summary, sample_results())
    assert result.state == FAILED and result.header_text == 'export to cloudgauge failed: cloudgauge-job-17-findings: Access Denied: Dataset cloudgauge'
    assert result.dot_class == 'error' and any(name.startswith('exports/') for name in gcp.bucket.objects)  # staging kept for a look
    exporter.fake.states = {'cloudgauge-job-17-findings': [{'state': 'RUNNING'}, {'state': 'RUNNING'}, {'state': 'RUNNING'}, {'state': 'RUNNING'},
                                                           {'state': 'RUNNING'}, {'state': 'RUNNING'}, {'state': 'RUNNING'}]}
    result = exporter.export(summary, sample_results())
    assert result.state == RUNNING and result.job_ids == ('cloudgauge-job-17-findings',) and result.dot_class == 'investigation'
    assert 'still running when the report was written (cloudgauge-job-17-findings)' in result.header_text
    assert exporter.clock_state['now'] >= 10  # it waited the configured seconds, polling every two
    exporter.fake.states = {}
    exporter.fake.insert_error = http_error(403, 'bigquery.jobs.create denied')
    result = exporter.export(summary, sample_results())
    assert result.state == FAILED and 'bigquery.jobs.create denied' in result.detail
    gcp.bucket.error = RuntimeError('bucket down')
    assert exporter.export(summary, sample_results()).state == FAILED
    gcp.bucket.error = None
    assert exporter.export({'job_id': 'x'}, {}).state == FAILED  # a summary without what the rows need: still never raises


def test_exported_job_ids_for_the_backfill(exporter):
    exporter.fake.query_rows = ['job-1', 'job-2']
    assert exporter.exported_job_ids() == {'job-1', 'job-2'}
    assert exporter.fake.queries[0]['query'] == 'SELECT DISTINCT job_id FROM `test-project.cloudgauge.scans`'
    exporter.fake.query_error = http_error(404, 'Not found: Table test-project:cloudgauge.scans')
    assert exporter.exported_job_ids() == set()
    exporter.fake.query_error = http_error(403, 'denied')
    with pytest.raises(HttpError):
        exporter.exported_job_ids()


def test_build_exporter_needs_a_dataset_and_a_store():
    store = GcsResultsStore('b')
    assert build_exporter(make_settings(), store) is None
    assert build_exporter(make_settings(BIGQUERY_DATASET='cloudgauge'), None) is None
    assert isinstance(build_exporter(make_settings(BIGQUERY_DATASET='cloudgauge'), store), BigQueryExporter)
    assert Settings.from_env(dict(DEPLOYED_ENV)).bigquery_dataset is None


# --- the hook: a scan with BIGQUERY_DATASET set exports before it renders, and says so in the header ---

@pytest.fixture
def scripted_scan(monkeypatch):
    """The sample findings written the way checks do, instead of the real checks."""
    def run_all_checks(scope, scope_id, job_id, progress_callback=None, *, sink, projects=None):
        sink.write_org_policies(job_id, samples.BEST_PRACTICES, samples.CURRENT_POLICIES)
        for finding in samples.all_findings():
            sink.write_finding(job_id, finding['Check'].replace(' ', '_'), finding)
        return True

    monkeypatch.setattr(scan_job, 'run_all_checks', run_all_checks)
    monkeypatch.setattr(scan_job, 'list_projects', lambda scope, scope_id: [{'projectId': 'web-prod'}, {'projectId': 'data-lake'}])


@pytest.fixture
def exporting_client(gcp, monkeypatch, scripted_scan):
    from app import create_app

    set_env(monkeypatch, {**DEPLOYED_ENV, 'BIGQUERY_DATASET': 'cloudgauge', 'BIGQUERY_EXPORT_WAIT_SECONDS': '0'})
    gcp.discovery.apis['bigquery'] = FakeBigQuery()
    app = create_app()
    return app.test_client(), app, gcp.discovery.apis['bigquery']


def test_the_worker_exports_a_finished_scan(exporting_client, gcp):
    client, app, bigquery = exporting_client
    services = app.extensions[EXTENSION_KEY]
    assert isinstance(services.get_exporter(), BigQueryExporter) and services.get_fanout().exporter is services.get_exporter()
    response = client.post('/run-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID, 'job_id': JOB})
    assert response.status_code == 200
    assert [body['jobReference']['jobId'] for _, body in bigquery.inserted] == ['cloudgauge-job-17-scans', 'cloudgauge-job-17-findings']
    html, _ = gcp.bucket.objects[f'{JOB}/{SCOPE_ID}_report.html']
    assert '<dt>BigQuery export</dt><dd class="coverage"><span class="dot dot-compliant"></span>' in html
    assert 'loaded into cloudgauge.findings and cloudgauge.scans' in html
    # The staging files were cleaned up; the summary was still filed; the report's scope summary names the job.
    assert not any(name.startswith('exports/') for name in gcp.bucket.objects)
    assert any(name.startswith(f'scopes/{SCOPE}/{SCOPE_ID}/') for name in gcp.bucket.objects)


def test_a_failed_export_never_fails_the_scan(exporting_client, gcp):
    client, app, bigquery = exporting_client
    bigquery.insert_error = http_error(403, 'bigquery.jobs.create denied')
    assert client.post('/run-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID, 'job_id': JOB}).status_code == 200
    html, _ = gcp.bucket.objects[f'{JOB}/{SCOPE_ID}_report.html']
    assert '<dt>BigQuery export</dt><dd class="coverage coverage-incomplete"><span class="dot dot-error"></span>export to cloudgauge failed: ' in html
    assert json.loads(gcp.bucket.objects[f'{JOB}/{SCOPE_ID}_status.json'][0])['status'] == 'completed'


def test_without_a_dataset_nothing_is_exported_and_the_header_has_no_export_row(client, gcp, scripted_scan, prod_app):
    assert prod_app.extensions[EXTENSION_KEY].get_exporter() is None
    assert client.post('/run-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID, 'job_id': JOB}).status_code == 200
    html, _ = gcp.bucket.objects[f'{JOB}/{SCOPE_ID}_report.html']
    assert 'BigQuery export' not in html and ('bigquery', 'v2') not in gcp.discovery.calls


def test_synthetic_scans_are_not_exported(exporter, monkeypatch):
    """The banner marks a synthetic scan; it neither enters the history nor the export."""
    calls = []
    monkeypatch.setattr(scan_job, 'generate_reports', lambda *args, **kwargs: (calls.append(kwargs.get('export')), ('<html>', 'csv', {}))[1])
    monkeypatch.setattr(scan_job, 'list_projects', lambda scope, scope_id: [{'projectId': 'p'}])
    monkeypatch.setattr(scan_job, 'run_all_checks', lambda *args, **kwargs: True)
    store = SimpleNamespace(read_status=lambda *a: None, update_status=lambda *a, **k: None, read_all_findings=lambda job: [],
                            read_org_policies=lambda job: (None, None), upload_reports=lambda *a: None, write_scan_summary=lambda s: None,
                            cleanup_intermediate=lambda job: 0, read_previous_summary=lambda *a: None)
    assert scan_job.execute_scan_job({'scope': 'project', 'scope_id': 'p', 'job_id': 'j'}, store=store, banner='SYNTHETIC', exporter=exporter) is True
    assert scan_job.execute_scan_job({'scope': 'project', 'scope_id': 'p', 'job_id': 'j'}, store=store, exporter=exporter) is True
    assert calls[0] is None and callable(calls[1])


# --- the backfill: the CSV report rebuilt into the export's rows ---

def test_the_backfill_rebuilds_the_rows_from_a_csv_report(gcp):
    from tools import backfill_export

    first = generate_reports(SCOPE, SCOPE_ID, 'job-1', sample_results(), total_projects=4)[2]
    results = sample_results()
    results['Security & Identity'][1]['Finding'].append({'Project': 'ml-dev', 'Member': 'serviceAccount:ci@ml-dev.iam.gserviceaccount.com', 'Role': 'roles/editor'})
    live = {}
    html, csv_text, summary = generate_reports(SCOPE, SCOPE_ID, 'job-2', results, total_projects=4, previous=first,
                                               export=lambda s, r, c: live.update(rows=finding_rows(s, r, c)) or None)
    rebuilt = backfill_export.rows_of(summary, csv_text)
    key = lambda r: (r['category'], r['check_name'], r['identity'])  # noqa: E731
    assert sorted(map(key, rebuilt)) == sorted(map(key, live['rows']))  # every row, with the identity the report compares by
    by_key = {key(r): r for r in rebuilt}
    for row in live['rows']:
        assert (by_key[key(row)]['status'], by_key[key(row)]['project'], by_key[key(row)]['new_since_last_scan']) == \
            (row['status'], row['project'], row['new_since_last_scan']), key(row)
    assert json.loads(by_key[('Security & Identity', 'Project IAM Hygiene', 'ml-dev · serviceAccount:ci@ml-dev.iam.gserviceaccount.com · roles/editor')]['row_json']) == \
        {'Project': 'ml-dev', 'Member': 'serviceAccount:ci@ml-dev.iam.gserviceaccount.com', 'Role': 'roles/editor'}
    # A first scan's CSV has no "New since last scan" column: the flag is unknown, not false.
    first_html, first_csv, _ = generate_reports(SCOPE, SCOPE_ID, 'job-1', sample_results(), total_projects=4)
    assert {r['new_since_last_scan'] for r in backfill_export.rows_of(first, first_csv)} == {None}


def test_the_backfill_tool_loads_what_is_not_in_bigquery_yet(gcp, capsys, monkeypatch):
    from tools import backfill_export

    store = GcsResultsStore('test-bucket', client=gcp.storage)
    for job_id in ('job-1', 'job-2'):
        html, csv_text, summary = generate_reports(SCOPE, SCOPE_ID, job_id, sample_results(), total_projects=4)
        store.upload_reports(job_id, SCOPE_ID, html, csv_text)
        store.write_scan_summary(summary)
    bigquery = FakeBigQuery()
    bigquery.query_rows = ['job-1']
    gcp.discovery.apis['bigquery'] = bigquery
    monkeypatch.setattr(backfill_export.BigQueryExporter, 'load_rows',
                        lambda self, job_id, scan, rows: ExportResult(EXPORTED, 'cloudgauge', rows=len(rows)) if rows else ExportResult(FAILED, 'cloudgauge', detail='no rows'))
    code = backfill_export.main(['--project', 'test-project', '--location', 'us-central1', '--bucket', 'test-bucket', '--dataset', 'cloudgauge'])
    out = capsys.readouterr().out
    assert code == 0 and '1 scope(s) with summaries; 1 scan(s) already in cloudgauge.scans' in out
    assert 'job-2' in out and 'exported' in out and 'Done: 1 loaded, 1 skipped, 0 failed.' in out
    assert backfill_export.main(['--project', 'test-project', '--location', 'us-central1', '--bucket', 'test-bucket', '--dataset', 'cloudgauge', '--dry-run']) == 0
    assert 'finding rows' in capsys.readouterr().out
