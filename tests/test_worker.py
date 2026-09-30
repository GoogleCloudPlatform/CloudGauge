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
"""The Cloud Tasks worker (``/run-scan``) and the concurrent check runner.

The worker tests post the same task to the legacy module and to the new app
and compare the response, the status updates the UI polls, the objects written
to and deleted from the bucket, and the reports. The checks are replaced by
the same scripted scan in both, so the comparison covers the job around them.

One difference is intended: the legacy CSV listed the categories in an order
that changed between processes (it came from a ``set``). The new CSV uses
``CATEGORY_ORDER``, so CSVs are compared section by section.
"""
import ast
import functools
import inspect
import re
import textwrap
import threading
from types import SimpleNamespace

import pytest

import samples
from app import scan_job
from app.checks import registry, runner
from app.checks.categories import CATEGORY_ORDER
from app.checks.registry import CheckSpec
from app.extensions import EXTENSION_KEY
from app.utils import ThrottledProgressReporter
from helpers import assert_same_response, csv_sections, report_lines

SCOPE, SCOPE_ID, JOB_ID = 'organization', '123456789', 'job-42'
PAYLOAD = {'scope': SCOPE, 'scope_id': SCOPE_ID, 'job_id': JOB_ID}
REPORT_HTML, REPORT_CSV, STATUS = (f'{JOB_ID}/{SCOPE_ID}_report.html', f'{JOB_ID}/{SCOPE_ID}_report.csv',
                                   f'{JOB_ID}/{SCOPE_ID}_status.json')
PROJECTS = [{'projectId': 'web-prod', 'displayName': 'Web Prod'}, {'projectId': 'data-lake', 'displayName': 'Data Lake'}]
# Progress reported by the scripted scan. With the clock stopped, only the first
# update passes the 2-second throttle; the last one is written by the final flush.
PROGRESS = [(35, '(5/14) Finished: GKE Hygiene'), (65, '(9/14) Finished: Standalone VMs'),
            (95, '(14/14) Finished: Service Quota Limits')]
UUID_SUFFIX = re.compile(r'_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$')


def without_uuids(names):
    """Object names with the random ``_<uuid4>.json`` suffix of finding files replaced."""
    return [UUID_SUFFIX.sub('_<uuid>.json', name) for name in names]


def stop_clocks(monkeypatch, legacy):
    """Both progress throttles see the same frozen time."""
    monkeypatch.setattr(legacy, 'time', SimpleNamespace(time=lambda: 1000.0))
    monkeypatch.setattr(scan_job, 'ThrottledProgressReporter', functools.partial(ThrottledProgressReporter, clock=lambda: 1000.0))


def run_both(legacy_client, client, bucket, **request):
    """Posts the task to legacy, then to the new app, emptying the bucket in between.

    ``request`` holds the test-client arguments (default: ``json=PAYLOAD``).
    Returns one record per app: the response, the objects left in the bucket,
    the status updates, and the names of the objects uploaded and deleted.
    """
    request = request or {'json': PAYLOAD}
    runs = []
    for http in (legacy_client, client):
        response = http.post('/run-scan', **request)
        runs.append(SimpleNamespace(
            response=response,
            objects=dict(bucket.objects),
            statuses=[(doc['progress'], doc['current_task'], doc['status'], content_type)
                      for doc, content_type in bucket.status_updates(JOB_ID, SCOPE_ID)],
            uploads=without_uuids(name for name, _, _ in bucket.uploads),
            deleted=without_uuids(bucket.deleted),
        ))
        bucket.objects.clear()
        bucket.uploads.clear()
        bucket.deleted.clear()
    return runs


@pytest.fixture
def scripted_scan(legacy, monkeypatch):
    """Replaces ``run_all_checks`` in both implementations with the same scripted scan.

    The scan writes the org policies and ``findings`` (default: samples.FINDINGS)
    the way checks do, reports PROGRESS, then raises ``error`` if one is set.
    """
    scan = SimpleNamespace(findings=samples.all_findings(), error=None, calls=[])

    def run(write_finding, write_org_policies, scope, scope_id, job_id, progress_callback):
        scan.calls.append((scope, scope_id, job_id))
        write_org_policies(job_id, samples.BEST_PRACTICES, samples.CURRENT_POLICIES)
        for finding in scan.findings:
            write_finding(job_id, finding['Check'].replace(' ', '_'), finding)
            if scan.error:
                raise scan.error
        for progress, task in PROGRESS:
            progress_callback(progress=progress, current_task=task)
        return True

    def legacy_run_all_checks(scope, scope_id, job_id, progress_callback=None):
        return run(legacy._write_finding_to_gcs, legacy._write_org_policies_to_gcs, scope, scope_id, job_id, progress_callback)

    def new_run_all_checks(scope, scope_id, job_id, progress_callback=None, *, sink):
        return run(sink.write_finding, sink.write_org_policies, scope, scope_id, job_id, progress_callback)

    monkeypatch.setattr(legacy, 'run_all_checks', legacy_run_all_checks)
    monkeypatch.setattr(scan_job, 'run_all_checks', new_run_all_checks)
    stop_clocks(monkeypatch, legacy)
    return scan


# --- /run-scan ---

def test_scan_job_matches_legacy(legacy_client, client, gcp, scripted_scan):
    legacy_run, run = run_both(legacy_client, client, gcp.bucket)
    assert_same_response(legacy_run.response, run.response)
    assert (run.response.status_code, run.response.get_data(as_text=True)) == (200, 'Scan completed and reports uploaded.')
    assert scripted_scan.calls == [(SCOPE, SCOPE_ID, JOB_ID)] * 2

    assert run.statuses == legacy_run.statuses
    assert run.statuses == [
        (5, 'Initializing scan and listing resources...', 'running', 'application/json'),
        (35, '(5/14) Finished: GKE Hygiene', 'running', 'application/json'),
        (95, '(14/14) Finished: Service Quota Limits', 'running', 'application/json'),
        (98, 'Generating final HTML and CSV reports...', 'running', 'application/json'),
        (100, 'Scan complete!', 'completed', 'application/json'),
    ]
    # Same writes in the same order; every intermediate file deleted afterwards.
    assert run.uploads == legacy_run.uploads
    assert run.deleted == legacy_run.deleted
    assert len(run.deleted) == len(scripted_scan.findings) + 2  # plus the two org-policy files
    assert all(name.startswith(f'intermediate/{JOB_ID}/') for name in run.deleted)

    assert sorted(run.objects) == sorted(legacy_run.objects) == sorted([REPORT_HTML, REPORT_CSV, STATUS])
    (html, html_type), (legacy_html, legacy_html_type) = run.objects[REPORT_HTML], legacy_run.objects[REPORT_HTML]
    assert html_type == legacy_html_type == 'text/html'
    assert report_lines(html) == report_lines(legacy_html)
    (csv_text, csv_type), (legacy_csv, legacy_csv_type) = run.objects[REPORT_CSV], legacy_run.objects[REPORT_CSV]
    assert csv_type == legacy_csv_type == 'text/csv'
    assert csv_sections(csv_text) == csv_sections(legacy_csv)
    assert list(csv_sections(csv_text)) == ['Organization Policies', *CATEGORY_ORDER]  # new: always this order
    assert csv_sections(csv_text)['Organization Policies'] == [['Category', 'Policy', 'Expected Value', 'Current Value', 'Status'],
                                                               *samples.ORG_POLICY_CSV_ROWS]


def test_failing_scan_matches_legacy(legacy_client, client, gcp, scripted_scan):
    scripted_scan.error = RuntimeError('429 Quota exceeded for compute.googleapis.com')
    legacy_run, run = run_both(legacy_client, client, gcp.bucket)
    assert_same_response(legacy_run.response, run.response)
    assert (run.response.status_code, run.response.get_data(as_text=True)) == (500, 'Internal Server Error')
    assert run.statuses == legacy_run.statuses
    assert run.statuses[-1] == (100, 'A critical error occurred: 429 Quota exceeded for compute.googleapis.com', 'error', 'application/json')
    assert run.uploads == legacy_run.uploads
    assert run.deleted == legacy_run.deleted and len(run.deleted) == 3  # org policies and the one finding written
    assert list(run.objects) == list(legacy_run.objects) == [STATUS]


def test_report_generation_error_matches_legacy(legacy_client, client, gcp, scripted_scan):
    """Table details mixing dicts and strings: the HTML report falls back to text, the CSV report raises."""
    scripted_scan.findings = [{'Check': 'VM Rightsizing', 'Status': 'Investigation Recommended',
                               'Finding': [{'Project': 'web-prod', 'VM': 'big-vm'}, 'n2-standard-8 is enough']}]
    legacy_run, run = run_both(legacy_client, client, gcp.bucket)
    assert_same_response(legacy_run.response, run.response)
    assert run.response.status_code == 500
    assert run.statuses == legacy_run.statuses
    assert run.statuses[-1][1:3] == ("A critical error occurred: 'str' object has no attribute 'values'", 'error')
    assert run.deleted == legacy_run.deleted


@pytest.mark.parametrize('kwargs', [
    {'json': {'scope': 'project', 'scope_id': 'p1'}},  # no job_id: no status to update, nothing to clean up
    {'json': {'scope': 'project', 'job_id': JOB_ID}},  # no scope_id
    {'json': {'scope_id': SCOPE_ID, 'job_id': JOB_ID}},  # no scope
    {'json': ['project', 'p1', JOB_ID]},
    {'data': 'null', 'content_type': 'application/json'},
    {'data': '{"scope": ', 'content_type': 'application/json'},  # invalid JSON: 400 before the job starts
    {'data': 'scope=project', 'content_type': 'text/plain'},  # force=True parses any content type
])
def test_malformed_tasks_match_legacy(kwargs, legacy_client, client, gcp, scripted_scan):
    legacy_run, run = run_both(legacy_client, client, gcp.bucket, **kwargs)
    assert_same_response(legacy_run.response, run.response, html=True)
    assert run.response.status_code in (400, 500)
    assert run.uploads == legacy_run.uploads == []
    assert run.deleted == legacy_run.deleted == []
    assert scripted_scan.calls == []


def test_scan_without_projects_matches_legacy(legacy_client, client, gcp, legacy, monkeypatch):
    """The real runners find no projects: both still upload empty reports and report success."""
    for module in (legacy, runner):
        monkeypatch.setattr(module, 'list_projects_for_scope', lambda scope, scope_id: [])
    legacy_run, run = run_both(legacy_client, client, gcp.bucket)
    assert_same_response(legacy_run.response, run.response)
    assert run.response.status_code == 200
    assert run.statuses == legacy_run.statuses
    assert [status[0] for status in run.statuses] == [5, 98, 100]
    assert run.objects[REPORT_CSV] == legacy_run.objects[REPORT_CSV]  # no category sections, so same bytes
    assert report_lines(run.objects[REPORT_HTML][0]) == report_lines(legacy_run.objects[REPORT_HTML][0])


def test_scan_job_with_the_real_runner(client, prod_app, gcp, monkeypatch):
    """New app only: the runner executes a check plan, turns a failing check into an Error finding, and reports progress."""
    calls = []

    def open_firewall_rules(scope_id, all_projects, job_id, *, sink):
        calls.append(('Open Firewall Rules', sink))
        sink.write_finding(job_id, 'Open_Firewall_Rules',
                           {'Check': 'Open Firewall Rules', 'Status': 'Compliant', 'Finding': 'No rules allow 0.0.0.0/0.'})

    def gke_hygiene(scope_id, all_projects, job_id, *, sink):
        calls.append(('GKE Hygiene', sink))
        raise RuntimeError('quota exceeded')

    plan = [CheckSpec('Security & Identity', 'Open Firewall Rules', open_firewall_rules, (SCOPE_ID, PROJECTS, JOB_ID)),
            CheckSpec('Reliability & Resilience', 'GKE Hygiene', gke_hygiene, (SCOPE_ID, PROJECTS, JOB_ID))]
    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: PROJECTS)
    monkeypatch.setattr(runner, 'get_active_compute_locations', lambda all_projects: ([], ['global']))
    monkeypatch.setattr(runner, 'build_check_plan', lambda *args: plan)
    monkeypatch.setattr(scan_job, 'ThrottledProgressReporter', functools.partial(ThrottledProgressReporter, clock=lambda: 1000.0))

    response = client.post('/run-scan', json=PAYLOAD)
    assert (response.status_code, response.get_data(as_text=True)) == (200, 'Scan completed and reports uploaded.')
    store = prod_app.extensions[EXTENSION_KEY].results_store
    assert sorted(calls, key=lambda call: call[0]) == [('GKE Hygiene', store), ('Open Firewall Rules', store)]
    assert [doc['progress'] for doc, _ in gcp.bucket.status_updates(JOB_ID, SCOPE_ID)] == [5, 50, 95, 98, 100]
    assert sorted(without_uuids(gcp.bucket.deleted)) == [f'intermediate/{JOB_ID}/ERROR_GKE_Hygiene_<uuid>.json',
                                                         f'intermediate/{JOB_ID}/Open_Firewall_Rules_<uuid>.json']

    html, _ = gcp.bucket.objects[REPORT_HTML]
    assert '<strong>Open Firewall Rules</strong>' in html
    assert "<table class='details-table'><thead><tr><th>Error</th></tr></thead><tbody><tr><td>quota exceeded</td></tr></tbody></table>" in html
    csv_text, _ = gcp.bucket.objects[REPORT_CSV]
    assert csv_sections(csv_text)['Reliability & Resilience'] == [['Check', 'Status', 'Error'], ['GKE Hygiene', 'Error', 'quota exceeded'], []]


# --- The check runner ---

class RecordingSink:
    """Stands in for GcsResultsStore; records the findings written."""

    def __init__(self):
        self.findings = []

    def write_finding(self, job_id, check_name, finding_data):
        self.findings.append((job_id, check_name, finding_data))


@pytest.fixture
def one_project(monkeypatch):
    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: PROJECTS[:1])
    monkeypatch.setattr(runner, 'get_active_compute_locations', lambda all_projects: ([], ['global']))


BETA_V1_CHECKS = ['check_cloud_sql_security', 'check_vpc_configuration', 'check_storage_ubla', 'check_vm_external_ips']


@pytest.mark.parametrize('scope, scope_id', [('organization', '123456789'), ('folder', '42'), ('project', 'web-prod')])
def test_runner_runs_the_beta_v1_check_plan(scope, scope_id, beta, monkeypatch):
    """Both runners call the same check functions with the same arguments and report the same progress.

    The reference is upstream beta v1's ``run_all_checks``: the legacy plan plus four Security checks.
    """
    zones, regions = ['us-central1-a'], ['us-central1', 'global']
    names = [spec.func.__name__ for spec in registry.build_check_plan(scope, scope_id, JOB_ID, PROJECTS, zones, regions)]
    assert len(names) == (24 if scope == 'organization' else 18)
    # Same order as beta v1's plan lists, which append the four checks after "Service Quota Limits".
    beta_plan = ast.parse(textwrap.dedent(inspect.getsource(beta.run_all_checks)))
    beta_names = [entry.elts[2].id for node in ast.walk(beta_plan) if isinstance(node, ast.List)
                  for entry in node.elts if isinstance(entry, ast.Tuple)]
    assert names == beta_names[:len(names)]
    assert names[14:18] == BETA_V1_CHECKS
    calls = {'beta': {}, 'new': {}}
    sink = RecordingSink()

    def recorder(implementation, name):
        def check(*args, **kwargs):
            calls[implementation][name] = (args, kwargs)
        return check

    for name in names:
        monkeypatch.setattr(beta, name, recorder('beta', name))
        monkeypatch.setattr(registry, name, recorder('new', name))
    for module in (beta, runner):
        monkeypatch.setattr(module, 'list_projects_for_scope', lambda scope, scope_id: PROJECTS)
        monkeypatch.setattr(module, 'get_active_compute_locations', lambda all_projects: (zones, regions))

    beta_progress, progress = [], []
    assert beta.run_all_checks(scope, scope_id, JOB_ID, progress_callback=lambda **kw: beta_progress.append(kw)) is True
    assert runner.run_all_checks(scope, scope_id, JOB_ID, progress_callback=lambda **kw: progress.append(kw), sink=sink) is True

    assert set(calls['new']) == set(calls['beta']) == set(names)
    for name in names:
        beta_args, beta_kwargs = calls['beta'][name]
        args, kwargs = calls['new'][name]
        assert (args, beta_kwargs, kwargs) == (beta_args, {}, {'sink': sink}), name
    # Checks finish in any order, so compare progress as sets of values and messages.
    assert [p['progress'] for p in progress] == [p['progress'] for p in beta_progress]
    assert {p['current_task'].split(' Finished: ')[1] for p in progress} == {p['current_task'].split(' Finished: ')[1] for p in beta_progress}
    assert sink.findings == []


@pytest.mark.parametrize('scope', ['organization', 'project'])
def test_check_plan_is_the_legacy_plan_plus_the_beta_v1_checks(scope, legacy):
    """No legacy check was dropped: the plan is the checks legacy ``run_all_checks`` names, plus the four."""
    names = [spec.func.__name__ for spec in registry.build_check_plan(scope, SCOPE_ID, JOB_ID, PROJECTS, [], ['global'])]
    legacy_names = set(legacy.run_all_checks.__code__.co_names)
    assert [name for name in names if name not in legacy_names] == BETA_V1_CHECKS


def test_runner_runs_checks_concurrently(one_project, monkeypatch):
    """Three checks wait for each other at a barrier, which only works if they run at the same time."""
    barrier = threading.Barrier(3, timeout=5)

    def check(*args, sink):
        barrier.wait()

    monkeypatch.setattr(runner, 'build_check_plan', lambda *args: [CheckSpec('Security & Identity', f'Check {i}', check, ()) for i in range(3)])
    sink, progress = RecordingSink(), []
    assert runner.run_all_checks('project', 'web-prod', JOB_ID, progress_callback=lambda **kw: progress.append(kw), sink=sink) is True
    assert sink.findings == []  # no BrokenBarrierError
    assert [p['progress'] for p in progress] == [35, 65, 95]


def test_runner_concurrency_is_bounded_by_max_workers(one_project, monkeypatch):
    barrier = threading.Barrier(2, timeout=0.5)

    def check(*args, sink):
        barrier.wait()

    monkeypatch.setattr(runner, 'build_check_plan', lambda *args: [CheckSpec('Security & Identity', f'Check {i}', check, ()) for i in range(2)])
    sink = RecordingSink()
    runner.run_all_checks('project', 'web-prod', JOB_ID, sink=sink, max_workers=1)
    assert sorted(name for _, name, _ in sink.findings) == ['ERROR_Check_0', 'ERROR_Check_1']


def test_runner_records_a_failed_check_and_continues(one_project, monkeypatch):
    def failing(*args, sink):
        raise RuntimeError('quota exceeded')

    def passing(*args, sink):
        sink.write_finding(JOB_ID, 'Public_GCS_Buckets', {'Check': 'Public GCS Buckets', 'Status': 'Compliant', 'Finding': 'None'})

    monkeypatch.setattr(runner, 'build_check_plan', lambda *args: [
        CheckSpec('Reliability & Resilience', 'GKE Hygiene', failing, ()),
        CheckSpec('Security & Identity', 'Public GCS Buckets', passing, ())])
    sink, progress = RecordingSink(), []
    runner.run_all_checks('project', 'web-prod', JOB_ID, progress_callback=lambda **kw: progress.append(kw), sink=sink)
    assert (JOB_ID, 'ERROR_GKE_Hygiene', {'Check': 'GKE Hygiene', 'Finding': [{'Error': 'quota exceeded'}], 'Status': 'Error'}) in sink.findings
    assert len(sink.findings) == 2
    assert [p['progress'] for p in progress] == [50, 95]
