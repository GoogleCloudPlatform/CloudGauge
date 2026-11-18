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

The worker tests post a task to the app and pin the response, the status
updates the UI polls, the objects written to and deleted from the bucket, and
the reports. The checks are replaced by a scripted scan, so the tests cover the
job around them; ``test_scan_job_with_the_real_runner`` runs the real runner
over a two-check plan. The check plan itself is pinned by name
(``test_the_check_plan_is_pinned``).
"""
import functools
import json
import re
import threading
from types import SimpleNamespace

import pytest

import fakes
import samples
from app import scan_job
from app.checks import registry, runner
from app.checks.categories import CATEGORY_ORDER
from app.checks.registry import CheckSpec
from app.config import VERSION
from app.extensions import EXTENSION_KEY
from app.services import org_policies
from app.synthetic.world import BEST_PRACTICES_CSV
from app.utils import ThrottledProgressReporter
from helpers import csv_sections, report_facts

SCOPE, SCOPE_ID, JOB_ID = 'organization', '123456789', '42424242-4242-4242-8242-424242424242'
JOB_1, JOB_2 = '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'  # v18.6.1: a job ID is a UUID
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
    """Object names with the random ``_<uuid4>.json`` suffix of finding files replaced (the scan summary ends in the
    job's own UUID since v18.6.1 and keeps it)."""
    return [UUID_SUFFIX.sub('_<uuid>.json', name) if name.startswith('intermediate/') else name for name in names]


def run_one(client, bucket, **request):
    """Posts the task to the app and returns a record of the run.

    ``request`` holds the test-client arguments (default: ``json=PAYLOAD``).
    The record: the response, the objects left in the bucket, the status
    updates, and the names of the objects uploaded and deleted.
    """
    request = request or {'json': PAYLOAD}
    response = client.post('/run-scan', **request)
    return SimpleNamespace(
        response=response,
        objects=dict(bucket.objects),
        statuses=[(doc['progress'], doc['current_task'], doc['status'], content_type)
                  for doc, content_type in bucket.status_updates(JOB_ID, SCOPE_ID)],
        uploads=without_uuids(name for name, _, _ in bucket.uploads),
        deleted=sorted(without_uuids(bucket.deleted)),  # deleted in parallel: the order is not part of the contract
    )


@pytest.fixture
def scripted_scan(monkeypatch):
    """Replaces ``run_all_checks`` with a scripted scan, and stops the progress throttle's clock.

    The scan writes the org policies and ``findings`` (default: samples.FINDINGS)
    the way checks do, reports PROGRESS, then raises ``error`` if one is set.
    """
    scan = SimpleNamespace(findings=samples.all_findings(), error=None, calls=[])

    def run_all_checks(scope, scope_id, job_id, progress_callback=None, *, sink, projects=None):
        scan.calls.append((scope, scope_id, job_id))
        sink.write_org_policies(job_id, samples.BEST_PRACTICES, samples.CURRENT_POLICIES)
        for finding in scan.findings:
            sink.write_finding(job_id, finding['Check'].replace(' ', '_'), finding)
            if scan.error:
                raise scan.error
        for progress, task in PROGRESS:
            progress_callback(progress=progress, current_task=task)
        return True

    monkeypatch.setattr(scan_job, 'run_all_checks', run_all_checks)
    monkeypatch.setattr(scan_job, 'ThrottledProgressReporter', functools.partial(ThrottledProgressReporter, clock=lambda: 1000.0))
    return scan


# --- /run-scan ---

def test_scan_job_writes_the_status_the_reports_and_the_summary(client, gcp, scripted_scan):
    """A completed scan: the status documents in order (the throttle lets the first scripted update through, the final
    flush the last), the HTML and CSV reports, then the scan summary (v15) once the reports are up; every intermediate
    finding file deleted afterwards."""
    run = run_one(client, gcp.bucket)
    assert (run.response.status_code, run.response.get_data(as_text=True)) == (200, 'Scan completed and reports uploaded.')
    assert scripted_scan.calls == [(SCOPE, SCOPE_ID, JOB_ID)]

    assert run.statuses == [
        (5, 'Initializing scan and listing resources...', 'running', 'application/json'),
        (35, '(5/14) Finished: GKE Hygiene', 'running', 'application/json'),
        (95, '(14/14) Finished: Service Quota Limits', 'running', 'application/json'),
        (98, 'Generating final HTML and CSV reports...', 'running', 'application/json'),
        (100, 'Scan complete!', 'completed', 'application/json'),
    ]
    summaries = [name for name in run.uploads if name.startswith('scopes/')]
    assert len(summaries) == 1 and re.fullmatch(rf'scopes/{SCOPE}/{SCOPE_ID}/\d{{8}}T\d{{6}}Z_{JOB_ID}\.json', summaries[0])
    assert run.uploads.index(summaries[0]) > run.uploads.index(REPORT_CSV)
    # The writes in order: the status, the org-policy pair and one file per finding (intermediate), the statuses as the
    # scan progresses, the two reports, the summary, the final status.
    intermediate = [name for name in run.uploads if name.startswith('intermediate/')]
    assert len(intermediate) == len(scripted_scan.findings) + 2
    assert run.uploads.index(REPORT_HTML) < run.uploads.index(REPORT_CSV) < run.uploads.index(summaries[0])
    assert run.uploads[0] == STATUS and run.uploads[-1] == STATUS
    assert run.deleted == sorted(intermediate)
    assert all(name.startswith(f'intermediate/{JOB_ID}/') for name in run.deleted)

    assert sorted(run.objects) == sorted([REPORT_HTML, REPORT_CSV, STATUS, *summaries])
    summary = json.loads(run.objects[summaries[0]][0])
    assert (summary['version'], summary['release'], summary['job_id'], summary['scope'], summary['scope_id']) == (3, VERSION, JOB_ID, SCOPE, SCOPE_ID)
    assert {finding['Check'] for finding in scripted_scan.findings} <= set(summary['checks'])
    html, html_type = run.objects[REPORT_HTML]
    assert html_type == 'text/html'
    facts = report_facts(html)
    assert facts['title'] == 'CloudGauge Report: Organization 123456789' and facts['header'] == ('Organization', SCOPE_ID, JOB_ID)
    assert {finding['Check'] for finding in scripted_scan.findings} | {'Organization Policies'} <= {name for name, *_ in facts['items']}
    assert facts['sections'] == ['security-identity', 'cost-optimization', 'reliability-resilience', 'operational-excellence-observability']
    assert 'none — first scan of this organization' in html  # the bucket was empty: nothing to compare with
    csv_text, csv_type = run.objects[REPORT_CSV]
    assert csv_type == 'text/csv'
    assert list(csv_sections(csv_text)) == ['Organization Policies', *CATEGORY_ORDER]  # always this order
    assert csv_sections(csv_text)['Organization Policies'] == [['Category', 'Policy', 'Expected Value', 'Current Value', 'Status'],
                                                               *samples.ORG_POLICY_CSV_ROWS]
    assert {finding['Check'] for finding in scripted_scan.findings} <= {row[0] for rows in csv_sections(csv_text).values() for row in rows if row}


def test_a_failing_scan_reports_the_error_and_cleans_up(client, gcp, scripted_scan):
    scripted_scan.error = RuntimeError('429 Quota exceeded for compute.googleapis.com')
    run = run_one(client, gcp.bucket)
    assert (run.response.status_code, run.response.get_data(as_text=True)) == (500, 'Internal Server Error')
    assert run.statuses[0] == (5, 'Initializing scan and listing resources...', 'running', 'application/json')
    assert run.statuses[-1] == (100, 'A critical error occurred: 429 Quota exceeded for compute.googleapis.com', 'error', 'application/json')
    assert len(run.deleted) == 3  # org policies and the one finding written
    assert list(run.objects) == [STATUS]


def test_a_report_generation_error_is_reported(client, gcp, scripted_scan):
    """Table details mixing dicts and strings: the HTML report falls back to text, the CSV report raises — the status
    says so and the intermediate files are still cleaned up."""
    scripted_scan.findings = [{'Check': 'VM Rightsizing', 'Status': 'Investigation Recommended',
                               'Finding': [{'Project': 'web-prod', 'VM': 'big-vm'}, 'n2-standard-8 is enough']}]
    run = run_one(client, gcp.bucket)
    assert run.response.status_code == 500
    assert run.statuses[-1][1:3] == ("A critical error occurred: 'str' object has no attribute 'values'", 'error')
    assert len(run.deleted) == 3  # org policies and the one finding
    assert REPORT_CSV not in run.objects


def test_a_second_scan_of_the_scope_compares_with_the_first(client, gcp, scripted_scan):
    """New app only (v15): the second scan's report shows what changed since the first, and the CSV flags the new rows."""
    def html_of(job_id):
        return gcp.bucket.objects[f'{job_id}/{SCOPE_ID}_report.html'][0]

    assert client.post('/run-scan', json={**PAYLOAD, 'job_id': JOB_1}).status_code == 200
    assert 'none — first scan of this organization' in html_of(JOB_1)

    # Between the scans: alice's owner role was removed and a CI account was granted editor.
    scripted_scan.findings = [f for f in samples.all_findings() if f['Check'] != 'Project IAM Hygiene'] + [
        {'Check': 'Project IAM Hygiene', 'Status': 'Action Required', 'Finding': [
            {'Project': 'data-lake', 'Member': 'allUsers', 'Role': 'roles/viewer'},
            {'Project': 'ml-dev', 'Member': 'serviceAccount:ci@ml-dev.iam.gserviceaccount.com', 'Role': 'roles/editor'}]}]
    assert client.post('/run-scan', json={**PAYLOAD, 'job_id': JOB_2}).status_code == 200
    html = html_of(JOB_2)
    assert f'<a href="/report/{JOB_1}/{SCOPE_ID}">view</a>' in html  # the header's Previous scan line
    assert '<h2>Changes since last scan</h2>' in html
    assert '+1 new · −1 resolved' in html
    assert '<tr class="row-new"><td class="nowrap code"><code class="chip">ml-dev</code></td>' in html
    assert '<li>web-prod · user:alice@example.com · roles/owner</li>' in html
    csv_text = gcp.bucket.objects[f'{JOB_2}/{SCOPE_ID}_report.csv'][0]
    iam_rows = [row for row in csv_sections(csv_text)['Security & Identity'] if row and row[0] == 'Project IAM Hygiene']
    assert [(row[2], row[-1]) for row in iam_rows] == [('data-lake', ''), ('ml-dev', 'yes')]
    summaries = sorted(name for name in gcp.bucket.objects if name.startswith(f'scopes/{SCOPE}/{SCOPE_ID}/'))
    assert [name.rpartition('_')[2] for name in summaries] == [f'{JOB_1}.json', f'{JOB_2}.json']

    # A retried render of job-2 compares with job-1 again, never with job-2's own summary.
    assert client.post('/run-scan', json={**PAYLOAD, 'job_id': JOB_2}).status_code == 200
    assert f'<a href="/report/{JOB_1}/{SCOPE_ID}">view</a>' in html_of(JOB_2) and '+1 new · −1 resolved' in html_of(JOB_2)


@pytest.mark.parametrize('kwargs', [
    {'json': {'scope': 'project', 'scope_id': 'proj-one'}},  # no job_id: no status to update, nothing to clean up
    {'json': {'scope': 'project', 'job_id': JOB_ID}},  # no scope_id
    {'json': {'scope_id': SCOPE_ID, 'job_id': JOB_ID}},  # no scope
    {'json': ['project', 'proj-one', JOB_ID]},
    {'data': 'null', 'content_type': 'application/json'},
    {'data': '{"scope": ', 'content_type': 'application/json'},  # invalid JSON: 400 before the job starts
    {'data': 'scope=project', 'content_type': 'text/plain'},  # force=True parses any content type
])
def test_malformed_tasks_are_refused_before_any_work(kwargs, client, gcp, scripted_scan):
    """Since v18.6.1 the body is validated first: 400 with the reason (Cloud Tasks retries either status the same
    bounded way; the pre-refactor worker answered 400 or 500 from a KeyError inside the job). Nothing is written."""
    run = run_one(client, gcp.bucket, **kwargs)
    assert run.response.status_code == 400 and set(run.response.get_json()) == {'error'}
    assert run.uploads == []
    assert run.deleted == []
    assert scripted_scan.calls == []


@pytest.mark.parametrize('body, message', [
    ({**PAYLOAD, 'job_id': 'job-42'}, 'job_id must be a UUID.'),
    ({**PAYLOAD, 'scope_id': '../other'}, "scope_id must be the organization's number."),
    ({**PAYLOAD, 'scope': 'team'}, 'scope must be organization, folder or project.'),
    ({**PAYLOAD, 'requested_by': 'x' * 400}, 'requested_by must be a short, printable name.'),
])
def test_tasks_with_identifiers_that_are_not_ones_are_refused(body, message, client, gcp, scripted_scan):
    """v18.6.1 (the pre-refactor worker ran whatever it was given): a job ID that is not a UUID, a scope ID or scope
    that is not one — 400 naming the field, nothing written, no check run."""
    response = client.post('/run-scan', json=body)
    assert (response.status_code, response.get_json()) == (400, {'error': message})
    assert gcp.bucket.uploads == [] and scripted_scan.calls == []


def test_scan_without_projects_runs_the_scope_level_checks(client, gcp, monkeypatch):
    """The real runner finds no projects. Since v15.3 the scan still runs the checks that look at the scope itself (an
    organization's own checks here, a folder's Organization Policies) and reports them, so an empty folder's policies
    are still evaluated (the pre-refactor worker stopped there and uploaded an empty report). The scan succeeds."""
    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: [])
    # The best-practices CSV comes from GitHub: served here, so the test needs no network.
    monkeypatch.setattr(org_policies.gcp, 'http_get', lambda url, **kwargs: SimpleNamespace(status_code=200, text=BEST_PRACTICES_CSV, raise_for_status=lambda: None))
    # One policy set on the organization: what the Organization Policies check evaluates with no project to list.
    gcp.discovery.apis['cloudresourcemanager'] = fakes.FakeResourceManager({f'organizations/{SCOPE_ID}': {'compute.requireOsLogin': True}})
    run = run_one(client, gcp.bucket)
    assert (run.response.status_code, run.response.get_data(as_text=True)) == (200, 'Scan completed and reports uploaded.')
    assert (run.statuses[0][0], run.statuses[-1][:2]) == (5, (100, 'Scan complete!'))
    assert any('Finished: ' in status[1] for status in run.statuses)  # the scope-level checks ran (progress is throttled)
    html = run.objects[REPORT_HTML][0]
    assert '0 of 0 projects · organization-level checks completed' in html
    assert 'Organization Policies' in html and 'policies as recommended' in html


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
    monkeypatch.setattr(runner, 'get_active_compute_locations', lambda all_projects, on_error=None: ([], ['global']))
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
    assert ("<table class='data-table details-table'><thead><tr><th>Error</th></tr></thead><tbody><tr><td class=\"prose\">quota exceeded</td></tr></tbody></table>") in html
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
    monkeypatch.setattr(runner, 'get_active_compute_locations', lambda all_projects, on_error=None: ([], ['global']))


# The check plan by function name, per scope: the stability contract of the check names. A change here is a release
# note (RELEASE_NOTES.md), never an incidental edit: the scan summary records these names, and a later scan tells a
# check new to the release from one that had nothing to check by them (app.changes). Order is the plan's order.
COMMON_CHECKS = [
    'check_organization_policies', 'check_project_iam_policy', 'check_sa_key_rotation', 'check_public_buckets',
    'check_open_firewall_rules', 'run_cost_recommendations', 'check_storage_versioning', 'check_gke_hygiene',
    'check_os_config_coverage', 'check_monitoring_coverage', 'check_standalone_vms', 'run_network_insights',
    'run_miscellaneous_checks_refactored', 'run_service_limit_checks_refactored',
    'check_cloud_sql_security', 'check_vpc_configuration', 'check_storage_ubla', 'check_vm_external_ips',  # beta v1
    'check_service_health_incidents',  # v14
    'check_gke_supported_versions',  # v15
    'check_resilience_assets',  # v15.6
    'check_cost_allocation_labels', 'check_storage_lifecycle', 'check_snapshot_sprawl', 'check_cloud_sql_versions',  # v17
    'check_capacity_commitments', 'check_capacity_signals', 'check_quota_recommendations', 'check_iam_recommendations',
    'check_gke_security', 'check_service_account_impersonation', 'check_vpc_sc_coverage',  # v17.1
    'check_essential_contacts', 'check_data_access_audit_logs',  # v18.1
    'check_gke_operations',  # v18.2
    'check_hybrid_connectivity', 'check_load_balancer_edge', 'check_dns_posture', 'check_flow_logs', 'check_peering_and_nat',  # v18.3
    'check_bigquery_governance', 'check_sql_flags', 'check_alloydb_posture', 'check_kms_keys', 'check_api_keys',  # v18.4
    'check_vm_posture', 'check_identity_hygiene', 'check_unused_service_accounts',  # v18.5
    'check_serverless_posture', 'check_edge_security', 'check_container_scanning',  # v18.6
    'check_folder_roles', 'check_privileged_grants', 'check_secret_posture', 'check_custom_roles',  # v18.7
    'check_spend', 'check_log_cost', 'check_serverless_cost',  # v18.8
    'check_audit_pipeline', 'check_duplicate_routing', 'check_project_routing', 'check_alert_channels', 'check_synthetic_coverage',  # v18.9
    'check_scc_findings', 'check_detector_coverage', 'check_os_vulnerabilities', 'check_exposed_vms',  # v19
    'check_platform_footprint', 'check_gke_activity', 'check_sa_signals',  # v19.1
    'check_support_cases',  # v19.2
    'check_org_policy_exceptions', 'check_bucket_logging',  # v19.3
]
PINNED_CHECK_PLAN = {
    # An organization scan adds the organization's own checks, and reads Advisory Notifications from the organization.
    'organization': COMMON_CHECKS + ['check_org_iam_policy', 'check_scc_status', 'check_audit_logging', 'check_org_advisories'],
    # A folder or project scan reads Advisory Notifications per project.
    'folder': COMMON_CHECKS + ['check_project_advisories'],
    'project': COMMON_CHECKS + ['check_project_advisories'],
}


@pytest.mark.parametrize('scope, scope_id', [('organization', SCOPE_ID), ('folder', '42'), ('project', 'web-prod')])
def test_the_check_plan_is_pinned(scope, scope_id):
    """The plan runs exactly these check functions, in this order (``PINNED_CHECK_PLAN``): 77 for an organization,
    74 for a folder or a project. Adding, renaming or retiring a check changes this list and is a release note."""
    names = [spec.func.__name__ for spec in registry.build_check_plan(scope, scope_id, JOB_ID, PROJECTS, [], ['global'])]
    assert names == PINNED_CHECK_PLAN[scope]
    assert len(names) == len(set(names)) == (77 if scope == 'organization' else 74)


def test_runner_passes_location_discovery_failures_to_the_plan(monkeypatch):
    """A project whose locations could not be discovered reaches the location-based checks, which report it
    as not checked (app.checks.not_checked); without this the cost check could pass it silently."""
    seen, error = [], RuntimeError('403 The caller does not have permission')

    def discovery(all_projects, on_error=None):
        on_error(all_projects[0]['projectId'], error)
        return [], ['global']

    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: PROJECTS)
    monkeypatch.setattr(runner, 'get_active_compute_locations', discovery)
    monkeypatch.setattr(runner, 'build_check_plan', lambda *args: (seen.append(args), [])[1])
    assert runner.run_all_checks('organization', SCOPE_ID, JOB_ID, sink=RecordingSink()) is True
    assert seen == [('organization', SCOPE_ID, JOB_ID, PROJECTS, [], ['global'], {'web-prod': error})]


@pytest.mark.parametrize('scope, scope_id', [('folder', '42'), ('project', 'web-prod'), ('organization', SCOPE_ID)])
def test_runner_runs_the_scope_level_checks_when_there_is_no_project(scope, scope_id, monkeypatch):
    """v15.3: an empty folder (or a listing that failed) still gets the checks that look at the scope itself -
    its organization policies and, since v15.6, the resilience of its assets - where the scan used to stop before
    any check and report every category as not assessed under a header that said the folder-level checks had completed."""
    ran = []
    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: [])
    monkeypatch.setattr(runner, 'get_active_compute_locations', lambda *args, **kwargs: pytest.fail('no project to discover locations in'))
    monkeypatch.setattr(runner, 'run_check_plan', lambda plan, job_id, **kwargs: ran.extend(spec.name for spec in plan))
    assert runner.run_all_checks(scope, scope_id, JOB_ID, sink=RecordingSink()) is True
    assert ran == [spec.name for spec in registry.scope_check_plan(scope, scope_id, JOB_ID)]
    # v17: Snapshot Sprawl and Cloud SQL Extended Support look at the scope too; an organization or folder has IAM
    # recommendations of its own (the scope half of the split check). v17.1: the three SSRF-chain checks are scope-level.
    scope_level = ['Organization Policies', registry.RESILIENCE_CHECK, 'Snapshot Sprawl', 'Cloud SQL Extended Support',
                   'GKE Credential Exposure', 'Service Account Impersonation', 'VPC Service Controls Coverage',
                   'Essential Contacts', 'Data Access Audit Logs', 'GKE Upgrade Readiness',  # v18.1: the contacts and audit pair; v18.2: GKE upgrade readiness
                   'Hybrid Connectivity', 'Load Balancer Edge', 'DNS Posture', 'VPC Flow Logs', 'VPC Peering & Cloud NAT',  # v18.3: the network edge
                   'BigQuery Governance', 'Cloud SQL Flags', 'AlloyDB Posture', 'KMS Keys', 'API Keys',  # v18.4: data governance
                   'VM Service Accounts', 'Service Account Privileges',  # v18.5: VM posture and identity hygiene (two records each)
                   'Serverless Exposure', 'Cloud Armor Policy Content', 'Container Scanning Enabled',  # v18.6: serverless and edge exposure (two records each for the first two)
                   'Folder Primitive Roles', 'Secret Access Scope',  # v18.7: the folders under the scope; the secrets (two records)
                   'Spend Briefing', 'Serverless Cost Hygiene',  # v18.8: the billing export under the scope's ancestry (two records); the workloads and connectors
                   'Audit Log Pipeline', 'Duplicate Log Routing', 'Synthetic and SLO Coverage',  # v18.9: the scope's sinks; the aggregated sinks under it; the edge and the workloads
                   'SCC Active Findings', 'Exposed Privileged VMs',  # v19: SCC's findings under the scope; the instances, firewall rules and policies
                   'Platform Footprint',  # v19.1: the inventory under the scope (the two detection records read per project; the SA one has a scope half below)
                   'Support Cases',  # v19.2: the open support cases under the scope (two records)
                   'Organization Policy Exceptions', 'Bucket Logging']  # v19.3: the policies set under the scope; the buckets, projects and IAM policies under it
    split_halves = ['Privileged Grants', 'Custom Roles With IAM Powers']  # v18.7: the scope halves of the two split checks, in every scope
    sa_half = ['Service Account Activity Signals']  # v19.1: the organization's or folder's own Admin Activity entries — a project scan has no scope half
    if scope == 'organization':
        assert ran[:39] == scope_level + ['Organization IAM Policy'] and registry.MISCELLANEOUS_CHECK in ran and 'IAM Least Privilege' in ran and ran[-3:] == split_halves + sa_half
    elif scope == 'folder':
        assert ran == scope_level + ['Open Firewall Rules', 'IAM Least Privilege'] + split_halves + sa_half  # the split halves: firewall policies (v18.3), the folder's IAM recommendations
    else:
        assert ran == scope_level + ['Open Firewall Rules'] + split_halves


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
