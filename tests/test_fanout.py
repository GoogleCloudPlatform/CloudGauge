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
"""Sharded scans (``app.fanout``): planning, shards, fan-in, aggregation, the sweeper, and the whole flow.

The unit tests drive ``FanOut`` directly with an in-memory bucket and a recorded
``enqueue``. The end-to-end tests run the app in the synthetic profile with the
fake Cloud Tasks client playing the queue (``FakeTasksClient.drain``), and check
that a sharded scan produces the same report a single-task scan of the same
organization does.
"""
import csv
import io
import json
import re
import threading
import time
from datetime import datetime, timedelta
from html import unescape as html_unescape
from types import SimpleNamespace

import pytest

import fakes
from app import create_app, fanout, scan_job
from app.checks import registry, runner
from app.checks.categories import merge_shard_findings
from app.checks.registry import CheckSpec
from app.extensions import EXTENSION_KEY
from app.fanout import SCOPE_SHARD, FanOut, build_coverage, build_manifest, plan_shards
from app.services import gcp as gcp_clients
from app.services.results_store import ShardSink
from app.synthetic import SyntheticGcp, banner_for
from app.synthetic.memory_store import memory_results_store
from app.synthetic.world import ORG_ID
from helpers import DEPLOYED_ENV, make_settings, set_env

JOB, SCOPE_ID = 'job-f1', '123456789'
BODY = {'scope': 'organization', 'scope_id': SCOPE_ID, 'job_id': JOB}


def projects(n, prefix='p'):
    return [{'projectId': f'{prefix}-{i:03d}', 'displayName': f'Project {i}'} for i in range(n)]


def coverage_line(html):
    """The header's Coverage line as text, e.g. "3 of 3 projects · organization-level checks completed"."""
    match = re.search(r'<dt>Coverage</dt><dd class="coverage[^"]*"><span class="dot dot-[\w-]+"></span>(.*?)</dd>', html, re.S)
    return ' '.join(html_unescape(match.group(1)).split()) if match else None


def coverage_dot(html):
    """The dot on the header's Coverage line: ``compliant`` when every project and the scope-level checks ran, else ``investigation``."""
    return re.search(r'<dt>Coverage</dt><dd class="coverage[^"]*"><span class="dot dot-([\w-]+)">', html).group(1)


def coverage_note(html):
    """The note under the overview counts (only an incomplete scan has one), as one line of text; ``None`` without."""
    match = re.search(r'<p role="note" class="coverage-note">.*?<strong>Coverage:</strong>(.*?)</span>', html, re.S)
    return ' '.join(html_unescape(match.group(1)).split()) if match else None


class Queue:
    """Records ``enqueue`` calls and de-duplicates task IDs like Cloud Tasks."""

    def __init__(self):
        self.calls = []  # (path, body, task_id, schedule_delay_seconds)
        self.ids = set()
        self.alive = None  # task_exists() answers: None (unknown), or a dict task_id -> bool

    def enqueue(self, path, body, task_id, schedule_delay_seconds=None):
        self.calls.append((path, body, task_id, schedule_delay_seconds))
        if task_id in self.ids:
            return False
        self.ids.add(task_id)
        return True

    def task_exists(self, task_id):
        return None if self.alive is None else self.alive.get(task_id, False)

    def paths(self):
        return [path for path, _, _, _ in self.calls]


@pytest.fixture
def store():
    return memory_results_store()


@pytest.fixture
def queue():
    return Queue()


def make_fanout(store, queue, **overrides):
    env = {'SCAN_SHARD_SIZE': '2', 'TASK_MAX_ATTEMPTS': '3', **overrides}
    return FanOut(make_settings(**env), store, enqueue=queue.enqueue, task_exists=queue.task_exists)


def bucket_names(store, prefix=''):
    return store.client.bucket(store.bucket_name).object_names(prefix)


# --- Planning ---

def test_plan_shards_splits_projects_consecutively():
    shards = plan_shards(projects(45), 20)
    assert list(shards) == ['shard-001', 'shard-002', 'shard-003']
    assert [len(s) for s in shards.values()] == [20, 20, 5]
    assert [p['projectId'] for p in shards['shard-003']] == ['p-040', 'p-041', 'p-042', 'p-043', 'p-044']
    assert plan_shards([], 20) == {}
    assert list(plan_shards(projects(21), 1))[-1] == 'shard-021'
    assert list(plan_shards(projects(1001), 1))[-1] == 'shard-1001'  # the width grows with the count


def test_manifest_adds_the_scope_shard():
    manifest = build_manifest('organization', SCOPE_ID, JOB, projects(5), 2)
    assert manifest['total_projects'] == 5 and manifest['total_shards'] == 4
    assert list(manifest['shards']) == ['shard-001', 'shard-002', 'shard-003', SCOPE_SHARD]
    assert manifest['shards'][SCOPE_SHARD] == []
    assert manifest['scope'] == 'organization' and manifest['job_id'] == JOB and manifest['created_at']


@pytest.mark.parametrize('scope', ['organization', 'folder', 'project'])
def test_scope_and_project_plans_partition_the_full_plan(scope):
    """Scope-level = the checks that don't take the project list; together with the project checks they are the full plan."""
    plist = projects(3)
    scope_level = registry.scope_level_checks(scope)
    full = registry.build_check_plan(scope, SCOPE_ID, JOB, plist, ['z'], ['r'])
    by_args = {spec.name for spec in full if not any(arg is plist for arg in spec.args)}
    assert by_args == {spec.name for spec in full if spec.name in scope_level}
    # Advisory Notifications is read once at the organization, per project everywhere else.
    assert (registry.ADVISORIES_CHECK in scope_level) == (scope == 'organization')

    scope_plan = registry.scope_check_plan(scope, SCOPE_ID, JOB)
    project_plan = registry.project_check_plan(scope, SCOPE_ID, JOB, plist, ['z'], ['r'])
    assert [spec.name for spec in project_plan] == [spec.name for spec in full if spec.name not in scope_level]
    misc_in_scope = [spec for spec in scope_plan if spec.name == registry.MISCELLANEOUS_CHECK]
    assert [spec.name for spec in scope_plan if spec.name != registry.MISCELLANEOUS_CHECK] == \
           [spec.name for spec in full if spec.name in scope_level]
    # The miscellaneous check is split: org-wide insights once (organization only), project work in every shard.
    assert bool(misc_in_scope) == (scope == 'organization')
    if misc_in_scope:
        assert misc_in_scope[0].func.keywords == {'project_checks': False} and misc_in_scope[0].args[2] == []
    misc_in_project = next(spec for spec in project_plan if spec.name == registry.MISCELLANEOUS_CHECK)
    assert misc_in_project.func.keywords == {'org_insights': False} and misc_in_project.args[2] is plist


def test_project_plan_passes_the_shard_projects_and_locations():
    plist, errors = projects(2), {'p-1': RuntimeError('403')}
    plan = registry.project_check_plan('folder', '42', JOB, plist, ['us-central1-a'], ['us-central1'], errors)
    for spec in plan:
        assert plist in spec.args
    # The location-based checks also get the locations and the projects whose discovery failed.
    by_location = [spec.name for spec in plan if ['us-central1-a'] in spec.args]
    assert by_location == ['Cost-Saving Recommendations', 'Network Insights']
    for spec in plan:
        has_locations = len(spec.args) == 6 and spec.args[2:4] == (['us-central1-a'], ['us-central1']) and spec.args[5] is errors
        assert has_locations == (spec.name in by_location), spec.name


# --- Merging ---

def test_merge_drops_placeholders_when_another_shard_found_something():
    placeholder = {'Check': 'Open Firewall Rules', 'Status': 'Compliant', 'Finding': [{'Status': 'No firewall rules found open to 0.0.0.0/0.'}]}
    real = {'Check': 'Open Firewall Rules', 'Status': 'Action Required', 'Finding': [{'Project': 'p-001', 'Rule Name': 'allow-all', 'VPC': 'default'}]}
    other = {'Check': 'Public GCS Buckets', 'Status': 'Compliant', 'Finding': [{'Status': 'No publicly accessible buckets found.'}]}
    merged = merge_shard_findings([placeholder, other, real, dict(placeholder), dict(other), {**other, 'Finding': 'different text'}])
    assert merged == [other, real, {**other, 'Finding': 'different text'}]


def test_merge_keeps_a_single_shards_findings_unchanged():
    findings = [{'Check': 'GKE Hygiene', 'Status': 'Compliant', 'Finding': [{'Status': 'ok'}]},
                {'Check': 'VM Rightsizing', 'Status': 'Investigation Recommended', 'Finding': [{'Project': 'p', 'VM': 'v'}]},
                {'Check': 'GKE Hygiene', 'Status': 'Error', 'Finding': [{'Error': 'boom'}]}]
    # One scan never writes a placeholder next to findings of the same check; errors do drop the placeholder.
    assert merge_shard_findings(findings[:2]) == findings[:2]
    assert merge_shard_findings(findings) == findings[1:]


def test_merge_joins_a_checks_rows_from_several_shards_in_order():
    a = {'Check': 'Public GCS Buckets', 'Status': 'Action Required', 'Finding': [{'Project': 'p-001', 'Bucket': 'b1', 'Issue': 'public'}]}
    b = {'Check': 'Public GCS Buckets', 'Status': 'Action Required', 'Finding': [{'Project': 'p-021', 'Bucket': 'b2', 'Issue': 'public'}]}
    err = {'Check': 'Public GCS Buckets', 'Status': 'Error', 'Finding': [{'Error': 'Shard shard-003 failed after 3 attempts'}]}
    other = {'Check': 'VM External IPs', 'Status': 'Action Required', 'Finding': [{'Project': 'p-005', 'VM': 'v', 'Issue': 'x'}]}
    merged = merge_shard_findings([a, other, b, err])
    # One item per check and status, its rows in shard order; a different status stays its own item.
    assert merged == [{**a, 'Finding': a['Finding'] + b['Finding']}, other, err]
    assert a['Finding'] == [{'Project': 'p-001', 'Bucket': 'b1', 'Issue': 'public'}]  # the input is left alone


def test_merge_joins_not_checked_records_per_category():
    """The one "Projects not checked" name is written in every category; shards' records join only within one."""
    def not_checked(category, project, check):
        return {'Check': 'Projects not checked', 'Category': category, 'Status': 'Error',
                'Finding': [{'Project': project, 'Skipped check': check, 'Reason': '403 denied'}]}

    sec_1, cost_1 = not_checked('Security & Identity', 'p-001', 'Open Firewall Rules'), not_checked('Cost Optimization', 'p-001', 'Cost-Saving Recommendations')
    sec_2, cost_2 = not_checked('Security & Identity', 'p-021', 'VM External IPs'), not_checked('Cost Optimization', 'p-021', 'Cost-Saving Recommendations')
    merged = merge_shard_findings([sec_1, cost_1, sec_2, cost_2])
    assert merged == [{**sec_1, 'Finding': sec_1['Finding'] + sec_2['Finding']}, {**cost_1, 'Finding': cost_1['Finding'] + cost_2['Finding']}]


# --- The store's shard layout ---

def test_shard_sink_keeps_shards_apart_and_cleanup_is_per_shard(store):
    a, b = ShardSink(store, JOB, 'shard-001'), ShardSink(store, JOB, SCOPE_SHARD)
    a.write_finding(JOB, 'Open_Firewall_Rules', {'Check': 'Open Firewall Rules', 'Status': 'Compliant', 'Finding': 'none'})
    b.write_finding(JOB, 'Essential_Contacts', {'Check': 'Essential Contacts', 'Status': 'Compliant', 'Finding': 'ok'})
    b.write_org_policies(JOB, {'bp': 1}, {'cp': 2})
    store.write_manifest(JOB, {'total_shards': 2})
    store.write_marker(JOB, 'shard-001', {'status': 'success'})

    names = bucket_names(store, f'intermediate/{JOB}/')
    assert any(n.startswith(f'intermediate/{JOB}/shards/shard-001/Open_Firewall_Rules_') for n in names)
    assert f'intermediate/{JOB}/shards/scope/best_practices.json' in names
    assert f'intermediate/{JOB}/manifest.json' in names and f'intermediate/{JOB}/markers/shard-001.json' in names
    # Reading the whole job returns findings only (no manifest, markers, or policy files), one shard reads only its own.
    assert sorted(f['Check'] for f in store.read_all_findings(JOB)) == ['Essential Contacts', 'Open Firewall Rules']
    assert [f['Check'] for f in store.read_all_findings(JOB, shard_id='shard-001')] == ['Open Firewall Rules']
    assert store.read_org_policies(JOB, shard_id=SCOPE_SHARD) == ({'bp': 1}, {'cp': 2})
    assert store.read_org_policies(JOB) == (None, None)  # the inline layout has none
    assert store.read_manifest(JOB) == {'total_shards': 2} and store.read_markers(JOB) == {'shard-001': {'status': 'success'}}

    assert store.cleanup_intermediate(JOB, shard_id='shard-001') == 1
    assert store.read_all_findings(JOB, shard_id='shard-001') == [] and store.read_markers(JOB)  # the marker stays
    assert store.cleanup_intermediate(JOB) == 5 and bucket_names(store, 'intermediate/') == []


def test_marker_can_be_written_only_if_absent(store):
    assert store.write_marker(JOB, 's', {'status': 'success'}) is True
    assert store.write_marker(JOB, 's', {'status': 'failed'}, only_if_absent=True) is False
    assert store.read_markers(JOB) == {'s': {'status': 'success'}}
    assert store.write_marker(JOB, 't', {'status': 'failed'}, only_if_absent=True) is True


def test_unreadable_marker_counts_as_a_failed_shard(store):
    store.client.bucket(store.bucket_name).blob(f'intermediate/{JOB}/markers/x.json').upload_from_string('not json')
    assert store.read_markers(JOB)['x']['status'] == 'failed'


def test_status_document_carries_extra_fields(store):
    store.update_status(JOB, SCOPE_ID, 42, 'Scanning', phase='scanning', total_shards=9)
    status = store.read_status(JOB, SCOPE_ID)
    assert (status['progress'], status['status'], status['phase'], status['total_shards']) == (42, 'running', 'scanning', 9)


# --- The runner's time budget ---

class RecordingSink:
    def __init__(self):
        self.findings = []

    def write_finding(self, job_id, check_name, data):
        self.findings.append((check_name, data))


def test_run_check_plan_records_unfinished_checks_when_the_budget_runs_out():
    release = threading.Event()

    def slow(*args, sink):
        release.wait(5)

    def quick(*args, sink):
        sink.write_finding(JOB, 'Quick', {'Check': 'Quick', 'Status': 'Compliant', 'Finding': 'ok'})

    plan = [CheckSpec('Security & Identity', 'Slow Check', slow, ()), CheckSpec('Security & Identity', 'Quick Check', quick, ())]
    sink, progress = RecordingSink(), []
    started = time.monotonic()
    try:
        summary = runner.run_check_plan(plan, JOB, sink=sink, progress_callback=lambda **kw: progress.append(kw), time_budget_seconds=0.3)
    finally:
        release.set()
    assert time.monotonic() - started < 3
    assert summary == {'checks': 2, 'completed': 1, 'failed': 0, 'unfinished': ['Slow Check']}
    assert [p['progress'] for p in progress] == [50]
    assert sink.findings[0][0] == 'Quick'
    assert sink.findings[1] == ('ERROR_Slow_Check', {'Check': 'Slow Check', 'Status': 'Error', 'Finding': [
        {'Error': "Check did not finish within the time budget of 0 seconds."}]})


def test_run_check_plan_without_a_budget_waits_for_everything():
    summary = runner.run_check_plan([CheckSpec('c', 'A', lambda *a, sink: time.sleep(0.05), ())] * 3, JOB, sink=RecordingSink())
    assert summary == {'checks': 3, 'completed': 3, 'failed': 0, 'unfinished': []}


# --- Dispatch ---

def test_dispatch_writes_the_manifest_and_enqueues_named_tasks(store, queue):
    fan = make_fanout(store, queue, SWEEP_INTERVAL_SECONDS='900')
    assert fan.should_fan_out(projects(2)) is False and fan.should_fan_out(projects(3)) is True
    manifest = fan.dispatch('organization', SCOPE_ID, JOB, projects(5))

    assert store.read_manifest(JOB) == manifest and manifest['total_shards'] == 4
    assert [task_id for _, _, task_id, _ in queue.calls] == [f'{JOB}-scope', f'{JOB}-shard-001', f'{JOB}-shard-002', f'{JOB}-shard-003', f'{JOB}-sweep-1']
    assert queue.paths() == ['/scan-shard'] * 4 + ['/sweep']
    assert queue.calls[1][1] == {**BODY, 'shard_id': 'shard-001'}
    assert queue.calls[-1] == ('/sweep', {**BODY, 'sweep': 1}, f'{JOB}-sweep-1', 900)
    status = store.read_status(JOB, SCOPE_ID)
    assert status['status'] == 'running' and status['phase'] == 'scanning' and status['progress'] == 5
    assert status['current_task'] == 'Scanning 5 projects in parallel...'
    assert (status['total_projects'], status['total_shards'], status['completed_shards']) == (5, 4, 0)


def test_dispatch_is_idempotent_for_a_retried_dispatcher(store, queue):
    fan = make_fanout(store, queue)
    first = fan.dispatch('organization', SCOPE_ID, JOB, projects(3))
    store.update_status(JOB, SCOPE_ID, 47, 'Scanned 2 of 3 projects (1/3 shards done)', phase='scanning', completed_shards=1)
    writes = store.client.stats()['writes']
    # The retry comes without a project list and must reuse the plan, not re-list and re-plan.
    assert fan.dispatch('organization', SCOPE_ID, JOB) == first
    assert store.client.stats()['writes'] == writes  # and it leaves the progress the shards report alone
    assert store.read_status(JOB, SCOPE_ID)['progress'] == 47
    assert len(queue.calls) == 8 and len(queue.ids) == 4  # every task tried twice, created once
    # Unless the first dispatcher crashed before it could write the status: then the retry writes it.
    store.update_status(JOB, SCOPE_ID, 5, 'Initializing scan and listing resources...')
    fan.dispatch('organization', SCOPE_ID, JOB)
    status = store.read_status(JOB, SCOPE_ID)
    assert status['phase'] == 'scanning' and status['current_task'] == 'Scanning 3 projects in parallel...'
    with pytest.raises(RuntimeError):
        make_fanout(memory_results_store(), queue).dispatch('organization', SCOPE_ID, 'other-job')


# --- Shards ---

def fake_plans(monkeypatch, calls, fail_for=()):
    """Replaces the shard plans with one check per shard that records the projects it was given."""
    def check(scope_id, plist, job_id, *, sink):
        calls.append(('project-check', [p['projectId'] for p in plist]))
        sink.write_finding(job_id, 'Open_Firewall_Rules', {
            'Check': 'Open Firewall Rules',
            'Status': 'Action Required' if plist[0]['projectId'] == 'p-000' else 'Compliant',
            'Finding': [{'Project': p['projectId'], 'Rule Name': 'allow-all', 'VPC': 'default'} for p in plist]
            if plist[0]['projectId'] == 'p-000' else [{'Status': 'No firewall rules found open to 0.0.0.0/0.'}]})

    def scope_check(scope, scope_id, job_id, *, sink):
        calls.append(('scope-check', scope))
        sink.write_org_policies(
            job_id,
            {'Security': [{'policyId': 'iam.disableServiceAccountKeyCreation', 'displayName': 'Disable SA key creation',
                           'expectedValue': 'True'}]},
            {'iam.disableServiceAccountKeyCreation': {'booleanPolicy': {'enforced': True}}})
        sink.write_finding(job_id, 'Essential_Contacts', {'Check': 'Essential Contacts', 'Status': 'Compliant',
                                                          'Finding': [{'Status': 'All key contact categories are configured.'}]})

    def project_plan(scope, scope_id, job_id, plist, zones, regions, location_errors=None):
        if plist and plist[0]['projectId'] in fail_for:
            raise RuntimeError('compute.googleapis.com quota exceeded')
        return [CheckSpec('Security & Identity', 'Open Firewall Rules', check, (scope_id, plist, job_id))]

    monkeypatch.setattr(fanout, 'get_active_compute_locations', lambda plist, on_error=None: (calls.append(('locations', len(plist))), ([], ['global']))[1])
    monkeypatch.setattr(fanout, 'project_check_plan', project_plan)
    monkeypatch.setattr(fanout, 'scope_check_plan', lambda scope, scope_id, job_id: [
        CheckSpec('Reliability & Resilience', 'Essential Contacts', scope_check, (scope, scope_id, job_id))])


def test_shard_runs_its_projects_writes_a_marker_and_reports_progress(store, queue, monkeypatch):
    calls = []
    fake_plans(monkeypatch, calls)
    fan = make_fanout(store, queue)
    fan.dispatch('organization', SCOPE_ID, JOB, projects(5))
    queue.calls.clear()

    assert fan.run_shard({**BODY, 'shard_id': 'shard-002'}) is True
    assert calls == [('locations', 2), ('project-check', ['p-002', 'p-003'])]
    marker = store.read_markers(JOB)['shard-002']
    assert marker['status'] == 'success' and marker['projects'] == 2 and marker['checks'] == 1 and marker['failed_checks'] == 0
    assert [f['Check'] for f in store.read_all_findings(JOB, shard_id='shard-002')] == ['Open Firewall Rules']
    assert queue.calls == []  # 3 shards still to go: no aggregation yet
    status = store.read_status(JOB, SCOPE_ID)
    assert status['current_task'] == 'Scanned 2 of 5 projects · organization-level checks: in progress'
    assert status['progress'] == 5 + int(85 * 1 / 4) and status['completed_shards'] == 1

    assert fan.run_shard({**BODY, 'shard_id': SCOPE_SHARD}) is True
    assert calls[-1] == ('scope-check', 'organization')
    assert store.read_org_policies(JOB, shard_id=SCOPE_SHARD)[1] == {'iam.disableServiceAccountKeyCreation': {'booleanPolicy': {'enforced': True}}}
    assert store.read_status(JOB, SCOPE_ID)['current_task'] == 'Scanned 2 of 5 projects · organization-level checks: completed'


def test_shard_passes_its_location_discovery_failures_to_the_plan(store, queue, monkeypatch):
    """Each shard discovers its own locations, so a shard whose projects all fail discovery finds none and
    the cost check would query nothing; the failures reach the location-based checks, which report them."""
    calls = []
    fake_plans(monkeypatch, calls)
    seen, error = [], RuntimeError('403 The caller does not have permission')

    def discovery(plist, on_error=None):
        on_error(plist[0]['projectId'], error)
        return [], ['global']

    real_plan = fanout.project_check_plan
    monkeypatch.setattr(fanout, 'get_active_compute_locations', discovery)
    monkeypatch.setattr(fanout, 'project_check_plan', lambda *args: (seen.append(args), real_plan(*args))[1])
    fan = make_fanout(store, queue)
    fan.dispatch('organization', SCOPE_ID, JOB, projects(5))
    assert fan.run_shard({**BODY, 'shard_id': 'shard-002'}) is True
    assert [(args[3], args[4:]) for args in seen] == [(projects(5)[2:4], ([], ['global'], {'p-002': error}))]


def test_last_shard_triggers_the_aggregation_exactly_once(store, queue, monkeypatch):
    fake_plans(monkeypatch, [])
    fan = make_fanout(store, queue)
    manifest = fan.dispatch('organization', SCOPE_ID, JOB, projects(3))
    queue.calls.clear()
    for shard_id in manifest['shards']:
        assert fan.run_shard({**BODY, 'shard_id': shard_id}) is True
    assert queue.calls == [('/run-aggregation', BODY, f'{JOB}-aggregate', None)]
    status = store.read_status(JOB, SCOPE_ID)
    assert (status['progress'], status['phase'], status['current_task']) == (90, 'aggregating', 'Scanning finished. Merging the results...')

    # A duplicate delivery of a finished shard re-checks the fan-in; the named task is not created again.
    writes = store.client.stats()['writes']
    assert fan.run_shard({**BODY, 'shard_id': 'shard-001'}) is True
    assert len(queue.calls) == 2 and len(queue.ids) == 4 + 1 and store.client.stats()['writes'] == writes


def test_a_retried_shard_starts_clean(store, queue, monkeypatch):
    fake_plans(monkeypatch, [])
    fan = make_fanout(store, queue)
    fan.dispatch('organization', SCOPE_ID, JOB, projects(3))
    ShardSink(store, JOB, 'shard-001').write_finding(JOB, 'Stale', {'Check': 'Open Firewall Rules', 'Status': 'Error', 'Finding': 'from a crashed attempt'})
    assert fan.run_shard({**BODY, 'shard_id': 'shard-001'}, retry_count=1) is True
    findings = store.read_all_findings(JOB, shard_id='shard-001')
    assert len(findings) == 1 and findings[0]['Finding'] != 'from a crashed attempt'
    assert store.read_markers(JOB)['shard-001']['attempt'] == 2


def test_shard_failure_is_retried_then_becomes_error_rows(store, queue, monkeypatch):
    fake_plans(monkeypatch, [], fail_for={'p-000'})
    fan = make_fanout(store, queue)
    fan.dispatch('organization', SCOPE_ID, JOB, projects(3))
    body = {**BODY, 'shard_id': 'shard-001'}

    assert fan.run_shard(body, retry_count=0) is False  # 500: Cloud Tasks retries
    assert fan.run_shard(body, retry_count=1) is False
    assert 'shard-001' not in store.read_markers(JOB) and store.read_all_findings(JOB, shard_id='shard-001') == []

    assert fan.run_shard(body, retry_count=2) is True  # the last attempt: error rows, marker, and the job goes on
    marker = store.read_markers(JOB)['shard-001']
    assert marker['status'] == 'failed' and marker['attempt'] == 3 and 'quota exceeded' in marker['error']
    names = [spec.name for spec in registry.project_check_plan('organization', SCOPE_ID, JOB, projects(2), [], [])]
    errors = store.read_all_findings(JOB, shard_id='shard-001')
    assert sorted(f['Check'] for f in errors) == sorted(names) and len(names) == 19  # v14: + Service Health Incidents; v15: + GKE Supported Versions
    assert all(f['Status'] == 'Error' and f['Finding'][0]['Error'].startswith(
        'Not checked for 2 projects (p-000, p-001): the scan failed after 3 attempts. Last error: ') for f in errors)
    assert 'quota exceeded' in errors[0]['Finding'][0]['Error']
    assert store.read_status(JOB, SCOPE_ID)['current_task'] == ('Scanned 2 of 3 projects · organization-level checks: in progress'
                                                                ' · some checks could not run (listed as errors in the report)')


def test_shard_of_a_finished_or_unknown_job(store, queue, monkeypatch):
    fake_plans(monkeypatch, [])
    fan = make_fanout(store, queue)
    assert fan.run_shard({**BODY, 'shard_id': 'shard-001'}) is False  # no manifest, no report: something is wrong, retry
    store.upload_reports(JOB, SCOPE_ID, '<html>', 'csv')
    assert fan.run_shard({**BODY, 'shard_id': 'shard-001'}) is True  # the job is complete: nothing to do
    fan.dispatch('organization', SCOPE_ID, 'job-2', projects(3))
    assert fan.run_shard({**BODY, 'job_id': 'job-2', 'shard_id': 'shard-999'}) is False  # not in the manifest


def test_shard_time_budget_is_passed_to_the_runner(store, queue, monkeypatch):
    seen = {}

    def run_check_plan(plan, job_id, *, sink, time_budget_seconds=None, clock=None, **kwargs):
        seen['budget'] = time_budget_seconds
        return {'checks': len(plan), 'completed': len(plan) - 1, 'failed': 0, 'unfinished': ['Open Firewall Rules']}

    fake_plans(monkeypatch, [])
    monkeypatch.setattr(fanout, 'run_check_plan', run_check_plan)
    fan = make_fanout(store, queue, SHARD_TIME_BUDGET_SECONDS='600')
    fan.dispatch('organization', SCOPE_ID, JOB, projects(3))
    assert fan.run_shard({**BODY, 'shard_id': 'shard-001'}) is True
    assert seen['budget'] == 600
    marker = store.read_markers(JOB)['shard-001']
    assert marker['status'] == 'timed_out' and marker['unfinished_checks'] == ['Open Firewall Rules']


# --- Aggregation ---

def finished_job(store, queue, monkeypatch, n_projects=3, skip=()):
    """Dispatches and runs every shard except ``skip``; returns the FanOut."""
    fake_plans(monkeypatch, [])
    fan = make_fanout(store, queue)
    manifest = fan.dispatch('organization', SCOPE_ID, JOB, projects(n_projects))
    for shard_id in manifest['shards']:
        if shard_id not in skip:
            fan.run_shard({**BODY, 'shard_id': shard_id})
    return fan


def csv_rows(text):
    return [row for row in csv.reader(io.StringIO(text)) if row]


def test_aggregate_merges_the_shards_into_one_report(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch)
    assert fan.aggregate(BODY) is True

    html = store.read_report(JOB, SCOPE_ID, 'html')
    assert '<strong>Open Firewall Rules</strong>' in html and 'allow-all' in html
    assert 'No firewall rules found open to 0.0.0.0/0.' not in html  # shard-002's placeholder was dropped
    assert html.count('All key contact categories are configured.') == 1
    assert coverage_line(html) == '3 of 3 projects · organization-level checks completed'
    assert 'shard' not in html.lower()  # how the scan ran is not the reader's concern
    assert coverage_dot(html) == 'compliant' and coverage_note(html) is None  # complete: the emerald dot, no note
    assert 'none — first scan of this organization' in html  # nothing to compare with yet
    assert 'Disable SA key creation' in html  # the org policies came from the scope shard
    rows = csv_rows(store.read_report(JOB, SCOPE_ID, 'csv'))
    assert ['Open Firewall Rules', 'Action Required', 'p-000', 'allow-all', 'default'] in rows
    assert ['Open Firewall Rules', 'Action Required', 'p-001', 'allow-all', 'default'] in rows
    assert not any(row[:2] == ['Open Firewall Rules', 'Compliant'] for row in rows)
    assert rows[0] == ['Organization Policies'] and rows[1] == ['Category', 'Policy', 'Expected Value', 'Current Value', 'Status']
    assert ['Security', 'Disable SA key creation', 'True', 'True', 'Compliant'] in rows

    status = store.read_status(JOB, SCOPE_ID)
    assert (status['status'], status['progress'], status['phase'], status['current_task']) == ('completed', 100, 'completed', 'Scan complete!')
    assert bucket_names(store, 'intermediate/') == []  # everything cleaned up
    # Idempotent: a second delivery finds the report and does nothing.
    writes = store.client.stats()['writes']
    assert fan.aggregate(BODY) is True and store.client.stats()['writes'] == writes


def test_aggregate_records_missing_shards_as_error_rows(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch, skip={'shard-002', SCOPE_SHARD})
    assert fan.aggregate(BODY) is True
    html = store.read_report(JOB, SCOPE_ID, 'html')
    assert coverage_line(html) == '2 of 3 projects · 1 not scanned · organization-level checks did not finish'
    assert coverage_note(html) == ('2 of 3 projects scanned (67%), 1 not scanned; organization-level checks did not finish. '
                                   'Checks that could not run are listed as errors in their sections.')
    assert coverage_dot(html) == 'investigation' and 'shard' not in html.lower()
    assert 'Not checked for 1 project (p-002): the scan did not finish; the results are missing from this report.' in html
    assert 'This check did not run: the organization-level checks did not finish; the results are missing from this report.' in html
    rows = csv_rows(store.read_report(JOB, SCOPE_ID, 'csv'))
    error_checks = sorted({row[0] for row in rows if len(row) > 1 and row[1] == 'Error'})
    expected = sorted({spec.name for spec in registry.project_check_plan('organization', SCOPE_ID, JOB, projects(1), [], [])}
                      | {spec.name for spec in registry.scope_check_plan('organization', SCOPE_ID, JOB)})
    assert error_checks == expected
    assert store.read_status(JOB, SCOPE_ID)['status'] == 'completed'


def test_aggregate_failure_sets_the_error_status_only_on_the_last_attempt(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch)
    monkeypatch.setattr(store, 'upload_reports', lambda *args: (_ for _ in ()).throw(RuntimeError('bucket gone')))
    assert fan.aggregate(BODY, retry_count=0) is False
    status = store.read_status(JOB, SCOPE_ID)
    assert status['status'] == 'running' and status['current_task'] == 'Report generation failed (bucket gone); retrying...'
    assert bucket_names(store, 'intermediate/')  # kept for the retry

    assert fan.aggregate(BODY, retry_count=2) is False
    status = store.read_status(JOB, SCOPE_ID)
    assert (status['status'], status['current_task']) == ('error', 'A critical error occurred: bucket gone')
    assert bucket_names(store, 'intermediate/') == []


def test_build_coverage_counts_projects_by_outcome():
    manifest = build_manifest('organization', SCOPE_ID, JOB, projects(7), 2)  # shards of 2, 2, 2, 1 + scope
    markers = {'shard-001': {'status': 'success'}, 'shard-002': {'status': 'timed_out'}, 'shard-003': {'status': 'failed'},
               SCOPE_SHARD: {'status': 'success'}}
    assert build_coverage(manifest, markers) == {
        'total_projects': 7, 'projects_scanned': 2, 'projects_partial': 2, 'projects_not_scanned': 3,
        'total_shards': 5, 'shards_succeeded': 2, 'shards_failed': 2, 'shards_missing': 1, 'scope_checks': 'success'}


def test_coverage_line_is_worded_for_the_reader():
    """Projects and "organization-level checks", never shards; a percentage that never contradicts the counts."""
    from app.reporting.html_report import generate_html_report
    coverage = {'total_projects': 1000, 'projects_scanned': 996, 'projects_partial': 2, 'projects_not_scanned': 2,
                'total_shards': 51, 'shards_succeeded': 49, 'shards_failed': 1, 'shards_missing': 1, 'scope_checks': 'timed_out'}
    html = generate_html_report('organization', '123', JOB, coverage=coverage)
    assert coverage_line(html) == '996 of 1,000 projects · 2 partially scanned · 2 not scanned · organization-level checks timed out'
    assert coverage_note(html) == ('996 of 1,000 projects scanned (>99%), 2 partially scanned (some checks did not finish in time), '
                                   '2 not scanned; organization-level checks timed out. '
                                   'Checks that could not run are listed as errors in their sections.')
    assert coverage_dot(html) == 'investigation' and 'shard' not in html.lower()
    folder = generate_html_report('folder', '456', JOB, coverage={**coverage, 'projects_scanned': 1000, 'projects_partial': 0,
                                                                 'projects_not_scanned': 0, 'scope_checks': 'success'})
    assert coverage_line(folder) == '1,000 of 1,000 projects · folder-level checks completed' and coverage_note(folder) is None


def test_single_task_scans_state_their_coverage_too():
    """A scan that ran in one task covered every project it listed: the header says so, in the same words as a sharded scan."""
    from app.reporting.html_report import generate_html_report
    org = generate_html_report('organization', '123', JOB, total_projects=3)
    assert coverage_line(org) == '3 of 3 projects · organization-level checks completed' and coverage_dot(org) == 'compliant'
    assert coverage_note(org) is None
    project = generate_html_report('project', 'p-000', JOB, total_projects=1)
    assert coverage_line(project) == '1 project'  # no scope-level checks to mention
    unknown = generate_html_report('organization', '123', JOB)  # the scan could not count its projects
    assert coverage_line(unknown) is None and '<dt>Coverage</dt>' not in unknown


def test_a_sharded_folder_scan_states_what_the_listing_reconciled(store, queue, monkeypatch):
    """v15.4: the manifest keeps the project dicts as the listing produced them, membership marks included, so the
    aggregated report has the same Folder membership row a single-task scan would."""
    fake_plans(monkeypatch, [])
    fan = make_fanout(store, queue)
    listed = projects(3) + [{'projectId': 'moved-in', 'displayName': 'Moved In', 'membership': 'resource-manager-only'}]
    body = {'scope': 'folder', 'scope_id': '42', 'job_id': JOB}
    manifest = fan.dispatch('folder', '42', JOB, listed)
    assert store.read_manifest(JOB)['shards']['shard-002'][1]['membership'] == 'resource-manager-only'
    for shard_id in manifest['shards']:
        assert fan.run_shard({**body, 'shard_id': shard_id}) is True
    assert fan.aggregate(body) is True
    html = store.read_report(JOB, '42', 'html')
    assert coverage_line(html) == '4 of 4 projects · folder-level checks completed'
    assert '<dt>Folder membership</dt>' in html and '1 project added from Resource Manager' in html
    assert 'Resource Manager places moved-in in this folder' in html


def test_error_rows_name_projects_not_shards():
    manifest = build_manifest('organization', SCOPE_ID, JOB, projects(30), 30)
    assert fanout.describe_projects(projects(1)) == '1 project (p-000)'
    assert fanout.describe_projects(projects(3)) == '3 projects (p-000, p-001, p-002)'
    assert fanout.describe_projects(projects(30)).endswith('p-024, and 5 more)')  # 25 IDs listed
    assert fanout.not_checked_message(manifest, 'shard-001', 'crashed on every attempt.').startswith(
        'Not checked for 30 projects (p-000, ')
    assert fanout.not_checked_message(manifest, SCOPE_SHARD, 'failed after 3 attempts. Last error: boom') == \
        'This check did not run: the organization-level checks failed after 3 attempts. Last error: boom'


# --- The sweeper ---

def test_sweep_is_a_no_op_once_the_report_exists(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch)
    fan.aggregate(BODY)
    queue.calls.clear()
    assert fan.sweep({**BODY, 'sweep': 1}) is True and queue.calls == []


def test_sweep_retriggers_a_lost_aggregation(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch)
    queue.ids.discard(f'{JOB}-aggregate')  # as if the trigger had been lost
    queue.calls.clear()
    assert fan.sweep({**BODY, 'sweep': 1}) is True
    assert queue.calls == [('/run-aggregation', BODY, f'{JOB}-aggregate', None)]


def test_sweep_waits_while_shards_are_still_queued(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch, skip={'shard-002'})
    queue.alive = {f'{JOB}-shard-002': True}
    queue.calls.clear()
    assert fan.sweep({**BODY, 'sweep': 1}) is True
    assert queue.calls == [('/sweep', {**BODY, 'sweep': 2}, f'{JOB}-sweep-2', fan.settings.sweep_interval_seconds)]
    assert 'shard-002' not in store.read_markers(JOB)
    # Unknown liveness counts as alive too.
    queue.alive = None
    queue.calls.clear()
    assert fan.sweep({**BODY, 'sweep': 2}) is True
    assert queue.calls[0][2] == f'{JOB}-sweep-3'


def test_sweep_finishes_the_job_when_a_shard_has_died(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch, skip={'shard-002'})
    queue.alive = {f'{JOB}-shard-002': False}
    queue.calls.clear()
    assert fan.sweep({**BODY, 'sweep': 1}) is True
    marker = store.read_markers(JOB)['shard-002']
    assert marker['status'] == 'failed' and marker['swept'] == 1 and 'crashed on every attempt' in marker['error']
    errors = store.read_all_findings(JOB, shard_id='shard-002')
    assert len(errors) == 19 and all(f['Status'] == 'Error' for f in errors)  # one per project-level check (v15: 19)
    assert queue.calls == [('/run-aggregation', BODY, f'{JOB}-aggregate', None)]
    assert store.read_status(JOB, SCOPE_ID)['current_task'] == 'The scan of 1 project failed; merging the results of the others...'
    assert all(f['Finding'][0]['Error'] == 'Not checked for 1 project (p-002): the scan crashed on every attempt.' for f in errors)


def test_sweep_does_not_overwrite_a_marker_written_in_the_meantime(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch, skip={'shard-002'})
    queue.alive = {f'{JOB}-shard-002': False}

    def task_exists(task_id):  # the shard finishes between the sweeper's listing and its liveness check
        fan.run_shard({**BODY, 'shard_id': 'shard-002'})
        return False

    fan.task_exists = task_exists
    assert fan.sweep({**BODY, 'sweep': 1}) is True
    assert store.read_markers(JOB)['shard-002']['status'] == 'success'
    assert all(f['Status'] != 'Error' for f in store.read_all_findings(JOB, shard_id='shard-002'))


def test_job_time_limit_scales_with_the_shard_count():
    """Defaults: 25 concurrent shards, 30-minute deadline, factor 2, at least 6 hours."""
    settings = make_settings()
    assert fanout.job_time_limit_seconds(settings, 4) == 6 * 3600
    assert fanout.job_time_limit_seconds(settings, 150) == 6 * 3600  # 6 waves × 30 min × 2 = the minimum
    assert fanout.job_time_limit_seconds(settings, 151) == 7 * 3600
    assert fanout.job_time_limit_seconds(settings, 501) == 21 * 3600  # 10,000 projects in shards of 20
    assert fanout.job_time_limit_seconds(make_settings(SCAN_MAX_CONCURRENT_SHARDS='100'), 501) == 6 * 3600
    assert fanout.job_time_limit_seconds(make_settings(TASK_DISPATCH_DEADLINE_SECONDS='900'), 501) == 21 * 1800
    # An explicit limit replaces the computed one, whatever the size.
    assert fanout.job_time_limit_seconds(make_settings(SCAN_TIME_LIMIT_SECONDS='3600'), 501) == 3600


def test_dispatch_records_the_time_limit_and_times_the_first_sweep(store, queue):
    manifest = make_fanout(store, queue).dispatch('organization', SCOPE_ID, JOB, projects(5))
    assert manifest['time_limit_seconds'] == 6 * 3600 and store.read_manifest(JOB)['time_limit_seconds'] == 6 * 3600
    assert queue.calls[-1][3] == 1800  # the first sweep after the usual interval
    # A limit shorter than the interval is checked when it is up.
    queue = Queue()
    manifest = make_fanout(store, queue, SCAN_TIME_LIMIT_SECONDS='600').dispatch('organization', SCOPE_ID, 'job-short', projects(5))
    assert manifest['time_limit_seconds'] == 600 and queue.calls[-1] == ('/sweep', {**BODY, 'job_id': 'job-short', 'sweep': 1}, 'job-short-sweep-1', 600)


def hours_later(fan, hours):
    """Moves the FanOut's wall clock to ``hours`` after the job was dispatched."""
    created = datetime.fromisoformat(fan.store.read_manifest(JOB)['created_at'])
    fan.now = lambda: created + timedelta(hours=hours)


def test_sweep_waits_for_a_large_job_past_six_hours(store, queue, monkeypatch):
    """14 projects in shards of 2, one shard at a time: 8 shards, 8 waves of 30 minutes, limit 2 × 4 h = 8 h."""
    fake_plans(monkeypatch, [])
    fan = make_fanout(store, queue, SCAN_MAX_CONCURRENT_SHARDS='1')
    manifest = fan.dispatch('organization', SCOPE_ID, JOB, projects(14))
    assert manifest['total_shards'] == 8 and manifest['time_limit_seconds'] == 8 * 3600
    fan.run_shard({**BODY, 'shard_id': 'shard-001'})
    queue.alive = None  # liveness unknown: the shards count as queued
    queue.calls.clear()

    hours_later(fan, 7)  # the old fixed wall would have given up here
    assert fan.sweep({**BODY, 'sweep': 14}) is True
    assert queue.calls == [('/sweep', {**BODY, 'sweep': 15}, f'{JOB}-sweep-15', 1800)]
    hours_later(fan, 7.9)  # 6 minutes to the limit: the next sweep lands on it, not 30 minutes later
    queue.calls.clear()
    assert fan.sweep({**BODY, 'sweep': 15}) is True
    assert queue.calls[0][3] == 360

    hours_later(fan, 8.01)
    queue.calls.clear()
    assert fan.sweep({**BODY, 'sweep': 16}) is True
    assert queue.calls == [('/run-aggregation', BODY, f'{JOB}-aggregate', None)]
    assert store.read_status(JOB, SCOPE_ID)['current_task'] == ('The scan of 12 projects and the organization-level checks did not finish; '
                                                                'generating the report with the results so far...')


def test_sweep_gives_up_at_the_time_limit(store, queue, monkeypatch):
    fan = finished_job(store, queue, monkeypatch, skip={'shard-002'})
    queue.alive = {f'{JOB}-shard-002': True}
    queue.calls.clear()
    hours_later(fan, 5.99)
    assert fan.sweep({**BODY, 'sweep': 12}) is True
    assert queue.calls[0][2] == f'{JOB}-sweep-13'  # still within the 6-hour minimum: wait
    queue.calls.clear()
    hours_later(fan, 6)
    assert fan.sweep({**BODY, 'sweep': 13}) is True
    assert queue.calls == [('/run-aggregation', BODY, f'{JOB}-aggregate', None)]
    assert store.read_status(JOB, SCOPE_ID)['current_task'] == 'The scan of 1 project did not finish; generating the report with the results so far...'
    assert fan.aggregate(BODY) is True
    assert 'Not checked for 1 project (p-002): the scan did not finish' in store.read_report(JOB, SCOPE_ID, 'html')


def test_sweep_computes_the_limit_for_a_manifest_without_one(store, queue, monkeypatch):
    """A job dispatched by a revision that did not record the limit (an upgrade in flight) still terminates."""
    fan = finished_job(store, queue, monkeypatch, skip={'shard-002'})
    manifest = store.read_manifest(JOB)
    del manifest['time_limit_seconds']
    store.write_manifest(JOB, manifest)
    queue.alive = {f'{JOB}-shard-002': True}
    queue.calls.clear()
    hours_later(fan, 1)
    assert fan.sweep({**BODY, 'sweep': 2}) is True and queue.calls[0][2] == f'{JOB}-sweep-3'
    queue.calls.clear()
    hours_later(fan, 6)
    assert fan.sweep({**BODY, 'sweep': 3}) is True and queue.calls == [('/run-aggregation', BODY, f'{JOB}-aggregate', None)]


def test_sweep_of_an_errored_job_is_a_no_op(store, queue):
    assert make_fanout(store, queue).sweep({**BODY, 'sweep': 1}) is True and queue.calls == []


# --- /run-scan decides ---

def test_small_scopes_run_inline_and_create_no_tasks(client, prod_app, gcp, monkeypatch):
    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: projects(20))
    monkeypatch.setattr(runner, 'get_active_compute_locations', lambda plist, on_error=None: ([], ['global']))
    monkeypatch.setattr(runner, 'build_check_plan', lambda *args: [])
    assert client.post('/run-scan', json=BODY).status_code == 200
    assert gcp.tasks.tasks == [] and json.loads(gcp.bucket.blob(f'{JOB}/{SCOPE_ID}_status.json').download_as_text())['status'] == 'completed'
    assert f'{JOB}/{SCOPE_ID}_report.html' in gcp.bucket.objects


def test_large_scopes_are_dispatched_and_the_dispatcher_returns(client, prod_app, gcp, monkeypatch):
    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: projects(21))
    monkeypatch.setattr(runner, 'build_check_plan', lambda *args: pytest.fail('the dispatcher must not run checks'))
    assert client.post('/run-scan', json=BODY).status_code == 200
    assert gcp.tasks.task_ids() == [f'{JOB}-scope'] + [f'{JOB}-shard-00{i}' for i in (1, 2)] + [f'{JOB}-sweep-1']
    task = dict(gcp.tasks.tasks[0][1])
    assert task['dispatch_deadline'].total_seconds() == 1800 and task['http_request']['url'] == f'{fakes.WORKER_URL}/scan-shard'
    assert gcp.tasks.tasks[-1][1]['schedule_time']
    status = json.loads(gcp.bucket.blob(f'{JOB}/{SCOPE_ID}_status.json').download_as_text())
    assert status['phase'] == 'scanning' and status['status'] == 'running'
    assert f'intermediate/{JOB}/manifest.json' in gcp.bucket.objects  # not cleaned up: the shards write there now
    # A retried dispatcher re-enqueues nothing new and doesn't reset the status.
    gcp.bucket.put(f'{JOB}/{SCOPE_ID}_status.json', json.dumps({**status, 'progress': 47}), 'application/json')
    assert client.post('/run-scan', json=BODY).status_code == 200
    assert len(gcp.tasks.task_ids()) == 4
    assert json.loads(gcp.bucket.blob(f'{JOB}/{SCOPE_ID}_status.json').download_as_text())['progress'] == 47


def test_completed_jobs_are_not_scanned_again(client, prod_app, gcp, monkeypatch):
    gcp.bucket.put(f'{JOB}/{SCOPE_ID}_status.json', json.dumps({'status': 'completed', 'progress': 100}), 'application/json')
    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: pytest.fail('must not list'))
    assert client.post('/run-scan', json=BODY).status_code == 200
    assert gcp.tasks.tasks == [] and gcp.bucket.uploads == []


def test_execute_scan_job_without_a_fanout_never_shards(gcp, monkeypatch):
    monkeypatch.setattr(runner, 'list_projects_for_scope', lambda scope, scope_id: projects(500))
    monkeypatch.setattr(runner, 'get_active_compute_locations', lambda plist, on_error=None: ([], []))
    monkeypatch.setattr(runner, 'build_check_plan', lambda *args: [])
    store = memory_results_store()
    assert scan_job.execute_scan_job(BODY, store=store) is True
    assert store.read_status(JOB, SCOPE_ID)['status'] == 'completed' and store.read_manifest(JOB) is None


# --- End to end: the app, the fake queue, and a synthetic organization ---

def synthetic_env(n_projects, shard_size):
    return {**DEPLOYED_ENV, 'CLOUDGAUGE_ENV': 'synthetic', 'SYNTHETIC_PROJECTS': str(n_projects), 'SYNTHETIC_LATENCY_MS': '0',
            'SYNTHETIC_DENIED_FRACTION': '0', 'SCAN_SHARD_SIZE': str(shard_size)}


def report_rows(csv_text):
    """The CSV's data rows (no headers or section titles), as a sorted multiset."""
    rows = []
    for row in csv_rows(csv_text):
        if len(row) > 1 and row[0] not in ('Check', 'Category'):
            rows.append(tuple(row))
    return sorted(rows)


def check_statuses(html):
    """``{check name: status badge}`` for every check item (the title and the pill of its accordion's summary row)."""
    import re
    return dict(re.findall(r'<span class="check-title"><strong>([^<]+)</strong>.*?<span class="status-badge[^"]*">([^<]+)</span>', html, re.S))


def test_sharded_scan_end_to_end_matches_a_single_task_scan(gcp, monkeypatch):
    """50 synthetic projects, shards of 20: dispatcher -> 3 project shards + scope shard -> aggregation.

    The fake Cloud Tasks client delivers the tasks; the report must be the one a
    single-task scan of the same organization produces.
    """
    set_env(monkeypatch, synthetic_env(50, 20))
    app = create_app()
    client = app.test_client()
    job = {'scope': 'organization', 'scope_id': ORG_ID, 'job_id': 'job-e2e'}

    assert client.post('/run-scan', json=job).status_code == 200
    assert gcp.tasks.task_ids() == ['job-e2e-scope', 'job-e2e-shard-001', 'job-e2e-shard-002', 'job-e2e-shard-003', 'job-e2e-sweep-1']
    status_blob = gcp.bucket.blob(f'job-e2e/{ORG_ID}_status.json')
    assert json.loads(status_blob.download_as_text())['current_task'] == 'Scanning 50 projects in parallel...'

    deliveries = gcp.tasks.drain(client, skip_scheduled=True)  # the shards, then the aggregation
    assert deliveries == 5 and all(code == 200 for _, _, _, code in gcp.tasks.deliveries)
    assert [path for path, _, _, _ in gcp.tasks.deliveries] == ['/scan-shard'] * 4 + ['/run-aggregation']
    status = json.loads(status_blob.download_as_text())
    assert (status['status'], status['progress'], status['completed_shards'], status['failed_shards']) == ('completed', 100, 4, 0)
    html = gcp.bucket.blob(f'job-e2e/{ORG_ID}_report.html').download_as_text()
    assert coverage_line(html) == '50 of 50 projects · organization-level checks completed' and 'SYNTHETIC LOAD TEST' in html
    assert 'pill-error">Error<' not in html
    assert [name for name in gcp.bucket.objects if name.startswith('intermediate/')] == []
    assert [name for name in gcp.bucket.objects if name.startswith('scopes/')] == []  # synthetic scans enter no history
    # The sweep fires later and finds the job complete.
    assert gcp.tasks.drain(client) == 1 and gcp.tasks.deliveries[-1][0] == '/sweep'

    # The same organization in one task (shards of 1,000): same checks, same statuses, same rows.
    sharded_csv = gcp.bucket.blob(f'job-e2e/{ORG_ID}_report.csv').download_as_text()
    provider = SyntheticGcp(50, latency_ms=0, denied_fraction=0)
    gcp_clients.install_provider(provider)
    store = memory_results_store()
    assert scan_job.execute_scan_job({**job, 'job_id': 'job-inline'}, store=store, banner=banner_for(provider)) is True
    inline_html, inline_csv = store.read_report('job-inline', ORG_ID, 'html'), store.read_report('job-inline', ORG_ID, 'csv')
    assert check_statuses(html) == check_statuses(inline_html) and len(check_statuses(html)) > 25
    assert coverage_line(inline_html) == coverage_line(html)  # both paths state what they covered, in the same words
    assert html.count('status-badge') == inline_html.count('status-badge')  # one item per check, not one per shard
    assert report_rows(sharded_csv) == report_rows(inline_csv) and len(report_rows(inline_csv)) > 100
    assert len(sharded_csv.splitlines()) == len(inline_csv.splitlines())  # same records: same headers and spacers too


def test_sharded_scan_survives_a_crashing_shard(gcp, monkeypatch):
    """One shard crashes on every attempt: the report still comes out, with that shard's checks as error rows."""
    set_env(monkeypatch, synthetic_env(50, 20))
    app = create_app()
    client = app.test_client()
    job = {'scope': 'organization', 'scope_id': ORG_ID, 'job_id': 'job-crash'}
    real_plan = fanout.project_check_plan

    def crashing_plan(scope, scope_id, job_id, plist, zones, regions, location_errors=None):
        if plist[0]['projectId'] == 'syn-42-00020':  # shard-002
            raise MemoryError('container out of memory')
        return real_plan(scope, scope_id, job_id, plist, zones, regions, location_errors)

    monkeypatch.setattr(fanout, 'project_check_plan', crashing_plan)
    assert client.post('/run-scan', json=job).status_code == 200
    gcp.tasks.drain(client, skip_scheduled=True)
    attempts = [(path, body['shard_id'], retry, code) for path, body, retry, code in gcp.tasks.deliveries if path == '/scan-shard']
    assert [(retry, code) for _, shard, retry, code in attempts if shard == 'shard-002'] == [(0, 500), (1, 500), (2, 200)]
    status = json.loads(gcp.bucket.blob(f'job-crash/{ORG_ID}_status.json').download_as_text())
    assert (status['status'], status['failed_shards']) == ('completed', 1)
    html = gcp.bucket.blob(f'job-crash/{ORG_ID}_report.html').download_as_text()
    assert coverage_line(html) == '30 of 50 projects · 20 not scanned · organization-level checks completed'
    assert coverage_note(html) == ('30 of 50 projects scanned (60%), 20 not scanned; organization-level checks completed. '
                                   'Checks that could not run are listed as errors in their sections.')
    assert ('Not checked for 20 projects (syn-42-00020, syn-42-00021, ' in html and 'syn-42-00039): the scan failed after 3 attempts. '
            'Last error: container out of memory' in html)
    assert 'and 0 more' not in html and 'shard' not in html.lower()
    assert check_statuses(html)['Open Firewall Rules'] in ('Action Required', 'Error')


def test_status_page_and_api_follow_a_sharded_job(gcp, monkeypatch):
    set_env(monkeypatch, synthetic_env(25, 20))
    client = create_app().test_client()
    job = {'scope': 'organization', 'scope_id': ORG_ID, 'job_id': 'job-ui'}
    assert client.post('/run-scan', json=job).status_code == 200
    status = client.get(f'/api/status/job-ui/{ORG_ID}').get_json()
    assert status['status'] == 'running' and status['progress'] == 5 and status['current_task'] == 'Scanning 25 projects in parallel...'
    gcp.tasks.drain(client, skip_scheduled=True)
    status = client.get(f'/api/status/job-ui/{ORG_ID}').get_json()
    assert status['status'] == 'completed' and status['progress'] == 100
    assert client.get(f'/report/job-ui/{ORG_ID}').status_code == 200
    assert client.get(f'/status/job-ui/organization/{ORG_ID}').status_code == 200


def test_services_build_the_fanout_from_the_app_configuration(prod_app):
    services = prod_app.extensions[EXTENSION_KEY]
    fan = services.get_fanout()
    assert fan is services.get_fanout() and fan.settings is services.settings and fan.store is services.results_store
    assert fan.settings.scan_shard_size == 20 and fan.settings.scan_max_concurrent_shards == 25
    assert fan.settings.shard_time_budget_seconds == 1200 and fan.settings.task_dispatch_deadline_seconds == 1800


@pytest.mark.parametrize('name, value, message', [
    ('SCAN_SHARD_SIZE', '0', 'between 1'),
    ('TASK_DISPATCH_DEADLINE_SECONDS', '3600', 'between 15 and 1800'),
    ('SHARD_TIME_BUDGET_SECONDS', '10', 'between 60'),
    ('SCAN_MAX_CONCURRENT_SHARDS', 'many', 'must be a number'),
    ('SCAN_TIME_LIMIT_SECONDS', '-1', 'between 0'),
])
def test_fanout_settings_are_validated(name, value, message):
    with pytest.raises(ValueError, match=message):
        make_settings(**{name: value})


def test_fanout_settings_are_read():
    settings = make_settings(SCAN_SHARD_SIZE='50', SCAN_MAX_CONCURRENT_SHARDS='10', SHARD_TIME_BUDGET_SECONDS='300',
                             TASK_DISPATCH_DEADLINE_SECONDS='900', SWEEP_INTERVAL_SECONDS='120', TASK_MAX_ATTEMPTS='5',
                             SCAN_TIME_LIMIT_SECONDS='7200')
    assert (settings.scan_shard_size, settings.scan_max_concurrent_shards, settings.shard_time_budget_seconds,
            settings.task_dispatch_deadline_seconds, settings.sweep_interval_seconds, settings.task_max_attempts,
            settings.scan_time_limit_seconds) == (50, 10, 300, 900, 120, 5, 7200)
    assert SimpleNamespace(**make_settings().__dict__).scan_shard_size == 20
    assert make_settings().scan_time_limit_seconds == 0  # computed per job
