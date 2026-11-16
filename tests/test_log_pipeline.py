"""
v18.9 — Logging pipeline and alerting hygiene, the pipeline: the rules of ``app.checks.log_pipeline`` on fixture sinks, buckets, views and
search results, and the three checks end to end with their failure paths.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

from googleapiclient.errors import HttpError

from app.checks import log_pipeline as lp
from app.checks.log_pipeline import (AUDIT_PIPELINE_CHECK, DUPLICATE_ROUTING_CHECK, PROJECT_ROUTING_CHECK, admits_default_streams, admits_required_streams,
                                     admitted_audit_types, aggregated_bucket_sinks, audit_exclusions, check_audit_pipeline, check_duplicate_routing,
                                     check_project_routing, default_sink_enabled, destination_facts, duplicate_rows, export_errors, in_scope, pipeline_rows,
                                     project_routing_rows, required_stream_rows, view_excludes_data_access, writer_grant_found)
from app.checks.not_checked import NOT_CHECKED
from fakes import ORG_ID as ORG, _execute

JOB = 'job-189'
NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
P, P2, N, N2 = 'stark-logs-prod', 'stark-logs-dev', '111111111111', '222222222222'
WRITER = f'service-org-{ORG}@gcp-sa-logging.iam.gserviceaccount.com'
MEMBERS = {'projects': {P, P2, N, N2}, 'folders': {'1061'}, 'aliases': {P: N, N: P, P2: N2, N2: P2}}
AUDIT = 'logName:"cloudaudit.googleapis.com"'
ACTIVITY = 'LOG_ID("cloudaudit.googleapis.com/activity")'
DEFAULT_FILTER = ('NOT LOG_ID("cloudaudit.googleapis.com/activity") AND NOT LOG_ID("externalaudit.googleapis.com/activity") AND NOT LOG_ID("cloudaudit.googleapis.com/system_event") '
                  'AND NOT LOG_ID("externalaudit.googleapis.com/system_event") AND NOT LOG_ID("cloudaudit.googleapis.com/access_transparency") AND NOT LOG_ID("externalaudit.googleapis.com/access_transparency")')


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_check(self):
        return {record['Check']: record for _, record in self.records if record['Check'] != NOT_CHECKED}

    def not_checked(self):
        return [row for _, record in self.records if record['Check'] == NOT_CHECKED for row in record['Finding']]


def sink(name, destination, log_filter=AUDIT, writer=WRITER, **more):
    return {'name': name, 'destination': destination, 'filter': log_filter, 'writerIdentity': f'serviceAccount:{writer}', **more}


def bucket(name, days=400, locked=False, state='ACTIVE', project=P, location='global', **more):
    return {'name': f'projects/{project}/locations/{location}/buckets/{name}', 'retentionDays': days, 'locked': locked, 'lifecycleState': state, **more}


def policy(resource, role, member=f'serviceAccount:{WRITER}'):
    return SimpleNamespace(resource=resource, policy=SimpleNamespace(bindings=[SimpleNamespace(role=role, members=[member])]))


def http_error(status, message):
    return HttpError(SimpleNamespace(status=status, reason=message), message.encode(), uri='https://x/')


BUCKET_DEST = f'logging.googleapis.com/projects/{P}/locations/global/buckets/audit'


# --- the filter reading ---

def test_admitted_audit_types_reads_log_ids_lognames_generic_matches_and_negations():
    assert admitted_audit_types('') == (set(lp.AUDIT_TYPES), 'all')
    assert admitted_audit_types(None) == (set(lp.AUDIT_TYPES), 'all')
    assert admitted_audit_types(AUDIT) == (set(lp.AUDIT_TYPES), 'audit')
    assert admitted_audit_types('protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"') == (set(lp.AUDIT_TYPES), 'audit')
    assert admitted_audit_types(ACTIVITY) == ({'activity'}, 'audit')
    assert admitted_audit_types('logName:"/logs/cloudaudit.googleapis.com%2Factivity"') == ({'activity'}, 'audit')  # the organization's platform sink
    assert admitted_audit_types(f'{ACTIVITY} OR LOG_ID("cloudaudit.googleapis.com/data_access") OR LOG_ID("cloudaudit.googleapis.com/policy")') == ({'activity', 'data_access', 'policy'}, 'audit')
    assert admitted_audit_types('severity>=ERROR') == (set(), 'other')
    assert admitted_audit_types('resource.type="gce_instance"') == (set(), 'other')
    assert admitted_audit_types(DEFAULT_FILTER) == (set(), 'other')  # every mention negated: the _Default shape
    assert admitted_audit_types(f'severity>=WARNING AND NOT {ACTIVITY}') == (set(), 'other')
    assert admitted_audit_types('-logName:"projects/p/logs/cloudaudit.googleapis.com%2Fdata_access"') == (set(), 'other')
    assert admitted_audit_types(f'{AUDIT} AND NOT LOG_ID("cloudaudit.googleapis.com/data_access")') == (set(lp.AUDIT_TYPES), 'audit')  # a generic match with one type negated: still an audit filter


def test_required_and_default_stream_rules():
    assert admits_required_streams('') and admits_required_streams(AUDIT) and admits_required_streams(ACTIVITY)
    assert admits_required_streams('LOG_ID("cloudaudit.googleapis.com/system_event")')
    assert not admits_required_streams('LOG_ID("cloudaudit.googleapis.com/data_access")')
    assert not admits_required_streams('severity>=ERROR') and not admits_required_streams(DEFAULT_FILTER)
    assert admits_default_streams('') and admits_default_streams('severity>=ERROR') and admits_default_streams(DEFAULT_FILTER)
    assert not admits_default_streams(AUDIT) and not admits_default_streams(ACTIVITY)


def test_audit_exclusions_name_the_enabled_exclusions_that_drop_audit_entries():
    entry = sink('s', BUCKET_DEST, exclusions=[{'name': 'drop-data-access', 'filter': 'LOG_ID("cloudaudit.googleapis.com/data_access")'},
                                               {'name': 'off', 'filter': AUDIT, 'disabled': True}, {'name': 'debug', 'filter': 'severity=DEBUG'}, {'filter': AUDIT}])
    assert audit_exclusions(entry) == ['drop-data-access', '?']
    assert audit_exclusions(sink('s', BUCKET_DEST)) == []


# --- destinations and scope ---

def test_destination_facts_read_every_destination_kind():
    assert destination_facts(BUCKET_DEST) == {'kind': 'bucket', 'name': f'projects/{P}/locations/global/buckets/audit', 'short': 'audit', 'project': P, 'parent': f'projects/{P}'}
    assert destination_facts('logging.googleapis.com/folders/1061/locations/global/buckets/b') == {'kind': 'bucket', 'name': 'folders/1061/locations/global/buckets/b', 'short': 'b', 'project': '', 'parent': 'folders/1061'}
    assert destination_facts(f'logging.googleapis.com/projects/{P2}') == {'kind': 'project', 'name': f'projects/{P2}', 'short': f'projects/{P2}', 'project': P2, 'parent': f'projects/{P2}'}
    assert destination_facts(f'bigquery.googleapis.com/projects/{P}/datasets/audit_logs') == {'kind': 'bigquery', 'name': f'projects/{P}/datasets/audit_logs', 'short': 'audit_logs', 'project': P, 'parent': f'projects/{P}'}
    assert destination_facts('storage.googleapis.com/my-archive') == {'kind': 'storage', 'name': 'my-archive', 'short': 'my-archive', 'project': '', 'parent': ''}
    assert destination_facts(f'pubsub.googleapis.com/projects/{N}/topics/audit') == {'kind': 'pubsub', 'name': f'projects/{N}/topics/audit', 'short': 'audit', 'project': N, 'parent': f'projects/{N}'}
    assert destination_facts('')['kind'] == 'other' and destination_facts('splunk://x')['kind'] == 'other'


def test_in_scope_judges_by_project_id_or_number_folder_or_the_scope_itself():
    assert in_scope(destination_facts(BUCKET_DEST), 'organization', ORG, MEMBERS) is True
    assert in_scope(destination_facts(f'pubsub.googleapis.com/projects/{N2}/topics/t'), 'organization', ORG, MEMBERS) is True
    assert in_scope(destination_facts('pubsub.googleapis.com/projects/sst-multiorg-880241551927/topics/t'), 'organization', ORG, MEMBERS) is False
    assert in_scope(destination_facts('logging.googleapis.com/folders/1061/locations/global/buckets/b'), 'organization', ORG, MEMBERS) is True
    assert in_scope(destination_facts('logging.googleapis.com/folders/9/locations/global/buckets/b'), 'organization', ORG, MEMBERS) is False
    assert in_scope(destination_facts(f'logging.googleapis.com/organizations/{ORG}/locations/global/buckets/b'), 'organization', ORG, MEMBERS) is True
    assert in_scope(destination_facts(f'logging.googleapis.com/organizations/{ORG}/locations/global/buckets/b'), 'folder', '1061', MEMBERS) is False
    assert in_scope(destination_facts('storage.googleapis.com/b'), 'organization', ORG, MEMBERS) is None


def test_writer_grant_found_matches_the_destination_its_project_by_id_or_number_and_its_parent():
    facts = destination_facts(BUCKET_DEST)
    assert writer_grant_found([policy(f'//cloudresourcemanager.googleapis.com/projects/{P}', 'roles/logging.bucketWriter')], facts, MEMBERS['aliases'])
    assert writer_grant_found([policy(f'//cloudresourcemanager.googleapis.com/projects/{N}', 'roles/logging.bucketWriter')], facts, MEMBERS['aliases'])  # the grant named by number
    assert not writer_grant_found([policy(f'//cloudresourcemanager.googleapis.com/projects/{P2}', 'roles/logging.bucketWriter')], facts, MEMBERS['aliases'])
    assert not writer_grant_found([policy(f'//cloudresourcemanager.googleapis.com/projects/{P}', 'roles/viewer')], facts, MEMBERS['aliases'])
    assert writer_grant_found([policy(f'//cloudresourcemanager.googleapis.com/projects/{P}', 'roles/owner')], facts)
    topic = destination_facts(f'pubsub.googleapis.com/projects/{P}/topics/audit')
    assert writer_grant_found([policy(f'//pubsub.googleapis.com/projects/{P}/topics/audit', 'roles/pubsub.publisher')], topic)
    assert not writer_grant_found([policy(f'//pubsub.googleapis.com/projects/{P}/topics/other', 'roles/pubsub.publisher')], topic)
    dataset = destination_facts(f'bigquery.googleapis.com/projects/{P}/datasets/audit_logs')
    assert writer_grant_found([policy(f'//bigquery.googleapis.com/projects/{P}/datasets/audit_logs', 'roles/bigquery.dataEditor')], dataset)
    gcs = destination_facts('storage.googleapis.com/my-archive')
    assert writer_grant_found([policy('//storage.googleapis.com/my-archive', 'roles/storage.objectCreator')], gcs)
    assert writer_grant_found([policy('//cloudresourcemanager.googleapis.com/folders/1061', 'roles/logging.bucketWriter')], destination_facts('logging.googleapis.com/folders/1061/locations/global/buckets/b'))
    assert not writer_grant_found([], facts)


def test_export_errors_sum_the_points_per_sink():
    series = [{'resource': {'labels': {'name': 'audit'}}, 'points': [{'value': {'int64Value': '12'}}, {'value': {'int64Value': '3'}}]},
              {'resource': {'labels': {'name': 'audit'}}, 'points': [{'value': {'doubleValue': 1.0}}]},
              {'resource': {'labels': {'name': 'quiet'}}, 'points': [{'value': {'int64Value': '0'}}]},
              {'resource': {'labels': {'name': 'odd'}}, 'points': [{'value': {'int64Value': 'x'}}]}, {'points': [{'value': {'int64Value': '5'}}]}]
    assert export_errors(series) == {'audit': 16}
    assert export_errors(None) == {}


# --- Audit Log Pipeline rows ---

def test_pipeline_rows_judge_filter_exclusions_children_bucket_and_errors():
    org = f'organizations/{ORG}'
    sinks = [{'name': '_Required', 'destination': BUCKET_DEST}, {'name': '_Default', 'destination': BUCKET_DEST},
             sink('narrow', BUCKET_DEST, ACTIVITY, exclusions=[{'name': 'drop', 'filter': 'LOG_ID("cloudaudit.googleapis.com/activity")'}], disabled=True)]
    buckets = {f'projects/{P}/locations/global/buckets/audit': bucket('audit', days=30)}
    rows = pipeline_rows(org, sinks, 'organization', ORG, MEMBERS, bucket_reader=buckets.__getitem__, writer_policies=lambda w: [policy(f'//cloudresourcemanager.googleapis.com/projects/{P}', 'roles/logging.bucketWriter')],
                         errors={'narrow': 1200})
    assert [(r['Issue'], r['_status']) for r in rows] == [('Sink disabled.', 'Investigation Recommended'), ('Audit export incomplete.', 'Investigation Recommended'),
                                                           ('Exclusion drops audit entries.', 'Investigation Recommended'), ('Audit retention under a year.', 'Investigation Recommended'),
                                                           ('Audit bucket not locked.', 'Informational'), ('Export errors.', 'Action Required')]
    assert rows[0]['Fix'] == f'gcloud logging sinks update narrow --organization={ORG} --no-disabled'
    assert rows[1]['Detail'] == 'The filter admits activity and leaves out system_event, data_access, policy: those audit logs are not exported.'
    assert rows[1]['Fix'] == f"gcloud logging sinks update narrow --organization={ORG} --log-filter='{AUDIT}'"
    assert rows[2]['Fix'] == f'gcloud logging sinks update narrow --organization={ORG} --remove-exclusions=drop'
    assert rows[3]['Fix'] == f'gcloud logging buckets update audit --location=global --project={P} --retention-days=365'
    assert rows[4]['Fix'] == f'gcloud logging buckets update audit --location=global --project={P} --locked  # irreversible'
    assert rows[5]['Detail'] == '1,200 entries failed to export in the last 7 days (logging.googleapis.com/exports/error_count).'
    assert all((r['Resource'], r['Sink'], r['Destination']) == (org, 'narrow', 'log bucket audit') for r in rows)
    # A folder sink without children; a complete, locked, long archive is clean.
    rows = pipeline_rows('folders/1061', [sink('archive', BUCKET_DEST)], 'folder', '1061', MEMBERS, bucket_reader=lambda name: bucket('audit', locked=True),
                         writer_policies=lambda w: [policy('//cloudresourcemanager.googleapis.com/folders/1061', 'roles/logging.bucketWriter')])
    assert [(r['Issue'], r['Fix']) for r in rows] == [('Folder sink without children.', 'gcloud logging sinks update archive --folder=1061 --include-children')]  # the folder's grant is inherited
    assert pipeline_rows('folders/1061', [sink('archive', BUCKET_DEST, includeChildren=True)], 'folder', '1061', MEMBERS, bucket_reader=lambda name: bucket('audit', locked=True),
                         writer_policies=lambda w: [policy(f'//cloudresourcemanager.googleapis.com/projects/{P}', 'roles/logging.bucketWriter')]) == []


def test_pipeline_rows_judge_the_destination_and_the_writer():
    org = f'organizations/{ORG}'
    gone = lambda name: (_ for _ in ()).throw(http_error(404, 'bucket not found'))  # noqa: E731
    rows = pipeline_rows(org, [sink('s', BUCKET_DEST)], 'organization', ORG, MEMBERS, bucket_reader=gone, writer_policies=lambda w: [])
    assert [(r['Issue'], r['_status']) for r in rows] == [('Destination bucket gone.', 'Action Required'), ('Writer without the destination role.', 'Action Required')]
    assert rows[0]['Fix'] == f'gcloud logging buckets create audit --location=global --project={P} --retention-days=365  # or point the sink elsewhere'
    assert rows[1]['Detail'] == f'{WRITER} holds no roles/logging.bucketWriter on the destination or its project: the sink cannot write, and every entry is dropped.'
    assert rows[1]['Fix'] == f'gcloud projects add-iam-policy-binding {P} --member=serviceAccount:{WRITER} --role=roles/logging.bucketWriter  # or on the bucket\'s folder / organization'
    unreadable = lambda name: (_ for _ in ()).throw(RuntimeError('403 forbidden'))  # noqa: E731
    rows = pipeline_rows(org, [sink('s', BUCKET_DEST)], 'organization', ORG, MEMBERS, bucket_reader=unreadable, writer_policies=lambda w: [policy(f'//cloudresourcemanager.googleapis.com/projects/{P}', 'roles/logging.bucketWriter')])
    assert [(r['Issue'], r['_status']) for r in rows] == [('Destination bucket not readable.', 'Informational')]
    rows = pipeline_rows(org, [sink('s', BUCKET_DEST)], 'organization', ORG, MEMBERS, bucket_reader=lambda name: bucket('audit', state='DELETE_REQUESTED'), writer_policies=lambda w: [])
    assert [(r['Issue'], r['_status']) for r in rows] == [('Destination bucket not active.', 'Action Required'), ('Writer without the destination role.', 'Action Required')]
    # Outside the scope: one Informational row and nothing else is judged.
    outside = sink('platform', 'pubsub.googleapis.com/projects/sst-multiorg-880241551927/topics/activity', 'logName:"/logs/cloudaudit.googleapis.com%2Factivity"')
    rows = pipeline_rows(org, [outside], 'organization', ORG, MEMBERS, destination_exists=lambda kind, facts: False, writer_policies=lambda w: [])
    assert [(r['Issue'], r['_status']) for r in rows] == [('Audit export incomplete.', 'Investigation Recommended'), ('Destination outside the scanned scope.', 'Informational')]
    assert rows[1]['Destination'] == 'Pub/Sub topic activity'
    # A dataset gone, a topic present with the grant, a Cloud Storage bucket not in the inventory, a project destination.
    sinks = [sink('bq', f'bigquery.googleapis.com/projects/{P}/datasets/audit_logs'), sink('ps', f'pubsub.googleapis.com/projects/{P}/topics/audit'),
             sink('gcs', 'storage.googleapis.com/my-archive'), sink('proj', f'logging.googleapis.com/projects/{P2}')]
    exists = lambda kind, facts: {'bigquery': False, 'pubsub': True, 'storage': False}[kind]  # noqa: E731
    rows = pipeline_rows(org, sinks, 'organization', ORG, MEMBERS, destination_exists=exists, writer_policies=lambda w: [policy(f'//pubsub.googleapis.com/projects/{P}/topics/audit', 'roles/pubsub.publisher')])
    assert [(r['Sink'], r['Issue'], r['_status']) for r in rows] == [('bq', 'Destination BigQuery dataset gone.', 'Action Required'), ('gcs', 'Destination bucket not in the scanned scope.', 'Informational')]
    # The writer rule: the shared identity and a project's sink into its own bucket are never judged; an unknown inventory (None) judges nothing.
    assert pipeline_rows(f'projects/{P}', [sink('own', BUCKET_DEST)], 'project', P, MEMBERS, bucket_reader=lambda name: bucket('audit', locked=True), writer_policies=lambda w: []) == []
    assert pipeline_rows(org, [sink('shared', f'pubsub.googleapis.com/projects/{P}/topics/audit', writer=lp.SHARED_WRITER)], 'organization', ORG, MEMBERS,
                         destination_exists=lambda kind, facts: True, writer_policies=lambda w: []) == []
    assert pipeline_rows(org, [sink('ps', f'pubsub.googleapis.com/projects/{P}/topics/audit')], 'organization', ORG, MEMBERS, destination_exists=lambda kind, facts: None,
                         writer_policies=lambda w: (_ for _ in ()).throw(RuntimeError('search down'))) == []
    assert pipeline_rows(org, [], 'organization', ORG, MEMBERS) == []


# --- Duplicate Log Routing ---

def test_duplicate_rows_count_the_projects_whose_default_sink_still_stores():
    org_sink = sink('all-logs', f'logging.googleapis.com/projects/{P}/locations/global/buckets/central', '', includeChildren=True)
    folder_sink = sink('folder-errors', f'logging.googleapis.com/projects/{P}/locations/global/buckets/errors', 'severity>=ERROR', includeChildren=True)
    by_parent = {f'organizations/{ORG}': [org_sink, sink('audit', BUCKET_DEST, AUDIT, includeChildren=True), sink('off', BUCKET_DEST, '', includeChildren=True, disabled=True),
                                          sink('no-children', BUCKET_DEST, ''), sink('bq', f'bigquery.googleapis.com/projects/{P}/datasets/d', '', includeChildren=True)],
                 'folders/1061': [folder_sink], f'projects/{P}': [sink('project-sink', BUCKET_DEST, '', includeChildren=True)]}
    aggregated = aggregated_bucket_sinks(by_parent)
    assert [(parent, s['name']) for parent, s in aggregated] == [(f'organizations/{ORG}', 'all-logs'), ('folders/1061', 'folder-errors')]
    projects = [{'id': P, 'number': N, 'folders': ['1061']}, {'id': P2, 'number': N2, 'folders': ['2000']}, {'id': 'p3', 'number': '3', 'folders': ['1061']}]
    defaults = {P: {'name': '_Default'}, P2: {'name': '_Default', 'disabled': True}, 'p3': {'name': '_Default', 'exclusions': [{'name': 'all', 'filter': '*'}]}}
    rows = duplicate_rows(aggregated, projects, defaults)
    assert [(r['Resource'], r['Sink'], r['Projects'], r['Issue'], r['_status']) for r in rows] == [(f'organizations/{ORG}', 'all-logs', 1, 'Logs stored twice.', 'Investigation Recommended'),
                                                                                                  ('folders/1061', 'folder-errors', 1, 'Logs stored twice.', 'Investigation Recommended')]
    assert rows[0]['Detail'] == f'The aggregated sink stores the logs of 1 project ({P}) in central while their own _Default sinks store them again: ingestion is billed in both buckets.'
    assert rows[0]['Fix'].startswith(f'gcloud logging sinks update _Default --project={P} --disabled')
    rows = duplicate_rows(aggregated, projects, {})  # nothing read: every project counted as storing
    assert [(r['Sink'], r['Projects']) for r in rows] == [('all-logs', 3), ('folder-errors', 2)]
    assert rows[1]['Detail'].startswith(f'The aggregated sink stores the logs of 2 projects (p3, {P})')
    many = [{'id': f'p{i}', 'number': str(i), 'folders': []} for i in range(8)]
    assert duplicate_rows([aggregated[0]], many, {})[0]['Detail'].startswith('The aggregated sink stores the logs of 8 projects (p0, p1, p2, p3, p4, …)')
    assert duplicate_rows([], projects, defaults) == []


def test_default_sink_enabled_reads_disabled_and_catch_all_exclusions():
    assert default_sink_enabled({}) and default_sink_enabled({'exclusions': [{'name': 'debug', 'filter': 'severity=DEBUG'}]})
    assert not default_sink_enabled({'disabled': True})
    assert not default_sink_enabled({'exclusions': [{'name': 'all', 'filter': '"TRUE"'}]}) and not default_sink_enabled({'exclusions': [{'filter': ' * '}]})
    assert default_sink_enabled({'exclusions': [{'filter': '*', 'disabled': True}]})


def test_required_stream_rows_are_informational_for_bucket_sinks_that_admit_the_required_streams():
    by_parent = {f'organizations/{ORG}': [sink('audit', BUCKET_DEST, AUDIT, includeChildren=True), sink('bq', f'bigquery.googleapis.com/projects/{P}/datasets/d', AUDIT, includeChildren=True),
                                          sink('data-access', BUCKET_DEST, 'LOG_ID("cloudaudit.googleapis.com/data_access")', includeChildren=True), {'name': '_Required', 'destination': BUCKET_DEST}],
                 f'projects/{P}': [sink('errors', BUCKET_DEST, 'severity>=ERROR'), sink('everything', BUCKET_DEST, '')]}
    rows = required_stream_rows(by_parent)
    assert [(r['Resource'], r['Sink'], r['_status']) for r in rows] == [(f'organizations/{ORG}', 'audit', 'Informational'), (f'projects/{P}', 'everything', 'Informational')]
    assert rows[0]['Issue'] == '_Required streams stored again.' and rows[0]['Fix'].startswith(f'gcloud logging sinks update audit --organization={ORG} --log-filter=')
    assert rows[1]['Fix'].startswith(f'gcloud logging sinks update everything --project={P} --log-filter=')


# --- Project Log Routing ---

def test_view_excludes_data_access_reads_the_default_view_filter():
    assert view_excludes_data_access({'filter': 'NOT LOG_ID("cloudaudit.googleapis.com/data_access") AND NOT LOG_ID("externalaudit.googleapis.com/data_access")'})
    assert view_excludes_data_access({'filter': '-logName:"projects/p/logs/cloudaudit.googleapis.com%2Fdata_access"'})
    assert not view_excludes_data_access({'filter': ''}) and not view_excludes_data_access({})
    assert not view_excludes_data_access({'filter': 'LOG_ID("cloudaudit.googleapis.com/data_access")'})
    assert not view_excludes_data_access({'filter': 'NOT LOG_ID("cloudaudit.googleapis.com/activity")'})


def test_project_routing_rows_judge_the_default_sink_view_and_analytics():
    default_sink = {'name': '_Default', 'destination': f'logging.googleapis.com/projects/{P}/locations/global/buckets/_Default', 'disabled': True}
    buckets = [bucket('_Required', locked=True), bucket('_Default', days=30)]
    views = [{'name': f'projects/{P}/locations/global/buckets/_Default/views/_AllLogs'}, {'name': f'projects/{P}/locations/global/buckets/_Default/views/_Default', 'filter': ''}]
    rows = project_routing_rows(P, [default_sink], buckets, views, data_access_on=True)
    assert [(r['Resource'], r['Issue'], r['_status']) for r in rows] == [('sink _Default', 'Logs discarded.', 'Action Required'), ('view _Default', 'Data Access logs in the default view.', 'Informational'),
                                                                        ('bucket _Default', 'Log Analytics off.', 'Informational')]
    assert rows[0]['Fix'] == f'gcloud logging sinks update _Default --project={P} --no-disabled'
    assert rows[1]['Fix'] == (f"gcloud logging views update _Default --bucket=_Default --location=global --project={P} "
                              "--log-filter='NOT LOG_ID(\"cloudaudit.googleapis.com/data_access\") AND NOT LOG_ID(\"externalaudit.googleapis.com/data_access\")'")
    assert rows[2]['Fix'] == f'gcloud logging buckets update _Default --location=global --project={P} --enable-analytics  # irreversible'
    # Excluding everything, with another bucket sink that stores everything: not discarded. Data Access off: the view is not judged. Analytics on: nothing.
    excluding = {'name': '_Default', 'exclusions': [{'name': 'all', 'filter': '*'}]}
    rows = project_routing_rows(P, [excluding, sink('archive', BUCKET_DEST, '')], [bucket('_Default', days=30, analyticsEnabled=True)], views, data_access_on=False)
    assert rows == []
    assert project_routing_rows(P, [excluding, sink('errors', BUCKET_DEST, 'severity>=ERROR')], [bucket('_Default', days=30, analyticsEnabled=True)], views, False) == []
    # An audit-only bucket sink (the sandbox probe) or a sink into Cloud Storage does not stand in for a dead _Default: the logs are discarded.
    rows = project_routing_rows(P, [default_sink, sink('audit', BUCKET_DEST, ACTIVITY), sink('gcs', 'storage.googleapis.com/archive', '')], [bucket('_Default', days=30, analyticsEnabled=True)], views, False)
    assert [(r['Issue'], r['_status']) for r in rows] == [('Logs discarded.', 'Action Required')]
    assert rows[0]['Detail'] == ("The _Default sink is disabled and no other sink stores the project's logs into a log bucket (an audit-only sink does not): "
                                 "they are dropped as they arrive, the _Required audit streams excepted.")
    rows = project_routing_rows(P, [excluding], [bucket('_Default', days=30, analyticsEnabled=True)], [], data_access_on=False)
    assert [(r['Issue'], r['Fix']) for r in rows] == [('Logs discarded.', f'gcloud logging sinks update _Default --project={P} --clear-exclusions')]
    assert rows[0]['Detail'].startswith('The _Default sink is excluding everything')
    assert project_routing_rows(P, [], [], [], False) == []


# --- the checks ---

class FakeLogging:
    """``organizations()`` / ``folders()`` / ``projects()`` with sinks, buckets (list and get) and views, keyed by parent."""

    def __init__(self, sinks=None, buckets=None, views=None, sink_errors=None, bucket_errors=None, view_error=None):
        self.sinks_, self.buckets_, self.views_ = sinks or {}, buckets or {}, views or {}
        self.sink_errors, self.bucket_errors, self.view_error = sink_errors or {}, bucket_errors or {}, view_error
        self.sink_parents, self.bucket_gets, self.view_parents = [], [], []

    def _collection(self):
        def sinks_list(parent):
            self.sink_parents.append(parent)
            return _execute(self.sink_errors.get(parent) or {'sinks': self.sinks_.get(parent, [])})

        def buckets_list(parent):
            return _execute(self.bucket_errors.get(parent) or {'buckets': self.buckets_.get(parent.replace('/locations/-', ''), [])})

        def buckets_get(name):
            self.bucket_gets.append(name)
            error = self.bucket_errors.get(name)
            if error:
                return _execute(error)
            found = next((b for buckets in self.buckets_.values() for b in buckets if b['name'] == name), None)
            return _execute(found or http_error(404, f'{name} not found'))

        def views_list(parent):
            self.view_parents.append(parent)
            return _execute(self.view_error or {'views': self.views_.get(parent, [])})
        none = lambda previous_request, previous_response: None  # noqa: E731
        buckets = SimpleNamespace(list=buckets_list, list_next=none, get=buckets_get, views=lambda: SimpleNamespace(list=views_list))
        return SimpleNamespace(sinks=lambda: SimpleNamespace(list=sinks_list, list_next=none), locations=lambda: SimpleNamespace(buckets=lambda: buckets))

    organizations = folders = projects = _collection


class FakeMonitoring:
    def __init__(self, series=(), error=None):
        self.series_, self.error, self.requests = list(series), error, []

    def projects(self):
        def list_(**kwargs):
            self.requests.append(kwargs)
            return _execute(self.error or {'timeSeries': self.series_})
        return SimpleNamespace(timeSeries=lambda: SimpleNamespace(list=list_, list_next=lambda previous_request, previous_response: None))


class FakeCrm:
    def __init__(self, project_configs=None, org_configs=None, error=None):
        self.project_configs, self.org_configs, self.error = project_configs or {}, org_configs or [], error
        self.org_reads = 0

    def projects(self):
        def get_iam_policy(resource, body):
            return _execute(self.error or {'auditConfigs': self.project_configs.get(resource, [])})
        return SimpleNamespace(getIamPolicy=get_iam_policy, getAncestry=lambda projectId, body: _execute({'ancestor': [{'resourceId': {'type': 'project', 'id': projectId}}, {'resourceId': {'type': 'organization', 'id': ORG}}]}))

    def organizations(self):
        def get_iam_policy(resource, body):
            self.org_reads += 1
            return _execute({'auditConfigs': self.org_configs})
        return SimpleNamespace(getIamPolicy=get_iam_policy)


def add_members(gcp):
    gcp.assets.add('projects', P, 'Logs prod', parent='folders/1061', project_number=N, organization=ORG)
    gcp.assets.add('projects', P2, 'Logs dev', parent='folders/1061', project_number=N2, organization=ORG)
    gcp.assets.add('folders', '1061', 'stark-folder', parent=f'organizations/{ORG}')


def test_check_audit_pipeline_end_to_end(gcp, monkeypatch):
    monkeypatch.setattr(lp, 'utcnow', lambda: NOW)
    add_members(gcp)
    org = f'organizations/{ORG}'
    gcp.discovery.apis['logging'] = FakeLogging(
        sinks={org: [{'name': '_Required', 'destination': BUCKET_DEST}, sink('narrow', BUCKET_DEST, ACTIVITY, includeChildren=True),
                     sink('platform', 'pubsub.googleapis.com/projects/sst-multiorg-880241551927/topics/activity', 'logName:"/logs/cloudaudit.googleapis.com%2Factivity"', includeChildren=True),
                     sink('ps', f'pubsub.googleapis.com/projects/{P}/topics/audit', includeChildren=True), sink('bq', f'bigquery.googleapis.com/projects/{P}/datasets/gone', includeChildren=True)]},
        buckets={f'projects/{P}': [bucket('audit', days=30)]})
    gcp.discovery.apis['monitoring'] = FakeMonitoring(series=[{'resource': {'labels': {'name': 'narrow'}}, 'points': [{'value': {'int64Value': '7'}}]}])
    gcp.assets.add_asset('pubsub.googleapis.com/Topic', f'//pubsub.googleapis.com/projects/{P}/topics/audit', {'name': f'projects/{P}/topics/audit'}, project_number=N)
    gcp.assets.add_iam_policy('cloudresourcemanager.googleapis.com/Project', f'//cloudresourcemanager.googleapis.com/projects/{P}', [('roles/logging.bucketWriter', [f'serviceAccount:{WRITER}'])], project_number=N)
    monkeypatch.setenv('PROJECT_ID', 'cg-host')
    s = Sink()
    check_audit_pipeline('organization', ORG, JOB, sink=s)
    record = s.by_check()[AUDIT_PIPELINE_CHECK]
    assert record['Status'] == 'Action Required'
    assert [(r['Sink'], r['Issue']) for r in record['Finding']] == [
        ('narrow', 'Audit export incomplete.'), ('narrow', 'Audit retention under a year.'), ('narrow', 'Audit bucket not locked.'), ('narrow', 'Export errors.'),
        ('platform', 'Audit export incomplete.'), ('platform', 'Destination outside the scanned scope.'),
        ('ps', 'Writer without the destination role.'), ('bq', 'Destination BigQuery dataset gone.')]
    assert all('_status' not in r for r in record['Finding']) and s.not_checked() == []
    assert gcp.discovery.apis['logging'].bucket_gets == [f'projects/{P}/locations/global/buckets/audit']
    assert gcp.discovery.apis['monitoring'].requests[0]['name'] == 'projects/cg-host' and gcp.discovery.apis['monitoring'].requests[0]['interval_startTime'] == '2026-11-09T12:00:00Z'
    assert gcp.assets.iam_queries == [f'policy:"{WRITER}"'] * 2  # the bucket's and the topic's writer; not the platform sink's (outside) nor the dataset's (gone)
    assert [r['asset_types'] for r in gcp.assets.list_requests] == [['pubsub.googleapis.com/Topic'], ['bigquery.googleapis.com/Dataset']]
    # A project scan reads the project's own Monitoring and has no search for folders.
    gcp.assets.list_requests.clear()
    gcp.discovery.apis['logging'] = FakeLogging(sinks={f'projects/{P}': [sink('own', BUCKET_DEST, '')]}, buckets={f'projects/{P}': [bucket('audit', locked=True)]})
    s = Sink()
    check_audit_pipeline('project', P, JOB, sink=s)
    assert s.by_check()[AUDIT_PIPELINE_CHECK] == {'Check': AUDIT_PIPELINE_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': lp.AUDIT_PIPELINE_ALL_CLEAR}]}
    assert gcp.discovery.apis['monitoring'].requests[-1]['name'] == f'projects/{P}'


def test_check_audit_pipeline_notes_and_failures(gcp, monkeypatch):
    monkeypatch.setattr(lp, 'utcnow', lambda: NOW)
    add_members(gcp)
    org = f'organizations/{ORG}'
    gcp.discovery.apis['logging'] = FakeLogging(sinks={org: [{'name': '_Required', 'destination': BUCKET_DEST}, {'name': '_Default', 'destination': BUCKET_DEST}]})
    gcp.discovery.apis['monitoring'] = FakeMonitoring()
    s = Sink()
    check_audit_pipeline('organization', ORG, JOB, sink=s)
    assert s.by_check()[AUDIT_PIPELINE_CHECK] == {'Check': AUDIT_PIPELINE_CHECK, 'Status': 'Informational',
                                                  'Finding': [{'Summary': f'No customer log sink at organizations/{ORG}: nothing to judge here — Organization Log Sink says what that means.'}]}
    s = Sink()
    check_audit_pipeline('folder', '1061', JOB, sink=s)
    assert s.by_check()[AUDIT_PIPELINE_CHECK]['Finding'][0]['Summary'] == "No customer log sink at folders/1061; the organization's aggregated sink, if any, covers it — judged in an organization scan."
    # The listing fails: an Error record.
    gcp.discovery.apis['logging'] = FakeLogging(sink_errors={org: RuntimeError('logging down')})
    s = Sink()
    check_audit_pipeline('organization', ORG, JOB, sink=s)
    assert s.by_check()[AUDIT_PIPELINE_CHECK] == {'Check': AUDIT_PIPELINE_CHECK, 'Status': 'Error', 'Finding': [{'Error': 'logging down'}]}
    # The project search fails: destinations are judged against the scope alone; the Monitoring read fails quietly; the inventory listing fails: a note.
    gcp.assets.error = RuntimeError('search down')
    gcp.assets.list_errors['pubsub.googleapis.com/Topic'] = RuntimeError('listing down')
    gcp.discovery.apis['logging'] = FakeLogging(sinks={org: [sink('ps', f'pubsub.googleapis.com/projects/{P}/topics/audit', includeChildren=True), sink('ob', f'logging.googleapis.com/organizations/{ORG}/locations/global/buckets/ob', includeChildren=True)]},
                                                buckets={org: [{'name': f'organizations/{ORG}/locations/global/buckets/ob', 'retentionDays': 400, 'locked': True}]})
    gcp.discovery.apis['monitoring'] = FakeMonitoring(error=RuntimeError('monitoring down'))
    s = Sink()
    check_audit_pipeline('organization', ORG, JOB, sink=s)
    record = s.by_check()[AUDIT_PIPELINE_CHECK]
    assert [(r['Sink'], r['Issue']) for r in record['Finding']] == [('ps', 'Destination outside the scanned scope.')]
    assert [(r['Project'], r['Skipped check'], r['Reason']) for r in s.not_checked()] == [
        (org, f'{AUDIT_PIPELINE_CHECK} (the project search failed; destinations are judged as in scope only when they name the scanned resource)', 'search down')]
    assert record['Status'] == 'Informational'


def test_check_duplicate_routing_end_to_end(gcp):
    add_members(gcp)
    org = f'organizations/{ORG}'
    central = sink('all-logs', f'logging.googleapis.com/projects/{P}/locations/global/buckets/central', '', includeChildren=True)
    gcp.discovery.apis['logging'] = FakeLogging(sinks={org: [central, sink('audit', BUCKET_DEST, AUDIT, includeChildren=True)], 'folders/1061': [],
                                                       f'projects/{P}': [{'name': '_Default'}], f'projects/{P2}': [{'name': '_Default', 'disabled': True}]})
    s = Sink()
    check_duplicate_routing('organization', ORG, JOB, sink=s)
    record = s.by_check()[DUPLICATE_ROUTING_CHECK]
    assert record['Status'] == 'Investigation Recommended'
    assert [(r['Sink'], r['Projects'], r['Issue']) for r in record['Finding']] == [('all-logs', 1, 'Logs stored twice.'), ('all-logs', '', '_Required streams stored again.'), ('audit', '', '_Required streams stored again.')]
    assert gcp.discovery.apis['logging'].sink_parents == [org, 'folders/1061', f'projects/{P}', f'projects/{P2}']
    # No aggregated bucket sink: the projects are not read; a folder scan lists the folder (the search includes it once).
    gcp.discovery.apis['logging'] = FakeLogging(sinks={'folders/1061': [sink('bq', f'bigquery.googleapis.com/projects/{P}/datasets/d', '', includeChildren=True)]})
    s = Sink()
    check_duplicate_routing('folder', '1061', JOB, sink=s)
    assert s.by_check()[DUPLICATE_ROUTING_CHECK] == {'Check': DUPLICATE_ROUTING_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': lp.DUPLICATE_ALL_CLEAR}]}
    assert gcp.discovery.apis['logging'].sink_parents == ['folders/1061']
    # A project scan reads the project's sinks alone; a folder whose sinks cannot be listed is noted; a project whose _Default cannot be read counts as storing.
    gcp.discovery.apis['logging'] = FakeLogging(sinks={org: [central]}, sink_errors={'folders/1061': RuntimeError('folder down'), f'projects/{P2}': RuntimeError('project down')})
    s = Sink()
    check_duplicate_routing('organization', ORG, JOB, sink=s)
    assert [(r['Sink'], r['Projects']) for r in s.by_check()[DUPLICATE_ROUTING_CHECK]['Finding']] == [('all-logs', 2), ('all-logs', '')]
    assert [(r['Project'], r['Reason']) for r in s.not_checked()] == [('folders/1061', 'folder down'), (P2, 'project down')]
    gcp.assets.error = RuntimeError('search down')
    s = Sink()
    check_duplicate_routing('organization', ORG, JOB, sink=s)
    assert s.by_check()[DUPLICATE_ROUTING_CHECK]['Status'] == 'Error'
    s = Sink()
    check_duplicate_routing('project', P, JOB, sink=s)  # no search in a project scan
    assert s.by_check()[DUPLICATE_ROUTING_CHECK]['Status'] == 'Compliant'


def test_check_project_routing_end_to_end(gcp):
    default_bucket = f'projects/{P}/locations/global/buckets/_Default'
    gcp.discovery.apis['logging'] = FakeLogging(
        sinks={f'projects/{P}': [{'name': '_Default', 'disabled': True}], f'projects/{P2}': [{'name': '_Default'}]},
        buckets={f'projects/{P}': [bucket('_Default', days=30)], f'projects/{P2}': [bucket('_Default', days=30, project=P2, analyticsEnabled=True)]},
        views={default_bucket: [{'name': f'{default_bucket}/views/_Default', 'filter': ''}]})
    gcp.discovery.apis['cloudresourcemanager'] = FakeCrm(org_configs=[{'service': 'allServices', 'auditLogConfigs': [{'logType': 'ADMIN_READ'}]}])
    s = Sink()
    check_project_routing(ORG, [{'projectId': P}, {'projectId': P2}], JOB, sink=s)
    record = s.by_check()[PROJECT_ROUTING_CHECK]
    assert record['Status'] == 'Action Required'
    assert [(r['Project'], r['Resource'], r['Issue']) for r in record['Finding']] == [(P, 'sink _Default', 'Logs discarded.'), (P, 'view _Default', 'Data Access logs in the default view.'), (P, 'bucket _Default', 'Log Analytics off.')]
    assert gcp.discovery.apis['cloudresourcemanager'].org_reads == 1  # the organization's configuration once
    assert gcp.discovery.apis['logging'].view_parents == [default_bucket, f'projects/{P2}/locations/global/buckets/_Default']
    # Data Access off everywhere: no view read. A project-level configuration for one service counts.
    gcp.discovery.apis['logging'] = FakeLogging(sinks={f'projects/{P}': [{'name': '_Default'}]}, buckets={f'projects/{P}': [bucket('_Default', days=30, analyticsEnabled=True)]})
    gcp.discovery.apis['cloudresourcemanager'] = FakeCrm()
    s = Sink()
    check_project_routing(ORG, [{'projectId': P}], JOB, sink=s)
    assert s.by_check()[PROJECT_ROUTING_CHECK] == {'Check': PROJECT_ROUTING_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': lp.PROJECT_ROUTING_ALL_CLEAR}]}
    assert gcp.discovery.apis['logging'].view_parents == []
    gcp.discovery.apis['cloudresourcemanager'] = FakeCrm(project_configs={P: [{'service': 'container.googleapis.com', 'auditLogConfigs': [{'logType': 'DATA_READ'}]}]})
    s = Sink()
    check_project_routing(ORG, [{'projectId': P}], JOB, sink=s)
    assert gcp.discovery.apis['logging'].view_parents == [default_bucket]
    # Failures: the sinks unreadable → the project not checked; the IAM policy unreadable → the view rule skipped with a note.
    gcp.discovery.apis['logging'] = FakeLogging(sinks={f'projects/{P}': [{'name': '_Default'}]}, buckets={f'projects/{P}': [bucket('_Default', days=30)]}, sink_errors={f'projects/{P2}': RuntimeError('sinks down')})
    gcp.discovery.apis['cloudresourcemanager'] = FakeCrm(error=RuntimeError('iam down'))
    s = Sink()
    check_project_routing(ORG, [{'projectId': P}, {'projectId': P2}], JOB, sink=s)
    assert [(r['Project'], r['Issue']) for r in s.by_check()[PROJECT_ROUTING_CHECK]['Finding']] == [(P, 'Log Analytics off.')]
    assert [(r['Project'], r['Skipped check'], r['Reason']) for r in s.not_checked()] == [
        (P, f'{PROJECT_ROUTING_CHECK} (the audit configuration or the views could not be read; the view rule was not applied)', 'iam down'), (P2, PROJECT_ROUTING_CHECK, 'sinks down')]
