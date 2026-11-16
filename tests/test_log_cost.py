"""
v18.8 — Forecasts, budgets and spend, the log levers: the rules of ``app.checks.log_cost`` on fixture buckets, subnets, sinks and byte-count series,
and the check end to end with every read failing on its own.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

from google.api_core import exceptions as core_exceptions
from googleapiclient.errors import HttpError

from app.checks import log_cost
from app.checks.log_cost import (GIB, LOG_COST_CHECK, bucket_rows, check_log_cost, debug_excluded, debug_rows, flow_log_rows, severity_volume, volume_request)
from app.checks.not_checked import NOT_CHECKED
from fakes import _execute

JOB = 'job-189'
NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
P = 'stark-logs-prod'


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


def bucket(name, days, location='global', locked=False, state='ACTIVE'):
    return {'name': f'projects/{P}/locations/{location}/buckets/{name}', 'retentionDays': days, 'locked': locked, 'lifecycleState': state}


def subnet(name, region='asia-south1', enable=True, sampling=None, metadata=None, interval=None):
    config = {'enable': enable}
    if sampling is not None:
        config['flowSampling'] = sampling
    if metadata:
        config['metadata'] = metadata
    if interval:
        config['aggregationInterval'] = interval
    return {'name': name, 'region': f'https://www.googleapis.com/compute/v1/projects/{P}/regions/{region}', 'logConfig': config, 'enableFlowLogs': enable}


def series(severity, value):
    return {'metric': {'type': 'logging.googleapis.com/byte_count', 'labels': {'severity': severity}}, 'points': [{'value': {'int64Value': str(value)}}]}


# --- rules ---

def test_bucket_rows_name_the_paid_days_and_skip_required_and_short_buckets():
    buckets = [bucket('_Required', 400, locked=True), bucket('_Default', 180), bucket('short', 30), bucket('audit', 400, location='asia-south1', locked=True),
               bucket('gone', 365, state='DELETE_REQUESTED'), {'name': 'odd', 'retentionDays': '45'}]
    rows = bucket_rows(P, buckets)
    assert [(r['Resource'], r['Issue'], r['_status']) for r in rows] == [
        ('log bucket _Default (global)', 'Retention beyond 30 days.', 'Informational'), ('log bucket audit (asia-south1)', 'Retention beyond 30 days.', 'Informational'),
        ('log bucket odd (global)', 'Retention beyond 30 days.', 'Informational')]
    assert rows[0]['Detail'] == 'Keeps 180 days: the 150 beyond the 30 included with ingestion are billed storage, per GiB and month. Keep it where a policy requires the history.'
    assert rows[0]['Fix'] == f'gcloud logging buckets update _Default --location=global --project={P} --retention-days=30'
    assert 'and the bucket is locked' in rows[1]['Detail'] and rows[1]['Fix'].startswith('The bucket is locked: its retention cannot be shortened.')
    assert bucket_rows(P, []) == []


def test_flow_log_rows_flag_sampling_above_half_and_note_the_verbose_settings():
    subnets = [subnet('all-in', sampling=1.0, metadata='INCLUDE_ALL_METADATA', interval='INTERVAL_5_SEC'), subnet('mostly', sampling=0.75), subnet('half', sampling=0.5),
               subnet('default-rate'), subnet('off', enable=False, sampling=1.0), subnet('broken', sampling='x'), {'name': 'legacy', 'enableFlowLogs': True, 'region': 'r'}]
    rows = flow_log_rows(P, subnets)
    assert [(r['Resource'], r['Issue'], r['_status']) for r in rows] == [('subnet all-in (asia-south1)', 'Flow log sampling above 0.5.', 'Investigation Recommended'),
                                                                        ('subnet mostly (asia-south1)', 'Flow log sampling above 0.5.', 'Investigation Recommended')]
    assert rows[0]['Detail'] == 'Samples 100 % of flows (the console default is 50 %; the log volume, and its ingestion bill, scale with the rate), with all metadata, aggregated every 5 seconds.'
    assert rows[0]['Fix'] == (f'gcloud compute networks subnets update all-in --region=asia-south1 --project={P} --logging-flow-sampling=0.5'
                              '  # and --logging-metadata=exclude-all --logging-aggregation-interval=interval-5-min to cut the volume further')
    assert rows[1]['Detail'].startswith('Samples 75 % of flows') and rows[1]['Fix'].endswith('--logging-flow-sampling=0.5')


def test_debug_exclusions_are_read_from_the_default_sink():
    default = {'name': '_Default', 'destination': f'logging.googleapis.com/projects/{P}/locations/global/buckets/_Default'}
    assert not debug_excluded([default, {'name': '_Required', 'exclusions': [{'name': 'x', 'filter': 'severity=DEBUG'}]}])  # _Required's exclusions do not count
    assert debug_excluded([{**default, 'exclusions': [{'name': 'drop-debug', 'filter': 'severity = DEBUG'}]}])
    assert debug_excluded([{**default, 'exclusions': [{'name': 'quiet', 'filter': 'resource.type="k8s_container" AND severity<=DEBUG'}]}])
    assert debug_excluded([{**default, 'exclusions': [{'name': 'quiet', 'filter': 'severity < INFO'}]}])
    assert not debug_excluded([{**default, 'exclusions': [{'name': 'off', 'filter': 'severity=DEBUG', 'disabled': True}]}])
    assert not debug_excluded([{**default, 'exclusions': [{'name': 'other', 'filter': 'severity=INFO'}]}])
    # A custom sink into the _Default bucket counts too.
    assert debug_excluded([{'name': 'projects/p/sinks/mine', 'destination': f'logging.googleapis.com/projects/{P}/locations/global/buckets/_Default',
                            'exclusions': [{'name': 'd', 'filter': 'severity="DEBUG"'}]}])


def test_debug_rows_need_volume_above_the_free_tier_a_tenth_of_it_debug_and_no_exclusion():
    volume = severity_volume([series('DEBUG', 40 * GIB), series('INFO', 50 * GIB), series('ERROR', 30 * GIB), {'metric': {}, 'points': [{'value': {'doubleValue': '1.5'}}]}])
    assert volume == {'DEBUG': 40 * GIB, 'INFO': 50 * GIB, 'ERROR': 30 * GIB, 'DEFAULT': 1}
    rows = debug_rows(P, volume, excluded=False)
    assert len(rows) == 1 and rows[0]['Resource'] == 'log ingestion' and rows[0]['_status'] == 'Investigation Recommended'
    assert rows[0]['Detail'] == 'DEBUG entries were 33 % of the 120.0 GiB ingested in 30 days (the first 50 GiB a month are free, the rest is billed per GiB), and no exclusion on the _Default sink drops them.'
    assert rows[0]['Fix'] == f"gcloud logging sinks update _Default --project={P} --add-exclusion='name=drop-debug,filter=severity=DEBUG'"
    assert debug_rows(P, volume, excluded=True) == []
    assert debug_rows(P, {'DEBUG': 20 * GIB, 'INFO': 20 * GIB}, False) == []  # 40 GiB: under the free tier
    assert debug_rows(P, {'DEBUG': 5 * GIB, 'INFO': 95 * GIB}, False) == []  # 5 %: not a lever
    assert debug_rows(P, {}, False) == []


def test_volume_request_asks_for_thirty_days_summed_by_severity():
    request = volume_request(P, NOW)
    assert request['name'] == f'projects/{P}' and request['filter'] == 'metric.type = "logging.googleapis.com/byte_count"'
    assert (request['interval_startTime'], request['interval_endTime']) == ('2026-10-17T12:00:00Z', '2026-11-16T12:00:00Z')
    assert (request['aggregation_alignmentPeriod'], request['aggregation_perSeriesAligner'], request['aggregation_crossSeriesReducer'], request['aggregation_groupByFields']) == (
        '2592000s', 'ALIGN_SUM', 'REDUCE_SUM', ['metric.label.severity'])


# --- the check ---

class FakeLogging:
    def __init__(self, buckets=(), sinks=(), bucket_error=None, sink_error=None):
        self.buckets_, self.sinks_, self.bucket_error, self.sink_error = list(buckets), list(sinks), bucket_error, sink_error
        self.parents = []

    def projects(self):
        def buckets_list(parent):
            self.parents.append(parent)
            return _execute(self.bucket_error or {'buckets': self.buckets_})

        def sinks_list(parent):
            return _execute(self.sink_error or {'sinks': self.sinks_})
        buckets = SimpleNamespace(list=buckets_list, list_next=lambda previous_request, previous_response: None)
        sinks = SimpleNamespace(list=sinks_list, list_next=lambda previous_request, previous_response: None)
        return SimpleNamespace(locations=lambda: SimpleNamespace(buckets=lambda: buckets), sinks=lambda: sinks)


class FakeCompute:
    def __init__(self, subnets=(), error=None):
        self.subnets_, self.error = list(subnets), error

    def subnetworks(self):
        return SimpleNamespace(aggregatedList=lambda project: _execute(self.error or {'items': {'regions/asia-south1': {'subnetworks': self.subnets_}}}),
                               aggregatedList_next=lambda previous_request, previous_response: None)


class FakeMonitoring:
    def __init__(self, series=(), error=None):
        self.series_, self.error, self.requests = list(series), error, []

    def projects(self):
        def list_(**kwargs):
            self.requests.append(kwargs)
            return _execute(self.error or {'timeSeries': self.series_})
        return SimpleNamespace(timeSeries=lambda: SimpleNamespace(list=list_, list_next=lambda previous_request, previous_response: None))


def http_error(status, message):
    return HttpError(SimpleNamespace(status=status, reason=message), message.encode(), uri='https://x/')


def test_check_writes_one_record_under_the_worst_status(gcp, monkeypatch):
    monkeypatch.setattr(log_cost, 'utcnow', lambda: NOW)
    gcp.discovery.apis['logging'] = FakeLogging(buckets=[bucket('_Required', 400, locked=True), bucket('_Default', 90)],
                                                sinks=[{'name': '_Default', 'destination': f'logging.googleapis.com/projects/{P}/locations/global/buckets/_Default'}])
    gcp.discovery.apis['compute'] = FakeCompute(subnets=[subnet('vm-subnet', sampling=1.0)])
    gcp.discovery.apis['monitoring'] = FakeMonitoring(series=[series('DEBUG', 60 * GIB), series('INFO', 60 * GIB)])
    sink = Sink()
    check_log_cost('org', [{'projectId': P}], JOB, sink=sink)
    record = sink.by_check()[LOG_COST_CHECK]
    assert record['Status'] == 'Investigation Recommended'
    assert [(r['Project'], r['Resource'], r['Issue']) for r in record['Finding']] == [
        (P, 'log bucket _Default (global)', 'Retention beyond 30 days.'), (P, 'subnet vm-subnet (asia-south1)', 'Flow log sampling above 0.5.'), (P, 'log ingestion', 'DEBUG logs ingested at volume.')]
    assert all('_status' not in r for r in record['Finding']) and sink.not_checked() == []
    assert gcp.discovery.apis['logging'].parents == [f'projects/{P}/locations/-']
    assert gcp.discovery.apis['monitoring'].requests[0]['aggregation_groupByFields'] == ['metric.label.severity']
    # Retention rows alone: Informational, outside the score.
    gcp.discovery.apis['compute'] = FakeCompute()
    gcp.discovery.apis['monitoring'] = FakeMonitoring()
    sink = Sink()
    check_log_cost('org', [{'projectId': P}], JOB, sink=sink)
    record = sink.by_check()[LOG_COST_CHECK]
    assert record['Status'] == 'Informational' and len(record['Finding']) == 1
    # Nothing at all: the all-clear row.
    gcp.discovery.apis['logging'] = FakeLogging(buckets=[bucket('_Default', 30)])
    sink = Sink()
    check_log_cost('org', [{'projectId': P}], JOB, sink=sink)
    assert sink.by_check()[LOG_COST_CHECK] == {'Check': LOG_COST_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': log_cost.ALL_CLEAR}]}


def test_check_reports_each_failing_read_under_projects_not_checked(gcp, monkeypatch):
    monkeypatch.setattr(log_cost, 'utcnow', lambda: NOW)
    gcp.discovery.apis['logging'] = FakeLogging(bucket_error=core_exceptions.PermissionDenied('no buckets'), sinks=[])
    gcp.discovery.apis['compute'] = FakeCompute(error=http_error(403, 'Compute Engine API has not been used in project stark-logs-prod before or it is disabled'))
    gcp.discovery.apis['monitoring'] = FakeMonitoring(error=RuntimeError('monitoring down'))
    sink = Sink()
    check_log_cost('org', [{'projectId': P}, {'projectId': 'other'}], JOB, sink=sink)
    assert sink.by_check()[LOG_COST_CHECK]['Status'] == 'Compliant'  # nothing could be judged; the rows below say why
    rows = sink.not_checked()
    assert [(r['Project'], r['Skipped check']) for r in rows] == [(P, f'{LOG_COST_CHECK} (log buckets)'), (P, f'{LOG_COST_CHECK} (log volume by severity)'),
                                                                 ('other', f'{LOG_COST_CHECK} (log buckets)'), ('other', f'{LOG_COST_CHECK} (log volume by severity)')]
    assert rows[0]['Reason'] == '403 no buckets' and rows[1]['Reason'] == 'monitoring down'  # a disabled Compute Engine API: no subnets to read, not a row
    # A failing sink read loses the DEBUG rule only.
    gcp.discovery.apis['logging'] = FakeLogging(buckets=[bucket('_Default', 30)], sink_error=RuntimeError('sinks down'))
    gcp.discovery.apis['compute'] = FakeCompute()
    gcp.discovery.apis['monitoring'] = FakeMonitoring(series=[series('DEBUG', 60 * GIB), series('INFO', 60 * GIB)])
    sink = Sink()
    check_log_cost('org', [{'projectId': P}], JOB, sink=sink)
    assert sink.by_check()[LOG_COST_CHECK]['Status'] == 'Compliant'
    assert [(r['Skipped check'], r['Reason']) for r in sink.not_checked()] == [(f'{LOG_COST_CHECK} (log volume by severity)', 'sinks down')]
