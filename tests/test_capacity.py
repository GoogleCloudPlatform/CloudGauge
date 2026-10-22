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
"""The capacity checks (v17, ``app.checks.capacity``): reservations, future reservations and commitments as a
briefing; reservation coverage; commitments about to end; stockout and quota signals from Cloud Logging. Plus the
quota check's v17 shape (``app.checks.operations``): the accelerator family, two thresholds, headroom, and the quota
recommender."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import httplib2
import pytest
from google.api_core import exceptions as core_exceptions
from google.cloud import recommender_v1
from googleapiclient.errors import HttpError

from app.checks import capacity, operations
from app.checks.capacity import (
    COMMITMENTS_BRIEFING,
    COVERAGE_CHECK,
    EXPIRING_CHECK,
    SIGNALS_CHECK,
    check_capacity_commitments,
    check_capacity_signals,
    classify_signal,
    coverage_rows,
    describe_instances,
    describe_resources,
    expiring_row,
    machine_type_vcpus,
    signal_of,
    signals_filter,
)
from app.checks.not_checked import NOT_CHECKED
from app.checks.operations import (
    QUOTA_RECOMMENDATIONS_CHECK,
    check_quota_recommendations,
    quota_family,
    quota_row,
    run_service_limit_checks_refactored,
)
from fakes import _execute
from helpers import set_env

JOB = 'job-17'
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
ZONE = 'us-central1-a'


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_name(self):
        return {name: record for name, record in self.records}

    def not_checked(self):
        return [(record['Category'], row) for _, record in self.records if record['Check'] == NOT_CHECKED for row in record['Finding']]


@pytest.fixture
def frozen_clock(monkeypatch):
    monkeypatch.setattr(capacity, 'utcnow', lambda: NOW)


# --- the rules ---

@pytest.mark.parametrize('machine_type, vcpus', [
    ('n2-standard-8', 8), ('https://www.googleapis.com/compute/v1/projects/p/zones/z/machineTypes/e2-standard-4', 4),
    ('e2-medium', 2), ('f1-micro', 1), ('n2-custom-4-16384', 4), ('custom-6-20480', 6), ('a2-highgpu-1g', 12), ('a3-highgpu-8g', 208),
    ('g2-standard-12', 12), ('c3-highmem-176', 176), ('mystery', None), ('', None), (None, None),
])
def test_machine_type_vcpus(machine_type, vcpus):
    assert machine_type_vcpus(machine_type) == vcpus


def test_resources_and_instances_are_described_for_a_reader():
    assert describe_resources([{'type': 'VCPU', 'amount': '16'}, {'type': 'MEMORY', 'amount': '65536'},
                               {'type': 'ACCELERATOR', 'amount': '2', 'acceleratorType': '.../acceleratorTypes/nvidia-tesla-t4'}]) == \
        '16 vCPU, 64 GB, 2 nvidia-tesla-t4'
    assert describe_resources([{'type': 'LOCAL_SSD', 'amount': '1'}]) == '1 local_ssd' and describe_resources(None) == ''
    assert describe_instances(4, {'machineType': 'e2-medium'}) == '4 × e2-medium'
    assert describe_instances(2, {'machineType': 'a2-highgpu-1g', 'guestAccelerators': [{'acceleratorType': 'nvidia-tesla-a100', 'acceleratorCount': 1}]}) == \
        '2 × a2-highgpu-1g (2 × nvidia-tesla-a100)'


def commitment(name, days_left, status='ACTIVE', auto_renew=False):
    end = (NOW + __import__('datetime').timedelta(days=days_left)).strftime('%Y-%m-%dT%H:%M:%S.000-00:00')
    return {'name': name, 'plan': 'TWELVE_MONTH', 'status': status, 'autoRenew': auto_renew, 'endTimestamp': end,
            'resources': [{'type': 'VCPU', 'amount': '8'}, {'type': 'MEMORY', 'amount': '32768'}]}


def test_commitments_expiring_within_the_window_that_do_not_renew():
    row = expiring_row('p1', 'us-central1', commitment('cud-a', 45), NOW)
    assert (row['Commitment'], row['Region'], row['Plan'], row['Resources'], row['Days Left']) == ('cud-a', 'us-central1', 'TWELVE_MONTH', '8 vCPU, 32 GB', 45)
    assert row['Ends'] == '2026-12-06' and row['Issue'].startswith('Ends in 45 days and does not renew')
    assert row['Fix'] == 'gcloud compute commitments update cud-a --project=p1 --region=us-central1 --auto-renew'
    assert expiring_row('p1', 'r', commitment('far', 200), NOW) is None
    assert expiring_row('p1', 'r', commitment('renews', 10, auto_renew=True), NOW) is None
    assert expiring_row('p1', 'r', commitment('over', -3), NOW) is None  # already ended: not expiring, expired
    assert expiring_row('p1', 'r', commitment('pending', 10, status='NOT_YET_ACTIVE'), NOW) is None
    assert expiring_row('p1', 'r', {'name': 'odd', 'status': 'ACTIVE'}, NOW) is None  # no end: nothing to count down
    assert expiring_row('p1', 'r', commitment('today', 0), NOW)['Days Left'] == 0


def instance(machine_type, status='RUNNING'):
    return {'name': f'vm-{machine_type}', 'status': status, 'machineType': f'https://www.googleapis.com/compute/v1/projects/p/zones/{ZONE}/machineTypes/{machine_type}'}


def test_reservation_coverage_rows_name_the_zone_and_the_most_common_machine_type():
    instances = [(ZONE, instance('n2-standard-16')), (ZONE, instance('n2-standard-16')), (ZONE, instance('e2-medium')),
                 (ZONE, instance('n2-standard-16', status='TERMINATED')), ('us-east1-b', instance('n2-standard-8'))]
    rows = coverage_rows('p1', instances, reserved={ZONE: 16}, minimum=32)
    assert [(r['Zone'], r['Running vCPUs'], r['Reserved vCPUs']) for r in rows] == [(ZONE, 34, 16)]  # the terminated VM is not running
    assert rows[0]['Fix'] == ('gcloud compute reservations create p1-us-central1-a-reserved --project=p1 --zone=us-central1-a '
                              '--vm-count=2 --machine-type=n2-standard-16 --require-specific-reservation')
    assert coverage_rows('p1', instances, reserved={ZONE: 34}, minimum=32) == []  # covered
    assert coverage_rows('p1', instances, reserved={}, minimum=40) == []  # below the minimum
    assert [r['Zone'] for r in coverage_rows('p1', instances, reserved={}, minimum=8)] == ['us-central1-a', 'us-east1-b']


def entry(message, zone=ZONE, machine_type='n2-standard-8', timestamp='2026-10-20T10:00:00Z', reason=None, accelerator=None):
    request = {'machineType': f'.../machineTypes/{machine_type}'} if machine_type else {}
    if accelerator:
        request['guestAccelerators'] = [{'acceleratorType': f'.../acceleratorTypes/{accelerator}', 'acceleratorCount': 1}]
    payload = {'methodName': 'v1.compute.instances.insert', 'status': {'message': message}, 'request': request,
               'resourceName': f'projects/p1/zones/{zone}/instances/vm-new'}
    if reason:
        payload['response'] = {'error': {'errors': [{'reason': reason}]}}
    return {'timestamp': timestamp, 'resource': {'type': 'gce_instance', 'labels': {'zone': zone}}, 'protoPayload': payload}


def test_signals_are_classified_and_described():
    assert classify_signal("ZONE_RESOURCE_POOL_EXHAUSTED: The zone 'us-central1-a' does not have enough resources") == 'Stockout'
    assert classify_signal('QUOTA_EXCEEDED: Quota CPUS exceeded.') == 'Quota' and classify_signal('Invalid value') is None
    assert signal_of(entry('ZONE_RESOURCE_POOL_EXHAUSTED', accelerator='nvidia-tesla-t4')) == (ZONE, 'nvidia-tesla-t4', 'Stockout', '2026-10-20T10:00:00Z')
    assert signal_of(entry('Quota exceeded', reason='quotaExceeded')) == (ZONE, 'n2-standard-8', 'Quota', '2026-10-20T10:00:00Z')
    assert signal_of(entry('Something else', reason='quotaExceeded'))[2] == 'Quota'  # the response's reason counts too
    assert signal_of(entry('Permission denied')) is None
    no_zone = entry('QUOTA_EXCEEDED', machine_type=None)
    no_zone['resource']['labels'] = {}
    assert signal_of(no_zone) == (ZONE, 'instances', 'Quota', '2026-10-20T10:00:00Z')  # the zone from the resource name, the kind from the method
    assert 'timestamp >= "2026-09-22T12:00:00Z"' in signals_filter('2026-09-22T12:00:00Z') and 'ZONE_RESOURCE_POOL_EXHAUSTED' in signals_filter('x')


# --- the checks against the Compute Engine and Logging APIs ---

class FakeCompute:
    """``compute v1``: the four aggregated listings, one page each, per project (``data[project][collection]``)."""

    def __init__(self, data):
        self.data = data  # project -> {collection: {scope key: [items]}} or an exception
        self.calls = []

    def __getattr__(self, collection):
        if collection.startswith('_'):
            raise AttributeError(collection)
        key = {'reservations': 'reservations', 'futureReservations': 'futureReservations', 'regionCommitments': 'commitments', 'instances': 'instances'}[collection]
        fake = self

        def aggregated_list(project, **kwargs):
            fake.calls.append((collection, project, kwargs))
            answer = fake.data.get(project, {})
            if isinstance(answer, Exception):
                return _execute(answer)
            return _execute({'items': {scope: {key: items} for scope, items in answer.get(collection, {}).items()}})

        return lambda: SimpleNamespace(aggregatedList=aggregated_list, aggregatedList_next=lambda previous_request, previous_response: None)


def denied(message='denied'):
    return HttpError(httplib2.Response({'status': 403, 'reason': message}), json.dumps({'error': {'code': 403, 'message': message}}).encode(), uri='x')


COMPUTE = {
    'web-prod': {
        'reservations': {f'zones/{ZONE}': [{'name': 'web-reserved', 'status': 'READY', 'specificReservation': {
            'count': '2', 'inUseCount': '2', 'instanceProperties': {'machineType': 'n2-standard-16'}}}]},
        'futureReservations': {'zones/us-east1-b': [{'name': 'gpu-2027', 'status': {'procurementStatus': 'APPROVED'},
                                                     'timeWindow': {'startTime': '2027-01-01T00:00:00Z', 'endTime': '2027-12-31T00:00:00Z'},
                                                     'specificSkuProperties': {'totalCount': '8', 'instanceProperties': {'machineType': 'a2-highgpu-1g'}}}]},
        'regionCommitments': {'regions/us-central1': [commitment('web-cud', 30), commitment('web-cud-long', 300)]},
        'instances': {f'zones/{ZONE}': [instance('n2-standard-16')] * 3 + [instance('e2-medium')], 'zones/us-east1-b': [instance('n2-standard-8')]},
    },
    'quiet': {'instances': {f'zones/{ZONE}': [instance('e2-medium')]}},
    'locked': denied('no compute.reservations.list'),
}


def test_capacity_commitments_write_the_briefing_the_coverage_and_the_expiring_commitments(gcp, frozen_clock, monkeypatch):
    set_env(monkeypatch, {'RESERVATION_COVERAGE_MIN_VCPUS': '32'})
    fake = FakeCompute(COMPUTE)
    gcp.discovery.apis['compute'] = fake
    sink = Sink()
    check_capacity_commitments('123', [{'projectId': p} for p in ('web-prod', 'quiet', 'locked')], JOB, sink=sink)
    records = sink.by_name()
    assert list(records) == ['Capacity_Commitments', 'Reservation_Coverage', 'NOT_CHECKED_Reservation_Coverage', 'Commitments_Expiring',
                             'NOT_CHECKED_Commitments_Expiring']
    briefing = records['Capacity_Commitments']
    assert (briefing['Check'], briefing['Status']) == (COMMITMENTS_BRIEFING, 'Informational')
    assert [(r['Kind'], r['Name'], r['Location'], r['Resources'], r['In Use'], r['Status'], r['Ends']) for r in briefing['Finding']] == [
        ('Reservation', 'web-reserved', ZONE, '2 × n2-standard-16', '2', 'READY', ''),
        ('Future reservation', 'gpu-2027', 'us-east1-b', '8 × a2-highgpu-1g', '', 'APPROVED', '2027-01-01 → 2027-12-31'),
        ('Commitment', 'web-cud', 'us-central1', '8 vCPU, 32 GB', '', 'ACTIVE', '2026-11-21'),
        ('Commitment', 'web-cud-long', 'us-central1', '8 vCPU, 32 GB', '', 'ACTIVE', '2027-08-18'),
    ]
    # 3 × 16 + 2 = 50 vCPUs run in the zone, 32 are reserved: a row; us-east1-b runs 8, under the minimum.
    coverage = records['Reservation_Coverage']
    assert (coverage['Check'], coverage['Status']) == (COVERAGE_CHECK, 'Investigation Recommended')
    assert [(r['Project'], r['Zone'], r['Running vCPUs'], r['Reserved vCPUs']) for r in coverage['Finding']] == [('web-prod', ZONE, 50, 32)]
    expiring = records['Commitments_Expiring']
    assert (expiring['Check'], expiring['Status']) == (EXPIRING_CHECK, 'Investigation Recommended')
    assert [(r['Commitment'], r['Days Left']) for r in expiring['Finding']] == [('web-cud', 30)]
    # The project the API refused is on the not-checked rows of both scored checks, in their categories.
    assert sink.not_checked() == [
        ('Reliability & Resilience', {'Project': 'locked', 'Skipped check': COVERAGE_CHECK, 'Reason': '403 no compute.reservations.list'}),
        ('Cost Optimization', {'Project': 'locked', 'Skipped check': EXPIRING_CHECK, 'Reason': '403 no compute.reservations.list'}),
    ]
    assert [call[:2] for call in fake.calls][:4] == [('reservations', 'web-prod'), ('futureReservations', 'web-prod'), ('regionCommitments', 'web-prod'), ('instances', 'web-prod')]
    assert fake.calls[3][2] == {'filter': 'status = "RUNNING"'}


def test_capacity_commitments_all_clear(gcp, frozen_clock):
    gcp.discovery.apis['compute'] = FakeCompute({'quiet': COMPUTE['quiet']})
    sink = Sink()
    check_capacity_commitments('123', [{'projectId': 'quiet'}], JOB, sink=sink)
    records = sink.by_name()
    assert records['Capacity_Commitments']['Finding'] == [{'Summary': 'No reservations, future reservations or commitments in the scanned projects.'}]
    assert records['Reservation_Coverage'] == {'Check': COVERAGE_CHECK, 'Status': 'Compliant',
                                               'Finding': [{'Status': 'No project runs 32 or more vCPUs in a zone without reservations covering them.'}]}
    assert records['Commitments_Expiring'] == {'Check': EXPIRING_CHECK, 'Status': 'Compliant',
                                               'Finding': [{'Status': 'No commitment ends within the next 90 days without renewing.'}]}


class FakeLogging:
    """``logging v2``: ``entries().list(body=...)``, answered per project from ``body['resourceNames']``."""

    def __init__(self, entries):
        self.data = entries  # project -> entries, or an exception; a (entries, next token) pair pages
        self.bodies = []

    def entries(self):
        def list_entries(body):
            self.bodies.append(body)
            project = body['resourceNames'][0].split('/', 1)[1]
            answer = self.data.get(project, [])
            if isinstance(answer, Exception):
                return _execute(answer)
            if isinstance(answer, tuple):
                return _execute({'entries': answer[0], 'nextPageToken': answer[1]})
            return _execute({'entries': answer})
        return SimpleNamespace(list=list_entries)


def test_capacity_signals_group_the_log_entries_by_zone_resource_and_kind(gcp, frozen_clock):
    gcp.discovery.apis['logging'] = FakeLogging({
        'web-prod': [entry('ZONE_RESOURCE_POOL_EXHAUSTED', timestamp='2026-10-21T08:00:00Z'), entry('ZONE_RESOURCE_POOL_EXHAUSTED', timestamp='2026-10-19T08:00:00Z'),
                     entry('QUOTA_EXCEEDED', zone='us-east1-b', machine_type='e2-medium', timestamp='2026-10-01T08:00:00Z'), entry('Permission denied')],
        'ml': ([entry('ZONE_RESOURCE_POOL_EXHAUSTED', accelerator='nvidia-tesla-a100', timestamp='2026-10-10T00:00:00Z')], 'more'),
        'quiet': [],
        'locked': denied('no logging.logEntries.list'),
    })
    sink = Sink()
    check_capacity_signals('123', [{'projectId': p} for p in ('web-prod', 'ml', 'quiet', 'locked')], JOB, sink=sink)
    record = sink.by_name()['Capacity_Signals']
    assert (record['Check'], record['Status']) == (SIGNALS_CHECK, 'Action Required')  # a signal younger than 7 days
    assert [(r['Project'], r['Zone'], r['Resource'], r['Signal'], r['Events'], r['Last Seen']) for r in record['Finding']] == [
        ('web-prod', ZONE, 'n2-standard-8', 'Stockout', 2, '2026-10-21 08:00 UTC'),
        ('web-prod', 'us-east1-b', 'e2-medium', 'Quota', 1, '2026-10-01 08:00 UTC'),
        ('ml', ZONE, 'nvidia-tesla-a100', 'Stockout', '1+', '2026-10-10 00:00 UTC'),  # a full page: at least this many
    ]
    assert record['Finding'][0]['Issue'] == 'Compute Engine could not find capacity for n2-standard-8 in us-central1-a, last 1 days ago.'
    assert record['Finding'][1]['Issue'] == 'the project hit a quota for e2-medium in us-east1-b, last 21 days ago.'
    assert sink.not_checked() == [('Reliability & Resilience', {'Project': 'locked', 'Skipped check': SIGNALS_CHECK, 'Reason': '403 no logging.logEntries.list'})]
    body = gcp.discovery.apis['logging'].bodies[0]
    assert body['resourceNames'] == ['projects/web-prod'] and body['orderBy'] == 'timestamp desc' and body['pageSize'] == 500
    assert body['filter'].startswith('timestamp >= "2026-09-22T12:00:00Z" AND (')


def test_capacity_signals_older_than_a_week_are_investigation_and_none_is_compliant(gcp, frozen_clock):
    gcp.discovery.apis['logging'] = FakeLogging({'web-prod': [entry('QUOTA_EXCEEDED', timestamp='2026-10-10T00:00:00Z')]})
    sink = Sink()
    check_capacity_signals('123', [{'projectId': 'web-prod'}], JOB, sink=sink)
    assert sink.by_name()['Capacity_Signals']['Status'] == 'Investigation Recommended'
    gcp.discovery.apis['logging'] = FakeLogging({'web-prod': []})
    sink = Sink()
    check_capacity_signals('123', [{'projectId': 'web-prod'}], JOB, sink=sink)
    assert sink.by_name()['Capacity_Signals'] == {'Check': SIGNALS_CHECK, 'Status': 'Compliant',
                                                  'Finding': [{'Status': 'No stockout or quota errors in Compute Engine operations in the last 30 days.'}]}


# --- Quota Utilization (>80%) in its v17 shape, and the quota recommender ---

def test_quota_rows_carry_family_headroom_and_a_severity():
    assert quota_family('NVIDIA_T4_GPUS') == 'Accelerator' and quota_family('PREEMPTIBLE_NVIDIA_L4_GPUS') == 'Accelerator'
    assert quota_family('TPUS_PER_PROJECT') == 'Accelerator' and quota_family('CPUS') == 'Compute' and quota_family('IN_USE_ADDRESSES') == 'Compute'
    assert quota_row('p', 'r', {'metric': 'CPUS', 'usage': 80.0, 'limit': 100.0}) is None  # over 80 %, as the name says
    warn = quota_row('p', 'r', {'metric': 'CPUS', 'usage': 81.0, 'limit': 100.0})
    assert warn == {'Project': 'p', 'Region': 'r', 'Metric': 'CPUS', 'Family': 'Compute', 'Usage': '81.0%', 'Details': '81/100', 'Headroom': 19,
                    '_status': 'Investigation Recommended'}
    critical = quota_row('p', 'r', {'metric': 'NVIDIA_T4_GPUS', 'usage': 19.0, 'limit': 20.0})
    assert (critical['Family'], critical['Usage'], critical['Headroom'], critical['_status']) == ('Accelerator', '95.0%', 1, 'Action Required')
    assert quota_row('p', 'r', {'metric': 'CPUS', 'usage': 5.0, 'limit': 0.0}) is None


class FakeQuotaCompute:
    def __init__(self, quotas):
        self.quotas = quotas  # project -> {region: [quota dicts]} or an exception

    def regions(self):
        fake = self

        def list_regions(project):
            answer = fake.quotas.get(project, {})
            return _execute(answer if isinstance(answer, Exception) else {'items': [{'name': region} for region in answer]})

        def get_region(project, region):
            return _execute({'name': region, 'quotas': fake.quotas[project][region]})
        return SimpleNamespace(list=list_regions, get=get_region)


def test_quota_check_is_action_required_only_over_the_critical_threshold(gcp):
    gcp.discovery.apis['compute'] = FakeQuotaCompute({
        'web-prod': {'us-central1': [{'metric': 'CPUS', 'usage': 85.0, 'limit': 100.0}, {'metric': 'DISKS_TOTAL_GB', 'usage': 10.0, 'limit': 100.0}]},
        'ml': {'us-central1': [{'metric': 'NVIDIA_T4_GPUS', 'usage': 4.0, 'limit': 4.0}]},
    })
    sink = Sink()
    run_service_limit_checks_refactored('123', [{'projectId': 'web-prod'}, {'projectId': 'ml'}], JOB, sink=sink)
    record = sink.by_name()['Quota_Utilization']
    assert record['Status'] == 'Action Required'
    assert [(r['Project'], r['Metric'], r['Family'], r['Usage'], r['Headroom']) for r in record['Finding']] == [
        ('web-prod', 'CPUS', 'Compute', '85.0%', 15), ('ml', 'NVIDIA_T4_GPUS', 'Accelerator', '100.0%', 0)]
    assert all('_status' not in row for row in record['Finding'])
    sink = Sink()
    run_service_limit_checks_refactored('123', [{'projectId': 'web-prod'}], JOB, sink=sink)
    assert sink.by_name()['Quota_Utilization']['Status'] == 'Investigation Recommended'
    gcp.discovery.apis['compute'] = FakeQuotaCompute({'web-prod': {'us-central1': [{'metric': 'CPUS', 'usage': 1.0, 'limit': 100.0}]}})
    sink = Sink()
    run_service_limit_checks_refactored('123', [{'projectId': 'web-prod'}], JOB, sink=sink)
    assert sink.by_name()['Quota_Utilization']['Finding'] == [{'Status': 'No quotas found over 80% utilization.'}]


def test_quota_recommendations(gcp):
    gcp.recommender.recommendations[operations.QUOTA_RECOMMENDER] = [
        recommender_v1.Recommendation({'name': 'r', 'description': 'Increase the CPUS quota in us-central1 from 100 to 200.',
                                       'content': {'overview': {'serviceName': 'compute.googleapis.com', 'quotaName': 'CPUS',
                                                                'metric': 'compute.googleapis.com/cpus', 'currentLimit': 100}}}),
        # The real recommender's shape for a lifetime quota: a float limit, no dimensions; and one with no overview at all.
        recommender_v1.Recommendation({'name': 's', 'description': 'Recent quota utilization was near the limit.',
                                       'content': {'overview': {'serviceName': 'sqladmin.googleapis.com', 'metric': 'sqladmin.googleapis.com/free_trial',
                                                                'currentLimit': 1.0}}}),
        recommender_v1.Recommendation({'name': 't', 'description': 'A bare recommendation.'})]
    gcp.recommender.project_errors['locked'] = core_exceptions.PermissionDenied('denied')
    gcp.recommender.project_errors['odd'] = core_exceptions.InvalidArgument('not offered')  # a request error: not a skipped project
    sink = Sink()
    check_quota_recommendations('123', [{'projectId': p} for p in ('web-prod', 'locked', 'odd')], JOB, sink=sink)
    record = sink.by_name()['Quota_Increase_Recommendations']
    assert (record['Check'], record['Status']) == (QUOTA_RECOMMENDATIONS_CHECK, 'Investigation Recommended')
    # The service, the quota (its name, or the metric when it has none) and the current limit come from the overview.
    assert record['Finding'] == [
        {'Project': 'web-prod', 'Service': 'compute.googleapis.com', 'Quota': 'CPUS', 'Current Limit': '100',
         'Recommendation': 'Increase the CPUS quota in us-central1 from 100 to 200.'},
        {'Project': 'web-prod', 'Service': 'sqladmin.googleapis.com', 'Quota': 'sqladmin.googleapis.com/free_trial', 'Current Limit': '1',
         'Recommendation': 'Recent quota utilization was near the limit.'},
        {'Project': 'web-prod', 'Service': 'unknown', 'Quota': 'unknown', 'Current Limit': 'unknown', 'Recommendation': 'A bare recommendation.'}]
    assert sink.not_checked() == [('Operational Excellence & Observability', {'Project': 'locked', 'Skipped check': QUOTA_RECOMMENDATIONS_CHECK, 'Reason': '403 denied'})]
    assert gcp.recommender.parents[0] == f'projects/web-prod/locations/global/recommenders/{operations.QUOTA_RECOMMENDER}'
    gcp.recommender.recommendations.clear()
    sink = Sink()
    check_quota_recommendations('123', [{'projectId': 'web-prod'}], JOB, sink=sink)
    assert sink.by_name()['Quota_Increase_Recommendations']['Finding'] == [{'Status': 'No quota increase recommendations.'}]
