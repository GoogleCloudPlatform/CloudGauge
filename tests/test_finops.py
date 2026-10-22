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
"""The FinOps checks (v17, ``app.checks.cost``): the six new recommenders' locations, cost-allocation labels,
storage lifecycle, snapshot sprawl — and the settings behind them, and the Scorecard's savings tally."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from google.api_core import exceptions as core_exceptions

from app.checks import cost
from app.checks.cost import (
    BIGQUERY_MULTI_REGIONS,
    COST_RECOMMENDERS,
    LABELS_CHECK,
    LIFECYCLE_CHECK,
    SNAPSHOT_SPRAWL_CHECK,
    bucket_tiers_or_expires,
    check_cost_allocation_labels,
    check_snapshot_sprawl,
    check_storage_lifecycle,
    disk_path,
    label_fix,
    location_bound_recommenders,
    missing_labels,
    recommender_locations,
    snapshot_issues,
)
from app.checks.not_checked import NOT_CHECKED
from app.reporting.html_report import generate_html_report
from app.reporting.scorecard import savings_text
from fakes import _execute
from helpers import make_settings, set_env

JOB = 'job-17'
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_name(self):
        return {name: record for name, record in self.records}

    def not_checked(self):
        return [row for _, record in self.records if record['Check'] == NOT_CHECKED for row in record['Finding']]


# --- settings ---

def test_the_finops_settings_have_defaults_and_are_validated():
    settings = make_settings()
    assert (settings.cost_allocation_labels, settings.snapshot_max_age_days, settings.reservation_coverage_min_vcpus) == ((), 90, 32)
    assert settings.bigquery_dataset is None and settings.bigquery_export_wait_seconds == 60
    settings = make_settings(COST_ALLOCATION_LABELS=' Cost-Center, environment,owner ,cost-center', SNAPSHOT_MAX_AGE_DAYS='30',
                             RESERVATION_COVERAGE_MIN_VCPUS='8', BIGQUERY_DATASET='cloudgauge', BIGQUERY_EXPORT_WAIT_SECONDS='0')
    assert settings.cost_allocation_labels == ('cost-center', 'environment', 'owner')  # lower-cased, de-duplicated, in order
    assert (settings.snapshot_max_age_days, settings.reservation_coverage_min_vcpus) == (30, 8)
    assert settings.bigquery_dataset == 'cloudgauge' and settings.bigquery_export_wait_seconds == 0
    for name, value in (('COST_ALLOCATION_LABELS', 'Cost Center'), ('COST_ALLOCATION_LABELS', '9lives'), ('SNAPSHOT_MAX_AGE_DAYS', '0'),
                        ('RESERVATION_COVERAGE_MIN_VCPUS', 'many'), ('BIGQUERY_DATASET', 'my-dataset'), ('BIGQUERY_DATASET', 'a.b'),
                        ('BIGQUERY_EXPORT_WAIT_SECONDS', '601')):
        with pytest.raises(ValueError, match=name):
            make_settings(**{name: value})


# --- the recommenders' locations ---

def test_recommenders_are_asked_where_they_live():
    zones, regions = ['us-central1-a', 'global'], ['us-central1', 'asia-south1', 'global']
    assert recommender_locations('zone', zones, regions) == ['us-central1-a']
    assert recommender_locations('region', zones, regions) == ['us-central1', 'asia-south1']
    assert recommender_locations('global', zones, regions) == ['global']
    assert recommender_locations('bigquery', zones, regions) == ['US', 'EU', 'us-central1', 'asia-south1']
    assert recommender_locations('global', [], []) == ['global'] and recommender_locations('bigquery', [], []) == list(BIGQUERY_MULTI_REGIONS)
    assert len(COST_RECOMMENDERS) == 14 and len(location_bound_recommenders()) == 11
    assert [name for name in COST_RECOMMENDERS if name not in location_bound_recommenders()] == \
        ['BigQuery Slot Commitments', 'Idle Images', 'Cloud Storage Soft Delete']
    assert COST_RECOMMENDERS['Resource-Based Commitment Recommendations'] == ('google.compute.commitment.UsageCommitmentRecommender', 'region')
    assert COST_RECOMMENDERS['Idle Images'] == ('google.compute.image.IdleResourceRecommender', 'global')


# --- Cost Allocation Labels ---

def test_missing_labels_and_the_fix():
    assert missing_labels({'cost-center': 'cc-1', 'owner': ' '}, ('cost-center', 'environment', 'owner')) == ['environment', 'owner']
    assert missing_labels(None, ('owner',)) == ['owner'] and missing_labels({'owner': 'x'}, ('owner',)) == []
    assert label_fix('p1', ['environment', 'owner']) == 'gcloud projects update p1 --update-labels=environment=<value>,owner=<value>'


class FakeResourceManagerLabels:
    def __init__(self, labels):
        self.labels = labels  # project id -> labels dict, or an exception

    def projects(self):
        def get(projectId):
            answer = self.labels.get(projectId, {})
            return _execute(answer if isinstance(answer, Exception) else {'projectId': projectId, 'labels': answer})
        return SimpleNamespace(get=get)


def test_labels_check_is_informational_until_configured(gcp, monkeypatch):
    set_env(monkeypatch, {})  # no COST_ALLOCATION_LABELS
    sink = Sink()
    check_cost_allocation_labels('123', [{'projectId': 'p1'}], JOB, sink=sink)
    ((name, record),) = sink.records
    assert record['Status'] == 'Informational' and record['Check'] == LABELS_CHECK
    assert record['Finding'][0]['Summary'].startswith('Not configured: set COST_ALLOCATION_LABELS')
    assert gcp.discovery.calls == []  # nothing was read


def test_labels_check_lists_projects_missing_a_key(gcp, monkeypatch):
    set_env(monkeypatch, {'COST_ALLOCATION_LABELS': 'cost-center,environment,owner'})
    gcp.discovery.apis['cloudresourcemanager'] = FakeResourceManagerLabels({
        'web-prod': {'cost-center': 'cc-1', 'environment': 'prod', 'owner': 'web'},
        'data-lake': {'cost-center': 'cc-2'},
        'locked': core_exceptions.PermissionDenied('denied'),
    })
    sink = Sink()
    check_cost_allocation_labels('123', [{'projectId': p} for p in ('web-prod', 'data-lake', 'locked')], JOB, sink=sink)
    record = sink.by_name()['Cost_Allocation_Labels']
    assert record['Status'] == 'Action Required'
    assert record['Finding'] == [{'Project': 'data-lake', 'Missing Labels': 'environment, owner',
                                  'Fix': 'gcloud projects update data-lake --update-labels=environment=<value>,owner=<value>'}]
    assert sink.not_checked() == [{'Project': 'locked', 'Skipped check': LABELS_CHECK, 'Reason': '403 denied'}]
    # Every project labelled: Compliant with the keys named.
    gcp.discovery.apis['cloudresourcemanager'] = FakeResourceManagerLabels({'web-prod': {'cost-center': '1', 'environment': '2', 'owner': '3'}})
    sink = Sink()
    check_cost_allocation_labels('123', [{'projectId': 'web-prod'}], JOB, sink=sink)
    assert sink.by_name()['Cost_Allocation_Labels']['Finding'] == [{'Status': 'Every project carries the cost-allocation labels cost-center, environment, owner.'}]


# --- Cloud Storage Lifecycle ---

def bucket(name, rules=(), autoclass=False, storage_class='STANDARD'):
    return SimpleNamespace(name=name, lifecycle_rules=list(rules), autoclass_enabled=autoclass, storage_class=storage_class)


def test_a_bucket_tiers_or_expires_with_a_rule_or_autoclass():
    assert bucket_tiers_or_expires(bucket('a', rules=[{'action': {'type': 'Delete'}}]))
    assert bucket_tiers_or_expires(bucket('b', autoclass=True))
    assert not bucket_tiers_or_expires(bucket('c'))
    assert not bucket_tiers_or_expires(SimpleNamespace(name='d'))  # neither attribute: nothing configured
    generator = SimpleNamespace(name='e', lifecycle_rules=(rule for rule in [{'x': 1}]), autoclass_enabled=False)
    assert bucket_tiers_or_expires(generator)  # google-cloud-storage exposes the rules as a generator


def test_lifecycle_check_lists_buckets_that_never_tier_or_expire(gcp):
    gcp.storage.listings.update({
        'web-prod': [bucket('web-assets'), bucket('web-logs', rules=[{'action': {'type': 'Delete'}, 'condition': {'age': 30}}]), bucket('web-archive', autoclass=True)],
        'data-lake': [bucket('lake-raw', storage_class='NEARLINE')],
        'locked': core_exceptions.PermissionDenied('denied'),
    })
    sink = Sink()
    check_storage_lifecycle('123', [{'projectId': p} for p in ('web-prod', 'data-lake', 'locked')], JOB, sink=sink)
    record = sink.by_name()['Cloud_Storage_Lifecycle']
    assert (record['Check'], record['Status']) == (LIFECYCLE_CHECK, 'Investigation Recommended')
    assert [(r['Project'], r['Bucket'], r['Storage Class'], r['Fix']) for r in record['Finding']] == [
        ('web-prod', 'web-assets', 'STANDARD', 'gcloud storage buckets update gs://web-assets --enable-autoclass'),
        ('data-lake', 'lake-raw', 'NEARLINE', 'gcloud storage buckets update gs://lake-raw --enable-autoclass')]
    assert record['Finding'][0]['Issue'] == 'No lifecycle rules and Autoclass off: objects never move to a colder storage class or expire.'
    assert sink.not_checked() == [{'Project': 'locked', 'Skipped check': LIFECYCLE_CHECK, 'Reason': '403 denied'}]
    gcp.storage.listings.update({'web-prod': [bucket('web-archive', autoclass=True)]})
    sink = Sink()
    check_storage_lifecycle('123', [{'projectId': 'web-prod'}], JOB, sink=sink)
    assert sink.by_name()['Cloud_Storage_Lifecycle'] == {'Check': LIFECYCLE_CHECK, 'Status': 'Compliant',
                                                         'Finding': [{'Status': 'Every bucket has lifecycle rules or Autoclass.'}]}


# --- Snapshot Sprawl ---

DISK = 'https://www.googleapis.com/compute/v1/projects/web-prod/zones/us-central1-a/disks/web-1'


def test_snapshot_issues_age_and_orphans():
    disks = {'web-prod/zones/us-central1-a/disks/web-1'}
    assert disk_path(DISK) == 'web-prod/zones/us-central1-a/disks/web-1'
    assert disk_path('projects/p/zones/z/disks/d') == 'p/zones/z/disks/d' and disk_path('') == ''
    fresh = {'creationTimestamp': '2026-10-01T00:00:00.000-07:00', 'sourceDisk': DISK}
    assert snapshot_issues(fresh, disks, NOW, 90) == (21, [])
    old = {'creationTimestamp': '2026-01-01T00:00:00Z', 'sourceDisk': DISK}
    assert snapshot_issues(old, disks, NOW, 90) == (294, ['Older than 90 days.'])
    orphan = {'creationTimestamp': '2026-10-01T00:00:00Z', 'sourceDisk': DISK.replace('web-1', 'gone')}
    assert snapshot_issues(orphan, disks, NOW, 90) == (21, ['Source disk no longer exists.'])
    both = {'creationTimestamp': '2025-01-01T00:00:00Z', 'sourceDisk': ''}
    assert snapshot_issues(both, disks, NOW, 90) == (659, ['Older than 90 days.', 'Source disk no longer exists.'])
    assert snapshot_issues({'creationTimestamp': 'yesterday', 'sourceDisk': DISK}, disks, NOW, 90) == (None, [])


@pytest.fixture
def frozen_clock(monkeypatch):
    monkeypatch.setattr(cost, 'utcnow', lambda: NOW)


def test_snapshot_sprawl_lists_old_and_orphaned_snapshots_oldest_first(gcp, frozen_clock, monkeypatch):
    set_env(monkeypatch, {'SNAPSHOT_MAX_AGE_DAYS': '60'})
    for project, name, created, source, size in (('web-prod', 'nightly', '2026-10-20T00:00:00Z', DISK, '50'),
                                                 ('web-prod', 'q1-baseline', '2026-03-01T00:00:00Z', DISK, '200'),
                                                 ('data-lake', 'orphan', '2026-10-01T00:00:00Z', DISK.replace('web-1', 'gone'), '50'),
                                                 ('data-lake', 'ancient', '2024-01-01T00:00:00Z', '', '50')):
        gcp.assets.add_asset('compute.googleapis.com/Snapshot', f'//compute.googleapis.com/projects/{project}/global/snapshots/{name}',
                             {'name': name, 'creationTimestamp': created, 'sourceDisk': source, 'diskSizeGb': size})
    gcp.assets.add_asset('compute.googleapis.com/Disk', '//compute.googleapis.com/projects/web-prod/zones/us-central1-a/disks/web-1',
                         {'name': 'web-1', 'selfLink': DISK})
    sink = Sink()
    check_snapshot_sprawl('organization', '987654321', JOB, sink=sink)
    ((name, record),) = sink.records
    assert (name, record['Check'], record['Status']) == ('Snapshot_Sprawl', SNAPSHOT_SPRAWL_CHECK, 'Investigation Recommended')
    assert [(r['Project'], r['Snapshot'], r['Age (days)'], r['Size (GB)'], r['Issue']) for r in record['Finding']] == [
        ('data-lake', 'ancient', 1025, '50', 'Older than 60 days. Source disk no longer exists.'),
        ('web-prod', 'q1-baseline', 235, '200', 'Older than 60 days.'),
        ('data-lake', 'orphan', 21, '50', 'Source disk no longer exists.'),
    ]
    assert record['Finding'][1]['Fix'] == 'gcloud compute snapshots delete q1-baseline --project=web-prod'
    assert [request['parent'] for request in gcp.assets.list_requests] == ['organizations/987654321', 'organizations/987654321']


def test_snapshot_sprawl_all_clear_and_a_failed_listing(gcp, frozen_clock):
    gcp.assets.add_asset('compute.googleapis.com/Snapshot', '//compute.googleapis.com/projects/web-prod/global/snapshots/nightly',
                         {'name': 'nightly', 'creationTimestamp': '2026-10-20T00:00:00Z', 'sourceDisk': DISK})
    gcp.assets.add_asset('compute.googleapis.com/Disk', '//compute.googleapis.com/projects/web-prod/zones/us-central1-a/disks/web-1',
                         {'name': 'web-1', 'selfLink': DISK})
    sink = Sink()
    check_snapshot_sprawl('project', 'web-prod', JOB, sink=sink)
    assert sink.by_name()['Snapshot_Sprawl'] == {'Check': SNAPSHOT_SPRAWL_CHECK, 'Status': 'Compliant',
                                                 'Finding': [{'Status': 'No snapshots older than 90 days or without a source disk found.'}]}
    assert gcp.assets.list_requests[-1]['parent'] == 'projects/web-prod'
    gcp.assets.list_errors['compute.googleapis.com/Disk'] = core_exceptions.PermissionDenied('no cloudasset.assets.listResource')
    sink = Sink()
    check_snapshot_sprawl('folder', '42', JOB, sink=sink)
    assert sink.by_name()['Snapshot_Sprawl'] == {'Check': SNAPSHOT_SPRAWL_CHECK, 'Status': 'Error',
                                                 'Finding': [{'Error': '403 no cloudasset.assets.listResource'}]}


# --- The Scorecard's savings tally (B2) ---

def test_the_efficiency_stoplight_sums_the_estimated_monthly_savings():
    results = {'Cost Optimization': [
        {'Check': 'Idle Persistent Disks', 'Status': 'Action Required', 'Finding': [
            {'Project': 'a', 'Resource Name': 'd1', 'Recommendation': 'Delete.', 'Est. Monthly Saving': '1,200.50 USD'},
            {'Project': 'b', 'Resource Name': 'd2', 'Recommendation': 'Delete.', 'Est. Monthly Saving': 'N/A'}]},
        {'Check': 'BigQuery Slot Commitments', 'Status': 'Action Required', 'Finding': [
            {'Project': 'c', 'Resource Name': 'US', 'Recommendation': 'Buy.', 'Est. Monthly Saving': '300.00 EUR'}]},
        {'Check': 'VM Rightsizing', 'Status': 'Compliant', 'Finding': [{'Status': 'No VM rightsizing recommendations found.'}]},
    ]}
    html = generate_html_report('organization', '123', JOB, **results)
    assert '300.00 EUR + 1,200.50 USD/month in identified savings' in html
    assert generate_html_report('organization', '123', JOB, **{'Cost Optimization': results['Cost Optimization'][2:]}).count('identified savings') == 0
    assert savings_text(SimpleNamespace(checks=[])) is None
