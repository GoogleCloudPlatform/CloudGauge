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
"""Resilience of Critical Assets (v15.6): the three Asset Inventory listings run under the scanned scope,
each of the six check names ends the scan with a verdict, and a failed listing is reported under the names
it served. Before v15.6 the check was organization-only, wrote rows only when it found something, and
reported any failure under a seventh name ("Resilience Asset Checks"). v16.1: Disk Snapshot Resilience
reads the kind of a snapshot's storage location (a multi-region passes) instead of counting locations."""
import pytest
from google.api_core.exceptions import PermissionDenied
from google.cloud import asset_v1

import fakes
from app.checks.categories import CATEGORY_MAP
from app.checks.reliability import (
    MIG_RESILIENCE_CHECK, MULTI_REGIONS, RESILIENCE_CHECKS, RESILIENCE_NOTHING_FOUND, SNAPSHOT_RESILIENCE_CHECK,
    SQL_RESILIENCE_CHECKS, check_resilience_assets, is_single_region,
)
from app.services import gcp as gcp_clients

JOB_ID = 'job-1'
SQL = 'sqladmin.googleapis.com/Instance'
MIG = 'compute.googleapis.com/InstanceGroupManager'
SNAPSHOT = 'compute.googleapis.com/Snapshot'
RETIRED_ERROR_NAME = 'Resilience Asset Checks'


class Sink:
    def __init__(self):
        self.findings = []

    def write_finding(self, job_id, slug, finding):
        self.findings.append((job_id, slug, finding))

    @property
    def by_check(self):
        return {finding['Check']: finding for _, _, finding in self.findings}


def sql_instance(project, name, *, zonal=False, backups=True, pitr=True, retained=30):
    settings = {'availabilityType': 'ZONAL' if zonal else 'REGIONAL',
                'backupConfiguration': {'enabled': backups, 'pointInTimeRecoveryEnabled': pitr, 'retainedBackupsCount': retained}}
    return SQL, f'//cloudsql.googleapis.com/projects/{project}/instances/{name}', {'name': name, 'settings': settings}


def mig(project, name, *, zone=None, region='us-central1'):
    place, data = (f'zones/{zone}', {'name': name, 'zone': zone}) if zone else (f'regions/{region}', {'name': name, 'region': region})
    return MIG, f'//compute.googleapis.com/projects/{project}/{place}/instanceGroupManagers/{name}', data


def snapshot(project, name, locations):
    return SNAPSHOT, f'//compute.googleapis.com/projects/{project}/global/snapshots/{name}', {'name': name, 'storageLocations': list(locations)}


def run(scope='organization', scope_id=fakes.ORG_ID):
    sink = Sink()
    check_resilience_assets(scope, scope_id, JOB_ID, sink=sink)
    return sink


def snapshot_rows(sink):
    return [(r['Project'], r['Snapshot']) for r in sink.by_check[SNAPSHOT_RESILIENCE_CHECK]['Finding']]


@pytest.mark.parametrize('scope, scope_id, parent', [
    ('organization', fakes.ORG_ID, f'organizations/{fakes.ORG_ID}'),
    ('folder', '42', 'folders/42'),
    ('project', 'web-prod', 'projects/web-prod'),
])
def test_the_listings_run_under_the_scanned_scope(scope, scope_id, parent, gcp):
    run(scope, scope_id)
    assert [r['parent'] for r in gcp.assets.list_requests] == [parent] * 3
    assert [r['asset_types'] for r in gcp.assets.list_requests] == [[SQL], [MIG], [SNAPSHOT]]
    assert {r['content_type'] for r in gcp.assets.list_requests} == {asset_v1.ContentType.RESOURCE}


@pytest.mark.parametrize('scope, scope_id', [('organization', fakes.ORG_ID), ('folder', '42'), ('project', 'web-prod')])
def test_nothing_found_is_a_compliant_row_per_check(scope, scope_id, gcp):
    """The listings answered and flagged nothing: six verdicts, so Stability counts them (an empty folder included)."""
    sink = run(scope, scope_id)
    assert [finding['Check'] for _, _, finding in sink.findings] == list(RESILIENCE_CHECKS)
    assert [slug for _, slug, _ in sink.findings] == [check.replace(' ', '_') for check in RESILIENCE_CHECKS]
    for _, _, finding in sink.findings:
        assert finding['Status'] == 'Compliant'
        assert finding['Finding'] == [{'Status': RESILIENCE_NOTHING_FOUND[finding['Check']]}]
    assert RESILIENCE_NOTHING_FOUND['Disk Snapshot Resilience'] == 'No single-region disk snapshots found.'
    assert RESILIENCE_NOTHING_FOUND['Cloud SQL Backup Retention'] == 'No Cloud SQL instances retaining fewer than 30 backups found.'


def test_findings_keep_their_rows_and_name_each_snapshot(gcp):
    for asset in (sql_instance('p1', 'db-a', zonal=True, backups=False, retained=7),  # no backups: no PITR row either
                  sql_instance('p1', 'db-b', pitr=False),
                  sql_instance('p2', 'db-c'),
                  mig('p1', 'web-mig', zone='us-central1-a'), mig('p1', 'gke-pool-1', zone='us-central1-a'), mig('p2', 'api-mig'),
                  snapshot('p1', 'nightly', ['us-central1']), snapshot('p2', 'weekly', ['us', 'eu']), snapshot('p2', 'orphan', [])):
        gcp.assets.add_asset(*asset)
    checks = run().by_check
    assert {name: f['Status'] for name, f in checks.items()} == {check: 'Action Required' for check in RESILIENCE_CHECKS}
    assert checks['Cloud SQL High Availability']['Finding'] == [{'Project': 'p1', 'Instance': 'db-a'}]
    assert checks['Cloud SQL Automated Backups']['Finding'] == [{'Project': 'p1', 'Instance': 'db-a'}]
    assert checks['Cloud SQL Backup Retention']['Finding'] == [{'Project': 'p1', 'Instance': 'db-a', 'Retention': 7}]
    assert checks['Cloud SQL PITR']['Finding'] == [{'Project': 'p1', 'Instance': 'db-b'}]
    assert checks[MIG_RESILIENCE_CHECK]['Finding'] == [{'Project': 'p1', 'MIG Name': 'web-mig'}]
    # v15.6: one row per single-region snapshot (a count row before), so the report and the action plan name it.
    # v16.1: 'weekly' is absent because its location is a multi-region (until then: because it listed two).
    assert checks[SNAPSHOT_RESILIENCE_CHECK]['Finding'] == [{'Project': 'p1', 'Snapshot': 'nightly', 'Location': 'us-central1'},
                                                            {'Project': 'p2', 'Snapshot': 'orphan', 'Location': 'unknown'}]


# --- v16.1: the kind of the storage location decides, not the count ---

@pytest.mark.parametrize('locations', [['asia'], ['us'], ['eu'], ['ASIA'], ['us', 'eu'], ['europe-west1', 'eu']])
def test_a_snapshot_in_a_multi_region_is_resilient(locations, gcp):
    """A snapshot has one storage location — a region or a multi-region — so counting them flagged every snapshot
    (an organization's 56 of 56, all in ``asia``, during the v15.6 rollout). A multi-region is geo-redundant."""
    assert is_single_region(locations) is False
    gcp.assets.add_asset(*snapshot('p1', 'nightly', locations))
    finding = run().by_check[SNAPSHOT_RESILIENCE_CHECK]
    assert (finding['Status'], finding['Finding']) == ('Compliant', [{'Status': 'No single-region disk snapshots found.'}])


@pytest.mark.parametrize('locations, shown', [(['asia-south1'], 'asia-south1'), (['us-central1'], 'us-central1'),
                                              (['europe-west1'], 'europe-west1'), ([], 'unknown'), (None, 'unknown')])
def test_a_snapshot_in_a_single_region_is_flagged_with_its_location(locations, shown, gcp):
    """A region is flagged as before; no location at all (it should not occur) is read conservatively, as before."""
    assert is_single_region(locations) is True
    asset_type, name, data = snapshot('p1', 'nightly', locations or [])
    if locations is None:
        del data['storageLocations']
    gcp.assets.add_asset(asset_type, name, data)
    finding = run().by_check[SNAPSHOT_RESILIENCE_CHECK]
    assert (finding['Status'], finding['Finding']) == ('Action Required', [{'Project': 'p1', 'Snapshot': 'nightly', 'Location': shown}])


def test_the_multi_regions_are_the_three_compute_engine_offers():
    assert MULTI_REGIONS == ('asia', 'eu', 'us')


def test_a_folder_or_project_scan_sees_only_its_own_assets(gcp):
    """The finding this release was born from: a snapshot in a folder's project that the folder scan could not
    see while the listing ran under the organization."""
    gcp.assets.add_asset(*snapshot('p1', 'nightly', ['us-central1']), folder='42')
    gcp.assets.add_asset(*snapshot('p2', 'nightly', ['europe-west1']))
    assert snapshot_rows(run('organization', fakes.ORG_ID)) == [('p1', 'nightly'), ('p2', 'nightly')]
    assert snapshot_rows(run('folder', '42')) == [('p1', 'nightly')]
    assert snapshot_rows(run('project', 'p2')) == [('p2', 'nightly')]
    assert run('folder', '7').by_check[SNAPSHOT_RESILIENCE_CHECK]['Status'] == 'Compliant'


@pytest.mark.parametrize('failing, affected', [
    (SQL, SQL_RESILIENCE_CHECKS),
    (MIG, (MIG_RESILIENCE_CHECK,)),
    (SNAPSHOT, (SNAPSHOT_RESILIENCE_CHECK,)),
])
def test_a_failed_listing_is_an_error_under_the_names_it_served(failing, affected, gcp):
    """Coverage, not a verdict: the report says these could not be checked; the other listings still reach a verdict."""
    gcp.assets.list_errors[failing] = PermissionDenied('cloudasset.assets.listResource')
    gcp.assets.add_asset(*mig('p1', 'web-mig', zone='us-central1-a'))
    checks = run('project', 'p1').by_check
    assert set(checks) == set(RESILIENCE_CHECKS) and RETIRED_ERROR_NAME not in checks
    for check in affected:
        assert checks[check] == {'Check': check, 'Finding': [{'Error': '403 cloudasset.assets.listResource'}], 'Status': 'Error'}
    for check in set(RESILIENCE_CHECKS) - set(affected):
        assert checks[check]['Status'] == ('Action Required' if check == MIG_RESILIENCE_CHECK else 'Compliant')


def test_a_credentials_failure_is_an_error_under_every_name(gcp, monkeypatch):
    def no_credentials(**kwargs):
        raise RuntimeError('no credentials')

    monkeypatch.setattr(gcp_clients, 'auth_default', no_credentials)
    checks = run().by_check
    assert set(checks) == set(RESILIENCE_CHECKS)
    assert all(f == {'Check': name, 'Finding': [{'Error': 'no credentials'}], 'Status': 'Error'} for name, f in checks.items())
    assert gcp.assets.list_requests == []


def test_every_resilience_name_is_a_stability_check():
    """The runner's error name (the registry's) and the six names the check writes all land on the Stability page;
    the all-clear table covers exactly the six (test_category_consistency reads the table through DYNAMIC_NAMES)."""
    assert set(RESILIENCE_NOTHING_FOUND) == set(RESILIENCE_CHECKS) and len(RESILIENCE_CHECKS) == 6
    for name in RESILIENCE_CHECKS + ('Resilience of Critical Assets',):
        assert CATEGORY_MAP[name] == 'Reliability & Resilience', name
    assert RETIRED_ERROR_NAME not in CATEGORY_MAP
