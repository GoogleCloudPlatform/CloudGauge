"""Incident Exposure (v17.3): the customer's assets without failover in a location where the product they run had an
incident - derived at categorization from the Service Health briefing and the resilience checks' rows.

Two sides and a join: tested here are the matching rules (product, project, location, global), the asset-centric
rows and their fixes, the three statuses and the note, and the derivation through ``categorize_findings`` - the one
path both a sharded and an inline scan take - including the briefing's Error becoming this check's and the
shards' incident rows folding before the join.
"""
import pytest

from app.checks import categories, exposure
from app.checks.categories import categorize_findings, merge_shard_findings
from app.checks.exposure import (INCIDENT_EXPOSURE_CHECK, INCIDENTS_CHECK, exposure_rows, footprint_rows, incident_label, location_matches,
                                 mapped_checks, with_incident_exposure)
from app.checks.service_health import INCIDENTS_CHECK as BRIEFING

RELIABILITY = 'Reliability & Resilience'
# Every region Personalized Service Health enumerates for a product-wide event (40 here: past GLOBAL_REGION_COUNT).
GLOBAL = ', '.join(f'{c}-{n}{i}' for c in ('us', 'europe', 'asia', 'australia') for n in ('east', 'west', 'north', 'south', 'central') for i in (1, 2))


def incident(incident_id, products, locations, projects, started='2026-10-13 14:19', relevance='Related'):
    return {categories.INCIDENT_STATE: 'Resolved', categories.INCIDENT_STARTED: started, 'Ended': '2026-10-13 17:35', 'Incident': f'Incident {incident_id}',
            'Products': products, 'Locations': locations, categories.INCIDENT_PROJECT_COUNT: len(projects.split(',')),
            categories.INCIDENT_PROJECTS: projects, categories.INCIDENT_RELEVANCE: relevance,
            categories.INCIDENT_SCOPE: categories.scope_of(locations),
            categories.INCIDENT_ID: incident_id}


def record(check, rows, status='Action Required'):
    return {'Check': check, 'Status': status, 'Finding': rows}


SQL = record('Cloud SQL High Availability', [{'Project': 'p1', 'Instance': 'aura-db', 'Region': 'asia-south1'},
                                             {'Project': 'p2', 'Instance': 'eu-db', 'Region': 'europe-west1'}])
MIGS = record('MIG Resilience (Zonal)', [{'Project': 'p1', 'MIG Name': 'dws-ig', 'Zone': 'asia-south1-c'},
                                         {'Project': 'p3', 'MIG Name': 'other-ig', 'Zone': 'asia-south1-a'}])
SNAPSHOTS = record('Disk Snapshot Resilience', [{'Project': 'p1', 'Snapshot': f'snap-{i}', 'Location': 'asia-south1'} for i in range(12)]
                   + [{'Project': 'p1', 'Snapshot': 'us-snap', 'Location': 'us-central1'}])
GKE = record('GKE Cluster Resilience', [
    {'Project': 'p1', 'Cluster': 'c1', 'Location': 'asia-south1-a', 'Node Pool': '(control plane)', 'Issue': 'Zonal control plane',
     'Fix': 'A zonal control plane cannot be made regional in place: create a regional cluster (gcloud container clusters create c1 --region=asia-south1 ...) and migrate the workloads.'},
    {'Project': 'p1', 'Cluster': 'c1', 'Location': 'asia-south1-a', 'Node Pool': 'pool-a', 'Issue': 'Single-zone node pool (asia-south1-a)',
     'Fix': 'gcloud container node-pools update pool-a --cluster=c1 --location=asia-south1-a --project=p1 --node-locations=asia-south1-a,asia-south1-b,asia-south1-c'}])
FOOTPRINT = [SQL, MIGS, SNAPSHOTS, GKE]
GCE_GKE = incident('A', 'Google Compute Engine, Google Kubernetes Engine', 'asia-south1, asia-south1-a, australia-southeast1, europe-west1', 'p1, p2')
CLOUD_SQL = incident('B', 'Google Cloud SQL', 'asia-south1', 'p1', started='2026-09-23 03:00')
NLB = incident('C', 'Cloud Load Balancing', 'asia-south1', 'p1', started='2026-08-27 10:00')
GLOBAL_GCE = incident('D', 'Google Compute Engine', GLOBAL, 'p1, p2, p3')


# --- the matching rules ---

def test_products_map_to_the_footprint_they_meet():
    assert mapped_checks('Google Compute Engine, Google Kubernetes Engine') == ['MIG Resilience (Zonal)', 'Disk Snapshot Resilience', 'GKE Cluster Resilience']
    assert mapped_checks('Persistent Disk') == ['MIG Resilience (Zonal)', 'Disk Snapshot Resilience']
    assert mapped_checks('Google Cloud SQL') == ['Cloud SQL High Availability'] == mapped_checks('Cloud SQL')  # the synthetic world's name too
    assert mapped_checks('Cloud Load Balancing, Google BigQuery, Cloud Run') == [] == mapped_checks('')


def test_a_zone_counts_for_its_region_on_both_sides():
    assert location_matches('asia-south1, europe-west1', 'asia-south1-c')  # the incident names the region, the asset is in one of its zones
    assert location_matches('asia-south1-a', 'asia-south1-c')  # the incident names a zone: its region had trouble
    assert location_matches('asia-south1-a', 'asia-south1')  # a regional location (a snapshot's, an instance's) in the incident's region
    assert not location_matches('asia-south1', 'asia-south2') and not location_matches('asia-south1', 'us-central1-a')
    assert not location_matches('asia-south1', '') and not location_matches('', 'asia-south1')


def test_global_and_unlocated_incidents_are_never_matched_nor_assessed():
    rows, assessed, unmapped = exposure_rows([GLOBAL_GCE], footprint_rows(FOOTPRINT))
    assert rows == [] and assessed == 0 and unmapped == []
    unlocated = incident('U', 'Google Compute Engine', '', 'p1, p2, p3')  # PSH gave no location: nothing to meet, nothing assessed
    rows, assessed, unmapped = exposure_rows([unlocated], footprint_rows(FOOTPRINT))
    assert rows == [] and assessed == 0 and unmapped == [] and unlocated[categories.INCIDENT_SCOPE] == 'No location'
    assert categories.is_global_incident(GLOBAL) and categories.regions_of(GLOBAL)[:2] == ['us-east1', 'us-east2']
    assert not categories.is_global_incident('asia-south1, asia-south1-a, asia-south1-b') and categories.regions_of('us, eu, asia-south1-a') == ['asia-south1']


def test_the_label_names_the_date_the_products_and_the_place():
    assert incident_label(GCE_GKE) == '2026-10-13 Google Compute Engine, Google Kubernetes Engine (3 regions)'
    assert incident_label(CLOUD_SQL) == '2026-09-23 Google Cloud SQL (asia-south1)'
    assert incident_label({**NLB, 'Locations': ''}) == '2026-08-27 Cloud Load Balancing (no location)'


# --- the rows ---

def test_rows_are_one_per_asset_with_the_incidents_as_evidence():
    rows, assessed, unmapped = exposure_rows([GCE_GKE, CLOUD_SQL, NLB, GLOBAL_GCE], footprint_rows(FOOTPRINT))
    assert assessed == 2 and [i[categories.INCIDENT_ID] for i in unmapped] == ['C']
    assert [(r['Project'], r['Asset'], r['Location']) for r in rows] == [  # by project, location, asset
        ('p1', '12 single-region snapshots', 'asia-south1'),
        ('p1', 'zonal Cloud SQL instance aura-db', 'asia-south1'),
        ('p1', 'cluster c1 (single-zone node pool (asia-south1-a))', 'asia-south1-a'),
        ('p1', 'cluster c1 (zonal control plane)', 'asia-south1-a'),
        ('p1', 'zonal MIG dws-ig', 'asia-south1-c'),
    ]
    # p3's MIG is in a matching zone but the incident did not touch p3; the us-central1 snapshot is not in a matching location;
    # p2's instance is in a region the Compute Engine incident touched, but a Compute Engine incident meets MIGs and snapshots, not
    # Cloud SQL instances (and the Cloud SQL incident did not touch p2).
    by_asset = {r['Asset']: r for r in rows}
    assert by_asset['zonal Cloud SQL instance aura-db']['Incidents'] == '2026-09-23 Google Cloud SQL (asia-south1)'
    assert by_asset['zonal MIG dws-ig']['Incidents'] == '2026-10-13 Google Compute Engine, Google Kubernetes Engine (3 regions)'
    assert by_asset['12 single-region snapshots']['Incidents'] == by_asset['zonal MIG dws-ig']['Incidents']


def test_the_cloud_sql_incident_meets_instances_only_and_the_compute_incident_never_meets_them():
    rows, _, _ = exposure_rows([CLOUD_SQL], footprint_rows(FOOTPRINT))
    assert [r['Asset'] for r in rows] == ['zonal Cloud SQL instance aura-db']
    rows, _, _ = exposure_rows([GCE_GKE], footprint_rows(FOOTPRINT))
    assert 'zonal Cloud SQL instance aura-db' not in [r['Asset'] for r in rows] and 'zonal Cloud SQL instance eu-db' not in [r['Asset'] for r in rows]


def test_fixes_are_the_owning_checks_or_the_mechanical_ones():
    rows, _, _ = exposure_rows([GCE_GKE, CLOUD_SQL], footprint_rows(FOOTPRINT))
    fixes = {r['Asset']: r['Fix'] for r in rows}
    assert fixes['zonal Cloud SQL instance aura-db'] == 'gcloud sql instances patch aura-db --project=p1 --availability-type=REGIONAL'
    assert fixes['zonal MIG dws-ig'].startswith('Recreate dws-ig as a regional MIG: gcloud compute instance-groups managed create dws-ig --project=p1 --region=asia-south1')
    assert fixes['12 single-region snapshots'].startswith('Store new snapshots in a multi-region: --storage-location=asia, eu or us')
    assert fixes['cluster c1 (zonal control plane)'] == GKE['Finding'][0]['Fix']  # the owning check knows it
    assert fixes['cluster c1 (single-zone node pool (asia-south1-a))'] == GKE['Finding'][1]['Fix']


def test_many_incidents_on_one_asset_are_listed_up_to_five():
    incidents = [incident(f'I{i}', 'Google Cloud SQL', 'asia-south1', 'p1', started=f'2026-09-{10 + i:02d} 00:00') for i in range(7)]
    rows, assessed, _ = exposure_rows(incidents, footprint_rows([SQL]))
    assert assessed == 7 and len(rows) == 1
    assert rows[0]['Incidents'].count(';') == 5 and rows[0]['Incidents'].endswith('; and 2 more')


# --- the record ---

def test_the_record_is_action_required_with_rows_and_carries_the_note(monkeypatch):
    monkeypatch.setenv('SERVICE_HEALTH_WINDOW_DAYS', '60')
    findings = with_incident_exposure([record(BRIEFING, [GCE_GKE, NLB], 'Informational'), *FOOTPRINT])
    exposure_record = findings[-1]
    assert exposure_record['Check'] == INCIDENT_EXPOSURE_CHECK == INCIDENTS_CHECK.replace('Service Health Incidents', 'Incident Exposure')
    assert exposure_record['Status'] == 'Action Required' and len(exposure_record['Finding']) == 4  # snapshots, pool, control plane, MIG; no Cloud SQL incident
    assert exposure_record[categories.NOTE_KEY] == ('1 location-specific incident in products this check has no footprint for (Cloud Load Balancing) '
                                                    'is listed under Service Health Incidents.')
    assert BRIEFING == INCIDENTS_CHECK  # the literal in app.checks.exposure is the briefing's name


def test_compliant_when_incidents_met_footprints_with_failover_and_informational_when_none_did(monkeypatch):
    monkeypatch.setenv('SERVICE_HEALTH_WINDOW_DAYS', '90')
    # A Cloud SQL incident in a region where the only zonal instance is somewhere else: assessed, nothing exposed.
    [*_, clear] = with_incident_exposure([record(BRIEFING, [incident('B', 'Google Cloud SQL', 'us-west1', 'p1')], 'Informational'), SQL])
    assert clear['Status'] == 'Compliant' and clear['Finding'] == [{'Status': '1 location-specific incident in Compute Engine, Persistent Disk, '
                                                                             'Google Kubernetes Engine or Cloud SQL touched the scanned projects in the '
                                                                             'last 90 days; every asset there had failover.'}]
    assert categories.NOTE_KEY not in clear
    # Only global incidents and unmapped products: nothing to assess.
    [*_, quiet] = with_incident_exposure([record(BRIEFING, [GLOBAL_GCE, NLB], 'Informational'), *FOOTPRINT])
    assert quiet['Status'] == 'Informational'
    assert quiet['Finding'][0]['Summary'].startswith('No location-specific incident in Compute Engine, Persistent Disk, Google Kubernetes Engine or Cloud SQL '
                                                     'touched the scanned projects in the last 90 days: nothing to assess.')
    assert quiet[categories.NOTE_KEY].startswith('1 location-specific incident in products this check has no footprint for (Cloud Load Balancing)')
    # An empty briefing (its note row only) is nothing to assess either.
    [*_, empty] = with_incident_exposure([record(BRIEFING, [{'Summary': 'No Google Cloud incidents ...'}], 'Informational'), *FOOTPRINT])
    assert empty['Status'] == 'Informational' and categories.NOTE_KEY not in empty


def test_no_briefing_no_record_and_the_briefings_error_is_this_checks_error():
    assert with_incident_exposure(FOOTPRINT) == FOOTPRINT  # SERVICE_HEALTH_INCIDENTS=off, or an older scan: the check does not exist
    [*_, error] = with_incident_exposure([{'Check': BRIEFING, 'Status': 'Error', 'Finding': [{'Error': '403 Enable the Service Health API'}]}, *FOOTPRINT])
    assert error == {'Check': INCIDENT_EXPOSURE_CHECK, 'Status': 'Error', 'Finding': [{'Error': '403 Enable the Service Health API'}]}
    once = with_incident_exposure([record(BRIEFING, [CLOUD_SQL], 'Informational'), SQL])
    assert with_incident_exposure(once) == once  # idempotent


def test_categorize_findings_derives_the_record_for_both_scan_paths():
    # Inline scan: one record per check.
    results = categorize_findings([record(BRIEFING, [CLOUD_SQL], 'Informational'), SQL])
    names = [r['Check'] for r in results[RELIABILITY]]
    assert names == [BRIEFING, 'Cloud SQL High Availability', INCIDENT_EXPOSURE_CHECK]
    assert results[RELIABILITY][-1]['Status'] == 'Action Required'
    # Sharded scan: the shards' incident rows fold first (one incident, both projects), the footprint rows join, then the derivation.
    shard_a = {**record(BRIEFING, [incident('B', 'Google Cloud SQL', 'asia-south1', 'p1')], 'Informational'), categories.OMITTED_KEY: ['G']}
    shard_b = {**record(BRIEFING, [incident('B', 'Google Cloud SQL', 'asia-south1', 'p4')], 'Informational'), categories.OMITTED_KEY: ['G']}
    sql_b = record('Cloud SQL High Availability', [{'Project': 'p4', 'Instance': 'p4-db', 'Region': 'asia-south1'}])
    results = categorize_findings(merge_shard_findings([shard_a, SQL, shard_b, sql_b]))
    by_name = {r['Check']: r for r in results[RELIABILITY]}
    assert by_name[BRIEFING]['Finding'][0][categories.INCIDENT_PROJECTS] == 'p1, p4'
    assert by_name[BRIEFING][categories.NOTE_KEY].startswith('1 Related incident without a specific location (global, or none given) is not listed')
    assert [(r['Project'], r['Asset']) for r in by_name[INCIDENT_EXPOSURE_CHECK]['Finding']] == [
        ('p1', 'zonal Cloud SQL instance aura-db'), ('p4', 'zonal Cloud SQL instance p4-db')]


@pytest.mark.parametrize('check', ['Cloud SQL High Availability', 'MIG Resilience (Zonal)'])
def test_the_footprint_columns_are_the_reliability_checks_own(check):
    """The join reads the columns ``app.checks.reliability`` writes (v17.3 added Region and Zone); the all-clear row is not a footprint."""
    name_column, location_column = exposure.FOOTPRINT[check][1:]
    assert footprint_rows([record(check, [{'Status': 'No zonal ... found.'}], 'Compliant')])[check] == []
    assert footprint_rows([SQL, MIGS])[check][0][location_column]
    assert name_column in ('Instance', 'MIG Name') and location_column in ('Region', 'Zone')
