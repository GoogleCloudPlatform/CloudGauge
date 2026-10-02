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
"""The synthetic load mode (``app.synthetic``): settings, the generated
organization, the provider, a full scan against it, and the app in the
``synthetic`` profile.

The scans here run with zero simulated latency, so the whole module takes a
few seconds. The provider is installed in the process-wide seam
(``app.services.gcp``); the ``gcp`` fixture resets it after every test.
"""
import json
import logging

import google.auth.exceptions
import pytest
from google.api_core import exceptions as core_exceptions
from google.cloud import recommender_v1
from googleapiclient.errors import HttpError

import fakes
from app import create_app, scan_job
from app.config import Settings
from app.extensions import EXTENSION_KEY
from app.reporting.html_report import generate_html_report
from app.services import gcp as gcp_clients
from app.synthetic import SyntheticGcp, SyntheticOrg, banner_for, build_provider
from app.synthetic.memory_store import memory_results_store
from app.synthetic.world import FOLDER_IDS, HOST_PROJECT, ORG_ID, REGIONS
from helpers import DEPLOYED_ENV, make_settings, set_env

BANNER_MARK = 'SYNTHETIC LOAD TEST'
SECTION_IDS = ('security-identity', 'cost-optimization', 'reliability-resilience', 'operational-excellence-observability')


def synthetic_settings(**overrides):
    return make_settings('synthetic', **{'SYNTHETIC_PROJECTS': '12', **overrides})


def scan(provider, scope='organization', job_id='syn-job'):
    """Runs one scan job against ``provider`` with an in-memory bucket; returns (ok, store, scope_id)."""
    gcp_clients.install_provider(provider)
    store = memory_results_store()
    world = provider.world
    scope_id = {'organization': world.org_id, 'folder': world.folder_ids[0], 'project': world.project_id(0)}[scope]
    ok = scan_job.execute_scan_job({'scope': scope, 'scope_id': scope_id, 'job_id': job_id},
                                   store=store, banner=banner_for(provider))
    return ok, store, scope_id


# --- Settings ---

def test_synthetic_profile_requires_a_project_count():
    with pytest.raises(ValueError, match='SYNTHETIC_PROJECTS'):
        make_settings('synthetic')
    with pytest.raises(ValueError, match='SYNTHETIC_PROJECTS'):
        make_settings('synthetic', SYNTHETIC_PROJECTS='0')


def test_synthetic_settings_are_read_and_validated():
    settings = synthetic_settings(SYNTHETIC_SEED='7', SYNTHETIC_LATENCY_MS='0', SYNTHETIC_ERROR_RATE='0.05', SYNTHETIC_DENIED_FRACTION='0')
    assert settings.is_synthetic and settings.startup_checks_enabled and not settings.is_production
    assert (settings.synthetic_projects, settings.synthetic_seed, settings.synthetic_latency_ms,
            settings.synthetic_error_rate, settings.synthetic_denied_fraction) == (12, 7, 0.0, 0.05, 0.0)
    for name, value in (('SYNTHETIC_ERROR_RATE', '2'), ('SYNTHETIC_PROJECTS', '-1'), ('SYNTHETIC_LATENCY_MS', 'fast')):
        with pytest.raises(ValueError, match=name):
            synthetic_settings(**{name: value})


def test_production_profile_ignores_synthetic_variables():
    settings = make_settings('production', SYNTHETIC_PROJECTS='500')
    assert settings.is_production and not settings.is_synthetic and settings.startup_checks_enabled
    assert Settings.from_env(dict(DEPLOYED_ENV)).synthetic_projects == 0


# --- The generated organization ---

def test_world_is_deterministic_per_seed():
    a, b = SyntheticOrg(40, seed=7), SyntheticOrg(40, seed=7)
    assert a.projects() == b.projects()
    assert a.projects()[3] == a.project(a.project_id(3))  # cached and rebuilt alike
    other = SyntheticOrg(40, seed=8)
    assert [p.project_id for p in other.projects()] != [p.project_id for p in a.projects()]
    assert [p.vms for p in other.projects()] != [p.vms for p in a.projects()]


def test_world_identity_and_folders():
    org = SyntheticOrg(25, seed=1)
    assert org.org_id == ORG_ID and org.folder_ids == FOLDER_IDS
    assert org.project_id(4) == 'syn-1-00004' and org.index_of('syn-1-00004') == 4
    assert org.project('syn-1-00025') is None and org.project('other') is None and org.project(None) is None
    by_folder = [p.project_id for folder in org.folder_ids for p in org.projects(folder)]
    assert sorted(by_folder) == [p.project_id for p in org.projects()]
    assert org.org_policies(f'organizations/{ORG_ID}') and org.unattended_project_ids() == ['syn-1-00000']


def test_world_denied_fraction():
    assert not any(p.denied for p in SyntheticOrg(200, denied_fraction=0).projects())
    assert all(p.denied for p in SyntheticOrg(50, denied_fraction=1).projects())
    half = sum(p.denied for p in SyntheticOrg(400, denied_fraction=0.5).projects())
    assert 150 < half < 250


# --- The provider ---

def test_denied_and_unknown_projects_raise_like_the_apis(gcp):
    provider = SyntheticGcp(50, latency_ms=0, denied_fraction=1.0)
    denied = provider.world.project_id(0)
    with pytest.raises(core_exceptions.PermissionDenied):
        provider.recommender_client().list_recommendations(parent=f'projects/{denied}/locations/global/recommenders/x')
    with pytest.raises(HttpError) as http_error:
        provider.api_build('compute', 'v1').firewalls().list(project=denied).execute()
    assert http_error.value.resp.status == 403
    with pytest.raises(HttpError) as not_found:
        provider.api_build('compute', 'v1').firewalls().list(project='syn-42-99999').execute()
    assert not_found.value.resp.status == 404
    assert provider.metrics.snapshot()['errors'] == {'recommender:403': 1, 'compute:403': 1, 'compute:404': 1}


def test_injected_quota_errors_and_latency(gcp):
    failing = SyntheticGcp(5, latency_ms=0, error_rate=1.0, denied_fraction=0)
    with pytest.raises(core_exceptions.ResourceExhausted):
        failing.asset_client().list_assets(request={'parent': f'projects/{failing.world.project_id(1)}', 'asset_types': []})
    assert failing.metrics.snapshot()['errors'] == {'asset:429': 1}

    quick = SyntheticGcp(5, latency_ms=0, denied_fraction=0)
    quick.api_build('compute', 'v1').regions().list(project=quick.world.project_id(0)).execute()
    assert quick.metrics.snapshot()['simulated_wait_seconds'] == 0

    slow = SyntheticGcp(5, latency_ms=20, denied_fraction=0)
    slow.api_build('compute', 'v1').regions().list(project=slow.world.project_id(0)).execute()
    assert slow.metrics.snapshot()['simulated_wait_seconds'] > 0


def test_discovery_stub_answers_the_calls_the_checks_make(gcp, caplog):
    provider = SyntheticGcp(5, latency_ms=0, denied_fraction=0)
    compute = provider.api_build('compute', 'v1')
    project = provider.world.project_id(0)
    regions = compute.regions().list(project=project).execute()
    assert [r['name'] for r in regions['items']] == REGIONS
    assert compute.regions().list_next(previous_request=None, previous_response=regions) is None
    assert compute.instances().aggregatedList_next(previous_request=None, previous_response={}) is None
    clusters = provider.api_build('container', 'v1').projects().locations().clusters().list(parent=f'projects/{project}/locations/-').execute()
    assert 'clusters' in clusters  # the project comes from ``parent``
    ancestry = provider.api_build('cloudresourcemanager', 'v1').projects().getAncestry(projectId=DEPLOYED_ENV['PROJECT_ID'], body={}).execute()
    assert ancestry['ancestor'][-1] == {'resourceId': {'type': 'organization', 'id': ORG_ID}}
    with caplog.at_level(logging.WARNING):
        assert compute.disks().list(project=project).execute() == {}
        assert compute.disks().list(project=project).execute() == {}
    assert [r.message for r in caplog.records].count('Synthetic provider: no handler for compute.disks.list; answering {}') == 1
    assert provider.metrics.snapshot()['by_method']['compute.disks.list?'] == 2


def test_infrastructure_calls_pass_through(gcp):
    """The Cloud Run Admin API and credentials are real: only scan data is synthetic."""
    provider = SyntheticGcp(5, latency_ms=0)
    run = provider.api_build('run', 'v1', credentials=gcp.credentials)
    assert gcp.discovery.calls == [('run', 'v1')]  # the library's discovery.build (patched to the fake), not a stub
    assert run.projects().locations().services().get(name='x').execute() == {'status': {'url': fakes.WORKER_URL}}
    assert provider.metrics.snapshot()['total_calls'] == 0
    credentials, project = provider.auth_default(scopes=['s'])
    assert credentials is gcp.credentials and project == HOST_PROJECT
    provider.auth_default(scopes=['s'])
    assert gcp.auth_scopes == [['s']]  # resolved once


def test_without_adc_the_provider_uses_synthetic_credentials(monkeypatch):
    def no_adc(**kwargs):
        raise google.auth.exceptions.DefaultCredentialsError('none')

    monkeypatch.setattr(google.auth, 'default', no_adc)
    credentials, _ = SyntheticGcp(1).auth_default()
    assert credentials.token == 'synthetic-access-token'


def test_recommender_answers_are_real_protos(gcp):
    """network.py calls ``Insight.to_dict`` and cost.py reads ``primary_impact.cost_projection``: dicts won't do."""
    from app.checks.cost import COST_RECOMMENDERS
    from app.checks.network import NETWORK_INSIGHT_TYPES

    provider = SyntheticGcp(60, latency_ms=0, denied_fraction=0)
    client = provider.recommender_client()
    ip_insight, rightsizing = NETWORK_INSIGHT_TYPES['VPC IP Address Utilization'], COST_RECOMMENDERS['VM Rightsizing'][0]
    insights = [i for p in provider.world.projects() for region in {'-'.join(z.split('-')[:-1]) for z in p.zones}
                for i in client.list_insights(parent=f'projects/{p.project_id}/locations/{region}/insightTypes/{ip_insight}')]
    assert insights and all(isinstance(i, recommender_v1.Insight) for i in insights)
    assert recommender_v1.Insight.to_dict(insights[0])['content']['ipUtilizationSummaryInfo']
    recos = [r for p in provider.world.projects() for zone in p.zones
             for r in client.list_recommendations(parent=f'projects/{p.project_id}/locations/{zone}/recommenders/{rightsizing}')]
    assert recos and recos[0].primary_impact.cost_projection.cost.units < 0
    unattended = client.list_recommendations(parent=f'organizations/{ORG_ID}/locations/global/recommenders/google.resourcemanager.projectUtilization.Recommender')
    assert [r.recommender_subtype for r in unattended] == ['CLEANUP_PROJECT', 'CLEANUP_PROJECT']


# --- A whole scan ---

@pytest.mark.parametrize('scope', ['organization', 'folder', 'project'])
def test_scan_completes_against_the_synthetic_organization(gcp, scope):
    provider = SyntheticGcp(12, latency_ms=0, denied_fraction=0)
    ok, store, scope_id = scan(provider, scope)
    assert ok is True
    status = store.read_status('syn-job', scope_id)
    assert (status['status'], status['progress']) == ('completed', 100)
    html = store.read_report('syn-job', scope_id, 'html')
    csv = store.read_report('syn-job', scope_id, 'csv')
    assert BANNER_MARK in html and 'generated organization of 12 projects' in html
    assert 'status-badge">Error<' not in html  # no check crashed on the synthetic answers
    assert 'Category,Policy,Expected Value,Current Value,Status' in csv and csv.count('\n') > 20
    metrics = provider.metrics.snapshot()
    assert metrics['total_calls'] > 50 and metrics['errors'] == {}
    assert store.client.bucket(store.bucket_name).object_names('intermediate/') == []  # cleaned up
    assert store.client.stats()['writes'] > 20


def test_organization_scan_covers_every_section_and_org_check(gcp):
    _, store, scope_id = scan(SyntheticGcp(40, latency_ms=0, denied_fraction=0))
    html = store.read_report('syn-job', scope_id, 'html')
    for section_id in SECTION_IDS:
        assert f'id="{section_id}-section"' in html
    for check in ('Organization Policies', 'Critical Org-Level Roles', 'Security Command Center Status', 'Organization Log Sink',
                  'Essential Contacts', 'MIG Resilience (Zonal)', 'Personalized Service Health', 'Unattended Projects',
                  'VM Rightsizing', 'VPC IP Address Utilization', 'Quota Utilization (&gt;80%)', 'OS Config Agent Coverage'):
        assert check in html, check
    assert 'Action Required' in html and 'Compliant' in html


def test_denied_projects_and_quota_errors_do_not_break_the_scan(gcp):
    """Every project answers 403 and 5% of calls answer 429: the scan still completes with a report."""
    ok, store, scope_id = scan(SyntheticGcp(8, latency_ms=0, denied_fraction=1.0, error_rate=0.05))
    assert ok is True
    assert store.read_status('syn-job', scope_id)['status'] == 'completed'
    assert BANNER_MARK in store.read_report('syn-job', scope_id, 'html')


def test_report_banner_is_optional_and_escaped():
    plain = generate_html_report('project', 'p', 'j')
    assert 'role="note"' not in plain
    marked = generate_html_report('project', 'p', 'j', banner='Synthetic <b>data</b>')
    assert 'role="note"' in marked and 'Synthetic &lt;b&gt;data&lt;/b&gt;' in marked and '<b>data</b>' not in marked


# --- The app in the synthetic profile ---

@pytest.fixture
def synthetic_app(gcp, monkeypatch):
    set_env(monkeypatch, {**DEPLOYED_ENV, 'CLOUDGAUGE_ENV': 'synthetic', 'SYNTHETIC_PROJECTS': '8', 'SYNTHETIC_LATENCY_MS': '0',
                          'SYNTHETIC_DENIED_FRACTION': '0'})
    return create_app()


def test_synthetic_app_runs_the_production_startup_against_real_infrastructure(synthetic_app, gcp):
    assert synthetic_app.config['CLOUDGAUGE_PROFILE'] == 'synthetic'
    provider = gcp_clients.current_provider()
    assert isinstance(provider, SyntheticGcp) and provider.describe()['projects'] == 8
    services = synthetic_app.extensions[EXTENSION_KEY]
    assert services.worker_url == fakes.WORKER_URL  # discovered through the (pass-through) Cloud Run Admin API
    assert gcp.discovery.run_services  # the fake run service was asked
    assert gcp.tasks.queues  # and the queue ensured, both real infrastructure
    assert BANNER_MARK in services.report_banner


def test_synthetic_app_lists_and_scans_the_generated_organization(synthetic_app, gcp):
    client = synthetic_app.test_client()
    assert BANNER_MARK in client.get('/').get_data(as_text=True)

    projects = client.get('/api/list-resources?scope=project').get_json()
    assert [p['id'] for p in projects] == [f'syn-42-{i:05d}' for i in range(8)]
    assert [f['id'] for f in client.get('/api/list-resources?scope=folder').get_json()] == FOLDER_IDS
    assert client.get('/api/list-resources?scope=organization').get_json() == [{'id': ORG_ID, 'name': f'Organization {ORG_ID}'}]

    response = client.post('/run-scan', data=json.dumps({'scope': 'project', 'scope_id': 'syn-42-00001', 'job_id': 'job-1'}),
                           content_type='application/json')
    assert response.status_code == 200
    report = gcp.bucket.blob('job-1/syn-42-00001_report.html').download_as_text()  # the real results store, fake bucket
    assert BANNER_MARK in report and 'syn-42-00001' in report
    assert json.loads(gcp.bucket.blob('job-1/syn-42-00001_status.json').download_as_text())['status'] == 'completed'
    page = client.get('/status/job-1/project/syn-42-00001').get_data(as_text=True)
    assert BANNER_MARK in page


def test_build_provider_uses_the_settings():
    provider = build_provider(synthetic_settings(SYNTHETIC_SEED='3', SYNTHETIC_LATENCY_MS='0', SYNTHETIC_ERROR_RATE='0.1', SYNTHETIC_DENIED_FRACTION='0.5'))
    assert provider.describe() == {'projects': 12, 'seed': 3, 'latency_ms': 0.0, 'error_rate': 0.1, 'denied_fraction': 0.5}
    assert 'seed 3' in banner_for(provider)


# --- The offline harness ---

def test_offline_harness_runs_a_scan_and_writes_reports(gcp, tmp_path, capsys):
    from tools import synthetic_scan

    json_path = tmp_path / 'metrics.json'
    code = synthetic_scan.main(['--projects', '6', '--latency-ms', '0', '--quiet', '--output-dir', str(tmp_path), '--json', str(json_path)])
    assert code == 0
    out = capsys.readouterr().out
    assert 'RESULT: ok (status=completed)' in out and 'API calls:' in out
    result = json.loads(json_path.read_text())
    assert result['outcome']['ok'] and result['api']['total_calls'] > 50 and result['report']['error_checks'] == []
    assert (tmp_path / 'organization-6-seed42.html').exists() and (tmp_path / 'organization-6-seed42.csv').exists()
