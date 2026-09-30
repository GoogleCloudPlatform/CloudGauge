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
"""create_app(): profiles, the production startup sequence, and per-app services.

In production, create_app() runs the startup that the legacy module ran at import
time, and fails the same way (same exception, same message) when the deployment
is misconfigured. One difference is intended: the environment is validated
before any GCP call, where the legacy module looked up its URL first.
"""
import json

import pytest
from google.api_core.exceptions import AlreadyExists, PermissionDenied

import fakes
from app import create_app
from app.extensions import EXTENSION_KEY, Services
from app.services import gcp as gcp_clients
from app.services.results_store import GcsResultsStore
from helpers import import_legacy, make_settings, set_env

REQUIRED = tuple(fakes.TEST_ENV)
REGION = 'projects/test-project/locations/us-central1'
QUEUE_CREATED = (REGION, {'name': f'{REGION}/queues/test-queue'})
RUN_SERVICE = f'{REGION}/services/{fakes.K_SERVICE}'


def services_of(app):
    return app.extensions[EXTENSION_KEY]


def legacy_startup_error(expected_type):
    """Imports a fresh copy of the legacy module, whose startup must fail with ``expected_type``."""
    with pytest.raises(expected_type) as error:
        import_legacy('cloudgauge_legacy_startup')
    return error.value


@pytest.mark.parametrize('profile', ['testing', 'development'])
def test_non_production_profiles_skip_startup(profile, gcp, env, monkeypatch):
    monkeypatch.setenv('CLOUDGAUGE_ENV', profile)
    app = create_app()
    assert app.testing is (profile == 'testing')
    assert app.config['CLOUDGAUGE_PROFILE'] == profile
    # No GCP call and no client, so no credentials are needed.
    assert gcp.auth_scopes == [] and gcp.discovery.calls == [] and gcp.tasks.queues == []
    assert gcp_clients._storage_client is None and gcp_clients._tasks_client is None


def test_testing_profile_needs_no_configuration(gcp, monkeypatch):
    set_env(monkeypatch, {'CLOUDGAUGE_ENV': 'testing'})
    app = create_app()
    assert app.test_client().get('/').status_code == 200


def test_testing_profile_resolves_the_worker_url_once_on_first_use(testing_app, gcp):
    http = testing_app.test_client()
    for _ in range(2):
        assert http.post('/scan', data={'scope': 'project', 'scope_id': 'p1'}).status_code == 302
    assert gcp.discovery.run_services == [RUN_SERVICE]
    assert [task['http_request']['url'] for _, task in gcp.tasks.tasks] == [f'{fakes.WORKER_URL}/run-scan'] * 2


def test_production_startup_matches_legacy(legacy_import, gcp, env):
    app = create_app()
    assert not app.testing
    assert app.config['CLOUDGAUGE_PROFILE'] == 'production'
    startup = legacy_import.startup
    assert gcp.discovery.run_services == startup.discovery.run_services == [RUN_SERVICE]
    assert gcp.tasks.queues == startup.tasks.queues == [QUEUE_CREATED]
    assert services_of(app).worker_url == legacy_import.module.WORKER_URL == fakes.WORKER_URL


@pytest.mark.parametrize('missing', [(name,) for name in REQUIRED] + [('PROJECT_ID', 'TASK_QUEUE'), REQUIRED])
def test_missing_env_vars_fail_startup_like_legacy(missing, gcp, env, monkeypatch):
    for name in missing:
        monkeypatch.delenv(name)
    with pytest.raises(RuntimeError) as error:
        create_app()
    assert gcp.discovery.calls == [] and gcp.tasks.queues == []  # failed before any GCP call
    assert str(error.value) == str(legacy_startup_error(RuntimeError))
    assert str(error.value) == f"FATAL: Missing required environment variables: {', '.join(missing)}"


def test_empty_env_var_counts_as_missing_like_legacy(gcp, env, monkeypatch):
    monkeypatch.setenv('RESULTS_BUCKET', '')
    with pytest.raises(RuntimeError) as error:
        create_app()
    assert str(error.value) == str(legacy_startup_error(RuntimeError))
    assert str(error.value) == 'FATAL: Missing required environment variables: RESULTS_BUCKET'


def test_missing_k_service_fails_startup_like_legacy(gcp, env, monkeypatch):
    monkeypatch.delenv('K_SERVICE')
    with pytest.raises(RuntimeError) as error:
        create_app()
    assert str(error.value) == str(legacy_startup_error(RuntimeError))
    assert str(error.value).startswith('K_SERVICE environment variable not found.')


def test_worker_url_lookup_failure_fails_startup_like_legacy(gcp, env):
    gcp.discovery.worker_url = None  # the Cloud Run API response has no URL
    with pytest.raises(RuntimeError) as error:
        create_app()
    assert str(error.value) == str(legacy_startup_error(RuntimeError))
    assert str(error.value) == f'Could not find URL in API response for service {fakes.K_SERVICE}.'


def test_worker_url_setting_replaces_the_lookup(gcp, env, monkeypatch):
    """New behavior (plan B5): the legacy code told users to set WORKER_URL but never read it."""
    monkeypatch.delenv('K_SERVICE')
    monkeypatch.setenv('WORKER_URL', 'https://worker.example/')
    app = create_app()
    assert services_of(app).worker_url == 'https://worker.example'
    assert gcp.discovery.calls == []
    assert gcp.tasks.queues == [QUEUE_CREATED]


def test_existing_queue_is_reused(gcp, env):
    gcp.tasks.create_queue_error = AlreadyExists('Queue already exists')
    create_app()
    assert gcp.tasks.queues == [QUEUE_CREATED]


@pytest.mark.parametrize('error', [PermissionDenied('The caller lacks cloudtasks.queues.create'), RuntimeError('Cloud Tasks unavailable')])
def test_queue_errors_fail_startup_like_legacy(error, gcp, env):
    gcp.tasks.create_queue_error = error
    with pytest.raises(type(error)) as raised:
        create_app()
    assert raised.value is error
    assert legacy_startup_error(type(error)) is error


def test_unknown_profile_is_rejected(gcp, env, monkeypatch):
    monkeypatch.setenv('CLOUDGAUGE_ENV', 'staging')
    with pytest.raises(ValueError, match="Invalid CLOUDGAUGE_ENV 'staging'"):
        create_app()


def test_each_app_has_its_own_services(gcp, env):
    app_a = create_app(make_settings(RESULTS_BUCKET='bucket-a'))
    app_b = create_app(make_settings(RESULTS_BUCKET='bucket-b'))
    assert services_of(app_a) is not services_of(app_b)
    status = {'status': 'running', 'progress': 40, 'current_task': '(4/14) Finished: GKE Hygiene'}
    gcp.storage.bucket('bucket-a').put('job-1/p1_status.json', json.dumps(status), 'application/json')
    assert app_a.test_client().get('/api/status/job-1/p1').get_json() == status
    assert app_b.test_client().get('/api/status/job-1/p1').get_json()['status'] == 'pending'


def test_routes_use_the_injected_services(env):
    """Without the gcp fixture nothing is patched, so a real GCP client would fail the test."""
    storage, tasks_client = fakes.FakeStorageClient(), fakes.FakeTasksClient()
    settings = make_settings()
    services = Services(settings=settings, results_store=GcsResultsStore('injected-bucket', client=storage),
                        tasks_client=tasks_client, worker_url='https://injected.example')
    app = create_app(settings, services=services)
    assert services_of(app) is services

    storage.bucket('injected-bucket').put('job-1/p1_report.html', '<p>injected</p>', 'text/html')
    http = app.test_client()
    assert http.get('/report/job-1/p1').get_data(as_text=True) == '<p>injected</p>'
    assert http.post('/scan', data={'scope': 'project', 'scope_id': 'p1'}).status_code == 302
    [(parent, task)] = tasks_client.tasks
    assert parent == 'projects/test-project/locations/us-central1/queues/test-queue'
    assert task['http_request']['url'] == 'https://injected.example/run-scan'
