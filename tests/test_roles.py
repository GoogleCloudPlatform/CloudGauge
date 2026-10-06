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
"""``CLOUDGAUGE_ROLE`` (v16): one image, two kinds of service.

``all`` is the single service every deployment had before v16 and stays the
default. ``web`` serves the pages and the API (behind Identity-Aware Proxy in
the recommended deployment) and sends every scan to ``WORKER_URL``; ``worker``
serves the Cloud Tasks endpoints only. The point of the split: nothing that
passes IAP can reach ``/run-aggregation``, and no Cloud Tasks request ever
meets IAP.
"""
import json
import logging

import pytest

import fakes
from app import create_app
from app.config import ROLES
from app.extensions import EXTENSION_KEY
from app.services.worker_url import resolve_worker_url
from helpers import make_settings

WORKER_URL = 'https://cloudgauge-worker-123.us-central1.run.app'
WORKER_PATHS = ('/run-scan', '/scan-shard', '/run-aggregation', '/sweep')
PAGE_PATHS = ('/', '/status/job-1/project/p1', '/report/job-1/p1', '/api/status/job-1/p1')
BLUEPRINTS = {'all': {'ui', 'api', 'worker'}, 'web': {'ui', 'api'}, 'worker': {'worker'}}
WEB_NEEDS_WORKER_URL = ("FATAL: CLOUDGAUGE_ROLE=web needs WORKER_URL, the URL of the worker service "
                        "(the one deployed with CLOUDGAUGE_ROLE=worker); the web service never runs scans itself.")


def services_of(app):
    return app.extensions[EXTENSION_KEY]


def test_the_roles_and_the_default():
    assert ROLES == ('all', 'web', 'worker')
    settings = make_settings()
    assert settings.role == 'all' and settings.serves_pages and settings.serves_worker and not settings.is_web_role


@pytest.mark.parametrize('role', ROLES)
def test_each_role_registers_its_blueprints(role, gcp):
    app = create_app(make_settings('testing', CLOUDGAUGE_ROLE=role, WORKER_URL=WORKER_URL))
    assert app.config['CLOUDGAUGE_ROLE'] == role
    assert set(app.blueprints) == BLUEPRINTS[role]


def test_the_role_is_read_case_insensitively():
    assert make_settings(CLOUDGAUGE_ROLE=' Web ').role == 'web'


def test_an_unknown_role_is_rejected(gcp, env, monkeypatch):
    monkeypatch.setenv('CLOUDGAUGE_ROLE', 'frontend')
    with pytest.raises(ValueError, match="Invalid CLOUDGAUGE_ROLE 'frontend'. Expected one of: all, web, worker"):
        create_app()


def test_the_web_service_has_no_worker_endpoints(gcp):
    """Whoever passes IAP gets the pages, and nothing a Cloud Tasks caller gets."""
    http = create_app(make_settings('testing', CLOUDGAUGE_ROLE='web', WORKER_URL=WORKER_URL)).test_client()
    assert http.get('/').status_code == 200
    assert [http.post(path, json={}).status_code for path in WORKER_PATHS] == [404] * len(WORKER_PATHS)


def test_the_worker_service_has_no_pages(gcp):
    """Nothing to sign in to: the worker is reachable by Cloud Tasks only, and serves it only."""
    http = create_app(make_settings('testing', CLOUDGAUGE_ROLE='worker')).test_client()
    assert [http.get(path).status_code for path in PAGE_PATHS] == [404] * len(PAGE_PATHS)
    assert http.post('/scan', data={'scope': 'project', 'scope_id': 'p1'}).status_code == 404
    assert http.post('/run-scan', json={}).status_code != 404  # the endpoint exists (and rejects the empty task)


def test_the_single_service_is_unchanged(prod_app):
    assert prod_app.config['CLOUDGAUGE_ROLE'] == 'all' and set(prod_app.blueprints) == BLUEPRINTS['all']


# --- Startup per role (production profile) ---

def test_a_web_service_without_worker_url_fails_startup_before_any_gcp_call(gcp, env, monkeypatch):
    """Self-discovery would hand the web service its own URL, and every scan would hit a service with no /run-scan."""
    monkeypatch.setenv('CLOUDGAUGE_ROLE', 'web')
    with pytest.raises(RuntimeError) as error:
        create_app()
    assert str(error.value) == WEB_NEEDS_WORKER_URL
    assert gcp.discovery.calls == [] and gcp.tasks.queues == []


def test_a_web_service_sends_scans_to_the_worker_and_never_discovers_itself(gcp, env, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    monkeypatch.setenv('CLOUDGAUGE_ROLE', 'web')
    monkeypatch.setenv('WORKER_URL', WORKER_URL + '/')
    app = create_app()
    assert services_of(app).worker_url == WORKER_URL
    assert gcp.discovery.calls == []  # no Cloud Run Admin API call, so no roles/run.viewer needed
    assert len(gcp.tasks.queues) == 1  # the queue is created by whichever service starts first
    assert app.test_client().post('/scan', data={'scope': 'project', 'scope_id': 'p1'}).status_code == 302
    ((_, task),) = gcp.tasks.tasks
    assert task['http_request']['url'] == f'{WORKER_URL}/run-scan'
    body = json.loads(task['http_request']['body'])
    assert body == {'scope': 'project', 'scope_id': 'p1', 'job_id': body['job_id']}  # the legacy body: no requested_by without IAP
    assert "CloudGauge role 'web': serving the pages and the API (scans run on WORKER_URL)." in caplog.text


def test_a_worker_service_discovers_its_own_url_like_the_single_service(gcp, env, monkeypatch):
    """Shard, aggregation and sweep tasks go to the worker itself: its URL is discovered as before, unless WORKER_URL says it."""
    monkeypatch.setenv('CLOUDGAUGE_ROLE', 'worker')
    app = create_app()
    assert services_of(app).worker_url == fakes.WORKER_URL
    assert gcp.discovery.run_services == [f'projects/test-project/locations/us-central1/services/{fakes.K_SERVICE}']
    assert len(gcp.tasks.queues) == 1


def test_a_worker_told_its_url_does_not_discover_it(gcp, env, monkeypatch):
    """What tools/deploy.sh does: WORKER_URL is the worker's deterministic URL, known before the service exists."""
    monkeypatch.setenv('CLOUDGAUGE_ROLE', 'worker')
    monkeypatch.setenv('WORKER_URL', WORKER_URL)
    assert services_of(create_app()).worker_url == WORKER_URL
    assert gcp.discovery.calls == []


@pytest.mark.parametrize('profile', ['testing', 'development', 'production'])
def test_a_web_service_never_discovers_itself_in_any_profile(profile):
    with pytest.raises(RuntimeError, match='CLOUDGAUGE_ROLE=web needs WORKER_URL'):
        resolve_worker_url(make_settings(profile, CLOUDGAUGE_ROLE='web'))
    assert resolve_worker_url(make_settings(profile, CLOUDGAUGE_ROLE='web', WORKER_URL=WORKER_URL)) == WORKER_URL
