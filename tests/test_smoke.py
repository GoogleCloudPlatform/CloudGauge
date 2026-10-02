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
"""Smoke tests: the deployable app answers its core routes and survives auxiliary-service failures.

A fast pre-deploy gate (``pytest tests/test_smoke.py``). The app is built the
way gunicorn builds it (``create_app()``, production profile, deployed
environment), with Cloud Storage and Cloud Tasks replaced by the in-memory
fakes in ``fakes.py``; ``unittest.mock`` injects failures. The parity suites
(test_api_parity.py, test_worker.py, ...) cover behavior in depth.

Route note: status is keyed by job *and* scope, since the worker writes
``{job_id}/{scope_id}_status.json``. The polling endpoint is therefore
``/api/status/<job_id>/<scope_id>`` (the status page calls it that way);
``/api/status/<job_id>`` alone is not a route.
"""
import json
from unittest import mock

import pytest
from flask import template_rendered
from google.api_core.exceptions import ServiceUnavailable

import fakes
from app import scan_job

JOB_ID, SCOPE, SCOPE_ID = 'test-job-id', 'project', 'web-prod'
PENDING = {'status': 'pending', 'progress': 0, 'current_task': 'Waiting for task to start...'}


@pytest.fixture
def rendered(prod_app):
    """Names of the templates rendered during the test."""
    names = []

    def record(sender, template, context, **extra):
        names.append(template.name)

    template_rendered.connect(record, prod_app)
    yield names
    template_rendered.disconnect(record, prod_app)


# --- Startup ---

def test_app_starts_with_the_production_startup_sequence(prod_app, gcp):
    """Building the app ran the startup checks against the fakes: worker URL lookup and queue creation."""
    assert prod_app.config['CLOUDGAUGE_PROFILE'] == 'production'
    assert gcp.discovery.run_services == [f"projects/{fakes.TEST_ENV['PROJECT_ID']}/locations/"
                                          f"{fakes.TEST_ENV['LOCATION']}/services/{fakes.K_SERVICE}"]
    assert [parent for parent, _ in gcp.tasks.queues] == [f"projects/{fakes.TEST_ENV['PROJECT_ID']}/locations/"
                                                          f"{fakes.TEST_ENV['LOCATION']}"]


# --- Root route ---

def test_root_renders_the_index_page(client, rendered):
    response = client.get('/')
    assert response.status_code == 200
    assert response.mimetype == 'text/html'
    assert rendered == ['index.html']
    assert b'/api/list-resources' in response.data  # the scope picker's data source


# --- Status route ---

def test_status_of_an_unknown_job_is_pending(client, gcp):
    """Nothing in GCS yet (the worker hasn't started): a pending status, not an error."""
    response = client.get(f'/api/status/{JOB_ID}/{SCOPE_ID}')
    assert response.status_code == 200
    assert response.mimetype == 'application/json'
    assert response.get_json() == PENDING


def test_status_returns_the_document_the_worker_wrote(client, gcp):
    status = {'job_id': JOB_ID, 'scope_id': SCOPE_ID, 'status': 'running', 'progress': 35,
              'current_task': '(5/18) Finished: GKE Hygiene', 'timestamp': '2026-09-29T12:00:00+00:00'}
    gcp.bucket.put(f'{JOB_ID}/{SCOPE_ID}_status.json', json.dumps(status), 'application/json')
    response = client.get(f'/api/status/{JOB_ID}/{SCOPE_ID}')
    assert (response.status_code, response.get_json()) == (200, status)


def test_status_reports_a_storage_failure_as_json(client, gcp):
    with mock.patch.object(gcp.bucket, 'error', RuntimeError('503 GCS unavailable')):
        response = client.get(f'/api/status/{JOB_ID}/{SCOPE_ID}')
    assert response.status_code == 500
    assert response.get_json() == {'status': 'error', 'message': '503 GCS unavailable'}


def test_status_route_needs_the_scope_id(client):
    assert client.get(f'/api/status/{JOB_ID}').status_code == 404


# --- Scan task generation (Cloud Tasks) ---

def test_scan_enqueues_a_task_and_redirects_to_the_status_page(client, gcp):
    response = client.post('/scan', data={'scope': SCOPE, 'scope_id': SCOPE_ID})
    assert response.status_code == 302
    job_id = response.headers['Location'].split('/')[2]
    assert response.headers['Location'] == f'/status/{job_id}/{SCOPE}/{SCOPE_ID}'

    ((parent, task),) = gcp.tasks.tasks
    assert parent == f"projects/{fakes.TEST_ENV['PROJECT_ID']}/locations/{fakes.TEST_ENV['LOCATION']}/queues/{fakes.TEST_ENV['TASK_QUEUE']}"
    request = task['http_request']
    assert request['url'] == f'{fakes.WORKER_URL}/run-scan'
    assert request['oidc_token'] == {'service_account_email': fakes.TEST_ENV['SERVICE_ACCOUNT_EMAIL']}
    assert json.loads(request['body']) == {'scope': SCOPE, 'scope_id': SCOPE_ID, 'job_id': job_id}


def test_scan_validates_its_form(client, gcp):
    response = client.post('/scan', data={'scope': SCOPE, 'scope_id': ''})
    assert (response.status_code, response.get_data(as_text=True)) == (400, 'Scope and ID are required.')
    assert gcp.tasks.tasks == []


def test_cloud_tasks_failure_is_a_500_and_the_app_keeps_serving(client, gcp):
    with mock.patch.object(gcp.tasks, 'create_task', side_effect=ServiceUnavailable('Cloud Tasks unavailable')):
        response = client.post('/scan', data={'scope': SCOPE, 'scope_id': SCOPE_ID})
    assert response.status_code == 500  # handled by Flask; no traceback leaks to the client
    assert b'Traceback' not in response.data
    assert client.get('/').status_code == 200


def test_status_page_renders_with_a_signed_csv_link(client, gcp, rendered):
    response = client.get(f'/status/{JOB_ID}/{SCOPE}/{SCOPE_ID}')
    assert response.status_code == 200
    assert rendered == ['status.html']
    assert 'X-Goog-Signature' in response.get_data(as_text=True)
    ((blob_name, kwargs),) = gcp.bucket.signed_url_requests
    assert blob_name == f'{JOB_ID}/{SCOPE_ID}_report.csv'
    assert kwargs['service_account_email'] == fakes.TEST_ENV['SERVICE_ACCOUNT_EMAIL']


def test_status_page_survives_a_signing_failure(client, gcp):
    with mock.patch.object(gcp.bucket, 'signing_error', PermissionError('iam.serviceAccounts.signBlob denied')):
        response = client.get(f'/status/{JOB_ID}/{SCOPE}/{SCOPE_ID}')
    assert response.status_code == 200
    assert 'const signed_csv_url = "#";' in response.get_data(as_text=True)


# --- Worker round trip (GCS writes and reads) ---

def test_worker_writes_status_and_reports_that_the_ui_reads_back(client, gcp, monkeypatch):
    """/run-scan with the checks mocked: status and reports land in (fake) GCS, and the UI routes serve them."""
    def fake_checks(scope, scope_id, job_id, progress_callback=None, *, sink, projects=None):
        sink.write_finding(job_id, 'Open_Firewall_Rules', {
            'Check': 'Open Firewall Rules', 'Status': 'Action Required',
            'Finding': [{'Project': SCOPE_ID, 'Rule Name': 'allow-all', 'VPC': 'default'}]})
        progress_callback(progress=95, current_task='(18/18) Finished: Open Firewall Rules')
        return True

    monkeypatch.setattr(scan_job, 'run_all_checks', fake_checks)
    response = client.post('/run-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID, 'job_id': JOB_ID})
    assert (response.status_code, response.get_data(as_text=True)) == (200, 'Scan completed and reports uploaded.')

    status = client.get(f'/api/status/{JOB_ID}/{SCOPE_ID}').get_json()
    assert (status['status'], status['progress'], status['current_task']) == ('completed', 100, 'Scan complete!')
    report = client.get(f'/report/{JOB_ID}/{SCOPE_ID}')
    assert report.status_code == 200
    assert '<strong>Open Firewall Rules</strong>' in report.get_data(as_text=True)
    assert f'{JOB_ID}/{SCOPE_ID}_report.csv' in gcp.bucket.objects
    assert not [name for name in gcp.bucket.objects if name.startswith('intermediate/')]  # cleaned up


def test_worker_fails_cleanly_on_an_incomplete_task(client, gcp):
    """A payload without job_id is caught and turned into a 500, matching the legacy worker; nothing is uploaded.

    (A 4xx would stop Cloud Tasks retrying a payload that can never succeed; that is a deferred behaviour change.)
    """
    response = client.post('/run-scan', json={'scope': SCOPE, 'scope_id': SCOPE_ID})
    assert (response.status_code, response.get_data(as_text=True)) == (500, 'Internal Server Error')
    assert gcp.bucket.uploads == []


def test_report_not_found_and_storage_failure(client, gcp):
    assert client.get(f'/report/{JOB_ID}/{SCOPE_ID}').status_code == 404
    with mock.patch.object(gcp.bucket, 'error', RuntimeError('503 GCS unavailable')):
        response = client.get(f'/report/{JOB_ID}/{SCOPE_ID}')
    assert (response.status_code, response.get_data(as_text=True)) == (500, 'Could not retrieve report.')
