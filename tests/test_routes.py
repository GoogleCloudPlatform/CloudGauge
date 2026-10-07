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
"""Route resolution: the blueprints serve the legacy URL map, rule for rule.

Only the endpoint names change: each one gets its blueprint's prefix
(``get_status`` is now ``ui.get_status``). URLs, converters and methods must
match the legacy module exactly, including the HEAD and OPTIONS methods that
Flask adds. The other test modules check what each route returns.
"""
import importlib
import sys

import pytest
from flask import Flask, url_for
from werkzeug.exceptions import HTTPException

import fakes
from app.routes import api, ui, worker
from helpers import assert_same_response

# rule -> (methods, legacy endpoint, blueprint endpoint)
ROUTES = {
    '/': ({'GET'}, 'index', 'ui.index'),
    '/scan': ({'POST'}, 'create_scan_task', 'ui.create_scan_task'),
    '/status/<string:job_id>/<string:scope>/<string:scope_id>': ({'GET'}, 'get_status', 'ui.get_status'),
    '/report/<string:job_id>/<string:scope_id>': ({'GET'}, 'view_report', 'ui.view_report'),
    '/api/list-resources': ({'GET'}, 'list_resources', 'api.list_resources'),
    '/api/status/<string:job_id>/<string:scope_id>': ({'GET'}, 'api_check_status', 'api.api_check_status'),
    '/api/get-insights': ({'POST'}, 'get_insights', 'api.get_insights'),
    '/api/get-summary': ({'POST'}, 'get_summary', 'api.get_summary'),
    '/api/get-suggestions': ({'POST'}, 'get_suggestions', 'api.get_suggestions'),
    '/run-scan': ({'POST'}, 'run_scan_worker', 'worker.run_scan_worker'),
    '/static/<path:filename>': ({'GET'}, 'static', 'static'),
    # New with sharded scans (app.fanout); Cloud Tasks is their only caller. No legacy endpoint.
    '/scan-shard': ({'POST'}, None, 'worker.scan_shard_worker'),
    '/run-aggregation': ({'POST'}, None, 'worker.run_aggregation_worker'),
    '/sweep': ({'POST'}, None, 'worker.sweep_worker'),
    # New with the enterprise report layout (plan item 6b): the report links to the complete CSV.
    '/report/<string:job_id>/<string:scope_id>/csv': ({'GET'}, None, 'ui.download_report_csv'),
}
NEW_ENDPOINT = {legacy: new for _, legacy, new in ROUTES.values() if legacy}
NEW_RULES = {rule for rule, (_, legacy, _) in ROUTES.items() if legacy is None}
NEW_WORKER_RULES = {rule for rule in NEW_RULES if ROUTES[rule][2].startswith('worker.')}
BLUEPRINT_MODULES = {'ui': ui, 'api': api, 'worker': worker}

# Requests that reach a view, one or more per rule.
MATCHING = [
    ('GET', '/'),
    ('HEAD', '/'),
    ('OPTIONS', '/'),
    ('POST', '/scan'),
    ('OPTIONS', '/scan'),
    ('GET', '/status/0f8fad5b-d9cb-469f-a165-70867728950e/organization/123456789'),
    ('GET', '/status/job-1/project/my-project'),
    ('HEAD', '/status/job-1/folder/42'),
    ('GET', '/report/job-1/123456789'),
    ('GET', '/report/job 1/café'),
    ('GET', '/api/list-resources'),
    ('GET', '/api/status/job-1/my-project'),
    ('POST', '/api/get-insights'),
    ('POST', '/api/get-summary'),
    ('POST', '/api/get-suggestions'),
    ('POST', '/run-scan'),
    ('GET', '/static/css/app.css'),
]
# Requests that don't: unknown paths (404) and wrong methods (405).
NOT_MATCHING = [
    ('POST', '/'),
    ('GET', '/scan'),
    ('PUT', '/scan'),
    ('GET', '/run-scan'),
    ('HEAD', '/run-scan'),
    ('GET', '/api/get-insights'),
    ('GET', '/api/get-summary'),
    ('DELETE', '/api/get-suggestions'),
    ('POST', '/api/list-resources'),
    ('POST', '/status/job-1/project/p1'),
    ('DELETE', '/report/job-1/p1'),
    ('GET', '/status/job-1/project'),
    ('GET', '/status/job-1/project/p1/extra'),
    ('GET', '/report/job-1'),
    ('GET', '/report/job-1/a/b'),
    ('GET', '/api/status/job-1'),
    ('GET', '/api/list-resources/'),
    ('GET', '/list-resources'),
    ('GET', '/get-summary'),
    ('POST', '/api/run-scan'),
    ('GET', '/api/'),
    ('GET', '/api'),
    ('GET', '/index.html'),
]


def url_map(app):
    """``{(rule, methods): endpoint}`` for every URL rule of ``app``."""
    return {(rule.rule, frozenset(rule.methods)): rule.endpoint for rule in app.url_map.iter_rules()}


def resolve(app, method, path):
    """What routing does with a request: the endpoint and arguments, or the HTTP error."""
    try:
        endpoint, args = app.url_map.bind('localhost').match(path, method=method)
    except HTTPException as error:
        return {'error': type(error).__name__, 'allowed': sorted(getattr(error, 'valid_methods', None) or [])}
    return {'endpoint': endpoint, 'args': args}


def test_url_map_is_the_legacy_url_map(legacy, testing_app):
    """Every legacy rule exists with the same methods; the only additions are the sharded-scan worker routes and the CSV download."""
    legacy_map = url_map(legacy.app)
    new_map = url_map(testing_app)
    additions = {key: endpoint for key, endpoint in new_map.items() if key not in legacy_map}
    assert {key: NEW_ENDPOINT[endpoint] for key, endpoint in legacy_map.items()} == {k: v for k, v in new_map.items() if k in legacy_map}
    assert {rule for rule, _ in additions} == NEW_RULES


def test_routes_table_is_complete(testing_app):
    """ROUTES lists every rule, so the tests built on it cover every route."""
    rules = {rule.rule: (set(rule.methods) - {'HEAD', 'OPTIONS'}, rule.endpoint) for rule in testing_app.url_map.iter_rules()}
    assert rules == {rule: (methods, endpoint) for rule, (methods, _, endpoint) in ROUTES.items()}


def test_blueprints_and_views(testing_app):
    assert {name: bp.url_prefix for name, bp in testing_app.blueprints.items()} == {'ui': None, 'api': '/api', 'worker': None}
    for endpoint in NEW_ENDPOINT.values():
        if endpoint != 'static':
            blueprint, view = endpoint.split('.')
            assert testing_app.view_functions[endpoint] is getattr(BLUEPRINT_MODULES[blueprint], view)


@pytest.mark.parametrize('method, path', MATCHING)
def test_request_reaches_the_legacy_view(method, path, legacy, testing_app):
    expected = resolve(legacy.app, method, path)
    assert 'endpoint' in expected, expected
    expected['endpoint'] = NEW_ENDPOINT[expected['endpoint']]
    assert resolve(testing_app, method, path) == expected


@pytest.mark.parametrize('path', sorted(NEW_WORKER_RULES))
def test_new_worker_routes_accept_post_only(path, testing_app):
    """The sharded-scan endpoints (no legacy counterpart) are POST-only like /run-scan."""
    assert resolve(testing_app, 'POST', path) == {'endpoint': ROUTES[path][2], 'args': {}}
    assert resolve(testing_app, 'GET', path) == {'error': 'MethodNotAllowed', 'allowed': ['OPTIONS', 'POST']}
    assert testing_app.test_client().get(path).status_code == 405


def test_csv_download_route(testing_app, gcp):
    """/report/<job>/<scope_id>/csv serves the stored CSV as a download: the report page links to it and, since
    v16.1, so does the status page (a signed Cloud Storage URL before). The object is streamed, with its size."""
    assert resolve(testing_app, 'GET', '/report/job-1/p1/csv') == {'endpoint': 'ui.download_report_csv', 'args': {'job_id': 'job-1', 'scope_id': 'p1'}}
    assert resolve(testing_app, 'POST', '/report/job-1/p1/csv') == {'error': 'MethodNotAllowed', 'allowed': ['GET', 'HEAD', 'OPTIONS']}
    client = testing_app.test_client()
    missing = client.get('/report/job-1/p1/csv')
    assert (missing.status_code, missing.get_data(as_text=True)) == (404, 'CSV report not found or is still generating.')
    assert gcp.bucket.opened == []
    body = 'Organization Policies\r\nCategory,Policy\r\nSécurité,—\r\n'  # non-ASCII: the size is in bytes, not characters
    gcp.bucket.put('job-1/p1_report.csv', body, 'text/csv')
    response = client.get('/report/job-1/p1/csv')
    assert response.status_code == 200
    assert response.headers['Content-Type'].startswith('text/csv')
    assert response.headers['Content-Disposition'] == 'attachment; filename="cloudgauge_p1_job-1.csv"'
    assert response.headers['Content-Length'] == str(len(body.encode()))
    assert response.get_data(as_text=True) == body
    assert gcp.bucket.opened == [('job-1/p1_report.csv', ui.CSV_CHUNK_BYTES)]
    # IDs that are not safe in a filename are sanitized (the lookup still uses them as given).
    gcp.bucket.put('job 1/a b_report.csv', 'x', 'text/csv')
    assert client.get('/report/job%201/a%20b/csv').headers['Content-Disposition'] == 'attachment; filename="cloudgauge_a_b_job_1.csv"'


def test_csv_download_streams_in_chunks(testing_app, gcp, monkeypatch):
    """A CSV larger than one chunk arrives whole, chunk by chunk, and the file is closed afterwards."""
    monkeypatch.setattr(ui, 'CSV_CHUNK_BYTES', 8)
    body = ''.join(f'row-{i:04d},value\r\n' for i in range(50))  # 800 bytes → 100 chunks of 8
    gcp.bucket.put('job-1/p1_report.csv', body, 'text/csv')
    files = []
    original_open = fakes.FakeBlob.open

    def recording_open(self, *args, **kwargs):
        files.append(original_open(self, *args, **kwargs))
        return files[-1]

    monkeypatch.setattr(fakes.FakeBlob, 'open', recording_open)
    with testing_app.test_client() as client:
        response = client.get('/report/job-1/p1/csv')
        chunks = list(response.response)
    assert len(chunks) == -(-len(body) // 8) == 100 and all(len(chunk) <= 8 for chunk in chunks)
    assert b''.join(chunks).decode() == body
    assert response.headers['Content-Length'] == str(len(body))
    assert gcp.bucket.opened == [('job-1/p1_report.csv', 8)]
    assert [f.closed for f in files] == [True]


def test_csv_download_reports_a_bucket_failure(testing_app, gcp):
    gcp.bucket.put('job-1/p1_report.csv', 'x', 'text/csv')
    gcp.bucket.error = RuntimeError('bucket unavailable')
    response = testing_app.test_client().get('/report/job-1/p1/csv')
    assert (response.status_code, response.get_data(as_text=True)) == (500, 'Could not retrieve the CSV report.')


@pytest.mark.parametrize('method, path', NOT_MATCHING)
def test_request_is_rejected_like_legacy(method, path, legacy, testing_app, legacy_client):
    expected = resolve(legacy.app, method, path)
    assert 'error' in expected, expected
    assert resolve(testing_app, method, path) == expected
    # Same status, Allow header and error page over HTTP.
    assert_same_response(legacy_client.open(path, method=method), testing_app.test_client().open(path, method=method), html=True)


@pytest.mark.parametrize('endpoint, values', [
    ('index', {}),
    ('create_scan_task', {}),
    ('get_status', {'job_id': 'job-1', 'scope': 'folder', 'scope_id': '42'}),
    ('get_status', {'job_id': 'a b', 'scope': 'project', 'scope_id': 'x/y?z'}),
    ('view_report', {'job_id': 'job-1', 'scope_id': '42'}),
    ('list_resources', {'scope': 'project'}),
    ('api_check_status', {'job_id': 'job-1', 'scope_id': 'my-project'}),
    ('get_insights', {}),
    ('get_summary', {}),
    ('get_suggestions', {}),
    ('run_scan_worker', {}),
    ('static', {'filename': 'css/app.css'}),
])
def test_url_for_builds_the_legacy_url(endpoint, values, legacy, testing_app):
    with legacy.app.test_request_context():
        expected = url_for(endpoint, **values)
    with testing_app.test_request_context():
        assert url_for(NEW_ENDPOINT[endpoint], **values) == expected


@pytest.fixture
def import_shim():
    """Imports cloudgauge.py afresh (it builds its app when imported) and forgets it afterwards."""
    def load():
        sys.modules.pop('cloudgauge', None)
        return importlib.import_module('cloudgauge')
    yield load
    sys.modules.pop('cloudgauge', None)


def test_shim_exposes_the_app(import_shim, testing_app):
    shim = import_shim()  # CLOUDGAUGE_ENV=testing, set by the testing_app fixture
    assert isinstance(shim.app, Flask)
    assert shim.app is not testing_app
    assert url_map(shim.app) == url_map(testing_app)
    assert shim.app.test_client().get('/').status_code == 200


def test_shim_runs_the_legacy_startup_in_production(import_shim, gcp, env, legacy_import):
    shim = import_shim()
    assert not shim.app.testing
    startup = legacy_import.startup
    assert gcp.discovery.run_services == startup.discovery.run_services
    # Same queue (the new app also sets its limits; see test_app_factory.py)
    assert [(parent, queue['name']) for parent, queue in gcp.tasks.queues] == \
           [(parent, queue['name']) for parent, queue in startup.tasks.queues]
    assert len(gcp.tasks.queues) == 1
