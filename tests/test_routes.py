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
"""Route resolution: the URL map is pinned, rule for rule.

URLs, converters, methods (including the HEAD and OPTIONS methods that Flask
adds) and endpoint names are the contract of the blueprints with the pages,
the scripts and Cloud Tasks; ``PINNED_URL_MAP`` writes it out. The other test
modules check what each route returns.
"""
import importlib
import sys

import pytest
from flask import Flask, url_for
from werkzeug.exceptions import HTTPException

import fakes
from app.routes import api, ui, worker

# rule -> (methods, endpoint)
ROUTES = {
    '/': ({'GET'}, 'ui.index'),
    '/scan': ({'POST'}, 'ui.create_scan_task'),
    '/status/<string:job_id>/<string:scope>/<string:scope_id>': ({'GET'}, 'ui.get_status'),
    '/report/<string:job_id>/<string:scope_id>': ({'GET'}, 'ui.view_report'),
    '/api/list-resources': ({'GET'}, 'api.list_resources'),
    '/api/status/<string:job_id>/<string:scope_id>': ({'GET'}, 'api.api_check_status'),
    '/api/get-insights': ({'POST'}, 'api.get_insights'),
    '/api/get-summary': ({'POST'}, 'api.get_summary'),
    '/api/get-suggestions': ({'POST'}, 'api.get_suggestions'),
    '/run-scan': ({'POST'}, 'worker.run_scan_worker'),
    '/static/<path:filename>': ({'GET'}, 'static'),
    # Sharded scans (app.fanout); Cloud Tasks is their only caller.
    '/scan-shard': ({'POST'}, 'worker.scan_shard_worker'),
    '/run-aggregation': ({'POST'}, 'worker.run_aggregation_worker'),
    '/sweep': ({'POST'}, 'worker.sweep_worker'),
    # The enterprise report layout (plan item 6b): the report links to the complete CSV.
    '/report/<string:job_id>/<string:scope_id>/csv': ({'GET'}, 'ui.download_report_csv'),
    # v17: the scope's scans over time, and the endpoint Cloud Scheduler posts to (the worker's, like the task endpoints).
    '/history/<string:scope>/<string:scope_id>': ({'GET'}, 'ui.view_history'),
    '/scheduled-scan': ({'POST'}, 'worker.scheduled_scan'),
}
WORKER_RULES = {rule for rule, (_, endpoint) in ROUTES.items() if endpoint.startswith('worker.')}
BLUEPRINT_MODULES = {'ui': ui, 'api': api, 'worker': worker}

# Every URL rule of the app, with the methods Flask adds: ``url_map(testing_app)``, written out.
PINNED_URL_MAP = {
    ('/', frozenset({'GET', 'HEAD', 'OPTIONS'})): 'ui.index',
    ('/api/get-insights', frozenset({'OPTIONS', 'POST'})): 'api.get_insights',
    ('/api/get-suggestions', frozenset({'OPTIONS', 'POST'})): 'api.get_suggestions',
    ('/api/get-summary', frozenset({'OPTIONS', 'POST'})): 'api.get_summary',
    ('/api/list-resources', frozenset({'GET', 'HEAD', 'OPTIONS'})): 'api.list_resources',
    ('/api/status/<string:job_id>/<string:scope_id>', frozenset({'GET', 'HEAD', 'OPTIONS'})): 'api.api_check_status',
    ('/history/<string:scope>/<string:scope_id>', frozenset({'GET', 'HEAD', 'OPTIONS'})): 'ui.view_history',
    ('/report/<string:job_id>/<string:scope_id>', frozenset({'GET', 'HEAD', 'OPTIONS'})): 'ui.view_report',
    ('/report/<string:job_id>/<string:scope_id>/csv', frozenset({'GET', 'HEAD', 'OPTIONS'})): 'ui.download_report_csv',
    ('/run-aggregation', frozenset({'OPTIONS', 'POST'})): 'worker.run_aggregation_worker',
    ('/run-scan', frozenset({'OPTIONS', 'POST'})): 'worker.run_scan_worker',
    ('/scan', frozenset({'OPTIONS', 'POST'})): 'ui.create_scan_task',
    ('/scan-shard', frozenset({'OPTIONS', 'POST'})): 'worker.scan_shard_worker',
    ('/scheduled-scan', frozenset({'OPTIONS', 'POST'})): 'worker.scheduled_scan',
    ('/static/<path:filename>', frozenset({'GET', 'HEAD', 'OPTIONS'})): 'static',
    ('/status/<string:job_id>/<string:scope>/<string:scope_id>', frozenset({'GET', 'HEAD', 'OPTIONS'})): 'ui.get_status',
    ('/sweep', frozenset({'OPTIONS', 'POST'})): 'worker.sweep_worker',
}

# Requests that reach a view, one or more per rule: (method, path, endpoint, view arguments).
MATCHING = [
    ('GET', '/', 'ui.index', {}),
    ('HEAD', '/', 'ui.index', {}),
    ('OPTIONS', '/', 'ui.index', {}),
    ('POST', '/scan', 'ui.create_scan_task', {}),
    ('OPTIONS', '/scan', 'ui.create_scan_task', {}),
    ('GET', '/status/0f8fad5b-d9cb-469f-a165-70867728950e/organization/123456789', 'ui.get_status',
     {'job_id': '0f8fad5b-d9cb-469f-a165-70867728950e', 'scope': 'organization', 'scope_id': '123456789'}),
    ('GET', '/status/job-1/project/my-project', 'ui.get_status', {'job_id': 'job-1', 'scope': 'project', 'scope_id': 'my-project'}),
    ('HEAD', '/status/job-1/folder/42', 'ui.get_status', {'job_id': 'job-1', 'scope': 'folder', 'scope_id': '42'}),
    ('GET', '/report/job-1/123456789', 'ui.view_report', {'job_id': 'job-1', 'scope_id': '123456789'}),
    ('GET', '/report/job 1/café', 'ui.view_report', {'job_id': 'job 1', 'scope_id': 'café'}),  # routing decodes; the view validates (v18.6.1)
    ('GET', '/api/list-resources', 'api.list_resources', {}),
    ('GET', '/api/status/job-1/my-project', 'api.api_check_status', {'job_id': 'job-1', 'scope_id': 'my-project'}),
    ('POST', '/api/get-insights', 'api.get_insights', {}),
    ('POST', '/api/get-summary', 'api.get_summary', {}),
    ('POST', '/api/get-suggestions', 'api.get_suggestions', {}),
    ('POST', '/run-scan', 'worker.run_scan_worker', {}),
    ('GET', '/static/css/app.css', 'static', {'filename': 'css/app.css'}),
]
# Requests that don't: wrong methods (405, with the methods the rule allows) and unknown paths (404).
NOT_MATCHING = [
    ('POST', '/', 'MethodNotAllowed', ['GET', 'HEAD', 'OPTIONS']),
    ('GET', '/scan', 'MethodNotAllowed', ['OPTIONS', 'POST']),
    ('PUT', '/scan', 'MethodNotAllowed', ['OPTIONS', 'POST']),
    ('GET', '/run-scan', 'MethodNotAllowed', ['OPTIONS', 'POST']),
    ('HEAD', '/run-scan', 'MethodNotAllowed', ['OPTIONS', 'POST']),
    ('GET', '/api/get-insights', 'MethodNotAllowed', ['OPTIONS', 'POST']),
    ('GET', '/api/get-summary', 'MethodNotAllowed', ['OPTIONS', 'POST']),
    ('DELETE', '/api/get-suggestions', 'MethodNotAllowed', ['OPTIONS', 'POST']),
    ('POST', '/api/list-resources', 'MethodNotAllowed', ['GET', 'HEAD', 'OPTIONS']),
    ('POST', '/status/job-1/project/p1', 'MethodNotAllowed', ['GET', 'HEAD', 'OPTIONS']),
    ('DELETE', '/report/job-1/p1', 'MethodNotAllowed', ['GET', 'HEAD', 'OPTIONS']),
    ('GET', '/status/job-1/project', 'NotFound', []),
    ('GET', '/status/job-1/project/p1/extra', 'NotFound', []),
    ('GET', '/report/job-1', 'NotFound', []),
    ('GET', '/report/job-1/a/b', 'NotFound', []),
    ('GET', '/api/status/job-1', 'NotFound', []),
    ('GET', '/api/list-resources/', 'NotFound', []),
    ('GET', '/list-resources', 'NotFound', []),
    ('GET', '/get-summary', 'NotFound', []),
    ('POST', '/api/run-scan', 'NotFound', []),
    ('GET', '/api/', 'NotFound', []),
    ('GET', '/api', 'NotFound', []),
    ('GET', '/index.html', 'NotFound', []),
]
ERROR_PAGE_TITLES = {'MethodNotAllowed': '<title>405 Method Not Allowed</title>', 'NotFound': '<title>404 Not Found</title>'}


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


def test_the_url_map_is_pinned(testing_app):
    """Every rule, its methods and its endpoint name, exactly: a route added, removed or renamed changes this map."""
    assert url_map(testing_app) == PINNED_URL_MAP


def test_routes_table_is_complete(testing_app):
    """ROUTES lists every rule, so the tests built on it cover every route."""
    rules = {rule.rule: (set(rule.methods) - {'HEAD', 'OPTIONS'}, rule.endpoint) for rule in testing_app.url_map.iter_rules()}
    assert rules == ROUTES


def test_blueprints_and_views(testing_app):
    assert {name: bp.url_prefix for name, bp in testing_app.blueprints.items()} == {'ui': None, 'api': '/api', 'worker': None}
    for _, endpoint in ROUTES.values():
        if endpoint != 'static':
            blueprint, view = endpoint.split('.')
            assert testing_app.view_functions[endpoint] is getattr(BLUEPRINT_MODULES[blueprint], view)


@pytest.mark.parametrize('method, path, endpoint, args', MATCHING)
def test_request_reaches_the_view(method, path, endpoint, args, testing_app):
    assert resolve(testing_app, method, path) == {'endpoint': endpoint, 'args': args}


@pytest.mark.parametrize('path', sorted(WORKER_RULES))
def test_worker_routes_accept_post_only(path, testing_app):
    """The Cloud Tasks endpoints are POST-only."""
    assert resolve(testing_app, 'POST', path) == {'endpoint': ROUTES[path][1], 'args': {}}
    assert resolve(testing_app, 'GET', path) == {'error': 'MethodNotAllowed', 'allowed': ['OPTIONS', 'POST']}
    assert testing_app.test_client().get(path).status_code == 405


def test_csv_download_route(testing_app, gcp):
    """/report/<job>/<scope_id>/csv serves the stored CSV as a download: the report page links to it and, since
    v16.1, so does the status page (a signed Cloud Storage URL before). The object is streamed, with its size."""
    assert resolve(testing_app, 'GET', '/report/job-1/p1/csv') == {'endpoint': 'ui.download_report_csv', 'args': {'job_id': 'job-1', 'scope_id': 'p1'}}
    assert resolve(testing_app, 'POST', '/report/job-1/p1/csv') == {'error': 'MethodNotAllowed', 'allowed': ['GET', 'HEAD', 'OPTIONS']}
    client = testing_app.test_client()
    missing = client.get('/report/11111111-1111-4111-8111-111111111111/proj-one/csv')
    assert (missing.status_code, missing.get_data(as_text=True)) == (404, 'CSV report not found or is still generating.')
    assert gcp.bucket.opened == []
    body = 'Organization Policies\r\nCategory,Policy\r\nSécurité,—\r\n'  # non-ASCII: the size is in bytes, not characters
    gcp.bucket.put('11111111-1111-4111-8111-111111111111/proj-one_report.csv', body, 'text/csv')
    response = client.get('/report/11111111-1111-4111-8111-111111111111/proj-one/csv')
    assert response.status_code == 200
    assert response.headers['Content-Type'].startswith('text/csv')
    assert response.headers['Content-Disposition'] == 'attachment; filename="cloudgauge_proj-one_11111111-1111-4111-8111-111111111111.csv"'
    assert response.headers['Content-Length'] == str(len(body.encode()))
    assert response.get_data(as_text=True) == body
    assert gcp.bucket.opened == [('11111111-1111-4111-8111-111111111111/proj-one_report.csv', ui.CSV_CHUNK_BYTES)]
    # v18.6.1: IDs that are not a job ID and a scope ID are refused before any lookup (before, they were only sanitized in the filename).
    assert (client.get('/report/job%201/a%20b/csv').status_code, client.get('/report/11111111-1111-4111-8111-111111111111/a%20b/csv').status_code) == (400, 400)
    assert gcp.bucket.opened == [('11111111-1111-4111-8111-111111111111/proj-one_report.csv', ui.CSV_CHUNK_BYTES)]


def test_csv_download_streams_in_chunks(testing_app, gcp, monkeypatch):
    """A CSV larger than one chunk arrives whole, chunk by chunk, and the file is closed afterwards."""
    monkeypatch.setattr(ui, 'CSV_CHUNK_BYTES', 8)
    body = ''.join(f'row-{i:04d},value\r\n' for i in range(50))  # 800 bytes → 100 chunks of 8
    gcp.bucket.put('11111111-1111-4111-8111-111111111111/proj-one_report.csv', body, 'text/csv')
    files = []
    original_open = fakes.FakeBlob.open

    def recording_open(self, *args, **kwargs):
        files.append(original_open(self, *args, **kwargs))
        return files[-1]

    monkeypatch.setattr(fakes.FakeBlob, 'open', recording_open)
    with testing_app.test_client() as client:
        response = client.get('/report/11111111-1111-4111-8111-111111111111/proj-one/csv')
        chunks = list(response.response)
    assert len(chunks) == -(-len(body) // 8) == 100 and all(len(chunk) <= 8 for chunk in chunks)
    assert b''.join(chunks).decode() == body
    assert response.headers['Content-Length'] == str(len(body))
    assert gcp.bucket.opened == [('11111111-1111-4111-8111-111111111111/proj-one_report.csv', 8)]
    assert [f.closed for f in files] == [True]


def test_csv_download_reports_a_bucket_failure(testing_app, gcp):
    gcp.bucket.put('11111111-1111-4111-8111-111111111111/proj-one_report.csv', 'x', 'text/csv')
    gcp.bucket.error = RuntimeError('bucket unavailable')
    response = testing_app.test_client().get('/report/11111111-1111-4111-8111-111111111111/proj-one/csv')
    assert (response.status_code, response.get_data(as_text=True)) == (500, 'Could not retrieve the CSV report.')


@pytest.mark.parametrize('method, path, error, allowed', NOT_MATCHING)
def test_request_is_rejected(method, path, error, allowed, testing_app):
    """Routing raises the error; over HTTP it is werkzeug's error page, with the Allow header on a 405."""
    assert resolve(testing_app, method, path) == {'error': error, 'allowed': allowed}
    response = testing_app.test_client().open(path, method=method)
    assert response.status_code == (405 if error == 'MethodNotAllowed' else 404)
    assert response.mimetype == 'text/html'
    if allowed:
        assert sorted(response.headers['Allow'].split(', ')) == allowed
    else:
        assert 'Allow' not in response.headers
    assert ERROR_PAGE_TITLES[error] in response.get_data(as_text=True) or method == 'HEAD'  # a HEAD response has no body


@pytest.mark.parametrize('endpoint, values, expected', [
    ('ui.index', {}, '/'),
    ('ui.create_scan_task', {}, '/scan'),
    ('ui.get_status', {'job_id': 'job-1', 'scope': 'folder', 'scope_id': '42'}, '/status/job-1/folder/42'),
    ('ui.get_status', {'job_id': 'a b', 'scope': 'project', 'scope_id': 'x/y?z'}, '/status/a%20b/project/x/y%3Fz'),
    ('ui.view_report', {'job_id': 'job-1', 'scope_id': '42'}, '/report/job-1/42'),
    ('api.list_resources', {'scope': 'project'}, '/api/list-resources?scope=project'),
    ('api.api_check_status', {'job_id': 'job-1', 'scope_id': 'my-project'}, '/api/status/job-1/my-project'),
    ('api.get_insights', {}, '/api/get-insights'),
    ('api.get_summary', {}, '/api/get-summary'),
    ('api.get_suggestions', {}, '/api/get-suggestions'),
    ('worker.run_scan_worker', {}, '/run-scan'),
    ('static', {'filename': 'css/app.css'}, '/static/css/app.css'),
])
def test_url_for_builds_the_url(endpoint, values, expected, testing_app):
    with testing_app.test_request_context():
        assert url_for(endpoint, **values) == expected


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


def test_shim_runs_the_production_startup(import_shim, gcp, env):
    """Imported with a deployed revision's environment (what gunicorn does), the shim builds the production app: the
    startup looked the worker URL up with the Cloud Run API and created the one task queue (see test_app_factory.py
    for the queue's limits)."""
    shim = import_shim()
    assert not shim.app.testing
    assert gcp.discovery.calls == [('run', 'v1')]
    assert gcp.discovery.run_services == [f'projects/test-project/locations/us-central1/services/{fakes.K_SERVICE}']
    assert [(parent, queue['name']) for parent, queue in gcp.tasks.queues] == \
           [('projects/test-project/locations/us-central1', 'projects/test-project/locations/us-central1/queues/test-queue')]
