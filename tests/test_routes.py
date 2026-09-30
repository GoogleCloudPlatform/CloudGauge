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
}
NEW_ENDPOINT = {legacy: new for _, legacy, new in ROUTES.values()}
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
    legacy_map = url_map(legacy.app)
    assert url_map(testing_app) == {key: NEW_ENDPOINT[endpoint] for key, endpoint in legacy_map.items()}


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
    assert gcp.tasks.queues == startup.tasks.queues
    assert len(gcp.tasks.queues) == 1
