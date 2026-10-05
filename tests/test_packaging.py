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
"""Packaging and the entrypoint: what the container runs.

The Dockerfile runs ``gunicorn ... cloudgauge:app``. These tests start fresh
interpreters, so nothing imported by other tests hides an import-time effect:

- importing any ``app`` module does no I/O, and the core modules don't load Flask;
- ``cloudgauge.py`` builds the app when imported, and fails fast without its configuration;
- the container command (gunicorn via /bin/sh) serves the shim over real HTTP;
- ``python run.py`` serves the app locally in the development profile;
- the templates ship inside the package.
"""
import contextlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest
from jinja2 import PackageLoader

from app import create_app
from app.reporting.html_report import report_environment
from helpers import make_settings

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ['_design.css', 'index.html', 'report/_macros.html', 'report/_scorecard.html', 'report/_script.js', 'report/_styles.css',
             'report/report.html', 'status.html']
WEB_MODULES = ['app.extensions', 'app.routes', 'app.routes.api', 'app.routes.ui', 'app.routes.worker']

# Makes any network connection or GCP client creation raise.
TRAPS = '''
import socket

def _trap(*args, **kwargs):
    raise AssertionError("I/O at import time")

socket.socket.connect = socket.create_connection = socket.getaddrinfo = _trap
import google.auth
from google.cloud import asset_v1, storage, tasks_v2
from googleapiclient import discovery
google.auth.default = discovery.build = _trap
storage.Client = tasks_v2.CloudTasksClient = asset_v1.AssetServiceClient = _trap
'''

IMPORT_EVERY_MODULE = TRAPS + f'''
import importlib, json, logging, pathlib, sys
root_handlers = list(logging.getLogger().handlers)
web = {WEB_MODULES!r}
names = sorted(".".join(path.with_suffix("").parts).removesuffix(".__init__") for path in pathlib.Path("app").rglob("*.py"))
for name in names:
    if name not in web:
        importlib.import_module(name)
assert "flask" not in sys.modules, "a core module imported Flask"
for name in web:
    importlib.import_module(name)
from app.services import gcp
assert gcp._storage_client is None and gcp._tasks_client is None, "a GCP client was created"
assert logging.getLogger().handlers == root_handlers, "logging was configured at import time"
print(json.dumps(names))
'''


def run_python(code, **env):
    """Runs ``code`` in a fresh interpreter from the repo root, with only ``env`` set among the app's variables."""
    base_env = {name: os.environ[name] for name in ('PATH', 'HOME', 'SYSTEMROOT') if name in os.environ}
    result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True, encoding='utf-8',
                            timeout=120, env={**base_env, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8', **env})
    assert result.returncode == 0, f'exit {result.returncode}\n--- stdout\n{result.stdout}\n--- stderr\n{result.stderr}'
    return result.stdout.strip().splitlines()[-1]


def test_importing_app_modules_has_no_side_effects():
    modules = json.loads(run_python(IMPORT_EVERY_MODULE))
    for name in ('app', 'app.config', 'app.checks.runner', 'app.reporting.html_report', 'app.scan_job', *WEB_MODULES):
        assert name in modules


def test_shim_builds_the_app_in_the_testing_profile():
    code = 'import json, cloudgauge\nprint(json.dumps(sorted([r.rule, sorted(r.methods), r.endpoint] for r in cloudgauge.app.url_map.iter_rules())))'
    rules = json.loads(run_python(code, CLOUDGAUGE_ENV='testing'))
    expected = sorted([rule.rule, sorted(rule.methods), rule.endpoint] for rule in create_app(make_settings()).url_map.iter_rules())
    assert rules == expected
    assert len(rules) == 15  # 14 routes and static


def test_shim_fails_fast_without_configuration():
    """A revision deployed without its environment fails at import, before any GCP call (the traps would raise)."""
    code = TRAPS + '''
try:
    import cloudgauge
except RuntimeError as error:
    print(f"RuntimeError: {error}")
'''
    assert run_python(code) == ('RuntimeError: FATAL: Missing required environment variables: '
                                'PROJECT_ID, LOCATION, TASK_QUEUE, RESULTS_BUCKET, SERVICE_ACCOUNT_EMAIL')


def test_templates_ship_inside_the_package():
    def visible(names):
        return sorted(name for name in names if not name.rsplit('/', 1)[-1].startswith('.'))

    assert visible(PackageLoader('app', 'templates').list_templates()) == TEMPLATES
    assert visible(create_app(make_settings()).jinja_loader.list_templates()) == TEMPLATES
    for name in TEMPLATES:
        report_environment().get_template(name)  # compiles


# --- Serving: the container command (gunicorn) and run.py (development) ---

NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http(method, url, data=None, content_type=None):
    """Returns ``(status, content type, body)``; HTTP errors are returned, not raised."""
    request = urllib.request.Request(url, data=data, method=method, headers={'Content-Type': content_type} if content_type else {})
    try:
        with NO_PROXY.open(request, timeout=10) as response:
            return response.status, response.headers['Content-Type'], response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.headers['Content-Type'], error.read().decode()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def serving(command, port, **env):
    """Runs ``command`` from the repo root with only ``env`` (plus PATH/HOME) set.

    Yields ``(base URL, server)`` once ``GET /`` answers on 127.0.0.1:``port``;
    afterwards ``server.output`` holds everything the server printed.
    """
    base_env = {name: os.environ[name] for name in ('PATH', 'HOME') if name in os.environ}
    server = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                              env={**base_env, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8', **env})
    base = f'http://127.0.0.1:{port}'
    try:
        deadline = time.monotonic() + 90
        while True:
            if server.poll() is not None:
                pytest.fail(f'{command} exited with {server.returncode}:\n{server.communicate()[0]}')
            try:
                http('GET', f'{base}/')
                break
            except (urllib.error.URLError, OSError):
                if time.monotonic() > deadline:
                    pytest.fail(f'{command} did not start within 90 seconds')
                time.sleep(0.25)
        yield base, server
    finally:
        server.terminate()
        server.output = server.communicate(timeout=30)[0]


def assert_serves_the_app(base):
    """Requests that need no GCP call: the UI page and the routes' input validation."""
    status, content_type, body = http('GET', f'{base}/')
    assert (status, content_type) == (200, 'text/html; charset=utf-8')
    assert 'fetch(`/api/list-resources?scope=${selectedScope}`)' in body
    assert http('GET', f'{base}/api/list-resources') == (400, 'application/json', '{"error":"Scope parameter is required"}\n')
    assert http('POST', f'{base}/scan', b'scope=project&scope_id=', 'application/x-www-form-urlencoded') \
        == (400, 'text/html; charset=utf-8', 'Scope and ID are required.')
    assert http('POST', f'{base}/run-scan', b'{"scope": ', 'application/json')[0] == 400
    assert http('GET', f'{base}/api/get-summary')[0] == 405
    assert http('GET', f'{base}/no-such-page')[0] == 404


def dockerfile_lines(instruction):
    return [line.removeprefix(f'{instruction} ') for line in (ROOT / 'Dockerfile').read_text().splitlines()
            if line.startswith(f'{instruction} ')]


CONTAINER_COMMAND = 'exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 cloudgauge:app'


def test_dockerfile_command():
    """Shell-form CMD so Cloud Run's $PORT is honored; ``exec`` makes gunicorn PID 1, so it gets SIGTERM."""
    assert dockerfile_lines('CMD') == [CONTAINER_COMMAND]
    assert dockerfile_lines('ENTRYPOINT') == []  # `docker run IMAGE <command>` and Dockerfile.test can replace it
    dockerfile = (ROOT / 'Dockerfile').read_text()
    assert 'PORT=8080' in dockerfile  # the default for `docker run` without -e PORT (Cloud Run always sets it)
    assert 'COPY app ./app' in dockerfile and 'COPY cloudgauge.py .' in dockerfile
    assert 'COPY . .' not in dockerfile  # tests, run.py, and dev files stay out of the image
    assert '\nUSER cloudgauge\n' in dockerfile


def test_container_command_serves_the_shim():
    """The Dockerfile's CMD, run by /bin/sh as in the container, in the testing profile.

    The only change is the bind address: 127.0.0.1:$PORT instead of all interfaces.
    """
    pytest.importorskip('gunicorn')
    command = CONTAINER_COMMAND.replace('--bind :$PORT', '--bind 127.0.0.1:$PORT') \
                               .replace('exec gunicorn', f'exec {sys.executable} -m gunicorn')
    port = free_port()
    with serving(['/bin/sh', '-c', command], port, PORT=str(port), CLOUDGAUGE_ENV='testing') as (base, server):
        assert_serves_the_app(base)
    assert 'Booting worker' in server.output, server.output
    assert f'Listening at: http://127.0.0.1:{port}' in server.output  # $PORT was expanded
    assert f'[{server.pid}] [INFO] Starting gunicorn' in server.output  # exec: gunicorn replaced the shell


# --- run.py ---

RUN_PY_CALLS = TRAPS + '''
import json, flask
calls = []
flask.Flask.run = lambda self, **kwargs: calls.append([self.config["CLOUDGAUGE_PROFILE"], kwargs])
import run
assert calls == [] and not hasattr(run, "app"), "importing run.py built or started the app"
run.main()
print(json.dumps(calls))
'''


@pytest.mark.parametrize('env, expected', [
    ({}, ['development', {'host': '127.0.0.1', 'port': 8080, 'debug': True}]),
    ({'HOST': '0.0.0.0', 'PORT': '9000', 'FLASK_DEBUG': '0'}, ['development', {'host': '0.0.0.0', 'port': 9000, 'debug': False}]),
    ({'CLOUDGAUGE_ENV': 'testing', 'FLASK_DEBUG': 'false'}, ['testing', {'host': '127.0.0.1', 'port': 8080, 'debug': False}]),
])
def test_run_py_configuration(env, expected):
    """Importing run.py does nothing; main() builds the app (development profile by default) without any
    GCP call (the traps would raise) and serves it on localhost with the debugger, unless configured otherwise."""
    assert json.loads(run_python(RUN_PY_CALLS, **env)) == [expected]


def test_run_py_serves_the_app_without_gcp_configuration():
    """``python run.py`` with no GCP variables at all: the development server starts and serves the UI."""
    port = free_port()
    with serving([sys.executable, 'run.py'], port, PORT=str(port), FLASK_DEBUG='0') as (base, server):
        assert_serves_the_app(base)
    assert "CloudGauge 'development' profile: skipping startup checks" in server.output, server.output
    assert f'Running on http://127.0.0.1:{port}' in server.output


# --- Container files ---

def requirement_lines(name):
    return [line.split('#')[0].strip() for line in (ROOT / name).read_text().splitlines()
            if line.split('#')[0].strip()]


def test_requirements_are_pinned_and_use_google_genai():
    requirements = requirement_lines('requirements.txt')
    assert all('==' in line for line in requirements), requirements
    names = {line.split('==')[0].lower() for line in requirements}
    assert {'flask', 'gunicorn', 'google-genai', 'google-cloud-storage', 'google-cloud-tasks'} <= names
    assert 'google-cloud-aiplatform' not in names  # vertexai.generative_models is deprecated
    # Test and lint tools are dev-only.
    dev = requirement_lines('requirements-dev.txt')
    assert dev[0] == '-r requirements.txt'
    dev_names = {line.split('==')[0].lower() for line in dev[1:]}
    assert {'pytest', 'ruff'} <= dev_names and not dev_names & names


def ignore_patterns(name):
    return {line.strip() for line in (ROOT / name).read_text().splitlines() if line.strip() and not line.startswith('#')}


def test_build_contexts():
    """The app image's context leaves out VCS, caches, venvs, tests and tools; the test image's keeps tests/ and tools/."""
    app_context = ignore_patterns('.dockerignore')
    assert {'.git/', '.venv/', '**/__pycache__/', 'tests/', 'tools/', 'run.py'} <= app_context
    for needed in ('app/', 'app', 'cloudgauge.py', 'requirements.txt', 'Dockerfile'):
        assert needed not in app_context
    test_context = ignore_patterns('Dockerfile.test.dockerignore')
    assert {'.git/', '.venv/', '**/__pycache__/'} <= test_context
    for needed in ('tests/', 'tools/', 'run.py', 'pytest.ini', 'requirements-dev.txt', 'Dockerfile',
                   '.dockerignore', 'Dockerfile.test.dockerignore'):
        assert needed not in test_context
    assert 'COPY tools ./tools' in (ROOT / 'Dockerfile.test').read_text()  # test_synthetic.py imports the harness


def test_app_needs_neither_vertexai_nor_aiplatform():
    """With both made unimportable, every module imports and the app builds."""
    code = '''
import sys
sys.modules["vertexai"] = sys.modules["google.cloud.aiplatform"] = None
''' + IMPORT_EVERY_MODULE + '''
import cloudgauge
print("ok")
'''
    assert run_python(code, CLOUDGAUGE_ENV='testing') == 'ok'
