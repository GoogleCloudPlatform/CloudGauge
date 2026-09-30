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
"""Shared fixtures.

- ``gcp``: in-memory GCP fakes (``fakes.FakeGcp``), patched in for one test.
- ``env``: the environment of a deployed Cloud Run revision.
- ``legacy``: the frozen pre-refactor module (``tests/legacy/cloudgauge_legacy.py``),
  imported once per session with fakes, then pointed at each test's ``gcp``.
- ``prod_app``: what gunicorn serves, ``create_app()`` in the production profile.
  The startup sequence runs against ``gcp``.
- ``testing_app``: ``create_app()`` in the testing profile (no startup calls).

Parity tests send the same request to ``legacy_client`` and ``client``. Both
apps use the same fakes.
"""
import sys
from types import SimpleNamespace

import pytest

import fakes
from app import create_app
from app.services import gcp as gcp_clients
from app.services import gemini as gemini_service
from helpers import BETA_V1_PATH, DEPLOYED_ENV, LEGACY_PATH, import_legacy, set_env


@pytest.fixture
def env(monkeypatch):
    """The five required environment variables plus K_SERVICE; nothing else the app reads."""
    set_env(monkeypatch, DEPLOYED_ENV)
    return dict(DEPLOYED_ENV)


@pytest.fixture
def gcp(monkeypatch):
    """This test's GCP fakes. The shared Storage and Tasks clients are created from them on first use."""
    fake = fakes.FakeGcp()
    fake.install(monkeypatch)
    monkeypatch.setattr(gemini_service, 'get_client', fake.gemini.client)
    gemini_service.reset_model_cache()
    gcp_clients.reset_clients()
    yield fake
    gcp_clients.reset_clients()
    gemini_service.reset_model_cache()


def _import_frozen(module_name, path):
    """Imports a frozen module with fakes. ``startup`` holds the fakes that its import-time startup used."""
    with pytest.MonkeyPatch.context() as mp:
        set_env(mp, DEPLOYED_ENV)
        startup = fakes.FakeGcp()
        startup.install(mp)
        module = import_legacy(module_name, path)
    return SimpleNamespace(module=module, startup=startup)


def _repoint(module, gcp, monkeypatch):
    """Points a frozen module at this test's fakes.

    The module created or imported these by name at import time, so they
    still refer to the session's startup fakes (or the vertexai stub).
    """
    monkeypatch.setattr(module, 'storage_client', gcp.storage)
    monkeypatch.setattr(module, 'tasks_client', gcp.tasks)
    monkeypatch.setattr(module, 'google_auth_default', gcp.auth_default)
    monkeypatch.setattr(module, 'google_api_build', gcp.discovery)
    monkeypatch.setattr(module, 'vertexai', SimpleNamespace(init=gcp.gemini.init))
    monkeypatch.setattr(module, 'GenerativeModel', gcp.gemini.model_class)
    return module


@pytest.fixture(scope='session')
def legacy_import():
    """Imports the legacy module once."""
    yield _import_frozen('cloudgauge_legacy', LEGACY_PATH)
    sys.modules.pop('cloudgauge_legacy', None)


@pytest.fixture
def legacy(legacy_import, gcp, env, monkeypatch):
    """The legacy module, re-pointed at this test's fakes."""
    return _repoint(legacy_import.module, gcp, monkeypatch)


@pytest.fixture(scope='session')
def beta_import():
    """Imports the frozen upstream beta v1 module once (the reference for the four checks it added)."""
    yield _import_frozen('cloudgauge_beta_v1', BETA_V1_PATH)
    sys.modules.pop('cloudgauge_beta_v1', None)


@pytest.fixture
def beta(beta_import, gcp, env, monkeypatch):
    """The beta v1 module, re-pointed at this test's fakes."""
    return _repoint(beta_import.module, gcp, monkeypatch)


@pytest.fixture
def prod_app(gcp, env):
    """``create_app()`` with a deployed revision's environment (production profile)."""
    return create_app()


@pytest.fixture
def testing_app(gcp, env, monkeypatch):
    monkeypatch.setenv('CLOUDGAUGE_ENV', 'testing')
    return create_app()


@pytest.fixture
def client(prod_app):
    return prod_app.test_client()


@pytest.fixture
def legacy_client(legacy):
    return legacy.app.test_client()
