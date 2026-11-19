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
- ``prod_app``: what gunicorn serves, ``create_app()`` in the production profile.
  The startup sequence runs against ``gcp``.
- ``testing_app``: ``create_app()`` in the testing profile (no startup calls).
- ``client``: ``prod_app``'s test client, which the route and worker tests
  send their requests to.
"""
import pytest

import fakes
from app import create_app
from app.services import gcp as gcp_clients
from app.services import gemini as gemini_service
from helpers import DEPLOYED_ENV, set_env


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
    gcp_clients.reset_provider()
    yield fake
    gcp_clients.reset_clients()
    gcp_clients.reset_provider()
    gemini_service.reset_model_cache()


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
