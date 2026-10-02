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
"""Late-bound access to Google Cloud auth and clients.

Call sites use ``gcp.auth_default(...)``, ``gcp.api_build(...)`` and the client
factories below through this module rather than importing the libraries. That
way tests can patch either this module or the underlying libraries, regardless
of import order, and the synthetic load mode (``app.synthetic``) can stand in
for every API the checks call without touching the checks.

Two kinds of clients:

- **Data-plane clients** (everything the checks and discovery call: Discovery
  APIs, per-project Storage, Asset Inventory, Recommender, OS Config, plain
  HTTP GET) go through the installed *provider*. The default provider,
  :class:`RealGcp`, calls the libraries at call time. ``install_provider``
  swaps in another one (the synthetic provider); ``reset_provider`` restores
  the real one.
- **Infrastructure clients** (the results bucket's ``storage.Client`` and the
  Cloud Tasks client) are shared by the whole process, like the legacy
  module-level clients, and are never replaced by a provider. They are created
  on first use, under a lock, so that importing the package never creates a
  client.

Discovery clients are built on every call, because ``httplib2`` is not
thread-safe and the checks run on a thread pool.
"""
import threading

import google.auth
import requests
from google.cloud import asset_v1, osconfig_v1, recommender_v1, storage, tasks_v2
from googleapiclient import discovery

_client_lock = threading.Lock()
_storage_client = None
_tasks_client = None


class RealGcp:
    """The default provider: every method calls the Google library at call time."""

    name = "real"

    def auth_default(self, scopes=None, **kwargs):
        return google.auth.default(scopes=scopes, **kwargs)

    def api_build(self, serviceName, version, **kwargs):
        return discovery.build(serviceName, version, **kwargs)

    def project_storage_client(self, project_id):
        return storage.Client(project=project_id)

    def asset_client(self, credentials=None):
        return asset_v1.AssetServiceClient(credentials=credentials)

    def recommender_client(self, credentials=None):
        return recommender_v1.RecommenderClient(credentials=credentials)

    def osconfig_client(self):
        return osconfig_v1.OsConfigZonalServiceClient()

    def http_get(self, url, **kwargs):
        return requests.get(url, **kwargs)


_real_provider = RealGcp()
_provider = _real_provider


def install_provider(provider):
    """Routes the data-plane factories through ``provider`` (see ``app.synthetic``)."""
    global _provider
    _provider = provider


def reset_provider():
    """Restores the real provider."""
    global _provider
    _provider = _real_provider


def current_provider():
    """Returns the installed provider (``RealGcp`` unless one was installed)."""
    return _provider


# --- Data-plane factories (go through the provider) ---

def auth_default(scopes=None, **kwargs):
    """Pass-through to ``google.auth.default``; returns ``(credentials, project_id)``."""
    return _provider.auth_default(scopes=scopes, **kwargs)


def api_build(serviceName, version, **kwargs):
    """Pass-through to ``googleapiclient.discovery.build``; returns a new client."""
    return _provider.api_build(serviceName, version, **kwargs)


def project_storage_client(project_id):
    """``storage.Client(project=project_id)``: lists and inspects a scanned project's buckets."""
    return _provider.project_storage_client(project_id)


def asset_client(credentials=None):
    """A Cloud Asset Inventory client (``asset_v1.AssetServiceClient``)."""
    return _provider.asset_client(credentials=credentials)


def recommender_client(credentials=None):
    """A Recommender client (``recommender_v1.RecommenderClient``)."""
    return _provider.recommender_client(credentials=credentials)


def osconfig_client():
    """An OS Config client (``osconfig_v1.OsConfigZonalServiceClient``)."""
    return _provider.osconfig_client()


def http_get(url, **kwargs):
    """``requests.get``: the best-practices CSV and the Service Health REST call."""
    return _provider.http_get(url, **kwargs)


# --- Infrastructure clients (shared, never replaced by a provider) ---

def storage_client():
    """Returns the shared ``storage.Client`` for the results bucket, creating it on first use."""
    global _storage_client
    if _storage_client is None:
        with _client_lock:
            if _storage_client is None:
                _storage_client = storage.Client()
    return _storage_client


def tasks_client():
    """Returns the shared ``tasks_v2.CloudTasksClient``, creating it on first use."""
    global _tasks_client
    if _tasks_client is None:
        with _client_lock:
            if _tasks_client is None:
                _tasks_client = tasks_v2.CloudTasksClient()
    return _tasks_client


def reset_clients():
    """Drops the shared clients so the next call creates new ones (for tests)."""
    global _storage_client, _tasks_client
    with _client_lock:
        _storage_client = None
        _tasks_client = None
