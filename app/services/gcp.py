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

v18.8.1: every client the real provider builds carries the solution's client
identifier in its user agent (``app.services.user_agent``), unless
``CLOUDGAUGE_DISABLE_ATTRIBUTION`` is set — the Discovery services through an
authorized transport with the agent set (``discovery.build`` takes ``http`` or
``credentials``, never both), the ``google-cloud-*`` clients through
``client_info`` — and, for the gRPC ones, a transport whose channel carries it
as its primary user agent — the one plain ``requests`` call through its headers.
"""
import pathlib
import threading

import google.auth
import requests
from google.cloud import asset_v1, osconfig_v1, recommender_v1, storage, tasks_v2
from google.cloud.asset_v1.services.asset_service.transports.grpc import AssetServiceGrpcTransport
from google.cloud.osconfig_v1.services.os_config_zonal_service.transports.grpc import OsConfigZonalServiceGrpcTransport
from google.cloud.recommender_v1.services.recommender.transports.grpc import RecommenderGrpcTransport
from google.cloud.tasks_v2.services.cloud_tasks.transports.grpc import CloudTasksGrpcTransport
from googleapiclient import discovery

from app.services import user_agent

_client_lock = threading.Lock()
_storage_client = None
_tasks_client = None


class RealGcp:
    """The default provider: every method calls the Google library at call time."""

    name = "real"

    def auth_default(self, scopes=None, **kwargs):
        return google.auth.default(scopes=scopes, **kwargs)

    def api_build(self, serviceName, version, **kwargs):
        """``discovery.build`` with the client identifier: ``credentials`` become an authorized transport carrying it (``http=``);
        without credentials, or with attribution off, the call is passed through as given."""
        http = user_agent.authorized_http(kwargs.get("credentials"))
        if http is not None:
            kwargs = {key: value for key, value in kwargs.items() if key != "credentials"}
            return discovery.build(serviceName, version, http=http, **kwargs)
        return discovery.build(serviceName, version, **kwargs)

    def project_storage_client(self, project_id):
        return storage.Client(project=project_id, client_info=user_agent.client_info())

    def asset_client(self, credentials=None):
        return asset_v1.AssetServiceClient(credentials=credentials, client_info=user_agent.client_info(), transport=user_agent.grpc_transport(AssetServiceGrpcTransport))

    def recommender_client(self, credentials=None):
        return recommender_v1.RecommenderClient(credentials=credentials, client_info=user_agent.client_info(), transport=user_agent.grpc_transport(RecommenderGrpcTransport))

    def osconfig_client(self):
        return osconfig_v1.OsConfigZonalServiceClient(client_info=user_agent.client_info(), transport=user_agent.grpc_transport(OsConfigZonalServiceGrpcTransport))

    def http_get(self, url, **kwargs):
        """``requests.get``; a call to a Google API carries the client identifier (the policy table's GitHub URL does not)."""
        if ".googleapis.com/" in str(url):
            kwargs = {**kwargs, "headers": user_agent.request_headers(kwargs.get("headers"))}
        return requests.get(url, **kwargs)

    def policy_table(self):
        """The policy table shipped with the release (v18.1): ``assets/gcp_best_practices.csv`` next to the ``app`` package."""
        return BUNDLED_POLICY_TABLE_PATH.read_text(encoding="utf-8")


# assets/gcp_best_practices.csv: in the repository root, and copied next to the app package in the image (Dockerfile).
BUNDLED_POLICY_TABLE_PATH = pathlib.Path(__file__).resolve().parents[2] / "assets" / "gcp_best_practices.csv"
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
    """``requests.get``: an https:// policy table and the Service Health REST call."""
    return _provider.http_get(url, **kwargs)


def policy_table():
    """The text of the policy table shipped with the release (the synthetic provider answers its own small table)."""
    return _provider.policy_table()


# --- Infrastructure clients (shared, never replaced by a provider) ---

def storage_client():
    """Returns the shared ``storage.Client`` for the results bucket, creating it on first use."""
    global _storage_client
    if _storage_client is None:
        with _client_lock:
            if _storage_client is None:
                _storage_client = storage.Client(client_info=user_agent.client_info())
    return _storage_client


def tasks_client():
    """Returns the shared ``tasks_v2.CloudTasksClient``, creating it on first use."""
    global _tasks_client
    if _tasks_client is None:
        with _client_lock:
            if _tasks_client is None:
                _tasks_client = tasks_v2.CloudTasksClient(client_info=user_agent.client_info(), transport=user_agent.grpc_transport(CloudTasksGrpcTransport))
    return _tasks_client


def reset_clients():
    """Drops the shared clients so the next call creates new ones (for tests)."""
    global _storage_client, _tasks_client
    with _client_lock:
        _storage_client = None
        _tasks_client = None
