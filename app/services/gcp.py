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

Call sites use ``gcp.auth_default(...)`` and ``gcp.api_build(...)`` through this
module rather than importing the functions. That way tests can patch either this
module or the underlying libraries, regardless of import order.

- Discovery clients are built on every call, because ``httplib2`` is not
  thread-safe and the checks run on a thread pool.
- The Storage and Cloud Tasks clients are shared by the whole process, like the
  legacy module-level clients. They are created on first use, under a lock, so
  that importing the package never creates a client.
"""
import threading

import google.auth
from google.cloud import storage, tasks_v2
from googleapiclient import discovery

_client_lock = threading.Lock()
_storage_client = None
_tasks_client = None


def auth_default(scopes=None, **kwargs):
    """Pass-through to ``google.auth.default``; returns ``(credentials, project_id)``."""
    return google.auth.default(scopes=scopes, **kwargs)


def api_build(serviceName, version, **kwargs):
    """Pass-through to ``googleapiclient.discovery.build``; returns a new client."""
    return discovery.build(serviceName, version, **kwargs)


def storage_client():
    """Returns the shared ``storage.Client``, creating it on first use."""
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
