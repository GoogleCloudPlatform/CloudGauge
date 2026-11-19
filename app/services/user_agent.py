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
"""API attribution (v18.8.1): the client identifier CloudGauge adds to the user agent of its Google Cloud API calls.

CloudGauge runs inside the deploying project and sends nothing anywhere: no finding, no
resource configuration, no organization metadata leaves it. What it does do, unless
``CLOUDGAUGE_DISABLE_ATTRIBUTION`` turns it off, is append a static identifier —
``cloud-solutions/cloudgauge-v<release>`` — to the SDK ``User-Agent`` header of the
standard Google Cloud API calls a scan makes, so that aggregate adoption of the open-source
solution can be measured on Google's side from API usage alone. The identifier carries the
release and nothing else.

One helper per SDK family, all read by ``app.services.gcp`` and ``app.services.gemini``:

- :func:`client_info` — ``google-cloud-*`` clients (Storage, Cloud Tasks, Asset
  Inventory, Recommender, OS Config): ``client_info=``. On a gRPC client that
  reaches the ``x-goog-api-client`` metadata only; the ``user-agent`` header of
  the calls — what the API front end records — is the channel's, so
- :func:`grpc_transport` — the gRPC GAPIC clients: a transport factory whose
  channel carries the identifier as its primary user agent (``transport=``).
- :func:`authorized_http` — ``google-api-python-client`` Discovery services: the
  authorized ``httplib2`` transport with the agent set (``discovery.build`` takes
  ``http`` *or* ``credentials``, never both).
- :func:`genai_http_options` — the ``google-genai`` client for Vertex AI.
- :func:`request_headers` — the one plain ``requests`` call to a Google API.
"""
import re

import google_auth_httplib2
import requests
from google.api_core.gapic_v1.client_info import ClientInfo
from googleapiclient import http as google_http

from app.config import VERSION, get_settings

# The identifier: the solution token Google's API analytics key on, the release behind it. A user-agent product token
# may hold letters, digits, ``.``, ``_``, ``-`` and ``/`` and no space; the release ("18.8.1") already fits, the
# substitution keeps it so if the format ever changes.
ATTRIBUTION_PREFIX = "cloud-solutions/cloudgauge-v"
SAFE_VERSION = re.sub(r"[^0-9A-Za-z._\-/]", "-", VERSION)
USER_AGENT = f"{ATTRIBUTION_PREFIX}{SAFE_VERSION}"


def attribution_enabled():
    """Whether the identifier is sent: ``CLOUDGAUGE_DISABLE_ATTRIBUTION`` unset or off."""
    return get_settings().attribution


def client_info():
    """``ClientInfo`` for a ``google-cloud-*`` client, or ``None`` when attribution is off (the client's default agent)."""
    return ClientInfo(user_agent=USER_AGENT) if attribution_enabled() else None


def authorized_http(credentials):
    """The transport for ``discovery.build(http=...)``: ``credentials`` on a fresh ``httplib2`` instance (what ``discovery.build``
    builds itself from ``credentials=``) with the agent set on every request; ``None`` when attribution is off or there are no
    credentials, in which case the caller passes ``credentials=`` as before."""
    if credentials is None or not attribution_enabled():
        return None
    http = google_auth_httplib2.AuthorizedHttp(credentials, http=google_http.build_http())
    return google_http.set_user_agent(http, USER_AGENT)


def grpc_transport(transport_class):
    """A ``transport=`` for a gRPC GAPIC client: the client calls it with its resolved endpoint, credentials and ``client_info``, and the
    transport's channel is created with the identifier as ``grpc.primary_user_agent`` — the start of the ``user-agent`` the API records
    (``client_info`` alone reaches the ``x-goog-api-client`` metadata of a gRPC call). ``None`` when attribution is off: the client's default."""
    if not attribution_enabled():
        return None

    def channel(host, **kwargs):
        options = list(kwargs.pop("options", None) or []) + [("grpc.primary_user_agent", USER_AGENT)]
        return transport_class.create_channel(host, options=options, **kwargs)

    def transport(**kwargs):
        return transport_class(channel=channel, **kwargs)
    return transport


def genai_http_options():
    """``http_options`` for ``google.genai.Client``: the agent under the lower-case key the SDK merges its own label into (an
    upper-case ``User-Agent`` would travel beside the SDK's, not with it); ``None`` when attribution is off."""
    return {"headers": {"user-agent": USER_AGENT}} if attribution_enabled() else None


def request_headers(headers=None):
    """``headers`` for a plain ``requests`` call to a Google API, with the agent in front of the one they carry (or ``requests``' own)."""
    merged = dict(headers or {})
    if attribution_enabled():
        existing = next((merged.pop(key) for key in list(merged) if key.lower() == "user-agent"), None) or requests.utils.default_user_agent()
        merged["User-Agent"] = f"{USER_AGENT} {existing}".strip()
    return merged
