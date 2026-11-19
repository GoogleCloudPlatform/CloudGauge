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
"""Request guards the blueprints run before their handlers (v18.6.1).

Two of them:

- **Same origin** for the pages' and the API's POST routes (``POST /scan``, the three
  ``/api/get-*`` endpoints). Identity-Aware Proxy says *who* is in the browser, not *which
  page* made the request: a form on another site could still post a scan as the operator
  (cross-site request forgery). Browsers label every request with ``Sec-Fetch-Site``; it must
  read ``same-origin`` (the pages and reports this service serves) or ``none`` (the person
  typed or bookmarked it). Without that header the ``Origin`` is checked, then the ``Referer``
  — their host must be this service's. A request with none of the three (``curl``, a script)
  is allowed: it has no victim's browser behind it. Refused requests get **403**.

- **The caller** of the worker routes (``/run-scan``, ``/scan-shard``, ``/run-aggregation``,
  ``/sweep``, ``/scheduled-scan``). Cloud Tasks and Cloud Scheduler call them with the service
  account's OIDC token; Cloud Run's IAM check is what keeps everyone else out of the worker
  service — and Cloud Run hands the ``Authorization`` header on to the container, so the token
  is verified here too (``app.identity.CallerVerifier``): defence in depth behind IAM, and the
  only guard when the single-service public mode is used. A missing or wrong token gets **401**.
  The check runs in the ``production`` and ``synthetic`` profiles (both receive real tasks) unless
  ``WORKER_TOKEN_CHECK=off``; ``testing`` and ``development`` skip it.
"""
import logging
from urllib.parse import urlsplit

from flask import jsonify, request

from app.extensions import get_services

ALLOWED_FETCH_SITES = ("same-origin", "none")


def cross_site_reason(headers, host):
    """Why the request is cross-site, or ``None`` when it is not (or cannot be a browser's)."""
    site = headers.get("Sec-Fetch-Site")
    if site:
        return None if site in ALLOWED_FETCH_SITES else f"Sec-Fetch-Site is {site}"
    for name in ("Origin", "Referer"):
        value = headers.get(name)
        if not value:
            continue
        if value == "null":
            return f"{name} is null"
        sender = urlsplit(value).netloc.lower()
        return None if sender == host.lower() else f"{name} host {sender!r} is not {host.lower()!r}"
    return None


def same_origin_required():
    """``before_request`` of the ``ui`` and ``api`` blueprints: a cross-site POST is refused with 403."""
    if request.method != "POST":
        return None
    reason = cross_site_reason(request.headers, request.host)
    if reason is None:
        return None
    logging.warning(f"Cross-site {request.method} {request.path} refused: {reason}.")
    message = "This request did not come from a CloudGauge page (cross-site requests are refused)."
    if request.blueprint == "api" or request.is_json:
        return jsonify({"error": message}), 403
    return message, 403


def worker_caller_required():
    """``before_request`` of the ``worker`` blueprint: the service account's ID token, or 401."""
    services = get_services()
    settings = services.settings
    if not settings.worker_token_check or not (settings.is_production or settings.is_synthetic):
        return None
    token = bearer_token(request.headers.get("Authorization"))
    if not token:
        logging.warning(f"{request.method} {request.path} refused: no bearer token.")
        return jsonify({"error": "The worker accepts the service account's ID token only."}), 401
    verifier = services.get_caller_verifier()
    if verifier.verify(token, audiences=request_audiences(services)) is None:
        return jsonify({"error": "The worker accepts the service account's ID token only."}), 401
    return None


def bearer_token(header):
    """The token of an ``Authorization: Bearer <token>`` header, or ``None``."""
    if not header:
        return None
    scheme, _, token = header.strip().partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def request_audiences(services):
    """The audiences a token for this request may carry.

    ``WORKER_AUDIENCE`` when set (what Cloud Tasks mints when told); the worker's own URL, bare (what Cloud Scheduler
    jobs carry) and with the request's path (what Cloud Tasks mints when not told: the task URL); and the request's own
    URL with and without its path, under the scheme the front put in ``X-Forwarded-Proto`` (Cloud Run speaks plain HTTP
    to the container) as well as the one Flask sees. The worker URL lookup can fail outside Cloud Run; then the request's
    URLs stand alone. Each audience is accepted with and without a trailing slash.
    """
    audiences = []
    if services.settings.worker_audience:
        audiences.append(services.settings.worker_audience)
    try:
        worker_url = services.get_worker_url().rstrip("/")
        audiences.extend((worker_url, worker_url + request.path))
    except Exception as e:  # noqa: BLE001 - self-discovery needs the metadata server
        logging.warning(f"The worker's own URL is unknown ({e}); accepting the request's URL as the audience.")
    for scheme in dict.fromkeys((request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip() or request.scheme, request.scheme)):
        origin = f"{scheme}://{request.host}"
        audiences.extend((origin, origin + request.path))
    seen = {}
    for audience in audiences:
        if audience:
            bare = audience.rstrip("/")
            seen.setdefault(bare, None)
            seen.setdefault(bare + "/", None)
    return tuple(seen)
