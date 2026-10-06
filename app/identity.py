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
"""Who is signed in: the identity Identity-Aware Proxy puts on the request, verified.

Behind IAP every request carries ``X-Goog-IAP-JWT-Assertion``: a JWT that IAP
signs (ES256) with ``iss`` ``https://cloud.google.com/iap``, ``aud``
``/projects/NUMBER/locations/REGION/services/SERVICE`` (the same value on a
revision tag URL), the signed-in ``email`` and a ten-minute ``exp``. The email
is read from the verified assertion only — never from the plain
``X-Goog-Authenticated-User-Email`` header — so a service that is reachable
without IAP cannot be told a name. Without the header (a public deployment, a
local run, the tests) nobody is signed in: ``current_user_email()`` is None,
the pages say nothing and scans have no *Requested by*.

The verifier keeps IAP's public keys for an hour and refetches them once when
an assertion names a key it does not have. The project number the audience
needs is ``PROJECT_NUMBER`` or, on Cloud Run, the metadata server's (read once).
Without it an assertion cannot be verified and counts as absent, with one
warning in the log.
"""
import logging
import threading
import time

from flask import g, has_request_context, request
from google.auth import jwt as google_jwt

IAP_ASSERTION_HEADER = "X-Goog-IAP-JWT-Assertion"
IAP_ISSUER = "https://cloud.google.com/iap"
IAP_PUBLIC_KEYS_URL = "https://www.gstatic.com/iap/verify/public_key"
METADATA_PROJECT_NUMBER_URL = "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id"
KEYS_TTL_SECONDS = 3600
FETCH_TIMEOUT_SECONDS = 5
# Cloud Run's clock and IAP's agree; a little skew tolerance keeps a just-issued assertion from failing ``iat``.
CLOCK_SKEW_SECONDS = 10


def expected_audience(project_number, location, service):
    """The ``aud`` IAP puts in its assertions for a Cloud Run service."""
    return f"/projects/{project_number}/locations/{location}/services/{service}"


def fetch_public_keys():
    """IAP's current signing keys: key ID → public key in PEM form."""
    import requests

    response = requests.get(IAP_PUBLIC_KEYS_URL, timeout=FETCH_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def fetch_metadata_project_number():
    """The project number from the Cloud Run metadata server."""
    import requests

    response = requests.get(METADATA_PROJECT_NUMBER_URL, headers={"Metadata-Flavor": "Google"}, timeout=FETCH_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.text.strip()


class IapVerifier:
    """Verifies the IAP assertions addressed to one service.

    ``fetch_keys`` and ``fetch_project_number`` default to the real lookups;
    tests inject their own. ``now`` is ``time.time`` (the key cache's clock).
    """

    def __init__(self, settings, fetch_keys=None, fetch_project_number=None, now=None):
        self.settings = settings
        self._fetch_keys = fetch_keys or fetch_public_keys
        self._fetch_project_number = fetch_project_number or fetch_metadata_project_number
        self._now = now or time.time
        self._keys = None
        self._keys_fetched_at = 0.0
        self._project_number = settings.project_number
        self._warned_no_audience = False
        self._lock = threading.Lock()

    def audience(self):
        """The audience this service's assertions must carry, or None when it cannot be built."""
        if not self._project_number:
            with self._lock:
                if not self._project_number:
                    try:
                        self._project_number = (self._fetch_project_number() or "").strip() or None
                    except Exception as e:  # noqa: BLE001 - any failure means "unknown"; the caller treats it as absent
                        self._warn_once(f"could not read the project number from the metadata server ({e}); "
                                        "set PROJECT_NUMBER to verify IAP identities")
        if not (self._project_number and self.settings.location and self.settings.k_service):
            self._warn_once("the audience needs PROJECT_NUMBER (or the metadata server), LOCATION and K_SERVICE")
            return None
        return expected_audience(self._project_number, self.settings.location, self.settings.k_service)

    def keys(self, refresh=False):
        """IAP's public keys, cached for ``KEYS_TTL_SECONDS``; ``refresh`` fetches them again now."""
        with self._lock:
            stale = self._keys is None or self._now() - self._keys_fetched_at > KEYS_TTL_SECONDS
            if refresh or stale:
                self._keys = dict(self._fetch_keys())
                self._keys_fetched_at = self._now()
            return self._keys

    def verify(self, assertion):
        """The assertion's claims if IAP signed it for this service and it is current; else None.

        Rejections are logged with their reason (the assertion itself is not).
        """
        audience = self.audience()
        if audience is None:
            return None
        try:
            key_id = google_jwt.decode_header(assertion).get("kid")
            keys = self.keys()
            if key_id and key_id not in keys:
                keys = self.keys(refresh=True)  # IAP rotates its keys; one refetch covers a rotation
            claims = google_jwt.decode(assertion, certs=keys, audience=audience, clock_skew_in_seconds=CLOCK_SKEW_SECONDS)
        except Exception as e:  # noqa: BLE001 - ValueError from google-auth, or the key fetch failed
            logging.warning(f"IAP assertion rejected: {e}")
            return None
        if claims.get("iss") != IAP_ISSUER:
            logging.warning(f"IAP assertion rejected: issuer {claims.get('iss')!r} is not {IAP_ISSUER}")
            return None
        if not claims.get("email"):
            logging.warning("IAP assertion rejected: no email claim")
            return None
        return claims

    def email_from(self, headers):
        """The verified email of the request with ``headers``, or None when there is no assertion or it fails."""
        assertion = headers.get(IAP_ASSERTION_HEADER)
        if not assertion:
            return None
        claims = self.verify(assertion)
        return claims["email"] if claims else None

    def _warn_once(self, reason):
        if not self._warned_no_audience:
            self._warned_no_audience = True
            logging.warning(f"IAP identities cannot be verified: {reason}.")


def current_user_email():
    """The verified email of the person behind the current request, or None.

    Computed once per request (``flask.g``); None outside a request.
    """
    if not has_request_context():
        return None
    if "cloudgauge_user_email" not in g:
        from app.extensions import get_services

        g.cloudgauge_user_email = get_services().get_identity_verifier().email_from(request.headers)
    return g.cloudgauge_user_email
