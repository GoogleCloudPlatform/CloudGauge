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
"""Resolves the public URL that Cloud Tasks calls back (``{url}/run-scan``)."""
import logging

from app.config import SCOPES
from app.services import gcp


def discover_self_url(settings):
    """
    (NEW) Dynamically discovers the public URL of the Cloud Run service itself.
    This avoids the need to manually set WORKER_URL during deployment.
    """
    # Cloud Run automatically injects the K_SERVICE environment variable
    service_name = settings.k_service
    if not service_name:
        raise RuntimeError("K_SERVICE environment variable not found. Cannot auto-discover URL. Please set WORKER_URL manually.")

    print(f"🚀 Auto-discovering URL for service: {service_name}...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        # Use the Cloud Run Admin API
        run_service = gcp.api_build('run', 'v1', credentials=credentials)

        service_path = f"projects/{settings.project_id}/locations/{settings.location}/services/{service_name}"

        request = run_service.projects().locations().services().get(name=service_path)
        response = request.execute()

        url = response.get('status', {}).get('url')
        if not url:
            raise RuntimeError(f"Could not find URL in API response for service {service_name}.")

        print(f"✅ Auto-discovered WORKER_URL: {url}")
        return url
    except Exception as e:
        logging.critical(f"FATAL: Could not discover WORKER_URL via API. Ensure the 'Cloud Run Admin API' is enabled. Error: {e}")
        raise


def resolve_worker_url(settings):
    """Returns ``WORKER_URL`` if it is set, otherwise discovers the URL via the Cloud Run Admin API.

    The legacy code told users to set ``WORKER_URL`` but never read it (plan B5).
    Call this once at startup and reuse the result. A ``web`` service never
    discovers itself: its scans run on the worker service, so ``WORKER_URL``
    must name it (``Settings.validate`` says so at startup in production; this
    is the guard for the other profiles).
    """
    if settings.worker_url:
        worker_url = settings.worker_url.rstrip('/')
        print(f"✅ Using WORKER_URL from environment: {worker_url}")
        return worker_url
    if settings.is_web_role:
        raise RuntimeError("CLOUDGAUGE_ROLE=web needs WORKER_URL, the URL of the worker service; "
                           "the web service never runs scans itself.")
    return discover_self_url(settings)
