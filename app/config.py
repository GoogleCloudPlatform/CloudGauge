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
"""Constants and environment-driven settings.

Replaces the module-level globals and ``check_environment_variables()`` of the
legacy ``cloudgauge.py``. Reading settings has no side effects: nothing here
touches the network or creates clients.
"""
import logging
import os
from dataclasses import dataclass

# --- Environment Variables & Constants ---
# Best-practices CSV for the Organization Policies check (legacy name: GCS_PUBLIC_URL;
# it points at GitHub, not GCS). The value is frozen byte-for-byte; override it
# with the BEST_PRACTICES_CSV_URL environment variable.
BEST_PRACTICES_CSV_URL = "https://raw.githubusercontent.com/GoogleCloudPlatform/CloudGauge/Beta/assets/gcp_best_practices.csv"
BEST_PRACTICES_FETCH_TIMEOUT_SECONDS = 30
SCOPES = ['https://www.googleapis.com/auth/cloud-platform']

# These names are part of the deploy contract (README, Terraform); don't rename them.
REQUIRED_ENV_VARS = ('PROJECT_ID', 'LOCATION', 'TASK_QUEUE', 'RESULTS_BUCKET', 'SERVICE_ACCOUNT_EMAIL')

# GEMINI_MODEL: "auto" (the default) uses the newest stable Gemini Flash model
# available to the project, looked up at runtime (see app.services.gemini).
# Any other value is used as the model ID, e.g. "gemini-3.5-flash" to pin one.
AUTO_GEMINI_MODEL = "auto"
DEFAULT_GEMINI_MODEL = AUTO_GEMINI_MODEL
# Used when "auto" can't list the models: Google's alias for its latest Flash model.
FALLBACK_GEMINI_MODEL = "gemini-flash-latest"
DEFAULT_VERTEX_LOCATION = "global"

CHECK_RUNNER_MAX_WORKERS = 15
# --- Throttling logic setup ---
# We will only update GCS if at least 2 seconds have passed since the last update.
STATUS_UPDATE_INTERVAL_SECONDS = 2

# Configures logging to display INFO level messages with a timestamp.
LOG_FORMAT = '%(levelname)s: [%(asctime)s] %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'

# CLOUDGAUGE_ENV selects the profile. The app factory (Phase 4) runs the startup
# checks (env validation, worker URL lookup, queue creation) only in production.
PROFILES = ('production', 'development', 'testing')
DEFAULT_PROFILE = 'production'


def _gemini_model(value):
    """``GEMINI_MODEL`` as a model ID, or ``AUTO_GEMINI_MODEL`` when unset, empty, or any casing of "auto"."""
    value = (value or '').strip()
    return AUTO_GEMINI_MODEL if value.lower() in ('', AUTO_GEMINI_MODEL) else value


@dataclass(frozen=True)
class Settings:
    """Runtime settings. Build them with :meth:`from_env`; they never change afterwards."""

    # Required (see REQUIRED_ENV_VARS)
    project_id: str | None = None
    location: str | None = None
    task_queue: str | None = None
    results_bucket: str | None = None
    service_account_email: str | None = None
    # Set by Cloud Run
    k_service: str | None = None
    # Optional; the defaults match the legacy behavior
    worker_url: str | None = None
    # OIDC audience for the scan task's token. Unset: Cloud Tasks uses the task URL.
    # Needed when WORKER_URL is a revision tag URL (canary): Cloud Run rejects
    # tokens whose audience is a tag URL (401), so set this to the service's main URL.
    worker_audience: str | None = None
    gemini_model: str = DEFAULT_GEMINI_MODEL
    vertex_location: str = DEFAULT_VERTEX_LOCATION
    best_practices_csv_url: str = BEST_PRACTICES_CSV_URL
    profile: str = DEFAULT_PROFILE

    @classmethod
    def from_env(cls, environ=None):
        """Reads settings from ``environ`` (default: ``os.environ``).

        Raises:
            ValueError: If ``CLOUDGAUGE_ENV`` is not one of ``PROFILES``.
        """
        env = os.environ if environ is None else environ
        profile = (env.get('CLOUDGAUGE_ENV') or DEFAULT_PROFILE).strip().lower()
        if profile not in PROFILES:
            raise ValueError(f"Invalid CLOUDGAUGE_ENV '{profile}'. Expected one of: {', '.join(PROFILES)}")
        return cls(
            project_id=env.get('PROJECT_ID'),
            location=env.get('LOCATION'),
            task_queue=env.get('TASK_QUEUE'),
            results_bucket=env.get('RESULTS_BUCKET'),
            service_account_email=env.get('SERVICE_ACCOUNT_EMAIL'),
            k_service=env.get('K_SERVICE'),
            worker_url=env.get('WORKER_URL') or None,
            worker_audience=env.get('WORKER_AUDIENCE') or None,
            gemini_model=_gemini_model(env.get('GEMINI_MODEL')),
            vertex_location=env.get('VERTEX_LOCATION') or DEFAULT_VERTEX_LOCATION,
            best_practices_csv_url=env.get('BEST_PRACTICES_CSV_URL') or BEST_PRACTICES_CSV_URL,
            profile=profile,
        )

    @property
    def is_production(self):
        return self.profile == 'production'

    @property
    def is_testing(self):
        return self.profile == 'testing'

    def missing_required(self):
        """Returns the names of required environment variables that are unset or empty."""
        values = {
            'PROJECT_ID': self.project_id,
            'LOCATION': self.location,
            'TASK_QUEUE': self.task_queue,
            'RESULTS_BUCKET': self.results_bucket,
            'SERVICE_ACCOUNT_EMAIL': self.service_account_email,
        }
        return [var for var in REQUIRED_ENV_VARS if not values[var]]

    def validate(self):
        """Checks for required environment variables at startup."""
        missing_vars = self.missing_required()
        if missing_vars:
            error_message = f"FATAL: Missing required environment variables: {', '.join(missing_vars)}"
            logging.critical(error_message)
            # In a production environment, you might want to raise an exception or exit
            # For Cloud Run, this will make the deployment fail with a clear log message
            raise RuntimeError(error_message)
        else:
            print("✅ All required environment variables are set.")


def get_settings(environ=None):
    """Returns a new :class:`Settings` read from the environment."""
    return Settings.from_env(environ)
