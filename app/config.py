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
# The release, as the image tag names it ("15.5" for v15.5; tests/test_packaging.py pins it to the newest entry
# of RELEASE_NOTES.md). The report's footer shows it, and every scan summary records it so the next scan can tell
# a check that is new to the release from one that merely had nothing to check last time (app.reporting.changes).
VERSION = "15.5"
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

# --- Sharded scans (app.fanout) ---
# A scan of more than SCAN_SHARD_SIZE projects is split into shards of that many
# projects, each run by its own Cloud Tasks task; smaller scans run inline in
# one task as before. SCAN_MAX_CONCURRENT_SHARDS bounds how many shards run at
# once (the queue's max_concurrent_dispatches: with 15 check threads per shard
# it caps the organization-wide API concurrency). Every task gets a Cloud Tasks
# dispatch deadline of TASK_DISPATCH_DEADLINE_SECONDS (its maximum is 30 min) so
# a hung request is retried instead of silently duplicated, and a shard stops
# starting new checks after SHARD_TIME_BUDGET_SECONDS so it always answers
# before that deadline. A sweeper task re-checks a running job every
# SWEEP_INTERVAL_SECONDS and finishes it with error rows if shards have died.
DEFAULT_SCAN_SHARD_SIZE = 20
DEFAULT_SCAN_MAX_CONCURRENT_SHARDS = 25
DEFAULT_SHARD_TIME_BUDGET_SECONDS = 20 * 60
DEFAULT_TASK_DISPATCH_DEADLINE_SECONDS = 30 * 60
MAX_TASK_DISPATCH_DEADLINE_SECONDS = 30 * 60  # Cloud Tasks' maximum for HTTP tasks
DEFAULT_SWEEP_INTERVAL_SECONDS = 30 * 60
# A job's *time limit*: when it has run this long, the sweeper finishes it with
# the results it has (the rest become error rows). It is computed per job from
# its size, so a large organization is never cut off while its shards are still
# queued: the queue runs the shards in waves of SCAN_MAX_CONCURRENT_SHARDS, and
# the limit is JOB_TIME_LIMIT_FACTOR times the time all the waves take if every
# shard uses its full dispatch deadline (the factor leaves room for retries), and
# never less than MIN_JOB_TIME_LIMIT_SECONDS. SCAN_TIME_LIMIT_SECONDS replaces
# the computed limit (see app.fanout.job_time_limit_seconds).
MIN_JOB_TIME_LIMIT_SECONDS = 6 * 60 * 60
JOB_TIME_LIMIT_FACTOR = 2
# Retry policy of the queue (created at startup if missing). Three attempts:
# a crashed shard is re-run, a persistently failing one ends up as error rows
# in the report instead of retrying for hours.
QUEUE_MAX_ATTEMPTS = 3
QUEUE_MIN_BACKOFF_SECONDS = 30
QUEUE_MAX_BACKOFF_SECONDS = 600

# --- Service Health incidents and Advisory Notifications (the report's briefings) ---
# The Service Health Incidents briefing lists the incidents updated in the last
# SERVICE_HEALTH_WINDOW_DAYS whose relevance to a scanned project is one of
# SERVICE_HEALTH_RELEVANCE (comma-separated; "Impacted" is only computed for some
# products, so "Related" is included by default). The Advisory Notifications
# briefing lists the notifications created in the last ADVISORY_WINDOW_DAYS (the
# API keeps about a year).
DEFAULT_SERVICE_HEALTH_WINDOW_DAYS = 90
DEFAULT_SERVICE_HEALTH_RELEVANCE = ("IMPACTED", "RELATED")
SERVICE_HEALTH_RELEVANCE_VALUES = ("IMPACTED", "RELATED", "PARTIALLY_RELATED", "NOT_IMPACTED", "UNKNOWN")
DEFAULT_ADVISORY_WINDOW_DAYS = 365

# Configures logging to display INFO level messages with a timestamp.
LOG_FORMAT = '%(levelname)s: [%(asctime)s] %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'

# CLOUDGAUGE_ENV selects the profile. The app factory (Phase 4) runs the startup
# checks (env validation, worker URL lookup, queue creation) only in production
# and synthetic. 'synthetic' is production plus the synthetic load mode
# (app.synthetic): the checks run against a generated organization instead of
# Google Cloud APIs. It is opt-in by profile *and* SYNTHETIC_PROJECTS, so it
# can't be switched on by accident on a real deployment.
PROFILES = ('production', 'development', 'testing', 'synthetic')
DEFAULT_PROFILE = 'production'
SYNTHETIC_PROFILE = 'synthetic'
DEFAULT_SYNTHETIC_SEED = 42
DEFAULT_SYNTHETIC_LATENCY_MS = 150.0  # median simulated latency per API call
DEFAULT_SYNTHETIC_ERROR_RATE = 0.0  # share of API calls that fail with 429
DEFAULT_SYNTHETIC_DENIED_FRACTION = 0.02  # share of projects that answer 403 to everything


def _gemini_model(value):
    """``GEMINI_MODEL`` as a model ID, or ``AUTO_GEMINI_MODEL`` when unset, empty, or any casing of "auto"."""
    value = (value or '').strip()
    return AUTO_GEMINI_MODEL if value.lower() in ('', AUTO_GEMINI_MODEL) else value


def _number(env, name, default, cast, minimum=None, maximum=None):
    """Reads a numeric environment variable, with a default and an inclusive range."""
    raw = (env.get(name) or '').strip()
    if not raw:
        return default
    try:
        value = cast(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got '{raw}'") from None
    if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        raise ValueError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


def _relevance(value):
    """``SERVICE_HEALTH_RELEVANCE`` as a tuple of relevance values (any casing, comma-separated); the default when unset."""
    values = tuple(dict.fromkeys(v.strip().upper() for v in (value or '').split(',') if v.strip()))
    if not values:
        return DEFAULT_SERVICE_HEALTH_RELEVANCE
    unknown = [v for v in values if v not in SERVICE_HEALTH_RELEVANCE_VALUES]
    if unknown:
        raise ValueError(f"SERVICE_HEALTH_RELEVANCE has unknown values {unknown}; expected a comma-separated subset of "
                         f"{', '.join(SERVICE_HEALTH_RELEVANCE_VALUES)}")
    return values


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
    # Sharded scans (see the constants above and app.fanout)
    scan_shard_size: int = DEFAULT_SCAN_SHARD_SIZE
    scan_max_concurrent_shards: int = DEFAULT_SCAN_MAX_CONCURRENT_SHARDS
    shard_time_budget_seconds: int = DEFAULT_SHARD_TIME_BUDGET_SECONDS
    task_dispatch_deadline_seconds: int = DEFAULT_TASK_DISPATCH_DEADLINE_SECONDS
    sweep_interval_seconds: int = DEFAULT_SWEEP_INTERVAL_SECONDS
    scan_time_limit_seconds: int = 0  # 0: computed per job (app.fanout.job_time_limit_seconds)
    task_max_attempts: int = QUEUE_MAX_ATTEMPTS
    # Service Health incidents and Advisory Notifications (see the constants above)
    service_health_window_days: int = DEFAULT_SERVICE_HEALTH_WINDOW_DAYS
    service_health_relevance: tuple = DEFAULT_SERVICE_HEALTH_RELEVANCE
    advisory_window_days: int = DEFAULT_ADVISORY_WINDOW_DAYS
    # Synthetic load mode (profile 'synthetic' only; see app.synthetic)
    synthetic_projects: int = 0
    synthetic_seed: int = DEFAULT_SYNTHETIC_SEED
    synthetic_latency_ms: float = DEFAULT_SYNTHETIC_LATENCY_MS
    synthetic_error_rate: float = DEFAULT_SYNTHETIC_ERROR_RATE
    synthetic_denied_fraction: float = DEFAULT_SYNTHETIC_DENIED_FRACTION

    @classmethod
    def from_env(cls, environ=None):
        """Reads settings from ``environ`` (default: ``os.environ``).

        Raises:
            ValueError: If ``CLOUDGAUGE_ENV`` is not one of ``PROFILES``, if a
                numeric setting is out of range, or if the synthetic profile
                is selected without ``SYNTHETIC_PROJECTS``.
        """
        env = os.environ if environ is None else environ
        profile = (env.get('CLOUDGAUGE_ENV') or DEFAULT_PROFILE).strip().lower()
        if profile not in PROFILES:
            raise ValueError(f"Invalid CLOUDGAUGE_ENV '{profile}'. Expected one of: {', '.join(PROFILES)}")
        synthetic_projects = _number(env, 'SYNTHETIC_PROJECTS', 0, int, minimum=0)
        if profile == SYNTHETIC_PROFILE and synthetic_projects < 1:
            raise ValueError("CLOUDGAUGE_ENV=synthetic needs SYNTHETIC_PROJECTS (the number of generated projects, at least 1)")
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
            scan_shard_size=_number(env, 'SCAN_SHARD_SIZE', DEFAULT_SCAN_SHARD_SIZE, int, minimum=1),
            scan_max_concurrent_shards=_number(env, 'SCAN_MAX_CONCURRENT_SHARDS', DEFAULT_SCAN_MAX_CONCURRENT_SHARDS, int, minimum=1, maximum=1000),
            shard_time_budget_seconds=_number(env, 'SHARD_TIME_BUDGET_SECONDS', DEFAULT_SHARD_TIME_BUDGET_SECONDS, int, minimum=60,
                                              maximum=MAX_TASK_DISPATCH_DEADLINE_SECONDS),
            task_dispatch_deadline_seconds=_number(env, 'TASK_DISPATCH_DEADLINE_SECONDS', DEFAULT_TASK_DISPATCH_DEADLINE_SECONDS, int, minimum=15,
                                                   maximum=MAX_TASK_DISPATCH_DEADLINE_SECONDS),
            sweep_interval_seconds=_number(env, 'SWEEP_INTERVAL_SECONDS', DEFAULT_SWEEP_INTERVAL_SECONDS, int, minimum=60),
            scan_time_limit_seconds=_number(env, 'SCAN_TIME_LIMIT_SECONDS', 0, int, minimum=0),
            task_max_attempts=_number(env, 'TASK_MAX_ATTEMPTS', QUEUE_MAX_ATTEMPTS, int, minimum=1, maximum=100),
            service_health_window_days=_number(env, 'SERVICE_HEALTH_WINDOW_DAYS', DEFAULT_SERVICE_HEALTH_WINDOW_DAYS, int, minimum=1, maximum=366),
            service_health_relevance=_relevance(env.get('SERVICE_HEALTH_RELEVANCE')),
            advisory_window_days=_number(env, 'ADVISORY_WINDOW_DAYS', DEFAULT_ADVISORY_WINDOW_DAYS, int, minimum=1, maximum=3660),
            synthetic_projects=synthetic_projects,
            synthetic_seed=_number(env, 'SYNTHETIC_SEED', DEFAULT_SYNTHETIC_SEED, int),
            synthetic_latency_ms=_number(env, 'SYNTHETIC_LATENCY_MS', DEFAULT_SYNTHETIC_LATENCY_MS, float, minimum=0),
            synthetic_error_rate=_number(env, 'SYNTHETIC_ERROR_RATE', DEFAULT_SYNTHETIC_ERROR_RATE, float, minimum=0, maximum=1),
            synthetic_denied_fraction=_number(env, 'SYNTHETIC_DENIED_FRACTION', DEFAULT_SYNTHETIC_DENIED_FRACTION, float, minimum=0, maximum=1),
        )

    @property
    def is_production(self):
        return self.profile == 'production'

    @property
    def is_testing(self):
        return self.profile == 'testing'

    @property
    def is_synthetic(self):
        """True in the synthetic load mode: generated organization, no Google Cloud data-plane calls."""
        return self.profile == SYNTHETIC_PROFILE

    @property
    def startup_checks_enabled(self):
        """Whether ``create_app`` validates the env, resolves the worker URL and ensures the queue."""
        return self.profile in ('production', SYNTHETIC_PROFILE)

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
