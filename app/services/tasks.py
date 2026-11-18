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
"""Cloud Tasks: the startup queue check and task enqueueing.

The task sent to ``{worker_url}/run-scan`` (OIDC-authenticated POST with the
JSON body ``{"scope", "scope_id", "job_id"}``) is a frozen contract. Sharded
scans (``app.fanout``) add tasks for ``/scan-shard``, ``/run-aggregation`` and
``/sweep`` with the same body plus ``shard_id``/``sweep``; those are **named**
tasks, so creating the same one twice is a no-op (``AlreadyExists``), which is
what makes retries of the dispatcher and the fan-in trigger idempotent.
Since v20 the scan task is named too (``scan-{job_id}``), so that
:data:`ENQUEUE_RETRY` — the retry of a transient Cloud Tasks answer — can never
start a scan twice.
"""
import json
import logging
from datetime import datetime, timedelta, timezone

from google.api_core.exceptions import AlreadyExists, DeadlineExceeded, InternalServerError, NotFound, PermissionDenied, ServiceUnavailable
from google.api_core.retry import Retry, if_exception_type
from google.cloud import tasks_v2

from app.config import QUEUE_MAX_BACKOFF_SECONDS, QUEUE_MIN_BACKOFF_SECONDS
from app.services import gcp

# v20: the retry of ``create_task``. The client retries nothing on it by itself (a create is not idempotent in general;
# ours are, every task being named), so one transient answer — UNAVAILABLE ("Stream removed" has been seen in
# production), DEADLINE_EXCEEDED, INTERNAL — used to reach the person as a 500. Now: exponential backoff from one second,
# capped at eight, for up to thirty seconds in all; what is still failing then raises ``RetryError`` (the last answer is
# its cause) and the callers say that the scan could not be queued (``POST /scan``: 503, nothing started).
TRANSIENT_ERRORS = (ServiceUnavailable, DeadlineExceeded, InternalServerError)
ENQUEUE_RETRY = Retry(predicate=if_exception_type(*TRANSIENT_ERRORS), initial=1.0, maximum=8.0, multiplier=2.0, timeout=30.0)


# --- Startup Functions ---

def queue_limits(settings):
    """The rate and retry limits a CloudGauge queue should have (see app.config)."""
    return {
        "max_concurrent_dispatches": settings.scan_max_concurrent_shards,
        "max_attempts": settings.task_max_attempts,
        "min_backoff_seconds": QUEUE_MIN_BACKOFF_SECONDS,
        "max_backoff_seconds": QUEUE_MAX_BACKOFF_SECONDS,
    }


def queue_update_command(settings):
    """The gcloud command that applies :func:`queue_limits` to the configured queue."""
    limits = queue_limits(settings)
    return (f"gcloud tasks queues update {settings.task_queue} --project {settings.project_id} --location {settings.location} "
            f"--max-concurrent-dispatches={limits['max_concurrent_dispatches']} --max-attempts={limits['max_attempts']} "
            f"--min-backoff={limits['min_backoff_seconds']}s --max-backoff={limits['max_backoff_seconds']}s")


def _queue_limit_mismatches(queue, limits):
    """Returns ``[(setting, actual, wanted), ...]`` for the limits of ``queue`` that differ from ``limits``."""
    actual = {
        "max_concurrent_dispatches": queue.rate_limits.max_concurrent_dispatches,
        "max_attempts": queue.retry_config.max_attempts,
        "min_backoff_seconds": queue.retry_config.min_backoff.total_seconds(),
        "max_backoff_seconds": queue.retry_config.max_backoff.total_seconds(),
    }
    return [(name, actual[name], wanted) for name, wanted in limits.items() if actual[name] != wanted]


def verify_queue_limits(settings, queue_name, client):
    """Warns (never changes anything) if an existing queue's limits differ from :func:`queue_limits`.

    The limits matter for sharded scans: ``max_concurrent_dispatches`` is the
    shard concurrency, and ``max_attempts`` is how often a crashed shard is
    re-run before it is reported as an error. Returns the mismatches.
    """
    try:
        queue = client.get_queue(name=queue_name)
        mismatches = _queue_limit_mismatches(queue, queue_limits(settings))
    except Exception as e:  # the check is advisory: a missing permission must not stop the service
        logging.warning(f"Could not read the limits of Cloud Tasks queue '{settings.task_queue}': {e}")
        return []
    if mismatches:
        details = ", ".join(f"{name}={actual:g} (expected {wanted:g})" for name, actual, wanted in mismatches)
        logging.warning(f"⚠️ Cloud Tasks queue '{settings.task_queue}' has different limits than this deployment expects: {details}. "
                        f"Apply them with: {queue_update_command(settings)}")
    else:
        logging.info(f"✅ Cloud Tasks queue '{settings.task_queue}' limits match the configuration.")
    return mismatches


def ensure_queue_exists(settings, client=None):
    """
    Verifies the existence of the required Cloud Tasks queue upon application startup.
    If the queue does not exist, it creates it (with the limits in :func:`queue_limits`);
    if it exists, its limits are checked and a warning is logged when they differ.
    This function is essential for the asynchronous task processing of the application.
    """
    client = client or gcp.tasks_client()
    print("🚀 Checking for Cloud Tasks queue...")
    logging.info("🚀 Initializing startup checks: Verifying Cloud Tasks queue...")
    LOCATION = settings.location
    if not LOCATION:
        logging.critical("FATAL: Location environment variable not found.")
        raise RuntimeError("Location environment variable is not available.")
    logging.info(f"✅ Detected Cloud Run region: {LOCATION}")
    parent = f"projects/{settings.project_id}/locations/{LOCATION}"
    queue_name = f"{parent}/queues/{settings.task_queue}"
    try:
        limits = queue_limits(settings)
        client.create_queue(parent=parent, queue={
            "name": queue_name,
            "rate_limits": {"max_concurrent_dispatches": limits["max_concurrent_dispatches"]},
            "retry_config": {
                "max_attempts": limits["max_attempts"],
                "min_backoff": timedelta(seconds=limits["min_backoff_seconds"]),
                "max_backoff": timedelta(seconds=limits["max_backoff_seconds"]),
            },
        })
        logging.info(f"✅ Successfully created Cloud Tasks queue '{settings.task_queue}' in '{LOCATION}'.")
    except AlreadyExists:
        logging.info(f"✅ Cloud Tasks queue '{settings.task_queue}' already exists. No action needed.")
        verify_queue_limits(settings, queue_name, client)
    except PermissionDenied:
        logging.critical(f"FATAL: PERMISSION DENIED. The service account '{settings.service_account_email}' is likely missing the 'Cloud Tasks Admin' role.")
        raise
    except Exception as e:
        logging.critical(f"FATAL: An unexpected error occurred during startup task queue checks: {e}")
        raise


def ensure_queue_if_configured(settings, client=None):
    """Runs :func:`ensure_queue_exists` if the project and queue are configured."""
    # Initialize task queue if environment variables are set.
    if settings.project_id and settings.task_queue:
        ensure_queue_exists(settings, client=client)
    else:
        print("⚠️ PROJECT_ID or TASK_QUEUE environment variables not set. Skipping queue creation.")


# --- Tasks ---

def build_task(worker_url, path, body, service_account_email, *, audience=None, name=None,
               dispatch_deadline_seconds=None, schedule_delay_seconds=None, now=None):
    """Builds a Cloud Tasks HTTP task: an OIDC-authenticated JSON POST to ``{worker_url}{path}``.

    Args:
        worker_url: Base URL of this service (Cloud Tasks calls it back).
        path: The endpoint, e.g. ``"/run-scan"``.
        body: JSON-serializable payload.
        service_account_email: The service account whose OIDC token authenticates the call.
        audience: OIDC token audience; when omitted Cloud Tasks uses the task URL.
        name: Full task name (``projects/.../tasks/<id>``) for a named task; omitted: unnamed.
        dispatch_deadline_seconds: How long Cloud Tasks waits for the response before it
            counts the attempt as failed and retries (its default is 10 minutes, its maximum 30).
        schedule_delay_seconds: Run the task this many seconds from ``now`` instead of immediately.
        now: The current time (tests); default: ``datetime.now(timezone.utc)``.
    """
    task = {
        "http_request": {
            "http_method": tasks_v2.HttpMethod.POST,
            "url": f"{worker_url}{path}",
            "headers": {"Content-Type": "application/json"},
            "oidc_token": {
                "service_account_email": service_account_email
            },
        }
    }
    if audience:
        task["http_request"]["oidc_token"]["audience"] = audience
    task["http_request"]["body"] = json.dumps(body).encode()
    if name:
        task["name"] = name
    if dispatch_deadline_seconds:
        task["dispatch_deadline"] = timedelta(seconds=dispatch_deadline_seconds)
    if schedule_delay_seconds:
        task["schedule_time"] = (now or datetime.now(timezone.utc)) + timedelta(seconds=schedule_delay_seconds)
    return task


def build_scan_task(worker_url, service_account_email, scope, scope_id, job_id, audience=None, dispatch_deadline_seconds=None,
                    requested_by=None):
    """Builds the Cloud Tasks HTTP task that triggers ``/run-scan`` for one scan.

    ``audience`` sets the OIDC token audience; when omitted (the legacy task),
    Cloud Tasks uses the task URL. ``dispatch_deadline_seconds`` is new: the
    legacy task had none, so Cloud Tasks retried any scan still running after
    10 minutes while the first attempt kept going. ``requested_by`` is the
    signed-in person's email when the request came through Identity-Aware
    Proxy (``app.identity``); the payload carries it only then, and the report
    shows it as *Requested by*.
    """
    # NEW: Use a generic payload
    body = {"scope": scope, "scope_id": scope_id, "job_id": job_id}
    if requested_by:
        body["requested_by"] = requested_by
    return build_task(worker_url, "/run-scan", body,
                      service_account_email, audience=audience, dispatch_deadline_seconds=dispatch_deadline_seconds)


def scan_task_id(job_id):
    """The name of a job's scan task on the queue (v20): a job ID is a UUID, which is a valid task ID as it is."""
    return f"scan-{job_id}"


def enqueue_scan(settings, worker_url, scope, scope_id, job_id, client=None, requested_by=None):
    """Creates the scan task on the configured queue and returns the created task.

    The task is named after the job (v20), so a retry after a lost answer (:data:`ENQUEUE_RETRY`) meets
    ``AlreadyExists`` instead of starting the scan twice; that answer counts as created and returns ``None``.
    Anything else Cloud Tasks still answers after the retry propagates: nothing was started.
    """
    client = client or gcp.tasks_client()
    task = build_scan_task(worker_url, settings.service_account_email, scope, scope_id, job_id,
                           audience=settings.worker_audience, dispatch_deadline_seconds=settings.task_dispatch_deadline_seconds,
                           requested_by=requested_by)
    parent = client.queue_path(settings.project_id, settings.location, settings.task_queue)
    task["name"] = f"{parent}/tasks/{scan_task_id(job_id)}"
    try:
        return client.create_task(parent=parent, task=task, retry=ENQUEUE_RETRY)
    except AlreadyExists:
        logging.info(f"[{job_id}] The scan task already exists; not created again.")
        return None


def task_name(settings, client, task_id):
    """The full resource name of task ``task_id`` on the configured queue."""
    return f"{client.queue_path(settings.project_id, settings.location, settings.task_queue)}/tasks/{task_id}"


def enqueue_task(settings, worker_url, path, body, *, task_id, schedule_delay_seconds=None, client=None):
    """Creates the named task ``task_id`` for ``path`` and returns whether it was created.

    ``False`` means a task with that name already exists (or ran within the
    last hour, Cloud Tasks' de-duplication window): the caller's intent is
    already covered, so this is not an error. Task IDs may contain letters,
    digits, ``-`` and ``_``.
    """
    client = client or gcp.tasks_client()
    parent = client.queue_path(settings.project_id, settings.location, settings.task_queue)
    task = build_task(worker_url, path, body, settings.service_account_email, audience=settings.worker_audience,
                      name=f"{parent}/tasks/{task_id}", dispatch_deadline_seconds=settings.task_dispatch_deadline_seconds,
                      schedule_delay_seconds=schedule_delay_seconds)
    try:
        client.create_task(parent=parent, task=task, retry=ENQUEUE_RETRY)
        return True
    except AlreadyExists:
        logging.info(f"Task '{task_id}' already exists; not created again.")
        return False


def task_exists(settings, task_id, client=None):
    """Whether the named task is still on the queue (pending, running, or awaiting a retry).

    Cloud Tasks deletes a task once it has succeeded or exhausted its attempts.
    Returns ``None`` if the lookup failed (the caller should assume it exists).
    """
    client = client or gcp.tasks_client()
    try:
        client.get_task(name=task_name(settings, client, task_id))
        return True
    except NotFound:
        return False
    except Exception as e:
        logging.warning(f"Could not look up task '{task_id}': {e}")
        return None
