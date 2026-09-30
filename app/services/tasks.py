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
"""Cloud Tasks: the startup queue check and scan-task enqueueing.

The task sent to ``{worker_url}/run-scan`` (OIDC-authenticated POST with the
JSON body ``{"scope", "scope_id", "job_id"}``) is a frozen contract.
"""
import json
import logging

from google.api_core.exceptions import AlreadyExists, PermissionDenied
from google.cloud import tasks_v2

from app.services import gcp


# --- Startup Functions ---

def ensure_queue_exists(settings, client=None):
    """
    Verifies the existence of the required Cloud Tasks queue upon application startup.
    If the queue does not exist, it creates it. This function is essential for
    the asynchronous task processing of the application.
    """
    client = client or gcp.tasks_client()
    print("🚀 Checking for Cloud Tasks queue...")
    logging.info("🚀 Initializing startup checks: Verifying Cloud Tasks queue...")
    LOCATION = settings.location
    if not LOCATION:
        logging.critical("FATAL: Location environment variable not found.")
        raise RuntimeError("Location environment variable is not available.")
    logging.info(f"✅ Detected Cloud Run region: {LOCATION}")
    try:
        parent = f"projects/{settings.project_id}/locations/{LOCATION}"
        queue_name = f"{parent}/queues/{settings.task_queue}"
        client.create_queue(parent=parent, queue={"name": queue_name})
        logging.info(f"✅ Successfully created Cloud Tasks queue '{settings.task_queue}' in '{LOCATION}'.")
    except AlreadyExists:
        logging.info(f"✅ Cloud Tasks queue '{settings.task_queue}' already exists. No action needed.")
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


def build_scan_task(worker_url, service_account_email, scope, scope_id, job_id):
    """Builds the Cloud Tasks HTTP task that triggers ``/run-scan`` for one scan."""
    task = {
        "http_request": {
            "http_method": tasks_v2.HttpMethod.POST,
            "url": f"{worker_url}/run-scan",
            "headers": {"Content-Type": "application/json"},
            "oidc_token": {
                "service_account_email": service_account_email
            },
        }
    }
    # NEW: Use a generic payload
    task["http_request"]["body"] = json.dumps({"scope": scope, "scope_id": scope_id, "job_id": job_id}).encode()
    return task


def enqueue_scan(settings, worker_url, scope, scope_id, job_id, client=None):
    """Creates the scan task on the configured queue and returns the created task."""
    client = client or gcp.tasks_client()
    task = build_scan_task(worker_url, settings.service_account_email, scope, scope_id, job_id)
    parent = client.queue_path(settings.project_id, settings.location, settings.task_queue)
    return client.create_task(parent=parent, task=task)
