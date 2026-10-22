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
"""Scheduled scans (v17): what the worker's ``/scheduled-scan`` endpoint does.

Cloud Scheduler posts ``{"scope", "scope_id", "name"}`` to the worker with the service
account's OIDC token (``tools/deploy.sh`` creates the jobs from ``SCHEDULES``). The
endpoint enqueues the same Cloud Tasks task the web service's **Start scan** does, with
*Requested by* ``schedule: <name>``, so a scheduled scan is a scan like any other: the
same report, the same summary under ``scopes/``, the same comparison with the previous
one. One rule on top: a scope scans once at a time. The last scheduled job of each scope
is noted in the results bucket (``schedules/<scope>/<scope_id>.json``); while that job is
still running the endpoint answers **409** and starts nothing, so a weekly schedule on an
organization that takes longer than a week never piles scans up.
"""
import re
import uuid
from datetime import timedelta

from app.services import tasks
from app.utils import parse_timestamp, utcnow

SCOPES = ("organization", "folder", "project")
SCHEDULE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
# A noted job older than this counts as finished whatever its status file says (a scan has a time limit well under it).
LOCK_MAX_AGE = timedelta(hours=36)
FINISHED_STATUSES = ("completed", "error")


def requested_by(name):
    """What the report's *Requested by* row and the scan summary record for a scheduled scan."""
    return f"schedule: {name}"


def validate(data):
    """``(scope, scope_id, name)`` of a Cloud Scheduler body, or raises ``ValueError`` with what is wrong."""
    if not isinstance(data, dict):
        raise ValueError("The body must be a JSON object with scope, scope_id and name.")
    scope, scope_id, name = data.get("scope"), data.get("scope_id"), data.get("name") or "unnamed"
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {', '.join(SCOPES)}.")
    if not isinstance(scope_id, str) or not scope_id.strip() or "/" in scope_id:
        raise ValueError("scope_id must be an organization ID, folder ID or project ID.")
    if not isinstance(name, str) or not SCHEDULE_NAME.match(name):
        raise ValueError("name must be 1-64 letters, digits, dashes or underscores (the Cloud Scheduler job's name).")
    return scope, scope_id.strip(), name


def scan_in_progress(store, lock, now):
    """Whether the job a schedule lock names is still running: its status file says so, or is not written yet.

    A lock older than ``LOCK_MAX_AGE`` is stale. When the status cannot be read the job is assumed to
    be running (the conservative answer: the next run of the schedule tries again).
    """
    if not lock or not lock.get("job_id"):
        return False
    started = parse_timestamp(lock.get("started_at"))
    if started is None or now - started > LOCK_MAX_AGE:
        return False
    try:
        status = store.read_status(lock["job_id"], lock.get("scope_id", ""))
    except Exception:
        return True
    return status is None or status.get("status") not in FINISHED_STATUSES


def start_scheduled_scan(services, data, now=None):
    """Starts the scan a Cloud Scheduler body asks for; returns ``(response dict, HTTP status)``.

    202 with the job ID when the scan was enqueued (the body carries the status page's path);
    400 when the body is malformed; 409 when the scope's previous scheduled scan is still running.
    """
    now = now or utcnow()
    try:
        scope, scope_id, name = validate(data)
    except ValueError as e:
        return {"error": str(e)}, 400
    store = services.results_store
    lock = store.read_schedule_lock(scope, scope_id)
    if scan_in_progress(store, lock, now):
        return {"error": f"A scan of {scope} {scope_id} is still running (job {lock['job_id']}, started {lock.get('started_at')}); "
                         f"nothing was started.", "job_id": lock["job_id"], "schedule": name}, 409
    job_id = str(uuid.uuid4())
    who = requested_by(name)
    print(f"Scheduled scan '{name}': creating scan task for {scope}: {scope_id} with Job ID: {job_id}")
    tasks.enqueue_scan(services.settings, services.get_worker_url(), scope, scope_id, job_id,
                       client=services.get_tasks_client(), requested_by=who)
    store.write_schedule_lock(scope, scope_id, {"job_id": job_id, "scope": scope, "scope_id": scope_id, "schedule": name,
                                                "requested_by": who, "started_at": now.isoformat(timespec="seconds")})
    return {"job_id": job_id, "scope": scope, "scope_id": scope_id, "schedule": name, "requested_by": who,
            "status_path": f"/status/{job_id}/{scope}/{scope_id}"}, 202
