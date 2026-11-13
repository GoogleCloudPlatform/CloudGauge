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
"""Starting a scan — one per scope at a time — and scheduled scans (v17).

``start_scan`` is what both entry points call: the web service's **Start scan**
(``POST /scan``) and the worker's ``/scheduled-scan``, which Cloud Scheduler posts
``{"scope", "scope_id", "name"}`` to with the service account's OIDC token
(``tools/deploy.sh`` creates the jobs from ``SCHEDULES``). Both enqueue the same
Cloud Tasks task, so a scheduled scan is a scan like any other: the same report,
the same summary under ``scopes/``, the same comparison with the previous one;
its *Requested by* reads ``schedule: <name>``.

One rule on top: **a scope scans once at a time.** The job a scope last started
is noted in the results bucket (``schedules/<scope>/<scope_id>.json``, whoever
started it); while that job is still running nothing new starts — ``/scheduled-scan``
answers **409**, ``POST /scan`` shows the running scan (v18.6.1; before, only
schedules kept the rule, and a double-click or two operators queued two scans). A
noted job counts as running while its status file says so; a job with no status
file yet counts as running for ``PENDING_MAX_AGE`` only (a task that never
dispatched must not block its scope), and any note older than ``LOCK_MAX_AGE`` is
stale (the sweeper finishes dead jobs well before).
"""
import logging
import re
import uuid
from datetime import timedelta

from app import validation
from app.services import tasks
from app.utils import parse_timestamp, utcnow

SCOPES = validation.SCOPES
SCHEDULE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
# A noted job older than this counts as finished whatever its status file says (a scan has a time limit well under it).
LOCK_MAX_AGE = timedelta(hours=36)
# A noted job that has not written its status file yet counts as running for this long (Cloud Tasks dispatches in
# seconds; a task that never arrives must not block its scope for LOCK_MAX_AGE).
PENDING_MAX_AGE = timedelta(minutes=10)
FINISHED_STATUSES = ("completed", "error")


class ScanInProgress(Exception):
    """The scope's previous scan is still running; ``lock`` is its note (``job_id``, ``started_at``, ``requested_by``)."""

    def __init__(self, lock):
        super().__init__(f"A scan of {lock.get('scope')} {lock.get('scope_id')} is still running (job {lock.get('job_id')}).")
        self.lock = lock


def requested_by(name):
    """What the report's *Requested by* row and the scan summary record for a scheduled scan."""
    return f"schedule: {name}"


def validate(data):
    """``(scope, scope_id, name)`` of a Cloud Scheduler body, or raises ``ValueError`` with what is wrong."""
    if not isinstance(data, dict):
        raise ValueError("The body must be a JSON object with scope, scope_id and name.")
    try:
        scope = validation.clean_scope(data.get("scope"))
        scope_id = validation.clean_scope_id(scope, data.get("scope_id"))
    except validation.RequestError as e:
        raise ValueError(str(e)) from None
    name = data.get("name") or "unnamed"
    if not isinstance(name, str) or not SCHEDULE_NAME.match(name):
        raise ValueError("name must be 1-64 letters, digits, dashes or underscores (the Cloud Scheduler job's name).")
    return scope, scope_id, name


def scan_in_progress(store, lock, now):
    """Whether the job a scope's note names is still running.

    Its status file says so (anything but ``completed``/``error``); no status file yet counts as running
    within ``PENDING_MAX_AGE`` of the start; a note older than ``LOCK_MAX_AGE`` is stale. When the status
    cannot be read the job is assumed to be running (the conservative answer: the caller tries again later).
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
    if status is None:
        return now - started <= PENDING_MAX_AGE
    return status.get("status") not in FINISHED_STATUSES


def start_scan(services, scope, scope_id, *, requested_by=None, schedule=None, now=None):
    """Starts a scan of the scope unless one is running: enqueues the task and notes the job.

    Returns the note written (``job_id``, ``scope``, ``scope_id``, ``requested_by``, ``started_at`` and, for a
    scheduled scan, ``schedule``). Raises :class:`ScanInProgress` with the running job's note instead of starting
    a second scan. The note is read and written with the bucket; a note that cannot be read counts as absent and
    a note that cannot be written is logged (the scan is already on its way) — the rule is a courtesy, the scan
    is the point.
    """
    now = now or utcnow()
    store = services.results_store
    try:
        lock = store.read_schedule_lock(scope, scope_id)
    except Exception as e:  # noqa: BLE001 - the bucket; without the note the scan starts as it did before v18.6.1
        logging.warning(f"Could not read the last job noted for {scope} {scope_id} ({e}); starting the scan.")
        lock = None
    if scan_in_progress(store, lock, now):
        raise ScanInProgress(lock)
    job_id = str(uuid.uuid4())
    who = f" (requested by {requested_by})" if requested_by else ""
    print(f"Creating scan task for {scope}: {scope_id} with Job ID: {job_id}{who}")
    tasks.enqueue_scan(services.settings, services.get_worker_url(), scope, scope_id, job_id,
                       client=services.get_tasks_client(), requested_by=requested_by)
    note = {"job_id": job_id, "scope": scope, "scope_id": scope_id, "requested_by": requested_by,
            "started_at": now.isoformat(timespec="seconds")}
    if schedule:
        note["schedule"] = schedule
    try:
        store.write_schedule_lock(scope, scope_id, note)
    except Exception as e:  # noqa: BLE001 - the scan is enqueued; only the one-at-a-time courtesy is lost for it
        logging.error(f"[{job_id}] Could not note the job for {scope} {scope_id}: {e}")
    return note


def start_scheduled_scan(services, data, now=None):
    """Starts the scan a Cloud Scheduler body asks for; returns ``(response dict, HTTP status)``.

    202 with the job ID when the scan was enqueued (the body carries the status page's path);
    400 when the body is malformed; 409 when the scope's previous scan is still running.
    """
    try:
        scope, scope_id, name = validate(data)
    except ValueError as e:
        return {"error": str(e)}, 400
    try:
        note = start_scan(services, scope, scope_id, requested_by=requested_by(name), schedule=name, now=now)
    except ScanInProgress as e:
        lock = e.lock
        return {"error": f"A scan of {scope} {scope_id} is still running (job {lock['job_id']}, started {lock.get('started_at')}); "
                         f"nothing was started.", "job_id": lock["job_id"], "schedule": name}, 409
    return {"job_id": note["job_id"], "scope": scope, "scope_id": scope_id, "schedule": name, "requested_by": note["requested_by"],
            "status_path": f"/status/{note['job_id']}/{scope}/{scope_id}"}, 202
