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
"""Sharded scans: dispatch, shard workers, automatic fan-in, aggregation, and the sweeper.

A scan of more than ``SCAN_SHARD_SIZE`` projects doesn't run in one request.
``/run-scan`` becomes a **dispatcher** (``FanOut.dispatch``): it writes the
job's *manifest* (which projects belong to which shard), enqueues one Cloud
Tasks task per shard plus a *scope shard* for the checks that look at the
organization or folder itself, schedules a *sweeper*, and returns within
seconds. The status page keeps polling the same job as before; from the
user's point of view nothing changed but the speed.

- ``/scan-shard`` (``run_shard``) runs the project checks over its shard's
  projects (or the scope-level checks), writing findings under the shard's own
  prefix in the results bucket, then writes a *marker*. Markers are the fan-in:
  the shard that sees a marker for every shard enqueues the aggregation task.
  Two shards finishing together both try; the task name is deterministic, so
  Cloud Tasks accepts only one. Because every shard lists the markers after
  writing its own, the last one always sees them all, so the trigger can't be
  lost to a race.
- ``/run-aggregation`` (``aggregate``) merges every shard's findings into one
  report, exactly as a single-task scan would have written it, uploads it,
  marks the job complete, and deletes the intermediate files.
- ``/sweep`` (``sweep``) makes the job terminate no matter what: every
  ``SWEEP_INTERVAL_SECONDS`` it checks whether the shards that haven't reported
  are still queued or running. Shards whose task is gone (crashed on every
  attempt) get error rows and a marker; when nothing is left the report is
  produced with what there is. A shard that fails for good writes error rows
  itself, so a bad shard costs that shard's rows, never the whole report. A job
  that is still running at its *time limit* (``job_time_limit_seconds``: sized
  from its number of shards, so a large organization is never cut off while its
  shards are queued) is finished with the results it has.

Shards are idempotent: a retried shard first deletes what its previous attempt
wrote. Cloud Tasks may deliver a task more than once; a shard whose marker
already exists just re-runs the fan-in check.

The small-scan path is untouched: ``app.scan_job`` only calls ``dispatch`` when
there are more projects than fit in one shard.
"""
import logging
import math
import time
import traceback
from datetime import datetime, timezone

from app.checks.categories import categorize_findings, merge_shard_findings
from app.checks.registry import project_check_plan, scope_check_plan, shard_check_names
from app.checks.runner import error_finding, record_error, run_check_plan
from app.config import JOB_TIME_LIMIT_FACTOR, MIN_JOB_TIME_LIMIT_SECONDS
from app.reporting.html_report import generate_reports
from app.services.resource_manager import folder_membership, get_active_compute_locations
from app.services.results_store import ShardSink

SCOPE_SHARD = "scope"
SHARD_PATH, AGGREGATE_PATH, SWEEP_PATH = "/scan-shard", "/run-aggregation", "/sweep"
# Set by Cloud Tasks on every attempt: 0 on the first, 1 on the first retry, ...
RETRY_COUNT_HEADER = "X-CloudTasks-TaskRetryCount"
# Marker statuses. "success" includes shards in which individual checks failed
# (those are error rows already); "timed_out" means some checks were cut off by
# the time budget; "failed" means the shard as a whole failed on its last attempt.
SUCCESS, TIMED_OUT, FAILED = "success", "timed_out", "failed"
# The sweeper's next check comes after SWEEP_INTERVAL_SECONDS, or sooner when the
# job's time limit is closer than that; never sooner than this.
MIN_SWEEP_DELAY_SECONDS = 60


def shard_task_id(job_id, shard_id):
    return f"{job_id}-{shard_id}"


def aggregate_task_id(job_id):
    return f"{job_id}-aggregate"


def sweep_task_id(job_id, sweep):
    return f"{job_id}-sweep-{sweep}"


def plan_shards(projects, shard_size):
    """Splits ``projects`` into consecutive shards of ``shard_size``: ``{"shard-001": [...], ...}``."""
    count = math.ceil(len(projects) / shard_size)
    width = max(3, len(str(count)))
    return {f"shard-{i + 1:0{width}d}": projects[i * shard_size:(i + 1) * shard_size] for i in range(count)}


def job_time_limit_seconds(settings, total_shards):
    """How long a job may run before the sweeper finishes it with the results it has.

    ``SCAN_TIME_LIMIT_SECONDS`` if set. Otherwise the queue runs the shards in
    waves of ``SCAN_MAX_CONCURRENT_SHARDS``; the limit is ``JOB_TIME_LIMIT_FACTOR``
    times the time the waves take if every shard uses its full dispatch deadline
    (the factor leaves room for retried shards), and at least
    ``MIN_JOB_TIME_LIMIT_SECONDS``. With the defaults (25 concurrent, 30-minute
    deadline): up to 150 shards (~3,000 projects) keep the 6-hour minimum; 501
    shards (10,000 projects) get 21 waves, 21 hours.
    """
    if settings.scan_time_limit_seconds:
        return settings.scan_time_limit_seconds
    waves = math.ceil(total_shards / settings.scan_max_concurrent_shards)
    return max(MIN_JOB_TIME_LIMIT_SECONDS, JOB_TIME_LIMIT_FACTOR * waves * settings.task_dispatch_deadline_seconds)


def build_manifest(scope, scope_id, job_id, projects, shard_size, now=None, time_limit_seconds=None, requested_by=None):
    """The job's shard plan: the project shards plus the scope shard (which has no projects).

    ``requested_by`` (the signed-in requester, when known) rides along for the
    aggregation, which puts it on the report.
    """
    shards = plan_shards(projects, shard_size)
    shards[SCOPE_SHARD] = []
    manifest = {
        "job_id": job_id, "scope": scope, "scope_id": scope_id,
        "shard_size": shard_size, "total_projects": len(projects), "total_shards": len(shards),
        "shards": shards,
        "created_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "time_limit_seconds": time_limit_seconds,
    }
    if requested_by:
        manifest["requested_by"] = requested_by
    return manifest


def build_coverage(manifest, markers):
    """How much of the scope the report covers, from the manifest and the markers that exist.

    Returns a dict for the report's summary: project counts by outcome and shard counts.
    """
    shards = manifest["shards"]
    scanned = partial = not_scanned = 0
    succeeded = failed = missing = 0
    for shard_id, projects in shards.items():
        marker = markers.get(shard_id)
        status = marker.get("status") if marker else None
        if status == SUCCESS:
            succeeded += 1
            scanned += len(projects)
        elif status == TIMED_OUT:
            failed += 1
            partial += len(projects)
        elif status == FAILED:
            failed += 1
            not_scanned += len(projects)
        else:
            missing += 1
            not_scanned += len(projects)
    scope_status = (markers.get(SCOPE_SHARD) or {}).get("status") or "missing"
    return {
        "total_projects": manifest["total_projects"], "projects_scanned": scanned,
        "projects_partial": partial, "projects_not_scanned": not_scanned,
        "total_shards": manifest["total_shards"], "shards_succeeded": succeeded,
        "shards_failed": failed, "shards_missing": missing, "scope_checks": scope_status,
    }


# What the user reads (status page, error rows, coverage line) speaks of projects
# and "organization-level checks". Shards are how the scan is run; their IDs are
# for the logs. README: "Scaling to Large Organizations".

def describe_projects(projects, max_ids=25):
    """``"20 projects (p-001, p-002, ...)"``: the subject of an error row a reader can act on.

    A shard holds ``SCAN_SHARD_SIZE`` projects (20 by default), so the list is
    normally complete; beyond ``max_ids`` it ends with "and N more".
    """
    ids = [p.get("projectId", "?") if isinstance(p, dict) else str(p) for p in projects]
    listed = ", ".join(ids[:max_ids])
    if len(ids) > max_ids:
        listed += f", and {len(ids) - max_ids:,} more"
    return f"{len(ids):,} project{'' if len(ids) == 1 else 's'} ({listed})"


def not_checked_message(manifest, shard_id, reason):
    """The error row for a check a shard could not run.

    ``reason`` completes "the scan ..." (a project shard) or "the
    organization-level checks ..." (the scope shard), e.g. "failed after 3 attempts."
    """
    if shard_id == SCOPE_SHARD:
        return f"This check did not run: the {manifest['scope']}-level checks {reason}"
    return f"Not checked for {describe_projects(manifest['shards'][shard_id])}: the scan {reason}"


class FanOut:
    """Runs sharded scans. One instance per app (``Services.get_fanout()``).

    Args:
        settings: The app's settings (shard size, budgets, attempts).
        store: The results store (``GcsResultsStore``).
        enqueue: ``enqueue(path, body, task_id, schedule_delay_seconds=None) -> bool``:
            creates the named task, returning ``False`` if it already exists.
        task_exists: ``task_exists(task_id) -> bool | None``: whether a named task is
            still on the queue; ``None`` if unknown. Default: always unknown.
        banner: Notice rendered on the report (synthetic mode).
        clock: Monotonic clock for time budgets (tests).
        now: Wall clock, ``now() -> datetime`` (UTC), for the job's time limit (tests).
    """

    def __init__(self, settings, store, *, enqueue, task_exists=None, banner=None, clock=time.monotonic, now=None):
        self.settings = settings
        self.store = store
        self.enqueue = enqueue
        self.task_exists = task_exists or (lambda task_id: None)
        self.banner = banner
        self.clock = clock
        self.now = now or (lambda: datetime.now(timezone.utc))

    # --- Dispatch -----------------------------------------------------------------

    def should_fan_out(self, projects):
        """Whether a scan of ``projects`` is sharded (more projects than one shard holds)."""
        return len(projects) > self.settings.scan_shard_size

    def is_dispatched(self, job_id):
        """Whether the job already has a manifest (a retried dispatcher must not re-plan it)."""
        return self.store.read_manifest(job_id) is not None

    def dispatch(self, scope, scope_id, job_id, projects=None, requested_by=None):
        """Plans the shards (or re-reads the plan), enqueues every shard task and the first sweep.

        Safe to call again for the same job: the manifest is reused and the
        named tasks already on the queue are not created twice.
        """
        manifest = self.store.read_manifest(job_id)
        fresh = manifest is None
        if fresh:
            if projects is None:
                raise RuntimeError(f"[{job_id}] No manifest and no projects to plan shards from.")
            manifest = build_manifest(scope, scope_id, job_id, projects, self.settings.scan_shard_size, now=self.now(),
                                      requested_by=requested_by)
            manifest["time_limit_seconds"] = job_time_limit_seconds(self.settings, manifest["total_shards"])
            self.store.write_manifest(job_id, manifest)
        body = {"scope": scope, "scope_id": scope_id, "job_id": job_id}
        # The scope shard first: its checks (org policies, resilience assets) tend to be the slowest.
        shard_ids = [SCOPE_SHARD] + [shard_id for shard_id in manifest["shards"] if shard_id != SCOPE_SHARD]
        created = sum(1 for shard_id in shard_ids
                      if self.enqueue(SHARD_PATH, {**body, "shard_id": shard_id}, shard_task_id(job_id, shard_id)))
        self.enqueue(SWEEP_PATH, {**body, "sweep": 1}, sweep_task_id(job_id, 1),
                     schedule_delay_seconds=self._sweep_delay(manifest, elapsed=0))
        print(f"[{job_id}] Dispatched {manifest['total_projects']} projects in {manifest['total_shards']} shards "
              f"({created} tasks created); time limit {self._time_limit(manifest) / 3600:.1f} h.")
        # A retried dispatcher must not move the progress backwards: the shards may be
        # reporting already. It writes the status only if the first attempt never did.
        if fresh or not (self._current_status(job_id, scope_id) or {}).get("phase"):
            markers = {} if fresh else self.store.read_markers(job_id)
            text = (self._progress_text(manifest, markers) if markers
                    else f"Scanning {manifest['total_projects']:,} projects in parallel...")
            self.store.update_status(job_id, scope_id, 5, text, **self._status_fields(manifest, markers, phase="scanning"))
        return manifest

    def _current_status(self, job_id, scope_id):
        try:
            return self.store.read_status(job_id, scope_id)
        except Exception as e:
            print(f"[{job_id}] Could not read the job's status ({e}).")
            return None

    # --- Time limit ---------------------------------------------------------------

    def _time_limit(self, manifest):
        """The job's time limit in seconds: as planned at dispatch, else computed from the manifest."""
        return manifest.get("time_limit_seconds") or job_time_limit_seconds(self.settings, manifest["total_shards"])

    def _elapsed_seconds(self, manifest):
        """Wall-clock seconds since the job was dispatched (the manifest's ``created_at``)."""
        created = datetime.fromisoformat(manifest["created_at"])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0.0, (self.now() - created).total_seconds())

    def _sweep_delay(self, manifest, elapsed):
        """Seconds until the next sweep: the usual interval, or less so the time limit is checked on time."""
        remaining = self._time_limit(manifest) - elapsed
        return int(min(self.settings.sweep_interval_seconds, max(remaining, MIN_SWEEP_DELAY_SECONDS)))

    # --- Shards -------------------------------------------------------------------

    def _check_names(self, manifest, shard_id):
        """The names of the checks a shard owns (static: no clients, no network)."""
        return shard_check_names(manifest["scope"], shard_id == SCOPE_SHARD)

    def _plan_for(self, manifest, shard_id):
        scope, scope_id, job_id = manifest["scope"], manifest["scope_id"], manifest["job_id"]
        if shard_id == SCOPE_SHARD:
            return scope_check_plan(scope, scope_id, job_id)
        projects = manifest["shards"][shard_id]
        print(f"📍 [{job_id}] {shard_id}: discovering active locations of {len(projects)} projects...")
        location_errors = {}  # project ID -> why its locations could not be discovered; the location checks report these
        active_zones, active_regions = get_active_compute_locations(projects, on_error=location_errors.__setitem__)
        return project_check_plan(scope, scope_id, job_id, projects, active_zones, active_regions, location_errors)

    def run_shard(self, data, retry_count=0):
        """Body of ``/scan-shard``.

        Returns ``True`` when the shard is finished (its marker is written: success,
        partial, or final failure with error rows) and ``False`` when this attempt
        failed and Cloud Tasks should retry it.
        """
        job_id = shard_id = None
        try:
            scope_id, job_id, shard_id = data['scope_id'], data['job_id'], data['shard_id']
            attempt = retry_count + 1
            last_attempt = attempt >= self.settings.task_max_attempts
            print(f"[{job_id}] Shard {shard_id} starting (attempt {attempt}/{self.settings.task_max_attempts}).")

            manifest = self.store.read_manifest(job_id)
            if manifest is None:
                if self.store.report_exists(job_id, scope_id):
                    print(f"[{job_id}] Shard {shard_id}: the job is already complete; nothing to do.")
                    return True
                raise RuntimeError(f"No manifest for job {job_id}.")
            if shard_id not in manifest["shards"]:
                raise ValueError(f"Shard {shard_id} is not in the manifest of job {job_id}.")

            markers = self.store.read_markers(job_id)
            if shard_id in markers:
                print(f"[{job_id}] Shard {shard_id} already finished (duplicate delivery); re-checking fan-in.")
                return self._after_shard(manifest, scope_id, job_id, markers)

            # A retry starts clean: whatever a previous attempt wrote is replaced, never duplicated.
            self.store.cleanup_intermediate(job_id, shard_id=shard_id)
            sink = ShardSink(self.store, job_id, shard_id)
            started = self.clock()
            marker = {"shard_id": shard_id, "attempt": attempt, "projects": len(manifest["shards"][shard_id])}
            try:
                plan = self._plan_for(manifest, shard_id)
                subject = None if shard_id == SCOPE_SHARD else describe_projects(manifest["shards"][shard_id])
                summary = run_check_plan(plan, job_id, sink=sink, time_budget_seconds=self.settings.shard_time_budget_seconds,
                                         clock=self.clock, subject=subject)
                marker.update(status=TIMED_OUT if summary["unfinished"] else SUCCESS, checks=summary["checks"],
                              failed_checks=summary["failed"], unfinished_checks=summary["unfinished"])
            except Exception as e:
                print(f"[{job_id}] Shard {shard_id} failed on attempt {attempt}: {e}")
                traceback.print_exc()
                if not last_attempt:
                    return False  # 5xx: Cloud Tasks retries the task
                # Final attempt: this shard's checks become error rows, and the job goes on without it.
                names = self._check_names(manifest, shard_id)
                message = not_checked_message(manifest, shard_id, f"failed after {attempt} attempts. Last error: {e}")
                for name in names:
                    record_error(sink, job_id, name, message)
                marker.update(status=FAILED, error=str(e), checks=len(names), failed_checks=len(names), unfinished_checks=[])
            marker["elapsed_seconds"] = round(self.clock() - started, 1)
            marker["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self.store.write_marker(job_id, shard_id, marker)
            print(f"[{job_id}] Shard {shard_id} finished: {marker['status']} in {marker['elapsed_seconds']} s.")
            return self._after_shard(manifest, scope_id, job_id, self.store.read_markers(job_id))
        except Exception as e:
            print(f"[{job_id}] CRITICAL ERROR in shard {shard_id}: {e}")
            traceback.print_exc()
            return False

    def _status_fields(self, manifest, markers, phase):
        done = len(markers)
        failed = sum(1 for marker in markers.values() if marker.get("status") != SUCCESS)
        return {"phase": phase, "total_projects": manifest["total_projects"], "total_shards": manifest["total_shards"],
                "completed_shards": done, "failed_shards": failed}

    def _progress_text(self, manifest, markers):
        """The status page's message while the scan runs: projects and the scope checks, not shards."""
        shards = manifest["shards"]
        scanned = sum(len(shards.get(shard_id, [])) for shard_id in markers)
        text = f"Scanned {scanned:,} of {manifest['total_projects']:,} projects"
        text += f" · {manifest['scope']}-level checks: {'completed' if SCOPE_SHARD in markers else 'in progress'}"
        if any(marker.get("status") != SUCCESS for marker in markers.values()):
            text += " · some checks could not run (listed as errors in the report)"
        return text

    def _subjects(self, manifest, shard_ids):
        """``"20 projects and the organization-level checks"``: what some shards cover, for a status message."""
        count = sum(len(manifest["shards"][shard_id]) for shard_id in shard_ids if shard_id != SCOPE_SHARD)
        parts = [f"{count:,} project{'' if count == 1 else 's'}"] if count else []
        if SCOPE_SHARD in shard_ids:
            parts.append(f"the {manifest['scope']}-level checks")
        return " and ".join(parts)

    def _after_shard(self, manifest, scope_id, job_id, markers):
        """The fan-in: triggers the aggregation once every shard has a marker, else reports progress."""
        total = manifest["total_shards"]
        if len(markers) >= total:
            self._trigger_aggregation(manifest, scope_id, job_id, markers)
        else:
            progress = 5 + int(85 * len(markers) / total)
            self.store.update_status(job_id, scope_id, progress, self._progress_text(manifest, markers),
                                     **self._status_fields(manifest, markers, phase="scanning"))
        return True

    def _trigger_aggregation(self, manifest, scope_id, job_id, markers, note=None):
        body = {"scope": manifest["scope"], "scope_id": scope_id, "job_id": job_id}
        created = self.enqueue(AGGREGATE_PATH, body, aggregate_task_id(job_id))
        if created:
            text = note or "Scanning finished. Merging the results..."
            self.store.update_status(job_id, scope_id, 90, text, **self._status_fields(manifest, markers, phase="aggregating"))
        return created

    # --- Aggregation --------------------------------------------------------------

    def aggregate(self, data, retry_count=0):
        """Body of ``/run-aggregation``: merges the shards' findings into the final reports.

        Returns ``True`` when the reports are uploaded (or already were) and
        ``False`` when this attempt failed. The job's status is set to ``error``
        only on the last attempt; until then the files stay for the retry.
        """
        scope_id = job_id = None
        last_attempt = retry_count + 1 >= self.settings.task_max_attempts
        try:
            scope, scope_id, job_id = data['scope'], data['scope_id'], data['job_id']
            if self.store.report_exists(job_id, scope_id):
                print(f"[{job_id}] Aggregation: the report already exists; nothing to do.")
                return True
            manifest = self.store.read_manifest(job_id)
            if manifest is None:
                raise RuntimeError(f"No manifest for job {job_id}; nothing to aggregate.")
            markers = self.store.read_markers(job_id)
            missing = [shard_id for shard_id in manifest["shards"] if shard_id not in markers]
            fields = self._status_fields(manifest, markers, phase="aggregating")
            self.store.update_status(job_id, scope_id, 92, f"Merging the findings of {manifest['total_projects']:,} projects...", **fields)

            findings = self.store.read_all_findings(job_id)
            for shard_id in missing:
                message = not_checked_message(manifest, shard_id, "did not finish; the results are missing from this report.")
                for name in self._check_names(manifest, shard_id):
                    findings.append(error_finding(name, message))
            findings = merge_shard_findings(findings)
            all_results = categorize_findings(findings)
            # Also read the special-cased org policy data (written by the scope shard)
            org_policy_data = self.store.read_org_policies(job_id, shard_id=SCOPE_SHARD)
            if org_policy_data[0] and org_policy_data[1]:
                all_results["Organization Policies"] = org_policy_data

            self.store.update_status(job_id, scope_id, 98, "Generating final HTML and CSV reports...", **fields)
            coverage = build_coverage(manifest, markers)
            previous = None if self.banner else self.store.read_previous_summary(scope, scope_id, job_id)
            # The manifest's project dicts carry what the folder listing reconciled (app.services.resource_manager).
            membership = folder_membership([project for shard in manifest["shards"].values() for project in shard])
            html_report, csv_report, summary = generate_reports(scope, scope_id, job_id, all_results, banner=self.banner,
                                                                coverage=coverage, previous=previous, membership=membership,
                                                                requested_by=manifest.get("requested_by"))
            self.store.upload_reports(job_id, scope_id, html_report, csv_report)
            if not self.banner:
                self.store.write_scan_summary(summary)
            self.store.update_status(job_id, scope_id, 100, "Scan complete!", status="completed",
                                     **self._status_fields(manifest, markers, phase="completed"))
            self.store.cleanup_intermediate(job_id)
            print(f"[{job_id}] Aggregation complete: {coverage['projects_scanned']}/{coverage['total_projects']} projects scanned, "
                  f"{coverage['shards_failed']} shards with errors, {coverage['shards_missing']} missing.")
            return True
        except Exception as e:
            print(f"[{job_id}] CRITICAL ERROR in aggregation for ID {scope_id}: {e}")
            traceback.print_exc()
            if job_id and scope_id:
                if last_attempt:
                    self.store.update_status(job_id, scope_id, 100, f"A critical error occurred: {e}", status="error", phase="error")
                    self.store.cleanup_intermediate(job_id)
                else:
                    self.store.update_status(job_id, scope_id, 92, f"Report generation failed ({e}); retrying...", phase="aggregating")
            return False

    # --- Sweeper ------------------------------------------------------------------

    def sweep(self, data):
        """Body of ``/sweep``: finishes a job whose shards have died, re-schedules itself otherwise.

        Always returns ``True``: a sweep that fails is simply repeated by the next one.
        """
        job_id = None
        try:
            scope, scope_id, job_id = data['scope'], data['scope_id'], data['job_id']
            sweep = int(data.get('sweep', 1))
            if self.store.report_exists(job_id, scope_id):
                print(f"[{job_id}] Sweep {sweep}: the job is complete.")
                return True
            manifest = self.store.read_manifest(job_id)
            if manifest is None:
                print(f"[{job_id}] Sweep {sweep}: no manifest (the job ended in an error); nothing to do.")
                return True
            markers = self.store.read_markers(job_id)
            pending = [shard_id for shard_id in manifest["shards"] if shard_id not in markers]
            if not pending:
                print(f"[{job_id}] Sweep {sweep}: every shard finished but no report yet; (re-)triggering the aggregation.")
                self._trigger_aggregation(manifest, scope_id, job_id, markers)
                return True

            # Shards whose task is gone crashed on every attempt: give them error rows and a marker.
            dead = [shard_id for shard_id in pending if self.task_exists(shard_task_id(job_id, shard_id)) is False]
            for shard_id in dead:
                sink = ShardSink(self.store, job_id, shard_id)
                names = self._check_names(manifest, shard_id)
                marker = {"shard_id": shard_id, "status": FAILED, "checks": len(names), "failed_checks": len(names),
                          "unfinished_checks": [], "projects": len(manifest["shards"][shard_id]),
                          "error": "The shard's task disappeared without reporting a result (it crashed on every attempt).",
                          "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "swept": sweep}
                if not self.store.write_marker(job_id, shard_id, marker, only_if_absent=True):
                    continue  # it finished after all, between our listing and now
                message = not_checked_message(manifest, shard_id, "crashed on every attempt.")
                for name in names:
                    record_error(sink, job_id, name, message)
                logging.warning(f"[{job_id}] Sweep {sweep}: shard {shard_id} is dead; recorded error rows.")
            markers = self.store.read_markers(job_id)
            still_pending = [shard_id for shard_id in manifest["shards"] if shard_id not in markers]
            if not still_pending:
                self._trigger_aggregation(manifest, scope_id, job_id, markers,
                                          note=f"The scan of {self._subjects(manifest, dead)} failed; merging the results of the others...")
                return True
            elapsed, limit = self._elapsed_seconds(manifest), self._time_limit(manifest)
            if elapsed < limit:
                print(f"[{job_id}] Sweep {sweep}: {len(still_pending)} shards still queued or running after {elapsed / 3600:.1f} h "
                      f"(time limit {limit / 3600:.1f} h); checking again later.")
                self.enqueue(SWEEP_PATH, {"scope": scope, "scope_id": scope_id, "job_id": job_id, "sweep": sweep + 1},
                             sweep_task_id(job_id, sweep + 1), schedule_delay_seconds=self._sweep_delay(manifest, elapsed))
                return True
            # The time limit is up: the aggregation records the missing shards as error rows.
            logging.error(f"[{job_id}] Sweep {sweep}: {len(still_pending)} shards still not finished after {elapsed / 3600:.1f} h, "
                          f"the job's time limit of {limit / 3600:.1f} h; finishing the job without them.")
            self._trigger_aggregation(manifest, scope_id, job_id, markers,
                                      note=f"The scan of {self._subjects(manifest, still_pending)} did not finish; "
                                           f"generating the report with the results so far...")
            return True
        except Exception as e:
            print(f"[{job_id}] Sweep failed: {e}")
            traceback.print_exc()
            return True
