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
"""Runs one scan job end to end: the body of the legacy ``run_scan_worker`` route.

``execute_scan_job`` takes the Cloud Tasks payload ``{"scope", "scope_id", "job_id"}``
and, in order: writes status updates, runs every check with throttled progress
reporting, reads the findings back and categorizes them, renders the HTML and
CSV reports, uploads them, and marks the job complete. If anything fails, the
error is written to the job's status file. Intermediate files are always
deleted. The ``/run-scan`` route only turns the result into an HTTP response.

Large scopes don't run here: when a ``fanout`` is given and the scope has more
projects than one shard holds, the job is handed to ``app.fanout`` (the
dispatcher enqueues one task per shard and returns), and the status page
follows those tasks instead. Small scopes run inline exactly as before.

It sits above ``app.checks`` and ``app.reporting`` so that neither depends on the other.
"""
import traceback

from app.checks.categories import categorize_findings
from app.checks.runner import list_projects, run_all_checks
from app.reporting.csv_report import generate_csv_data
from app.reporting.html_report import generate_html_report
from app.utils import ThrottledProgressReporter


def already_completed(store, job_id, scope_id):
    """Whether the job's status says it is done (a retried task must not scan again)."""
    try:
        status = store.read_status(job_id, scope_id)
    except Exception as e:
        print(f"[{job_id}] Could not read the job's status ({e}); assuming it has not run.")
        return False
    return bool(status) and status.get("status") == "completed"


def execute_scan_job(data, *, store, banner=None, fanout=None):
    """
    Executes the main `run_all_checks` function and uploads the generated reports
    to Google Cloud Storage.

    Args:
        data (dict): The Cloud Tasks payload with ``scope``, ``scope_id`` and ``job_id``.
        store (GcsResultsStore): The results bucket: findings, status, and reports.
        banner (str, optional): A notice rendered at the top of the HTML report
            (the synthetic load mode marks its reports with one).
        fanout (FanOut, optional): Runs scopes with more projects than one shard
            holds as a sharded scan. ``None``: every scope runs inline.

    Returns:
        bool: True if the reports were uploaded (or the job was dispatched to
        shards, or had already completed). False if the job failed; the error
        was logged and, if the job is known, written to its status file.
    """
    scope_id, job_id = None, None
    dispatched = False
    try:
        scope = data['scope']
        scope_id = data['scope_id']
        job_id = data['job_id']
        print(f"[{job_id}] Worker received task for ID: {scope_id}")

        # Cloud Tasks delivers at least once: a task retried after the scan finished must not run it again.
        if already_completed(store, job_id, scope_id):
            print(f"[{job_id}] Job already completed; ignoring the duplicate task.")
            dispatched = True  # nothing to clean up either
            return True
        if fanout is not None and fanout.is_dispatched(job_id):
            # A retried dispatcher: the shards are planned; make sure every task exists and leave them to it.
            print(f"[{job_id}] Job already dispatched to shards; re-enqueueing any missing shard tasks.")
            fanout.dispatch(scope, scope_id, job_id)
            dispatched = True
            return True

        store.update_status(job_id, scope_id, 5, "Initializing scan and listing resources...")

        projects = None
        if fanout is not None:
            projects = list_projects(scope, scope_id)
            if fanout.should_fan_out(projects):
                fanout.dispatch(scope, scope_id, job_id, projects)
                dispatched = True
                return True

        # --- Throttling logic setup ---
        # We will only update GCS if at least 2 seconds have passed since the last update.
        progress_reporter = ThrottledProgressReporter(
            lambda progress, current_task: store.update_status(job_id, scope_id, progress, current_task)
        )

        run_all_checks(scope, scope_id, job_id, progress_callback=progress_reporter, sink=store, projects=projects)

        # --- Final, unconditional update after checks complete ---
        progress_reporter.flush()

        store.update_status(job_id, scope_id, 98, "Generating final HTML and CSV reports...")

        # 2. Read all results back from /gcs for report generation
        all_results = categorize_findings(store.read_all_findings(job_id))
        # Also read the special-cased org policy data
        org_policy_data = store.read_org_policies(job_id)
        if org_policy_data[0] and org_policy_data[1]:
            all_results["Organization Policies"] = org_policy_data

        html_report = generate_html_report(scope, scope_id, job_id, banner=banner, **all_results)
        csv_report = generate_csv_data(all_results)

        store.upload_reports(job_id, scope_id, html_report, csv_report)

        store.update_status(job_id, scope_id, 100, "Scan complete!", status="completed")

        print(f"[{job_id}] Task completed successfully.")
        return True
    except Exception as e:
        print(f"[{job_id}] CRITICAL ERROR in worker for ID {scope_id}: {e}")
        traceback.print_exc()
        if job_id and scope_id:
            store.update_status(job_id, scope_id, 100, f"A critical error occurred: {e}", status="error")
        return False
    finally:
        # CRUCIAL: Clean up all intermediate files from GCS for this job_id
        # (not when the job runs in shards: they are writing there now).
        if job_id and not dispatched:
            store.cleanup_intermediate(job_id)
