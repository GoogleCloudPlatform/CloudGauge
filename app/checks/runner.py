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
"""Runs a scan's checks concurrently.

``run_all_checks`` replaces the legacy function of the same name. It lists the
projects in scope (unless given them), discovers active locations once, builds
the plan with ``app.checks.registry.build_check_plan``, and runs every check on
a ``ThreadPoolExecutor`` through ``run_check_plan``, which the sharded scan
(``app.fanout``) also uses for one shard's plan. Checks write their findings
through ``sink``. A check that raises is recorded as an ``ERROR_<name>`` finding
and the scan continues; so is a check that hasn't finished when the optional
time budget runs out.
"""
import concurrent.futures
import time

from app.checks.registry import build_check_plan, scope_check_plan
from app.config import CHECK_RUNNER_MAX_WORKERS
from app.services.resource_manager import get_active_compute_locations, list_projects_for_scope


def list_projects(scope, scope_id):
    """Lists the ACTIVE projects in scope: the first step of every scan."""
    print("🚀 Starting organization scan, fetching all projects first...")
    return list_projects_for_scope(scope, scope_id)


def error_finding(check_name, message):
    """The finding the runner records for a check that failed or didn't finish."""
    return {"Check": check_name, "Finding": [{"Error": message}], "Status": "Error"}


def record_error(sink, job_id, check_name, message):
    """Writes :func:`error_finding` under the ``ERROR_<name>`` file name."""
    sink.write_finding(job_id, f"ERROR_{check_name}".replace(" ", "_"), error_finding(check_name, message))


def run_check_plan(plan, job_id, *, sink, progress_callback=None, max_workers=CHECK_RUNNER_MAX_WORKERS,
                   time_budget_seconds=None, clock=time.monotonic, subject=None):
    """Runs the ``CheckSpec`` entries of ``plan`` concurrently and returns a summary.

    Args:
        plan: ``CheckSpec`` entries; each is called as ``func(*args, sink=sink)``.
        job_id: The scan's job ID, used to name the findings.
        sink: Where checks (and the runner's error records) write their findings.
        progress_callback: Called after every check with ``progress`` (5..95) and ``current_task``.
        max_workers: Number of checks that run at the same time.
        time_budget_seconds: If set, checks that have not finished by then are
            recorded as errors and the call returns without waiting for them
            (queued ones are cancelled; running ones finish in the background).
        clock: Monotonic clock (tests).
        subject: What the plan covers, for the time-budget error row a user
            reads, e.g. ``"20 projects (p-001, ...)"``.

    Returns:
        dict: ``{"checks", "completed", "failed", "unfinished": [names]}``.
    """
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    started = clock()
    # This map directly links each running task (future) to its specific name and category.
    future_to_info = {
        executor.submit(func, *args, sink=sink): {"category": category, "name": name}
        for category, name, func, args in plan
    }
    total_checks = len(future_to_info)
    completed_checks, failed = 0, 0
    pending = set(future_to_info)
    timed_out = False

    while pending:
        timeout = None
        if time_budget_seconds is not None:
            timeout = max(0.0, time_budget_seconds - (clock() - started))
        done, pending = concurrent.futures.wait(pending, timeout=timeout, return_when=concurrent.futures.FIRST_COMPLETED)
        if not done:
            timed_out = True
            break
        for future in done:
            check_name = future_to_info[future]["name"]  # This will now ALWAYS be the specific name.
            try:
                future.result()  # Call result to raise exceptions, but don't store return value
            except Exception as e:
                print(f"❌ Check '{check_name}' failed critically: {e}")
                failed += 1
                # Optionally write an error finding to a temp file
                record_error(sink, job_id, check_name, str(e))
            finally:
                completed_checks += 1
                progress = 5 + int((completed_checks / total_checks) * 90)
                if progress_callback:
                    progress_callback(progress=progress, current_task=f"({completed_checks}/{total_checks}) Finished: {check_name}")

    unfinished = []
    if timed_out:
        for_whom = f" for {subject}" if subject else ""
        for future in pending:
            future.cancel()
            check_name = future_to_info[future]["name"]
            unfinished.append(check_name)
            print(f"⏱️ Check '{check_name}' did not finish within the {time_budget_seconds:.0f} s budget.")
            record_error(sink, job_id, check_name,
                         f"Check did not finish within the time budget of {time_budget_seconds:.0f} seconds{for_whom}.")
    # Don't block on checks that are still running after a timeout: the caller must answer Cloud Tasks.
    executor.shutdown(wait=not timed_out, cancel_futures=True)
    return {"checks": total_checks, "completed": completed_checks, "failed": failed, "unfinished": sorted(unfinished)}


def run_all_checks(scope, scope_id, job_id, progress_callback=None, *, sink, max_workers=CHECK_RUNNER_MAX_WORKERS, projects=None):
    """
    Orchestrates the entire scan by running all check functions in parallel.
    Groups the results into high-level categories for reporting.

    Args:
        scope (str): The scope of the scan (organization, folder, project).
        scope_id (str): The ID of the resource to scan.
        job_id (str): The scan's job ID, used to name the findings in GCS.
        progress_callback (function, optional): A function to call with progress updates.
        sink (GcsResultsStore): Where checks write their findings.
        max_workers (int): Number of checks that run at the same time.
        projects (list, optional): The projects in scope, if the caller has
            already listed them; ``None`` lists them here.

    Returns:
        bool: ``True`` once every check has finished. Findings are in ``sink``.
        With no project in scope only the scope-level checks run
        (``app.checks.registry.scope_check_plan``).
    """
    all_projects = list_projects(scope, scope_id) if projects is None else projects
    if not all_projects:
        # An empty folder, or a listing that failed (resource_manager logged why). There is nothing
        # to discover locations in and no project check to run, but the scope's own checks still
        # apply: a folder's organization policies hold whether or not it holds a project (v15.3;
        # the scan used to stop here and report every category as not assessed).
        print("⚠️ No active projects found or failed to list projects: running the scope-level checks only.")
        run_check_plan(scope_check_plan(scope, scope_id, job_id), job_id, sink=sink,
                       progress_callback=progress_callback, max_workers=max_workers)
        return True

    # --- RUN LOCATION SCAN ONCE HERE ---
    print("📍 Discovering all active locations (running once)...")
    location_errors = {}  # project ID -> why its locations could not be discovered; the location checks report these
    active_zones, active_regions = get_active_compute_locations(all_projects, on_error=location_errors.__setitem__)
    print(f"✅ Discovery complete. Found {len(active_zones)} zones and {len(active_regions)} regions.")

    # The registry lists every check as (Category, Friendly Name, function_to_run, (tuple_of_arguments,))
    all_checks_to_run = build_check_plan(scope, scope_id, job_id, all_projects, active_zones, active_regions, location_errors)
    run_check_plan(all_checks_to_run, job_id, sink=sink, progress_callback=progress_callback, max_workers=max_workers)
    return True
