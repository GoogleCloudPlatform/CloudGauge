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
projects in scope, discovers active locations once, builds the plan with
``app.checks.registry.build_check_plan``, and runs every check on a
``ThreadPoolExecutor``. Checks write their findings through ``sink``. A check
that raises is recorded as an ``ERROR_<name>`` finding and the scan continues.
"""
import concurrent.futures

from app.checks.registry import build_check_plan
from app.config import CHECK_RUNNER_MAX_WORKERS
from app.services.resource_manager import get_active_compute_locations, list_projects_for_scope


def run_all_checks(scope, scope_id, job_id, progress_callback=None, *, sink, max_workers=CHECK_RUNNER_MAX_WORKERS):
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

    Returns:
        dict: A dictionary containing all categorized findings.
        (In practice: ``True`` once every check has finished, or
        ``{"error": ...}`` if no projects were found. Findings are in ``sink``.)
    """
    print("🚀 Starting organization scan, fetching all projects first...")
    all_projects = list_projects_for_scope(scope, scope_id)
    if not all_projects:
        print("❌ No active projects found or failed to list projects. Aborting scan.")
        return {"error": "Could not retrieve project list."}

    # --- RUN LOCATION SCAN ONCE HERE ---
    print("📍 Discovering all active locations (running once)...")
    active_zones, active_regions = get_active_compute_locations(all_projects)
    print(f"✅ Discovery complete. Found {len(active_zones)} zones and {len(active_regions)} regions.")

    # The registry lists every check as (Category, Friendly Name, function_to_run, (tuple_of_arguments,))
    all_checks_to_run = build_check_plan(scope, scope_id, job_id, all_projects, active_zones, active_regions)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # This map directly links each running task (future) to its specific name and category.
        future_to_info = {
            executor.submit(func, *args, sink=sink): {"category": category, "name": name}
            for category, name, func, args in all_checks_to_run
        }

        total_checks = len(future_to_info)
        completed_checks = 0

        for future in concurrent.futures.as_completed(future_to_info):
            info = future_to_info[future]
            check_name = info["name"] # This will now ALWAYS be the specific name.

            try:
                future.result()  # Call result to raise exceptions, but don't store return value
            except Exception as e:
                print(f"❌ Check '{check_name}' failed critically: {e}")
                # Optionally write an error finding to a temp file
                error_result = {"Check": check_name, "Finding": [{"Error": str(e)}], "Status": "Error"}
                sink.write_finding(job_id, f"ERROR_{check_name}".replace(" ", "_"), error_result)
            finally:
                completed_checks += 1
                progress = 5 + int((completed_checks / total_checks) * 90)
                if progress_callback:
                    progress_callback(progress=progress, current_task=f"({completed_checks}/{total_checks}) Finished: {check_name}")

    return True
