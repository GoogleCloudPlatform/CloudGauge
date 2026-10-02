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
"""The Cloud Tasks worker endpoints.

Cloud Tasks posts ``{"scope", "scope_id", "job_id"}`` to ``/run-scan`` and retries
the task when the response is a 5xx, so the bodies and status codes are unchanged.

Sharded scans (``app.fanout``) add three endpoints with the same body plus a
``shard_id`` or ``sweep`` number: ``/scan-shard``, ``/run-aggregation`` and
``/sweep``. They follow the same convention: 200 when the task's work is done
(or no longer needed), 500 when Cloud Tasks should retry it. The
``X-CloudTasks-TaskRetryCount`` header tells a task whether this is its last
attempt, so that a shard that keeps failing ends as error rows in the report
rather than as a missing one.
"""
from flask import Blueprint, request

from app import scan_job
from app.extensions import get_services
from app.fanout import RETRY_COUNT_HEADER

bp = Blueprint("worker", __name__)


def retry_count():
    """The attempt's retry count from Cloud Tasks (0 on the first attempt, and when called directly)."""
    try:
        return int(request.headers.get(RETRY_COUNT_HEADER, 0))
    except (TypeError, ValueError):
        return 0


@bp.route('/run-scan', methods=['POST'])
def run_scan_worker():
    """
    The worker endpoint triggered by Cloud Tasks. It executes the main `run_all_checks`
    function and uploads the generated reports to Google Cloud Storage (or, for a
    scope with more projects than one shard holds, dispatches the shard tasks).
    """
    data = request.get_json(force=True)
    services = get_services()
    if scan_job.execute_scan_job(data, store=services.results_store, banner=services.report_banner, fanout=services.get_fanout()):
        return "Scan completed and reports uploaded.", 200
    return "Internal Server Error", 500


@bp.route('/scan-shard', methods=['POST'])
def scan_shard_worker():
    """Runs one shard of a sharded scan and, if it was the last one, triggers the aggregation."""
    data = request.get_json(force=True)
    if get_services().get_fanout().run_shard(data, retry_count=retry_count()):
        return "Shard finished.", 200
    return "Internal Server Error", 500


@bp.route('/run-aggregation', methods=['POST'])
def run_aggregation_worker():
    """Merges the shards' findings into the final reports and completes the job."""
    data = request.get_json(force=True)
    if get_services().get_fanout().aggregate(data, retry_count=retry_count()):
        return "Aggregation completed and reports uploaded.", 200
    return "Internal Server Error", 500


@bp.route('/sweep', methods=['POST'])
def sweep_worker():
    """Checks on a running sharded job; finishes it if its shards have died, else re-schedules itself."""
    data = request.get_json(force=True)
    get_services().get_fanout().sweep(data)
    return "Sweep done.", 200
