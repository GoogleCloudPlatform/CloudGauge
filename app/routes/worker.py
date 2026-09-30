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
"""The Cloud Tasks worker endpoint.

Cloud Tasks posts ``{"scope", "scope_id", "job_id"}`` to ``/run-scan`` and retries
the task when the response is a 5xx, so the bodies and status codes are unchanged.
"""
from flask import Blueprint, request

from app import scan_job
from app.extensions import get_services

bp = Blueprint("worker", __name__)


@bp.route('/run-scan', methods=['POST'])
def run_scan_worker():
    """
    The worker endpoint triggered by Cloud Tasks. It executes the main `run_all_checks`
    function and uploads the generated reports to Google Cloud Storage.
    """
    data = request.get_json(force=True)
    if scan_job.execute_scan_job(data, store=get_services().results_store):
        return "Scan completed and reports uploaded.", 200
    return "Internal Server Error", 500
