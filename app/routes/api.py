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
"""JSON endpoints under ``/api``.

Reports already stored in GCS call ``/api/get-insights``, ``/api/get-summary``
and ``/api/get-suggestions`` by path, so these URLs must not change.
"""
import concurrent.futures
import traceback

from flask import Blueprint, jsonify, request

from app.extensions import get_services
from app.services import gemini, resource_manager
from app.services import insights as insights_service

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route('/list-resources')
def list_resources():
    """API endpoint to list resources based on scope (org, folder, project)."""
    scope = request.args.get('scope')
    if not scope:
        return jsonify({"error": "Scope parameter is required"}), 400

    org_id = resource_manager.get_parent_org(get_services().settings.project_id)
    if not org_id:
        return jsonify({"error": "Could not determine parent organization"}), 500

    try:
        resources = resource_manager.list_resources_for_scope(scope, org_id)
        return jsonify(resources)
    except resource_manager.InvalidScopeError:
        return jsonify({"error": "Invalid scope"}), 400
    except Exception as e:
        print(f"❌ Error listing resources: {e}")
        traceback.print_exc()
        return jsonify({"error": f"Failed to list resources: {e}"}), 500


@bp.route('/status/<string:job_id>/<string:scope_id>')
def api_check_status(job_id, scope_id):
    """
    API endpoint for the front-end to poll. Checks the status.json file
    in GCS to provide real-time progress updates.
    """
    try:
        status_data = get_services().results_store.read_status(job_id, scope_id)
        if status_data is not None:
            # If the status file is there, return its content
            return jsonify(status_data)
        else:
            # If the worker hasn't created the file yet, return a pending state
            return jsonify({"status": "pending", "progress": 0, "current_task": "Waiting for task to start..."})

    except Exception as e:
        print(f"Error checking status for job {job_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/get-insights', methods=['POST'])
def get_insights():
    """
    On-demand endpoint to run a slower, more detailed scan for cost optimization
    insights, separate from the main recommendations.
    """
    data = request.get_json()
    scope = data.get('scope')
    scope_id = data.get('scope_id')
    if not scope_id or not scope:
        return jsonify({"error": "Scope and Scope ID are required."}), 400

    try:
        insights = insights_service.run_cost_optimization_insights(scope, scope_id)
        return jsonify(insights)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"An internal error occurred while fetching insights: {e}"}), 500


@bp.route('/get-summary', methods=['POST'])
def get_summary():
    """
    On-demand endpoint to generate a Gemini-powered executive summary
    from the full CSV report data stored in GCS.
    """
    try:
        data = request.get_json()
        scope_id = data.get('scope_id')  # CORRECTED
        job_id = data.get('job_id')
        print(f"🤖 Received on-demand request for AI summary for job {job_id}...")

        if not scope_id or not job_id:
            return jsonify({"error": "Scope ID and Job ID are required."}), 400

        services = get_services()

        # 1. Fetch the context (the full CSV report) from GCS
        csv_data = services.results_store.read_report(job_id, scope_id, extension="csv")
        if csv_data is None:
            return jsonify({"error": "CSV report not found. Cannot generate summary."}), 404

        # 2-4. Prompt Gemini on Vertex AI for the summary
        summary = gemini.generate_executive_summary(csv_data, settings=services.settings)

        print(f"✅ AI summary generated successfully for job {job_id}.")
        return jsonify({"summary": summary})

    except Exception as e:
        print(f"CRITICAL ERROR in /api/get-summary: {e}")
        traceback.print_exc()
        return jsonify({"error": "An internal error occurred while generating the AI summary."}), 500


@bp.route('/get-suggestions', methods=['POST'])
def get_suggestions():
    """
    Receives a batch of findings from the report and uses the Gemini API
    to generate gcloud remediation commands for each one.
    """
    try:
        data = request.get_json()
        actionable_findings = data.get('findings', [])
        # Read here: the worker threads below have no app context.
        settings = get_services().settings

        remediation_map = {}
        if actionable_findings:
            print(f"🤖 On-demand request for {len(actionable_findings)} Gemini suggestions...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                def call_gemini(finding_info):
                    # The generate_remediation_command function already has its own internal try/except,
                    # which is good for handling individual AI call failures.
                    return gemini.generate_remediation_command(finding_info['finding_text'], finding_info['project_id'], settings=settings)

                results = executor.map(call_gemini, actionable_findings)

            for i, command in enumerate(results):
                # The key is now based on the original index from the batch
                original_index = actionable_findings[i]['index']
                remediation_map[f"finding-{original_index}"] = command

            print("✅ Gemini on-demand suggestions received.")

        return jsonify(remediation_map)

    except Exception as e:
        # This is the crucial safety net. It will catch any unhandled exceptions.
        print(f"CRITICAL ERROR in /api/get-suggestions: {e}")
        traceback.print_exc()
        # Return a 500 error to the browser so the 'catch' block is triggered.
        return jsonify({"error": "An internal error occurred on the server."}), 500
