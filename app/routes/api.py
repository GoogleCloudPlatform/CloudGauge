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

v18.6.1: every identifier is validated (``app.validation``; a malformed one is a 400 JSON
error), the POST routes are same-origin only (``app.routes.guards``), and
``/api/get-suggestions`` takes at most ``MAX_SUGGESTIONS_PER_REQUEST`` findings.
"""
import concurrent.futures
import traceback

from flask import Blueprint, jsonify, request

from app import validation
from app.config import MAX_SUGGESTION_PROJECT_CHARS, MAX_SUGGESTION_TEXT_CHARS, MAX_SUGGESTIONS_PER_REQUEST
from app.extensions import get_services
from app.routes import guards
from app.services import gemini, resource_manager
from app.services import insights as insights_service

bp = Blueprint("api", __name__, url_prefix="/api")
bp.before_request(guards.same_origin_required)


@bp.errorhandler(validation.RequestError)
def bad_request(error):
    """A malformed value in a path or a JSON body: 400 with the reason."""
    return jsonify({"error": str(error)}), 400


def json_body():
    """The request's JSON object, or a 400 (a body that is not JSON, not an object, or ``null``)."""
    return validation.clean_body(request.get_json(force=True, silent=True))


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
    job_id = validation.clean_job_id(job_id)
    scope_id = validation.clean_any_scope_id(scope_id)
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
    data = json_body()
    scope = validation.clean_scope(data.get('scope'))
    scope_id = validation.clean_scope_id(scope, data.get('scope_id'))

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
    data = json_body()
    job_id = validation.clean_job_id(data.get('job_id'))
    scope = data.get('scope')  # v15.3: the report page sends it; absent from pages rendered earlier
    scope = validation.clean_scope(scope) if scope else None
    scope_id = validation.clean_scope_id(scope, data.get('scope_id')) if scope else validation.clean_any_scope_id(data.get('scope_id'))
    try:
        print(f"🤖 Received on-demand request for AI summary for job {job_id}...")
        services = get_services()

        # 1. Fetch the context (the full CSV report) from GCS
        csv_data = services.results_store.read_report(job_id, scope_id, extension="csv")
        if csv_data is None:
            return jsonify({"error": "CSV report not found. Cannot generate summary."}), 404

        # 2-4. Prompt Gemini on Vertex AI for the summary
        summary = gemini.generate_executive_summary(csv_data, scope=scope, settings=services.settings)

        print(f"✅ AI summary generated successfully for job {job_id}.")
        return jsonify({"summary": summary})

    except Exception as e:
        print(f"CRITICAL ERROR in /api/get-summary: {e}")
        traceback.print_exc()
        return jsonify({"error": "An internal error occurred while generating the AI summary."}), 500


def clean_findings(data):
    """The findings of a ``/api/get-suggestions`` body, bounded (v18.6.1): at most ``MAX_SUGGESTIONS_PER_REQUEST`` of
    ``{index, finding_text, project_id}`` with the text and the project name capped. Raises ``RequestError``."""
    findings = data.get('findings', [])
    if not isinstance(findings, list):
        raise validation.RequestError("findings must be a list.")
    if len(findings) > MAX_SUGGESTIONS_PER_REQUEST:
        raise validation.RequestError(f"findings holds {len(findings)} items; at most {MAX_SUGGESTIONS_PER_REQUEST} per request.")
    cleaned = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise validation.RequestError("Each finding must be an object with index, finding_text and project_id.")
        index, text, project = finding.get('index'), finding.get('finding_text'), finding.get('project_id') or ''
        if isinstance(index, bool) or not isinstance(index, (int, str)) or not str(index).strip().isdigit():
            raise validation.RequestError("A finding's index must be a non-negative integer.")
        if not isinstance(text, str) or not text.strip():
            raise validation.RequestError("A finding's finding_text must be a non-empty string.")
        if len(text) > MAX_SUGGESTION_TEXT_CHARS:
            raise validation.RequestError(f"A finding's finding_text is longer than {MAX_SUGGESTION_TEXT_CHARS:,} characters.")
        if not isinstance(project, str) or len(project) > MAX_SUGGESTION_PROJECT_CHARS or not project.isprintable():
            raise validation.RequestError(f"A finding's project_id must be a printable name of at most {MAX_SUGGESTION_PROJECT_CHARS} characters.")
        cleaned.append({'index': str(index).strip(), 'finding_text': text, 'project_id': project.strip()})
    return cleaned


@bp.route('/get-suggestions', methods=['POST'])
def get_suggestions():
    """
    Receives a batch of findings from the report and uses the Gemini API
    to generate gcloud remediation commands for each one.
    """
    actionable_findings = clean_findings(json_body())
    try:
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
