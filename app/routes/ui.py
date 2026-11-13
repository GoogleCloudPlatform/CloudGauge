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
"""Pages: the landing form, scan submission, the status page, the report viewer, the CSV download, and the history page (v17).

Every identifier a URL or the form carries goes through ``app.validation`` first (v18.6.1): a malformed one is a 400 before
anything is read or written. ``POST /scan`` is also same-origin only (``app.routes.guards``) and starts nothing while the
scope's previous scan is still running (409, ``app.services.schedules``).
"""
from flask import Blueprint, Response, jsonify, redirect, render_template, request, stream_with_context, url_for
from werkzeug.utils import secure_filename

from app import identity, validation
from app.config import HISTORY_PAGE_SCANS
from app.extensions import get_services
from app.reporting.history import build_history
from app.routes import guards
from app.services import schedules

bp = Blueprint("ui", __name__)
bp.before_request(guards.same_origin_required)
SCOPES = validation.SCOPES
# How much of a CSV report the download route holds at a time (v16.1: the status page's Download CSV
# goes through this route, so an organization-sized CSV must not sit whole in the web service's memory).
CSV_CHUNK_BYTES = 1024 * 1024


@bp.errorhandler(validation.RequestError)
def bad_request(error):
    """A malformed identifier in a page URL or the form: 400 with the reason."""
    return str(error), 400


@bp.route('/', methods=['GET'])
def index():
    """Renders the main landing page with a dynamic form to select a resource."""
    return render_template("index.html")


@bp.route('/scan', methods=['POST'])
def create_scan_task():
    """
    Receives the scope ( Org, Folder or Project ) from the form, creates an asynchronous Cloud Task
    to perform the scan, and redirects the user to a status page — or, while the scope's previous
    scan is still running, answers 409 with that scan's status page (v18.6.1).
    """
    scope = validation.clean_scope(request.form.get('scope'))
    scope_id = validation.clean_scope_id(scope, request.form.get('scope_id'))
    requested_by = identity.current_user_email()  # None unless the request came through Identity-Aware Proxy

    try:
        note = schedules.start_scan(get_services(), scope, scope_id, requested_by=requested_by)
    except schedules.ScanInProgress as running:
        lock = running.lock
        status_path = url_for('ui.get_status', job_id=lock['job_id'], scope_id=scope_id, scope=scope)
        if request.accept_mimetypes.best_match(("text/html", "application/json")) == "application/json":
            return jsonify({"error": str(running), "job_id": lock["job_id"], "started_at": lock.get("started_at"),
                            "requested_by": lock.get("requested_by"), "status_path": status_path}), 409
        return render_template("scan_running.html", scope=scope, scope_id=scope_id, lock=lock, status_path=status_path), 409

    # NEW: Pass both IDs to the status page
    return redirect(url_for('ui.get_status', job_id=note['job_id'], scope_id=scope_id, scope=scope))


@bp.route('/status/<string:job_id>/<string:scope>/<string:scope_id>')
def get_status(job_id, scope, scope_id):
    """
    Renders the status page that users see while a scan is running.
    It simulates progress and polls the `/api/status` endpoint; when the scan
    completes it links to the report and to the CSV download route (v16.1 —
    before, a signed Cloud Storage URL good for an hour, minted here).
    """
    job_id = validation.clean_job_id(job_id)
    scope = validation.clean_scope(scope)
    scope_id = validation.clean_scope_id(scope, scope_id)
    return render_template("status.html", job_id=job_id, scope_id=scope_id, scope=scope)


@bp.route('/report/<string:job_id>/<string:scope_id>')
def view_report(job_id, scope_id):
    """Serves the final HTML report from GCS to the user."""
    job_id, scope_id = validation.clean_job_id(job_id), validation.clean_any_scope_id(scope_id)
    try:
        report_html = get_services().results_store.read_report(job_id, scope_id)
        if report_html is None:
            return "Report not found or is still generating.", 404
        return report_html

    except Exception as e:
        print(f"Error fetching report {job_id} from GCS: {e}")
        return "Could not retrieve report.", 500


@bp.route('/report/<string:job_id>/<string:scope_id>/csv')
def download_report_csv(job_id, scope_id):
    """Serves the complete CSV report as a download, streamed from the bucket.

    The HTML report's toolbar and the status page link here (the status page
    since v16.1; before, it carried a signed Cloud Storage URL that expired
    after an hour). The report's tables include at most ``MAX_ROWS_PER_CHECK``
    rows of a check; the CSV has every row, so it is read ``CSV_CHUNK_BYTES``
    at a time and sent with the object's size as ``Content-Length``.
    """
    job_id, scope_id = validation.clean_job_id(job_id), validation.clean_any_scope_id(scope_id)
    try:
        opened = get_services().results_store.open_report(job_id, scope_id, extension="csv", chunk_size=CSV_CHUNK_BYTES)
        if opened is None:
            return "CSV report not found or is still generating.", 404
        csv_file, size = opened
    except Exception as e:
        print(f"Error fetching CSV report {job_id} from GCS: {e}")
        return "Could not retrieve the CSV report.", 500

    def chunks():
        with csv_file:
            while True:
                chunk = csv_file.read(CSV_CHUNK_BYTES)
                if not chunk:
                    break
                yield chunk

    filename = f"cloudgauge_{secure_filename(scope_id) or 'report'}_{secure_filename(job_id) or 'job'}.csv"
    return Response(stream_with_context(chunks()), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "Content-Length": str(size)})


@bp.route('/history/<string:scope>/<string:scope_id>')
def view_history(scope, scope_id):
    """The scope's scans over time (v17): scores, counts, who asked, and the status changes between consecutive scans,
    from the summaries the finished scans filed under ``scopes/`` (``app.reporting.history``)."""
    if scope not in SCOPES:
        return "Scope must be organization, folder or project.", 404
    scope_id = validation.clean_scope_id(scope, scope_id)
    try:
        summaries, total = get_services().results_store.list_summaries(scope, scope_id, limit=HISTORY_PAGE_SCANS, with_total=True)
    except Exception as e:
        print(f"Error listing the scan history of {scope} {scope_id}: {e}")
        return "Could not read the scan history.", 500
    return render_template("history.html", history=build_history(scope, scope_id, summaries, total=total))
