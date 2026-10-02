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
"""Pages: the landing form, scan submission, the status page, the report viewer, and the CSV download."""
import uuid

from flask import Blueprint, Response, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from app.extensions import get_services
from app.services import tasks

bp = Blueprint("ui", __name__)


@bp.route('/', methods=['GET'])
def index():
    """Renders the main landing page with a dynamic form to select a resource."""
    return render_template("index.html")


@bp.route('/scan', methods=['POST'])
def create_scan_task():
    """
    Receives the scope ( Org, Folder or Project ) from the form, creates an asynchronous Cloud Task
    to perform the scan, and redirects the user to a status page.
    """
    scope = request.form['scope']
    scope_id = request.form['scope_id']
    if not scope_id or not scope:
        return "Scope and ID are required.", 400

    job_id = str(uuid.uuid4())
    print(f"Creating scan task for {scope}: {scope_id} with Job ID: {job_id}")

    services = get_services()
    tasks.enqueue_scan(services.settings, services.get_worker_url(), scope, scope_id, job_id,
                       client=services.get_tasks_client())

    # NEW: Pass both IDs to the status page
    return redirect(url_for('ui.get_status', job_id=job_id, scope_id=scope_id, scope=scope))


@bp.route('/status/<string:job_id>/<string:scope>/<string:scope_id>')
def get_status(job_id, scope, scope_id):
    """
    Renders the status page that users see while a scan is running.
    It simulates progress and polls the `/api/status` endpoint. Also generates
    a signed URL for the CSV download.
    """
    if not scope_id:
        return "Error:  ID is missing from the status URL.", 400

    services = get_services()
    signed_csv_url = "#"
    try:
        signed_csv_url = services.results_store.generate_signed_csv_url(
            job_id, scope_id, services.settings.service_account_email)
    except Exception as e:
        print(f"Could not generate signed URL for job {job_id}: {e}")

    # Pass the signed URL into the template
    return render_template("status.html", job_id=job_id, scope_id=scope_id, scope=scope, signed_csv_url=signed_csv_url)


@bp.route('/report/<string:job_id>/<string:scope_id>')
def view_report(job_id, scope_id):
    """Serves the final HTML report from GCS to the user."""
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
    """Serves the complete CSV report as a download.

    The HTML report links here: its tables include at most
    ``MAX_ROWS_PER_CHECK`` rows of a check, and the status page's signed CSV
    URL expires after an hour.
    """
    try:
        csv_report = get_services().results_store.read_report(job_id, scope_id, extension="csv")
        if csv_report is None:
            return "CSV report not found or is still generating.", 404
        filename = f"cloudgauge_{secure_filename(scope_id) or 'report'}_{secure_filename(job_id) or 'job'}.csv"
        return Response(csv_report, mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    except Exception as e:
        print(f"Error fetching CSV report {job_id} from GCS: {e}")
        return "Could not retrieve the CSV report.", 500
