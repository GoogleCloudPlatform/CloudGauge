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
"""Cloud Storage-backed results store for scan jobs.

Wraps every read and write the legacy ``cloudgauge.py`` made through its
module-level ``storage_client``. The object layout is a frozen contract and is
unchanged:

- ``intermediate/{job_id}/{check_name}_{uuid4}.json``: one finding per object
- ``intermediate/{job_id}/best_practices.json``: org-policy best practices
- ``intermediate/{job_id}/current_policies.json``: effective org policies
- ``{job_id}/{scope_id}_status.json``: scan status polled by the UI
- ``{job_id}/{scope_id}_report.html`` and ``.csv``: final reports

Checks receive a ``GcsResultsStore`` as their keyword-only ``sink`` argument.
"""
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import google.auth.transport.requests

from app.services import gcp


class GcsResultsStore:
    """Reads and writes one results bucket.

    One instance can be shared by the runner's worker threads, the same way the
    legacy global ``storage_client`` was. The Storage client is created on first
    use (``gcp.storage_client()``) unless one is passed in.
    """

    def __init__(self, bucket_name, client=None):
        self.bucket_name = bucket_name
        self._client = client

    @property
    def client(self):
        if self._client is None:
            self._client = gcp.storage_client()
        return self._client

    def bucket(self):
        return self.client.bucket(self.bucket_name)

    # --- Helper Functions for Streaming Architecture ---
    def write_finding(self, job_id, check_name, finding_data):
        """Uploads a single finding record as a JSON object to GCS."""
        try:
            bucket = self.bucket()
            # Use a unique name for each finding to prevent overwrites
            blob_name = f"intermediate/{job_id}/{check_name}_{uuid.uuid4()}.json"
            blob = bucket.blob(blob_name)
            blob.upload_from_string(
                json.dumps(finding_data),
                content_type='application/json'
            )
        except Exception as e:
            logging.error(f"Failed to write finding to GCS for {check_name}: {e}")

    def read_all_findings(self, job_id):
        """Reads all temporary finding files for a job, in listing order.

        This is the read half of the legacy ``_read_all_findings_from_gcs``. The
        org-policy files are skipped (see :meth:`read_org_policies`). To group the
        findings by category, pass the result to
        ``app.checks.categories.categorize_findings``.
        """
        findings = []
        try:
            bucket = self.bucket()
            prefix = f"intermediate/{job_id}/"
            blobs = bucket.list_blobs(prefix=prefix)

            for blob in blobs:
                # Skip the org policy files
                if "best_practices.json" in blob.name or "current_policies.json" in blob.name:
                    continue

                try:
                    data_string = blob.download_as_text()
                    data = json.loads(data_string)
                    # The check name is stored inside the JSON object itself, so it must be an object
                    if not isinstance(data, dict):
                        raise TypeError(f"expected a JSON object, got {type(data).__name__}")
                    findings.append(data)
                except Exception as e:
                    logging.error(f"Failed to read and process GCS finding {blob.name}: {e}")
        except Exception as e:
            logging.error(f"Failed to list findings from GCS for job {job_id}: {e}")

        return findings

    def write_org_policies(self, job_id, best_practices, current_policies):
        """Writes the raw org policy data to JSON files in GCS."""
        try:
            bucket = self.bucket()

            bp_blob = bucket.blob(f"intermediate/{job_id}/best_practices.json")
            bp_blob.upload_from_string(json.dumps(best_practices), content_type='application/json')

            cp_blob = bucket.blob(f"intermediate/{job_id}/current_policies.json")
            cp_blob.upload_from_string(json.dumps(current_policies), content_type='application/json')
        except Exception as e:
            logging.error(f"Failed to write org policy files to GCS: {e}")

    def read_org_policies(self, job_id):
        """Reads the raw org policy data from GCS files."""
        try:
            bucket = self.bucket()

            bp_blob = bucket.blob(f"intermediate/{job_id}/best_practices.json")
            best_practices = json.loads(bp_blob.download_as_text())

            cp_blob = bucket.blob(f"intermediate/{job_id}/current_policies.json")
            current_policies = json.loads(cp_blob.download_as_text())

            return (best_practices, current_policies)
        except Exception as e:
            logging.error(f"Failed to read org policy files from GCS: {e}")
            return (None, None)

    def update_status(self, job_id, scope_id, progress, current_task, status="running"):
        """Creates or overwrites a status file in GCS for the given job."""
        try:
            bucket = self.bucket()
            status_blob = bucket.blob(f"{job_id}/{scope_id}_status.json")
            status_data = {
                "job_id": job_id,
                "scope_id": scope_id,
                "progress": progress,
                "current_task": current_task,
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            status_blob.upload_from_string(json.dumps(status_data), content_type='application/json')
            print(f"[{job_id}] Status updated: {progress}% - {current_task}")
        except Exception as e:
            print(f"[{job_id}] WARNING: Could not update status file in GCS: {e}")

    def read_status(self, job_id, scope_id):
        """Returns the job's status dict, or ``None`` if the worker hasn't written it yet.

        Errors are raised to the caller, which reports them (the legacy
        ``/api/status`` route returned HTTP 500).
        """
        bucket = self.bucket()
        status_blob = bucket.blob(f"{job_id}/{scope_id}_status.json")

        if status_blob.exists():
            # If the status file is there, return its content
            return json.loads(status_blob.download_as_text())
        return None

    def upload_reports(self, job_id, scope_id, html_report, csv_report):
        """Uploads the final HTML and CSV reports."""
        bucket = self.bucket()
        bucket.blob(f"{job_id}/{scope_id}_report.html").upload_from_string(html_report, content_type='text/html')
        bucket.blob(f"{job_id}/{scope_id}_report.csv").upload_from_string(csv_report, content_type='text/csv')

    def read_report(self, job_id, scope_id, extension="html"):
        """Returns a report's text, or ``None`` if it doesn't exist (yet). Errors are raised."""
        bucket = self.bucket()
        blob = bucket.blob(f"{job_id}/{scope_id}_report.{extension}")
        if not blob.exists():
            return None
        return blob.download_as_text()

    def generate_signed_csv_url(self, job_id, scope_id, signer_email):
        """Returns a V4 signed GET URL for the CSV report, valid for 1 hour.

        Errors are raised; the status page falls back to ``"#"``.
        """
        # --- START SIGNED LOGIC ---

        # 1. Get the default credentials from the metadata server
        creds, _ = gcp.auth_default(scopes=["https://www.googleapis.com/auth/cloud-platform"])

        # 2. Manually refresh them to get a usable access token
        auth_req = google.auth.transport.requests.Request()
        creds.refresh(auth_req)
        access_token = creds.token

        # 3. The service account email (signer_email) is passed in by the caller
        #    (legacy: read from the SERVICE_ACCOUNT_EMAIL environment variable here)

        # 4. Generate the signed URL, providing BOTH the email and the access token
        #    This tells the library: "Use this token to authorize a request for
        #    'signer_email' to sign the following content."
        bucket = self.bucket()
        csv_blob_name = f"{job_id}/{scope_id}_report.csv"
        blob = bucket.blob(csv_blob_name)

        expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)

        signed_csv_url = blob.generate_signed_url(
            version="v4",
            expiration=expiration_time,
            method="GET",
            service_account_email=signer_email,
            access_token=access_token  # <-- Pass the fetched token here
        )
        # --- END SIGNED LOGIC ---
        return signed_csv_url

    def cleanup_intermediate(self, job_id):
        """Deletes all intermediate files for the job and returns how many were deleted."""
        print(f"[{job_id}] Cleaning up intermediate files from GCS...")
        try:
            bucket = self.bucket()
            prefix_to_delete = f"intermediate/{job_id}/"
            blobs_to_delete = list(bucket.list_blobs(prefix=prefix_to_delete))
            if blobs_to_delete:
                bucket.delete_blobs(blobs_to_delete)
                print(f"[{job_id}] Deleted {len(blobs_to_delete)} intermediate files.")
            return len(blobs_to_delete)
        except Exception as e:
            logging.error(f"[{job_id}] Failed to clean up intermediate GCS files: {e}")
            return 0
