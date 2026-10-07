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
unchanged for scans that run in one task:

- ``intermediate/{job_id}/{check_name}_{uuid4}.json``: one finding per object
- ``intermediate/{job_id}/best_practices.json``: org-policy best practices
- ``intermediate/{job_id}/current_policies.json``: effective org policies
- ``{job_id}/{scope_id}_status.json``: scan status polled by the UI
- ``{job_id}/{scope_id}_report.html`` and ``.csv``: final reports

Sharded scans (``app.fanout``) keep each shard's findings apart and add the
job's bookkeeping, all under the same ``intermediate/{job_id}/`` prefix so one
cleanup removes everything:

- ``intermediate/{job_id}/shards/{shard_id}/...``: a shard's findings and org-policy files
- ``intermediate/{job_id}/manifest.json``: the shard plan written by the dispatcher
- ``intermediate/{job_id}/markers/{shard_id}.json``: written once by each finished shard

Scan history (``app.reporting.changes``) adds one small object per completed
scan, filed by scope so the next scan of the same scope finds its predecessor
with one listing and nothing is ever rewritten:

- ``scopes/{scope}/{scope_id}/{generated_ts}_{job_id}.json``: the scan's summary

Checks receive a ``GcsResultsStore`` (or a ``ShardSink`` bound to a shard) as
their keyword-only ``sink`` argument.
"""
import concurrent.futures
import json
import logging
import uuid
from datetime import datetime, timezone

from google.api_core.exceptions import PreconditionFailed

from app.services import gcp

MANIFEST_FILE = "manifest.json"
MARKERS_DIR = "markers"
SHARDS_DIR = "shards"
SCOPES_DIR = "scopes"
ORG_POLICY_FILES = ("best_practices.json", "current_policies.json")
READ_WORKERS = 16  # parallel downloads when reading a job's findings back
DELETE_WORKERS = 16  # parallel deletions when cleaning a job's intermediate files up


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

    @staticmethod
    def intermediate_prefix(job_id, shard_id=None):
        """Where a job's (or one shard's) intermediate files live."""
        if shard_id:
            return f"intermediate/{job_id}/{SHARDS_DIR}/{shard_id}/"
        return f"intermediate/{job_id}/"

    @staticmethod
    def _is_finding(blob_name):
        """Whether an intermediate object is a finding file (not bookkeeping or org-policy data)."""
        basename = blob_name.rsplit("/", 1)[-1]
        if basename in ORG_POLICY_FILES or basename == MANIFEST_FILE:
            return False
        return f"/{MARKERS_DIR}/" not in blob_name

    # --- Helper Functions for Streaming Architecture ---
    def write_finding(self, job_id, check_name, finding_data, shard_id=None):
        """Uploads a single finding record as a JSON object to GCS."""
        try:
            bucket = self.bucket()
            # Use a unique name for each finding to prevent overwrites
            blob_name = f"{self.intermediate_prefix(job_id, shard_id)}{check_name}_{uuid.uuid4()}.json"
            blob = bucket.blob(blob_name)
            blob.upload_from_string(
                json.dumps(finding_data),
                content_type='application/json'
            )
        except Exception as e:
            logging.error(f"Failed to write finding to GCS for {check_name}: {e}")

    def read_all_findings(self, job_id, shard_id=None):
        """Reads all temporary finding files for a job, in listing order.

        This is the read half of the legacy ``_read_all_findings_from_gcs``. The
        org-policy files (see :meth:`read_org_policies`) and the sharded scan's
        bookkeeping files are skipped. Without ``shard_id`` this covers every
        shard of a sharded job. Objects are downloaded in parallel; the order of
        the result is the listing order. To group the findings by category, pass
        the result to ``app.checks.categories.categorize_findings``.
        """
        findings = []
        try:
            bucket = self.bucket()
            blobs = [blob for blob in bucket.list_blobs(prefix=self.intermediate_prefix(job_id, shard_id))
                     if self._is_finding(blob.name)]

            def read(blob):
                try:
                    data = json.loads(blob.download_as_text())
                    # The check name is stored inside the JSON object itself, so it must be an object
                    if not isinstance(data, dict):
                        raise TypeError(f"expected a JSON object, got {type(data).__name__}")
                    return data
                except Exception as e:
                    logging.error(f"Failed to read and process GCS finding {blob.name}: {e}")
                    return None

            if blobs:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(READ_WORKERS, len(blobs))) as executor:
                    findings = [data for data in executor.map(read, blobs) if data is not None]
        except Exception as e:
            logging.error(f"Failed to list findings from GCS for job {job_id}: {e}")

        return findings

    def write_org_policies(self, job_id, best_practices, current_policies, shard_id=None):
        """Writes the raw org policy data to JSON files in GCS."""
        try:
            bucket = self.bucket()
            prefix = self.intermediate_prefix(job_id, shard_id)

            bp_blob = bucket.blob(f"{prefix}best_practices.json")
            bp_blob.upload_from_string(json.dumps(best_practices), content_type='application/json')

            cp_blob = bucket.blob(f"{prefix}current_policies.json")
            cp_blob.upload_from_string(json.dumps(current_policies), content_type='application/json')
        except Exception as e:
            logging.error(f"Failed to write org policy files to GCS: {e}")

    def read_org_policies(self, job_id, shard_id=None):
        """Reads the raw org policy data from GCS files."""
        try:
            bucket = self.bucket()
            prefix = self.intermediate_prefix(job_id, shard_id)

            bp_blob = bucket.blob(f"{prefix}best_practices.json")
            best_practices = json.loads(bp_blob.download_as_text())

            cp_blob = bucket.blob(f"{prefix}current_policies.json")
            current_policies = json.loads(cp_blob.download_as_text())

            return (best_practices, current_policies)
        except Exception as e:
            logging.error(f"Failed to read org policy files from GCS: {e}")
            return (None, None)

    def update_status(self, job_id, scope_id, progress, current_task, status="running", **extra):
        """Creates or overwrites a status file in GCS for the given job.

        ``extra`` adds fields to the document (sharded scans record their
        ``phase`` and shard counts); the status page only reads ``progress``,
        ``current_task`` and ``status``.
        """
        try:
            bucket = self.bucket()
            status_blob = bucket.blob(f"{job_id}/{scope_id}_status.json")
            status_data = {
                "job_id": job_id,
                "scope_id": scope_id,
                "progress": progress,
                "current_task": current_task,
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **extra,
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

    def report_exists(self, job_id, scope_id):
        """Whether the final HTML report has been uploaded (errors are raised)."""
        return self.bucket().blob(f"{job_id}/{scope_id}_report.html").exists()

    def read_report(self, job_id, scope_id, extension="html"):
        """Returns a report's text, or ``None`` if it doesn't exist (yet). Errors are raised."""
        bucket = self.bucket()
        blob = bucket.blob(f"{job_id}/{scope_id}_report.{extension}")
        if not blob.exists():
            return None
        return blob.download_as_text()

    def open_report(self, job_id, scope_id, extension="html", *, chunk_size=1024 * 1024):
        """Opens a report for reading in chunks: ``(file, size)``, or ``None`` if it doesn't exist (yet).

        ``file`` is a binary file object that fetches ``chunk_size`` bytes of the object at a time
        (pinned to the generation whose ``size`` is returned), so a CSV with every row of a large
        organization streams through the web service instead of sitting in its memory. The caller
        closes it. Errors are raised. v16.1: before, the status page's CSV link was a signed Cloud
        Storage URL, good for an hour for whoever held it, which needed the service account to sign
        as itself (``roles/iam.serviceAccountTokenCreator`` on itself).
        """
        blob = self.bucket().blob(f"{job_id}/{scope_id}_report.{extension}")
        if not blob.exists():
            return None
        blob.reload()
        return blob.open("rb", chunk_size=chunk_size), blob.size

    def cleanup_intermediate(self, job_id, shard_id=None):
        """Deletes all intermediate files for the job (or one shard) and returns how many were deleted.

        One request per object, ``DELETE_WORKERS`` at a time: a job of 1,000
        projects leaves over a thousand objects, and the bucket may be far from
        the service. An object that is already gone is skipped, not an error.
        """
        what = f"shard {shard_id}" if shard_id else "intermediate"
        print(f"[{job_id}] Cleaning up {what} files from GCS...")
        try:
            bucket = self.bucket()
            prefix_to_delete = self.intermediate_prefix(job_id, shard_id)
            blobs_to_delete = list(bucket.list_blobs(prefix=prefix_to_delete))
            if blobs_to_delete:
                workers = min(DELETE_WORKERS, len(blobs_to_delete))
                chunks = [blobs_to_delete[i::workers] for i in range(workers)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                    list(executor.map(lambda chunk: bucket.delete_blobs(chunk, on_error=lambda blob: None), chunks))
                print(f"[{job_id}] Deleted {len(blobs_to_delete)} {what} files.")
            return len(blobs_to_delete)
        except Exception as e:
            logging.error(f"[{job_id}] Failed to clean up {what} GCS files: {e}")
            return 0

    # --- Sharded scans: manifest and markers ---
    def write_manifest(self, job_id, manifest):
        """Writes the job's shard plan. Errors are raised: without it no shard can run."""
        blob = self.bucket().blob(f"{self.intermediate_prefix(job_id)}{MANIFEST_FILE}")
        blob.upload_from_string(json.dumps(manifest), content_type='application/json')

    def read_manifest(self, job_id):
        """Returns the job's shard plan, or ``None`` if the job was not sharded (or not dispatched yet)."""
        blob = self.bucket().blob(f"{self.intermediate_prefix(job_id)}{MANIFEST_FILE}")
        if not blob.exists():
            return None
        return json.loads(blob.download_as_text())

    def write_marker(self, job_id, shard_id, marker, only_if_absent=False):
        """Records that a shard has finished (successfully or not). Errors are raised: the fan-in depends on it.

        With ``only_if_absent`` the write is an atomic create (GCS generation
        precondition): it returns ``False``, without changing anything, if the
        marker already exists. Returns ``True`` when the marker was written.
        """
        blob = self.bucket().blob(f"{self.intermediate_prefix(job_id)}{MARKERS_DIR}/{shard_id}.json")
        data = json.dumps(marker)
        if not only_if_absent:
            blob.upload_from_string(data, content_type='application/json')
            return True
        try:
            blob.upload_from_string(data, content_type='application/json', if_generation_match=0)
        except PreconditionFailed:
            return False
        return True

    def read_markers(self, job_id):
        """Returns ``{shard_id: marker}`` for every shard that has finished. Errors are raised."""
        bucket = self.bucket()
        prefix = f"{self.intermediate_prefix(job_id)}{MARKERS_DIR}/"
        markers = {}
        for blob in bucket.list_blobs(prefix=prefix):
            shard_id = blob.name[len(prefix):].rsplit(".json", 1)[0]
            try:
                markers[shard_id] = json.loads(blob.download_as_text())
            except Exception as e:  # a corrupt marker still means the shard finished
                logging.error(f"[{job_id}] Unreadable marker {blob.name}: {e}")
                markers[shard_id] = {"shard_id": shard_id, "status": "failed", "error": f"unreadable marker: {e}"}
        return markers

    # --- Scan history: one summary per completed scan, filed by scope ---
    @staticmethod
    def summaries_prefix(scope, scope_id):
        """Where a scope's scan summaries live: ``scopes/organization/123/``."""
        return f"{SCOPES_DIR}/{scope}/{scope_id}/"

    def write_scan_summary(self, summary):
        """Files a finished scan's summary (``app.reporting.changes.summarize``) under its scope.

        Named ``<generated_ts>_<job_id>.json`` so a listing is in time order and
        nothing is ever rewritten. Errors are logged, not raised: the reports are
        already uploaded, and a missing summary costs only the next comparison.
        """
        name = f"{self.summaries_prefix(summary['scope'], summary['scope_id'])}{summary['generated_ts']}_{summary['job_id']}.json"
        try:
            self.bucket().blob(name).upload_from_string(json.dumps(summary), content_type='application/json')
        except Exception as e:
            logging.error(f"[{summary.get('job_id')}] Could not file the scan summary {name}: {e}")

    def read_previous_summary(self, scope, scope_id, job_id):
        """The newest summary of the scope's earlier scans (never ``job_id``'s own), or ``None``.

        ``None`` also when the listing or the download fails (logged): a report
        without the comparison beats no report.
        """
        prefix = self.summaries_prefix(scope, scope_id)
        try:
            bucket = self.bucket()
            names = sorted(blob.name for blob in bucket.list_blobs(prefix=prefix) if blob.name.endswith(".json"))
            for name in reversed(names):
                if name[len(prefix):-len(".json")].partition("_")[2] == job_id:
                    continue  # a retried render: compare with the scan before, not with ourselves
                return json.loads(bucket.blob(name).download_as_text())
        except Exception as e:
            logging.error(f"[{job_id}] Could not read the previous scan summary under {prefix}: {e}")
        return None


class ShardSink:
    """A shard's view of the store: findings and org policies land under the shard's prefix.

    Checks only call ``write_finding`` and ``write_org_policies``, so this is
    all a shard needs to pass as ``sink``.
    """

    def __init__(self, store, job_id, shard_id):
        self.store, self.job_id, self.shard_id = store, job_id, shard_id

    def write_finding(self, job_id, check_name, finding_data):
        self.store.write_finding(job_id, check_name, finding_data, shard_id=self.shard_id)

    def write_org_policies(self, job_id, best_practices, current_policies):
        self.store.write_org_policies(job_id, best_practices, current_policies, shard_id=self.shard_id)
