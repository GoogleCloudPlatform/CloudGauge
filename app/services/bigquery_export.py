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
"""BigQuery export of finished scans (v17): every scan into two tables, for history and analytics.

With ``BIGQUERY_DATASET`` set, the report build hands each finished scan to
:class:`BigQueryExporter`, which writes two newline-delimited JSON files to the
results bucket (``exports/<job_id>/scans.ndjson``, ``.../findings.ndjson``) and
starts a BigQuery **load job** for each — free, unlike streaming inserts, and
idempotent: the job IDs are derived from the scan's job ID, so a retried
aggregation that exports again is told the jobs already exist and nothing is
loaded twice. The tables are created on the first load, partitioned by day on
``generated_at`` and clustered by ``scope_id`` (and ``check_name``), with a
schema that grows by addition only (``ALLOW_FIELD_ADDITION``).

- ``scans``: one row per scan — who asked, how many projects, the four scores,
  the four Overview counts, and every check's status and row count
  (``checks``, a repeated record), which is what a status-flip query reads.
- ``findings``: one row per finding row of every check (the Organization
  Policies rows included), with the project the row is about, the row's
  **identity** (``app.reporting.changes``: the same string the report compares
  scans by, so a finding can be followed across scans in SQL), whether it was
  new in that scan, and the raw row as a JSON string (``row_json``).

The export never fails a scan: whatever happens is logged and reported in the
report's header (*Exported to …*, *Export still running*, *Export failed: …*)
through :class:`ExportResult`; the reports are uploaded either way. The build
waits ``BIGQUERY_EXPORT_WAIT_SECONDS`` for the load jobs at most — a small
scan's jobs finish in seconds — and otherwise reports them as running.

``tools/backfill_export.py`` loads the scans made before the export existed,
from their summaries and CSVs, through :meth:`BigQueryExporter.load_rows`.

The BigQuery REST API (``bigquery`` v2, through ``app.services.gcp``) is used:
no new dependency, and the synthetic profile and the tests stand it in like
every other Discovery API.
"""
import json
import logging
import re
import time
from dataclasses import dataclass, field

from googleapiclient.errors import HttpError

from app.checks.categories import CATEGORY_ORDER
from app.config import SCOPES, get_settings
from app.reporting.changes import ORG_POLICIES_CHECK, identities_for
from app.reporting.context import PROJECT_COLUMNS, evaluate_org_policies, group_findings
from app.services import gcp

SCANS_TABLE, FINDINGS_TABLE = "scans", "findings"
EXPORT_PREFIX = "exports"
EXPORT_VERSION = 1
NDJSON = "application/x-ndjson"
POLL_SECONDS = 2.0

SCANS_SCHEMA = [
    {"name": "job_id", "type": "STRING", "mode": "REQUIRED"},
    {"name": "scope", "type": "STRING", "mode": "REQUIRED"},
    {"name": "scope_id", "type": "STRING", "mode": "REQUIRED"},
    {"name": "generated_at", "type": "TIMESTAMP", "mode": "REQUIRED"},
    {"name": "release", "type": "STRING"},
    {"name": "requested_by", "type": "STRING"},
    {"name": "total_projects", "type": "INTEGER"},
    {"name": "projects_scanned", "type": "INTEGER"},
    {"name": "action_count", "type": "INTEGER"},
    {"name": "investigation_count", "type": "INTEGER"},
    {"name": "compliant_count", "type": "INTEGER"},
    {"name": "error_count", "type": "INTEGER"},
    {"name": "security_score", "type": "FLOAT"},
    {"name": "cost_score", "type": "FLOAT"},
    {"name": "reliability_score", "type": "FLOAT"},
    {"name": "operations_score", "type": "FLOAT"},
    {"name": "checks", "type": "RECORD", "mode": "REPEATED", "fields": [
        {"name": "check_name", "type": "STRING"},
        {"name": "category", "type": "STRING"},
        {"name": "status", "type": "STRING"},
        {"name": "rows", "type": "INTEGER"},
    ]},
    {"name": "export_version", "type": "INTEGER"},
]
FINDINGS_SCHEMA = [
    {"name": "job_id", "type": "STRING", "mode": "REQUIRED"},
    {"name": "scope", "type": "STRING", "mode": "REQUIRED"},
    {"name": "scope_id", "type": "STRING", "mode": "REQUIRED"},
    {"name": "generated_at", "type": "TIMESTAMP", "mode": "REQUIRED"},
    {"name": "release", "type": "STRING"},
    {"name": "category", "type": "STRING"},
    {"name": "check_name", "type": "STRING"},
    {"name": "status", "type": "STRING"},
    {"name": "project", "type": "STRING"},
    {"name": "identity", "type": "STRING"},
    {"name": "new_since_last_scan", "type": "BOOLEAN"},
    {"name": "row_json", "type": "STRING"},
]
SCHEMAS = {SCANS_TABLE: SCANS_SCHEMA, FINDINGS_TABLE: FINDINGS_SCHEMA}
CLUSTERING = {SCANS_TABLE: ["scope_id"], FINDINGS_TABLE: ["scope_id", "check_name"]}
# The scores' column names, by report category.
SCORE_COLUMNS = {"Security & Identity": "security_score", "Cost Optimization": "cost_score",
                 "Reliability & Resilience": "reliability_score", "Operational Excellence & Observability": "operations_score"}
EXPORTED, RUNNING, FAILED = "exported", "running", "failed"


@dataclass(frozen=True)
class ExportResult:
    """What the report's header says about the export: ``state`` is ``exported``, ``running`` or ``failed``."""
    state: str
    dataset: str
    detail: str = ""
    job_ids: tuple = field(default_factory=tuple)
    rows: int = 0  # finding rows handed to BigQuery

    @property
    def header_text(self):
        if self.state == EXPORTED:
            return f"{self.rows:,} finding rows and this scan's summary loaded into {self.dataset}.{FINDINGS_TABLE} and {self.dataset}.{SCANS_TABLE}"
        if self.state == RUNNING:
            return f"load into {self.dataset} still running when the report was written ({', '.join(self.job_ids)}); it completes on its own"
        return f"export to {self.dataset} failed: {self.detail}"

    @property
    def dot_class(self):
        return {EXPORTED: "compliant", RUNNING: "investigation"}.get(self.state, "error")


# --- Rows --------------------------------------------------------------------------------------------------------

def timestamp_of(generated_ts):
    """``"2026-10-22T14:00:00Z"`` of a summary's ``generated_ts`` (``"20261022T140000Z"``); the value itself when it is not one."""
    match = re.fullmatch(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z", str(generated_ts or ""))
    return f"{match[1]}-{match[2]}-{match[3]}T{match[4]}:{match[5]}:{match[6]}Z" if match else str(generated_ts or "")


def scan_row(summary, projects_scanned=None):
    """The ``scans`` row of a scan summary (``app.reporting.changes.summarize``)."""
    scores, overview = summary.get("scores") or {}, summary.get("overview") or {}
    row = {
        "job_id": summary["job_id"], "scope": summary["scope"], "scope_id": summary["scope_id"],
        "generated_at": timestamp_of(summary.get("generated_ts")), "release": summary.get("release"),
        "requested_by": summary.get("requested_by"), "total_projects": summary.get("total_projects"),
        "projects_scanned": projects_scanned if projects_scanned is not None else summary.get("total_projects"),
        "action_count": overview.get("action_count"), "investigation_count": overview.get("investigation_count"),
        "compliant_count": overview.get("compliant_count"), "error_count": overview.get("error_count"),
        "checks": [{"check_name": name, "category": entry.get("category"), "status": entry.get("status"), "rows": entry.get("rows")}
                   for name, entry in (summary.get("checks") or {}).items()],
        "export_version": EXPORT_VERSION,
    }
    for category, column in SCORE_COLUMNS.items():
        row[column] = scores.get(category)
    return row


def finding_rows(summary, all_results, changes=None):
    """The ``findings`` rows of a scan: one per row of every check in ``all_results`` (the categorized findings the
    report was built from), plus one per organization policy; ``changes`` (``app.reporting.changes.Changes``) marks the
    rows the previous scan did not have."""
    base = {"job_id": summary["job_id"], "scope": summary["scope"], "scope_id": summary["scope_id"],
            "generated_at": timestamp_of(summary.get("generated_ts")), "release": summary.get("release")}
    new_identities = {name: change.new_identities for name, change in (changes.checks if changes else {}).items()}
    rows = []
    for category in CATEGORY_ORDER:
        for check_name, group in group_findings(all_results.get(category, [])).items():
            status, details = group.get("Status"), group.get("details", [])
            if not details:
                continue
            if isinstance(details[0], dict):
                headers = tuple(str(h) for h in details[0].keys())
                raw = [tuple(f"{item.get(h, '')}" for h in headers) for item in details]
                _, identities = identities_for(headers, raw)
                project_column = next((i for i, h in enumerate(headers) if h.strip().lower() in PROJECT_COLUMNS), None)
                for item, values, identity in zip(details, raw, identities):
                    rows.append({**base, "category": category, "check_name": check_name, "status": status,
                                 "project": values[project_column] if project_column is not None else None, "identity": identity,
                                 "new_since_last_scan": (identity in new_identities[check_name]) if check_name in new_identities else None,
                                 "row_json": json.dumps(item, default=str)})
            else:
                for line in details:
                    rows.append({**base, "category": category, "check_name": check_name, "status": status, "project": None,
                                 "identity": str(line), "new_since_last_scan": None, "row_json": json.dumps({"text": str(line)}, default=str)})
    policies = all_results.get(ORG_POLICIES_CHECK)
    if policies:
        for policy_category, results in evaluate_org_policies(*policies):
            for result in results:
                row = {"Category": policy_category, "Policy": f"{result.display_name}", "Expected Value": f"{result.expected_value}",
                       "Current Value": result.current_value, "Status": result.status}
                rows.append({**base, "category": "Security & Identity", "check_name": ORG_POLICIES_CHECK, "status": result.status,
                             "project": None, "identity": f"{policy_category} · {result.display_name}", "new_since_last_scan": None,
                             "row_json": json.dumps(row, default=str)})
    return rows


def ndjson(rows):
    return "".join(json.dumps(row, default=str) + "\n" for row in rows)


# --- The exporter -------------------------------------------------------------------------------------------------

class BigQueryExporter:
    """Loads scans into ``settings.bigquery_dataset`` (module docstring). One per app (``Services.get_exporter``)."""

    def __init__(self, settings, store, clock=time.monotonic, sleep=time.sleep):
        self.settings = settings
        self.store = store
        self.dataset = settings.bigquery_dataset
        self.clock, self.sleep = clock, sleep

    def _service(self):
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        return gcp.api_build("bigquery", "v2", credentials=credentials)

    @staticmethod
    def load_job_id(job_id, table):
        """The BigQuery job ID of a scan's load into ``table``: letters, digits, dashes and underscores only."""
        return re.sub(r"[^A-Za-z0-9_-]", "_", f"cloudgauge-{job_id}-{table}")[:1024]

    def staging_name(self, job_id, table):
        return f"{EXPORT_PREFIX}/{job_id}/{table}.ndjson"

    def export(self, summary, all_results, changes=None, projects_scanned=None):
        """Exports one finished scan; returns an :class:`ExportResult`. Never raises."""
        job_id = summary.get("job_id", "")
        try:
            rows = finding_rows(summary, all_results, changes)
            return self.load_rows(job_id, scan_row(summary, projects_scanned), rows)
        except Exception as e:  # the reports are uploaded whatever happens here
            logging.error(f"[{job_id}] BigQuery export failed: {e}")
            return ExportResult(FAILED, self.dataset, detail=str(e))

    def load_rows(self, job_id, scan, findings):
        """Stages ``scan`` and ``findings`` in the bucket, starts the two load jobs and waits for them (bounded)."""
        try:
            bucket = self.store.bucket()
            uris = {}
            for table, rows in ((SCANS_TABLE, [scan]), (FINDINGS_TABLE, findings)):
                name = self.staging_name(job_id, table)
                bucket.blob(name).upload_from_string(ndjson(rows), content_type=NDJSON)
                uris[table] = f"gs://{self.store.bucket_name}/{name}"
            service = self._service()
            started = [self._start_load(service, job_id, table, uri) for table, uri in uris.items()]
            result = self._wait(service, started, len(findings))
            if result.state == EXPORTED:
                self._cleanup(bucket, uris)
            return result
        except Exception as e:
            logging.error(f"[{job_id}] BigQuery export failed: {e}")
            return ExportResult(FAILED, self.dataset, detail=str(e))

    def _start_load(self, service, job_id, table, uri):
        """Inserts the load job for ``table`` (409 Already Exists: a retry; the earlier job is polled instead)."""
        load_job_id = self.load_job_id(job_id, table)
        body = {
            "jobReference": {"projectId": self.settings.project_id, "jobId": load_job_id, "location": self.settings.location},
            "configuration": {"load": {
                "sourceUris": [uri], "sourceFormat": "NEWLINE_DELIMITED_JSON",
                "destinationTable": {"projectId": self.settings.project_id, "datasetId": self.dataset, "tableId": table},
                "schema": {"fields": SCHEMAS[table]}, "writeDisposition": "WRITE_APPEND", "createDisposition": "CREATE_IF_NEEDED",
                "schemaUpdateOptions": ["ALLOW_FIELD_ADDITION"],
                "timePartitioning": {"type": "DAY", "field": "generated_at"}, "clustering": {"fields": CLUSTERING[table]},
            }},
        }
        try:
            service.jobs().insert(projectId=self.settings.project_id, body=body).execute()
        except HttpError as e:
            if getattr(e.resp, "status", None) != 409:
                raise
            logging.info(f"[{job_id}] BigQuery load job {load_job_id} already exists; waiting for it.")
        return load_job_id

    def _wait(self, service, job_ids, rows):
        """Polls the jobs until every one is DONE or the wait is up; a job that failed makes the export failed."""
        deadline = self.clock() + self.settings.bigquery_export_wait_seconds
        pending = list(job_ids)
        while pending:
            still = []
            for load_job_id in pending:
                job = service.jobs().get(projectId=self.settings.project_id, jobId=load_job_id, location=self.settings.location).execute() or {}
                status = job.get("status") or {}
                if status.get("state") != "DONE":
                    still.append(load_job_id)
                elif status.get("errorResult"):
                    message = status["errorResult"].get("message") or json.dumps(status["errorResult"])
                    return ExportResult(FAILED, self.dataset, detail=f"{load_job_id}: {message}", job_ids=tuple(job_ids), rows=rows)
            pending = still
            if pending:
                if self.clock() >= deadline:
                    return ExportResult(RUNNING, self.dataset, job_ids=tuple(pending), rows=rows)
                self.sleep(POLL_SECONDS)
        return ExportResult(EXPORTED, self.dataset, job_ids=tuple(job_ids), rows=rows)

    @staticmethod
    def _cleanup(bucket, uris):
        """Deletes the staging files once loaded (best effort)."""
        for uri in uris.values():
            try:
                bucket.blob(uri.split("/", 3)[3]).delete()
            except Exception as e:
                logging.info(f"Could not delete the export staging file {uri}: {e}")

    def exported_job_ids(self):
        """The job IDs already in the ``scans`` table (``tools/backfill_export.py`` skips them); ``set()`` when the table does not exist."""
        service = self._service()
        query = f"SELECT DISTINCT job_id FROM `{self.settings.project_id}.{self.dataset}.{SCANS_TABLE}`"
        try:
            response = service.jobs().query(projectId=self.settings.project_id,
                                            body={"query": query, "useLegacySql": False, "location": self.settings.location}).execute() or {}
        except HttpError as e:
            if getattr(e.resp, "status", None) == 404 or "Not found" in str(e):
                return set()
            raise
        return {row["f"][0]["v"] for row in response.get("rows", [])}


def build_exporter(settings=None, store=None):
    """The app's exporter, or ``None`` when ``BIGQUERY_DATASET`` is unset."""
    settings = settings or get_settings()
    if not settings.bigquery_dataset or store is None:
        return None
    return BigQueryExporter(settings, store)
