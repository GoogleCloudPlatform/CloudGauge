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
"""Loads the scans made before the BigQuery export existed (v17) into the ``scans`` and ``findings`` tables.

Every finished scan since v15 left a summary under ``scopes/<scope>/<scope id>/`` in the
results bucket and its CSV report under ``<job id>/``. This tool reads both, rebuilds the
rows the export would have written (``app.services.bigquery_export``) and loads them with
the same load jobs; scans already in the ``scans`` table are skipped, so it can be run again.

    python tools/backfill_export.py --project my-project --location asia-south1 \\
        --bucket cloudgauge-reports-my-project --dataset cloudgauge [--scope organization --scope-id 123] [--dry-run]

Runs with Application Default Credentials: an account that reads the bucket and may run
BigQuery load jobs into the dataset (the service account itself, impersonated, is the
natural choice: ``gcloud auth application-default login --impersonate-service-account=...``).
"""
import argparse
import csv
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.checks.categories import CATEGORY_ORDER  # noqa: E402
from app.config import Settings  # noqa: E402
from app.reporting.changes import ORG_POLICIES_CHECK  # noqa: E402
from app.reporting.csv_report import NEW_COLUMN  # noqa: E402
from app.services.bigquery_export import BigQueryExporter, finding_rows, scan_row, timestamp_of  # noqa: E402
from app.services.results_store import GcsResultsStore  # noqa: E402

POLICY_HEADER = ['Category', 'Policy', 'Expected Value', 'Current Value', 'Status']


def parse_csv_report(text):
    """``(all_results, policies, new_rows)`` from a CSV report (``app.reporting.csv_report.generate_csv_data``).

    ``all_results`` is the categorized findings the report was built from, as far as the CSV
    carries them (one record per run of rows of one check and status; text details as one
    line); ``policies`` the Organization Policies rows; ``new_rows`` the ``(check, row JSON)``
    pairs the CSV marked *New since last scan*, or ``None`` when the CSV has no such column (a
    first scan: nothing was compared).
    """
    rows = list(csv.reader(io.StringIO(text)))
    all_results, policies, new_rows = {category: [] for category in CATEGORY_ORDER}, [], None
    category, header, record = None, None, None
    for index, row in enumerate(rows):
        if index == 0 and row == [ORG_POLICIES_CHECK]:
            category = ORG_POLICIES_CHECK
            continue
        if not row:
            header, record = None, None
            continue
        if len(row) == 1 and row[0] in all_results:
            category, header, record = row[0], None, None
            continue
        if category == ORG_POLICIES_CHECK:
            if row != POLICY_HEADER:
                policies.append(dict(zip(POLICY_HEADER, row)))
            continue
        if row[:2] == ['Check', 'Status']:
            header, record = row, None
            continue
        if header is None or category is None:
            continue
        check, status, values = row[0], row[1], row[2:]
        columns = header[2:]
        new = False
        if columns and columns[-1] == NEW_COLUMN:
            new_rows = new_rows if new_rows is not None else set()
            columns, new, values = columns[:-1], (values[-1:] == ['yes']), values[:-1]
        if columns == ['Details']:
            # Text details were joined with "; " into one cell: split back into lines (the one ambiguity the CSV has).
            finding = [line for line in (values[0] if values else '').split('; ') if line]
            if not finding:
                continue  # a check with empty details: the live export writes nothing for it either
        else:
            finding = dict(zip(columns, values))
            if new:
                new_rows.add((check, json.dumps(finding, default=str)))
        text = isinstance(finding, list) and all(isinstance(line, str) for line in finding)
        if record is None or record['Check'] != check or record['Status'] != status or text != record.get('_text', False):
            record = {'Check': check, 'Status': status, 'Finding': finding if text else [finding], '_text': text}
            all_results[category].append(record)
        elif text:
            record['Finding'].extend(finding)
        else:
            record['Finding'].append(finding)
    for records in all_results.values():
        for record in records:
            record.pop('_text', None)
    return all_results, policies, new_rows


def rows_of(summary, csv_text):
    """The ``findings`` rows of an earlier scan, from its summary and CSV report."""
    all_results, policies, new_rows = parse_csv_report(csv_text)
    rows = finding_rows(summary, all_results)
    for row in rows:
        # Structured rows of a compared scan carry the flag; text rows and first scans never do (as in the live export).
        structured = not (set(json.loads(row['row_json'])) == {'text'})
        row['new_since_last_scan'] = ((row['check_name'], row['row_json']) in new_rows) if new_rows is not None and structured else None
    base = {'job_id': summary['job_id'], 'scope': summary['scope'], 'scope_id': summary['scope_id'],
            'generated_at': timestamp_of(summary.get('generated_ts')), 'release': summary.get('release')}
    for policy in policies:
        rows.append({**base, 'category': 'Security & Identity', 'check_name': ORG_POLICIES_CHECK, 'status': policy['Status'], 'project': None,
                     'identity': f"{policy['Category']} · {policy['Policy']}", 'new_since_last_scan': None, 'row_json': json.dumps(policy)})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--project', required=True, help='the project CloudGauge runs in (the dataset lives there)')
    parser.add_argument('--location', required=True, help="the dataset's location, e.g. asia-south1")
    parser.add_argument('--bucket', required=True, help='the results bucket')
    parser.add_argument('--dataset', required=True, help='the BigQuery dataset (BIGQUERY_DATASET)')
    parser.add_argument('--scope', choices=('organization', 'folder', 'project'), help='one scope only (with --scope-id)')
    parser.add_argument('--scope-id', help='one scope only (with --scope)')
    parser.add_argument('--dry-run', action='store_true', help='say what would be loaded and load nothing')
    args = parser.parse_args(argv)
    settings = Settings.from_env({'PROJECT_ID': args.project, 'LOCATION': args.location, 'RESULTS_BUCKET': args.bucket,
                                  'BIGQUERY_DATASET': args.dataset, 'BIGQUERY_EXPORT_WAIT_SECONDS': '300', 'CLOUDGAUGE_ENV': 'testing'})
    store = GcsResultsStore(args.bucket)
    exporter = BigQueryExporter(settings, store)
    scopes = [(args.scope, args.scope_id)] if args.scope and args.scope_id else store.list_scopes()
    done = set() if args.dry_run else exporter.exported_job_ids()
    print(f"{len(scopes)} scope(s) with summaries; {len(done)} scan(s) already in {args.dataset}.scans")
    loaded = skipped = failed = 0
    for scope, scope_id in scopes:
        for summary in reversed(store.list_summaries(scope, scope_id)):  # oldest first
            job_id = summary.get('job_id')
            if job_id in done:
                skipped += 1
                continue
            csv_text = store.read_report(job_id, scope_id, extension='csv')
            if csv_text is None:
                print(f"  {scope} {scope_id} {job_id}: no CSV report in the bucket; skipped")
                skipped += 1
                continue
            rows = rows_of(summary, csv_text)
            if args.dry_run:
                print(f"  {scope} {scope_id} {job_id} ({summary.get('generated_at')}): {len(rows)} finding rows")
                continue
            result = exporter.load_rows(job_id, scan_row(summary), rows)
            print(f"  {scope} {scope_id} {job_id} ({summary.get('generated_at')}): {result.state} ({len(rows)} rows){' - ' + result.detail if result.detail else ''}")
            if result.state == 'failed':
                failed += 1
            else:
                loaded += 1
    print(f"Done: {loaded} loaded, {skipped} skipped, {failed} failed.")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
