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
"""Renders the interactive HTML report from ``app/templates/report/``.

- The report is uploaded to GCS and served later exactly as stored, so it must
  not depend on whichever version is deployed: ``report.html`` inlines its CSS
  (``_styles.css``) and JavaScript (``_script.js``).
- The Jinja environment is separate from Flask's, so a report renders without an
  app or request context.
- Autoescaping is on (plan item B3). Finding text, IDs, and other values are
  inserted as text, so a finding that contains HTML (a resource name, a
  label, ...) can't inject markup or script into the report. The legacy
  f-strings inserted them raw. Values in the inline script are embedded with
  ``|tojson``, since HTML escaping doesn't protect a JavaScript string.
"""
import functools
from urllib.parse import quote

from jinja2 import Environment, PackageLoader, StrictUndefined

from app.reporting.changes import summarize
from app.reporting.context import build_report_context
from app.reporting.csv_report import generate_csv_data
from app.reporting.scorecard import scorecard_vars

REPORT_TEMPLATE = "report/report.html"


@functools.lru_cache(maxsize=None)
def report_environment():
    """Returns the Jinja environment for reports (created on first use)."""
    environment = Environment(
        loader=PackageLoader("app", "templates"),
        autoescape=True,  # B3: values are text, never markup
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,  # included CSS/JS keep their last line break
        undefined=StrictUndefined,  # a misspelled variable fails instead of rendering ""
    )
    # One path segment of a URL (the CSV link): unlike |urlencode, "/" is encoded too.
    environment.filters["pathsegment"] = lambda value: quote(str(value), safe="")
    return environment


def render_report(context):
    """Renders a :class:`~app.reporting.context.ReportContext` to the report HTML.

    The Scorecard page (``app.reporting.scorecard``) is built here from the
    finished context, so the context stays the single source it summarizes.
    """
    return report_environment().get_template(REPORT_TEMPLATE).render({**context.template_vars(), **scorecard_vars(context)})


def generate_html_report(scope, scope_id, job_id, banner=None, coverage=None, total_projects=None, previous=None, **all_results):
    """
    Generates a dynamic and interactive HTML report from the scan results.

    Args:
        scope (str): The scope of the scan (organization, folder, project).
        scope_id (str): The ID of the scanned resource.
        job_id (str): The unique ID for this scan job.
        banner (str, optional): A notice shown at the top of the report (the
            synthetic load mode uses it). ``None`` renders nothing.
        coverage (dict, optional): A sharded scan's coverage
            (``app.fanout.build_coverage``), for the header's Coverage line.
            Scans that ran in one task pass ``total_projects`` instead.
        total_projects (int, optional): Projects in the scope, for the checks'
            summary lines ("312 of 1,000 projects") and the Coverage line.
            Sharded scans take it from ``coverage``.
        previous (dict, optional): The previous scan's summary
            (``app.reporting.changes``): the report then shows what changed.
        **all_results: The dictionary of categorized findings.

    Returns:
        str: A string containing the full HTML report.
    """
    print(f"[{job_id}] 📊 Generating final report for {scope}: {scope_id}...")
    return render_report(build_report_context(scope, scope_id, job_id, all_results, banner=banner, coverage=coverage,
                                              total_projects=total_projects, previous=previous))


def generate_reports(scope, scope_id, job_id, all_results, *, banner=None, coverage=None, total_projects=None, previous=None,
                     membership=None, requested_by=None):
    """Everything a finished scan uploads: ``(html, csv, summary)``.

    The HTML and the CSV come from one context, so a row the page marks *New*
    is the row the CSV marks. ``summary`` is what the next scan of this scope
    compares with (``app.reporting.changes.summarize``); the caller files it
    with ``GcsResultsStore.write_scan_summary`` once the reports are uploaded.
    ``membership`` is what a folder scan reconciled between Asset Inventory and
    Resource Manager (``app.services.resource_manager.folder_membership``), None
    when they agreed. ``requested_by`` is the signed-in person who asked for the
    scan (behind Identity-Aware Proxy), None when unknown.
    """
    print(f"[{job_id}] 📊 Generating final report for {scope}: {scope_id}...")
    context = build_report_context(scope, scope_id, job_id, all_results, banner=banner, coverage=coverage,
                                   total_projects=total_projects, previous=previous, membership=membership,
                                   requested_by=requested_by)
    csv_report = generate_csv_data(all_results, row_matchers=context.row_matchers if context.changes else None)
    return render_report(context), csv_report, summarize(context)
