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

from jinja2 import Environment, PackageLoader, StrictUndefined

from app.reporting.context import build_report_context

REPORT_TEMPLATE = "report/report.html"


@functools.lru_cache(maxsize=None)
def report_environment():
    """Returns the Jinja environment for reports (created on first use)."""
    return Environment(
        loader=PackageLoader("app", "templates"),
        autoescape=True,  # B3: values are text, never markup
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,  # included CSS/JS keep their last line break
        undefined=StrictUndefined,  # a misspelled variable fails instead of rendering ""
    )


def render_report(context):
    """Renders a :class:`~app.reporting.context.ReportContext` to the report HTML."""
    return report_environment().get_template(REPORT_TEMPLATE).render(context.template_vars())


def generate_html_report(scope, scope_id, job_id, banner=None, **all_results):
    """
    Generates a dynamic and interactive HTML report from the scan results.

    Args:
        scope (str): The scope of the scan (organization, folder, project).
        scope_id (str): The ID of the scanned resource.
        job_id (str): The unique ID for this scan job.
        banner (str, optional): A notice shown at the top of the report (the
            synthetic load mode uses it). ``None`` renders nothing.
        **all_results: The dictionary of categorized findings.

    Returns:
        str: A string containing the full HTML report.
    """
    print(f"[{job_id}] 📊 Generating final report for {scope}: {scope_id}...")
    return render_report(build_report_context(scope, scope_id, job_id, all_results, banner=banner))
