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
"""Helpers for the tests: environments and settings, and readers that reduce a page, a report or a CSV to its facts.

Fixtures live in conftest.py.
"""
import csv
import io
import re
from html import unescape as html_unescape

import fakes
from app.checks.categories import CATEGORY_ORDER
from app.config import Settings

# Every environment variable that the app reads.
APP_ENV_VARS = (*fakes.TEST_ENV, 'K_SERVICE', 'WORKER_URL', 'WORKER_AUDIENCE', 'CLOUDGAUGE_ENV', 'CLOUDGAUGE_ROLE',
                'PROJECT_NUMBER', 'GEMINI_MODEL',
                'VERTEX_LOCATION', 'BEST_PRACTICES_CSV_URL', 'SYNTHETIC_PROJECTS', 'SYNTHETIC_SEED',
                'SYNTHETIC_LATENCY_MS', 'SYNTHETIC_ERROR_RATE', 'SYNTHETIC_DENIED_FRACTION',
                'SCAN_SHARD_SIZE', 'SCAN_MAX_CONCURRENT_SHARDS', 'SHARD_TIME_BUDGET_SECONDS',
                'TASK_DISPATCH_DEADLINE_SECONDS', 'SWEEP_INTERVAL_SECONDS', 'SCAN_TIME_LIMIT_SECONDS', 'TASK_MAX_ATTEMPTS',
                'SERVICE_HEALTH_WINDOW_DAYS', 'SERVICE_HEALTH_RELEVANCE', 'ADVISORY_WINDOW_DAYS',
                # v17
                'COST_ALLOCATION_LABELS', 'SNAPSHOT_MAX_AGE_DAYS', 'RESERVATION_COVERAGE_MIN_VCPUS', 'BIGQUERY_DATASET',
                'BIGQUERY_EXPORT_WAIT_SECONDS',
                # v17.3
                'SERVICE_HEALTH_INCIDENTS',
                # v18.5
                'TRUSTED_DOMAINS',
                # v18.6.1
                'WORKER_TOKEN_CHECK',
                # v18.8
                'BILLING_EXPORT', 'SPEND_ANOMALY_FLOOR',
                # v18.8.1
                'CLOUDGAUGE_DISABLE_ATTRIBUTION')
# What a deployed Cloud Run revision sees: the five required variables plus K_SERVICE — and, for the tests, the worker's
# in-process token check off (v18.6.1): the production-profile apps the suites post task bodies to have no Cloud Tasks
# behind them. tests/test_request_hardening.py turns the check on and verifies it with signed tokens.
DEPLOYED_ENV = {**fakes.TEST_ENV, 'K_SERVICE': fakes.K_SERVICE, 'WORKER_TOKEN_CHECK': 'off'}


def set_env(monkeypatch, values):
    """Sets exactly ``values`` among APP_ENV_VARS; the others are removed."""
    for name in APP_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def make_settings(profile='testing', **overrides):
    """Settings for DEPLOYED_ENV plus ``overrides`` (an override of ``None`` removes the variable)."""
    environ = {**DEPLOYED_ENV, 'CLOUDGAUGE_ENV': profile, **overrides}
    return Settings.from_env({name: value for name, value in environ.items() if value is not None})


def normalized_lines(text):
    """The non-blank lines of ``text``, stripped of surrounding whitespace (the templates' indentation is not a fact of a page)."""
    return [line.strip() for line in text.splitlines() if line.strip()]


def report_facts(html):
    """What a report says, independent of how it is laid out.

    The enterprise layout (plan item 6b) orders checks by severity, adds summary
    lines, hides rows past the first page, and so on, and the v14.2 redesign
    renders each check as an accordion with its badge in the summary row; a
    test that cares what a report says, not how, reads it through this: the
    title, the scope and report ID, the overview counts, the category scores,
    and every check item with its status badge, its details (table headers and
    rows, or text), and whether it has a remediation placeholder. Items are
    returned sorted, so their order within a section is not a fact. Values are
    HTML-unescaped; the markup inside a cell (chips, disclosures, pills) is
    reduced to its text.

    ``sections`` are the category pages that list checks (with their header
    scores in ``section_scores``): a category with nothing to list has a page
    too, which says so instead of listing.
    """
    def text(markup):
        # Only unescape: the report escapes the details it inserts, and a test compares the text.
        return html_unescape(markup.replace('<br>', '\n')).strip()

    def cell_text(markup):
        # Layout markup (app.reporting.layouts: titles, muted lines, chips, disclosures, lists, clamps, pills) is
        # reduced to its text, as a browser's textContent would be.
        return html_unescape(' '.join(re.sub(r'</?(?:span|details|summary|div|button|ul|li|br|code|svg|path|time)\b[^>]*>', ' ', markup).split()))

    items = []
    # An item runs to the </li> on its own line: a list cell's own <li> elements (written inline) must not end it early.
    for item in re.findall(r'<li class="status-[\w-]+"[^>]*>(.*?)\n\s*</li>', html, re.S):
        name = html_unescape(re.search(r'<strong>(.*?)</strong>', item, re.S).group(1))
        badge = html_unescape(re.search(r'<span class="status-badge[^"]*">(.*?)</span>', item, re.S).group(1))
        # The Organization Policies tally is a fact of the badge, not of the name.
        name = re.sub(r'^Organization Policies \(\d+/\d+ Compliant\)$', 'Organization Policies', name)
        headers = tuple(html_unescape(h) for h in re.findall(r'<th(?:\s[^>]*)?>(.*?)</th>', item, re.S))
        rows = tuple(cells for cells in (
            tuple(cell_text(cell) for cell in re.findall(r'<td(?:\s[^>]*)?>(.*?)</td>', row, re.S))
            for row in re.findall(r'<tr(?:\s[^>]*)?>(.*?)</tr>', item, re.S)) if cells)
        details = re.search(r'<div class="details">(.*?)</div>', item, re.S)
        details_text = None if (rows or details is None) else text(details.group(1))
        items.append((name, badge, headers, rows, details_text, "class='remediation-placeholder'" in item))
    # (section id, section body) pairs; the body runs to the next section or the script.
    parts = re.split(r'<div id="([\w-]+)-section" class="content-section"', html.split('<script', 1)[0])
    sections = [(parts[i], parts[i + 1]) for i in range(1, len(parts) - 1, 2)]
    listed = [(sid, body) for sid, body in sections if 'class="checks-list"' in body]
    # The header: a <dl> of the scope, its ID and the report ID (or the one-line "Scope: Organization | ID: 123 | Report ID: job-42" form).
    header = (re.search(r'Scope: (\w+) \| ID: (.*?) \| Report ID: (.*?)</p>', html)
              or re.search(r'<dt>Scope</dt><dd>(\w+) (.*?)</dd>\s*<dt>Report ID</dt><dd>(.*?)</dd>', html))
    return {
        'title': re.search(r'<title>(.*?)</title>', html).group(1),
        'header': tuple(html_unescape(value) for value in header.groups()),
        'overview': re.findall(r'<h3>([\w ]+)</h3><p class="count">(\d+)</p>', html),
        # The Review Scores table: the score next to its bar (a category left not assessed has no number and is not listed).
        'scores': re.findall(r'class="(?:score-badge|score) score-(\w+)">(\d+)%</span></td>', html),
        'sections': [sid for sid, _ in listed],
        # (section id, band, score): the score is None for a page whose pill says "Not assessed".
        'section_scores': [(sid, *re.search(r'(?:score-badge score|score-pill pill pill)-(\w+)">(?:(\d+)% [Cc]ompliant|Not assessed)', body).groups())
                           for sid, body in listed],
        'items': sorted(items),
        'console_link': 'active-assist/list/security/recommendations?organizationId=' in html,
    }


def page_facts(html):
    """What a page tells the browser to do, independent of how it is laid out.

    The contract of the index and status pages with the server and the user:
    the form (where it posts, its field names and which are required, the
    scope values) and the script (the values the page embeds, where it polls,
    where the report is).
    """
    markup, _, script = html.partition('<script')
    return {
        'forms': re.findall(r'<form action="([^"]*)" method="(\w+)"', markup),
        'fields': [(re.search(r'name="(\w+)"', attrs).group(1), ' required' in attrs, ' disabled' in attrs)
                   for attrs in re.findall(r'<select([^>]*)>', markup)],
        'options': re.findall(r'<option value="([^"]*)"', markup),
        'submit_disabled': bool(re.search(r'<button[^>]*type="submit"[^>]*\bdisabled\b', markup)),
        'constants': sorted(re.findall(r'const (job_id|scope_id) = (".*?");', script)),
        'urls': sorted(set(re.findall(r'`(/(?:api|report)/[^`]*)`', script))),
    }


def csv_sections(text):
    """Splits a CSV report into ``{section title: rows}``.

    The sections come in the order they are written (``Organization Policies``,
    then ``CATEGORY_ORDER``); the spacer row written before each category
    section is dropped.
    """
    rows = list(csv.reader(io.StringIO(text)))
    sections, current = {}, None
    for i, row in enumerate(rows):
        starts_section = len(row) == 1 and (i == 0 or (rows[i - 1] == [] and row[0] in CATEGORY_ORDER))
        if starts_section:
            if current is not None:
                sections[current].pop()  # the spacer row before this title
            current = row[0]
            sections[current] = []
        else:
            sections[current].append(row)
    return sections


def csv_tables(section_rows):
    """Splits one category section of the CSV into its tables.

    A table is a ``Check, Status, ...`` header row and the rows under it; the
    spacer rows between tables are dropped. Lets a test look at a section
    table by table (since v15.1 the writer lists them as the page does).
    """
    tables, current = [], None
    for row in section_rows:
        if not row:
            current = None
        elif row[0] == 'Check':
            current = [row]
            tables.append(current)
        elif current is not None:
            current.append(row)
        else:
            tables.append([row])  # a row outside any table: kept, so nothing is silently dropped
    return tables
