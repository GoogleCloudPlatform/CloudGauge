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
"""Helpers for the tests: environments, loading the legacy module, and parity comparisons.

Fixtures live in conftest.py.
"""
import csv
import importlib.util
import io
import pathlib
import re
import sys
import types
from html import unescape as html_unescape

import fakes
from app.checks.categories import CATEGORY_ORDER
from app.config import Settings

LEGACY_PATH = pathlib.Path(__file__).resolve().parent / 'legacy' / 'cloudgauge_legacy.py'
# Upstream beta/cloudgauge_beta_v1.py: the legacy monolith plus four checks (see tests/legacy/README.md).
BETA_V1_PATH = pathlib.Path(__file__).resolve().parent / 'legacy' / 'cloudgauge_beta_v1.py'

# Every environment variable that the app or the legacy module reads.
APP_ENV_VARS = (*fakes.TEST_ENV, 'K_SERVICE', 'WORKER_URL', 'WORKER_AUDIENCE', 'CLOUDGAUGE_ENV', 'GEMINI_MODEL',
                'VERTEX_LOCATION', 'BEST_PRACTICES_CSV_URL', 'SYNTHETIC_PROJECTS', 'SYNTHETIC_SEED',
                'SYNTHETIC_LATENCY_MS', 'SYNTHETIC_ERROR_RATE', 'SYNTHETIC_DENIED_FRACTION',
                'SCAN_SHARD_SIZE', 'SCAN_MAX_CONCURRENT_SHARDS', 'SHARD_TIME_BUDGET_SECONDS',
                'TASK_DISPATCH_DEADLINE_SECONDS', 'SWEEP_INTERVAL_SECONDS', 'SCAN_TIME_LIMIT_SECONDS', 'TASK_MAX_ATTEMPTS',
                'SERVICE_HEALTH_WINDOW_DAYS', 'SERVICE_HEALTH_RELEVANCE', 'ADVISORY_WINDOW_DAYS')
# What a deployed Cloud Run revision sees: the five required variables plus K_SERVICE.
DEPLOYED_ENV = {**fakes.TEST_ENV, 'K_SERVICE': fakes.K_SERVICE}


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


def _vertexai_stubs():
    """Stand-ins for ``vertexai`` and ``vertexai.generative_models``, which the frozen modules import.

    google-cloud-aiplatform is no longer a dependency. The ``legacy`` and
    ``beta`` fixtures replace ``init`` and ``GenerativeModel`` with fakes.
    """
    def not_faked(*args, **kwargs):
        raise RuntimeError('vertexai stub: point the frozen module at the Gemini fake first')

    vertexai = types.ModuleType('vertexai')
    generative_models = types.ModuleType('vertexai.generative_models')
    vertexai.init = not_faked
    generative_models.GenerativeModel = not_faked
    vertexai.generative_models = generative_models
    return {'vertexai': vertexai, 'vertexai.generative_models': generative_models}


def import_legacy(module_name, path=LEGACY_PATH):
    """Executes a frozen pre-refactor module (default: the legacy monolith) as ``module_name``.

    Its import runs the legacy startup sequence (worker URL discovery, env check,
    client creation, queue creation), so patch the GCP libraries first. A failed
    import leaves nothing behind in ``sys.modules``.
    """
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    stubs = _vertexai_stubs()
    saved = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)
    sys.modules[module_name] = module  # Flask(__name__) looks the module up
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[module_name]
        raise
    finally:
        for name, original in saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original
    return module


def normalized_lines(text):
    """The non-blank lines of ``text``, stripped of surrounding whitespace.

    The templates don't reproduce the legacy f-strings' indentation (which
    varied with the Python nesting), so pages are compared on this.
    """
    return [line.strip() for line in text.splitlines() if line.strip()]


def report_lines(text):
    """``normalized_lines`` of a report, for comparing the new (escaped) report with the legacy one.

    Since plan item B3 the report escapes every value it inserts (``&`` is
    written ``&amp;``), and its script embeds values as JSON strings (``"..."``
    rather than ``'...'``). With entities decoded and those quotes made
    uniform, a new and a legacy report compare equal when they show the same
    text. Tests in test_reporting.py check the escaping itself.
    """
    lines = []
    for line in normalized_lines(text):
        line = html_unescape(line)
        if 'JSON.stringify({' in line:
            line = line.replace('"', "'")
        lines.append(line)
    return lines


def report_facts(html):
    """What a report says, independent of how it is laid out.

    The enterprise layout (plan item 6b) orders checks by severity, adds summary
    lines, hides rows past the first page, and so on, and the v14.2 redesign
    renders each check as an accordion with its badge in the summary row, so a
    new report no longer matches the legacy one line for line. It must still
    show the same facts: the title, the scope and report ID, the overview
    counts, the category scores, and every check item with its status badge,
    its details (table headers and rows, or text), and whether it has a
    remediation placeholder. Items are returned sorted, since only their order
    within a section changed. Values are HTML-unescaped; the markup inside a
    cell (chips, disclosures, pills) is reduced to its text.

    ``sections`` are the category pages that list checks (with their header
    scores in ``section_scores``): the new report also gives a category with
    nothing to list a page, which the legacy report left out.
    """
    def text(markup):
        # Only unescape: legacy wrote some details as raw HTML (e.g. <b>allow-all</b>)
        # where the new report escapes them, and both unescape to the same string.
        return html_unescape(markup.replace('<br>', '\n')).strip()

    def cell_text(markup):
        # Layout markup (app.reporting.layouts: titles, muted lines, chips, disclosures, lists, clamps, pills) is
        # reduced to its text, as a browser's textContent would be. Legacy cells have none, so they compare as before.
        return html_unescape(' '.join(re.sub(r'</?(?:span|details|summary|div|button|ul|li|br|code|svg|path|time)\b[^>]*>', ' ', markup).split()))

    items = []
    # An item runs to the </li> on its own line: a list cell's own <li> elements (written inline) must not end it early.
    for item in re.findall(r'<li class="status-[\w-]+"[^>]*>(.*?)\n\s*</li>', html, re.S):
        name = html_unescape(re.search(r'<strong>(.*?)</strong>', item, re.S).group(1))
        badge = html_unescape(re.search(r'<span class="status-badge[^"]*">(.*?)</span>', item, re.S).group(1))
        # Legacy wrote the Organization Policies tally into the name as well as the badge; the new report once.
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
    # Legacy: "Scope: Organization | ID: 123 | Report ID: job-42" in one line; new: a <dl> of the same values.
    header = (re.search(r'Scope: (\w+) \| ID: (.*?) \| Report ID: (.*?)</p>', html)
              or re.search(r'<dt>Scope</dt><dd>(\w+) (.*?)</dd>\s*<dt>Report ID</dt><dd>(.*?)</dd>', html))
    return {
        'title': re.search(r'<title>(.*?)</title>', html).group(1),
        'header': tuple(html_unescape(value) for value in header.groups()),
        'overview': re.findall(r'<h3>([\w ]+)</h3><p class="count">(\d+)</p>', html),
        # The Review Scores table: legacy's score badge, or the new report's score next to its bar (a category the
        # new report leaves not assessed has no number and is not listed).
        'scores': re.findall(r'class="(?:score-badge|score) score-(\w+)">(\d+)%</span></td>', html),
        'sections': [sid for sid, _ in listed],
        # (section id, band, score): the score is None for a page whose pill says "Not assessed".
        'section_scores': [(sid, *re.search(r'(?:score-badge score|score-pill pill pill)-(\w+)">(?:(\d+)% [Cc]ompliant|Not assessed)', body).groups())
                           for sid, body in listed],
        'items': sorted(items),
        'console_link': 'active-assist/list/security/recommendations?organizationId=' in html,
    }


# The facts the new report states differently from the legacy one by design (v15.2, app.reporting.scoring): an
# Error is coverage rather than a failure, Organization Policies is one check rather than one per policy, and a
# category without a verdict is not assessed rather than 100%. The scores, the section pills and the Overview
# counts follow; the parity tests compare everything else (``comparable``). The rule has its own tests.
SCORED_FACTS = ('scores', 'section_scores', 'overview')


def comparable(facts):
    """``report_facts`` minus the ``SCORED_FACTS``: what a new report and a legacy one must still agree on."""
    return {key: value for key, value in facts.items() if key not in SCORED_FACTS}


def page_facts(html):
    """What a page tells the browser to do, independent of how it is laid out.

    The v14.2 redesign rewrote the index and status pages, so they no longer
    compare line by line with the legacy ones. What must not change is their
    contract with the server and the user: the form (where it posts, its field
    names and which are required, the scope values) and the script (the values
    the page embeds, where it polls, where the report is).
    """
    markup, _, script = html.partition('<script')
    return {
        'forms': re.findall(r'<form action="([^"]*)" method="(\w+)"', markup),
        'fields': [(re.search(r'name="(\w+)"', attrs).group(1), ' required' in attrs, ' disabled' in attrs)
                   for attrs in re.findall(r'<select([^>]*)>', markup)],
        'options': re.findall(r'<option value="([^"]*)"', markup),
        'submit_disabled': bool(re.search(r'<button[^>]*type="submit"[^>]*\bdisabled\b', markup)),
        'constants': sorted(re.findall(r'const (job_id|scope_id|signed_csv_url) = (".*?");', script)),
        'urls': sorted(set(re.findall(r'`(/(?:api|report)/[^`]*)`', script))),
    }


def assert_same_response(legacy_response, response, *, html=False, facts=None):
    """Asserts the same status, headers that matter, and body.

    HTML bodies compare by ``normalized_lines``, or by ``facts(html)`` when the
    new page is laid out differently from the legacy one (``page_facts`` for
    the pages redesigned in v14.2); everything else byte for byte.
    """
    assert response.status_code == legacy_response.status_code
    for header in ('Content-Type', 'Location', 'Allow'):
        assert response.headers.get(header) == legacy_response.headers.get(header), header
    if facts is not None:
        assert facts(response.get_data(as_text=True)) == facts(legacy_response.get_data(as_text=True))
    elif html:
        assert normalized_lines(response.get_data(as_text=True)) == normalized_lines(legacy_response.get_data(as_text=True))
    else:
        assert response.get_data() == legacy_response.get_data()


def csv_sections(text):
    """Splits a CSV report into ``{section title: rows}``.

    The legacy worker built its categories from a ``set``, so the order of the
    category sections in its CSV varied between processes; compare sections as a
    dict to ignore that order. The spacer row written before each category
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
    spacer rows between tables are dropped. Lets a test compare two CSVs table
    by table regardless of the order the tables come in (since v15.1 the writer
    lists them as the page does, the legacy writer kept arrival order).
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


def assert_same_csv_tables(csv_text, legacy_csv_text):
    """The two CSV reports have the same sections (in any order: the legacy worker
    built its categories from a set), the same Organization Policies rows, and
    in each category the same tables with the same rows — in any table order
    (see ``csv_tables``)."""
    ours, theirs = csv_sections(csv_text), csv_sections(legacy_csv_text)
    assert set(ours) == set(theirs)
    for title in ours:
        if title == 'Organization Policies':
            assert ours[title] == theirs[title]
        else:
            assert sorted(csv_tables(ours[title])) == sorted(csv_tables(theirs[title])), title
