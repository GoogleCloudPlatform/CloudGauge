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
                'TASK_DISPATCH_DEADLINE_SECONDS', 'SWEEP_INTERVAL_SECONDS', 'SCAN_TIME_LIMIT_SECONDS', 'TASK_MAX_ATTEMPTS')
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
    lines, hides rows past the first page, and so on, so a new report no longer
    matches the legacy one line for line. It must still show the same facts:
    the title, the overview counts, the category scores, and every check item
    with its status badge, its details (table headers and rows, or text), and
    whether it has a remediation placeholder. Items are returned sorted, since
    only their order within a section changed. Values are HTML-unescaped.
    """
    def text(markup):
        # Only unescape: legacy wrote some details as raw HTML (e.g. <b>allow-all</b>)
        # where the new report escapes them, and both unescape to the same string.
        return html_unescape(markup.replace('<br>', '\n')).strip()

    items = []
    for item in re.findall(r'<li class="status-[\w-]+">(.*?)</li>', html, re.S):
        name = html_unescape(re.search(r'<strong>(.*?)</strong>', item, re.S).group(1))
        badge = html_unescape(re.search(r'<span class="status-badge">(.*?)</span>', item, re.S).group(1))
        headers = tuple(html_unescape(h) for h in re.findall(r'<th(?:\s[^>]*)?>(.*?)</th>', item, re.S))
        rows = tuple(cells for cells in (
            tuple(html_unescape(cell) for cell in re.findall(r'<td(?:\s[^>]*)?>(.*?)</td>', row, re.S))
            for row in re.findall(r'<tr(?:\s[^>]*)?>(.*?)</tr>', item, re.S)) if cells)
        details = re.search(r'<div class="details">(.*?)</div>', item, re.S)
        details_text = None if (rows or details is None) else text(details.group(1))
        items.append((name, badge, headers, rows, details_text, "class='remediation-placeholder'" in item))
    return {
        'title': re.search(r'<title>(.*?)</title>', html).group(1),
        'header': text(re.search(r'<p style="color: var\(--light-text-color\);">(.*?)</p>', html).group(1)),
        'overview': re.findall(r'<h3>([\w ]+)</h3><p class="count">(\d+)</p>', html),
        'scores': re.findall(r'score-badge score-(\w+)">(\d+)%', html),
        'sections': re.findall(r'<div id="([\w-]+)-section" class="content-section"', html),
        'items': sorted(items),
        'console_link': 'active-assist/list/security/recommendations?organizationId=' in html,
    }


def assert_same_response(legacy_response, response, *, html=False):
    """Asserts the same status, headers that matter, and body (HTML: by ``normalized_lines``)."""
    assert response.status_code == legacy_response.status_code
    for header in ('Content-Type', 'Location', 'Allow'):
        assert response.headers.get(header) == legacy_response.headers.get(header), header
    if html:
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
