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
"""The design system (v14.2): the rules every page follows, pinned so defaults cannot creep back.

The brief: separation by 1px zinc-200 borders, never a shadow; a zinc-50
canvas with white cards; one high-contrast (zinc-900) primary button; status
as a soft pill in its semantic colour (rose, amber, emerald, zinc, sky), never
raw red or green; Inter for text and a monospace face for IDs, metrics,
principals and anything a machine would read; tables with no vertical rules,
quiet uppercase headers, a hairline under each row and a hover; findings as
accordions that open what needs a human; sentence-case headings while status
names keep theirs.

The tokens and primitives live in app/templates/_design.css, which the three
pages inline (a stored report must never depend on a stylesheet served
later). The tests read the rules from the stylesheets and check the rendered
pages: the report as the worker writes it, the index and status pages as the
app serves them.
"""
import pathlib
import re
from html import unescape

import pytest

import samples
from app.checks.categories import CATEGORY_ORDER
from app.reporting.html_report import generate_html_report

TEMPLATES = pathlib.Path(__file__).resolve().parent.parent / 'app' / 'templates'
DESIGN = (TEMPLATES / '_design.css').read_text(encoding='utf-8')
REPORT_STYLES = (TEMPLATES / 'report' / '_styles.css').read_text(encoding='utf-8')
STATUS_PAGE = (TEMPLATES / 'status.html').read_text(encoding='utf-8')
INDEX_PAGE = (TEMPLATES / 'index.html').read_text(encoding='utf-8')

# Tailwind's palette, by the names the brief uses.
ZINC_50, ZINC_200, ZINC_900, WHITE = '#fafafa', '#e4e4e7', '#18181b', '#ffffff'
ROSE = {'50': '#fff1f2', '200': '#fecdd3', '700': '#be123c'}
EMERALD = {'50': '#ecfdf5', '200': '#a7f3d0', '700': '#047857'}

SECURITY = 'Security & Identity'
# Status name -> class suffix (app.reporting.context.STATUS_STYLES) -> hue of its dot and pill.
STATUS_CLASSES = {'Action Required': 'action-required', 'Investigation Recommended': 'investigation', 'Compliant': 'compliant',
                  'Error': 'error', 'Informational': 'informational'}
STATUS_HUES = {'action-required': 'rose', 'investigation': 'amber', 'compliant': 'emerald', 'error': 'zinc', 'informational': 'sky'}
NEEDS_A_HUMAN = {'action-required', 'investigation', 'error'}  # open on load (accordion default B)
PROPER_NOUNS = {'CloudGauge', 'Gemini', 'AI', 'CSV'}  # keep their capitals inside a sentence-case heading or label


AT_RULE_BLOCK = re.compile(r'@(?:media|keyframes)[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}', re.S)


def rules(css):
    """``[(selectors, {property: value})]`` for every top-level rule in ``css`` (@media and @keyframes blocks set aside)."""
    parsed = []
    plain = AT_RULE_BLOCK.sub('', re.sub(r'/\*.*?\*/', '', css, flags=re.S))
    for selectors, body in re.findall(r'([^{}]+)\{([^{}]*)\}', plain):
        declarations = dict(map(str.strip, declaration.split(':', 1)) for declaration in body.split(';') if ':' in declaration)
        parsed.append(([selector.strip() for selector in selectors.strip().split(',')], declarations))
    return parsed


def rule(css, selector):
    """The declarations written for ``selector``: every rule naming it, merged in source order as the cascade would."""
    merged = {}
    for selectors, declarations in rules(css):
        if selector in selectors:
            merged.update(declarations)
    assert merged, f'no rule for {selector}'
    return merged


def render(results):
    return generate_html_report('organization', '123456789', 'job-42', **results)


def ui_copy(page):
    """The fixed headings and button labels of a page (the labels its script sets included), not the data shown."""
    copy = re.findall(r'<h[12][^>]*>([^<{]+)</h[12]>', page)  # the status page's headings are in its script's template literals
    copy += re.findall(r'<(?:button|a)\b[^>]*class="(?:btn|link-btn)[^"]*"[^>]*>([^<$]+)</(?:button|a)>', page)
    copy += re.findall(r'textContent = "([^"]+)"', page)
    return [unescape(text).strip() for text in copy]


def sentence_case(text):
    first, *rest = text.split()
    return first[0].isupper() and all(word in PROPER_NOUNS or not word[0].isupper() for word in rest)


@pytest.fixture
def pages(client):
    """The three pages as a browser gets them."""
    return {
        'report': render(samples.FINDINGS),
        'index': client.get('/').get_data(as_text=True),
        'status': client.get('/status/job-1/project/web-prod').get_data(as_text=True),
    }


def test_every_page_inlines_the_design_system_and_loads_inter(pages):
    for name, page in pages.items():
        assert DESIGN.strip() in page, name  # the tokens and primitives, verbatim
        stylesheets = re.findall(r'<link[^>]*rel="stylesheet"[^>]*>', page)
        assert len(stylesheets) == 1 and 'fonts.googleapis.com/css2?family=Inter:' in stylesheets[0], name  # Inter, nothing else
        assert '<script src=' not in page, name
    tokens = rule(DESIGN, ':root')
    assert tokens['--font-sans'].startswith('Inter, ') and tokens['--font-sans'].endswith(', sans-serif')
    assert tokens['--font-mono'].endswith(', monospace')
    assert rule(DESIGN, 'body')['font'] == '400 14px/1.5 var(--font-sans)'
    for css in (DESIGN, REPORT_STYLES):  # rendered through Jinja: a brace followed by {, % or # would be template syntax
        assert not re.search(r'\{[{%#]', css)


def test_separation_is_a_hairline_border_never_a_shadow(pages):
    for name, page in pages.items():
        assert not re.search(r'(?:box|text)-shadow|drop-shadow\(', page), name
    tokens = rule(DESIGN, ':root')
    assert (tokens['--canvas'], tokens['--surface'], tokens['--hairline']) == (ZINC_50, WHITE, ZINC_200)
    assert rule(DESIGN, 'body')['background'] == 'var(--canvas)'
    card = rule(DESIGN, '.card')
    assert (card['background'], card['border']) == ('var(--surface)', '1px solid var(--hairline)')
    assert rule(REPORT_STYLES, '.kpi')['border'] == '1px solid var(--hairline)'
    assert rule(REPORT_STYLES, '.sidebar')['border-right'] == '1px solid var(--hairline)'
    assert rule(REPORT_STYLES, '.checks-list > li')['border-bottom'] == '1px solid var(--hairline)'
    assert rule(DESIGN, '.notice')['border'] == '1px solid var(--hairline)'


def test_colours_are_palette_tokens_never_raw_red_or_green(pages):
    tokens = rule(DESIGN, ':root')
    assert tokens['--ink'] == ZINC_900
    assert {level: tokens[f'--rose-{level}'] for level in ROSE} == ROSE
    assert {level: tokens[f'--emerald-{level}'] for level in EMERALD} == EMERALD
    for name, page in pages.items():
        styles = ' '.join(re.findall(r'<style>(.*?)</style>', page, re.S))
        outside_tokens = re.sub(r':root \{[^}]*\}', '', styles)
        # Every colour is a token; the one literal is the primary button's white text.
        assert set(re.findall(r'#[0-9a-fA-F]{3,8}\b', outside_tokens)) == {'#fff'}, name
        assert not re.search(r':\s*(?:red|green|blue|orange|yellow)\b', outside_tokens), name


def test_the_primary_button_is_ink_on_white(pages):
    primary = rule(DESIGN, '.btn-primary')
    assert (primary['background'], primary['border-color'], primary['color']) == ('var(--ink)', 'var(--ink)', '#fff')
    assert rule(DESIGN, '.btn-outline')['border-color'] == 'var(--control-border)'
    # One primary action per page: start the scan, get the summary, open the report.
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', pages['index']) == ['Start scan']
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', pages['report']) == ['Get AI summary']
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', pages['status']) == ['View interactive report']


def test_status_is_a_dot_and_a_soft_pill_in_its_semantic_colour(pages):
    for status_class, hue in STATUS_HUES.items():
        fill, line, text = ('zinc-100', 'zinc-200', 'zinc-700') if hue == 'zinc' else (f'{hue}-50', f'{hue}-200', f'{hue}-700')
        pill = rule(DESIGN, f'.pill-{status_class}')
        assert (pill['background'], pill['border-color'], pill['color']) == (f'var(--{fill})', f'var(--{line})', f'var(--{text})'), status_class
        assert rule(DESIGN, f'.dot-{status_class}')['background'] == f'var(--{"zinc-400" if hue == "zinc" else hue + "-500"})'
    pill = rule(DESIGN, '.pill')
    assert pill['border'] == '1px solid var(--zinc-200)' and pill['border-radius'] == '999px'
    assert (rule(DESIGN, '.notice-rose')['color'], rule(DESIGN, '.notice-amber')['color']) == ('var(--rose-700)', 'var(--amber-800)')

    report = render({SECURITY: [{'Check': f'{status} check', 'Status': status, 'Finding': 'x'} for status in STATUS_CLASSES]})
    badges = re.findall(r'<span class="dot dot-([\w-]+)" aria-hidden="true"></span>.*?<span class="status-badge pill pill-([\w-]+)">([^<]+)</span>',
                        report, re.S)
    assert sorted(badges) == sorted((cls, cls, status) for status, cls in STATUS_CLASSES.items())  # the dot and the pill agree
    for cls in STATUS_CLASSES.values():  # the counts under the page title and the sidebar use the same dots
        assert f'<span class="count-{cls}"><span class="dot dot-{cls}"></span>' in report
    assert re.findall(r'<span class="nav-meta"><span class="dot dot-([\w-]+)"></span><span class="mono">(\d+)</span>', report)[0] == ('action-required', '3')


def test_ids_metrics_and_technical_values_are_monospace(pages):
    for css, selector in ((DESIGN, 'code'), (DESIGN, '.mono'), (DESIGN, '.chip'), (DESIGN, '.data-table td.num'), (DESIGN, '.data-table td.time'),
                          (REPORT_STYLES, '.report-meta'), (REPORT_STYLES, '.score'), (REPORT_STYLES, '.section-counts .n'),
                          (REPORT_STYLES, '.details-table .cell-code'), (REPORT_STYLES, '.sidebar-foot time'),
                          (STATUS_PAGE, '.scope-line'), (STATUS_PAGE, '.progress-text'), (STATUS_PAGE, '.job-line'), (STATUS_PAGE, '.error-box')):
        assert rule(css, selector)['font-family'] == 'var(--font-mono)', selector
    assert rule(DESIGN, '.data-table td.num')['font-variant-numeric'] == 'tabular-nums'
    # Rendered: a resource is a chip, a number a num cell, a time a time cell, a state a state cell (test_layouts.py has the roles).
    report = render({SECURITY: [{'Check': 'Key Rotation', 'Status': 'Action Required', 'Finding': [
        {'Project': 'web-prod', 'Principal': 'ci@p.iam.gserviceaccount.com', 'Usage': '91.3%', 'Date': '2026-09-20', 'Status': 'Active'}]}]})
    assert ('<td class="nowrap code"><code class="chip">web-prod</code></td><td class="nowrap code"><code class="chip">ci@p.iam.gserviceaccount.com</code></td>'
            '<td class="nowrap num">91.3%</td><td class="nowrap time">2026-09-20</td><td class="nowrap state">Active</td>') in report
    assert '<dl class="report-meta">' in report and '<dt>Report ID</dt><dd>job-42</dd>' in report
    assert re.search(r'<p class="scope-line">\$\{escapeHtml\(scope\)\} \$\{escapeHtml\(scope_id\)\}</p>', pages['status'])


def test_kpi_numbers_are_light_inter_with_tabular_figures(pages):
    count = rule(REPORT_STYLES, '.kpi .count')
    assert (count['font-size'], count['font-weight'], count['font-variant-numeric']) == ('48px', '300', 'tabular-nums')
    assert 'font-family' not in count  # Inter, as specified: the one place a number is not monospace
    assert 'family=Inter:wght@300;' in pages['report']  # the light weight is requested
    report = pages['report']
    kpis = re.findall(r'<div class="kpi"><span class="dot dot-([\w-]+)"></span><h3>([^<]+)</h3><p class="count">(\d+)</p><span class="kpi-unit">checks</span></div>',
                      report)
    assert [(cls, title) for cls, title, _ in kpis] == [('action-required', 'Action Required'), ('investigation', 'Investigation Recommended'),
                                                        ('compliant', 'Compliant'), ('error', 'Errors')]
    assert rule(REPORT_STYLES, '.kpi-grid')['grid-template-columns'] == 'repeat(4, minmax(0, 1fr))'


def test_tables_have_no_vertical_rules_quiet_headers_and_a_row_hover(pages):
    header = rule(DESIGN, '.data-table th')
    assert (header['font-size'], header['font-weight'], header['letter-spacing'], header['text-transform'], header['color']) == \
        ('12px', '600', '0.05em', 'uppercase', 'var(--muted)')
    cell = rule(DESIGN, '.data-table td')
    assert (cell['padding'], cell['border-bottom']) == ('6px 12px', '1px solid var(--rule)')
    assert rule(DESIGN, '.data-table tbody tr:hover > td')['background'] == 'var(--canvas)'
    assert rule(DESIGN, '.data-table')['border-collapse'] == 'collapse'
    for css in (DESIGN, REPORT_STYLES):
        for selectors, declarations in rules(css):
            if any(re.search(r'\b(?:td|th)\b', selector) for selector in selectors):
                assert not {'border', 'border-left', 'border-right'} & set(declarations), selectors
    for name, page in pages.items():  # every table, the one the cost insights script builds included
        assert all('data-table' in attributes for attributes in re.findall(r'<table\b([^>]*)>', page)), name


def test_findings_are_accordions_that_open_what_needs_a_human():
    report = render({
        SECURITY: [{'Check': f'{status} check', 'Status': status, 'Finding': 'x'} for status in STATUS_CLASSES]
        + [{'Check': 'Odd status', 'Status': 'Warning', 'Finding': 'styled as Informational'}],
        'Organization Policies': (samples.BEST_PRACTICES, samples.CURRENT_POLICIES),
    })
    items = re.findall(r'<li class="status-([\w-]+)" id="([\w-]+)">\s*<details class="check"( open)?>', report)
    assert len(items) == 7 and {cls for cls, _, _ in items} == set(STATUS_CLASSES.values())
    for cls, item_id, is_open in items:
        assert bool(is_open) is (cls in NEEDS_A_HUMAN), item_id
    assert ('action-required', 'security-identity-organization-policies', ' open') in items  # some policies differ
    all_compliant = render({'Organization Policies': ({'Security': samples.BEST_PRACTICES['Security'][:1]}, samples.CURRENT_POLICIES)})
    assert re.search(r'<li class="status-compliant" id="security-identity-organization-policies">\s*<details class="check">', all_compliant)
    # The controls: a chevron, Expand all / Collapse all on the toolbar, and the summary row as the hover target.
    assert '<svg class="chevron"' in report and 'onclick="setAllChecks(true)">Expand all<' in report and 'onclick="setAllChecks(false)">Collapse all<' in report
    assert rule(REPORT_STYLES, 'details.check[open] > summary .chevron')['transform'] == 'rotate(90deg)'
    assert rule(REPORT_STYLES, 'details.check > summary:hover')['background'] == 'var(--canvas)'


def test_headings_are_sentence_case_and_status_names_keep_theirs(pages):
    for name, page in pages.items():
        copy = [text for text in ui_copy(page) if text not in CATEGORY_ORDER]  # category names are data, not UI copy
        assert copy, name
        for text in copy:
            assert sentence_case(text), (name, text)
    assert 'Review your cloud environment' in ui_copy(pages['index'])
    assert {'Scan in progress', 'Scan complete', 'Scan failed', 'View interactive report', 'Download CSV'} <= set(ui_copy(pages['status']))
    assert {'CloudGauge report', 'Overview', 'Review scores', 'Gemini', 'Executive summary', 'Get AI summary', 'Get remediation suggestions',
            'Download CSV', 'Expand all', 'Collapse all'} <= set(ui_copy(pages['report']))
    assert set(CATEGORY_ORDER) <= set(ui_copy(pages['report']))
    assert re.findall(r'<span class="status-badge pill pill-[\w-]+">([^<]+)</span>', pages['report'])
    assert set(re.findall(r'<span class="status-badge pill pill-[\w-]+">([^<]+)</span>', pages['report'])) <= set(STATUS_CLASSES)


def test_setup_and_status_pages_are_one_centred_card_on_a_dot_grid(pages):
    assert rule(DESIGN, '.dotgrid')['background-image'] == 'radial-gradient(circle, var(--zinc-300) 1px, transparent 1px)'
    for name, page, source, card_class in (('index', pages['index'], INDEX_PAGE, 'setup-card'), ('status', pages['status'], STATUS_PAGE, 'status-card')):
        assert '<body class="dotgrid">' in page, name
        assert re.search(rf'<main[^>]*class="card {card_class}"', page), name
        card = rule(source, f'.{card_class}')
        assert (card['max-width'], card['width']) == ('448px', '100%'), name  # max-w-md
        body = rule(source, 'body')
        assert (body['display'], body['align-items'], body['justify-content']) == ('flex', 'center', 'center'), name
    assert rule(DESIGN, '.field label')['font-weight'] == '500' and rule(DESIGN, '.select')['border'] == '1px solid var(--control-border)'
    assert rule(STATUS_PAGE, '.progress-bar')['background'] == 'var(--ink)' and rule(STATUS_PAGE, '.progress-bar-container')['height'] == '4px'
    assert (rule(STATUS_PAGE, '.state-icon.ok')['color'], rule(STATUS_PAGE, '.state-icon.failed')['color']) == ('var(--emerald-600)', 'var(--rose-700)')
