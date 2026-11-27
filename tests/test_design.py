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
import json
import pathlib
import re
from html import unescape
from urllib.parse import unquote

import pytest

import samples
from app.checks.categories import CATEGORY_ORDER
from app.reporting.html_report import generate_html_report

TEMPLATES = pathlib.Path(__file__).resolve().parent.parent / 'app' / 'templates'
DESIGN = (TEMPLATES / '_design.css').read_text(encoding='utf-8')
REPORT_STYLES = (TEMPLATES / 'report' / '_styles.css').read_text(encoding='utf-8')
STATUS_PAGE = (TEMPLATES / 'status.html').read_text(encoding='utf-8')
INDEX_PAGE = (TEMPLATES / 'index.html').read_text(encoding='utf-8')
HISTORY_PAGE = (TEMPLATES / 'history.html').read_text(encoding='utf-8')
ASSETS = TEMPLATES.parent.parent / 'assets'
ICON_SVG = (ASSETS / 'cloudgauge_icon.svg').read_text(encoding='utf-8')  # the mark: nine tiles
LOGO_SVG = (ASSETS / 'cloudgauge_logo.svg').read_text(encoding='utf-8')  # the mark beside the wordmark

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
PROPER_NOUNS = {'CloudGauge', 'Gemini', 'AI', 'CSV', 'PDF', 'Markdown'}  # keep their capitals inside a sentence-case heading or label


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
    page = re.sub(r'<svg class="cg-mark"[^>]*>.*?</svg>', '', page, flags=re.S)  # the brand (v20.0.1) reads as its accessible name
    page = re.sub(r'<svg class="cg-wordmark"[^>]*>.*?</svg>', 'CloudGauge', page, flags=re.S)
    copy = re.findall(r'<h[12][^>]*>([^<{]+)</h[12]>', page)  # the status page's headings are in its script's template literals
    for heading, attribution in re.findall(r'<h2>([^<{]+)<span class="attribution">([^<]+)</span></h2>', page):
        copy += [heading, attribution]  # "AI analysis" with its "Powered by Gemini"
    copy += re.findall(r'<(?:button|a)\b[^>]*class="(?:btn|link-btn)[^"]*"[^>]*>([^<$]+)</(?:button|a)>', page)
    copy += re.findall(r'textContent = "([^"]+)"', page)
    return [unescape(text).strip() for text in copy]


def sentence_case(text):
    first, *rest = text.split()
    return first[0].isupper() and all(word in PROPER_NOUNS or not word[0].isupper() for word in rest)


@pytest.fixture
def pages(client, gcp):
    """The pages as a browser gets them (v17: the history page too, with one scan on record; v18.6.1: the *scan already
    running* page, a POST /scan while the scope's noted job has not finished)."""
    import json
    from datetime import datetime, timezone

    from app.reporting.html_report import generate_reports

    summary = generate_reports('organization', '123456789', 'job-1', samples.FINDINGS, total_projects=4)[2]
    gcp.bucket.put(f"scopes/organization/123456789/{summary['generated_ts']}_job-1.json", json.dumps(summary), 'application/json')
    gcp.bucket.put('schedules/project/web-prod.json', json.dumps({
        'job_id': '11111111-1111-4111-8111-111111111111', 'scope': 'project', 'scope_id': 'web-prod', 'requested_by': 'alice@example.com',
        'started_at': datetime.now(timezone.utc).isoformat(timespec='seconds')}), 'application/json')
    return {
        'report': render(samples.FINDINGS),
        'index': client.get('/').get_data(as_text=True),
        'status': client.get('/status/11111111-1111-4111-8111-111111111111/project/web-prod').get_data(as_text=True),
        'history': client.get('/history/organization/123456789').get_data(as_text=True),
        'running': client.post('/scan', data={'scope': 'project', 'scope_id': 'web-prod'}).get_data(as_text=True),
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
    # One primary action per page: start the scan, generate the summary, open the report. Copy controls stay outline.
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', pages['index']) == ['Start scan']
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', pages['report']) == ['Generate executive summary']
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', pages['status']) == ['View interactive report']
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', pages['history']) == []  # a page to read: outline actions only
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', pages['running']) == ['Open the running scan']


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
                          (REPORT_STYLES, '.details-table .cell-code'), (REPORT_STYLES, '.sidebar-foot time'), (REPORT_STYLES, '.sidebar-foot .version'),
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
    # v17: the history page's chart is monochrome ink on hairlines, its table the same quiet table.
    assert rule(HISTORY_PAGE, '.chart .line')['stroke'] == 'var(--ink)' and rule(HISTORY_PAGE, '.chart .grid')['stroke'] == 'var(--hairline)'
    assert rule(HISTORY_PAGE, '.score')['font-family'] == 'var(--font-mono)' and rule(HISTORY_PAGE, '.page')['max-width'] == '1200px'  # v20: eight columns fit a laptop


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
    assert {'Scan in progress', 'Scan complete', 'Scan failed', 'View interactive report', 'Download CSV', 'View history'} <= set(ui_copy(pages['status']))
    assert {'Scan history', 'Scores over time', 'Scans', 'Start a scan'} <= set(ui_copy(pages['history']))
    assert {'CloudGauge report', 'Overview', 'Review scores', 'Suggested fixes', 'Powered by Gemini', 'Draft fixes', 'Download CSV',
            'Expand all', 'Collapse all', 'Copy', 'Scorecard', 'Top actions', 'Executive summary', 'Generate executive summary',
            'Print', 'Download action plan (CSV)', 'Copy as Markdown', 'Print or save as PDF'} <= set(ui_copy(pages['report']))
    assert set(CATEGORY_ORDER) <= set(ui_copy(pages['report']))
    assert re.findall(r'<span class="status-badge pill pill-[\w-]+">([^<]+)</span>', pages['report'])
    assert set(re.findall(r'<span class="status-badge pill pill-[\w-]+">([^<]+)</span>', pages['report'])) <= set(STATUS_CLASSES)


def test_gemini_actions_name_what_they_do_and_credit_gemini_quietly(pages):
    """Each Gemini action lives where its result lands: Draft fixes on the Overview (the fixes go to the category pages,
    the status line says where), the executive summary on the Scorecard, in the card that shows it (v15.1)."""
    report = pages['report']
    overview, scorecard = report.split('id="scorecard-section"')
    assert '<h2>Suggested fixes <span class="attribution">Powered by Gemini</span></h2>' in overview
    assert '<p>Draft a gcloud fix for every failing finding that does not already show one; each appears under its finding on the category pages.</p>' in overview
    assert 'onclick="getGeminiSuggestions(this)">Draft fixes<' in overview and 'generateAiSummary' not in overview
    assert '<h2>Executive summary <span class="attribution">Powered by Gemini</span></h2>' in scorecard
    assert 'onclick="generateAiSummary()">Generate executive summary<' in scorecard and 'getGeminiSuggestions' not in scorecard.split('<script')[0]
    attribution = rule(REPORT_STYLES, '.attribution')
    assert (attribution['color'], attribution['font-weight']) == ('var(--muted)', '400')  # text, not a pill: pills mean status
    assert 'Get AI summary' not in report and 'Get remediation suggestions' not in report and 'AI analysis' not in report


def test_every_fix_block_has_the_same_copy_control():
    """A gcloud line is a gcloud line: built-in fixes and AI-drafted ones share one title row with one Copy button."""
    copy_button = '<button type="button" class="btn btn-outline btn-sm copy-btn" onclick="copyFix(this)">Copy</button>'
    report = render({SECURITY: [{'Check': 'Audit Logging', 'Status': 'Action Required', 'Finding': [
        {'Project': 'web-prod', 'Issue': 'Data access logs off', 'Fix': 'gcloud projects set-iam-policy web-prod policy.yaml'}]}]})
    # v17.3: the title row says what the block is, so nobody waits for Draft fixes to produce what is already there.
    caption = '<span class="attribution">exact, from the check — Draft fixes covers the findings without one</span>'
    assert f'<div class="fix-block"><div class="fix-head"><strong>Fix</strong>{caption}{copy_button}</div><pre>gcloud projects set-iam-policy web-prod policy.yaml</pre></div>' in report
    # The AI-drafted block is built by the script with the same row (plus its AI-generated pill), and the executive summary's
    # Copy is the same control; all three go through one copyText helper.
    script = report.split('<script>')[-1]
    assert f'<strong>Suggested fix</strong> <span class="pill pill-sky">AI-generated</span>\'\n        + \'{copy_button}' in script
    assert 'id="copy-summary-btn" class="btn btn-outline btn-sm" onclick="copySummary(this)"' in report
    assert script.count('return copyText(btn,') == 2 and 'async function copyText(btn, text)' in script
    assert rule(REPORT_STYLES, '.fix-head .copy-btn')['margin-left'] == 'auto'


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


# ---- The logo on the pages (v20.0.1): app/templates/_logo.html inlines the mark and the wordmark, pinned to the asset files ----

TILE_COLOURS = ['#E8EAED', '#E8EAED', '#1E8E3E', '#E8EAED', '#F9AB00', '#1A73E8', '#EA4335', '#4285F4', '#1A73E8']  # row-major
MARK_SIZES = {'status': ['32'], 'index': ['32'], 'history': ['32'], 'running': ['32'], 'report': ['24', '36']}  # the brand rows (v20.0.2: every page); the sidebar brand and the report title
MARK = re.compile(r'<svg class="cg-mark" viewBox="0 0 144 144" width="(\d+)" height="(\d+)" aria-hidden="true" focusable="false">(.*?)</svg>', re.S)
WORDMARK = re.compile(r'<svg class="cg-wordmark" viewBox="194 48 456 64" width="([\d.]+)" height="([\d.]+)" style="margin-left:([\d.]+)px" '
                      r'role="img" aria-label="CloudGauge" focusable="false">(.*?)</svg>', re.S)


def svg_rects(svg):
    return [dict(re.findall(r'([\w-]+)="([^"]*)"', attributes)) for attributes in re.findall(r'<rect\b([^>]*)/>', svg)]


def with_script_markup(page):
    """The page plus the markup its script holds as JSON: the status page's brand row, built for each of its states."""
    return page + ''.join(json.loads(literal) for literal in re.findall(r'const LOCKUP = ("(?:[^"\\]|\\.)*");', page))


def test_the_mark_is_the_icon_tile_for_tile(pages):
    """Nine <rect>s in the icon's order (the status page's script moves them by index) with the icon's geometry and colours,
    as SVG attributes: the stylesheets keep to the tokens (test_colours_are_palette_tokens_never_raw_red_or_green)."""
    icon = svg_rects(ICON_SVG)
    assert len(icon) == 9 and [tile['fill'] for tile in icon] == TILE_COLOURS
    assert [(tile['x'], tile['y']) for tile in icon] == [(str(8 + 46 * (n % 3)), str(8 + 46 * (n // 3))) for n in range(9)]  # CELL = 46
    for name, page in pages.items():
        marks = MARK.findall(with_script_markup(page))
        assert [width for width, _, _ in marks] == MARK_SIZES.get(name, []), name
        for width, height, tiles in marks:
            assert width == height and svg_rects(tiles) == icon, name


def test_the_wordmark_is_the_logo_outline(pages):
    """Beside every mark, the logo file's wordmark: its two glyph outlines, the arc of the G and the G's blue bar, sized
    from the mark in the logo's proportions (gap 50, cap height 64, width 456 of the mark's 144) and reading as its name."""
    outlines = [re.sub(r'\s+', ' ', d).strip() for d in re.findall(r'<path\s+d="([^"]+)"\s+id="text(?:9|10)"', LOGO_SVG)]
    assert len(outlines) == 2 and re.search(r'<rect\s+x="436.5"\s+y="75.5"\s+width="29"\s+height="9"\s+rx="1.8"\s+fill="#1A73E8"', LOGO_SVG)
    for name, page in pages.items():
        page = with_script_markup(page)
        wordmarks, marks = WORDMARK.findall(page), MARK.findall(page)
        assert len(wordmarks) == len(marks), name
        for (width, height, gap, inner), (size, _, _) in zip(wordmarks, marks):
            size = int(size)
            assert (float(width), float(height), float(gap)) == (round(456 * size / 144, 1), round(64 * size / 144, 1), round(50 * size / 144, 1)), name
            assert re.findall(r'<path fill="currentColor" d="([^"]+)"', inner) == outlines, name
            assert 'stroke="currentColor" stroke-width="9.0"' in inner and '<rect x="436.5" y="75.5" width="29" height="9" rx="1.8" fill="#1A73E8"/>' in inner, name
    assert '<div class="sidebar-brand"><svg class="cg-mark"' in pages['report'] and 'CloudGauge report' in ui_copy(pages['report'])
    lockup = rule(DESIGN, '.cg-lockup')
    assert (lockup['display'], lockup['align-items'], lockup['color']) == ('inline-flex', 'center', 'var(--ink)')
    assert rule(DESIGN, '.cg-wordmark')['overflow'] == 'visible'  # the descender of the g lies below the cap-height viewBox
    assert rule(REPORT_STYLES, '.sidebar-brand')['display'] == 'flex' and rule(REPORT_STYLES, '.report-header h1')['display'] == 'flex'


def test_every_page_carries_the_mark_as_its_favicon(pages):
    icon = svg_rects(ICON_SVG)
    for name, page in pages.items():
        icons = re.findall(r'<link rel="icon" type="image/svg\+xml" href="data:image/svg\+xml,([^"]+)">', page)
        assert len(icons) == 1, name  # inline, so a stored report stays self-contained
        svg = unquote(icons[0])
        assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 144 144">') and svg_rects(svg) == icon, name


def test_the_status_page_assembles_the_logo_as_the_scan_advances(pages):
    """The brand row of the status page is the lockup, in every state. While the scan runs the mark's tiles slide like
    the rows and columns of a puzzle cube and lock home in the gauge's order as the poll's progress grows, so 100% is
    the logo; the bar, the percentage and the task line are what they were; under prefers-reduced-motion nothing slides."""
    assert pages['status'].count('const LOCKUP = ') == 1 and STATUS_PAGE.count('return `<div class="brand brand-lockup">${LOCKUP}${who}</div>`;') == 1
    assert STATUS_PAGE.count('${brandHtml()}') == 3  # in progress, complete, failed
    assert 'const LOCK_ORDER = [6, 7, 8, 5, 4, 2, 0, 1, 3];' in STATUS_PAGE  # red, light blue, blue, blue, amber, green, then the greys
    assert 'const CELL = 46;' in STATUS_PAGE and "window.matchMedia('(prefers-reduced-motion: reduce)').matches" in STATUS_PAGE
    assert 'if (mark) mark.setProgress(data.progress);' in STATUS_PAGE and 'setInterval(() => { if (mark) mark.move(); }, 700)' in STATUS_PAGE
    assert 'if (mark) mark.setProgress(100);' in STATUS_PAGE and len(re.findall(r'^\s+mark = null;', STATUS_PAGE, re.M)) == 2  # settled on complete and on failed
    assert rule(STATUS_PAGE, '.cg-mark rect')['transition'].startswith('transform ') and rule(STATUS_PAGE, '.cg-mark rect.wrap')['transition'] == 'none'
    for source in (STATUS_PAGE, INDEX_PAGE, HISTORY_PAGE):  # v20.0.2: the lockup is the brand row of every page
        assert rule(source, '.brand-lockup')['align-items'] == 'center'
    for unchanged in ('<span id="progress-bar" class="progress-bar"></span>', '<span id="progress-text" class="progress-text">0%</span>',
                      '<p id="status-message" class="status-message">Starting…</p>', "progressBar.style.width = data.progress + '%'"):
        assert unchanged in STATUS_PAGE
