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
"""The reports: the Jinja HTML report and the CSV match the legacy generators.

Both generators get the same categorized results. The HTML reports are compared
on what they say (``helpers.report_facts``: title, overview counts, scores, and
every check item with its status, details and remediation placeholder) rather
than line by line: the enterprise layout (plan item 6b) orders checks by
severity, adds summary lines and paging, and so on, but must not lose or alter
a finding. Entities are decoded in the comparison: the new report escapes the
values it inserts (plan item B3), the legacy one didn't. The CSVs are compared
byte for byte. No Flask app or request context is involved: reports are
rendered by the worker, outside any request for a page.
"""
import json
import re
from html import unescape

import pytest
from jinja2 import UndefinedError

import samples
from app.reporting.context import MAX_ROWS_PER_CHECK, ROWS_PER_PAGE
from app.reporting.csv_report import generate_csv_data
from app.reporting.html_report import generate_html_report, report_environment
from helpers import csv_sections, report_facts

SECURITY, COST, RELIABILITY, OPERATIONS = ('Security & Identity', 'Cost Optimization', 'Reliability & Resilience',
                                           'Operational Excellence & Observability')
ORG_POLICIES = (samples.BEST_PRACTICES, samples.CURRENT_POLICIES)


def checks(status, count, prefix='Check'):
    """``count`` findings for distinct checks, all with ``status``."""
    return [{'Check': f'{prefix} {status} {i}', 'Status': status, 'Finding': f'Finding {i}'} for i in range(count)]


# name -> categorized results, as the worker passes them to both generators
SCENARIOS = {
    'no results': {},
    'empty categories': {category: [] for category in (SECURITY, COST, RELIABILITY, OPERATIONS)},
    'sample scan': {**samples.FINDINGS, 'Organization Policies': ORG_POLICIES},
    'sample findings only': dict(samples.FINDINGS),
    'org policies only': {'Organization Policies': ORG_POLICIES},
    'all org policies compliant': {'Organization Policies': (
        {'Security': samples.BEST_PRACTICES['Security'][:1]}, samples.CURRENT_POLICIES)},
    'html in findings': {SECURITY: [
        {'Check': 'Open Firewall Rules', 'Status': 'Action Required', 'Finding': 'Rule <b>allow-all</b> & "default" open to 0.0.0.0/0'},
        {'Check': 'Project IAM Hygiene', 'Status': 'Investigation Recommended', 'Finding': [{'Member': '<script>alert(1)</script>', 'Role': "roles/owner's"}]},
    ]},
    'unknown and missing statuses': {OPERATIONS: [
        {'Check': 'Unattended Projects', 'Status': 'Warning', 'Finding': 'Not a known status: styled as Informational'},
        {'Check': 'Recent Changes (Org & Project)', 'Finding': 'No Status key: rendered as None'},
    ]},
    'mixed detail types': {COST: [
        {'Check': 'VM Rightsizing', 'Status': 'Investigation Recommended', 'Finding': [{'VM': 'big-vm'}, 'n2-standard-8 is enough']}]},
    'falsy details': {RELIABILITY: [
        {'Check': 'GKE Hygiene', 'Status': 'Compliant', 'Finding': ''},
        {'Check': 'Essential Contacts', 'Status': 'Compliant', 'Finding': None},
        {'Check': 'Cloud SQL PITR', 'Status': 'Compliant'},
    ]},
    'cell values': {COST: [
        {'Check': 'Idle Persistent Disks', 'Status': 'Investigation Recommended',
         'Finding': [{'Size (GB)': 500, 'Monthly Savings': 12.5, 'Snapshot': None, 'Attached': False, 'Ratio': 1 / 3}]}]},
    'multiline text': {OPERATIONS: [
        {'Check': 'Quota Utilization (>80%)', 'Status': 'Action Required', 'Finding': ['CPUS: 92%\nin us-central1', 'GPUS: 81%']}]},
    'score boundaries': {  # 90% is "medium", 90.9% is "high", 70% is "low", 71.4% is "medium"
        SECURITY: checks('Compliant', 9, 'Security') + checks('Action Required', 1, 'Security'),
        COST: checks('Compliant', 10, 'Cost') + checks('Investigation Recommended', 1, 'Cost'),
        RELIABILITY: checks('Compliant', 7, 'Reliability') + checks('Error', 3, 'Reliability'),
        OPERATIONS: checks('Compliant', 5, 'Operations') + checks('Action Required', 2, 'Operations')
        + checks('Informational', 4, 'Operations'),
    },
    'unknown category': {'Uncategorized': [{'Check': 'Something else', 'Status': 'Action Required', 'Finding': 'ignored'}]},
}


@pytest.fixture
def legacy_reports(legacy):
    """The legacy report generators (from the module imported once per session)."""
    return legacy


@pytest.mark.parametrize('name', SCENARIOS)
def test_html_report_matches_legacy(name, legacy_reports):
    results = SCENARIOS[name]
    html = generate_html_report('organization', '123456789', 'job-42', **results)
    assert report_facts(html) == report_facts(legacy_reports.generate_html_report('organization', '123456789', 'job-42', **results))


@pytest.mark.parametrize('scope, scope_id', [('organization', '123456789'), ('folder', '42'), ('project', 'web-prod')])
def test_html_report_matches_legacy_for_each_scope(scope, scope_id, legacy_reports):
    """The title and header use the scope; the Security section's console link is for organizations only."""
    results = SCENARIOS['sample scan']
    html = generate_html_report(scope, scope_id, 'job-42', **results)
    assert report_facts(html) == report_facts(legacy_reports.generate_html_report(scope, scope_id, 'job-42', **results))
    assert f'<title>CloudGauge Report: {scope.capitalize()} {scope_id}</title>' in html
    assert ('active-assist/list/security/recommendations?organizationId=' in html) is (scope == 'organization')


@pytest.mark.parametrize('name', [name for name in SCENARIOS if name != 'mixed detail types'])
def test_csv_report_matches_legacy(name, legacy_reports):
    results = SCENARIOS[name]
    assert generate_csv_data(results) == legacy_reports.generate_csv_data(results)


def test_csv_report_raises_like_legacy_on_mixed_detail_types(legacy_reports):
    """Details mixing dicts and strings: the HTML report falls back to text, but the CSV raises (in both)."""
    results = SCENARIOS['mixed detail types']
    with pytest.raises(AttributeError) as legacy_error:
        legacy_reports.generate_csv_data(results)
    with pytest.raises(AttributeError) as error:
        generate_csv_data(results)
    assert str(error.value) == str(legacy_error.value)


def test_csv_report_rows():
    sections = csv_sections(generate_csv_data(SCENARIOS['sample scan']))
    assert list(sections) == ['Organization Policies', SECURITY, COST, RELIABILITY, OPERATIONS]
    assert sections['Organization Policies'] == [['Category', 'Policy', 'Expected Value', 'Current Value', 'Status'],
                                                 *samples.ORG_POLICY_CSV_ROWS]
    assert sections[COST] == [
        ['Check', 'Status', 'Project', 'Disk', 'Monthly Savings'],
        ['Idle Persistent Disks', 'Investigation Recommended', 'data-lake', 'orphan-disk', '12.4'],
        ['Idle Persistent Disks', 'Investigation Recommended', 'web-prod', 'old-boot-disk'],
        [],
        ['Check', 'Status', 'Details'],
        ['VM Rightsizing', 'Compliant', ''],
    ]


def test_report_scores_and_overview():
    html = generate_html_report('organization', '123456789', 'job-42', **SCENARIOS['score boundaries'])
    scores = re.findall(r'<span class="score-badge score-(\w+)">(\d+)%</span>', html)
    assert scores == [('medium', '90'), ('high', '91'), ('low', '70'), ('medium', '71')]
    counts = dict(re.findall(r'<h3>([\w ]+)</h3><p class="count">(\d+)</p>', html))
    assert counts == {'Action Required': '3', 'Investigation Recommended': '1', 'Compliant': '31', 'Errors': '3'}


def test_org_policies_count_toward_security():
    html = generate_html_report('organization', '123456789', 'job-42', **SCENARIOS['org policies only'])
    assert '<strong>Organization Policies (1/4 Compliant)</strong>' in html
    assert '<span class="score-badge score-low">25% Compliant</span>' in html  # 1 compliant out of 4 policies


def test_remediation_placeholders_are_numbered_in_display_order():
    """getGeminiSuggestions() pairs fix-N with the N-th actionable check on the page."""
    html = generate_html_report('organization', '123456789', 'job-42', **SCENARIOS['sample scan'])
    placeholders = [int(n) for n in re.findall(r"id='fix-(\d+)'", html)]
    assert placeholders == list(range(4))  # one per Action Required / Investigation Recommended check
    # Security (Project IAM Hygiene), Cost (Idle Persistent Disks), Reliability (Essential Contacts), Operations (Quota)
    order = [html.index(f'<strong>{name}</strong>') for name in
             ('Project IAM Hygiene', 'Idle Persistent Disks', 'Essential Contacts', 'Quota Utilization (&gt;80%)')]
    assert order == sorted(order)


def test_grouped_check_keeps_the_most_severe_status():
    html = generate_html_report('project', 'web-prod', 'job-42', **SCENARIOS['sample findings only'])
    item = html[html.index('<strong>Project IAM Hygiene</strong>'):]
    assert item.index('<span class="status-badge">Action Required</span>') < item.index('</li>')
    assert "<td>web-prod</td><td>user:alice@example.com</td><td>roles/owner</td>" in item  # both records' details
    assert "<td>data-lake</td><td>allUsers</td><td>roles/viewer</td>" in item


def test_report_is_self_contained():
    """Stored reports are served as-is long after the scan: no template syntax left, CSS and JS inline,
    and the only calls back to the app are the three /api/get-* endpoints (plus the CSV download link)."""
    html = generate_html_report('organization', '123456789', 'job-42', **SCENARIOS['sample scan'])
    for delimiter in ('{{', '{%', '{#'):
        assert delimiter not in html
    assert '<script src=' not in html and 'rel="stylesheet"' in html  # the Google Fonts link, as before
    handlers = {'showSection', 'toggleSubSection', 'getGeminiSuggestions', 'generateAiSummary', 'fetchInsights',
                'renderTablePage'}  # renderTablePage is in HTML built by the script
    assert set(re.findall(r'onclick="(\w+)\(', html)) == handlers
    paging = {'showMoreRows', 'showAllRows'}  # only emitted under tables longer than one page
    long_table = {SECURITY: [{'Check': 'Public Buckets', 'Status': 'Action Required',
                              'Finding': [{'Project': 'p1', 'Bucket': f'b{i}'} for i in range(ROWS_PER_PAGE + 10)]}]}
    assert paging <= set(re.findall(r'onclick="(\w+)\(', generate_html_report('project', 'p1', 'job-42', **long_table)))
    for handler in handlers | paging | {'scheduleRowFilter', 'applyRowFilter', 'sortTable'}:  # defined in the inlined script
        assert re.search(rf'function {handler}\(', html), handler
    assert sorted(set(re.findall(r"fetch\('([^']+)'", html))) == ['/api/get-insights', '/api/get-suggestions', '/api/get-summary']
    assert 'JSON.stringify({ scope_id: "123456789", job_id: "job-42" })' in html
    assert 'JSON.stringify({ scope: "organization", scope_id: "123456789" })' in html


# --- Layout for large organizations (plan item 6b) ---

def table_check(name, rows, status='Action Required'):
    return {'Check': name, 'Status': status, 'Finding': rows}


def check_names(html):
    """Check titles in page order (a bare <strong> regex would also match strings in the inlined script)."""
    return re.findall(r'<div class="check-content">\s*<strong>([^<]+)</strong>', html)


def detail_tables(html):
    """The details tables only: the page also has the Review Scores table and <tr> strings in the script."""
    return re.findall(r"<table class='details-table'>.*?</table>", html)


def test_checks_are_ordered_by_severity_then_name():
    results = {SECURITY: [
        {'Check': 'B Compliant', 'Status': 'Compliant', 'Finding': 'ok'},
        {'Check': 'A Compliant', 'Status': 'Compliant', 'Finding': 'ok'},
        {'Check': 'Z Error', 'Status': 'Error', 'Finding': [{'Error': 'quota'}]},
        {'Check': 'M Investigation', 'Status': 'Investigation Recommended', 'Finding': 'look'},
        {'Check': 'Y Action', 'Status': 'Action Required', 'Finding': 'fix'},
        {'Check': 'A Action', 'Status': 'Action Required', 'Finding': 'fix'},
        {'Check': 'N Informational', 'Status': 'Informational', 'Finding': 'fyi'},
    ]}
    html = generate_html_report('project', 'p1', 'job-42', **results)
    assert check_names(html) == ['A Action', 'Y Action', 'M Investigation', 'Z Error', 'N Informational', 'A Compliant', 'B Compliant']
    assert re.search(r'<div class="section-counts">\s*<span class="count-action-required">2 Action Required</span>\s*'
                     r'<span class="count-investigation">1 Investigation Recommended</span>\s*<span class="count-error">1 Error</span>\s*'
                     r'<span class="count-informational">1 Informational</span>\s*<span class="count-compliant">2 Compliant</span>', html)


def summaries(html):
    return [(name, unescape(summary)) for name, summary in
            re.findall(r'<strong>([^<]+)</strong>\s*<div class="check-summary">([^<]+)</div>', html)]


def test_check_summary_counts_findings_and_projects():
    rows = [{'Project': f'p{i % 4}', 'Bucket': f'b{i}'} for i in range(10)]
    results = {SECURITY: [table_check('Public Buckets', rows),
                          table_check('One Row', [{'Project': 'p9', 'Bucket': 'b'}]),
                          table_check('No Project Column', [{'Rule': 'r1'}, {'Rule': 'r2'}]),
                          table_check('Broken', [{'Error': 'quota exceeded'}], status='Error'),
                          table_check('Shard Errors', [{'Error': 'a'}, {'Error': 'b'}], status='Error'),
                          {'Check': 'Text Details', 'Status': 'Action Required', 'Finding': ['line 1', 'line 2']}]}
    # The share of projects needs the scope's total. Single-row tables without a project column and text details get no line.
    html = generate_html_report('organization', '123', 'job-42', total_projects=1000, **results)
    assert dict(summaries(html)) == {'Public Buckets': '10 findings across 4 of 1,000 projects (<1%)',
                                     'One Row': '1 finding across 1 of 1,000 projects (<1%)',
                                     'No Project Column': '2 findings', 'Shard Errors': '2 errors'}
    html = generate_html_report('organization', '123', 'job-42', total_projects=5, **results)
    assert dict(summaries(html))['Public Buckets'] == '10 findings across 4 of 5 projects (80%)'
    # Without the total: no share.
    html = generate_html_report('organization', '123', 'job-42', **results)
    assert dict(summaries(html))['Public Buckets'] == '10 findings across 4 projects'
    # A project scan: its rows are all in the one project, so no project phrase at all.
    one_project = [{'Project': 'p1', 'Bucket': f'b{i}'} for i in range(10)]
    html = generate_html_report('project', 'p1', 'job-42', total_projects=1, **{SECURITY: [table_check('Public Buckets', one_project)]})
    assert dict(summaries(html))['Public Buckets'] == '10 findings'


def test_rows_past_the_first_page_are_hidden_until_asked_for():
    rows = [{'Project': 'p1', 'Bucket': f'b{i}'} for i in range(ROWS_PER_PAGE + 10)]
    html = generate_html_report('project', 'p1', 'job-42', **{SECURITY: [table_check('Public Buckets', rows)]})
    [table] = detail_tables(html)
    assert table.count('<tr>') == ROWS_PER_PAGE + 1 and table.count('<tr hidden>') == 10  # +1: the header row
    assert 'Showing <span class="shown-count">50</span> of 60 rows' in html
    assert 'onclick="showMoreRows(this)">Show 50 more</button>' in html and 'onclick="showAllRows(this)">Show all</button>' in html
    assert f'const ROWS_PER_PAGE = {ROWS_PER_PAGE};' in html
    # A table that fits on one page has no controls and keeps the plain markup.
    small = generate_html_report('project', 'p1', 'job-42', **{SECURITY: [table_check('Public Buckets', rows[:3])]})
    assert 'class="table-controls"' not in small and '<tr hidden>' not in small


def test_rows_are_capped_in_the_page_but_not_in_the_csv():
    rows = [{'Project': f'p{i % 700}', 'Bucket': f'b{i}'} for i in range(MAX_ROWS_PER_CHECK + 100)]
    results = {SECURITY: [table_check('Public Buckets', rows), table_check('Small', rows[:5])]}
    html = generate_html_report('organization', '123', 'job-42', total_projects=1000, **results)
    big, small = detail_tables(html)
    assert big.count('<tr') == 1 + MAX_ROWS_PER_CHECK and small.count('<tr') == 1 + 5  # +1: the header rows
    assert 'b1999' in big and 'b2000' not in html
    assert ('Only the first 2,000 of 2,100 rows are included in this page. The complete list is in the '
            '<a href="/report/job-42/123/csv">CSV report</a>.') in html
    assert html.count('class="table-note"') == 1  # the small table has no note
    assert dict(summaries(html))['Public Buckets'] == '2,100 findings across 700 of 1,000 projects (70%)'  # over all rows
    assert generate_csv_data(results).count('Public Buckets,Action Required,') == MAX_ROWS_PER_CHECK + 100


def test_toolbar_has_the_filter_and_the_csv_download():
    html = generate_html_report('organization', '123456789', 'job-42', **SCENARIOS['sample scan'])
    assert '<input id="row-filter" type="search"' in html and 'oninput="scheduleRowFilter()"' in html
    assert '<a class="toolbar-link" href="/report/job-42/123456789/csv">Download CSV (all rows)</a>' in html
    # The link is a URL: IDs are percent-encoded, not just HTML-escaped.
    html = generate_html_report('project', 'a b/c?d', 'job 1', **SCENARIOS['sample scan'])
    assert 'href="/report/job%201/a%20b%2Fc%3Fd/csv"' in html


def test_filter_box_is_hidden_on_the_overview():
    """The filter acts on a category page's checks; the Overview has none, so only the CSV link shows there."""
    html = generate_html_report('organization', '123456789', 'job-42', **SCENARIOS['sample scan'])
    assert '<div class="report-toolbar no-filter">' in html  # the Overview is the page shown first
    assert '.report-toolbar.no-filter #row-filter, .report-toolbar.no-filter #filter-status { display: none; }' in html
    assert "toolbar.classList.toggle('no-filter', !(targetSection && targetSection.querySelector('.checks-list')))" in html
    overview = re.search(r'<div id="overview-section" class="content-section">(.*?)<div id="[\w-]+-section" class="content-section"', html, re.S).group(1)
    assert 'checks-list' not in overview and html.count('class="checks-list"') == 4  # one per category page


def test_finding_text_is_escaped():
    """Plan item B3: finding text is inserted as text (the legacy report inserted it as raw HTML)."""
    html = generate_html_report('organization', '123456789', 'job-42', **SCENARIOS['html in findings'])
    assert 'Rule &lt;b&gt;allow-all&lt;/b&gt; &amp; &#34;default&#34; open to 0.0.0.0/0' in html
    assert '<td>&lt;script&gt;alert(1)&lt;/script&gt;</td><td>roles/owner&#39;s</td>' in html
    assert '<script>alert(1)' not in html and '<b>allow-all' not in html
    # The status icons are character references written once, not escaped a second time.
    assert '<span class="icon">&#10007;</span>' in html and '&amp;#' not in html


def test_text_details_keep_their_line_breaks():
    """Text details are joined with <br> tags; only the lines themselves are escaped."""
    results = {SECURITY: [{'Check': 'Open Firewall Rules', 'Status': 'Action Required', 'Finding': 'a <i>'},
                          {'Check': 'Open Firewall Rules', 'Status': 'Action Required', 'Finding': 'b & c'}]}
    html = generate_html_report('project', 'p1', 'job-42', **results)
    assert '<div class="details">a &lt;i&gt;<br>b &amp; c</div>' in html


@pytest.mark.parametrize('scope_id', ["o'brien\\", '</script><script>alert(1)</script>', 'a"b'])
def test_script_values_are_json_strings(scope_id):
    """IDs in the inline script can't end the string (quote, trailing backslash) or the <script> element."""
    html = generate_html_report('project', scope_id, 'job-42', **SCENARIOS['sample scan'])
    match = re.search(r'JSON\.stringify\(\{ scope_id: (.*), job_id: "job-42" \}\)', html)
    embedded = match.group(1)
    assert json.loads(embedded) == scope_id
    assert '<' not in embedded and "'" not in embedded  # tojson writes \u003c and \u0027
    assert html.count('</script>') == 1  # only the report's own script element ends
    match = re.search(r'JSON\.stringify\(\{ scope: "project", scope_id: (.*) \}\)', html)
    assert json.loads(match.group(1)) == scope_id


def test_report_environment_rejects_undefined_variables():
    """A misspelled template variable fails the render instead of printing nothing."""
    with pytest.raises(UndefinedError):
        report_environment().from_string('{{ scope_idd }}').render(scope_id='42')
