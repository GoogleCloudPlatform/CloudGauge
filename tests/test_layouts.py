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
"""``app.reporting.layouts`` and the report markup it drives (v14.1, restyled in v14.2).

Three things the screenshots of v14 showed were wrong, and what replaced them:
a ``Fix`` column crammed next to the finding (now one remediation block under
the table, so every failing finding gets exactly one: the check's own, or
Gemini's on request); ten incident columns and five notification columns
breaking mid-word (now six and four readable ones, short columns on one line,
long lists and messages behind a disclosure or a three-line clamp); and data
cut before it reached the page (now whole in the page and the CSV).

v14.2 added column roles: every column renders by what it holds (a resource is
a monospace chip, a number is right-aligned mono, a time is mono, a state stays
on one line, prose wraps), so all findings tables read the same way.
"""
import re

from app.checks.advisories import ADVISORIES_CHECK
from app.checks.service_health import COVERAGE_CHECK, INCIDENTS_CHECK
from app.reporting.csv_report import generate_csv_data
from app.reporting.html_report import generate_html_report
from app.reporting.layouts import (CLAMP_TOGGLE_LENGTH, COLUMN_ROLES, INCIDENT_HEADERS, INLINE_LINES, INLINE_LIST_ITEMS,
                                   MAX_DISCLOSED_ITEMS, MAX_FIX_LINES, MIN_COLUMNS_FOR_NOWRAP, NOTIFICATION_HEADERS, NUMBER, PROSE,
                                   RESOURCE, RESOURCE_LIST, ROLE_CSS, SHORT_VALUE_LENGTH, STATE, TABLE_LAYOUTS, TIME, Cell, article,
                                   chips, column_role, counted, fix_lines, generic_layout, lay_out, listed, role_cell, without_column)
from helpers import report_facts

SECURITY, RELIABILITY = 'Security & Identity', 'Reliability & Resilience'

ACTIVE = {'State': 'Active (confirmed)', 'Started': '2026-09-20 10:00', 'Ended': '', 'Incident': 'Cloud Run latency in us-central1',
          'Products': 'Cloud Run', 'Locations': 'us-central1, us-east1', 'Impacted projects': 4, 'Project IDs': 'p-1, p-2, p-3, p-4',
          'Relevance': 'Impacted', 'Incident ID': 'JZBYGFV'}
RESOLVED = {**ACTIVE, 'State': 'Resolved', 'Ended': '2026-09-20 12:30', 'Incident': 'Cloud SQL connectivity', 'Products': 'Cloud SQL, Cloud Run',
            'Locations': ', '.join(f'region-{i}' for i in range(5)), 'Impacted projects': 1, 'Project IDs': 'p-9', 'Relevance': 'Related',
            'Incident ID': 'A1B2C3'}
MSA = {'Date': '2026-09-28', 'Type': 'Mandatory Service Announcement', 'Subject': 'MSA: move off TLS 1.0',
       'Summary': 'Google will stop accepting TLS 1.0.\nAct now.',
       'Details': '4 affected resource rows (instances.csv)\nProject: p-1; Instance: sql-0\nProject: p-2; Instance: sql-1\n'
                  'Project: p-3; Instance: sql-2\nProject: p-4; Instance: sql-3'}
LONG_BODY = 'Hello Google Cloud customer,\n' + 'We are writing to let you know about a change to the product you use. ' * 4
ADVISORY = {'Date': '2026-09-01', 'Type': 'Security & Privacy Advisory', 'Subject': 'Security advisory: CVE-2026-0101',
            'Summary': LONG_BODY, 'Details': ''}
COVERAGE_ROWS = [{'Project': p, 'Issue': 'The Service Health API is not enabled, so its incidents are not personalized for this project.',
                  'Fix': f'gcloud services enable servicehealth.googleapis.com --project={p}'} for p in ('p-2', 'p-3')]


def tables(html):
    """The details tables (a laid-out cell may hold a newline, so the match spans lines)."""
    return re.findall(r"<table class='data-table details-table'>.*?</table>", html, re.S)


def item(html, name):
    """The markup of the check item titled ``name``: the accordion from its summary row to its closing tag."""
    return re.search(rf'<li class="status-[\w-]+" id="[\w-]+">\s*<details class="check"(?: open)?>\s*<summary>\s*<svg class="chevron"[^>]*><path [^>]*/></svg>\s*'
                     rf'<span class="dot dot-[\w-]+" aria-hidden="true"></span>\s*<span class="check-title"><strong>{re.escape(name)}</strong>'
                     r'.*?</details>\s*</li>', html, re.S).group(0)


# --- Generic rules ---

def test_short_columns_of_a_wide_table_never_wrap():
    """A column whose values are all short stays on one line, but only in a table wide enough to be squeezed;
    in a narrower table a prose column wraps as usual. (Resource, number, time and state cells stay on one line
    by role whatever the table's width: test_every_column_renders_by_its_role.)"""
    headers = ('Project', 'Rule Name', 'VPC', 'Reason')
    rows = (('p-1', 'allow-all', 'default', 'open'), ('p-2', 'allow-ssh', 'default', 'open'))
    display, cells = generic_layout(headers, rows)
    assert display == headers and len(headers) >= MIN_COLUMNS_FOR_NOWRAP
    assert [[cell.nowrap for cell in row] for row in cells] == [[True, True, True, True]] * 2  # every value is short
    assert cells[0][0] == Cell('text', 'p-1', nowrap=True, css='code') and cells[0][3] == Cell('text', 'open', nowrap=True, css='prose')
    long_reason = (rows[0], ('p-2', 'allow-ssh', 'default', 'open to the whole internet on every port'))
    _, cells = generic_layout(headers, long_reason)
    assert [[cell.nowrap for cell in row] for row in cells] == [[True, True, True, False]] * 2  # one long reason: the column wraps
    assert all(len(v) <= SHORT_VALUE_LENGTH for row in rows for v in row) and len(long_reason[1][3]) > SHORT_VALUE_LENGTH
    _, narrow = generic_layout(headers[1:], tuple(row[1:] for row in rows))  # three columns: never squeezed, so no generic rule
    assert [[cell.nowrap for cell in row] for row in narrow] == [[True, True, False]] * 2  # the resource cells by role, the prose wraps
    assert Cell('text', 'x').classes == '' and Cell('text', 'x', nowrap=True).classes == 'nowrap'
    assert Cell('text', 'x', nowrap=True, css='state state-active').classes == 'nowrap state state-active'


def test_every_column_renders_by_its_role():
    """A column's header gives its role (the names the checks use); an unknown header is judged by its values."""
    assert {column_role(h) for h in ('Project', 'Principal', 'Instance', 'Bucket', 'Rule Name', 'Incident ID', 'Policy')} == {RESOURCE}
    assert {column_role(h) for h in ('Projects', 'Project IDs', 'Locations', 'Standalone VMs', 'Source Ranges')} == {RESOURCE_LIST}
    assert {column_role(h) for h in ('Usage', 'Est. Monthly Saving', 'Impacted projects', 'Retention')} == {NUMBER}
    assert {column_role(h) for h in ('Date', 'When (UTC)', 'Started', 'Ended')} == {TIME}
    assert {column_role(h) for h in ('Status', 'State', 'Relevance', 'Type', 'Expected Value', 'Current Value')} == {STATE}
    assert {column_role(h) for h in ('Issue', 'Reason', 'Recommendation', 'Summary', 'Incident', 'Products', 'Skipped check')} == {PROSE}
    assert all(column_role(h) == role for h, role in COLUMN_ROLES.items())
    # Unknown headers: identifiers (a separator, no spaces) or digits are a resource; amounts, counts and shares a number; else prose.
    assert column_role('Sink', ('sink-1', 'logs@p.iam.gserviceaccount.com', '12345')) == RESOURCE
    assert column_role('Cost', ('$412.00', '1,204', '91.3%', '-3')) == NUMBER
    assert column_role('Note', ('sink-1', 'two words')) == PROSE and column_role('Empty', ('', None)) == PROSE
    # The cell: the role's class, and on one line for the roles that never wrap unless the value is long.
    assert ROLE_CSS == {RESOURCE: 'code', RESOURCE_LIST: 'code', NUMBER: 'num', TIME: 'time', STATE: 'state', PROSE: 'prose'}
    assert role_cell(RESOURCE, 'ci-builder@p.iam.gserviceaccount.com') == Cell('text', 'ci-builder@p.iam.gserviceaccount.com', nowrap=True, css='code')
    assert role_cell(RESOURCE, 'x' * (SHORT_VALUE_LENGTH * 2 + 1)).nowrap is False  # a long principal or path may wrap
    assert role_cell(NUMBER, '91.3%') == Cell('text', '91.3%', nowrap=True, css='num') and role_cell(TIME, '2026-09-20').css == 'time'
    assert role_cell(STATE, 'Active (confirmed)').nowrap is True and role_cell(PROSE, 'short').nowrap is False
    assert role_cell(PROSE, 'short', nowrap=True).nowrap is True  # the generic short-column rule still applies to prose


def test_chips_list_a_few_resources_inline_and_many_behind_a_count():
    assert chips(['a', 'b', 'c']) == Cell('chips', lines=('a', 'b', 'c'), css='code') and len(['a', 'b', 'c']) == INLINE_LIST_ITEMS
    assert chips(['a', 'b', 'c', 'd'], 'projects') == Cell('chips', text='4 projects', lines=('a', 'b', 'c', 'd'), css='code')
    capped = chips([f'p-{i}' for i in range(MAX_DISCLOSED_ITEMS + 50)], 'projects')
    assert capped.text == '250 projects' and len(capped.lines) == MAX_DISCLOSED_ITEMS and capped.body == '… and 50 more (all in the CSV)'
    assert role_cell(RESOURCE_LIST, 'web-prod, data-lake', 'Projects') == Cell('chips', lines=('web-prod', 'data-lake'), css='code')
    assert role_cell(RESOURCE_LIST, '', 'Projects') == Cell('chips', css='code')  # an empty cell: no chips
    assert role_cell(RESOURCE_LIST, 'vm-1, vm-2, vm-3, vm-4', 'Standalone VMs').text == '4 VMs'
    assert role_cell(RESOURCE_LIST, 'a, b, c, d', 'Ports').text == '4 ports' and role_cell(RESOURCE_LIST, 'a, b, c, d', 'New Column').text == '4 items'


def test_the_fix_column_becomes_the_remediation_lines():
    headers, rows = ('Project', 'Issue', 'Fix'), (('p-1', 'off', 'enable it'), ('p-2', 'off', 'enable it'), ('p-3', 'off', 'enable it twice'), ('p-4', 'off', ''))
    assert fix_lines(headers, rows) == ('enable it', 'enable it twice')  # distinct, in row order, blanks dropped
    assert fix_lines(('Project', 'Issue'), rows) == ()
    assert without_column(headers, rows, 'Fix') == (('Project', 'Issue'), (('p-1', 'off'), ('p-2', 'off'), ('p-3', 'off'), ('p-4', 'off')))
    assert without_column(headers, rows, 'Nope') == (headers, rows)
    many = tuple((f'p-{i}', 'off', f'fix {i}') for i in range(MAX_FIX_LINES + 5))
    lines = fix_lines(headers, many)
    assert len(lines) == MAX_FIX_LINES + 1 and lines[-1] == '… and 5 more (all in the CSV)'
    display, cells, fixes = lay_out('Any Check', headers, rows, [dict(zip(headers, row)) for row in rows])
    assert display == ('Project', 'Issue') and fixes == ('enable it', 'enable it twice')
    assert [[cell.text for cell in row] for row in cells][:2] == [['p-1', 'off'], ['p-2', 'off']]


def test_counted_lists_and_messages():
    assert counted(['a', 'b', 'c'], 'projects') == Cell('text', 'a, b, c') and len(['a', 'b', 'c']) == INLINE_LIST_ITEMS
    four = counted(['a', 'b', 'c', 'd'], 'projects')
    assert four == Cell('disclose', text='4 projects', body='a, b, c, d')
    capped = counted([f'p-{i}' for i in range(MAX_DISCLOSED_ITEMS + 50)], 'projects')
    assert capped.text == '250 projects' and capped.body.endswith(f'p-{MAX_DISCLOSED_ITEMS - 1} … and 50 more (all in the CSV)')
    assert listed(['x', '', 'y']) == Cell('list', lines=('x', 'y'))
    five = listed([f'line {i}' for i in range(5)])
    assert five.lines == ('line 0', 'line 1', 'line 2') and five.more == ('2 more', ('line 3', 'line 4')) and len(five.lines) == INLINE_LINES
    assert article('t', 'short') == Cell('article', text='t', body='short')  # no toggle: it cannot be clamped
    assert article('t', 'x' * (CLAMP_TOGGLE_LENGTH + 1)).more == ('Show full message', 'Show less')
    assert article('t', 'one\ntwo\nthree\nfour').more == ('Show full message', 'Show less')  # four lines: the fourth is clamped


# --- The briefings' layouts ---

def test_incident_rows_become_six_display_columns():
    assert set(TABLE_LAYOUTS) == {INCIDENTS_CHECK, ADVISORIES_CHECK}
    headers = tuple(ACTIVE)
    display, (active, resolved), fixes = lay_out(INCIDENTS_CHECK, headers, (tuple(map(str, ACTIVE.values())),), [ACTIVE, RESOLVED])
    assert display == INCIDENT_HEADERS == ('State', 'When (UTC)', 'Incident', 'Products', 'Projects', 'Relevance') and fixes == ()
    assert active[0] == Cell('text', 'Active (confirmed)', nowrap=True, css='state state-active') and resolved[0] == Cell('text', 'Resolved', nowrap=True, css='state')
    assert active[1] == Cell('stack', lines=('2026-09-20 10:00', '→ ongoing'), nowrap=True, css='time')
    assert resolved[1].lines == ('2026-09-20 10:00', '→ 2026-09-20 12:30')
    # The incident: title, the locations (listed when three or fewer, else behind "5 locations"), and the ID on its own mono line.
    assert active[2] == Cell('rich', text='Cloud Run latency in us-central1', secondary='us-central1, us-east1', code='JZBYGFV', css='prose')
    assert resolved[2] == Cell('rich', text='Cloud SQL connectivity', more=('5 locations', 'region-0, region-1, region-2, region-3, region-4'),
                               code='A1B2C3', css='prose')
    assert active[3] == Cell('text', 'Cloud Run', css='prose') and resolved[3].text == 'Cloud SQL, Cloud Run'
    assert active[4] == Cell('chips', text='4 projects', lines=('p-1', 'p-2', 'p-3', 'p-4'), css='code') and resolved[4] == Cell('chips', lines=('p-9',), css='code')
    assert active[5] == Cell('text', 'Impacted', nowrap=True, css='state') and resolved[5].text == 'Related'
    # A note or an error table has none of the incident columns: the generic layout applies.
    assert lay_out(INCIDENTS_CHECK, ('Summary',), (('No incidents.',),), [{'Summary': 'No incidents.'}])[0] == ('Summary',)
    assert lay_out(INCIDENTS_CHECK, ('Error',), (('403',),), [{'Error': '403'}])[1] == ((Cell('text', '403', css='prose'),),)


def test_notification_rows_become_four_display_columns_plus_projects_when_scanned_per_project():
    headers = tuple(MSA)
    display, (msa, advisory), _ = lay_out(ADVISORIES_CHECK, headers, (), [MSA, ADVISORY])
    assert display == NOTIFICATION_HEADERS == ('Date', 'Type', 'Notification', 'Details')
    assert msa[:2] == (Cell('text', '2026-09-28', nowrap=True, css='time'), Cell('text', 'Mandatory Service Announcement', css='state'))
    assert msa[2] == Cell('article', text='MSA: move off TLS 1.0', body='Google will stop accepting TLS 1.0.\nAct now.')
    assert msa[3].lines == ('4 affected resource rows (instances.csv)', 'Project: p-1; Instance: sql-0', 'Project: p-2; Instance: sql-1')
    assert msa[3].more == ('2 more', ('Project: p-3; Instance: sql-2', 'Project: p-4; Instance: sql-3'))
    assert advisory[2].more == ('Show full message', 'Show less') and advisory[2].body.startswith('Hello Google Cloud customer,\n')
    assert advisory[3] == Cell('list')  # nothing attached: an empty list
    with_projects = {'Projects': 'web-prod, data-lake, api, batch', **MSA}
    display, (row,), _ = lay_out(ADVISORIES_CHECK, tuple(with_projects), (), [with_projects])
    assert display == NOTIFICATION_HEADERS + ('Projects',) and row[4] == Cell('chips', text='4 projects', lines=('web-prod', 'data-lake', 'api', 'batch'), css='code')
    assert lay_out(ADVISORIES_CHECK, ('Summary',), (('none',),), [{'Summary': 'none'}])[0] == ('Summary',)


# --- The report ---

def test_a_check_that_knows_its_fix_shows_it_under_the_table_not_in_a_column():
    """Option C (report_layout_review): the Fix column is not a column. Its distinct values are one remediation
    block under the table, where Gemini's suggestion goes for the checks without one; the CSV keeps the column."""
    results = {RELIABILITY: [{'Check': COVERAGE_CHECK, 'Status': 'Action Required', 'Finding': COVERAGE_ROWS},
                             {'Check': 'Essential Contacts', 'Status': 'Action Required',
                              'Finding': [{'Missing Categories': 'LEGAL, SUSPENSION', 'Issue': 'No contact for these categories.',
                                           'Fix': 'gcloud essential-contacts create --organization=123 --email=<address> --notification-categories=LEGAL,SUSPENSION'}]},
                             {'Check': 'Cloud SQL PITR', 'Status': 'Action Required', 'Finding': [{'Project': 'p-1', 'Instance': 'sql-0', 'Issue': 'PITR is off'}]}]}
    html = generate_html_report('organization', '123', 'job-42', **results)
    coverage = item(html, COVERAGE_CHECK)
    assert '<th>Project</th><th>Issue</th></tr>' in coverage and '<th>Fix</th>' not in html
    assert ('<div class="fix-block"><div class="fix-head"><strong>Fix</strong>'
            '<button type="button" class="btn btn-outline btn-sm copy-btn" onclick="copyFix(this)">Copy</button></div>'
            '<pre>gcloud services enable servicehealth.googleapis.com --project=p-2\n'
            'gcloud services enable servicehealth.googleapis.com --project=p-3</pre></div>') in coverage
    assert coverage.index('class="fix-block"') < coverage.index("class='remediation-placeholder'")  # the placeholder stays for the script
    contacts = item(html, 'Essential Contacts')
    assert '<pre>gcloud essential-contacts create --organization=123 --email=&lt;address&gt; --notification-categories=LEGAL,SUSPENSION</pre>' in contacts
    assert 'fix-block' not in item(html, 'Cloud SQL PITR')  # no Fix column: Gemini's box only
    assert html.count('class="fix-block"') == 2
    # The page's facts still carry every finding; the CSV keeps the Fix column.
    facts = {name: (headers, rows) for name, _, headers, rows, _, _ in report_facts(html)['items']}
    assert facts[COVERAGE_CHECK] == (('Project', 'Issue'), tuple((row['Project'], row['Issue']) for row in COVERAGE_ROWS))
    csv = generate_csv_data(results)
    assert 'Check,Status,Project,Issue,Fix\r\n' in csv and csv.count('--project=p-') == 2
    # The script asks Gemini only for the checks without a fix-block, and labels what it adds like a built-in Fix.
    assert "if (listItem.querySelector('.fix-block')) { alreadyFixed++; return; }" in html
    assert 'btn.textContent = alreadyFixed ? "Every finding already shows its fix" : "No failing findings";' in html
    assert '<strong>Suggested fix</strong> <span class="pill pill-sky">AI-generated</span>' in html


def test_incident_table_markup():
    html = generate_html_report('organization', '123', 'job-42', **{RELIABILITY: [{'Check': INCIDENTS_CHECK, 'Status': 'Informational', 'Finding': [ACTIVE, RESOLVED]}]})
    [table] = tables(html)
    assert table.startswith("<table class='data-table details-table'><thead><tr><th>State</th><th>When (UTC)</th><th>Incident</th><th>Products</th>"
                            "<th>Projects</th><th>Relevance</th></tr></thead><tbody>")
    assert ('<tr><td class="nowrap state state-active">Active (confirmed)</td><td class="nowrap time">2026-09-20 10:00<br><span class="muted">→ ongoing</span></td>'
            '<td class="prose"><span class="cell-title">Cloud Run latency in us-central1</span><span class="cell-secondary">us-central1, us-east1'
            '<code class="cell-code">JZBYGFV</code></span></td><td class="prose">Cloud Run</td>'
            '<td class="code"><details class="cell-more"><summary>4 projects</summary><span class="more-body chip-list"><code class="chip">p-1</code> '
            '<code class="chip">p-2</code> <code class="chip">p-3</code> <code class="chip">p-4</code></span></details></td>'
            '<td class="nowrap state">Impacted</td></tr>') in table
    assert ('<tr><td class="nowrap state">Resolved</td><td class="nowrap time">2026-09-20 10:00<br><span class="muted">→ 2026-09-20 12:30</span></td>'
            '<td class="prose"><span class="cell-title">Cloud SQL connectivity</span><span class="cell-secondary"><details class="cell-more"><summary>5 locations</summary>'
            '<span class="more-body">region-0, region-1, region-2, region-3, region-4</span></details><code class="cell-code">A1B2C3</code></span></td>'
            '<td class="prose">Cloud SQL, Cloud Run</td><td class="code"><code class="chip">p-9</code></td><td class="nowrap state">Related</td></tr>') in table
    # What the page says is the raw data, flattened: nothing was cut on the way.
    (_, _, headers, rows, _, _), = report_facts(html)['items']
    assert headers == INCIDENT_HEADERS
    assert rows[0] == ('Active (confirmed)', '2026-09-20 10:00 → ongoing', 'Cloud Run latency in us-central1 us-central1, us-east1 JZBYGFV', 'Cloud Run',
                       '4 projects p-1 p-2 p-3 p-4', 'Impacted')
    assert '.details-table .state-active { color: var(--rose-700); font-weight: 500; }' in html
    assert '.details-table .cell-code { display: block; margin-top: 2px; font-family: var(--font-mono);' in html


def test_notification_table_markup():
    html = generate_html_report('organization', '123', 'job-42', **{SECURITY: [{'Check': ADVISORIES_CHECK, 'Status': 'Informational', 'Finding': [MSA, ADVISORY]}]})
    [table] = tables(html)
    assert table.startswith("<table class='data-table details-table'><thead><tr><th>Date</th><th>Type</th><th>Notification</th><th>Details</th></tr></thead><tbody>")
    assert ('<tr><td class="nowrap time">2026-09-28</td><td class="state">Mandatory Service Announcement</td>'
            '<td><span class="cell-title">MSA: move off TLS 1.0</span><div class="clamp">Google will stop accepting TLS 1.0.\nAct now.</div></td>'
            '<td><ul class="cell-list"><li>4 affected resource rows (instances.csv)</li><li>Project: p-1; Instance: sql-0</li><li>Project: p-2; Instance: sql-1</li></ul>'
            '<details class="cell-more"><summary>2 more</summary><ul class="cell-list more-body"><li>Project: p-3; Instance: sql-2</li><li>Project: p-4; Instance: sql-3</li></ul></details></td></tr>') in table
    # A long message: clamped to three lines from its first line (the salutation), with the toggle; the whole text is in the page.
    assert (f'<td><span class="cell-title">Security advisory: CVE-2026-0101</span><div class="clamp">{LONG_BODY}</div>'
            '<button class="link-btn clamp-toggle" type="button" onclick="toggleClamp(this)" data-more="Show full message" data-less="Show less" aria-expanded="false"></button></td>'
            '<td></td></tr>') in table  # nothing attached: an empty cell
    assert '.details-table .clamp { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; white-space: pre-line;' in html
    assert '.clamp-toggle::after { content: attr(data-more); }' in html and '.clamp.open + .clamp-toggle::after { content: attr(data-less); }' in html
    assert 'function toggleClamp(toggle)' in html and 'const CLAMP_MIN_CHARS = 200;' in html and 'settleClamps(targetSection);' in html


def test_cells_wrap_at_word_boundaries_and_wide_tables_scroll():
    """The legacy ``word-break: break-all`` split "Resolved" and incident IDs mid-word once a table was squeezed."""
    html = generate_html_report('project', 'p1', 'job-42', **{SECURITY: [{'Check': 'Open Firewall Rules', 'Status': 'Action Required',
                                                                           'Finding': [{'Project': 'p1', 'Rule Name': 'allow-all', 'VPC': 'default', 'Source': '0.0.0.0/0'}]}]})
    assert ('.data-table td { padding: 6px 12px; border-bottom: 1px solid var(--rule); text-align: left; vertical-align: top; color: var(--body); '
            'line-height: 1.45; word-break: normal; overflow-wrap: break-word; }') in html
    assert 'break-all' not in html and '.check-content .details { overflow-x: auto; }' in html and '.details-table td.nowrap { white-space: nowrap; }' in html
    assert '.data-table td.prose { min-width: 22ch; max-width: 64ch; }' in html  # prose never squeezed to a word a line
    assert ('<tr><td class="nowrap code"><code class="chip">p1</code></td><td class="nowrap code"><code class="chip">allow-all</code></td>'
            '<td class="nowrap code"><code class="chip">default</code></td><td class="nowrap code"><code class="chip">0.0.0.0/0</code></td></tr>') in html


def test_chips_never_break_inside_a_token():
    """A chip is one token (``white-space: nowrap``), so ``stark-argolis`` never splits at its hyphen; only a value longer than
    40 characters (a long principal, a resource path) gets ``chip-long`` and may wrap, at any character."""
    long_principal = 'serviceAccount:deployer@stark-nw-prod.iam.gserviceaccount.com'
    results = {SECURITY: [{'Check': 'Primitive Roles', 'Status': 'Action Required',
                           'Finding': [{'Project': 'stark-argolis', 'Principal': long_principal, 'Role': 'roles/owner'}]}]}
    html = generate_html_report('project', 'stark-argolis', 'job-42', **results)
    assert ('<td class="nowrap code"><code class="chip">stark-argolis</code></td>'
            f'<td class="code"><code class="chip chip-long">{long_principal}</code></td>'
            '<td class="nowrap code"><code class="chip">roles/owner</code></td>') in html and len(long_principal) > 40
    assert re.search(r'\.chip \{[^}]*white-space: nowrap;', html) and '.chip.chip-long { white-space: normal; overflow-wrap: anywhere; }' in html
