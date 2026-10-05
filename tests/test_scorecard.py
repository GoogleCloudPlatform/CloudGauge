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
"""The Scorecard page (v15.1): ``app.reporting.scorecard`` and what the report makes of it.

The first half builds scorecards from small scans and checks the model: the
stoplights' states follow the score bands the rest of the report uses, the
deltas and the since line come from the comparison with the previous scan,
the Top actions are ranked by status, projects, rows, and the footers name
what the table leaves out. The second half reads the rendered page the way a
reader would (the sidebar entry, the lamps, the table, the buttons), and the
two exports.
"""
import copy
import csv
import io
import json
import re

import pytest

import samples
from app.reporting.changes import summarize
from app.reporting.context import build_report_context
from app.reporting.html_report import generate_html_report, generate_reports, render_report
from app.reporting.scorecard import (ACTION_PLAN_COLUMNS, FIX_IN_REPORT, INLINE_STATUS_CHANGES, PILLARS, STATE, TOP_ACTIONS,
                                     action_plan_csv, action_plan_name, build_scorecard, markdown, scorecard_vars)

SCOPE, SCOPE_ID = 'organization', '123456789'
SECURITY, COST, RELIABILITY, OPERATIONS = ('Security & Identity', 'Cost Optimization', 'Reliability & Resilience',
                                           'Operational Excellence & Observability')
MINUS = '\u2212'


def check(name, status, finding):
    return {'Check': name, 'Status': status, 'Finding': finding}


def rows(n, project='p', **columns):
    """``n`` table rows, each in its own project unless ``project`` names one."""
    return [{'Project': f'{project}{i}' if project == 'p' else project, 'Resource': f'r{i}', **columns} for i in range(n)]


def context(results, job_id='job-2', previous=None, total_projects=4):
    return build_report_context(SCOPE, SCOPE_ID, job_id, results, total_projects=total_projects, previous=previous)


def card(results, **kwargs):
    return build_scorecard(context(results, **kwargs))


def two_scans(first, second):
    """The scorecard of ``second``, compared with a scan of ``first``."""
    return card(second, previous=summarize(context(first, 'job-1')))


def sample_results():
    return {**copy.deepcopy(samples.FINDINGS), 'Organization Policies': (copy.deepcopy(samples.BEST_PRACTICES), copy.deepcopy(samples.CURRENT_POLICIES))}


# --- Stoplights ---

def test_four_stoplights_in_the_playbook_order_each_over_one_category():
    lights = card({}).stoplights
    assert [(light.name, light.category) for light in lights] == list(PILLARS)
    assert [light.name for light in lights] == ['Stability', 'Security', 'Operations', 'Efficiency']
    assert [light.section_id for light in lights] == ['reliability-resilience', 'security-identity', 'operational-excellence-observability', 'cost-optimization']


@pytest.mark.parametrize('passing, failing, state, cls', [
    (10, 0, 'Healthy', 'high'), (91, 9, 'Healthy', 'high'),  # 100 and 91: above 90
    (9, 1, 'Needs attention', 'medium'), (71, 29, 'Needs attention', 'medium'),  # 90 and 71: above 70, not above 90
    (7, 3, 'At risk', 'low'), (0, 1, 'At risk', 'low'),  # 70 and 0
])
def test_the_state_follows_the_score_bands_the_score_bars_use(passing, failing, state, cls):
    results = {COST: [check(f'ok {i}', 'Compliant', 'fine') for i in range(passing)] + [check(f'bad {i}', 'Action Required', 'x') for i in range(failing)]}
    efficiency = card(results).stoplights[3]
    assert (efficiency.state, efficiency.score_class, efficiency.score_display) == (state, cls, f'{passing / (passing + failing) * 100:.0f}')
    assert STATE[cls] == state


def test_the_evidence_line_counts_checks_projects_and_incidents():
    results = {
        RELIABILITY: [check('Backups', 'Action Required', rows(3)), check('Snapshots', 'Investigation Recommended', rows(2, project='p0')),
                      check('Contacts', 'Compliant', 'set'), check('Projects not checked', 'Error', rows(2)),
                      check('Service Health Incidents', 'Informational', [
                          {'Title': 'GCE outage', 'State': 'CLOSED', 'Project': 'p0'}, {'Title': 'GKE outage', 'State': 'ACTIVE', 'Project': 'p1'}])],
        OPERATIONS: [check('Logs', 'Action Required', 'Logging is off.')],  # text details: no project count
        COST: [check('Disks', 'Compliant', 'none')],
    }
    stability, security, operations, efficiency = card(results).stoplights
    assert stability.evidence == '1 of 4 checks compliant · 3 projects with findings · 2 incidents impacted you in 90 days, 1 active'
    assert operations.evidence == '0 of 1 check compliant'  # text findings have no project column
    assert efficiency.evidence == '1 of 1 check compliant'
    assert security.evidence == '0 of 0 checks compliant'
    no_incidents = card({RELIABILITY: [check('Service Health Incidents', 'Informational', [])]}).stoplights[0]
    assert no_incidents.evidence == '0 of 0 checks compliant'  # an empty briefing is text details, so no tally


def test_the_evidence_line_counts_a_project_once_across_checks():
    results = {SECURITY: [check('Keys', 'Action Required', rows(2, project='web-prod')), check('Buckets', 'Action Required', rows(1, project='web-prod'))]}
    assert card(results).stoplights[1].evidence == '0 of 2 checks compliant · 1 project with findings'


def test_organization_policies_count_towards_security():
    light = card({'Organization Policies': (samples.BEST_PRACTICES, samples.CURRENT_POLICIES)}).stoplights[1]
    assert light.evidence == '1 of 4 checks compliant'  # samples: one of the four policies matches
    assert light.state == 'At risk'


def test_deltas_come_from_the_comparison_and_are_absent_on_a_first_scan():
    first = {COST: [check('Disks', 'Action Required', rows(2)), check('VMs', 'Action Required', rows(2))]}
    second = {COST: [check('Disks', 'Compliant', 'none'), check('VMs', 'Action Required', rows(2))]}
    efficiency = two_scans(first, second).stoplights[3]
    assert (efficiency.score_display, efficiency.delta_display, efficiency.delta_class) == ('50', '+50', 'up')
    worse = two_scans(second, first).stoplights[3]
    assert (worse.delta_display, worse.delta_class) == (f'{MINUS}50', 'down')
    same = two_scans(second, second).stoplights[3]
    assert (same.delta_display, same.delta_class) == ('\u2014', 'flat')
    assert card(second).stoplights[3].delta_display is None


# --- Top actions ---

def test_actions_rank_by_status_then_projects_then_rows_then_name():
    results = {
        SECURITY: [check('Beta', 'Action Required', rows(2)), check('Alpha', 'Action Required', rows(2)),
                   check('Wide', 'Action Required', rows(5)), check('Deep', 'Action Required', rows(9, project='p0')),
                   check('Later', 'Investigation Recommended', rows(50)), check('Fine', 'Compliant', 'ok'),
                   check('Broken', 'Error', 'boom'), check('FYI', 'Informational', 'note')],
    }
    actions = card(results).actions
    assert [(a.rank, a.check_name, a.projects, a.rows) for a in actions] == [
        (1, 'Wide', 5, 5), (2, 'Alpha', 2, 2), (3, 'Beta', 2, 2), (4, 'Deep', 1, 9), (5, 'Later', 50, 50)]
    assert {a.status for a in actions} == {'Action Required', 'Investigation Recommended'}  # errors and FYIs are not actions
    assert all(a.category == 'Security' and a.section_id == 'security-identity' for a in actions)  # the stoplight's name, not the category's
    assert actions[0].slug == 'wide'


def test_text_findings_rank_by_their_lines_with_no_project_count():
    results = {OPERATIONS: [check('Logs', 'Action Required', 'Project `a` has no sink.'), check('Logs', 'Action Required', 'Project `b` has no sink.'),
                            check('Table', 'Action Required', rows(1))]}
    actions = card(results).actions
    assert [(a.check_name, a.projects, a.rows) for a in actions] == [('Table', 1, 1), ('Logs', None, 2)]  # one line per record


def test_ten_actions_and_a_count_of_the_rest():
    results = {SECURITY: [check(f'Check {i:02d}', 'Action Required', rows(i + 1)) for i in range(14)]}
    scorecard = card(results)
    assert len(scorecard.actions) == TOP_ACTIONS == 10
    assert [a.check_name for a in scorecard.actions][:2] == ['Check 13', 'Check 12']
    assert scorecard.more_actions == 4
    assert card({SECURITY: [check('Only', 'Action Required', rows(1))]}).more_actions == 0
    assert card({}).actions == ()


def test_fix_in_report_marks_the_checks_that_ship_their_command():
    results = {RELIABILITY: [check('Essential Contacts', 'Action Required', [
        {'Project': 'p1', 'Issue': 'No contacts', 'Fix': 'gcloud essential-contacts create --project=p1 --email=<address>'}]),
        check('Backups', 'Action Required', rows(1))]}
    actions = {a.check_name: a for a in card(results).actions}
    assert actions['Essential Contacts'].fix_in_report is True
    assert actions['Backups'].fix_in_report is False


def test_each_action_says_what_moved_since_the_previous_scan():
    first = {SECURITY: [check('Keys', 'Action Required', rows(5)), check('Buckets', 'Compliant', 'none'),
                        check('Roles', 'Action Required', rows(2)), check('Firewall', 'Error', 'boom')]}
    second = {SECURITY: [check('Keys', 'Action Required', rows(4) + [{'Project': 'p9', 'Resource': 'new'}]),
                         check('Buckets', 'Action Required', rows(1)), check('Roles', 'Action Required', rows(2)),
                         check('Firewall', 'Action Required', rows(3)), check('Brand new', 'Action Required', rows(1))]}
    since = {a.check_name: a.since for a in two_scans(first, second).actions}
    assert since == {'Keys': f'+1 new · {MINUS}1 resolved', 'Buckets': '+1 new · was Compliant', 'Roles': '',
                     'Firewall': 'not compared', 'Brand new': 'not compared'}  # not compared: an error then, or a new check
    assert all(a.since == '' for a in card(second).actions)  # a first scan has nothing to say


# --- The since line and the footers ---

def test_the_since_line_names_regressions_first_then_links_the_rest_to_the_changes_card():
    first = {SECURITY: [check('A', 'Action Required', rows(1)), check('B', 'Action Required', rows(1)), check('C', 'Action Required', rows(1)),
                        check('D', 'Compliant', 'ok'), check('E', 'Investigation Recommended', rows(1))],
             COST: [check('F', 'Compliant', 'ok')]}
    second = {SECURITY: [check('A', 'Compliant', 'ok'), check('B', 'Compliant', 'ok'), check('C', 'Compliant', 'ok'),
                         check('D', 'Action Required', rows(2)), check('E', 'Action Required', rows(1))],
              COST: [check('F', 'Investigation Recommended', rows(1))]}
    since = two_scans(first, second).since
    assert since.status_changes[:3] == ('D Compliant → Action Required', 'E Investigation Recommended → Action Required',
                                        'F Compliant → Investigation Recommended')  # what got worse, worst first
    assert set(since.status_changes[3:]) == {'A Action Required → Compliant', 'B Action Required → Compliant', 'C Action Required → Compliant'}
    assert since.headline == since.status_changes[:INLINE_STATUS_CHANGES] and since.more_status_changes == 3
    assert (since.new, since.resolved, since.previous_job_id) == (3, 3, 'job-1')  # D's two rows and F's one are new; A, B, C's rows resolved
    assert card(second).since is None


def test_the_since_line_states_a_status_change_without_the_rows_note():
    # A check that was an Error last time carries "· not compared (could not be checked then)" on the Changes card;
    # the since line says the status change alone, and ranks it by that status (Error → Action Required is a regression).
    first = {SECURITY: [check('A', 'Error', 'boom'), check('B', 'Error', 'boom'), check('C', 'Action Required', rows(1))]}
    second = {SECURITY: [check('A', 'Action Required', rows(2)), check('B', 'Compliant', 'ok'), check('C', 'Compliant', 'ok')]}
    since = two_scans(first, second).since
    assert since.status_changes[0] == 'A Error → Action Required'
    assert set(since.status_changes[1:]) == {'B Error → Compliant', 'C Action Required → Compliant'}
    assert not any('not compared' in line for line in since.status_changes)


def test_the_footers_name_what_the_table_leaves_out():
    results = {SECURITY: [check('Firewall', 'Error', rows(2)), check('Keys', 'Error', 'denied')],
               'Organization Policies': (samples.BEST_PRACTICES, samples.CURRENT_POLICIES)}
    scorecard = card(results)
    assert scorecard.org_line == '3 of 4 organization policies differ from the recommendation'
    assert scorecard.could_not_check == ('Firewall (2 projects)', 'Keys')
    compliant = {'Security': samples.BEST_PRACTICES['Security'][:1]}  # the one policy that matches
    assert card({'Organization Policies': (compliant, samples.CURRENT_POLICIES)}).org_line is None
    assert card({}).org_line is None and card({}).could_not_check == ()


# --- The page ---

def section(html):
    """The Scorecard section's markup."""
    return html.split('<div id="scorecard-section" class="content-section" style="display: none;">', 1)[1].split('<div id="security-identity-section"', 1)[0]


def test_the_page_has_a_sidebar_entry_under_overview_and_comes_before_the_category_pages():
    html = generate_html_report(SCOPE, SCOPE_ID, 'job-42', total_projects=4, **samples.FINDINGS)
    assert re.search(r'<span class="nav-label">Overview</span></a>\s*<a href="#scorecard" class="nav-link" onclick="showSection\(\'scorecard\', this\)"><span class="nav-label">Scorecard</span></a>', html)
    assert html.index('id="overview-section"') < html.index('id="scorecard-section"') < html.index('id="security-identity-section"')
    assert section(html).count('<li class="stoplight">') == 4


def test_the_lamp_and_the_pill_say_the_same_thing_and_the_score_links_to_the_page():
    html = generate_html_report(SCOPE, SCOPE_ID, 'job-42', total_projects=4, **{COST: [check('Disks', 'Compliant', 'none')]})
    page = section(html)
    efficiency = re.search(r'<li class="stoplight">\s*<span class="lamp lamp-(\w+)" aria-hidden="true"><i></i><i></i><i></i></span>.*?'
                           r'<a href="#cost-optimization" onclick="showSection\(\'cost-optimization\'\)">Efficiency</a>'
                           r'<span class="stoplight-category">Cost Optimization</span>.*?<span class="score">(\d+)%</span></div>\s*'
                           r'<span class="pill pill-(\w+)">([^<]+)</span>', page, re.S)
    assert efficiency.groups() == ('high', '100', 'high', 'Healthy')
    assert re.findall(r'<span class="pill pill-(\w+)">(Healthy|Needs attention|At risk)</span>', page) == [
        ('high', 'Healthy'), ('high', 'Healthy'), ('high', 'Healthy'), ('high', 'Healthy')]  # empty categories score 100
    assert 'First scan of this organization — changes appear from the next scan.' in page


def test_the_table_links_each_action_to_its_check_and_marks_a_shipped_fix_quietly():
    results = {RELIABILITY: [check('Essential Contacts', 'Action Required', [
        {'Project': 'p1', 'Issue': 'No contacts', 'Fix': 'gcloud essential-contacts create --project=p1 --email=<address>'}])],
        SECURITY: [check('Service Account Keys', 'Action Required', rows(3))]}
    page = section(generate_html_report(SCOPE, SCOPE_ID, 'job-42', total_projects=4, **results))
    assert ('<td class="action-name"><a href="#security-identity-service-account-keys" onclick="showSection(\'security-identity\')">Service Account Keys</a></td>'
            '<td class="muted category-cell">Security</td><td><span class="pill pill-action-required">Action Required</span></td>'
            '<td class="num">3</td><td class="num">3</td>') in page.replace('\n', '').replace('  ', '')
    assert '>Essential Contacts</a> <span class="fix-tag">fix in report</span></td>' in page
    assert page.count('<span class="fix-tag">') == 1 and 'AI-drafted' not in page
    assert '<th>Since last scan</th>' not in page  # first scan: no column of dashes
    assert re.findall(r'<th[^>]*>([^<]+)</th>', page) == ['#', 'Check', 'Category', 'Status', 'Projects', 'Rows']


def test_a_second_scan_adds_the_since_column_and_the_since_line():
    first = sample_results()
    second = sample_results()
    second[SECURITY] = [f for f in second[SECURITY] if f['Check'] != 'Project IAM Hygiene'] + [check('Project IAM Hygiene', 'Compliant', 'clean')]
    html = generate_reports(SCOPE, SCOPE_ID, 'job-2', second, total_projects=4, previous=generate_reports(SCOPE, SCOPE_ID, 'job-1', first, total_projects=4)[2])[0]
    page = section(html)
    assert '<th>Since last scan</th>' in page
    assert re.search(r'Since the previous scan \(<a href="/report/job-1/123456789"><time>[^<]+</time></a>\):\s*'
                     r'<span class="mono">0</span> new rows · <span class="mono">2</span> resolved'
                     r' · status changes: Project IAM Hygiene Action Required → Compliant\.</p>', page)
    assert 'and <a href="#changes" onclick="showSection(\'overview\')">' not in page  # one change: nothing more to link


def test_the_since_line_links_the_overflow_to_the_changes_card():
    first = {SECURITY: [check(f'C{i}', 'Action Required', rows(1)) for i in range(5)]}
    second = {SECURITY: [check(f'C{i}', 'Compliant', 'ok') for i in range(5)]}
    html = generate_reports(SCOPE, SCOPE_ID, 'job-2', second, total_projects=4, previous=generate_reports(SCOPE, SCOPE_ID, 'job-1', first, total_projects=4)[2])[0]
    assert 'C2 Action Required → Compliant and <a href="#changes" onclick="showSection(\'overview\')">2 more</a>.' in section(html)
    assert '<section class="card changes-card" id="changes">' in html


def test_the_footers_and_the_empty_table():
    results = {SECURITY: [check('Firewall', 'Error', rows(2))], 'Organization Policies': (samples.BEST_PRACTICES, samples.CURRENT_POLICIES)}
    page = section(generate_html_report(SCOPE, SCOPE_ID, 'job-42', total_projects=4, **results))
    assert '<div class="empty-state"><span class="dot dot-compliant"></span>No failing checks — nothing to take away from this scan.</div>' in page
    assert ('<p class="actions-foot"><a href="#security-identity-organization-policies" onclick="showSection(\'security-identity\')">Organization Policies</a>: '
            '3 of 4 organization policies differ from the recommendation.</p>') in page
    assert '<p class="actions-foot">Could not check: Firewall (2 projects) — listed as errors on their category pages.</p>' in page
    many = {SECURITY: [check(f'Check {i:02d}', 'Action Required', rows(1)) for i in range(12)]}
    assert '<p class="actions-foot muted">2 more failing checks on the category pages.</p>' in section(generate_html_report(SCOPE, SCOPE_ID, 'job-42', **many))


def test_the_executive_summary_is_generated_on_the_scorecard_and_the_page_has_one_primary_button():
    html = generate_html_report(SCOPE, SCOPE_ID, 'job-42', total_projects=4, **samples.FINDINGS)
    page = section(html)
    assert '<section id="ai-summary-container" class="card scorecard-summary is-empty">' in page
    assert '<h2>Executive summary <span class="attribution">Powered by Gemini</span></h2>' in page
    assert '<span id="summary-pill" class="pill pill-sky" hidden>AI-generated</span>' in page
    assert '<button id="summaryBtn" class="btn btn-primary" onclick="generateAiSummary()">Generate executive summary</button>' in page
    assert re.findall(r'class="btn btn-primary[^"]*"[^>]*>([^<]+)<', html) == ['Generate executive summary']
    overview = html.split('id="overview-section"')[1].split('id="scorecard-section"')[0]
    assert 'summaryBtn' not in overview and 'ai-summary' not in overview and 'Draft fixes' in overview
    script = html.split('<script>')[-1]
    assert "container.classList.remove('is-empty')" in script and 'executiveSummaryMarkdown' in script


def test_the_buttons_print_the_page_alone_download_the_plan_and_copy_the_markdown():
    html = generate_html_report(SCOPE, SCOPE_ID, 'job-42', total_projects=4, **samples.FINDINGS)
    page = section(html)
    assert re.findall(r'<button type="button" class="btn btn-outline btn-sm" onclick="(\w+)\((?:this)?\)">([^<]+)</button>', page) == [
        ('printScorecard', 'Print'), ('downloadActionPlan', 'Download action plan (CSV)'), ('copyScorecardMarkdown', 'Copy as Markdown')]
    styles = html.split('</style>')[0]
    assert 'body.print-scorecard .content-section:not(#scorecard-section) { display: none !important; }' in styles
    assert '.scorecard-actions, .scorecard-summary.is-empty { display: none !important; }' in styles
    assert '.actions-table thead { display: table-header-group; }' in styles and '.actions-table tr { break-inside: avoid; }' in styles
    script = html.split('<script>')[-1]
    assert "document.body.classList.add('print-scorecard')" in script
    embedded = json.loads(re.search(r'const SCORECARD_EXPORTS = (.*?);\n', script).group(1))
    exports = scorecard_vars(build_report_context(SCOPE, SCOPE_ID, 'job-42', samples.FINDINGS, total_projects=4))['scorecard_exports']
    assert embedded == exports and sorted(embedded) == ['csv', 'csv_name', 'markdown']
    assert html.count('</script>') == 1  # the exports are a value in the report's own script, not an element of their own


def test_the_exports_are_html_safe_in_the_script():
    results = {SECURITY: [check('</script><script>alert(1)</script>', 'Action Required', rows(1))]}
    html = generate_html_report(SCOPE, SCOPE_ID, 'job-42', total_projects=4, **results)
    script = html.split('<script>')[-1]
    assert '</script><script>alert(1)' not in script and html.count('</script>') == 1
    assert '\\u003c/script\\u003e' in script


# --- The exports ---

def test_the_action_plan_lists_the_actions_then_the_policies_with_owner_and_date_blank():
    results = {RELIABILITY: [check('Essential Contacts', 'Action Required', [
        {'Project': 'p1', 'Issue': 'No contacts', 'Fix': 'gcloud essential-contacts create --project=p1 --email=<address>'}])],
        SECURITY: [check('Keys', 'Action Required', rows(3)), check('Note', 'Investigation Recommended', 'Have a look.')],
        'Organization Policies': (samples.BEST_PRACTICES, samples.CURRENT_POLICIES)}
    scorecard = card(results)
    table = list(csv.reader(io.StringIO(action_plan_csv(scorecard))))
    assert table[0] == list(ACTION_PLAN_COLUMNS) == ['Priority', 'Check', 'Category', 'Status', 'Projects affected', 'Resources', 'Fix in report', 'Owner', 'Target date']
    assert table[1:] == [
        ['1', 'Keys', 'Security', 'Action Required', '3', '3', '', '', ''],
        ['2', 'Essential Contacts', 'Stability', 'Action Required', '1', '1', FIX_IN_REPORT, '', ''],
        ['3', 'Note', 'Security', 'Investigation Recommended', '', '1', '', '', ''],
        ['', 'Organization Policies', 'Security', 'Action Required', '', '3', '', '', ''],
    ]
    assert action_plan_name(scorecard) == f'cloudgauge-action-plan-123456789-{scorecard.generated_ts[:8]}.csv'
    assert action_plan_csv(card({})).splitlines() == [','.join(ACTION_PLAN_COLUMNS)]


def test_the_markdown_copy_carries_the_page():
    first = sample_results()
    second = sample_results()
    second[SECURITY] = [f for f in second[SECURITY] if f['Check'] != 'Project IAM Hygiene'] + [check('Project IAM Hygiene', 'Compliant', 'clean')]
    scorecard = two_scans(first, second)
    text = markdown(scorecard)
    lines = text.splitlines()
    assert lines[0] == '# CloudGauge scorecard — Organization 123456789'
    assert lines[2] == f'Generated {scorecard.generated_at} · compared with {scorecard.since.previous_at} · 4 of 4 projects'
    assert lines[4] == '| Stoplight | Category | Score | Since last scan | State | Evidence |'
    assert '| Security | Security & Identity | 43% | +14 | At risk | 3 of 7 checks compliant |' in lines
    assert 'Since the previous scan' in text and 'status changes: Project IAM Hygiene Action Required → Compliant.' in text
    assert '| # | Check | Category | Status | Projects | Rows | Fix in report | Since last scan |' in lines
    assert '| 1 | Quota Utilization (>80%) | Operations | Action Required | 1 | 1 | — | — |' in lines
    assert 'Organization Policies: 3 of 4 organization policies differ from the recommendation.' in lines
    assert 'Could not check: Open Firewall Rules.' in lines
    first_scan = markdown(card(second)).splitlines()
    assert '| Stoplight | Category | Score | State | Evidence |' in first_scan  # no delta column before there is a previous scan
    assert '| # | Check | Category | Status | Projects | Rows | Fix in report |' in first_scan
    assert 'First scan of this organization — changes appear from the next scan.' in first_scan


def test_render_report_takes_the_scorecard_from_the_context_it_renders():
    context_ = context(samples.FINDINGS)
    html = render_report(context_)
    assert build_scorecard(context_) == scorecard_vars(context_)['scorecard']
    assert section(html).count('<tr>') - 1 == len(build_scorecard(context_).actions)  # the header row, then one per action
