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
"""The score of a category (v15.2): ``app.reporting.scoring`` and every place the report shows a score.

The rule: a score is the share of a category's checks that reached a verdict
and were compliant. An Error is coverage, stated next to the score and never
inside it; a briefing (Informational) is outside as before; Organization
Policies is one check with partial credit; a category without a verdict is
*Not assessed*. The first half tests the rule on tallies; the second renders
small scans and reads the Review scores table, the section pill, the empty
page, the Scorecard's stoplights and Markdown, and the Changes card — ending
with the case that prompted the rule: a transient Error in one scan no longer
moves the score between two scans of the same estate.
"""
import re
from html import unescape

import pytest

import samples
from app.reporting.changes import SUMMARY_VERSION, summarize
from app.reporting.context import build_report_context
from app.reporting.html_report import generate_html_report, generate_reports
from app.reporting.scorecard import DASH, build_scorecard, markdown
from app.reporting.scoring import (NOT_ASSESSED, NOT_ASSESSED_TEXT, VERDICT_FAILING, Tally, plural, score_class_for,
                                   tallies_from_checks, tally_statuses)

SCOPE, SCOPE_ID = 'organization', '123456789'
SECURITY, COST, RELIABILITY, OPERATIONS = ('Security & Identity', 'Cost Optimization', 'Reliability & Resilience',
                                           'Operational Excellence & Observability')
MINUS = '\u2212'


def checks(status, count, prefix='Check'):
    return [{'Check': f'{prefix} {status} {i}', 'Status': status, 'Finding': f'Finding {i}'} for i in range(count)]


def statuses(**counts):
    """``statuses(compliant=7, error=3)`` → the statuses of ten checks."""
    names = {'compliant': 'Compliant', 'action': 'Action Required', 'investigation': 'Investigation Recommended',
             'informational': 'Informational', 'error': 'Error'}
    return [names[key] for key, count in counts.items() for _ in range(count)]


# --- The rule ---

def test_a_score_is_the_share_of_verdicts_that_were_compliant():
    tally = tally_statuses(statuses(compliant=7, action=2, investigation=1))
    assert (tally.compliant, tally.failing, tally.not_checked, tally.verdicts) == (7, 3, 0, 10)
    assert (tally.score, tally.score_display, tally.score_class, tally.assessed) == (70.0, '70', 'low', True)
    assert tally.evidence == '7 of 10 checks compliant'
    assert VERDICT_FAILING == ('Action Required', 'Investigation Recommended')


def test_an_error_is_coverage_not_a_verdict():
    """7 Compliant and 3 Error: 100%, with the Errors stated next to the score (the old rule said 70%)."""
    tally = tally_statuses(statuses(compliant=7, error=3))
    assert (tally.score, tally.score_class, tally.not_checked) == (100.0, 'high', 3)
    assert tally.evidence == '7 of 7 checks compliant · 3 could not be checked'
    assert tally_statuses(statuses(compliant=7, error=3)).score == tally_statuses(statuses(compliant=7)).score


def test_a_briefing_is_outside_the_score():
    tally = tally_statuses(statuses(informational=4, compliant=1))
    assert (tally.score, tally.verdicts, tally.evidence) == (100.0, 1, '1 of 1 check compliant')


@pytest.mark.parametrize('tally, evidence', [
    (tally_statuses([]), 'no check reached a verdict'),
    (tally_statuses(statuses(error=2)), 'no check reached a verdict · 2 could not be checked'),
    (tally_statuses(statuses(informational=3)), 'no check reached a verdict'),
    (tally_statuses([], policies=(0, 0)), 'no check reached a verdict'),  # no policy evaluated: nothing to credit
])
def test_a_category_without_a_verdict_is_not_assessed(tally, evidence):
    assert (tally.assessed, tally.score, tally.score_display, tally.score_class) == (False, None, '', NOT_ASSESSED)
    assert tally.evidence == evidence
    assert NOT_ASSESSED == 'none' and NOT_ASSESSED_TEXT == 'Not assessed'


def test_organization_policies_are_one_check_with_partial_credit():
    """The stark organization: 7 Compliant, 5 Action Required, a briefing, and 18 of 128 policies as recommended.
    Under the old rule the policies were 128 checks and the score 18%; now (7 + 18/128) / 13 = 55%."""
    tally = tally_statuses(statuses(compliant=7, action=5, informational=1), policies=(18, 128))
    assert (tally.verdicts, tally.score_display, tally.score_class) == (13, '55', 'low')
    assert tally.score == pytest.approx((7 + 18 / 128) / 13 * 100)
    assert tally.evidence == '7 of 12 checks compliant · 18 of 128 policies as recommended'
    alone = tally_statuses([], policies=(1, 4))
    assert (alone.score, alone.evidence) == (25.0, '1 of 4 policies as recommended')
    assert tally_statuses([], policies=(4, 4)).score == 100.0
    assert tally_statuses(statuses(error=1), policies=(3, 4)).evidence == '3 of 4 policies as recommended · 1 could not be checked'


@pytest.mark.parametrize('score, cls', [(None, 'none'), (100, 'high'), (90.1, 'high'), (90, 'medium'), (70.1, 'medium'), (70, 'low'), (0, 'low')])
def test_the_bands(score, cls):
    assert score_class_for(score) == cls


def test_plural_and_the_thousands_separator():
    assert (plural(1, 'check'), plural(2, 'check'), plural(1234, 'check')) == ('1 check', '2 checks', '1,234 checks')
    assert Tally(compliant=1234, failing=1).evidence == '1,234 of 1,235 checks compliant'


def test_tallies_from_a_summary_follow_the_same_rule():
    """A stored scan's checks give the same tallies the live scan had: a category whose only entry is Organization
    Policies is tallied; an entry without a category (an older summary's) is skipped."""
    entries = {
        'Keys': {'category': SECURITY, 'status': 'Action Required'},
        'Buckets': {'category': SECURITY, 'status': 'Compliant'},
        'Projects not checked': {'category': COST, 'status': 'Error'},
        'Organization Policies': {'category': RELIABILITY, 'status': 'Action Required', 'rows': 4, 'identities': ['a', 'b', 'c']},
        'Stray': {'status': 'Compliant'},
    }
    tallies = tallies_from_checks(entries)
    assert {name: (t.score, t.evidence) for name, t in tallies.items()} == {
        SECURITY: (50.0, '1 of 2 checks compliant'),
        COST: (None, 'no check reached a verdict · 1 could not be checked'),
        RELIABILITY: (25.0, '1 of 4 policies as recommended'),
    }


# --- The report ---

def report(results, **kwargs):
    return generate_html_report(SCOPE, SCOPE_ID, 'job-42', total_projects=4, **results, **kwargs)


def review_scores(html):
    """The Review scores table: ``[(category, score cell, evidence)]``."""
    return [(unescape(name), score, evidence) for name, score, evidence in re.findall(
        r'<td class="score-name"><a [^>]*>([^<]*)</a></td>\s*<td class="score-bar-cell">.*?</td>\s*'
        r'<td class="num score-cell">(.*?)</td>\s*<td class="score-of">([^<]*)</td>', html, re.S)]


def kpi_counts(html):
    return dict(re.findall(r'<h3>([\w ]+)</h3><p class="count">(\d+)</p>', html))


def test_the_review_scores_table_states_the_evidence_and_says_not_assessed_in_words():
    results = {
        SECURITY: checks('Compliant', 7, 'S') + checks('Error', 3, 'S'),
        COST: checks('Error', 1, 'C') + checks('Informational', 1, 'C'),
        RELIABILITY: checks('Compliant', 1, 'R') + checks('Action Required', 1, 'R') + checks('Investigation Recommended', 2, 'R'),
    }
    html = report(results)
    assert review_scores(html) == [
        (SECURITY, '<span class="score score-high">100%</span>', '7 of 7 checks compliant · 3 could not be checked'),
        (COST, '<span class="score-none">Not assessed</span>', 'no check reached a verdict · 1 could not be checked'),
        (RELIABILITY, '<span class="score score-low">25%</span>', '1 of 4 checks compliant'),
        (OPERATIONS, '<span class="score-none">Not assessed</span>', 'no check reached a verdict'),
    ]
    # The bar of a category without a score is empty, and its fill carries the fourth band's class.
    assert html.count('<span class="bar-fill score-none" style="width: 0%"></span>') == 2
    assert '<span class="bar-fill score-high" style="width: 100%"></span>' in html
    # The section pills say the same; a category with no item at all says so where its list would be.
    assert re.findall(r'<span class="score-pill pill pill-(\w+)">([^<]+)</span>', html) == [
        ('high', '100% compliant'), ('none', 'Not assessed'), ('low', '25% compliant'), ('none', 'Not assessed')]
    assert html.count('<div class="empty-state" role="note"><span class="dot dot-none"></span>Not assessed — no ') == 1
    assert 'Not assessed — no Operational Excellence &amp; Observability check reported a result in this scan.' in html
    # The sidebar's dot agrees: zinc for the page with no item, the worst status elsewhere (Cost: its Error).
    assert re.findall(r'<span class="nav-meta"><span class="dot dot-([\w-]+)"></span><span class="mono">(\d+)</span>', html) == [
        ('error', '3'), ('error', '1'), ('action-required', '3'), ('none', '0')]
    # The Cost page lists its Error and its briefing, so it is not an empty page — but it has no verdict.
    assert 'Not assessed — no Cost Optimization check' not in html
    # The Errors are counted on the KPI cards, where they always were; they just do not score.
    assert kpi_counts(html) == {'Action Required': '1', 'Investigation Recommended': '2', 'Compliant': '8', 'Errors': '4'}
    assert 'all Cost Optimization checks were compliant' not in html and 'No findings in this category' not in html


def test_the_kpi_cards_count_organization_policies_once():
    policies = (samples.BEST_PRACTICES, samples.CURRENT_POLICIES)  # 1 of 4 policies as recommended
    html = report({SECURITY: checks('Compliant', 2, 'S'), 'Organization Policies': policies})
    assert kpi_counts(html) == {'Action Required': '1', 'Investigation Recommended': '0', 'Compliant': '2', 'Errors': '0'}
    assert review_scores(html)[0] == (SECURITY, '<span class="score score-medium">75%</span>', '2 of 2 checks compliant · 1 of 4 policies as recommended')
    all_set = report({'Organization Policies': ({'Security': samples.BEST_PRACTICES['Security'][:1]}, samples.CURRENT_POLICIES)})
    assert kpi_counts(all_set) == {'Action Required': '0', 'Investigation Recommended': '0', 'Compliant': '1', 'Errors': '0'}
    assert review_scores(all_set)[0] == (SECURITY, '<span class="score score-high">100%</span>', '1 of 1 policy as recommended')


def card(results, previous=None):
    return build_scorecard(build_report_context(SCOPE, SCOPE_ID, 'job-2', results, total_projects=4, previous=previous))


def test_the_scorecard_shows_the_fourth_state_on_the_lamp_the_pill_and_the_markdown():
    results = {COST: checks('Error', 1, 'C'), SECURITY: checks('Compliant', 1, 'S')}
    stability, security, operations, efficiency = card(results).stoplights
    assert (efficiency.score_display, efficiency.score_text, efficiency.score_class, efficiency.state) == ('', DASH, 'none', 'Not assessed')
    assert (efficiency.evidence, efficiency.delta_display, efficiency.delta_class) == ('no check reached a verdict · 1 could not be checked', None, None)
    assert (security.score_text, security.state) == ('100%', 'Healthy')
    text = markdown(card(results))
    assert '| Efficiency | Cost Optimization | — | Not assessed | no check reached a verdict · 1 could not be checked |' in text
    assert '| Security | Security & Identity | 100% | Healthy | 1 of 1 check compliant |' in text
    page = report(results).split('id="scorecard-section"', 1)[1].split('id="security-identity-section"', 1)[0]
    assert page.count('<span class="lamp lamp-none" aria-hidden="true">') == 3 and page.count('<span class="pill pill-none">Not assessed</span>') == 3
    assert page.count('<span class="score score-none">—</span>') == 3 and '<span class="score">100%</span>' in page


def two_scans(first, second):
    """``(html, summary)`` of a scan of ``second`` compared with a scan of ``first``."""
    previous = generate_reports(SCOPE, SCOPE_ID, 'job-1', first, total_projects=4)[2]
    html, _, summary = generate_reports(SCOPE, SCOPE_ID, 'job-2', second, total_projects=4, previous=previous)
    return html, summary


def card_rows(html):
    """The Changes card's score cells: ``{category: (score text, delta class, delta text)}``."""
    start = html.index('<section class="card changes-card" id="changes">')
    section = html[start:html.index('</section>', start)]
    return {unescape(name): (score, cls, delta.replace('&#9650; ', '▲ ').replace('&#9660; ', '▼ ')) for name, score, cls, delta in re.findall(
        r'<td class="score-name"><a [^>]*>([^<]*)</a></td>\s*<td class="num"><span class="score(?:-none)?">([^<]*)</span> '
        r'<span class="delta delta-(\w+)">(.*?)</span></td>', section)}


def test_the_changes_card_with_not_assessed_on_either_side():
    """No delta is shown unless both scans assessed the category; the side without a score says so in words."""
    first = {COST: checks('Error', 1, 'C'), SECURITY: checks('Compliant', 1, 'S')}
    second = {COST: checks('Compliant', 2, 'C'), SECURITY: checks('Error', 1, 'S')}
    html, summary = two_scans(first, second)
    rows = card_rows(html)
    assert rows[COST] == ('100%', 'flat', DASH)  # not assessed then: nothing to compare with
    assert rows[SECURITY] == ('Not assessed', 'flat', DASH)  # not assessed now
    assert rows[RELIABILITY] == ('Not assessed', 'flat', DASH)
    assert summary['version'] == SUMMARY_VERSION == 2 and summary['scores'] == {SECURITY: None, COST: 100.0, RELIABILITY: None, OPERATIONS: None}
    html, _ = two_scans(second, {COST: checks('Compliant', 1, 'C') + checks('Action Required', 1, 'C')})
    assert card_rows(html)[COST] == ('50%', 'down', f'▼ {MINUS}50')


def test_a_transient_error_in_the_previous_scan_does_not_move_the_score():
    """The case behind the rule: a scan with a *Projects not checked* Error under Operations read 25% (2 of 8) and the
    next 29% (2 of 7) with "no status changes". Both now read 29%, the retired item is listed as no longer checked,
    and a previous scan filed as version 1 (its scores computed under the old rule) is read the same way."""
    operations = checks('Compliant', 2, 'O') + checks('Action Required', 5, 'O')
    not_checked = [{'Check': 'Projects not checked', 'Status': 'Error', 'Finding': [{'Project': 'p3', 'Skipped check': 'Logs', 'Reason': '503'}]}]
    previous = generate_reports(SCOPE, SCOPE_ID, 'job-1', {OPERATIONS: operations + not_checked}, total_projects=4)[2]
    assert previous['scores'][OPERATIONS] == pytest.approx(2 / 7 * 100)
    previous['version'], previous['scores'][OPERATIONS] = 1, 25.0  # as the old rule filed it
    html, _, summary = generate_reports(SCOPE, SCOPE_ID, 'job-2', {OPERATIONS: operations}, total_projects=4, previous=previous)
    assert card_rows(html)[OPERATIONS] == ('29%', 'flat', DASH)
    assert 'No longer checked: Projects not checked.' in html
    page = html.split('id="scorecard-section"', 1)[1].split('id="security-identity-section"', 1)[0]
    assert '<span class="score">29%</span> <span class="delta delta-flat">—</span>' in page
    assert ' · no status changes.</p>' in page
    assert review_scores(html)[3] == (OPERATIONS, '<span class="score score-low">29%</span>', '2 of 7 checks compliant')
    # And the scan with the Error, scored today, says 29% with the Error next to it.
    with_error = report({OPERATIONS: operations + not_checked})
    assert review_scores(with_error)[3] == (OPERATIONS, '<span class="score score-low">29%</span>', '2 of 7 checks compliant · 1 could not be checked')
    assert summarize(build_report_context(SCOPE, SCOPE_ID, 'job-3', {OPERATIONS: operations + not_checked}))['scores'][OPERATIONS] == pytest.approx(2 / 7 * 100)
