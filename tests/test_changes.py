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
"""Changes since the previous scan (v15): ``app.reporting.changes`` and what the report makes of them.

The first half tests the comparison on its own: what makes two rows the same
finding (identities), the rules per check, the card's numbers. The second
half renders two scans of the same scope and reads the second report the way
a reader would: the header's *Previous scan*, the KPI deltas, the *Changes
since last scan* card, the chip on a check, the *New* rows, the resolved
list, and the CSV's last column. The last tests cover how the results store
files and finds summaries.
"""
import copy
import json
import re
from html import unescape

import pytest

import samples
from app.config import VERSION
from app.reporting.changes import (INLINE_STATUS_CHANGES, MAX_LISTED_RESOLVED, MINUS, NO_LONGER_CHECKED, NO_RESULT, NO_RESULT_NOW,
                                   NOT_COMPARED, ORG_POLICIES_CHECK, SUMMARY_VERSION, CheckChange, RowIdentities, RowMatcher,
                                   check_change, compare, count_delta, delta_class, first_result_change, identities_for,
                                   normalize_prose, same_release, text_identities)
from app.reporting.csv_report import NEW_COLUMN
from app.reporting.html_report import generate_reports
from app.reporting.layouts import NUMBER, PROSE, RESOURCE, STATE, TIME
from app.reporting.scoring import overview_from_checks, scores_from_checks, summary_policies
from app.synthetic.memory_store import memory_results_store
from helpers import csv_sections

SCOPE, SCOPE_ID = 'organization', '123456789'
SECURITY, COST, RELIABILITY, OPERATIONS = ('Security & Identity', 'Cost Optimization', 'Reliability & Resilience',
                                           'Operational Excellence & Observability')
SECTION_IDS = {SECURITY: 'security-identity', COST: 'cost-optimization', RELIABILITY: 'reliability-resilience',
               OPERATIONS: 'operational-excellence-observability'}
NONE_YET = 'none — first scan of this organization'
DASH = '\u2014'  # what the card shows for "no change" / zero
UNCHANGED = 'unchanged since last scan'
# The markup of each change element (the class names alone also occur in the inlined CSS).
CHANGE_CHIP, ROW_NEW, LINE_NEW = '<span class="change-chip', '<tr class="row-new"', '<span class="line-new">'
RESOLVED_LIST, KPI_DELTA = '<details class="resolved-list">', '<span class="kpi-delta">'


# --- Identities ---

def test_identity_leaves_out_measurements_and_the_fix():
    """Numbers, times and the Fix column change between scans without the finding changing."""
    headers = ('Project', 'Disk', 'Size (GB)', 'Est. Monthly Saving', 'Date', 'Fix', 'Recommendation')
    row = ('web-prod', 'old-boot-disk', '500', '$12.40', '2026-01-02', 'gcloud compute disks delete old-boot-disk', 'Idle for 31 days; 3 snapshots')
    roles, identities = identities_for(headers, [row, row])
    assert roles == (RESOURCE, RESOURCE, NUMBER, NUMBER, TIME, PROSE, PROSE)
    assert identities == ('web-prod · old-boot-disk · Idle for # days; # snapshots',
                          'web-prod · old-boot-disk · Idle for # days; # snapshots #2')  # the second identical row is still a finding


def test_identity_keeps_apart_the_rows_that_differ_in_a_kept_column():
    _, identities = identities_for(('Project', 'Member', 'Role'),
                                   [('a', 'allUsers', 'roles/viewer'), ('a', 'allUsers', 'roles/editor'), ('b', 'allUsers', 'roles/viewer')])
    assert identities == ('a · allUsers · roles/viewer', 'a · allUsers · roles/editor', 'b · allUsers · roles/viewer')


@pytest.mark.parametrize('text, normalized', [
    ('Save $12.34/month', 'Save $#/month'),
    ('taken 4 times, 1,204 GB left', 'taken # times, # GB left'),
    ('No security contact', 'No security contact'),
    ('n2-standard-8 is enough', 'n#-standard-# is enough'),
])
def test_prose_compares_without_its_numbers(text, normalized):
    assert normalize_prose(text) == normalized


def test_state_columns_keep_their_digits():
    """A node pool called pool-2 is not pool-3: only prose is digit-normalised."""
    builder = RowIdentities(('Cluster', 'State'), (RESOURCE, STATE))
    assert builder.next(('prod-1', 'pool-2')) != builder.next(('prod-1', 'pool-3'))


def test_gke_supported_versions_rows_are_the_same_finding_across_patches_and_quarters():
    """v15: the Version column is left out (a pool that takes a patch while it stays on a retired minor is the same
    finding), Component is a state (pool-2 is not pool-3) and the Issue is prose (the minors in it move on every quarter)."""
    headers = ('Project', 'Cluster', 'Location', 'Component', 'Version', 'Issue', 'Fix')
    issue = '1.27 is no longer offered; the oldest supported minor is 1.29.'
    roles, identities = identities_for(headers, [
        ('p', 'prod-1', 'us-central1', 'Node pool pool-2', '1.27.3-gke.100', issue, 'gcloud container clusters upgrade prod-1 ...'),
        ('p', 'prod-1', 'us-central1', 'Node pool pool-2', '1.27.9-gke.200', issue, 'gcloud container clusters upgrade prod-1 ...'),
        ('p', 'prod-1', 'us-central1', 'Node pool pool-3', '1.27.3-gke.100', issue, 'gcloud container clusters upgrade prod-1 ...'),
        ('p', 'prod-1', 'us-central1', 'Control plane', '1.29.1-gke.100', '1.29 is the oldest supported minor: the next to leave support.', ''),
    ])
    assert roles == (RESOURCE, RESOURCE, RESOURCE, STATE, RESOURCE, PROSE, PROSE)
    assert identities == (
        'p · prod-1 · us-central1 · Node pool pool-2 · # is no longer offered; the oldest supported minor is #.',
        'p · prod-1 · us-central1 · Node pool pool-2 · # is no longer offered; the oldest supported minor is #. #2',  # a patch later
        'p · prod-1 · us-central1 · Node pool pool-3 · # is no longer offered; the oldest supported minor is #.',
        'p · prod-1 · us-central1 · Control plane · # is the oldest supported minor: the next to leave support.',
    )


def test_text_details_are_one_prose_line_each():
    assert text_identities(['No security contact', 'Quota at 92%', 'Quota at 93%', 'Quota at 93%']) == (
        'No security contact', 'Quota at #%', 'Quota at #% #2', 'Quota at #% #3')


def test_row_identities_accept_dicts_with_missing_columns():
    builder = RowIdentities(('Project', 'Disk', 'Monthly Savings'), (RESOURCE, RESOURCE, NUMBER))
    assert builder.next_dict({'Project': 'web-prod', 'Disk': 'old-boot-disk'}) == 'web-prod · old-boot-disk'
    assert builder.next_dict({'Project': 'web-prod', 'Disk': 'old-boot-disk', 'Monthly Savings': 12.4}) == 'web-prod · old-boot-disk #2'


def test_row_matcher_marks_the_new_rows_in_csv_order():
    """The CSV rebuilds the identities row by row, so duplicates are numbered the same way as in the page."""
    matcher = RowMatcher(('Project', 'Member'), (RESOURCE, RESOURCE), frozenset({'b · allUsers', 'a · allUsers #2'}))
    tracker = matcher.tracker()
    flags = [tracker.is_new(row) for row in ({'Project': 'a', 'Member': 'allUsers'}, {'Project': 'a', 'Member': 'allUsers'},
                                             {'Project': 'b', 'Member': 'allUsers'})]
    assert flags == [False, True, True]
    assert matcher.tracker().is_new({'Project': 'a', 'Member': 'allUsers'}) is False  # every tracker starts counting afresh


# --- The rules per check ---

def entry(status, *identities, category=SECURITY):
    return {'category': category, 'status': status, 'rows': len(identities), 'identities': list(identities)}


def test_rows_in_both_scans_are_compared_by_identity():
    change = check_change(entry('Action Required', 'b', 'c', 'd'), entry('Action Required', 'a', 'b'))
    assert (change.new, change.resolved, change.previous_status, change.note) == (2, 1, None, None)
    assert change.new_identities == {'c', 'd'} and change.resolved_items == ('a',)
    assert (change.chip, change.chip_title) == (f'+2 new · {MINUS}1 resolved', 'Compared with the previous scan of this scope')


def test_nothing_changed_means_no_chip():
    change = check_change(entry('Action Required', 'a'), entry('Action Required', 'a'))
    assert change == CheckChange()
    assert change.chip is None


def test_a_check_that_starts_failing_lists_every_row_as_new():
    change = check_change(entry('Action Required', 'a', 'b'), entry('Compliant'))
    assert (change.new, change.resolved, change.previous_status) == (2, 0, 'Compliant')
    assert (change.chip, change.chip_title) == ('+2 new', 'Was Compliant in the previous scan')


def test_a_check_that_becomes_compliant_lists_every_previous_row_as_resolved():
    change = check_change(entry('Compliant'), entry('Investigation Recommended', 'a', 'b', 'c'))
    assert (change.new, change.resolved, change.previous_status) == (0, 3, 'Investigation Recommended')
    assert change.resolved_items == ('a', 'b', 'c')  # the previous scan's order
    assert change.chip == f'{MINUS}3 resolved'


def test_the_resolved_list_is_capped_but_the_count_is_not():
    previous = entry('Action Required', *(f'row-{i}' for i in range(MAX_LISTED_RESOLVED + 50)))
    change = check_change(entry('Action Required', 'row-0'), previous)
    assert (change.resolved, len(change.resolved_items), change.resolved_omitted) == (MAX_LISTED_RESOLVED + 49, MAX_LISTED_RESOLVED, 49)
    assert change.resolved_items[0] == 'row-1' and change.chip == f'{MINUS}149 resolved'


@pytest.mark.parametrize('now, then, previous_status, reason, title', [
    ('Error', 'Action Required', 'Action Required', 'could not be checked now',
     'Was Action Required in the previous scan; Rows not compared: could not be checked now'),
    ('Action Required', 'Error', 'Error', 'could not be checked then',
     'Was Error in the previous scan; Rows not compared: could not be checked then'),
    ('Error', 'Error', None, 'could not be checked in either scan', 'Rows not compared: could not be checked in either scan'),
])
def test_an_error_on_either_side_compares_nothing(now, then, previous_status, reason, title):
    """An Error scan did not look, so nothing was resolved and nothing is new: the status change only."""
    change = check_change(entry(now, *(['a', 'b'] if now != 'Error' else [])), entry(then, *(['c'] if then != 'Error' else [])))
    assert (change.new, change.resolved, change.new_identities, change.resolved_items) == (0, 0, frozenset(), ())
    assert (change.previous_status, change.note, change.note_reason) == (previous_status, NOT_COMPARED, reason)
    assert (change.chip, change.chip_title) == (NOT_COMPARED, title)


@pytest.mark.parametrize('now, then', [('Informational', 'Informational'), ('Informational', 'Action Required'), ('Compliant', 'Informational')])
def test_briefings_are_never_compared(now, then):
    assert check_change(entry(now, 'a'), entry(then, 'b')) is None


def test_a_check_with_no_result_in_the_previous_scan_of_the_same_release_is_all_new():
    """v15.5: the release could have run the check then and did not, so there was nothing to check (an empty folder
    with its first project now): every row that needs work is new. An Error now is still not compared."""
    change = first_result_change(entry('Action Required', 'a', 'b'))
    assert (change.new, change.resolved, change.previous_status, change.note, change.first_result) == (2, 0, None, None, True)
    assert change.new_identities == {'a', 'b'}
    assert (change.chip, change.chip_title) == ('+2 new', 'No result in the previous scan (nothing to check then), so every finding is new')
    assert first_result_change(entry('Compliant')) == CheckChange(first_result=True) and first_result_change(entry('Compliant')).chip is None
    assert first_result_change(entry('Error')) == CheckChange(note=NOT_COMPARED, note_reason='could not be checked now')


@pytest.mark.parametrize('then, now, same', [('15.5', '15.5', True), ('15.4', '15.5', False), (None, '15.5', False), ('', '15.5', False)])
def test_summaries_of_the_same_release_are_told_by_the_release_they_name(then, now, same):
    """A summary written before releases were named (v15.4 and earlier) is never the same release as this one."""
    assert same_release(summary('job-1', {}, {}, release=then), summary('job-2', {}, {}, release=now)) is same


# --- compare(): the card ---

def summary(job_id, checks, scores, overview=None, total_projects=4, generated_at='2026-01-01 10:00 UTC', release=None):
    """A scan summary as the store files it; without ``release`` (the default), as releases before v15.5 filed it."""
    return {'version': SUMMARY_VERSION, 'job_id': job_id, 'scope': SCOPE, 'scope_id': SCOPE_ID, 'generated_at': generated_at,
            'total_projects': total_projects, 'overview': overview or {}, 'scores': scores, 'checks': checks,
            **({'release': release} if release is not None else {})}


SLUGS = {'IAM': 'iam', 'Buckets': 'buckets', 'Firewall': 'firewall', 'Disks': 'disks', 'Fresh': 'fresh'}


def test_compare_needs_a_previous_scan():
    assert compare(None, summary('job-2', {}, {}), {}, {}) is None
    assert compare({}, summary('job-2', {}, {}), {}, {}) is None


def card_summaries(previous_release=None, current_release=VERSION):
    """The two summaries behind the card tests: the previous one, by default, as a release before v15.5 filed it (no
    ``release``); the current one as this release files it."""
    # The previous summary as the old rule stored it: Security 33 (its Error counted as failing), Operations 100 (nothing
    # counted), 7 Action Required (a policy per count). compare() reads its checks under the current rule instead
    # (app.reporting.scoring): Security 50, Operations not assessed, 2 Action Required.
    previous = summary('job-1', {
        'IAM': entry('Action Required', 'a', 'b'),
        'Buckets': entry('Compliant'),
        'Firewall': entry('Error'),
        'Disks': entry('Investigation Recommended', 'x', category=COST),
        'Retired': entry('Action Required', 'r', category=COST),
        'Old briefing': entry('Informational', category=OPERATIONS),
    }, {SECURITY: 33.3, COST: 0.0, OPERATIONS: 100.0}, overview={'action_count': 7, 'investigation_count': 1, 'compliant_count': 1, 'error_count': 1},
        release=previous_release)
    current = summary('job-2', {
        'IAM': entry('Action Required', 'b', 'c'),
        'Buckets': entry('Action Required', 'p'),
        'Firewall': entry('Action Required', 'f'),
        'Disks': entry('Compliant', category=COST),
        'Fresh': entry('Action Required', 'n', category=COST),
        'Briefing': entry('Informational', category=OPERATIONS),
        'Backups': entry('Compliant', category=RELIABILITY),
    }, {SECURITY: 0.0, COST: 50.0, OPERATIONS: None, RELIABILITY: 100.0},
        overview={'action_count': 4, 'investigation_count': 0, 'compliant_count': 2, 'error_count': 0}, total_projects=5, release=current_release)
    return previous, current


def test_compare_builds_the_card():
    """The previous summary by a release before v15.5 (it names none): a check only in this scan may be new to the
    release, so its rows are not compared, and a check only in the previous scan is no longer checked."""
    previous, current = card_summaries()
    changes = compare(previous, current, SLUGS, SECTION_IDS)
    assert (changes.previous_job_id, changes.previous_generated_at) == ('job-1', '2026-01-01 10:00 UTC')
    assert changes.population == '4 projects then · 5 now'
    # The previous counts come from its checks: 2 Action Required, 1 Investigation Recommended, 1 Compliant, 1 Error.
    assert changes.overview_deltas == {'action_count': 2, 'investigation_count': -1, 'compliant_count': 1, 'error_count': -1}
    assert (changes.new_total, changes.resolved_total) == (2, 2)  # IAM: +1 −1; Buckets: +1; Disks: −1; Fresh, Backups and Firewall: not compared
    assert (changes.retired_checks, changes.retired_label) == (('Retired',), NO_LONGER_CHECKED)  # the retired briefing is not listed
    assert set(changes.checks) == {'IAM', 'Buckets', 'Firewall', 'Disks', 'Fresh', 'Backups'}  # no briefings
    assert changes.checks['Fresh'] == CheckChange(note=NOT_COMPARED, note_reason='new check')

    security, cost, operations, reliability = changes.categories
    assert (security.category_name, security.section_id, security.score_display, security.previous_score_display) == (SECURITY, 'security-identity', '0', '50')
    assert (security.delta_display, security.delta_class, security.resolved, security.new) == (f'{MINUS}50', 'down', 1, 2)
    # Status changes first, then the checks whose rows were not compared, each with its anchor.
    assert [(e.check_name, e.slug, e.before, e.after) for e in security.entries] == [
        ('Buckets', 'buckets', 'Compliant', 'Action Required'),
        ('Firewall', 'firewall', 'Error', 'Action Required · not compared (could not be checked then)'),
    ]
    assert (cost.score_display, cost.previous_score_display, cost.delta_display, cost.delta_class, cost.resolved, cost.new) == ('50', '0', '+50', 'up', 1, 0)
    assert [(e.check_name, e.before, e.after) for e in cost.entries] == [
        ('Disks', 'Investigation Recommended', 'Compliant'), ('Fresh', None, 'not compared (new check)')]
    # A category without a verdict on either side has no delta; the card says so in words rather than with a number.
    assert (operations.score_display, operations.score_text, operations.previous_score_display) == ('', 'Not assessed', 'Not assessed')
    assert (operations.delta_display, operations.delta_class, operations.entries) == (DASH, 'flat', ())
    # A category the previous scan did not have at all has no previous score either.
    assert (reliability.score_display, reliability.previous_score_display, reliability.delta_display, reliability.delta_class) == ('100', None, DASH, 'flat')
    assert [(e.check_name, e.after) for e in reliability.entries] == [('Backups', 'not compared (new check)')]
    # A previous summary by another release reads the same way: the check may be new to this one.
    assert compare(*card_summaries('15.4'), SLUGS, SECTION_IDS).checks['Fresh'] == CheckChange(note=NOT_COMPARED, note_reason='new check')


def test_compare_within_a_release_counts_a_first_result_as_new():
    """v15.5: both summaries by this release, so the previous scan could have run Fresh and had nothing to check: its
    row is new (``no result → Action Required`` on the card). Backups' first result is Compliant: nothing to count and
    nothing to say. Retired had a result then and none now: listed as such, nothing resolved by it."""
    changes = compare(*card_summaries(VERSION), SLUGS, SECTION_IDS)
    assert changes.checks['Fresh'] == CheckChange(new=1, new_identities=frozenset({'n'}), first_result=True)
    assert changes.checks['Backups'] == CheckChange(first_result=True) and changes.checks['Backups'].chip is None
    assert changes.checks['Firewall'] == compare(*card_summaries(), SLUGS, SECTION_IDS).checks['Firewall']  # in both: as before
    assert (changes.new_total, changes.resolved_total) == (3, 2)  # IAM: +1 −1; Buckets: +1; Disks: −1; Fresh: +1
    assert (changes.retired_checks, changes.retired_label) == (('Retired',), NO_RESULT_NOW)
    security, cost, _, reliability = changes.categories
    assert security.entries == compare(*card_summaries(), SLUGS, SECTION_IDS).categories[0].entries
    assert (cost.resolved, cost.new) == (1, 1)
    assert [(e.check_name, e.slug, e.before, e.after) for e in cost.entries] == [
        ('Disks', 'disks', 'Investigation Recommended', 'Compliant'), ('Fresh', 'fresh', NO_RESULT, 'Action Required')]
    assert reliability.entries == ()  # a first Compliant result is not a change
    # An Error in its first result is not compared: the scan did not look.
    previous, current = card_summaries(VERSION)
    current['checks']['Fresh'] = entry('Error', category=COST)
    changes = compare(previous, current, SLUGS, SECTION_IDS)
    assert changes.checks['Fresh'] == CheckChange(note=NOT_COMPARED, note_reason='could not be checked now')
    assert [(e.check_name, e.before, e.after) for e in changes.categories[1].entries] == [
        ('Disks', 'Investigation Recommended', 'Compliant'), ('Fresh', None, 'not compared (could not be checked now)')]


def test_score_deltas_are_whole_points():
    """The card shows rounded scores, so the delta is the difference of what the reader sees: 66.4 → 66.6 is 66 → 67, +1."""
    def policies(compliant):
        return {ORG_POLICIES_CHECK: {'category': SECURITY, 'status': 'Action Required', 'rows': 1000, 'identities': [],
                                     'policies': {'compliant': compliant, 'total': 1000}}}
    previous = summary('job-1', policies(664), {SECURITY: 66.4}, overview={'action_count': 1})
    current = summary('job-2', policies(666), {SECURITY: 66.6}, overview={'action_count': 1, 'compliant_count': 2})
    changes = compare(previous, current, {}, SECTION_IDS)
    (security,) = changes.categories
    assert (security.score_display, security.previous_score_display, security.delta_display) == ('67', '66', '+1')
    assert changes.overview_deltas == {'action_count': 0, 'compliant_count': 2}  # the previous counts come from its one check


def test_the_previous_scan_is_read_under_the_current_rule():
    """The user's case: a scan with a *Projects not checked* Error under Operations (one API call failed for one project)
    scored 25% under the old rule (2 of 8, the Error counted against) and the next scan 29% (2 of 7) with nothing
    changed. Under the rule an Error is coverage, so both scans read 29% and the delta is none — and a stored version 1
    summary is read the same way (its ``scores`` are not used)."""
    def operations(*names):
        return {name: entry(status, *identities, category=OPERATIONS) for name, status, identities in names}
    checks = [('Logging', 'Compliant', ()), ('Monitoring', 'Compliant', ()), ('Quota', 'Action Required', ('a',)), ('Budgets', 'Action Required', ('b',)),
              ('Contacts', 'Action Required', ('c',)), ('Labels', 'Action Required', ('d',)), ('Retention', 'Action Required', ('e',))]
    previous = summary('job-1', operations(*checks, ('Projects not checked', 'Error', ())), {OPERATIONS: 25.0})
    previous['version'] = 1
    current = summary('job-2', operations(*checks), {OPERATIONS: 2 / 7 * 100})
    (ops,) = compare(previous, current, {}, SECTION_IDS).categories
    assert (ops.score_display, ops.previous_score_display, ops.delta_display, ops.delta_class) == ('29', '29', DASH, 'flat')
    assert ops.entries == () and compare(previous, current, {}, SECTION_IDS).retired_checks == ('Projects not checked',)


def test_a_summary_states_the_policies_behind_the_security_score_and_version_one_is_read_the_same_way():
    """Since version 2 a summary stores ``policies`` on the Organization Policies entry (version 3, v15.5, adds the
    ``release``); version 1 stored the total as ``rows`` and every differing policy as an identity, which gives the
    same numbers (app.reporting.scoring.summary_policies)."""
    _, _, first = scan(sample_results(), 'job-1')
    policies_entry = first['checks'][ORG_POLICIES_CHECK]
    assert (first['version'], first['release'], policies_entry['policies'], summary_policies(policies_entry)) == (3, VERSION, {'compliant': 1, 'total': 4}, (1, 4))
    version_one = {key: value for key, value in policies_entry.items() if key != 'policies'}
    assert summary_policies(version_one) == (1, 4) and summary_policies({'rows': 3, 'identities': []}) == (3, 3) and summary_policies({}) == (0, 0)
    # The invariant the recompute rests on: a summary's own scores and counts are what its checks give under the rule.
    assert scores_from_checks(first['checks']) == first['scores'] and overview_from_checks(first['checks']) == first['overview']
    checks = {'Projects not checked': entry('Error', category=COST), 'Idle Disks': entry('Compliant', category=COST), 'Keys': entry('Action Required', 'k')}
    assert scores_from_checks(checks) == {COST: 100.0, SECURITY: 0.0} and scores_from_checks({'Note': entry('Informational')}) == {SECURITY: None}
    assert overview_from_checks(checks) == {'action_count': 1, 'investigation_count': 0, 'compliant_count': 1, 'error_count': 1}


@pytest.mark.parametrize('value, display, cls', [(6, '+6', 'up'), (-11, f'{MINUS}11', 'down'), (0, DASH, 'flat'), (1234, '+1,234', 'up')])
def test_count_delta(value, display, cls):
    assert (count_delta(value), delta_class(value)) == (display, cls)


@pytest.mark.parametrize('then, now, text', [(4, 4, '4 projects'), (1, 1, '1 project'), (3, 4, '3 projects then · 4 now'),
                                             (1, 2, '1 project then · 2 now'), (None, 4, ''), (4, None, '')])
def test_population(then, now, text):
    changes = compare(summary('job-1', {}, {}, total_projects=then), summary('job-2', {}, {}, total_projects=now), {}, {})
    assert changes.population == text


# --- Two scans, read from the report ---

def sample_results():
    """A fresh copy of the sample scan, safe to edit."""
    return {**copy.deepcopy(samples.FINDINGS), 'Organization Policies': (copy.deepcopy(samples.BEST_PRACTICES), copy.deepcopy(samples.CURRENT_POLICIES))}


def scan(results, job_id, previous=None, total_projects=4):
    """``(html, csv, summary)`` of one scan of the sample scope."""
    return generate_reports(SCOPE, SCOPE_ID, job_id, results, total_projects=total_projects, previous=previous)


def two_scans(edit, total_projects=4):
    """Scans the sample scope, applies ``edit(results)`` and scans again, compared with the first: the second ``(html, csv, summary)``."""
    first = scan(sample_results(), 'job-1')[2]
    results = sample_results()
    edit(results)
    return scan(results, 'job-2', previous=first, total_projects=total_projects)


def finding(results, category, check_name):
    return next(f for f in results[category] if f['Check'] == check_name)


def replace_check(results, category, check_name, **fields):
    """Replaces every record of a check with one record (``Status``, ``Finding``)."""
    results[category] = [f for f in results[category] if f['Check'] != check_name] + [{'Check': check_name, **fields}]


def item(html, category, check_name):
    """The markup of one check's accordion (its ``</li>`` is the one at the start of a line; the resolved list's are inline)."""
    slug = re.sub(r'[^a-z0-9]+', '-', check_name.lower()).strip('-')
    start = html.index(f'id="{SECTION_IDS[category]}-{slug}"')
    return html[start:html.index('\n</li>', start)]


CHIP = re.compile(r'<span class="change-chip( change-chip-note)?" title="([^"]*)">([^<]*)</span>')


def chip(markup):
    """``(text, title)`` of the check's change chip, or None."""
    found = CHIP.findall(markup)
    assert len(found) <= 1
    return (unescape(found[0][2]), unescape(found[0][1])) if found else None


def text(markup):
    """The text of some markup, tags turned into spaces (then collapsed, and dropped before punctuation)."""
    flat = re.sub(r'\s+', ' ', unescape(re.sub(r'<[^>]+>', ' ', markup))).strip()
    return re.sub(r' ([.,;:)])', r'\1', flat)


def new_rows(markup):
    """The text of the table rows marked New, in page order."""
    return [text(row) for row in re.findall(r'<tr class="row-new"[^>]*>(.*?)</tr>', markup)]


def new_lines(markup):
    return [unescape(line) for line in re.findall(r'<span class="line-new">(.*?)</span>', markup)]


def resolved(markup):
    """``(count, items, tail)`` of the check's resolved list, or None."""
    found = re.search(r'<details class="resolved-list"><summary>Resolved since last scan \(<span class="mono">([\d,]+)</span>\)</summary>\s*'
                      r'<ul>(.*?)</ul>(.*?)</details>', markup, re.S)
    if not found:
        return None
    return int(found.group(1).replace(',', '')), [unescape(i) for i in re.findall(r'<li>(.*?)</li>', found.group(2))], text(found.group(3))


def previous_scan_line(html):
    return text(re.search(r'<dd class="previous-scan">(.*?)</dd>', html, re.S).group(1))


def kpi_deltas(html):
    """What the four KPI cards say under their count, in page order."""
    return [text(delta) for delta in re.findall(r'<span class="kpi-delta">(.*?)</span></span>', html)]


CARD_ROW = re.compile(r'<tr>\s*<td class="score-name"><a [^>]*>([^<]*)</a></td>\s*<td class="num"><span class="score">([^<]*)</span> '
                      r'<span class="delta delta-(\w+)">(.*?)</span></td>\s*<td class="num">([^<]*)</td>\s*<td class="num">([^<]*)</td>\s*'
                      r'<td class="prose status-changes">(.*?)</td>', re.S)
FOLD = re.compile(r'<details class="cell-more"><summary>([^<]*)</summary><span class="more-body">')


def changes_card(html):
    """The *Changes since last scan* card as ``(meta, {category: row}, feet)``, or None; ``row`` has the cells and the status-change entries."""
    start = html.find('<section class="card changes-card" id="changes">')
    if start < 0:
        return None
    card = html[start:html.index('</section>', start)]
    rows = {}
    for name, score, delta_cls, delta, resolved_count, new_count, cell in CARD_ROW.findall(card):
        fold = FOLD.search(cell)
        entries = FOLD.sub('', cell).replace('</span></details>', '').split('<span class="status-change">')[1:]
        rows[unescape(name)] = {
            'score': score, 'delta': text(delta), 'delta_class': delta_cls, 'resolved': text(resolved_count), 'new': text(new_count),
            'status_changes': [text(e) for e in entries], 'folded': fold.group(1) if fold else None,
            'none': '<span class="muted">none</span>' in cell,
        }
    meta = text(re.search(r'<span class="card-meta">(.*?)</span>\s*</div>', card, re.S).group(1))
    feet = [text(foot) for foot in re.findall(r'<p class="changes-foot">(.*?)</p>', card, re.S)]
    return meta, rows, feet


def csv_new_flags(csv_text, category, check_name):
    """``{row text: flag}`` of a check's structured CSV rows, from the trailing New column."""
    flags = {}
    headers = None
    for row in csv_sections(csv_text)[category]:
        if row[:2] == ['Check', 'Status']:
            headers = row
        elif row and row[0] == check_name and headers and headers[-1] == NEW_COLUMN:
            flags[' · '.join(row[2:-1])] = row[-1]
    return flags


def test_a_first_scan_states_that_it_is_one():
    html, csv_text, first = scan(sample_results(), 'job-1')
    assert previous_scan_line(html) == NONE_YET
    assert changes_card(html) is None and KPI_DELTA not in html
    assert not any(marker in html for marker in (CHANGE_CHIP, ROW_NEW, LINE_NEW, RESOLVED_LIST))
    assert NEW_COLUMN not in csv_text
    # The summary the next scan compares with: statuses for every check, identities for the ones that need work.
    assert (first['version'], first['release'], first['job_id'], first['scope'], first['scope_id'], first['total_projects']) == (
        SUMMARY_VERSION, VERSION, 'job-1', SCOPE, SCOPE_ID, 4)
    assert first['overview'] == {'action_count': 4, 'investigation_count': 1, 'compliant_count': 3, 'error_count': 1}  # Organization Policies counts once
    assert {name: round(score) for name, score in first['scores'].items()} == {SECURITY: 42, COST: 50, RELIABILITY: 50, OPERATIONS: 0}  # (1 + 1/4) / 3
    assert first['checks']['Project IAM Hygiene'] == {'category': SECURITY, 'status': 'Action Required', 'rows': 2, 'identities': [
        'web-prod · user:alice@example.com · roles/owner', 'data-lake · allUsers · roles/viewer']}
    assert first['checks']['Idle Persistent Disks']['identities'] == ['data-lake · orphan-disk', 'web-prod · old-boot-disk']  # the saving is not identity
    assert first['checks']['Essential Contacts']['identities'] == ['No security contact', 'No billing contact']  # text details, one line each
    assert first['checks']['Quota Utilization (>80%)']['identities'] == ['web-prod · CPUS']  # the usage is not identity
    assert first['checks'][ORG_POLICIES_CHECK] == {'category': SECURITY, 'status': 'Action Required', 'rows': 4, 'identities': [
        'Networking · Skip default network creation', 'Networking · Restrict VM external IPs', 'Security · Domain restricted sharing'],
        'policies': {'compliant': 1, 'total': 4}}
    assert {name: entry['status'] for name, entry in first['checks'].items() if 'identities' not in entry} == {
        'Open Firewall Rules': 'Error', 'Public GCS Buckets': 'Compliant', 'VM Rightsizing': 'Compliant', 'GKE Hygiene': 'Compliant',
        'Unattended Projects': 'Informational'}
    json.dumps(first)  # it is what the store files


def test_an_identical_second_scan_reports_nothing_changed():
    html, csv_text, second = two_scans(lambda results: None)
    assert previous_scan_line(html).startswith('20') and previous_scan_line(html).endswith('UTC view')
    assert f'<a href="/report/job-1/{SCOPE_ID}">view</a>' in html
    assert kpi_deltas(html) == [UNCHANGED] * 4
    meta, rows, feet = changes_card(html)
    assert meta.startswith('compared with 20') and meta.endswith('UTC · 4 projects')
    assert {name: (row['score'], row['delta'], row['delta_class'], row['resolved'], row['new']) for name, row in rows.items()} == {
        SECURITY: ('42%', DASH, 'flat', DASH, DASH), COST: ('50%', DASH, 'flat', DASH, DASH),
        RELIABILITY: ('50%', DASH, 'flat', DASH, DASH), OPERATIONS: ('0%', DASH, 'flat', DASH, DASH)}
    # The one thing to say: the check that errored both times could not be compared.
    assert rows[SECURITY]['status_changes'] == ['Open Firewall Rules not compared (could not be checked in either scan)']
    assert all(rows[name]['none'] and rows[name]['status_changes'] == [] for name in (COST, RELIABILITY, OPERATIONS))
    assert feet == ['New and resolved rows are counted per check on the category pages; rows the previous scan did not have are marked New. '
                    'Briefings are not compared.']
    assert chip(item(html, SECURITY, 'Open Firewall Rules')) == (NOT_COMPARED, 'Rows not compared: could not be checked in either scan')
    assert html.count(CHANGE_CHIP) == 1
    assert not any(marker in html for marker in (ROW_NEW, LINE_NEW, RESOLVED_LIST))
    # The CSV has the column, with nothing flagged.
    assert csv_new_flags(csv_text, SECURITY, 'Project IAM Hygiene') == {'web-prod · user:alice@example.com · roles/owner': '',
                                                                        'data-lake · allUsers · roles/viewer': ''}
    assert second['checks'] == scan(sample_results(), 'job-1')[2]['checks']


def test_a_second_scan_marks_new_rows_and_lists_resolved_ones():
    def edit(results):
        replace_check(results, SECURITY, 'Project IAM Hygiene', Status='Action Required', Finding=[  # alice's owner role is gone, a CI account is new
            {'Project': 'data-lake', 'Member': 'allUsers', 'Role': 'roles/viewer'},
            {'Project': 'ml-dev', 'Member': 'serviceAccount:ci@ml-dev.iam.gserviceaccount.com', 'Role': 'roles/editor'}])
        finding(results, SECURITY, 'Public GCS Buckets').update(Status='Action Required', Finding=[{'Project': 'web-prod', 'Bucket': 'logs-public'}])

    html, csv_text, _ = two_scans(edit)
    iam = item(html, SECURITY, 'Project IAM Hygiene')
    assert chip(iam) == (f'+1 new · {MINUS}1 resolved', 'Compared with the previous scan of this scope')
    assert new_rows(iam) == ['ml-dev serviceAccount:ci@ml-dev.iam.gserviceaccount.com roles/editor']
    assert resolved(iam) == (1, ['web-prod · user:alice@example.com · roles/owner'], '')
    buckets = item(html, SECURITY, 'Public GCS Buckets')
    assert chip(buckets) == ('+1 new', 'Was Compliant in the previous scan')
    assert new_rows(buckets) == ['web-prod logs-public']
    assert resolved(buckets) is None

    assert kpi_deltas(html) == ['+1 since last scan', UNCHANGED, f'{MINUS}1 since last scan', UNCHANGED]
    _, rows, _ = changes_card(html)
    # Security: no Compliant check left of two, 1 of 4 policies, the Error outside: (0 + 1/4) / 3 = 8, down from 42.
    assert (rows[SECURITY]['score'], rows[SECURITY]['delta'], rows[SECURITY]['delta_class']) == ('8%', f'\u25bc {MINUS}34', 'down')
    assert (rows[SECURITY]['resolved'], rows[SECURITY]['new']) == ('1', '2')
    assert rows[SECURITY]['status_changes'] == ['Public GCS Buckets Compliant → Action Required',
                                                'Open Firewall Rules not compared (could not be checked in either scan)']
    assert '<a href="#security-identity-public-gcs-buckets" onclick="showSection(\'security-identity\')">Public GCS Buckets</a>' in html
    # The CSV flags the same row.
    assert csv_new_flags(csv_text, SECURITY, 'Project IAM Hygiene') == {
        'data-lake · allUsers · roles/viewer': '', 'ml-dev · serviceAccount:ci@ml-dev.iam.gserviceaccount.com · roles/editor': 'yes'}
    assert csv_new_flags(csv_text, SECURITY, 'Public GCS Buckets') == {'web-prod · logs-public': 'yes'}


def test_the_new_marker_is_not_part_of_the_row_text():
    """Sorting, filtering, the CSV and the Gemini prompt read cell text: the marker is CSS-generated from the row's class."""
    def edit(results):
        finding(results, COST, 'Idle Persistent Disks')['Finding'].append({'Project': 'ml-dev', 'Disk': 'scratch-disk', 'Monthly Savings': 3.0})

    html, _, _ = two_scans(edit)
    disks = item(html, COST, 'Idle Persistent Disks')
    assert new_rows(disks) == ['ml-dev scratch-disk 3.0']
    assert 'New' not in text(re.search(r'<table.*?</table>', disks, re.S).group(0))
    assert '<span class="pill pill-new">New</span>' in html  # the legend on the card is the one place the word is in the page


def test_text_details_mark_new_lines():
    def edit(results):
        finding(results, RELIABILITY, 'Essential Contacts')['Finding'] = ['No security contact', 'No legal contact']

    html, csv_text, _ = two_scans(edit)
    contacts = item(html, RELIABILITY, 'Essential Contacts')
    assert chip(contacts) == (f'+1 new · {MINUS}1 resolved', 'Compared with the previous scan of this scope')
    assert new_lines(contacts) == ['No legal contact']
    assert '<div class="details">No security contact<br><span class="line-new">No legal contact</span></div>' in contacts
    assert resolved(contacts) == (1, ['No billing contact'], '')
    assert NEW_COLUMN in csv_text and csv_new_flags(csv_text, RELIABILITY, 'Essential Contacts') == {}  # text details are one CSV cell


def test_measurements_and_prose_numbers_do_not_make_new_findings():
    def edit(results):
        finding(results, COST, 'Idle Persistent Disks')['Finding'][0]['Monthly Savings'] = 15.9  # re-estimated
        finding(results, OPERATIONS, 'Quota Utilization (>80%)')['Finding'][0]['Usage'] = '97%'  # grew
        finding(results, RELIABILITY, 'Essential Contacts')['Finding'] = ['No security contact', 'No billing contact']  # the same

    html, csv_text, _ = two_scans(edit)
    for category, check_name in ((COST, 'Idle Persistent Disks'), (OPERATIONS, 'Quota Utilization (>80%)'), (RELIABILITY, 'Essential Contacts')):
        assert chip(item(html, category, check_name)) is None, check_name
    assert ROW_NEW not in html and LINE_NEW not in html
    assert set(csv_new_flags(csv_text, COST, 'Idle Persistent Disks').values()) == {''}


def test_duplicate_rows_are_matched_in_order():
    """Two identical rows, then three: the third is the new one, on the page and in the CSV."""
    row = {'Project': 'web-prod', 'Quota': 'CPUS', 'Usage': '92%'}
    first_results = sample_results()
    finding(first_results, OPERATIONS, 'Quota Utilization (>80%)')['Finding'] = [dict(row), dict(row)]
    first = scan(first_results, 'job-1')[2]
    assert first['checks']['Quota Utilization (>80%)']['identities'] == ['web-prod · CPUS', 'web-prod · CPUS #2']
    results = sample_results()
    finding(results, OPERATIONS, 'Quota Utilization (>80%)')['Finding'] = [dict(row), dict(row), dict(row, Usage='99%')]
    html, csv_text, _ = scan(results, 'job-2', previous=first)
    quota = item(html, OPERATIONS, 'Quota Utilization (>80%)')
    assert chip(quota) == ('+1 new', 'Compared with the previous scan of this scope')
    assert new_rows(quota) == ['web-prod CPUS 99%']
    assert list(csv_new_flags(csv_text, OPERATIONS, 'Quota Utilization (>80%)').items()) == [
        ('web-prod · CPUS · 92%', ''), ('web-prod · CPUS · 99%', 'yes')]  # (keyed by row text, so the twins collapse into one key)


def test_organization_policies_compare_by_policy():
    def edit(results):
        _, current = results['Organization Policies']
        current['compute.skipDefaultNetworkCreation'] = {'booleanPolicy': {'enforced': True}}  # fixed
        current['iam.disableServiceAccountKeyCreation'] = {'booleanPolicy': {}}  # regressed

    html, _, second = two_scans(edit)
    start = html.index('id="security-identity-organization-policies"')
    policies = html[start:html.index('\n</li>', start)]
    assert chip(policies) == (f'+1 new · {MINUS}1 resolved', 'Compared with the previous scan of this scope')
    assert new_rows(policies) == ['Disable service account key creation True False Non-compliant']
    assert resolved(policies) == (1, ['Networking · Skip default network creation'], '')
    assert second['checks'][ORG_POLICIES_CHECK]['identities'] == [
        'Networking · Restrict VM external IPs', 'Security · Disable service account key creation', 'Security · Domain restricted sharing']
    assert kpi_deltas(html) == [UNCHANGED] * 4  # one policy in, one out
    _, rows, _ = changes_card(html)
    assert (rows[SECURITY]['resolved'], rows[SECURITY]['new'], rows[SECURITY]['delta']) == ('1', '1', DASH)


def test_briefings_are_not_compared_in_the_report():
    def edit(results):
        finding(results, OPERATIONS, 'Unattended Projects')['Finding'] = ['sandbox-3', 'sandbox-4', 'sandbox-5']

    html, _, _ = two_scans(edit)
    briefing = item(html, OPERATIONS, 'Unattended Projects')
    assert chip(briefing) is None and LINE_NEW not in briefing and resolved(briefing) is None
    _, rows, _ = changes_card(html)
    assert rows[OPERATIONS]['none'] and (rows[OPERATIONS]['resolved'], rows[OPERATIONS]['new']) == (DASH, DASH)


def test_an_error_check_that_recovers_is_not_all_new():
    def edit(results):
        finding(results, SECURITY, 'Open Firewall Rules').update(Status='Action Required', Finding=[
            {'Project': 'web-prod', 'Rule Name': 'allow-all', 'Source Ranges': '0.0.0.0/0'}])

    html, csv_text, _ = two_scans(edit)
    firewall = item(html, SECURITY, 'Open Firewall Rules')
    assert chip(firewall) == (NOT_COMPARED, 'Was Error in the previous scan; Rows not compared: could not be checked then')
    assert new_rows(firewall) == [] and resolved(firewall) is None
    _, rows, _ = changes_card(html)
    assert rows[SECURITY]['status_changes'] == ['Open Firewall Rules Error → Action Required · not compared (could not be checked then)']
    assert (rows[SECURITY]['resolved'], rows[SECURITY]['new']) == (DASH, DASH)
    assert kpi_deltas(html) == ['+1 since last scan', UNCHANGED, UNCHANGED, f'{MINUS}1 since last scan']
    assert csv_new_flags(csv_text, SECURITY, 'Open Firewall Rules') == {'web-prod · allow-all · 0.0.0.0/0': ''}


def test_a_check_that_starts_erroring_keeps_its_rows_unresolved():
    def edit(results):
        finding(results, RELIABILITY, 'Essential Contacts').update(Status='Error', Finding=[{'Error': '403 essentialcontacts.contacts.list denied'}])

    html, _, _ = two_scans(edit)
    contacts = item(html, RELIABILITY, 'Essential Contacts')
    assert chip(contacts) == (NOT_COMPARED, 'Was Action Required in the previous scan; Rows not compared: could not be checked now')
    assert resolved(contacts) is None
    _, rows, _ = changes_card(html)
    assert rows[RELIABILITY]['status_changes'] == ['Essential Contacts Action Required → Error · not compared (could not be checked now)']
    assert rows[RELIABILITY]['resolved'] == DASH


def pitr_edit(results):
    """A check only in the second scan (Cloud SQL PITR) and one only in the first (VM Rightsizing)."""
    results[RELIABILITY].append({'Check': 'Cloud SQL PITR', 'Status': 'Action Required', 'Finding': [{'Project': 'web-prod', 'Instance': 'orders-db'}]})
    results[COST] = [f for f in results[COST] if f['Check'] != 'VM Rightsizing']


def test_within_a_release_a_first_result_is_new_and_a_missing_one_had_nothing_to_check():
    """v15.5: both scans by this release, so the previous one could have run Cloud SQL PITR and had nothing to check
    (a project moved into the folder since): its row is new. VM Rightsizing had a result then and none now."""
    html, csv_text, _ = two_scans(pitr_edit)
    pitr = item(html, RELIABILITY, 'Cloud SQL PITR')
    assert chip(pitr) == ('+1 new', 'No result in the previous scan (nothing to check then), so every finding is new')
    assert new_rows(pitr) == ['web-prod orders-db'] and resolved(pitr) is None
    _, rows, feet = changes_card(html)
    assert rows[RELIABILITY]['status_changes'] == ['Cloud SQL PITR no result → Action Required']
    assert (rows[RELIABILITY]['new'], rows[RELIABILITY]['resolved']) == ('1', DASH)
    assert (rows[COST]['new'], rows[COST]['resolved']) == (DASH, DASH)  # nothing resolved by VM Rightsizing's absence
    assert feet[0] == 'No result in this scan: VM Rightsizing.'
    assert csv_new_flags(csv_text, RELIABILITY, 'Cloud SQL PITR') == {'web-prod · orders-db': 'yes'}


@pytest.mark.parametrize('previous_release', ['15.4', None])
def test_across_releases_a_new_check_is_not_compared_and_a_missing_one_is_no_longer_checked(previous_release):
    """The previous scan by another release — or by one before v15.5, which named none — may not have had the check
    at all, so nothing is called new; a check it had and this release does not is no longer checked."""
    first = scan(sample_results(), 'job-1')[2]
    if previous_release:
        first['release'] = previous_release
    else:
        del first['release']
    results = sample_results()
    pitr_edit(results)
    html, csv_text, _ = scan(results, 'job-2', previous=first)
    pitr = item(html, RELIABILITY, 'Cloud SQL PITR')
    assert chip(pitr) == (NOT_COMPARED, 'Rows not compared: new check')
    assert new_rows(pitr) == []
    _, rows, feet = changes_card(html)
    assert rows[RELIABILITY]['status_changes'] == ['Cloud SQL PITR not compared (new check)']
    assert (rows[RELIABILITY]['new'], rows[RELIABILITY]['resolved']) == (DASH, DASH)
    assert feet[0] == 'No longer checked: VM Rightsizing.'
    assert csv_new_flags(csv_text, RELIABILITY, 'Cloud SQL PITR') == {'web-prod · orders-db': ''}


def test_the_card_folds_long_lists_of_status_changes():
    count = INLINE_STATUS_CHANGES + 2
    first_results = sample_results()
    first_results[OPERATIONS] = [{'Check': f'Check {i}', 'Status': 'Compliant', 'Finding': 'fine'} for i in range(count)]
    first = scan(first_results, 'job-1')[2]
    results = sample_results()
    results[OPERATIONS] = [{'Check': f'Check {i}', 'Status': 'Action Required', 'Finding': [{'Project': 'p', 'Issue': f'issue {i}'}]} for i in range(count)]
    html, _, _ = scan(results, 'job-2', previous=first)
    _, rows, _ = changes_card(html)
    operations = rows[OPERATIONS]
    assert operations['status_changes'] == [f'Check {i} Compliant → Action Required' for i in range(count)]
    assert operations['folded'] == '2 more'
    assert (operations['new'], operations['resolved'], operations['delta'], operations['delta_class']) == ('5', DASH, f'\u25bc {MINUS}100', 'down')


def test_the_card_states_the_population_when_it_changed():
    html, _, _ = two_scans(lambda results: None, total_projects=5)
    meta, _, _ = changes_card(html)
    assert meta.endswith('UTC · 4 projects then · 5 now')


def test_a_report_without_a_project_count_still_compares():
    """Project-scoped and older summaries may lack ``total_projects``: the card just omits the population."""
    first = scan(sample_results(), 'job-1', total_projects=None)[2]
    assert first['total_projects'] is None
    html, _, _ = scan(sample_results(), 'job-2', previous=first, total_projects=None)
    meta, rows, _ = changes_card(html)
    assert meta == f"compared with {first['generated_at']}" and len(rows) == 4


def test_a_summary_without_optional_fields_still_compares():
    """Only what ``compare`` reads is required: a trimmed or older summary must not cost the report."""
    first = {'version': 1, 'job_id': 'job-1', 'checks': {'Project IAM Hygiene': {'category': SECURITY, 'status': 'Compliant'}}}
    html, _, _ = scan(sample_results(), 'job-2', previous=first)
    assert chip(item(html, SECURITY, 'Project IAM Hygiene')) == ('+2 new', 'Was Compliant in the previous scan')
    assert chip(item(html, COST, 'Idle Persistent Disks')) == (NOT_COMPARED, 'Rows not compared: new check')  # it names no release
    assert previous_scan_line(html) == 'view'  # no time to show, but the link is there
    _, rows, _ = changes_card(html)
    assert all((row['delta'], row['delta_class']) == (DASH, 'flat') for row in rows.values())  # no previous scores


# --- The results store ---

def filed(store, prefix='scopes/'):
    return store.bucket().object_names(prefix)


def put_summary(store, ts, job_id, scope=SCOPE, scope_id=SCOPE_ID, body=None):
    name = f'scopes/{scope}/{scope_id}/{ts}_{job_id}.json'
    store.bucket().blob(name).upload_from_string(body if body is not None else json.dumps({'job_id': job_id, 'generated_ts': ts}), 'application/json')
    return name


def test_write_scan_summary_files_it_under_the_scope():
    store = memory_results_store()
    _, _, summary_doc = scan(sample_results(), 'job-1')
    store.write_scan_summary(summary_doc)
    (name,) = filed(store)
    assert re.fullmatch(rf'scopes/{SCOPE}/{SCOPE_ID}/\d{{8}}T\d{{6}}Z_job-1\.json', name)
    assert name == f"scopes/{SCOPE}/{SCOPE_ID}/{summary_doc['generated_ts']}_job-1.json"
    assert json.loads(store.bucket().blob(name).download_as_text()) == summary_doc
    assert store.bucket()._objects[name][1] == 'application/json'


def test_read_previous_summary_picks_the_newest_other_scan():
    store = memory_results_store()
    assert store.read_previous_summary(SCOPE, SCOPE_ID, 'job-1') is None  # nothing yet
    put_summary(store, '20260301T100000Z', 'job-2')  # written out of order, on purpose
    put_summary(store, '20260101T100000Z', 'job-1')
    put_summary(store, '20260201T100000Z', 'job_with_underscores')
    put_summary(store, '20260401T100000Z', 'other-scope', scope_id='999')
    put_summary(store, '20260401T100000Z', 'other-kind', scope='folder')
    assert store.read_previous_summary(SCOPE, SCOPE_ID, 'job-3')['job_id'] == 'job-2'  # the newest by name, not by write order
    assert store.read_previous_summary(SCOPE, SCOPE_ID, 'job-2')['job_id'] == 'job_with_underscores'  # a retried render skips itself
    assert store.read_previous_summary(SCOPE, SCOPE_ID, 'job_with_underscores')['job_id'] == 'job-2'
    assert store.read_previous_summary(SCOPE, '999', 'job-9')['job_id'] == 'other-scope'
    assert store.read_previous_summary('folder', SCOPE_ID, 'job-9')['job_id'] == 'other-kind'
    assert store.read_previous_summary('project', SCOPE_ID, 'job-9') is None


def test_read_previous_summary_never_raises(caplog):
    """A report without the comparison beats no report."""
    store = memory_results_store()
    put_summary(store, '20260101T100000Z', 'job-1')
    broken = put_summary(store, '20260201T100000Z', 'job-2', body='not json {')
    store.bucket().blob(f'scopes/{SCOPE}/{SCOPE_ID}/README.txt').upload_from_string('not a summary')
    assert store.read_previous_summary(SCOPE, SCOPE_ID, 'job-3') is None  # the newest is unreadable: logged, no silent fallback to an older scan
    assert 'Could not read the previous scan summary' in caplog.text
    store.bucket().delete_blobs([store.bucket().blob(broken)])
    assert store.read_previous_summary(SCOPE, SCOPE_ID, 'job-3')['job_id'] == 'job-1'  # the text file is not a summary


def test_write_scan_summary_never_raises(caplog):
    store = memory_results_store()

    def fail(*args, **kwargs):
        raise RuntimeError('bucket is read-only')
    store.bucket().blob = fail
    store.write_scan_summary({'job_id': 'job-1', 'scope': SCOPE, 'scope_id': SCOPE_ID, 'generated_ts': '20260101T100000Z'})
    assert 'Could not file the scan summary' in caplog.text and filed(store) == []
