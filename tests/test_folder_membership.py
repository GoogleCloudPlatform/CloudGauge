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
"""A folder scan's project list (``app.services.resource_manager``, v15.4): Cloud Asset
Inventory finds the folder's projects, recursively; Resource Manager's direct children
are compared with them, once per folder scan, and the report says what differed.

Cloud Asset Inventory is eventually consistent: a project moved into a folder was
missing from the folder-scoped search for about an hour (one moved out would linger
as long), while Resource Manager listed it at once. So a project Resource Manager
lists in the folder that Asset Inventory did not return is scanned too; a project
Asset Inventory still places in the folder that Resource Manager no longer lists
there is kept and noted; and when the two agree - the normal case - the report says
nothing. Organization and project scans are not concerned.
"""
import functools
import logging
import re
from html import unescape

import pytest

import fakes
from app import scan_job
from app.checks import runner
from app.checks.registry import CheckSpec
from app.reporting.context import FolderMembership, build_report_context
from app.reporting.html_report import generate_html_report, generate_reports
from app.reporting.scorecard import build_scorecard, markdown
from app.services.resource_manager import (ASSET_INVENTORY_ONLY, MEMBERSHIP, RESOURCE_MANAGER_ONLY, RESOURCE_MANAGER_PAGE_SIZE,
                                           folder_membership, list_projects_for_scope, parent_of)
from app.utils import ThrottledProgressReporter

FOLDER, PARENT, JOB = '42', 'folders/42', 'job-m1'
# Resource Manager's direct children, as v3 projects.list returns them.
WEB_PROD = {'projectId': 'web-prod', 'displayName': 'Web Prod', 'name': 'projects/111'}
MOVED_IN = {'projectId': 'moved-in', 'displayName': 'Moved In', 'name': 'projects/555'}


def membership_of(projects):
    """``{project_id: membership}`` of a project list; None when both sources list the project."""
    return {p['projectId']: p.get(MEMBERSHIP) for p in projects}


@pytest.fixture
def crm(gcp):
    """Resource Manager lists web-prod as the folder's one direct child, and Asset Inventory agrees."""
    manager = fakes.FakeResourceManager({}, children={PARENT: [WEB_PROD]})
    gcp.discovery.apis['cloudresourcemanager'] = manager
    gcp.assets.add('projects', 'web-prod', 'Web Prod', parent=PARENT)
    return manager


# --- The listing ---

def test_parent_of_reads_asset_searchs_parent():
    assert parent_of('//cloudresourcemanager.googleapis.com/folders/42') == 'folders/42'
    assert parent_of('//cloudresourcemanager.googleapis.com/organizations/1') == 'organizations/1'
    assert parent_of('') == '' and parent_of(None) == ''


def test_a_folder_scan_asks_resource_manager_once_and_says_nothing_when_they_agree(crm, capsys):
    projects = list_projects_for_scope('folder', FOLDER)
    assert projects == [{'projectId': 'web-prod', 'displayName': 'Web Prod', 'projectNumber': '', 'parent': PARENT}]
    assert crm.children_listed == [(PARENT, RESOURCE_MANAGER_PAGE_SIZE, None)]
    assert folder_membership(projects) is None
    assert 'Folder membership' not in capsys.readouterr().out


def test_a_project_resource_manager_lists_but_asset_inventory_misses_is_scanned_too(crm, capsys):
    """Moved into the folder, or created in it, and Asset Inventory has not caught up: appended, marked, logged."""
    crm.children[PARENT] = [WEB_PROD, MOVED_IN]
    projects = list_projects_for_scope('folder', FOLDER)
    assert membership_of(projects) == {'web-prod': None, 'moved-in': RESOURCE_MANAGER_ONLY}
    assert projects[1] == {'projectId': 'moved-in', 'displayName': 'Moved In', 'projectNumber': '555', 'parent': PARENT,
                           MEMBERSHIP: RESOURCE_MANAGER_ONLY}
    assert folder_membership(projects) == {'added': ['moved-in'], 'unlisted': []}
    assert ('⚠️ Folder membership: Cloud Asset Inventory and Resource Manager disagree on folder 42. '
            'Added from Resource Manager (not yet in Asset Inventory): moved-in. '
            'Listed by Asset Inventory only (no longer in the folder per Resource Manager): none.') in capsys.readouterr().out


def test_a_project_asset_inventory_still_places_in_the_folder_is_kept_and_noted(crm, gcp, capsys):
    """Moved out, deleted - or merely unreadable by the scanner, which is why it is not dropped."""
    gcp.assets.add('projects', 'moved-out', 'Moved Out', parent=PARENT)
    projects = list_projects_for_scope('folder', FOLDER)
    assert membership_of(projects) == {'web-prod': None, 'moved-out': ASSET_INVENTORY_ONLY}
    assert folder_membership(projects) == {'added': [], 'unlisted': ['moved-out']}
    assert ('Added from Resource Manager (not yet in Asset Inventory): none. '
            'Listed by Asset Inventory only (no longer in the folder per Resource Manager): moved-out.') in capsys.readouterr().out


def test_a_project_in_a_nested_folder_is_asset_inventorys_word_alone(crm, gcp):
    """Resource Manager lists one level: a project under a subfolder is no direct child, so its absence there means nothing."""
    gcp.assets.add('projects', 'deep', 'Deep', parent='folders/4242')
    projects = list_projects_for_scope('folder', FOLDER)
    assert membership_of(projects) == {'web-prod': None, 'deep': None}
    assert folder_membership(projects) is None


def test_only_active_children_are_added(crm):
    crm.children[PARENT] = [WEB_PROD, {**MOVED_IN, 'state': 'DELETE_REQUESTED'}]
    assert membership_of(list_projects_for_scope('folder', FOLDER)) == {'web-prod': None}


def test_every_page_of_resource_managers_answer_is_read(crm):
    crm.children[PARENT] = [WEB_PROD, MOVED_IN, {'projectId': 'third', 'displayName': 'Third', 'name': 'projects/333'}]
    crm.page_size = 2
    projects = list_projects_for_scope('folder', FOLDER)
    assert [p['projectId'] for p in projects] == ['web-prod', 'moved-in', 'third']
    assert crm.children_listed == [(PARENT, RESOURCE_MANAGER_PAGE_SIZE, None), (PARENT, RESOURCE_MANAGER_PAGE_SIZE, '2')]


def test_when_resource_manager_cannot_be_asked_asset_inventorys_list_stands(crm, gcp, caplog):
    gcp.assets.add('projects', 'moved-out', 'Moved Out', parent=PARENT)
    crm.children_error = RuntimeError('403 resourcemanager.projects.list denied')
    with caplog.at_level(logging.WARNING):
        projects = list_projects_for_scope('folder', FOLDER)
    assert membership_of(projects) == {'web-prod': None, 'moved-out': None}
    assert folder_membership(projects) is None
    assert ("⚠️ Could not list the folder's projects with Resource Manager; folder membership not checked: "
            "403 resourcemanager.projects.list denied") in caplog.text


def test_an_organization_scan_does_not_ask_resource_manager_for_children(crm):
    projects = list_projects_for_scope('organization', fakes.ORG_ID)
    assert membership_of(projects) == {'web-prod': None} and crm.children_listed == []


def test_folder_membership_sorts_the_ids_and_is_none_when_nothing_was_reconciled():
    projects = [{'projectId': 'b', MEMBERSHIP: RESOURCE_MANAGER_ONLY}, {'projectId': 'a', MEMBERSHIP: RESOURCE_MANAGER_ONLY},
                {'projectId': 'z', MEMBERSHIP: ASSET_INVENTORY_ONLY}, {'projectId': 'plain'}]
    assert folder_membership(projects) == {'added': ['a', 'b'], 'unlisted': ['z']}
    assert folder_membership([{'projectId': 'plain'}]) is None and folder_membership([]) is None


# --- The report ---

MEMBERSHIP_ROW = re.compile(r'<dt>Folder membership</dt><dd class="coverage coverage-incomplete">'
                            r'<span class="dot dot-investigation"></span>(.*?)</dd>', re.S)
MEMBERSHIP_NOTE = re.compile(r'<p role="note" class="coverage-note membership-note">\s*<span class="dot dot-investigation"></span>'
                             r'.*?<strong>Folder membership:</strong>(.*?)</span>', re.S)


def membership_line(html):
    """The header's Folder membership row as text; None when the report has none."""
    match = MEMBERSHIP_ROW.search(html)
    return ' '.join(unescape(match.group(1)).split()) if match else None


def membership_note(html):
    """The Overview's Folder membership note as one line of text; None without."""
    match = MEMBERSHIP_NOTE.search(html)
    return ' '.join(unescape(match.group(1)).split()) if match else None


def report(membership):
    html, _, _ = generate_reports('folder', FOLDER, JOB, {}, total_projects=2, membership=membership)
    return html


def test_the_report_says_nothing_when_the_sources_agree():
    for membership in (None, {'added': [], 'unlisted': []}):
        html = report(membership)
        assert 'Folder membership' not in html and 'membership-note' not in html
        assert '2 of 2 projects · folder-level checks completed' in html
    assert 'Folder membership' not in generate_html_report('folder', FOLDER, JOB, total_projects=2)


def test_the_header_row_and_the_overview_note_name_the_reconciled_projects():
    html = report({'added': ['moved-in'], 'unlisted': []})
    assert membership_line(html) == '1 project added from Resource Manager'
    assert membership_note(html) == ("Resource Manager places moved-in in this folder; Cloud Asset Inventory, which finds a folder's "
                                     "projects for the scan, does not list it yet (it can lag a move or a new project by an hour or "
                                     "more). It was scanned.")
    html = report({'added': [], 'unlisted': ['moved-out']})
    assert membership_line(html) == '1 project no longer in this folder per Resource Manager'
    assert membership_note(html) == ('Cloud Asset Inventory still places moved-out in this folder; Resource Manager no longer does '
                                     '(moved out, deleted, or not readable by the scanner). It was scanned anyway.')


def test_long_lists_are_counted_in_the_row_and_cut_short_in_the_note():
    html = report({'added': ['a', 'b', 'c', 'd'], 'unlisted': ['x', 'y']})
    assert membership_line(html) == '4 projects added from Resource Manager · 2 projects no longer in this folder per Resource Manager'
    note = membership_note(html)
    assert note.startswith('Resource Manager places a, b and 2 more in this folder;') and 'does not list them yet' in note
    assert 'They were scanned. Cloud Asset Inventory still places x and y in this folder;' in note
    assert note.endswith('They were scanned anyway.')


def test_the_view_model_drops_an_empty_reconciliation():
    assert FolderMembership.from_dict(None) is None and FolderMembership.from_dict({'added': [], 'unlisted': []}) is None
    assert FolderMembership.from_dict({'added': ['b', 'a']}) == FolderMembership(added=('b', 'a'), unlisted=())


def test_the_scorecard_markdown_carries_the_membership_line():
    """The Scorecard page sits under the report header; its Markdown copy has no header, so the line goes in its meta."""
    context = build_report_context('folder', FOLDER, JOB, {}, total_projects=2, membership={'added': ['moved-in'], 'unlisted': []})
    card = build_scorecard(context)
    assert card.coverage_text == '2 of 2 projects · 1 project added from Resource Manager'
    assert markdown(card).splitlines()[2] == f'Generated {card.generated_at} · 2 of 2 projects · 1 project added from Resource Manager'
    assert build_scorecard(build_report_context('folder', FOLDER, JOB, {}, total_projects=2)).coverage_text == '2 of 2 projects'


# --- The scan ---

def test_a_folder_scan_scans_the_project_resource_manager_adds_and_the_report_says_so(client, gcp, crm, monkeypatch, capsys):
    """Through ``/run-scan`` with the real project listing: Asset Inventory returns web-prod, Resource Manager also
    lists moved-in; the checks get both, the coverage counts both, the header and the Overview say what happened."""
    crm.children[PARENT] = [WEB_PROD, MOVED_IN]
    seen = {}

    def check(scope_id, all_projects, job_id, *, sink):
        sink.write_finding(job_id, 'Open_Firewall_Rules', {'Check': 'Open Firewall Rules', 'Status': 'Compliant', 'Finding': 'No rules allow 0.0.0.0/0.'})

    def plan(scope, scope_id, job_id, all_projects, *locations):
        seen['projects'] = all_projects
        return [CheckSpec('Security & Identity', 'Open Firewall Rules', check, (scope_id, all_projects, job_id))]

    monkeypatch.setattr(runner, 'get_active_compute_locations', lambda all_projects, on_error=None: ([], ['global']))
    monkeypatch.setattr(runner, 'build_check_plan', plan)
    monkeypatch.setattr(scan_job, 'ThrottledProgressReporter', functools.partial(ThrottledProgressReporter, clock=lambda: 1000.0))

    response = client.post('/run-scan', json={'scope': 'folder', 'scope_id': FOLDER, 'job_id': JOB})
    assert (response.status_code, response.get_data(as_text=True)) == (200, 'Scan completed and reports uploaded.')
    assert membership_of(seen['projects']) == {'web-prod': None, 'moved-in': RESOURCE_MANAGER_ONLY}
    html, _ = gcp.bucket.objects[f'{JOB}/{FOLDER}_report.html']
    assert '2 of 2 projects · folder-level checks completed' in html
    assert membership_line(html) == '1 project added from Resource Manager'
    assert membership_note(html).startswith('Resource Manager places moved-in in this folder;')
    assert '⚠️ Folder membership: Cloud Asset Inventory and Resource Manager disagree on folder 42.' in capsys.readouterr().out
