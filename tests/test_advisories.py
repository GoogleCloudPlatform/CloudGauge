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
"""``app.checks.advisories``: the Advisory Notifications briefing and the
Advisory Notifications Settings check (v14), at the organization and per project.

A fake discovery client answers ``notifications.list`` (paged) and
``getSettings`` per parent; the tests look at the records the checks write.
"""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httplib2
import pytest
from googleapiclient.errors import HttpError

from app.checks.advisories import (ADVISORIES_CHECK, MAX_ATTACHMENT_ROWS, MAX_SUMMARY_LENGTH, ORG_ONLY_NOTE, SETTINGS_CHECK,
                                   SETTINGS_FIX, check_org_advisories, check_project_advisories, html_to_lines, notification_row,
                                   settings_rows, strip_html, summarize_attachments, summarize_sensitive_actions)
from app.checks.categories import merge_shard_findings
from app.checks.not_checked import NOT_CHECKED
from fakes import _execute

JOB = 'job-14'
ORG = '987654321'
ORG_PARENT = f'organizations/{ORG}/locations/global'
PROJECTS = [{'projectId': 'web-prod', 'projectNumber': '111'}, {'projectId': 'data-lake', 'projectNumber': '222'},
            {'projectId': 'no-number', 'projectNumber': ''}, {'projectId': 'locked-down', 'projectNumber': '444'}]
DENIED = 'The caller does not have permission'
DISABLED = ("Advisory Notifications API has not been used in project {p} before or it is disabled. Enable it by visiting "
            "https://console.developers.google.com/apis/api/advisorynotifications.googleapis.com/overview?project={p} then retry.")
SENSITIVE_BODY = ('<div class="report-intro"><p>The following sensitive actions were detected.</p></div>'
                  '<h2>Organization policy updated</h2><p>Policy: constraints/iam.allowedPolicyMemberDomains</p>'
                  '<p>Policy action: Updated</p><p>This action was taken 4 times</p><p>By: admin@example.com</p><p>By: ops@example.com</p>'
                  '<h2>Owner role granted</h2><p>This action was taken 1 time</p><p>By: admin@example.com</p>')


def days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S.000000Z')


def notification(kind, subject, days, body='<p>Body.</p>', attachments=()):
    return {
        'name': f'{ORG_PARENT}/notifications/{subject[:8]}', 'notificationType': kind, 'createTime': days_ago(days),
        'subject': {'text': {'enText': subject}},
        'messages': [{'body': {'text': {'enText': body}},
                      'attachments': [{'displayName': name, 'csv': {'headers': list(headers), 'dataRows': [{'entries': list(r)} for r in rows]}}
                                      for name, headers, rows in attachments]}],
    }


MSA = notification('NOTIFICATION_TYPE_SECURITY_MSA', 'MSA: move off TLS 1.0', 20, '<p>Google <b>will</b> stop accepting TLS 1.0.</p><p>Act now.</p>',
                   [('instances.csv', ('Project', 'Instance'), (('p-1', 'sql-0'), ('p-2', 'sql-1'), ('p-3', 'sql-2'), ('p-4', 'sql-3')))])
DIGEST = notification('NOTIFICATION_TYPE_SENSITIVE_ACTIONS', 'Sensitive actions were taken', 5, SENSITIVE_BODY)
ADVISORY = notification('NOTIFICATION_TYPE_SECURITY_PRIVACY_ADVISORY', 'Security advisory: CVE-2026-0101', 60, '<p>Upgrade GKE nodes.</p>')
OLD = notification('NOTIFICATION_TYPE_THREAT_HORIZONS', 'Threat Horizons Report', 400)
ALL_ON = {'notificationSettings': {kind: {'enabled': True} for kind in (
    'NOTIFICATION_TYPE_SECURITY_MSA', 'NOTIFICATION_TYPE_SECURITY_PRIVACY_ADVISORY', 'NOTIFICATION_TYPE_SENSITIVE_ACTIONS', 'NOTIFICATION_TYPE_THREAT_HORIZONS')}}
HORIZONS_OFF = {'notificationSettings': {**ALL_ON['notificationSettings'], 'NOTIFICATION_TYPE_THREAT_HORIZONS': {'enabled': False}}}


def http_error(status, message):
    content = json.dumps({'error': {'code': status, 'message': message}}).encode()
    return HttpError(httplib2.Response({'status': status, 'reason': message}), content, uri='https://advisorynotifications.googleapis.com/')


class FakeAdvisories:
    """``advisorynotifications v1``: ``notifications.list`` pages per parent and ``getSettings`` per name, or an exception."""

    def __init__(self):
        self.notifications = {}  # parent -> [page, ...] or Exception
        self.settings = {}  # settings name -> dict or Exception
        self.list_calls = []  # (parent, view, pageSize, pageToken)

    def organizations(self):
        return self._level()

    def projects(self):
        return self._level()

    def _level(self):
        fake = self

        class Locations:
            def notifications(self):
                return SimpleNamespace(list=fake._list)

            def getSettings(self, name):
                return _execute(fake.settings.get(name, {}))

        return SimpleNamespace(locations=Locations)

    def _list(self, parent, view, pageSize, pageToken=None):
        self.list_calls.append((parent, view, pageSize, pageToken))
        answer = self.notifications.get(parent, [{}])
        if isinstance(answer, Exception):
            return _execute(answer)
        index = int(pageToken or 0)
        page = dict(answer[index])
        if index + 1 < len(answer):
            page['nextPageToken'] = str(index + 1)
        return _execute(page)


@pytest.fixture
def api(gcp):
    fake = FakeAdvisories()
    gcp.discovery.apis['advisorynotifications'] = fake
    return fake


def run(check, *args):
    writes = []
    sink = SimpleNamespace(write_finding=lambda job, name, record: writes.append((name, record)))
    check(*args, JOB, sink=sink)
    return dict(writes), [name for name, _ in writes]


# --- Rows ---

def test_html_bodies_become_text():
    assert html_to_lines('<p>One <b>two</b></p><style>x{}</style><ul><li>three</li><li>four &amp; five</li></ul>') == ['One two', 'three', 'four & five']
    assert strip_html('plain  text\n here') == 'plain text here' and html_to_lines('') == []


def test_notification_row_summarizes_the_body_and_the_attachments():
    """The message keeps a line per paragraph and the attachments a line per row: nothing is cut for the page's
    sake (v14.1; the report lays the lines out, the CSV quotes them)."""
    row = notification_row(MSA)
    assert row == {'Date': MSA['createTime'][:10], 'Type': 'Mandatory Service Announcement', 'Subject': 'MSA: move off TLS 1.0',
                   'Summary': 'Google will stop accepting TLS 1.0.\nAct now.',
                   'Details': '4 affected resource rows (instances.csv)\nProject: p-1; Instance: sql-0\nProject: p-2; Instance: sql-1\n'
                              'Project: p-3; Instance: sql-2\nProject: p-4; Instance: sql-3'}
    assert summarize_attachments([]) == '' and summarize_attachments([{'attachments': [{'displayName': 'empty.csv', 'csv': {}}]}]) == '0 affected resource rows (empty.csv)'
    # Past MAX_ATTACHMENT_ROWS rows, the rest is a count.
    big = notification('NOTIFICATION_TYPE_SECURITY_MSA', 's', 1, attachments=[('big.csv', ('Project',), tuple((f'p-{i}',) for i in range(MAX_ATTACHMENT_ROWS + 5)))])
    lines = summarize_attachments(big['messages']).split('\n')
    assert lines[0] == f'{MAX_ATTACHMENT_ROWS + 5} affected resource rows (big.csv)' and lines[1] == 'Project: p-0'
    assert len(lines) == MAX_ATTACHMENT_ROWS + 2 and lines[-1] == '(+5 more)'
    assert notification_row({})['Subject'] == '(no subject)' and notification_row({})['Type'] == 'Unknown'
    assert notification_row({'notificationType': 'NOTIFICATION_TYPE_NEW_KIND'})['Type'] == 'New Kind'
    # A long message is kept whole; only the safety cap cuts it.
    long = notification_row(notification('NOTIFICATION_TYPE_SECURITY_MSA', 's', 1, '<p>' + 'word ' * 200 + '</p>'))
    assert long['Summary'] == ('word ' * 200).strip()
    huge = notification_row(notification('NOTIFICATION_TYPE_SECURITY_MSA', 's', 1, '<p>' + 'word ' * 2000 + '</p>'))
    assert len(huge['Summary']) == MAX_SUMMARY_LENGTH and huge['Summary'].endswith('...')


def test_sensitive_actions_digest_lists_actions_and_actors():
    row = notification_row(DIGEST)
    assert row['Type'] == 'Sensitive Actions'
    assert row['Details'] == 'Organization policy updated (x4)\nOwner role granted (x1)\nby admin@example.com, ops@example.com'
    assert summarize_sensitive_actions(['nothing here']) == ''


def test_settings_rows_name_the_types_turned_off():
    assert settings_rows(ALL_ON) == [] and settings_rows({}) == []
    assert settings_rows(HORIZONS_OFF) == [{'Type': 'Threat Horizons', 'Issue': 'Threat Horizons notifications are turned off, so nobody receives them.',
                                            'Fix': SETTINGS_FIX}]


# --- The organization check ---

def test_org_check_writes_the_briefing_newest_first_and_the_settings(api):
    api.notifications[ORG_PARENT] = [{'notifications': [ADVISORY, OLD]}, {'notifications': [MSA, DIGEST]}]  # two pages
    api.settings[f'{ORG_PARENT}/settings'] = ALL_ON
    records, names = run(check_org_advisories, ORG)
    assert names == ['Advisory_Notifications', 'Advisory_Notifications_Settings']
    assert [call[1:] for call in api.list_calls] == [('FULL', 50, None), ('FULL', 50, '1')]
    briefing = records['Advisory_Notifications']
    assert briefing['Check'] == ADVISORIES_CHECK and briefing['Status'] == 'Informational'  # a briefing, never scored
    assert [r['Subject'] for r in briefing['Finding']] == ['Sensitive actions were taken', 'MSA: move off TLS 1.0', 'Security advisory: CVE-2026-0101']
    assert [r['Type'] for r in briefing['Finding']] == ['Sensitive Actions', 'Mandatory Service Announcement', 'Security & Privacy Advisory']
    assert 'Projects' not in briefing['Finding'][0]  # an organization's notifications have no project column
    assert records['Advisory_Notifications_Settings'] == {
        'Check': SETTINGS_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': 'Every advisory notification type is turned on for this organization.'}]}


def test_org_check_scores_a_type_turned_off_and_notes_an_empty_window(api, monkeypatch):
    monkeypatch.setenv('ADVISORY_WINDOW_DAYS', '10')
    api.notifications[ORG_PARENT] = [{'notifications': [MSA, ADVISORY]}]  # both older than 10 days
    api.settings[f'{ORG_PARENT}/settings'] = HORIZONS_OFF
    records, _ = run(check_org_advisories, ORG)
    assert records['Advisory_Notifications']['Finding'] == [{'Summary': 'No advisory notifications were published for this organization in the last 10 days.'}]
    settings = records['Advisory_Notifications_Settings']
    assert settings['Status'] == 'Action Required' and [r['Type'] for r in settings['Finding']] == ['Threat Horizons']


def test_org_check_reports_the_permission_or_api_to_fix(api):
    api.notifications[ORG_PARENT] = http_error(403, DENIED)
    api.settings[f'{ORG_PARENT}/settings'] = http_error(403, DISABLED.format(p='cloudgauge-host'))
    records, _ = run(check_org_advisories, ORG)
    briefing, settings = records['Advisory_Notifications'], records['Advisory_Notifications_Settings']
    assert briefing['Status'] == settings['Status'] == 'Error'
    assert briefing['Finding'] == [{'Error': f'403 {DENIED} The scanner\'s service account needs the advisorynotifications.notifications.list '
                                             'permission on the scanned scope (see the CloudGauge Advisory Notifications Viewer custom role in the README).'}]
    (row,) = settings['Finding']
    assert row['Error'].startswith('403 Advisory Notifications API has not been used in project cloudgauge-host')
    assert row['Error'].endswith('Enable the Advisory Notifications API in the CloudGauge project: gcloud services enable advisorynotifications.googleapis.com')


def test_org_check_without_a_client_writes_both_errors(gcp, monkeypatch):
    from app.services import gcp as gcp_module
    monkeypatch.setattr(gcp_module, 'api_build', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('no discovery document')))
    records, names = run(check_org_advisories, ORG)
    assert names == ['Advisory_Notifications', 'Advisory_Notifications_Settings']
    assert all(r == {'Check': c, 'Status': 'Error', 'Finding': [{'Error': 'no discovery document'}]}
               for r, c in zip(records.values(), (ADVISORIES_CHECK, SETTINGS_CHECK)))


# --- The per-project check (folder and project scans) ---

def test_project_check_folds_notifications_across_projects_and_scores_settings_per_project(api):
    api.notifications['projects/111/locations/global'] = [{'notifications': [ADVISORY, OLD]}]
    api.notifications['projects/222/locations/global'] = [{'notifications': [ADVISORY]}]
    api.notifications['projects/444/locations/global'] = http_error(403, DENIED)
    api.settings['projects/111/locations/global/settings'] = ALL_ON
    api.settings['projects/222/locations/global/settings'] = HORIZONS_OFF
    api.settings['projects/444/locations/global/settings'] = http_error(403, DENIED)
    records, names = run(check_project_advisories, 'folder-1', PROJECTS)
    assert names == ['Advisory_Notifications', 'Advisory_Notifications_Settings',
                     'NOT_CHECKED_Advisory_Notifications', 'NOT_CHECKED_Advisory_Notifications_Settings']
    assert {call[0] for call in api.list_calls} == {'projects/111/locations/global', 'projects/222/locations/global', 'projects/444/locations/global'}  # by number
    briefing = records['Advisory_Notifications']
    assert briefing['Status'] == 'Informational'
    assert [(r['Projects'], r['Subject'], r['Type']) for r in briefing['Finding']] == \
           [('web-prod, data-lake', 'Security advisory: CVE-2026-0101', 'Security & Privacy Advisory')]  # one row, both projects
    settings = records['Advisory_Notifications_Settings']
    assert settings['Status'] == 'Action Required'
    assert settings['Finding'] == [{'Project': 'data-lake', 'Type': 'Threat Horizons',
                                    'Issue': 'Threat Horizons notifications are turned off, so nobody receives them.', 'Fix': SETTINGS_FIX}]
    for name, check in (('NOT_CHECKED_Advisory_Notifications', ADVISORIES_CHECK), ('NOT_CHECKED_Advisory_Notifications_Settings', SETTINGS_CHECK)):
        record = records[name]
        assert (record['Check'], record['Category'], record['Status']) == (NOT_CHECKED, 'Security & Identity', 'Error')
        assert [(r['Project'], r['Skipped check']) for r in record['Finding']] == [('no-number', check), ('locked-down', check)]
        assert record['Finding'][0]['Reason'].startswith('the project number is not known')
        assert record['Finding'][1]['Reason'] == f'403 {DENIED}'


def test_project_check_notes_an_empty_window_and_points_to_the_organization_scan(api):
    api.settings['projects/111/locations/global/settings'] = ALL_ON
    records, names = run(check_project_advisories, 'web-prod', PROJECTS[:1])
    assert names == ['Advisory_Notifications', 'Advisory_Notifications_Settings']
    (note,) = records['Advisory_Notifications']['Finding']
    assert note['Summary'] == f'No advisory notifications were published for these projects in the last 365 days. {ORG_ONLY_NOTE}'
    assert records['Advisory_Notifications_Settings'] == {
        'Check': SETTINGS_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': 'Every advisory notification type is turned on in every checked project.'}]}


def test_project_check_stops_when_the_api_is_disabled_for_the_scanner(api):
    """A disabled-API answer naming a project other than the scanned one is CloudGauge's own project: every
    project would fail alike, so both records say so once and no project is listed as skipped."""
    for project in PROJECTS:
        api.notifications[f"projects/{project['projectNumber']}/locations/global"] = http_error(403, DISABLED.format(p='cloudgauge-host'))
    records, names = run(check_project_advisories, 'folder-1', PROJECTS)
    assert names == ['Advisory_Notifications', 'Advisory_Notifications_Settings'] and len(api.list_calls) == 1
    for record in records.values():
        assert record['Status'] == 'Error' and record['Finding'][0]['Error'].endswith('gcloud services enable advisorynotifications.googleapis.com')


def test_project_check_treats_a_disabled_api_in_the_project_itself_as_that_projects_skip(api):
    api.notifications['projects/111/locations/global'] = http_error(403, DISABLED.format(p='111'))
    api.notifications['projects/222/locations/global'] = [{'notifications': [MSA]}]
    api.settings['projects/111/locations/global/settings'] = ALL_ON
    api.settings['projects/222/locations/global/settings'] = ALL_ON
    records, names = run(check_project_advisories, 'folder-1', PROJECTS[:2])
    assert names == ['Advisory_Notifications', 'Advisory_Notifications_Settings', 'NOT_CHECKED_Advisory_Notifications']
    assert [r['Projects'] for r in records['Advisory_Notifications']['Finding']] == ['data-lake']
    assert [r['Project'] for r in records['NOT_CHECKED_Advisory_Notifications']['Finding']] == ['web-prod']


# --- Across shards ---

def test_advisory_rows_of_several_shards_fold_into_one():
    """Two shards saw the same project-level advisory from their own projects: one row naming all of them, newest first;
    a shard's "nothing in the window" note is dropped when another shard had rows."""
    row = {'Projects': 'p-1', 'Date': '2026-08-01', 'Type': 'Security & Privacy Advisory', 'Subject': 'CVE-2026-0101', 'Summary': 's', 'Details': ''}
    newer = {**row, 'Projects': 'p-5', 'Date': '2026-09-01', 'Subject': 'MSA'}
    note = {'Summary': 'No advisory notifications ...'}
    shards = [{'Check': ADVISORIES_CHECK, 'Status': 'Informational', 'Finding': [row]},
              {'Check': ADVISORIES_CHECK, 'Status': 'Informational', 'Finding': [note]},
              {'Check': ADVISORIES_CHECK, 'Status': 'Informational', 'Finding': [{**row, 'Projects': 'p-7, p-1'}, newer]}]
    (merged,) = merge_shard_findings(shards)
    assert merged['Finding'] == [newer, {**row, 'Projects': 'p-1, p-7'}]
    assert merge_shard_findings(shards[1:2]) == shards[1:2]
