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
"""The Essential Contacts check (v14 fix).

Beta v1 looked only at the *first* category of each contact and ignored
``ALL``, so an organization with one contact subscribed to
``[TECHNICAL, SECURITY, LEGAL]`` or to ``ALL`` was reported as missing
categories. The check now counts every subscription of every contact, treats
``ALL`` as covering everything, and requires ``SUSPENSION`` too.
"""
import json
from types import SimpleNamespace

import httplib2
import pytest
from googleapiclient.errors import HttpError

from app.checks.reliability import REQUIRED_CONTACT_CATEGORIES, check_essential_contacts, missing_contact_categories
from fakes import _execute

ORG, JOB = '987654321', 'job-14'


def contact(*categories):
    return {'name': f'organizations/{ORG}/contacts/{len(categories)}', 'email': 'ops@example.com',
            'notificationCategorySubscriptions': list(categories)}


@pytest.mark.parametrize('contacts, missing', [
    ([], ['SECURITY', 'TECHNICAL', 'LEGAL', 'SUSPENSION']),
    ([contact('TECHNICAL', 'SECURITY', 'LEGAL', 'SUSPENSION')], []),            # one contact, every category (beta saw only TECHNICAL)
    ([contact('ALL')], []),                                                       # ALL covers every category
    ([contact('BILLING'), contact('LEGAL', 'TECHNICAL')], ['SECURITY', 'SUSPENSION']),
    ([contact('SECURITY'), contact('TECHNICAL'), contact('LEGAL')], ['SUSPENSION']),  # v14: SUSPENSION is required too
    ([{'name': 'c', 'email': 'x@example.com'}], ['SECURITY', 'TECHNICAL', 'LEGAL', 'SUSPENSION']),  # no subscriptions at all
])
def test_missing_contact_categories(contacts, missing):
    assert missing_contact_categories(contacts) == missing


def test_required_categories_cover_security_outages_legal_and_suspension():
    assert REQUIRED_CONTACT_CATEGORIES == ('SECURITY', 'TECHNICAL', 'LEGAL', 'SUSPENSION')


class FakeEssentialContacts:
    def __init__(self, answer):
        self.answer, self.parents = answer, []

    def organizations(self):
        fake = self

        def list_contacts(parent):
            fake.parents.append(parent)
            return _execute(fake.answer)
        return SimpleNamespace(contacts=lambda: SimpleNamespace(list=list_contacts))


def run(gcp, answer):
    fake = FakeEssentialContacts(answer)
    gcp.discovery.apis['essentialcontacts'] = fake
    writes = []
    check_essential_contacts(ORG, JOB, sink=SimpleNamespace(write_finding=lambda job, name, record: writes.append((job, name, record))))
    assert fake.parents == [f'organizations/{ORG}']
    assert [(job, name) for job, name, _ in writes] == [(JOB, 'Essential_Contacts')]
    return writes[0][2]


def test_check_is_compliant_when_one_contact_covers_everything(gcp):
    record = run(gcp, {'contacts': [contact('ALL')]})
    assert record['Status'] == 'Compliant' and record['Check'] == 'Essential Contacts'
    assert record['Finding'] == [{'Status': 'A contact is subscribed to every key category (SECURITY, TECHNICAL, LEGAL, SUSPENSION).'}]


def test_check_names_the_missing_categories_with_a_fix(gcp):
    record = run(gcp, {'contacts': [contact('TECHNICAL', 'SECURITY')]})
    assert record['Status'] == 'Action Required'
    assert record['Finding'] == [{
        'Missing Categories': 'LEGAL, SUSPENSION',
        'Issue': "Nobody in the organization receives Google's notifications in these categories.",
        'Fix': f'gcloud essential-contacts create --organization={ORG} --email=<address> --notification-categories=LEGAL,SUSPENSION',
    }]


def test_check_reports_a_disabled_api_as_an_error(gcp):
    message = 'Essential Contacts API has not been used in project 123 before or it is disabled.'
    error = HttpError(httplib2.Response({'status': 403, 'reason': message}),
                      json.dumps({'error': {'code': 403, 'message': message}}).encode(), uri='https://essentialcontacts.googleapis.com/')
    record = run(gcp, error)
    assert record['Status'] == 'Error'
    assert record['Finding'] == [{'Error': 'The Essential Contacts API is not enabled. Please enable it to run this check.'}]
