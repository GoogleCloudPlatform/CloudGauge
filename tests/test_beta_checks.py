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
"""The four Security checks ported from upstream beta v1 (``tests/legacy/cloudgauge_beta_v1.py``).

Each check runs in the frozen beta v1 module and in ``app.checks.security``
against the same fake Cloud SQL Admin, Compute, and Storage APIs, and both
must write the same finding. Explicit expectations document what they report.
The one intended difference: a project the check could not read is also
written as a "Projects not checked" record (``app.checks.not_checked``), where
beta v1 only logged it.
"""
from types import SimpleNamespace

import pytest

from app.checks import security
from app.checks.categories import CATEGORY_MAP, CATEGORY_ORDER, categorize_findings
from fakes import _execute

JOB_ID = 'job-42'
SCOPE_ID = '123456789'
WEB, LAKE, BROKEN = ({'projectId': 'web-prod'}, {'projectId': 'data-lake'}, {'projectId': 'locked-down'})
CHECKS = {  # function name -> (check name, finding file name)
    'check_cloud_sql_security': ('Cloud SQL Security', 'Cloud_SQL_Security'),
    'check_vpc_configuration': ('VPC Configuration', 'VPC_Configuration'),
    'check_storage_ubla': ('GCS Uniform Bucket-Level Access', 'GCS_Uniform_Bucket-Level_Access'),
    'check_vm_external_ips': ('VM External IPs', 'VM_External_IPs'),
}
DENIED = RuntimeError('403 The caller does not have permission')

SQL_INSTANCES = {
    'web-prod': {'items': [
        {'name': 'db-public', 'settings': {'ipConfiguration': {'ipv4Enabled': True, 'requireSsl': True}}},
        {'name': 'db-no-ssl', 'settings': {'ipConfiguration': {'ipv4Enabled': False}}},
        {'name': 'db-both', 'settings': {'ipConfiguration': {'ipv4Enabled': True, 'requireSsl': False}}},
        {'name': 'db-bare'},  # no settings: SSL is not enforced
    ]},
    'data-lake': {'items': [{'name': 'db-ok', 'settings': {'ipConfiguration': {'ipv4Enabled': False, 'requireSsl': True}}}]},
    'locked-down': DENIED,
}
NETWORKS = {
    'web-prod': {'items': [{'name': 'default'}, {'name': 'prod-vpc'}]},
    'data-lake': {'items': [{'name': 'lake-vpc'}]},
    'locked-down': DENIED,
}
SUBNETS = {  # project -> region -> subnetworks
    'web-prod': {'us-central1': [{'name': 'web-a', 'privateIpGoogleAccess': True}, {'name': 'web-b'}],
                 'europe-west1': [{'name': 'web-c', 'privateIpGoogleAccess': False}], 'asia-south1': []},
    'data-lake': {'us-central1': [{'name': 'lake-a', 'privateIpGoogleAccess': True}]},
}
INSTANCE_PAGES = {  # project -> pages of instances().aggregatedList
    'web-prod': [
        {'items': {'zones/us-central1-a': {'instances': [
            {'name': 'web-1', 'networkInterfaces': [{'network': 'prod-vpc', 'accessConfigs': [{'natIP': '203.0.113.7'}]}]},
            {'name': 'web-2', 'networkInterfaces': [{'network': 'prod-vpc'}]},
        ]}, 'zones/us-east1-b': {'warning': {'code': 'NO_RESULTS_ON_PAGE'}}}},
        {'items': {'zones/europe-west1-b': {'instances': [
            {'name': 'web-3', 'networkInterfaces': [{'network': 'a'}, {'network': 'b', 'accessConfigs': []}]},  # key present: counted
            {'name': 'batch-1'},  # no interfaces
        ]}}},
    ],
    'data-lake': [{'items': {'zones/us-central1-a': {'instances': [{'name': 'lake-1', 'networkInterfaces': [{}]}]}}}, {}],
    'locked-down': DENIED,
}


def bucket(name, ubla):
    return SimpleNamespace(name=name, iam_configuration=SimpleNamespace(uniform_bucket_level_access_enabled=ubla))


BUCKETS = {
    'web-prod': [bucket('web-assets', False), bucket('web-logs', True), bucket('web-backups', False)],
    'data-lake': [bucket('lake-raw', True)],
    'locked-down': DENIED,
}


class FakeSqlAdmin:
    """``sqladmin v1beta4``: instances().list()."""

    def instances(self):
        return SimpleNamespace(list=lambda project: _execute(SQL_INSTANCES.get(project, {})))


class FakeCompute:
    """``compute v1``: networks, regions, subnetworks, and instances().aggregatedList with paging."""

    def networks(self):
        return SimpleNamespace(list=lambda project: _execute(NETWORKS.get(project, {})))

    def regions(self):
        return SimpleNamespace(list=lambda project: _execute({'items': [{'name': r} for r in SUBNETS.get(project, {})]}))

    def subnetworks(self):
        return SimpleNamespace(list=lambda project, region: _execute({'items': SUBNETS[project][region]}))

    def instances(self):
        return SimpleNamespace(aggregatedList=self._aggregated_list, aggregatedList_next=self._aggregated_list_next)

    @staticmethod
    def _page(project, index):
        pages = INSTANCE_PAGES.get(project, [{}])
        request = _execute(pages if isinstance(pages, Exception) else pages[index])
        request.project, request.index = project, index
        request.last = not isinstance(pages, Exception) and index == len(pages) - 1
        return request

    def _aggregated_list(self, project):
        return self._page(project, 0)

    def _aggregated_list_next(self, previous_request, previous_response):
        return None if previous_request.last else self._page(previous_request.project, previous_request.index + 1)


@pytest.fixture
def apis(gcp):
    gcp.discovery.apis.update(sqladmin=FakeSqlAdmin(), compute=FakeCompute())
    gcp.storage.listings.update(BUCKETS)
    return gcp


def run_new(name, projects):
    writes = []
    sink = SimpleNamespace(write_finding=lambda *args: writes.append(args))
    getattr(security, name)(SCOPE_ID, projects, JOB_ID, sink=sink)
    return writes


def run_beta(beta, name, projects, monkeypatch):
    writes = []
    monkeypatch.setattr(beta, '_write_finding_to_gcs', lambda *args: writes.append(args))
    getattr(beta, name)(SCOPE_ID, projects, JOB_ID)
    return writes


def split_not_checked(writes):
    """``(the check's own writes, the "Projects not checked" writes)``."""
    skipped = [w for w in writes if w[1].startswith('NOT_CHECKED_')]
    return [w for w in writes if w not in skipped], skipped


@pytest.mark.parametrize('projects', [[WEB, LAKE, BROKEN], [LAKE], [BROKEN], []], ids=['findings', 'compliant', 'errors only', 'no projects'])
@pytest.mark.parametrize('name', CHECKS)
def test_check_matches_beta_v1(name, projects, apis, beta, monkeypatch):
    """The check's own record is beta v1's; the projects it could not check are a second record (beta had none)."""
    new, skipped = split_not_checked(run_new(name, projects))
    assert new == run_beta(beta, name, projects, monkeypatch)
    check_name, file_name = CHECKS[name]
    ((job_id, written_name, finding),) = new
    assert (job_id, written_name, finding['Check']) == (JOB_ID, file_name, check_name)
    assert finding['Status'] == ('Action Required' if WEB in projects else 'Compliant')
    if BROKEN in projects:
        assert skipped == [(JOB_ID, f'NOT_CHECKED_{file_name}', {
            'Check': 'Projects not checked', 'Category': 'Security & Identity', 'Status': 'Error',
            'Finding': [{'Project': 'locked-down', 'Skipped check': check_name, 'Reason': '403 The caller does not have permission'}]})]
    else:
        assert skipped == []


def findings_of(name, projects=(WEB, LAKE, BROKEN)):
    ((_, _, finding),), _ = split_not_checked(run_new(name, list(projects)))
    return finding['Finding']


def test_cloud_sql_security_findings(apis):
    assert findings_of('check_cloud_sql_security') == [
        {'Project': 'web-prod', 'Instance': 'db-public', 'Issue': 'Public IP enabled.'},
        {'Project': 'web-prod', 'Instance': 'db-no-ssl', 'Issue': 'SSL not enforced.'},
        {'Project': 'web-prod', 'Instance': 'db-both', 'Issue': 'Public IP enabled.'},
        {'Project': 'web-prod', 'Instance': 'db-both', 'Issue': 'SSL not enforced.'},
        {'Project': 'web-prod', 'Instance': 'db-bare', 'Issue': 'SSL not enforced.'},
    ]
    assert findings_of('check_cloud_sql_security', [LAKE]) == [
        {'Status': 'All Cloud SQL instances have Public IP disabled and SSL enforced.'}]
    assert ('sqladmin', 'v1beta4') in apis.discovery.calls


def test_vpc_configuration_findings(apis):
    assert findings_of('check_vpc_configuration') == [
        {'Project': 'web-prod', 'Network': 'default', 'Issue': 'Default VPC network exists.'},
        {'Project': 'web-prod', 'Subnet': 'web-b', 'Issue': 'Private Google Access disabled.'},
        {'Project': 'web-prod', 'Subnet': 'web-c', 'Issue': 'Private Google Access disabled.'},
    ]
    assert findings_of('check_vpc_configuration', [LAKE]) == [
        {'Status': 'No default VPCs found and all subnets have Private Google Access.'}]


def test_storage_ubla_findings(apis):
    assert findings_of('check_storage_ubla') == [
        {'Project': 'web-prod', 'Bucket': 'web-assets', 'Issue': 'UBLA not enabled.'},
        {'Project': 'web-prod', 'Bucket': 'web-backups', 'Issue': 'UBLA not enabled.'},
    ]
    assert findings_of('check_storage_ubla', [LAKE]) == [{'Status': 'All buckets have Uniform Bucket-Level Access enabled.'}]


def test_vm_external_ips_findings_across_pages(apis):
    assert findings_of('check_vm_external_ips') == [
        {'Project': 'web-prod', 'VM': 'web-1', 'Issue': 'Has external IP address.'},
        {'Project': 'web-prod', 'VM': 'web-3', 'Issue': 'Has external IP address.'},  # second page
    ]
    assert findings_of('check_vm_external_ips', [LAKE]) == [{'Status': 'No VMs with external IP addresses found.'}]


@pytest.mark.parametrize('name', CHECKS)
def test_a_project_that_fails_is_logged_skipped_and_reported(name, apis, caplog):
    """As in beta v1, the error is logged and the other projects' results still count;
    unlike beta v1, the skipped project is reported instead of passing as compliant."""
    check_name, _ = CHECKS[name]
    assert findings_of(name, [BROKEN, LAKE]) == findings_of(name, [LAKE])
    assert f'Could not check {check_name} for locked-down: 403 The caller does not have permission' in caplog.text
    _, skipped = split_not_checked(run_new(name, [BROKEN, LAKE]))
    assert [row['Project'] for (_, _, record) in skipped for row in record['Finding']] == ['locked-down']


def test_findings_are_reported_under_security():
    """Beta v1 left these names out of its category map, so its reports dropped the findings."""
    for check_name, _ in CHECKS.values():
        assert CATEGORY_MAP[check_name] == 'Security & Identity'
    assert CATEGORY_ORDER[0] == 'Security & Identity'
    findings = [{'Check': check_name, 'Status': 'Compliant', 'Finding': []} for check_name, _ in CHECKS.values()]
    assert categorize_findings(findings)['Security & Identity'] == findings
