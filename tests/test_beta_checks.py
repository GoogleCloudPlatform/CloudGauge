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

Until v18 each ran in the frozen beta v1 module and in ``app.checks.security`` against the same fakes and had to
write the same finding — which froze beta v1's defects along with its behaviour. All four have since left the parity
by design: Cloud SQL Security and VM External IPs in v18 (``requireSsl``, access-config presence), VPC Configuration and
Uniform Bucket-Level Access in v18.1 (subnet purposes and the aggregated listing; a ``Fix`` column). Their rules are tested
in ``tests/test_revalidated_checks.py`` and ``tests/test_loose_rules.py``; this module keeps what the four still share
with beta v1 — the shape of their records, their names under Security, and the "skipped project" contract: a project
the check could not read is a *Projects not checked* record (``app.checks.not_checked``), where beta v1 only logged it.
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
        {'name': 'db-bare'},  # no settings: an instance mid-operation, no rows
    ]},
    'data-lake': {'items': [{'name': 'db-ok', 'settings': {'ipConfiguration': {'ipv4Enabled': False, 'requireSsl': True}}}]},
    'locked-down': DENIED,
}
NETWORKS = {
    'web-prod': {'items': [{'name': 'default'}, {'name': 'prod-vpc'}]},
    'data-lake': {'items': [{'name': 'lake-vpc'}]},
    'locked-down': DENIED,
}


def subnet(name, region, network, pga=None, purpose='PRIVATE'):
    entry = {'name': name, 'region': f'https://www.googleapis.com/compute/v1/projects/p/regions/{region}',
             'network': f'https://www.googleapis.com/compute/v1/projects/p/global/networks/{network}', 'purpose': purpose}
    if pga is not None:
        entry['privateIpGoogleAccess'] = pga
    return entry


SUBNETS = {  # project -> the aggregated listing
    'web-prod': {'items': {'regions/us-central1': {'subnetworks': [subnet('web-a', 'us-central1', 'prod-vpc', True), subnet('web-b', 'us-central1', 'prod-vpc'),
                                                                   subnet('default', 'us-central1', 'default', False)]},
                           'regions/europe-west1': {'subnetworks': [subnet('web-c', 'europe-west1', 'prod-vpc', False),
                                                                    subnet('proxy', 'europe-west1', 'prod-vpc', False, purpose='REGIONAL_MANAGED_PROXY')]},
                           'regions/asia-south1': {'warning': {'code': 'NO_RESULTS_ON_PAGE'}}}},
    'data-lake': {'items': {'regions/us-central1': {'subnetworks': [subnet('lake-a', 'us-central1', 'lake-vpc', True)]}}},
    'locked-down': DENIED,
}
INSTANCE_PAGES = {  # project -> pages of instances().aggregatedList
    'web-prod': [
        {'items': {'zones/us-central1-a': {'instances': [
            {'name': 'web-1', 'networkInterfaces': [{'network': 'prod-vpc', 'accessConfigs': [{'natIP': '203.0.113.7'}]}]},
            {'name': 'web-2', 'networkInterfaces': [{'network': 'prod-vpc'}]},
        ]}, 'zones/us-east1-b': {'warning': {'code': 'NO_RESULTS_ON_PAGE'}}}},
        {'items': {'zones/europe-west1-b': {'instances': [
            {'name': 'web-3', 'networkInterfaces': [{'network': 'a'}, {'network': 'b', 'accessConfigs': []}]},  # key present, no address: not a row since v18
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
    """``sqladmin v1``: instances().list(), one page."""

    def instances(self):
        return SimpleNamespace(list=lambda project: _execute(SQL_INSTANCES.get(project, {})), list_next=lambda previous_request, previous_response: None)


class FakeCompute:
    """``compute v1``: networks, subnetworks.aggregatedList, and instances().aggregatedList with paging."""

    def networks(self):
        return SimpleNamespace(list=lambda project: _execute(NETWORKS.get(project, {})), list_next=lambda previous_request, previous_response: None)

    def subnetworks(self):
        return SimpleNamespace(aggregatedList=lambda project: _execute(SUBNETS.get(project, {})), aggregatedList_next=lambda previous_request, previous_response: None)

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


def split_not_checked(writes):
    """``(the check's own writes, the "Projects not checked" writes)``."""
    skipped = [w for w in writes if w[1].startswith('NOT_CHECKED_')]
    return [w for w in writes if w not in skipped], skipped


@pytest.mark.parametrize('projects', [[WEB, LAKE, BROKEN], [LAKE], [BROKEN], []], ids=['findings', 'compliant', 'errors only', 'no projects'])
@pytest.mark.parametrize('name', CHECKS)
def test_each_check_writes_one_record_and_the_skipped_projects(name, projects, apis):
    """One record under the check's name and file; the projects it could not check in a second record (beta v1 had none)."""
    new, skipped = split_not_checked(run_new(name, projects))
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
    """v18: ``sslMode`` first, ``requireSsl`` only without it; an instance without settings has no rows (beta v1 flagged it)."""
    rows = findings_of('check_cloud_sql_security')
    assert [(r['Instance'], r['Issue'].split(':')[0]) for r in rows] == [
        ('db-public', 'Public IP enabled.'), ('db-no-ssl', 'TLS not enforced'), ('db-both', 'TLS not enforced'), ('db-both', 'Public IP enabled.')]
    assert findings_of('check_cloud_sql_security', [LAKE]) == [
        {'Status': 'Every Cloud SQL instance enforces TLS, has no public IP, and authorizes no internet range.'}]
    assert ('sqladmin', 'v1') in apis.discovery.calls and ('sqladmin', 'v1beta4') not in apis.discovery.calls


def test_vpc_configuration_findings(apis):
    """v18.1: the default network is one row (its subnet counted in), the proxy-only subnet is not judged, PGA rows carry the region."""
    assert [(r['Network / Subnet'], r['Region'], r['Issue']) for r in findings_of('check_vpc_configuration')] == [
        ('default (network)', 'global', 'Default VPC network exists. 1 of its auto-mode subnets lack Private Google Access (counted here, not listed).'),
        ('prod-vpc / web-b', 'us-central1', 'Private Google Access disabled.'),
        ('prod-vpc / web-c', 'europe-west1', 'Private Google Access disabled.'),
    ]
    assert findings_of('check_vpc_configuration', [LAKE]) == [{'Status': security.VPC_ALL_CLEAR}]


def test_storage_ubla_findings(apis):
    """v18.1: the rows carry the fix."""
    assert findings_of('check_storage_ubla') == [
        {'Project': 'web-prod', 'Bucket': 'web-assets', 'Issue': 'UBLA not enabled.', 'Fix': 'gcloud storage buckets update gs://web-assets --uniform-bucket-level-access'},
        {'Project': 'web-prod', 'Bucket': 'web-backups', 'Issue': 'UBLA not enabled.', 'Fix': 'gcloud storage buckets update gs://web-backups --uniform-bucket-level-access'},
    ]
    assert findings_of('check_storage_ubla', [LAKE]) == [{'Status': 'All buckets have Uniform Bucket-Level Access enabled.'}]


def test_vm_external_ips_findings(apis):
    """v18: addresses held, not access configs — ``web-3``'s empty ``accessConfigs`` is not a row."""
    assert [(r['VM'], r['External IPs'], r['Kind']) for r in findings_of('check_vm_external_ips')] == [('web-1', '203.0.113.7', 'standalone')]
    assert findings_of('check_vm_external_ips', [LAKE]) == [{'Status': 'No VM instance holds an external IP address.'}]


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
