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
"""Service Account Impersonation and VPC Service Controls Coverage (v17.1): member kinds, the path a role opens, the
severity rules, the rows and their reach; the perimeter facts and coverage rows; both checks against the fakes."""
from types import SimpleNamespace

import pytest
from google.api_core import exceptions as core_exceptions

from app.checks.impersonation import (
    IMPERSONATION_CHECK,
    SEARCH_QUERY,
    Inventory,
    check_service_account_impersonation,
    impersonation_rows,
    member_kind,
    path_of_role,
    severity,
)
from app.checks.not_checked import NOT_CHECKED
from app.checks.perimeters import REPLAY_SERVICES, VPC_SC_CHECK, check_vpc_sc_coverage, coverage_rows, perimeter_facts
from fakes import _execute

JOB = 'job-171'
PROJECT_ASSET = 'cloudresourcemanager.googleapis.com/Project'
SA_ASSET = 'iam.googleapis.com/ServiceAccount'
TOKEN = 'roles/iam.serviceAccountTokenCreator'


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_check(self):
        return {record['Check']: record for _, record in self.records if record['Check'] != NOT_CHECKED}

    def not_checked(self):
        return [row for _, record in self.records if record['Check'] == NOT_CHECKED for row in record['Finding']]


# --- the rules ---

@pytest.mark.parametrize('member, kind', [
    ('allUsers', 'public'), ('allAuthenticatedUsers', 'public'), ('domain:example.com', 'domain'), ('user:a@example.com', 'human'),
    ('group:ops@example.com', 'human'), ('serviceAccount:app@p1.iam.gserviceaccount.com', 'service account'),
    ('serviceAccount:111-compute@developer.gserviceaccount.com', 'service account'),
    ('serviceAccount:service-111@gcp-sa-cloudbuild.iam.gserviceaccount.com', 'google'), ('serviceAccount:111@cloudservices.gserviceaccount.com', 'google'),
    ('serviceAccount:service-111@container-engine-robot.iam.gserviceaccount.com', 'google'),
    ('serviceAccount:p1.svc.id.goog[default/default]', 'kubernetes'), ('principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/*', 'federated pool'),
    ('principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/subject/x', 'federated'), ('deleted:user:x@example.com?uid=1', 'deleted'),
])
def test_member_kinds(member, kind):
    assert member_kind(member) == kind


def test_path_of_role_predefined_custom_and_ignored():
    none = {}.get
    assert path_of_role(TOKEN, none) == 'token creator'
    assert path_of_role('roles/iam.serviceAccountUser', none) == 'actAs'
    assert path_of_role('roles/iam.workloadIdentityUser', none) == 'workload identity'
    assert path_of_role('roles/iam.serviceAccountKeyAdmin', none) == 'key admin'
    assert path_of_role('roles/iam.serviceAccountAdmin', none) == 'account admin'
    for role in ('roles/owner', 'roles/editor', 'roles/compute.serviceAgent', 'roles/container.admin', 'roles/viewer'):
        assert path_of_role(role, none) is None
    permissions = {'projects/p1/roles/minter': {'iam.serviceAccounts.getAccessToken'}, 'organizations/1/roles/keys': {'iam.serviceAccountKeys.create'},
                   'projects/p1/roles/deployer': {'iam.serviceAccounts.actAs'}, 'projects/p1/roles/reader': {'iam.serviceAccounts.get'},
                   'projects/p1/roles/unreadable': None}
    assert path_of_role('projects/p1/roles/minter', permissions.get) == 'token creator'
    assert path_of_role('organizations/1/roles/keys', permissions.get) == 'key admin'
    assert path_of_role('projects/p1/roles/deployer', permissions.get) == 'actAs'
    assert path_of_role('projects/p1/roles/reader', permissions.get) is None
    assert path_of_role('projects/p1/roles/unreadable', permissions.get) == 'custom role (not read)'
    assert 'policy:roles/iam.serviceAccountTokenCreator' in SEARCH_QUERY and 'policy.role.permissions:iam.serviceAccounts.getAccessToken' in SEARCH_QUERY


@pytest.mark.parametrize('level, path, kind, extra, expected', [
    ('project', 'token creator', 'human', {}, 'Action Required'),
    ('organization', 'key admin', 'service account', {}, 'Action Required'),
    ('folder', 'custom role (not read)', 'human', {}, 'Action Required'),
    ('project', 'actAs', 'human', {}, 'Investigation Recommended'),
    ('project', 'actAs', 'domain', {}, 'Action Required'),
    ('project', 'token creator', 'google', {}, None),
    ('service account', 'token creator', 'public', {}, 'Action Required'),
    ('service account', 'token creator', 'service account', {}, 'Action Required'),
    ('service account', 'actAs', 'service account', {}, 'Investigation Recommended'),
    ('service account', 'token creator', 'service account', {'foreign': True}, 'Action Required'),
    ('service account', 'token creator', 'service account', {'foreign': True, 'organization_scan': False}, 'Investigation Recommended'),
    ('service account', 'token creator', 'human', {}, 'Investigation Recommended'),
    ('service account', 'actAs', 'human', {}, None),
    ('service account', 'workload identity', 'kubernetes', {'member': 'serviceAccount:p.svc.id.goog[default/default]', 'target_privileged': ('roles/editor',)}, 'Action Required'),
    ('service account', 'workload identity', 'kubernetes', {'member': 'serviceAccount:p.svc.id.goog[default/default]'}, 'Investigation Recommended'),
    ('service account', 'workload identity', 'kubernetes', {'member': 'serviceAccount:p.svc.id.goog[kube-system/agent]'}, 'Investigation Recommended'),
    ('service account', 'workload identity', 'kubernetes', {'member': 'serviceAccount:p.svc.id.goog[shop/api]', 'target_privileged': ('roles/owner',)}, 'Investigation Recommended'),
    ('service account', 'workload identity', 'kubernetes', {'member': 'serviceAccount:p.svc.id.goog[shop/api]'}, None),
    ('service account', 'token creator', 'federated pool', {}, 'Action Required'),
    ('service account', 'token creator', 'federated', {}, 'Investigation Recommended'),
    ('service account', 'token creator', 'deleted', {}, None),
])
def test_severity_rules(level, path, kind, extra, expected):
    assert severity(level, path, kind, **extra) == expected


def result(asset_type, resource, bindings, project_number='111', folders=()):
    return SimpleNamespace(asset_type=asset_type, resource=resource, project=f'projects/{project_number}', organization='organizations/1',
                           folders=[f'folders/{f}' for f in folders],
                           policy=SimpleNamespace(bindings=[SimpleNamespace(role=role, members=list(members)) for role, members in bindings]))


def inventory(*accounts):
    """``accounts`` are ``(email, project_id, project_number, folder)``."""
    return Inventory([SimpleNamespace(name=f'//iam.googleapis.com/projects/{pid}/serviceAccounts/{email}', project=f'projects/{number}',
                                      folders=[f'folders/{folder}'] if folder else []) for email, pid, number, folder in accounts])


def test_impersonation_rows_reach_targets_order_and_fixes():
    inv = inventory(('a@p1.iam.gserviceaccount.com', 'p1', '111', '7'), ('b@p1.iam.gserviceaccount.com', 'p1', '111', '7'),
                    ('c@p1.iam.gserviceaccount.com', 'p1', '111', '7'), ('d@p2.iam.gserviceaccount.com', 'p2', '222', '8'))
    results = [
        result(PROJECT_ASSET, '//cloudresourcemanager.googleapis.com/projects/p1', [
            (TOKEN, ['serviceAccount:111-compute@developer.gserviceaccount.com', 'serviceAccount:service-111@gcp-sa-x.iam.gserviceaccount.com']),
            ('roles/iam.serviceAccountUser', ['group:deployers@example.com']), ('roles/editor', ['user:dev@example.com']),
            ('roles/compute.serviceAgent', ['serviceAccount:service-111@compute-system.iam.gserviceaccount.com'])]),
        result('cloudresourcemanager.googleapis.com/Folder', '//cloudresourcemanager.googleapis.com/folders/7', [(TOKEN, ['user:cto@example.com'])], folders=('7',)),
        result(SA_ASSET, '//iam.googleapis.com/projects/p1/serviceAccounts/a@p1.iam.gserviceaccount.com', [
            (TOKEN, ['serviceAccount:b@p1.iam.gserviceaccount.com', 'user:ops@example.com', 'serviceAccount:deploy@outside.iam.gserviceaccount.com']),
            ('roles/iam.workloadIdentityUser', ['serviceAccount:p1.svc.id.goog[default/default]']), ('roles/iam.serviceAccountUser', ['user:ops@example.com'])]),
        result(SA_ASSET, '//iam.googleapis.com/projects/p1/serviceAccounts/c@p1.iam.gserviceaccount.com', [
            (TOKEN, ['serviceAccount:b@p1.iam.gserviceaccount.com']),
            ('roles/iam.serviceAccountUser', ['serviceAccount:c@p1.iam.gserviceaccount.com']),  # bound on itself: not a row
            (TOKEN, ['serviceAccount:c@p1.iam.gserviceaccount.com'])]),
        result('storage.googleapis.com/Bucket', '//storage.googleapis.com/projects/_/buckets/b', [(TOKEN, ['user:x@example.com'])]),
    ]
    roles = {'a@p1.iam.gserviceaccount.com': {'roles/editor'}, 'c@p1.iam.gserviceaccount.com': set()}
    rows = impersonation_rows(results, inv, {}.get, roles.get, organization_scan=True)
    summary = [(r['Level'], r['Principal'], r['Path'], r['Reach'], r['_status']) for r in rows]
    assert summary == [
        ('folder', 'user:cto@example.com', 'token creator', 'every service account under folders/7 (3 in scope)', 'Action Required'),
        ('project', 'group:deployers@example.com', 'actAs', 'every service account under projects/p1 (3 in scope)', 'Investigation Recommended'),
        ('project', 'serviceAccount:111-compute@developer.gserviceaccount.com', 'token creator', 'every service account under projects/p1 (3 in scope)', 'Action Required'),
        ('service account', 'serviceAccount:b@p1.iam.gserviceaccount.com', 'token creator', '2 of 3 service accounts in projects/p1', 'Action Required'),
        ('service account', 'serviceAccount:deploy@outside.iam.gserviceaccount.com', 'token creator',
         '1 of 3 service accounts in projects/p1 — the principal is outside the organization', 'Action Required'),
        ('service account', 'serviceAccount:p1.svc.id.goog[default/default]', 'workload identity', '1 of 3 service accounts in projects/p1', 'Action Required'),
        ('service account', 'user:ops@example.com', 'token creator', '1 of 3 service accounts in projects/p1', 'Investigation Recommended'),
    ]
    chain = rows[3]
    assert chain['Targets'] == 'a@p1.iam.gserviceaccount.com, c@p1.iam.gserviceaccount.com' and chain['Target Roles'] == 'roles/editor'
    assert chain['Fix'].startswith('Replace the account-to-account chain') and 'remove-iam-policy-binding a@p1.iam.gserviceaccount.com' in chain['Fix']
    assert rows[2]['Fix'].startswith('Remove the project-level binding of roles/iam.serviceAccountTokenCreator')
    assert rows[5]['Fix'].startswith('Bind a dedicated Kubernetes service account')
    # Outside an organization scan the foreign principal is Investigation, worded for the scope.
    rows = impersonation_rows(results, inv, {}.get, roles.get, organization_scan=False)
    foreign = next(r for r in rows if 'outside' in r['Principal'])
    assert foreign['_status'] == 'Investigation Recommended' and foreign['Reach'].endswith('outside the scanned scope')


# --- the impersonation check ---

class FakeIam:
    def __init__(self, permissions=None, error=None):
        self.permissions, self.error, self.names = permissions or {}, error, []

    def _roles(self):
        iam = self

        def get(name):
            iam.names.append(name)
            return _execute(iam.error or {'name': name, 'includedPermissions': sorted(iam.permissions.get(name, []))})
        return SimpleNamespace(get=get)

    def projects(self):
        return SimpleNamespace(roles=self._roles)

    def organizations(self):
        return SimpleNamespace(roles=self._roles)


def test_the_impersonation_check_searches_the_scope_reads_custom_roles_and_counts_accounts(gcp):
    gcp.assets.add_service_account('a@p1.iam.gserviceaccount.com', 'p1', '111')
    gcp.assets.add_service_account('b@p1.iam.gserviceaccount.com', 'p1', '111')
    gcp.assets.add_iam_policy(PROJECT_ASSET, '//cloudresourcemanager.googleapis.com/projects/p1',
                              [('projects/p1/roles/minter', ['serviceAccount:ci@ci-project.iam.gserviceaccount.com'])], project_number='111')
    gcp.assets.add_iam_policy(SA_ASSET, '//iam.googleapis.com/projects/p1/serviceAccounts/a@p1.iam.gserviceaccount.com',
                              [(TOKEN, ['user:ops@example.com'])], project_number='111')
    gcp.discovery.apis['iam'] = FakeIam(permissions={'projects/p1/roles/minter': {'iam.serviceAccounts.getAccessToken'}})
    sink = Sink()
    check_service_account_impersonation('organization', '987654321', JOB, sink=sink)
    record = sink.by_check()[IMPERSONATION_CHECK]
    assert record['Status'] == 'Action Required'
    assert gcp.assets.iam_queries[0] == SEARCH_QUERY and gcp.assets.requests[0]['asset_types'] == [SA_ASSET]
    assert [(r['Level'], r['Principal'], r['Path'], r['Reach']) for r in record['Finding']] == [
        ('project', 'serviceAccount:ci@ci-project.iam.gserviceaccount.com', 'token creator', 'every service account under projects/p1 (2 in scope)'),
        ('service account', 'user:ops@example.com', 'token creator', '1 of 2 service accounts in projects/p1')]
    assert gcp.discovery.apis['iam'].names == ['projects/p1/roles/minter']
    assert sink.not_checked() == []


def test_policies_of_projects_pending_deletion_are_not_findings(gcp):
    gcp.assets.add('projects', 'live', 'Live', project_number='111', organization='987654321')  # the only active project
    gcp.assets.add_service_account('a@live.iam.gserviceaccount.com', 'live', '111')
    gcp.assets.add_service_account('z@gone.iam.gserviceaccount.com', 'gone', '999')
    gcp.assets.add_iam_policy(PROJECT_ASSET, '//cloudresourcemanager.googleapis.com/projects/gone', [(TOKEN, ['user:x@example.com'])], project_number='999')
    gcp.assets.add_iam_policy(SA_ASSET, '//iam.googleapis.com/projects/gone/serviceAccounts/z@gone.iam.gserviceaccount.com', [(TOKEN, ['user:x@example.com'])], project_number='999')
    gcp.assets.add_iam_policy(SA_ASSET, '//iam.googleapis.com/projects/live/serviceAccounts/a@live.iam.gserviceaccount.com', [(TOKEN, ['user:x@example.com'])], project_number='111')
    sink = Sink()
    check_service_account_impersonation('organization', '987654321', JOB, sink=sink)
    record = sink.by_check()[IMPERSONATION_CHECK]
    assert [(r['Resource'], r['Level']) for r in record['Finding']] == [('projects/live', 'service account')]
    assert [r['asset_types'] for r in gcp.assets.requests] == [[SA_ASSET], [PROJECT_ASSET]]
    # Without any project result the rows are kept: an empty search is not a list of zero active projects.
    inv = Inventory([], active_projects=[])
    assert inv.is_active('999') is True and Inventory([], active_projects=['projects/1']).is_active('999') is False


def test_the_impersonation_check_all_clear_unreadable_roles_and_a_failed_search(gcp):
    gcp.assets.add_service_account('a@p1.iam.gserviceaccount.com', 'p1', '111')
    sink = Sink()
    check_service_account_impersonation('project', 'p1', JOB, sink=sink)
    assert sink.by_check()[IMPERSONATION_CHECK] == {'Check': IMPERSONATION_CHECK, 'Status': 'Compliant', 'Finding': [
        {'Status': 'No principal can mint tokens for, act as or map onto service accounts beyond its own, across the 1 service accounts in scope.'}]}
    # A custom role that cannot be read is still a row (Action Required at project level) and a not-checked note.
    gcp.assets.add_iam_policy(PROJECT_ASSET, '//cloudresourcemanager.googleapis.com/projects/p1', [('projects/p1/roles/x', ['user:a@example.com'])], project_number='111')
    gcp.discovery.apis['iam'] = FakeIam(error=core_exceptions.PermissionDenied('no iam.roles.get'))
    sink = Sink()
    check_service_account_impersonation('project', 'p1', JOB, sink=sink)
    record = sink.by_check()[IMPERSONATION_CHECK]
    assert record['Status'] == 'Action Required' and record['Finding'][0]['Path'] == 'custom role (not read)'
    assert sink.not_checked() == [{'Project': 'p1', 'Skipped check': f'{IMPERSONATION_CHECK} (custom role projects/p1/roles/x)', 'Reason': '403 no iam.roles.get'}]
    gcp.assets.iam_error = core_exceptions.PermissionDenied('no searchAllIamPolicies')
    sink = Sink()
    check_service_account_impersonation('project', 'p1', JOB, sink=sink)
    assert sink.by_check()[IMPERSONATION_CHECK]['Status'] == 'Error'


# --- perimeters ---

def perimeter_json(name, resources, restricted, *, dry_run=False, regular=True):
    """A ServicePerimeter as the Access Context Manager API returns it (enforced: ``status``; dry run: ``spec``)."""
    config = {'resources': list(resources), 'restrictedServices': list(restricted)}
    entry = {'name': f'accessPolicies/1/servicePerimeters/{name}', 'title': name.replace('_', ' ')}
    if not regular:
        entry['perimeterType'] = 'PERIMETER_TYPE_BRIDGE'
    if dry_run:
        entry.update(spec=config, useExplicitDryRunSpec=True)
    else:
        entry['status'] = config
    return entry


def perimeter(name, resources, restricted, *, dry_run=False, regular=True):
    return perimeter_facts(perimeter_json(name, resources, restricted, dry_run=dry_run, regular=regular))


class FakeAcm:
    """``accesscontextmanager v1``: the organization's access policies and their perimeters, one page each."""

    def __init__(self, policies=None, error=None):
        self.policies, self.error, self.parents = policies or {}, error, []  # policy name -> [perimeter JSON]

    def accessPolicies(self):
        acm = self

        def list_policies(parent):
            acm.parents.append(parent)
            return _execute(acm.error or {'accessPolicies': [{'name': name, 'parent': parent} for name in acm.policies]})

        def list_perimeters(parent):
            acm.parents.append(parent)
            return _execute({'servicePerimeters': acm.policies.get(parent, [])})
        return SimpleNamespace(list=list_policies, list_next=lambda previous_request, previous_response: None,
                               servicePerimeters=lambda: SimpleNamespace(list=list_perimeters, list_next=lambda previous_request, previous_response: None))


def test_perimeter_facts_and_coverage_rows():
    projects = [('p1', '111'), ('p2', '222'), ('p3', '333')]
    assert coverage_rows(projects, [], '1')[0]['Issue'].startswith('No enforced VPC Service Controls perimeter protects the 3 scanned projects')
    enforced = perimeter('prod', ['projects/111', 'projects/222'], REPLAY_SERVICES)
    assert enforced['regular'] and enforced['enforced_resources'] == {'projects/111', 'projects/222'} and enforced['dry_run_resources'] == set()
    assert perimeter_facts({}) is None and perimeter_facts(None) is None
    assert perimeter('bare', [], [])['title'] == 'bare'  # perimeterType absent means regular
    partial = perimeter('data', ['projects/222'], ['storage.googleapis.com'])
    dry = perimeter('staging', ['projects/333'], REPLAY_SERVICES, dry_run=True)
    bridge = perimeter('bridge', ['projects/333'], [], regular=False)
    rows = coverage_rows(projects, [enforced, partial, dry, bridge, None], '1')
    assert [(r['Project'], r['Perimeter'], r['Projects']) for r in rows] == [
        ('(outside)', 'none', 'p3'), ('(inside)', 'data', 'p2'), ('(dry run)', 'staging', 'p3')]
    assert rows[1]['Issue'] == 'Restricts 1 services but not iamcredentials.googleapis.com, secretmanager.googleapis.com, container.googleapis.com, sqladmin.googleapis.com, compute.googleapis.com.'
    assert coverage_rows([('p1', '111')], [enforced], '1') == []


def test_the_vpc_sc_check_against_the_fakes(gcp):
    gcp.assets.add('projects', 'p1', 'P1', project_number='111', organization='987654321')
    gcp.assets.add('projects', 'p2', 'P2', project_number='222', organization='987654321')
    acm = FakeAcm({'accessPolicies/1': [perimeter_json('prod', ['projects/111'], REPLAY_SERVICES)],
                   'accessPolicies/2': [perimeter_json('scoped_dry', ['projects/222'], ['storage.googleapis.com'], dry_run=True)]})
    gcp.discovery.apis['accesscontextmanager'] = acm
    sink = Sink()
    check_vpc_sc_coverage('organization', '987654321', JOB, sink=sink)
    record = sink.by_check()[VPC_SC_CHECK]
    assert record['Status'] == 'Investigation Recommended'
    assert [(r['Project'], r['Perimeter'], r['Projects']) for r in record['Finding']] == [('(outside)', 'none', 'p2'), ('(dry run)', 'scoped dry', 'p2')]
    # The organization's policies (scoped ones included) and each policy's perimeters, one call each.
    assert acm.parents == ['organizations/987654321', 'accessPolicies/1', 'accessPolicies/2']
    # A folder scan reads the perimeters at the projects' organization; no access policy at all means no perimeter.
    gcp.discovery.apis['accesscontextmanager'] = FakeAcm({})
    sink = Sink()
    check_vpc_sc_coverage('folder', '42', JOB, sink=sink)
    record = sink.by_check()[VPC_SC_CHECK]
    assert record['Status'] == 'Investigation Recommended' and record['Finding'][0]['Perimeter'] == 'none' and record['Finding'][0]['Projects'] == 'p1, p2'
    assert gcp.discovery.apis['accesscontextmanager'].parents == ['organizations/987654321']
    # An API that cannot be called is the check's Error, naming the API to enable.
    gcp.discovery.apis['accesscontextmanager'] = FakeAcm(error=core_exceptions.PermissionDenied('Access Context Manager API has not been used in project x'))
    sink = Sink()
    check_vpc_sc_coverage('organization', '987654321', JOB, sink=sink)
    record = sink.by_check()[VPC_SC_CHECK]
    assert record['Status'] == 'Error' and 'accesscontextmanager.googleapis.com must be enabled' in record['Finding'][0]['Error']
    # Every project inside an enforced perimeter with the replay services: all clear.
    gcp.discovery.apis['accesscontextmanager'] = FakeAcm({'accessPolicies/1': [perimeter_json('all', ['projects/111', 'projects/222'], REPLAY_SERVICES)]})
    sink = Sink()
    check_vpc_sc_coverage('organization', '987654321', JOB, sink=sink)
    assert sink.by_check()[VPC_SC_CHECK]['Status'] == 'Compliant'
