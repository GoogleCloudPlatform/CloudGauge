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
"""The effective organization policies of a scope (``app.services.org_policies``):
the walk from the organization down to the scanned resource, the nearer policy
replacing the farther one.

v15.3: a project scan applied the policies in ``getAncestry`` order - project,
folder, organization, then the project again - so the organization's policy
overrode a folder's, and a project scan disagreed with the folder scan of the
folder it sits in. Inherited from upstream beta v1; invisible in an organization
whose projects sit directly under it.
"""
import pytest

import fakes
from app.services import gcp as gcp_clients
from app.services.org_policies import get_effective_org_policies
from app.synthetic import SyntheticGcp

ORG, PARENT, CHILD, PROJECT = 'organizations/1', 'folders/10', 'folders/11', 'projects/web-prod'

# The boolean constraints set on each resource. Each level relaxes one the organization enforces.
POLICIES = {
    ORG: {'compute.requireOsLogin': True, 'sql.restrictPublicIp': True, 'iam.disableServiceAccountKeyCreation': True},
    PARENT: {'compute.requireOsLogin': False},
    CHILD: {'sql.restrictPublicIp': False},
    PROJECT: {'iam.disableServiceAccountKeyCreation': False},
}
PARENTS = {CHILD: PARENT, PARENT: ORG}
# getAncestry lists the project first and the organization last.
ANCESTRY = {'web-prod': [('project', 'web-prod'), ('folder', '11'), ('folder', '10'), ('organization', '1')],
            'top-level': [('project', 'top-level'), ('organization', '1')]}


def enforced(policies):
    assert isinstance(policies, dict), policies  # a str is the function's error message
    return {constraint: policy['booleanPolicy']['enforced'] for constraint, policy in policies.items()}


@pytest.fixture
def crm(gcp):
    manager = fakes.FakeResourceManager(POLICIES, PARENTS, ANCESTRY)
    gcp.discovery.apis['cloudresourcemanager'] = manager
    return manager


def test_an_organization_scan_reads_the_organization(crm):
    assert enforced(get_effective_org_policies('organization', '1')) == POLICIES[ORG]
    assert crm.listed == [ORG]


def test_a_folder_scan_walks_down_from_the_organization(crm):
    """Through the parent folder (v3 ``folders.get`` gives the parents), nearest last."""
    policies = enforced(get_effective_org_policies('folder', '11'))
    assert crm.listed == [ORG, PARENT, CHILD]
    assert policies == {'compute.requireOsLogin': False, 'sql.restrictPublicIp': False, 'iam.disableServiceAccountKeyCreation': True}


def test_a_project_scan_applies_the_nearest_policy(crm):
    """v15.3: the project's own policy wins, then its folders' from the nearest up, then the organization's."""
    policies = enforced(get_effective_org_policies('project', 'web-prod'))
    assert crm.listed == [ORG, PARENT, CHILD, PROJECT]  # top-down, and the project listed once
    assert policies == {'compute.requireOsLogin': False, 'sql.restrictPublicIp': False, 'iam.disableServiceAccountKeyCreation': False}


def test_a_project_without_policies_of_its_own_reads_as_its_folder(crm):
    """The case that was wrong: the folder relaxes a constraint the organization enforces, the project is silent."""
    crm.policies = {**POLICIES, PROJECT: {}}
    from_project = enforced(get_effective_org_policies('project', 'web-prod'))
    from_folder = enforced(get_effective_org_policies('folder', '11'))
    assert from_project == from_folder
    assert from_project['sql.restrictPublicIp'] is False  # the child folder's, not the organization's True


def test_a_project_directly_under_the_organization(crm):
    crm.policies = {**POLICIES, 'projects/top-level': {'compute.requireOsLogin': False}}
    policies = enforced(get_effective_org_policies('project', 'top-level'))
    assert crm.listed == [ORG, 'projects/top-level']
    assert policies == {'compute.requireOsLogin': False, 'sql.restrictPublicIp': True, 'iam.disableServiceAccountKeyCreation': True}


def test_folder_and_project_scans_agree_in_the_synthetic_organization(gcp):
    """The generated organization: a folder that overrides a constraint and a project in it with no
    policy of its own read the same effective value from either scope (the probe that found the bug)."""
    provider = SyntheticGcp(60, latency_ms=0, denied_fraction=0)
    gcp_clients.install_provider(provider)
    world = provider.world
    cases = []
    for folder in world.folder_ids:
        override = world.org_policies(f'folders/{folder}')
        silent = [p for p in world.projects(folder) if not world.org_policies(f'projects/{p.project_id}')]
        if not override or not silent:
            continue
        constraint = override[0]['constraint'].split('/')[-1]
        from_folder = get_effective_org_policies('folder', folder)[constraint]['booleanPolicy']['enforced']
        from_project = get_effective_org_policies('project', silent[0].project_id)[constraint]['booleanPolicy']['enforced']
        assert from_project == from_folder == override[0]['booleanPolicy']['enforced'], (folder, silent[0].project_id, constraint)
        cases.append(constraint)
    assert len(cases) >= 3  # seed 42 overrides a constraint in several folders
