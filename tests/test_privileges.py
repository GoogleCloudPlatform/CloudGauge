"""
v18.7 — Folders, keys and privileged grants, the IAM half: the rules of ``app.checks.privileges`` on fixtures of the shapes read today (the
survey's folder, organization policy, custom roles — anonymised), the three checks end to end with their fresh reads and failure paths.
"""
from types import SimpleNamespace

import pytest

from app.checks import privileges as pr
from app.checks import registry
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS

JOB = 'job-187'
AR, IR, INFO, C = 'Action Required', 'Investigation Recommended', 'Informational', 'Compliant'
ORG, FOLDER, CHILD, PROJECT, NUMBER = '987654321', '1061000000000', '1061000000001', 'stark-sec-prod', '208800000000'
DOMAIN = 'example.test'


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


def binding(role, *members, condition=None):
    return {'role': role, 'members': list(members), **({'condition': {'title': condition, 'expression': f'expr({condition})'}} if condition else {})}


def bindings(*items):
    return pr.policy_bindings({'bindings': list(items)})


def _execute(value):
    class Request:
        def execute(self):
            if isinstance(value, Exception):
                raise value
            return value
    return Request()


# --- the hierarchy and the shapes -----------------------------------------------------------------------------------------

def test_policy_bindings_and_the_folder_label():
    assert bindings(binding('roles/owner', 'user:a@example.test', condition='temp'), binding('roles/viewer', 'group:g@example.test')) == [
        ('roles/owner', ['user:a@example.test'], {'title': 'temp', 'expression': 'expr(temp)'}), ('roles/viewer', ['group:g@example.test'], {})]
    assert pr.folder_label({'id': FOLDER, 'display': 'prod'}) == f'prod ({FOLDER})' and pr.folder_label({'id': FOLDER, 'display': ''}) == f'folders/{FOLDER}'
    assert pr.projects_below([{'id': 'a', 'number': '1', 'folders': [FOLDER, CHILD]}, {'id': 'b', 'number': '2', 'folders': [FOLDER]}, {'id': 'c', 'number': '3', 'folders': []}]) == {FOLDER: 2, CHILD: 1}


class Inventory:
    """The two searches the checks make: folders and projects (resources), policies and holders (IAM)."""

    def __init__(self, folders=(), projects=(), policies=(), error=None):
        self.folders, self.projects, self.policies, self.error, self.requests = list(folders), list(projects), list(policies), error, []

    def search_all_resources(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        if pr.FOLDER_TYPE in request['asset_types']:
            return iter([SimpleNamespace(name=f'//cloudresourcemanager.googleapis.com/folders/{fid}', display_name=display, parent_full_resource_name=f'//cloudresourcemanager.googleapis.com/{parent}', state=state)
                         for fid, display, parent, state in self.folders])
        return iter([SimpleNamespace(name=f'//cloudresourcemanager.googleapis.com/projects/{pid}', project=f'projects/{number}', folders=[f'folders/{f}' for f in folders], state='ACTIVE',
                                     additional_attributes={'projectId': pid}) for pid, number, folders in self.projects])

    def search_all_iam_policies(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return iter(self.policies)


def policy_result(kind, ident, *items):
    return SimpleNamespace(resource=f'//cloudresourcemanager.googleapis.com/{kind}/{ident}', asset_type=f'cloudresourcemanager.googleapis.com/{kind[:-1].capitalize()}',
                           project=f'projects/{NUMBER}' if kind == 'projects' else '', folders=[f'folders/{FOLDER}'] if kind != 'organizations' else [], organization=f'organizations/{ORG}',
                           policy=SimpleNamespace(bindings=[SimpleNamespace(role=b['role'], members=b['members'], condition=None) for b in items]))


def test_search_folders_and_projects_read_the_index():
    inventory = Inventory(folders=[(FOLDER, 'prod', f'organizations/{ORG}', 'ACTIVE'), (CHILD, 'prod-eu', f'folders/{FOLDER}', 'ACTIVE'), ('99', 'gone', f'organizations/{ORG}', 'DELETE_REQUESTED')],
                          projects=[(PROJECT, NUMBER, [CHILD, FOLDER])])
    folders = pr.search_folders(inventory, f'organizations/{ORG}')
    assert folders == {FOLDER: {'id': FOLDER, 'display': 'prod', 'parent': f'organizations/{ORG}'}, CHILD: {'id': CHILD, 'display': 'prod-eu', 'parent': f'folders/{FOLDER}'}}
    assert pr.search_projects(inventory, f'organizations/{ORG}') == [{'id': PROJECT, 'number': NUMBER, 'folders': [CHILD, FOLDER]}]
    assert inventory.requests[0]['read_mask'] == 'name,displayName,parentFullResourceName,state' and inventory.requests[1]['asset_types'] == [pr.PROJECT_TYPE]


# --- Folder Primitive Roles --------------------------------------------------------------------------------------------------

def test_folder_role_rows_by_kind_and_role():
    folder = {'id': FOLDER, 'display': 'prod', 'parent': f'organizations/{ORG}'}
    rows = pr.folder_role_rows(folder, bindings(
        binding('roles/owner', 'user:lead@example.test', 'serviceAccount:deploy@tooling.iam.gserviceaccount.com', 'group:platform@example.test', 'user:someone@gmail.com', 'allUsers',
                f'serviceAccount:service-{NUMBER}@gcp-sa-x.iam.gserviceaccount.com'),
        binding('roles/editor', 'domain:example.test', f'serviceAccount:{NUMBER}-compute@developer.gserviceaccount.com', condition='until-friday'),
        binding(pr.PROJECT_CREATOR, 'domain:example.test', 'user:lead@example.test', 'group:project-factory@example.test', 'serviceAccount:factory@tooling.iam.gserviceaccount.com'),
        binding('roles/viewer', 'user:reader@example.test')), 7, (DOMAIN,))
    assert [(r['Principal'].split(':')[-1].split('@')[0], r['Role'], r['_status']) for r in rows] == [
        ('lead', 'roles/owner', IR), ('deploy', 'roles/owner', AR), ('platform', 'roles/owner', IR), ('someone', 'roles/owner', AR),
        ('example.test', 'roles/editor', AR), (f'{NUMBER}-compute', 'roles/editor', IR),
        ('example.test', pr.PROJECT_CREATOR, AR), ('lead', pr.PROJECT_CREATOR, IR), ('project-factory', pr.PROJECT_CREATOR, INFO), ('factory', pr.PROJECT_CREATOR, INFO)]
    assert all(r['Folder'] == f'prod ({FOLDER})' and r['Projects below'] == 7 for r in rows)
    assert rows[0]['Fix'] == f'gcloud resource-manager folders remove-iam-policy-binding {FOLDER} --member=user:lead@example.test --role=roles/owner  # grant a predefined role for the work first; every project below inherits this one'
    assert rows[4]['Condition'] == 'until-friday' and "--condition='expression=expr(until-friday),title=until-friday'" in rows[4]['Fix']
    assert rows[6]['Fix'].endswith('# grant it to a project-factory group or service account')
    assert set(rows[0]) == {'Folder', 'Principal', 'Type', 'Role', 'Projects below', 'Condition', 'Fix', '_status'}
    # An external user without the organization's domain known rates as a user.
    assert pr.folder_role_rows(folder, bindings(binding('roles/owner', 'user:x@partner.example')), 0)[0]['Type'] == 'user'


class Crm:
    """Resource Manager v3 (folders) and v1 (organizations, projects): fresh policies, names, and the errors a test injects."""

    def __init__(self, folder_policies=None, org_policy=None, project_policies=None, org_name='example.test', errors=None):
        self.folder_policies, self.org_policy, self.project_policies = folder_policies or {}, org_policy or {'bindings': []}, project_policies or {}
        self.org_name, self.errors, self.calls = org_name, errors or {}, []

    def folders(self):
        crm = self

        class Folders:
            def getIamPolicy(self, resource, body):
                crm.calls.append(('folders.getIamPolicy', resource, body))
                fid = resource.split('/')[-1]
                if fid in crm.errors:
                    return _execute(crm.errors[fid])
                return _execute(crm.folder_policies.get(fid, {'bindings': []}))

            def get(self, name):
                crm.calls.append(('folders.get', name))
                return _execute({'name': name, 'displayName': f'folder-{name.split("/")[-1]}'})
        return Folders()

    def organizations(self):
        crm = self

        class Organizations:
            def getIamPolicy(self, resource, body):
                crm.calls.append(('organizations.getIamPolicy', resource, body))
                return _execute(crm.errors.get('org', crm.org_policy))

            def get(self, name):
                crm.calls.append(('organizations.get', name))
                return _execute(crm.errors.get('org-name', {'name': name, 'displayName': crm.org_name}))
        return Organizations()

    def projects(self):
        crm = self

        class Projects:
            def getIamPolicy(self, resource, body):
                crm.calls.append(('projects.getIamPolicy', resource, body))
                return _execute(crm.errors.get(resource, crm.project_policies.get(resource, {'bindings': []})))
        return Projects()


def test_check_folder_roles_end_to_end(gcp, monkeypatch):
    inventory = Inventory(folders=[(FOLDER, 'prod', f'organizations/{ORG}', 'ACTIVE'), (CHILD, '', f'folders/{FOLDER}', 'ACTIVE')], projects=[(PROJECT, NUMBER, [CHILD, FOLDER]), ('other', '1', [FOLDER])],
                          policies=[policy_result('folders', CHILD, binding('roles/editor', 'user:copy@example.test'))])
    crm = Crm(folder_policies={FOLDER: {'bindings': [binding('roles/owner', 'user:lead@example.test'), binding(pr.PROJECT_CREATOR, 'domain:example.test')]}},
              errors={CHILD: RuntimeError('403 folders.getIamPolicy')})
    monkeypatch.setattr(pr.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(pr.gcp, 'api_build', lambda *args, **kwargs: crm)
    sink = Sink()
    pr.check_folder_roles('organization', ORG, JOB, sink=sink)
    record = sink.by_check()['Folder Primitive Roles']
    assert record['Status'] == AR
    assert [(r['Folder'], r['Principal'], r['Role'], r['Projects below']) for r in record['Finding']] == [
        (f'prod ({FOLDER})', 'user:lead@example.test', 'roles/owner', 2), (f'prod ({FOLDER})', 'domain:example.test', pr.PROJECT_CREATOR, 2),
        (f'folders/{CHILD}', 'user:copy@example.test', 'roles/editor', 1)]  # the child's fresh read failed: the inventory's copy, named below (no display name read either)
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [
        (f'folders/{CHILD}', "Folder Primitive Roles (the Resource Manager read failed; the inventory's copy was used, which can lag changes by hours)")]
    assert ('folders.getIamPolicy', f'folders/{FOLDER}', pr.POLICY_V3) in crm.calls and ('organizations.get', f'organizations/{ORG}') in crm.calls
    assert all('_status' not in r for r in record['Finding'])
    # A folder scan: the search under the folder returns the folder itself and its descendants (here: the child alone, whose fresh read fails →
    # the inventory's copy); a project scan has no folders; a listing that fails is an Error.
    monkeypatch.setattr(pr.gcp, 'asset_client', lambda credentials=None: Inventory(folders=[(CHILD, 'prod-eu', f'folders/{FOLDER}', 'ACTIVE')], projects=[(PROJECT, NUMBER, [CHILD, FOLDER])],
                                                                                  policies=[policy_result('folders', CHILD, binding('roles/editor', 'user:copy@example.test'))]))
    sink = Sink()
    pr.check_folder_roles('folder', CHILD, JOB, sink=sink)
    record = sink.by_check()['Folder Primitive Roles']
    assert record['Status'] == IR and [(r['Folder'], r['Principal']) for r in record['Finding']] == [(f'prod-eu ({CHILD})', 'user:copy@example.test')]
    sink = Sink()
    pr.check_folder_roles('project', PROJECT, JOB, sink=sink)
    assert sink.by_check()['Folder Primitive Roles'] == {'Check': 'Folder Primitive Roles', 'Finding': [{'Status': pr.FOLDER_ROLES_ALL_CLEAR}], 'Status': C}
    monkeypatch.setattr(pr.gcp, 'asset_client', lambda credentials=None: Inventory(error=RuntimeError('503 inventory unavailable')))
    sink = Sink()
    pr.check_folder_roles('organization', ORG, JOB, sink=sink)
    assert sink.by_check()['Folder Primitive Roles']['Status'] == 'Error'


# --- Privileged Grants -------------------------------------------------------------------------------------------------------

ORG_BINDINGS = [binding(pr.PROJECT_CREATOR, 'domain:example.test', 'serviceAccount:factory@tooling.iam.gserviceaccount.com', 'user:lead@example.test', 'group:factory@example.test'),
                binding('roles/billing.user', 'group:ops-finance@partner.example', 'serviceAccount:bass@system.gserviceaccount.com', 'domain:example.test'),
                binding('roles/billing.viewer', 'user:cfo@example.test'),
                binding(pr.ORG_ADMIN, 'group:cloud-admins@example.test', 'user:admin@example.test', 'serviceAccount:automation@system.gserviceaccount.com'),
                binding('roles/owner', 'user:admin@example.test')]


def test_privileged_grant_rows_project_creation_billing_and_redundancy():
    rows = pr.privileged_grant_rows(ORG, bindings(*ORG_BINDINGS), (DOMAIN,))
    assert [(r['Principal'].split(':')[-1].split('@')[0], r['Role'], r['_status']) for r in rows] == [
        ('example.test', pr.PROJECT_CREATOR, AR), ('factory', pr.PROJECT_CREATOR, INFO), ('lead', pr.PROJECT_CREATOR, IR), ('factory', pr.PROJECT_CREATOR, INFO),
        ('ops-finance', 'roles/billing.user', IR), ('example.test', 'roles/billing.user', AR), ('cfo', 'roles/billing.viewer', IR)]
    assert rows[0]['Issue'] == 'Project creation granted at the organization.' and rows[0]['Detail'].startswith('Every account in it can create projects')
    assert rows[0]['Fix'] == f'gcloud organizations remove-iam-policy-binding {ORG} --member=domain:example.test --role={pr.PROJECT_CREATOR}  # grant it to a project-factory group or service account'
    assert rows[4]['Fix'].endswith('gcloud billing accounts add-iam-policy-binding ACCOUNT --member=group:ops-finance@partner.example --role=roles/billing.user')
    assert rows[5]['Detail'].endswith('Every account in the domain holds it.') and rows[4]['Type'] == 'group'
    assert set(rows[0]) == {'Resource', 'Principal', 'Type', 'Role', 'Condition', 'Issue', 'Detail', 'Fix', '_status'}
    # Two non-Google administrators: no redundancy row. One group: Informational. One person: Action Required. None: Action Required.
    assert not [r for r in rows if 'Administrator' in r['Issue']]
    one_group = pr.privileged_grant_rows(ORG, bindings(binding(pr.ORG_ADMIN, 'group:cloud-admins@example.test', 'serviceAccount:automation@system.gserviceaccount.com')))
    assert [(r['Issue'], r['Principal'], r['_status']) for r in one_group] == [('One Organization Administrator principal.', 'group:cloud-admins@example.test', INFO)]
    one_person = pr.privileged_grant_rows(ORG, bindings(binding(pr.ORG_ADMIN, 'user:admin@example.test'), binding(pr.ORG_ADMIN, 'user:jit@example.test', condition='PAM grant')))
    assert [(r['Issue'], r['Principal'], r['_status']) for r in one_person] == [('Single Organization Administrator.', 'user:admin@example.test', AR)]  # the conditional grant is not standing
    assert one_person[0]['Fix'] == f'gcloud organizations add-iam-policy-binding {ORG} --member=group:GROUP --role={pr.ORG_ADMIN}  # a second administrator: a group with few members'
    nobody = pr.privileged_grant_rows(ORG, bindings(binding('roles/viewer', 'user:x@example.test')))
    assert [(r['Issue'], r['_status']) for r in nobody] == [('No Organization Administrator.', AR)]


def test_deny_policy_row():
    row = pr.deny_policy_row(ORG, 0)
    assert row['Issue'] == 'No IAM deny policy guards the organization.' and row['_status'] == INFO
    assert row['Fix'].startswith(f'gcloud iam policies create org-guardrails --attachment-point=cloudresourcemanager.googleapis.com/organizations/{ORG} --kind=denypolicies')
    assert pr.deny_policy_row(ORG, 2) is None


def entitlement(short, roles, eligible=('user:oncall@example.test',), approvers=True, duration='3600s', justification=True, state='AVAILABLE', resource=f'projects/{PROJECT}'):
    body = {'name': f'{resource}/locations/global/entitlements/{short}', 'state': state, 'maxRequestDuration': duration,
            'eligibleUsers': [{'principals': list(eligible)}], 'privilegedAccess': {'gcpIamAccess': {'resource': f'//cloudresourcemanager.googleapis.com/{resource}', 'roleBindings': [{'role': r} for r in roles]}},
            'requesterJustificationConfig': {'unstructured': {}} if justification else {'notMandatory': {}}}
    if approvers:
        body['approvalWorkflow'] = {'manualApprovals': {'steps': [{'approvers': [{'principals': ['group:approvers@example.test']}], 'approvalsNeeded': 1}]}}
    return body


def test_entitlement_facts_and_rows():
    fact = pr.entitlement_facts(entitlement('jit-admin', ['roles/compute.admin', 'roles/viewer'], approvers=False, duration='7200s', justification=False))
    assert (fact['short'], fact['resource'], fact['roles'], fact['eligible'], fact['approvers'], fact['max_seconds'], fact['justification_optional'], fact['state']) == \
        ('jit-admin', f'projects/{PROJECT}', ['roles/compute.admin', 'roles/viewer'], ['user:oncall@example.test'], False, 7200, True, 'AVAILABLE')
    assert pr.is_admin_tier('roles/owner') and pr.is_admin_tier('roles/iam.securityAdmin') and pr.is_admin_tier('roles/compute.admin') and pr.is_admin_tier('roles/resourcemanager.organizationAdmin')
    assert not pr.is_admin_tier('roles/viewer') and not pr.is_admin_tier('roles/compute.instanceAdmin.v1')
    rows = pr.entitlement_rows([
        entitlement('jit-admin', ['roles/compute.admin'], approvers=False),  # the finding
        entitlement('jit-view', ['roles/viewer'], approvers=False),  # not an admin tier: nothing to approve
        entitlement('jit-long', ['roles/compute.admin'], duration='172800s', justification=False),  # approved, but long and unjustified
        entitlement('jit-fine', ['roles/owner']),  # approved, an hour, justified
        entitlement('jit-gone', ['roles/owner'], approvers=False, state='DELETING')])
    assert [(r['Condition'], r['Issue'], r['_status']) for r in rows] == [('jit-admin', 'Just-in-time grant without approval.', IR), ('jit-long', 'Long or unjustified just-in-time grant.', INFO)]
    assert rows[0]['Detail'] == f'user:oncall@example.test may take roles/compute.admin on projects/{PROJECT} with nobody approving.'
    assert rows[0]['Fix'] == (f'gcloud pam entitlements export jit-admin --location=global --project={PROJECT} > e.yaml  # add approvalWorkflow.manualApprovals.steps[0].approvers, then: '
                              f'gcloud pam entitlements update jit-admin --location=global --project={PROJECT} --entitlement-file=e.yaml')
    assert rows[1]['Detail'] == f'roles/compute.admin on projects/{PROJECT}: up to 48 h per request; no justification required.' and rows[1]['Type'] == 'PAM entitlement'
    org_row = pr.entitlement_rows([entitlement('org-jit', ['roles/resourcemanager.organizationAdmin'], approvers=False, resource=f'organizations/{ORG}')])[0]
    assert f'--organization={ORG}' in org_row['Fix'] and org_row['Resource'] == f'organizations/{ORG}'


def test_standing_grant_rows_match_principal_and_role_without_a_condition():
    entitlements = [entitlement('jit-admin', ['roles/compute.admin', 'roles/owner'], eligible=('user:oncall@example.test', 'group:sre@example.test'))]
    rows = pr.standing_grant_rows(f'projects/{PROJECT}', bindings(
        binding('roles/compute.admin', 'user:oncall@example.test', 'user:other@example.test'),  # the duplicate, and a principal the entitlement does not name
        binding('roles/owner', 'group:sre@example.test', condition='PAM grant until noon'),  # PAM's own grant: conditional, not standing
        binding('roles/viewer', 'user:oncall@example.test')), entitlements)  # a role the entitlement does not offer
    assert [(r['Principal'], r['Role'], r['_status']) for r in rows] == [('user:oncall@example.test', 'roles/compute.admin', AR)]
    assert rows[0]['Fix'] == f'gcloud projects remove-iam-policy-binding {PROJECT} --member=user:oncall@example.test --role=roles/compute.admin  # entitlement jit-admin grants it on request'
    assert rows[0]['Issue'] == 'Standing grant duplicates a just-in-time entitlement.' and rows[0]['Type'] == 'user'


class Pam:
    """Privileged Access Manager: entitlements per parent; SERVICE_DISABLED where the API is off; an injected failure."""

    def __init__(self, entitlements=None, disabled=(), failing=()):
        self.entitlements, self.disabled, self.failing, self.parents = entitlements or {}, set(disabled), set(failing), []

    def _collection(self):
        pam = self

        class Entitlements:
            def list(self, parent):
                pam.parents.append(parent)
                resource = parent.rsplit('/locations/', 1)[0]
                if resource in pam.disabled:
                    return _execute(RuntimeError(f'403 Privileged Access Manager API has not been used in project {resource} before or it is disabled. SERVICE_DISABLED'))
                if resource in pam.failing:
                    return _execute(RuntimeError('500 backend error'))
                return _execute({'entitlements': pam.entitlements.get(resource, [])})

            def list_next(self, previous_request, previous_response):
                return None
        return Entitlements()

    def organizations(self):
        return SimpleNamespace(locations=lambda: SimpleNamespace(entitlements=self._collection))

    def folders(self):
        return self.organizations()

    def projects(self):
        return self.organizations()


class IamV2:
    def __init__(self, policies=0, error=None):
        self.n, self.error, self.parents = policies, error, []

    def policies(self):
        iam = self

        class Policies:
            def listPolicies(self, parent):
                iam.parents.append(parent)
                return _execute(iam.error or {'policies': [{'name': f'p{i}'} for i in range(iam.n)]})

            def listPolicies_next(self, previous_request, previous_response):
                return None
        return Policies()


def api_builder(crm, pam, iam2):
    def build(service, version, **kwargs):
        if service == 'privilegedaccessmanager':
            assert kwargs.get('static_discovery') is False  # no bundled discovery document for PAM
            return pam
        if service == 'iam' and version == 'v2':
            return iam2
        return crm
    return build


def test_check_privileged_grants_end_to_end_organization(gcp, monkeypatch):
    crm = Crm(org_policy={'bindings': ORG_BINDINGS + [binding('roles/compute.admin', 'user:oncall@example.test')]},
              project_policies={PROJECT: {'bindings': [binding('roles/compute.admin', 'user:oncall@example.test')]}})
    pam = Pam(entitlements={f'organizations/{ORG}': [entitlement('org-jit', ['roles/compute.admin'], approvers=False, resource=f'organizations/{ORG}')],
                            f'projects/{PROJECT}': [entitlement('jit-admin', ['roles/compute.admin'])],
                            f'folders/{FOLDER}': [entitlement('folder-jit', ['roles/owner'], approvers=False, resource=f'folders/{FOLDER}')]},
              disabled={'projects/no-pam'}, failing={'projects/broken'})
    inventory = Inventory(folders=[(FOLDER, 'prod', f'organizations/{ORG}', 'ACTIVE')])
    monkeypatch.setattr(pr.gcp, 'api_build', api_builder(crm, pam, IamV2(policies=0)))
    monkeypatch.setattr(pr.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    pr.check_privileged_grants('organization', ORG, [{'projectId': PROJECT}, {'projectId': 'no-pam'}, {'projectId': 'broken'}], JOB, sink=sink)
    record = sink.by_check()['Privileged Grants']
    assert record['Status'] == AR
    issues = [(r['Resource'], r['Principal'], r['Issue']) for r in record['Finding']]
    assert issues[:7] == [(f'organizations/{ORG}', 'domain:example.test', 'Project creation granted at the organization.'),
                          (f'organizations/{ORG}', 'serviceAccount:factory@tooling.iam.gserviceaccount.com', 'Project creation granted at the organization.'),
                          (f'organizations/{ORG}', 'user:lead@example.test', 'Project creation granted at the organization.'),
                          (f'organizations/{ORG}', 'group:factory@example.test', 'Project creation granted at the organization.'),
                          (f'organizations/{ORG}', 'group:ops-finance@partner.example', 'Billing role granted at the organization.'),
                          (f'organizations/{ORG}', 'domain:example.test', 'Billing role granted at the organization.'),
                          (f'organizations/{ORG}', 'user:cfo@example.test', 'Billing role granted at the organization.')]
    assert issues[7:] == [(f'organizations/{ORG}', 'user:oncall@example.test', 'Just-in-time grant without approval.'),
                          (f'organizations/{ORG}', 'user:oncall@example.test', 'Standing grant duplicates a just-in-time entitlement.'),
                          (f'organizations/{ORG}', '—', 'No IAM deny policy guards the organization.'),
                          (f'folders/{FOLDER}', 'user:oncall@example.test', 'Just-in-time grant without approval.'),
                          (f'projects/{PROJECT}', 'user:oncall@example.test', 'Standing grant duplicates a just-in-time entitlement.')]
    assert pam.parents == [f'organizations/{ORG}/locations/global', f'folders/{FOLDER}/locations/global', f'projects/{PROJECT}/locations/global', 'projects/no-pam/locations/global', 'projects/broken/locations/global']
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [('broken', 'Privileged Grants (the Privileged Access Manager entitlements could not be listed)')]
    assert ('projects.getIamPolicy', PROJECT, pr.POLICY_V3) in crm.calls  # read only for the project with entitlements
    assert all('_status' not in r for r in record['Finding'])


def test_check_privileged_grants_halves_and_failures(gcp, monkeypatch):
    crm = Crm(org_policy={'bindings': ORG_BINDINGS})
    pam = Pam(entitlements={f'projects/{PROJECT}': [entitlement('jit-admin', ['roles/owner'], approvers=False)]})
    monkeypatch.setattr(pr.gcp, 'api_build', api_builder(crm, pam, IamV2(policies=1)))
    monkeypatch.setattr(pr.gcp, 'asset_client', lambda credentials=None: Inventory())
    # The scope half of an organization scan: the organization's rows, no project read; a deny policy exists: no Informational row.
    sink = Sink()
    pr.check_privileged_grants('organization', ORG, [{'projectId': PROJECT}], JOB, sink=sink, project_level=False)
    record = sink.by_check()['Privileged Grants']
    assert [r['Issue'] for r in record['Finding']].count('No IAM deny policy guards the organization.') == 0 and pam.parents == [f'organizations/{ORG}/locations/global']
    assert not any(call[0] == 'projects.getIamPolicy' for call in crm.calls)
    # The project half: the project's entitlement, no organization read.
    sink = Sink()
    pr.check_privileged_grants('organization', ORG, [{'projectId': PROJECT}], JOB, sink=sink, scope_level=False)
    record = sink.by_check()['Privileged Grants']
    assert [(r['Resource'], r['Issue'], ) for r in record['Finding']] == [(f'projects/{PROJECT}', 'Just-in-time grant without approval.')] and record['Status'] == IR
    assert not any(call[0] == 'organizations.getIamPolicy' for call in crm.calls[-2:])
    # A folder scan: the folder's entitlements (none) and the projects'; the organization rules are not judged there.
    sink = Sink()
    pr.check_privileged_grants('folder', FOLDER, [], JOB, sink=sink)
    assert sink.by_check()['Privileged Grants'] == {'Check': 'Privileged Grants', 'Finding': [{'Status': pr.PRIVILEGED_GRANTS_ALL_CLEAR}], 'Status': C}
    # The organization's policy refused: an Error record.
    monkeypatch.setattr(pr.gcp, 'api_build', api_builder(Crm(errors={'org': RuntimeError('403 organizations.getIamPolicy')}), pam, IamV2()))
    sink = Sink()
    pr.check_privileged_grants('organization', ORG, [], JOB, sink=sink)
    assert sink.by_check()['Privileged Grants']['Status'] == 'Error'
    # The deny-policy listing failing is a line, not an Error.
    monkeypatch.setattr(pr.gcp, 'api_build', api_builder(Crm(org_policy={'bindings': ORG_BINDINGS}), pam, IamV2(error=RuntimeError('403 iam.denypolicies.list'))))
    sink = Sink()
    pr.check_privileged_grants('organization', ORG, [], JOB, sink=sink)
    assert [r['Skipped check'] for r in sink.not_checked()] == ['Privileged Grants (the IAM deny policies could not be listed)']


# --- Custom Roles With IAM Powers --------------------------------------------------------------------------------------------

def role(parent, short, permissions, stage='GA', deleted=False):
    body = {'name': f'{parent}/roles/{short}', 'title': short, 'includedPermissions': list(permissions), 'etag': 'x'}
    if stage:
        body['stage'] = stage
    if deleted:
        body['deleted'] = True
    return body


def test_role_facts_and_powers():
    assert pr.iam_power('resourcemanager.projects.setIamPolicy') and pr.iam_power('storage.buckets.setIamPolicy') and pr.iam_power('iam.serviceAccounts.actAs')
    assert not pr.iam_power('resourcemanager.projects.getIamPolicy') and not pr.iam_power('compute.instances.setMetadata') and not pr.iam_power('iam.roles.get')
    fact = pr.role_facts(role(f'organizations/{ORG}', 'policy_automation', ['resourcemanager.projects.setIamPolicy', 'resourcemanager.folders.setIamPolicy', 'resourcemanager.projects.get'], stage=None), f'organizations/{ORG}')
    assert fact == {'name': f'organizations/{ORG}/roles/policy_automation', 'short': 'policy_automation', 'parent': f'organizations/{ORG}', 'stage': 'ALPHA', 'deleted': False,
                    'powers': ['resourcemanager.folders.setIamPolicy', 'resourcemanager.projects.setIamPolicy']}


def test_custom_role_rows_by_holder_and_stage():
    org = f'organizations/{ORG}'
    roles = [pr.role_facts(role(org, 'policy_automation', ['resourcemanager.projects.setIamPolicy']), org),
             pr.role_facts(role(org, 'dfir', ['iam.serviceAccounts.actAs', 'compute.instances.get']), org),
             pr.role_facts(role(org, 'project_automation', ['resourcemanager.projects.setIamPolicy']), org),
             pr.role_facts(role(org, 'old_viewer', ['compute.instances.get'], stage='DEPRECATED'), org),
             pr.role_facts(role(org, 'gone', ['compute.instances.get'], deleted=True), org),
             pr.role_facts(role(f'projects/{PROJECT}', 'subnet_role', ['compute.subnetworks.get']), f'projects/{PROJECT}'),
             pr.role_facts(role(f'projects/{PROJECT}', 'token_minter', ['iam.serviceAccounts.getAccessToken']), f'projects/{PROJECT}')]
    holders = {f'{org}/roles/policy_automation': [(org, 'group:ops-robots@partner.example'), (org, 'serviceAccount:automation@system.gserviceaccount.com')],
               f'{org}/roles/dfir': [(org, 'serviceAccount:forensics@system.gserviceaccount.com')],  # Google-managed only
               f'{org}/roles/old_viewer': [(f'projects/{PROJECT}', 'user:x@example.test')],
               f'projects/{PROJECT}/roles/token_minter': [(f'projects/{PROJECT}', f'serviceAccount:ci@{PROJECT}.iam.gserviceaccount.com')]}
    rows = pr.custom_role_rows(roles, holders)
    assert [(r['Role'], r['Stage'], r['Issue'], r['_status']) for r in rows] == [
        ('policy_automation', 'GA', 'Custom role carries IAM powers.', IR), ('dfir', 'GA', 'Dormant custom role carries IAM powers.', INFO),
        ('project_automation', 'GA', 'Dormant custom role carries IAM powers.', INFO), ('old_viewer', 'DEPRECATED', 'Retired custom role still bound.', INFO),
        ('token_minter', 'GA', 'Custom role carries IAM powers.', IR)]  # the deleted unbound role and the plain subnet role are not rows
    assert rows[0]['Holders'] == f'group:ops-robots@partner.example on {org}; serviceAccount:automation@system.gserviceaccount.com on {org}'
    assert rows[0]['Fix'] == f'gcloud iam roles update policy_automation --organization={ORG} --remove-permissions=resourcemanager.projects.setIamPolicy  # grant the predefined role that carries them, deliberately, to the principals that need them'
    assert rows[2]['Fix'] == f'gcloud iam roles delete project_automation --organization={ORG}  # nobody holds it; or keep it deliberately' and rows[2]['Holders'] == 'none'
    assert rows[3]['Fix'] == f'gcloud projects remove-iam-policy-binding {PROJECT} --member=user:x@example.test --role={org}/roles/old_viewer  # per holder; then delete the role'
    assert rows[4]['Fix'].startswith(f'gcloud iam roles update token_minter --project={PROJECT} --remove-permissions=iam.serviceAccounts.getAccessToken')
    assert set(rows[0]) == {'Role', 'Defined at', 'Stage', 'Powers', 'Holders', 'Issue', 'Detail', 'Fix', '_status'}


class Iam:
    def __init__(self, org_roles=(), project_roles=None, errors=None):
        self.org_roles, self.project_roles, self.errors, self.parents = list(org_roles), project_roles or {}, errors or {}, []

    def _collection(self, roles_of):
        iam = self

        class Roles:
            def list(self, parent, view, showDeleted):
                assert (view, showDeleted) == ('FULL', True)
                iam.parents.append(parent)
                if parent in iam.errors:
                    return _execute(iam.errors[parent])
                return _execute({'roles': roles_of(parent)})

            def list_next(self, previous_request, previous_response):
                return None
        return Roles()

    def organizations(self):
        return SimpleNamespace(roles=lambda: self._collection(lambda parent: self.org_roles))

    def projects(self):
        return SimpleNamespace(roles=lambda: self._collection(lambda parent: self.project_roles.get(parent, [])))


def test_check_custom_roles_end_to_end(gcp, monkeypatch):
    org = f'organizations/{ORG}'
    iam = Iam(org_roles=[role(org, 'policy_automation', ['resourcemanager.projects.setIamPolicy']), role(org, 'viewer_plus', ['compute.instances.get'])],
              project_roles={f'projects/{PROJECT}': [role(f'projects/{PROJECT}', 'token_minter', ['iam.serviceAccounts.getAccessToken'])]}, errors={'projects/locked': RuntimeError('403 iam.roles.list')})
    inventory = Inventory(policies=[policy_result('organizations', ORG, binding(f'{org}/roles/policy_automation', 'group:ops-robots@partner.example'), binding('roles/viewer', 'user:x@example.test')),
                                    policy_result('projects', PROJECT, binding(f'projects/{PROJECT}/roles/token_minter', f'serviceAccount:ci@{PROJECT}.iam.gserviceaccount.com'))])
    monkeypatch.setattr(pr.gcp, 'api_build', lambda *args, **kwargs: iam)
    monkeypatch.setattr(pr.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    pr.check_custom_roles('organization', ORG, [{'projectId': PROJECT}, {'projectId': 'locked'}], JOB, sink=sink)
    record = sink.by_check()['Custom Roles With IAM Powers']
    assert record['Status'] == IR and [(r['Role'], r['Defined at'], r['Holders']) for r in record['Finding']] == [
        ('policy_automation', org, f'group:ops-robots@partner.example on {org}'), ('token_minter', f'projects/{PROJECT}', f'serviceAccount:ci@{PROJECT}.iam.gserviceaccount.com on projects/{PROJECT}')]
    assert iam.parents == [org, f'projects/{PROJECT}', 'projects/locked'] and [r['Project'] for r in sink.not_checked()] == ['locked']
    query = inventory.requests[-1]['query']
    assert query == f'roles:("{org}/roles/policy_automation" OR "projects/{PROJECT}/roles/token_minter")' and inventory.requests[-1]['scope'] == org
    # The halves: the scope half lists the organization's roles only; the project half the projects' only. A folder scan never lists the organization's.
    sink, iam.parents = Sink(), []
    pr.check_custom_roles('organization', ORG, [{'projectId': PROJECT}], JOB, sink=sink, project_level=False)
    assert iam.parents == [org] and [r['Role'] for r in sink.by_check()['Custom Roles With IAM Powers']['Finding']] == ['policy_automation']
    sink, iam.parents = Sink(), []
    pr.check_custom_roles('folder', FOLDER, [{'projectId': PROJECT}], JOB, sink=sink)
    assert iam.parents == [f'projects/{PROJECT}'] and [r['Role'] for r in sink.by_check()['Custom Roles With IAM Powers']['Finding']] == ['token_minter']
    # Nothing flagged: no holders search, the all-clear. The holders search failing: the roles stand as dormant, a line says so.
    sink, inventory.requests = Sink(), []
    pr.check_custom_roles('project', PROJECT, [{'projectId': 'empty'}], JOB, sink=sink)
    assert sink.by_check()['Custom Roles With IAM Powers']['Status'] == C and inventory.requests == []
    monkeypatch.setattr(pr.gcp, 'asset_client', lambda credentials=None: Inventory(error=RuntimeError('503 search')))
    sink = Sink()
    pr.check_custom_roles('organization', ORG, [], JOB, sink=sink)
    record = sink.by_check()['Custom Roles With IAM Powers']
    assert record['Status'] == INFO and [r['Skipped check'] for r in sink.not_checked()] == ['Custom Roles With IAM Powers (holders: the IAM-policy search failed; the roles are listed as dormant)']
    # The organization's roles refused: an Error record.
    monkeypatch.setattr(pr.gcp, 'api_build', lambda *args, **kwargs: Iam(errors={org: RuntimeError('403 iam.roles.list')}))
    sink = Sink()
    pr.check_custom_roles('organization', ORG, [], JOB, sink=sink)
    assert sink.by_check()['Custom Roles With IAM Powers']['Status'] == 'Error'


# --- the registry ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('scope', ['organization', 'folder', 'project'])
def test_the_split_checks_run_their_halves_in_the_right_shards(scope):
    scope_plan = registry.scope_check_plan(scope, 'x', JOB)
    project_plan = registry.project_check_plan(scope, 'x', JOB, [{'projectId': PROJECT}], [], [])
    for name in (pr.PRIVILEGED_GRANTS_CHECK, pr.CUSTOM_ROLES_CHECK):
        in_scope = next(spec for spec in scope_plan if spec.name == name)
        in_project = next(spec for spec in project_plan if spec.name == name)
        assert in_scope.func.keywords == {'project_level': False} and in_scope.args[2] == []
        assert in_project.func.keywords == {'scope_level': False} and in_project.args[2] == [{'projectId': PROJECT}]
    assert pr.FOLDER_ROLES_CHECK in registry.SCOPE_LEVEL_CHECKS and not any(name in RESHAPED_CHECKS for name in pr.PRIVILEGE_CHECKS)
