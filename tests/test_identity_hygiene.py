"""
v18.5 — VM hardening & identities, the IAM half: the rules of ``app.checks.identity_hygiene`` on fixtures of the shapes the Asset
Inventory IAM-policy search returns (projects named by ID, with project number, folders and organization), the image search and the
recommender's service-account insights; the two checks end to end.
"""
from types import SimpleNamespace

from google.cloud import recommender_v1

from app.checks import identity_hygiene as ih
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS
from tests.helpers import make_settings

JOB = 'job-185'
AR, IR, C = 'Action Required', 'Investigation Recommended', 'Compliant'
ORG, FOLDER, PROJECT, NUMBER = '987654321', '1061000000000', 'stark-vm-prod', '208800000000'
DEFAULT = f'serviceAccount:{NUMBER}-compute@developer.gserviceaccount.com'


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
    return SimpleNamespace(role=role, members=list(members), condition=SimpleNamespace(title=condition, expression=f'expr({condition})') if condition else SimpleNamespace(title='', expression=''))


def policy(kind, ident, *bindings):
    """An IAM-policy search result: a project is named by ID and carries its number, folders and organization."""
    return SimpleNamespace(resource=f'//cloudresourcemanager.googleapis.com/{kind}/{ident}', asset_type=f'cloudresourcemanager.googleapis.com/{kind[:-1].capitalize()}',
                           project=f'projects/{NUMBER}' if kind == 'projects' else '', folders=[f'folders/{FOLDER}'] if kind != 'organizations' else [],
                           organization=f'organizations/{ORG}', policy=SimpleNamespace(bindings=list(bindings)))


def facts(*assets):
    return [ih.policy_facts(asset) for asset in assets]


# --- the facts -----------------------------------------------------------------------------------------------------------

def test_policy_facts_and_the_organization():
    fact = ih.policy_facts(policy('projects', PROJECT, binding('roles/viewer', 'group:readers@example.test', condition='temp')))
    assert (fact['resource'], fact['level'], fact['ancestors']) == (f'projects/{PROJECT}', 'project', [f'projects/{NUMBER}', f'folders/{FOLDER}', f'organizations/{ORG}'])
    assert fact['bindings'] == [('roles/viewer', ['group:readers@example.test'], {'title': 'temp', 'expression': 'expr(temp)'})]
    assert ih.policy_facts(policy('organizations', ORG))['level'] == 'organization' and ih.policy_facts(policy('folders', FOLDER))['level'] == 'folder'
    # A listed asset (content_type IAM_POLICY) reads the same way: name, iam_policy, ancestors.
    listed = SimpleNamespace(name=f'//cloudresourcemanager.googleapis.com/projects/{NUMBER}', asset_type='cloudresourcemanager.googleapis.com/Project',
                             ancestors=[f'projects/{NUMBER}', f'organizations/{ORG}'], iam_policy=SimpleNamespace(bindings=[binding('roles/viewer', 'user:a@example.test')]))
    assert ih.policy_facts(listed) == {'resource': f'projects/{NUMBER}', 'level': 'project', 'bindings': [('roles/viewer', ['user:a@example.test'], {})], 'ancestors': [f'projects/{NUMBER}', f'organizations/{ORG}']}
    assert ih.organization_of([], 'organization', ORG) == f'organizations/{ORG}'
    assert ih.organization_of(facts(policy('projects', PROJECT)), 'project', PROJECT) == f'organizations/{ORG}' and ih.organization_of([], 'project', PROJECT) == ''
    assert ih.is_admin_role('roles/compute.admin') and ih.is_admin_role('roles/iam.securityAdmin') and ih.is_admin_role('roles/storage.objectAdmin') and ih.is_admin_role('roles/billing.admin')
    assert not ih.is_admin_role('roles/viewer') and not ih.is_admin_role('roles/compute.instanceAdmin.v1') and not ih.is_admin_role(f'organizations/{ORG}/roles/customAdmin')
    assert ih.remove_binding(f'folders/{FOLDER}', 'user:a@example.test', 'roles/viewer', {}) == f'gcloud resource-manager folders remove-iam-policy-binding {FOLDER} --member=user:a@example.test --role=roles/viewer'
    assert ih.remove_binding(f'organizations/{ORG}', 'user:a@example.test', 'roles/viewer', {'title': 't', 'expression': 'e'}) == \
        f"gcloud organizations remove-iam-policy-binding {ORG} --member=user:a@example.test --role=roles/viewer --condition='expression=e,title=t'"


# --- Service Account Privileges --------------------------------------------------------------------------------------------

def test_admin_role_rows_by_role_holder_and_level():
    policies = facts(
        policy('projects', PROJECT,
               binding('roles/compute.admin', DEFAULT, 'user:ops@example.test'), binding('roles/container.admin', DEFAULT),  # the survey's default account
               binding('roles/storage.admin', f'serviceAccount:app@{PROJECT}.iam.gserviceaccount.com'),
               binding('roles/iam.securityAdmin', f'serviceAccount:ci@{PROJECT}.iam.gserviceaccount.com', condition='until-friday'),
               binding('roles/editor', f'serviceAccount:legacy@{PROJECT}.iam.gserviceaccount.com'),  # Primitive Roles' row
               binding('roles/compute.instanceAdmin.v1', f'serviceAccount:deploy@{PROJECT}.iam.gserviceaccount.com'),  # not admin-named
               binding(f'projects/{PROJECT}/roles/customAdmin', f'serviceAccount:app@{PROJECT}.iam.gserviceaccount.com'),  # custom: not judged
               binding('roles/compute.serviceAgent', f'serviceAccount:service-{NUMBER}@compute-system.iam.gserviceaccount.com'),
               binding('roles/cloudtasks.admin', f'serviceAccount:service-{NUMBER}@gcp-sa-cloudtasks.iam.gserviceaccount.com')),  # agents
        policy('organizations', ORG,
               binding('roles/resourcemanager.organizationAdmin', 'serviceAccount:automation@system.gserviceaccount.com', 'serviceAccount:env@tooling.iam.gserviceaccount.com'),  # critical: Critical Org-Level Roles' row
               binding('roles/orgpolicy.policyAdmin', 'serviceAccount:env@tooling.iam.gserviceaccount.com'),
               binding('roles/dns.admin', 'serviceAccount:env-mgmt@appspot.gserviceaccount.com')))
    rows = ih.admin_role_rows(policies)
    assert [(r['Resource'], r['Principal'].split(':')[1].split('@')[0], r['Role'], r['_status']) for r in rows] == [
        (f'projects/{PROJECT}', f'{NUMBER}-compute', 'roles/compute.admin', AR), (f'projects/{PROJECT}', f'{NUMBER}-compute', 'roles/container.admin', AR),
        (f'projects/{PROJECT}', 'app', 'roles/storage.admin', IR), (f'projects/{PROJECT}', 'ci', 'roles/iam.securityAdmin', AR),
        (f'organizations/{ORG}', 'env', 'roles/orgpolicy.policyAdmin', AR), (f'organizations/{ORG}', 'env-mgmt', 'roles/dns.admin', AR)]
    assert rows[0]['Type'] == 'default service account' and 'identity every VM, function and Cloud Run service gets' in rows[0]['Detail']
    assert rows[2]['Type'] == 'service account' and rows[2]['Detail'].startswith('An administrative role on a non-human identity')
    assert rows[3]['Detail'].startswith('Grants the power to change who may do what') and rows[3]['Fix'] == (
        f"gcloud projects remove-iam-policy-binding {PROJECT} --member=serviceAccount:ci@{PROJECT}.iam.gserviceaccount.com --role=roles/iam.securityAdmin "
        f"--condition='expression=expr(until-friday),title=until-friday'  # grant a role scoped to the work, on the resource it needs")
    assert rows[4]['Fix'].startswith(f'gcloud organizations remove-iam-policy-binding {ORG} ')
    assert all(set(r) == {'Resource', 'Principal', 'Type', 'Role', 'Issue', 'Detail', 'Fix', '_status'} and r['Issue'] == 'Administrative role on a service account.' for r in rows)


def test_role_separation_rows():
    policies = facts(policy('projects', PROJECT, binding('roles/iam.serviceAccountAdmin', 'user:platform@example.test', 'group:sa-admins@example.test', f'serviceAccount:service-{NUMBER}@gcp-sa-x.iam.gserviceaccount.com'),
                            binding('roles/iam.serviceAccountUser', 'user:platform@example.test', 'user:dev@example.test', f'serviceAccount:service-{NUMBER}@gcp-sa-x.iam.gserviceaccount.com'),
                            binding('roles/iam.serviceAccountTokenCreator', 'user:platform@example.test')),
                     policy('folders', FOLDER, binding('roles/iam.serviceAccountAdmin', 'group:sa-admins@example.test'), binding('roles/iam.serviceAccountTokenCreator', 'group:sa-admins@example.test')))
    rows = ih.role_separation_rows(policies)
    assert [(r['Resource'], r['Principal'], r['Role']) for r in rows] == [
        (f'projects/{PROJECT}', 'user:platform@example.test', 'roles/iam.serviceAccountAdmin, roles/iam.serviceAccountTokenCreator, roles/iam.serviceAccountUser'),
        (f'folders/{FOLDER}', 'group:sa-admins@example.test', 'roles/iam.serviceAccountAdmin, roles/iam.serviceAccountTokenCreator')]
    assert rows[0]['Fix'] == f'gcloud projects remove-iam-policy-binding {PROJECT} --member=user:platform@example.test --role=roles/iam.serviceAccountTokenCreator  # or the admin role; keep one'
    assert all(r['_status'] == IR and r['Issue'] == 'Administers and uses service accounts.' for r in rows)


# --- External Principals ----------------------------------------------------------------------------------------------------

def test_external_rows_by_kind_domain_and_trust():
    policies = facts(
        policy('projects', PROJECT,
               binding('roles/viewer', 'user:contractor@partner.example', 'user:dev@example.test', 'group:ops@acquired.example', 'group:readers@example.test', 'allUsers'),
               binding('roles/logging.viewer', 'user:contractor@partner.example', 'user:someone@gmail.com', 'deleted:user:gone@example.test?uid=123'),
               binding('roles/browser', 'domain:acquired.example', 'domain:example.test', 'serviceAccount:x@other.iam.gserviceaccount.com')),
        policy('folders', FOLDER, binding('roles/viewer', 'allAuthenticatedUsers', 'group:platform@twosync.google.example')),
        policy('organizations', ORG, binding('roles/browser', 'user:auditor@consulting.example')))
    rows = ih.external_rows(policies, ('example.test',))
    assert [(r['Resource'], r['Principal'], r['Issue'], r['_status']) for r in rows] == [
        (f'projects/{PROJECT}', 'user:contractor@partner.example', 'User outside the organization.', IR),
        (f'projects/{PROJECT}', 'group:ops@acquired.example', 'Group outside the organization.', IR),
        (f'projects/{PROJECT}', 'user:someone@gmail.com', 'Consumer account in the policy.', AR),
        (f'projects/{PROJECT}', 'deleted:user:gone@example.test?uid=123', 'Deleted principal still bound.', IR),
        (f'projects/{PROJECT}', 'domain:acquired.example', 'External domain granted.', AR),
        (f'folders/{FOLDER}', 'allAuthenticatedUsers', 'Folder open to the public.', AR),
        (f'folders/{FOLDER}', 'group:platform@twosync.google.example', 'Group outside the organization.', IR),
        (f'organizations/{ORG}', 'user:auditor@consulting.example', 'User outside the organization.', IR)]
    assert rows[0]['Roles'] == 'roles/logging.viewer, roles/viewer' and rows[0]['Type'] == 'user (outside the primary domain)'
    assert rows[0]['Fix'] == (f'gcloud projects remove-iam-policy-binding {PROJECT} --member=user:contractor@partner.example --role=roles/viewer; '
                              f'gcloud projects remove-iam-policy-binding {PROJECT} --member=user:contractor@partner.example --role=roles/logging.viewer')
    assert all(set(r) == {'Resource', 'Principal', 'Type', 'Roles', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    # Trusted domains are the organization's for the rule; the public principal on the project is Primitive Roles' row, not this check's.
    trusted = ih.external_rows(policies, ('example.test',), trusted=('partner.example', 'acquired.example', 'twosync.google.example', 'consulting.example'))
    assert [r['Principal'] for r in trusted] == ['user:someone@gmail.com', 'deleted:user:gone@example.test?uid=123', 'allAuthenticatedUsers']
    # Without the organization's domain only the rules that need none apply.
    assert [r['Issue'] for r in ih.external_rows(policies, ())] == ['Consumer account in the policy.', 'Deleted principal still bound.', 'Folder open to the public.']


def test_public_image_rows():
    public = {f'//compute.googleapis.com/projects/{PROJECT}/global/images/golden-2026': [('roles/compute.imageUser', 'allAuthenticatedUsers')]}
    rows = ih.public_image_rows(public)
    assert rows == [{'Resource': f'image golden-2026 ({PROJECT})', 'Principal': 'allAuthenticatedUsers', 'Type': 'public', 'Roles': 'roles/compute.imageUser', 'Issue': 'Image open to the public.',
                     'Detail': 'Anyone can boot from the image and read what it contains (credentials, code).',
                     'Fix': f'gcloud compute images remove-iam-policy-binding golden-2026 --project={PROJECT} --member=allAuthenticatedUsers --role=roles/compute.imageUser', '_status': AR}]


# --- Unused Service Accounts ------------------------------------------------------------------------------------------------

def insight(email, last=None, subtype='SERVICE_ACCOUNT_USAGE', state='ACTIVE'):
    content = {'email': email, 'serviceAccountId': '1136'}
    if last:
        content['lastAuthenticatedTime'] = last
    return recommender_v1.Insight({'name': f'projects/{PROJECT}/locations/global/insightTypes/{ih.INSIGHT_TYPE}/insights/1', 'description': f'Service account {email} was inactive.',
                                   'insight_subtype': subtype, 'severity': 'LOW', 'state_info': {'state': state}, 'content': content})


def test_unused_account_rows_from_insights():
    rows = ih.unused_account_rows(PROJECT, [insight(f'gcs-accessor@{PROJECT}.iam.gserviceaccount.com', '2025-09-24T07:00:00Z'), insight(f'{NUMBER}-compute@developer.gserviceaccount.com'),
                                            insight(f'old@{PROJECT}.iam.gserviceaccount.com', state='DISMISSED'), insight(f'x@{PROJECT}.iam.gserviceaccount.com', subtype='OTHER'),
                                            {'insightSubtype': 'SERVICE_ACCOUNT_USAGE', 'stateInfo': {'state': 'ACTIVE'}, 'content': {'email': f'dict@{PROJECT}.iam.gserviceaccount.com'}}])
    assert [(r['Service Account'], r['Last authenticated'], r['_status']) for r in rows] == [
        (f'gcs-accessor@{PROJECT}.iam.gserviceaccount.com', '2025-09-24', IR), (f'{NUMBER}-compute@developer.gserviceaccount.com', 'never (in the window)', IR),
        (f'dict@{PROJECT}.iam.gserviceaccount.com', 'never (in the window)', IR)]
    assert rows[0]['Fix'] == f'gcloud iam service-accounts disable gcs-accessor@{PROJECT}.iam.gserviceaccount.com --project={PROJECT}  # then delete it after a quiet period'
    assert rows[1]['Fix'].endswith('# a default account: detach it from what still names it, disable, never delete')
    assert all(set(r) == {'Project', 'Service Account', 'Last authenticated', 'Issue', 'Detail', 'Fix', '_status'} and r['Issue'] == 'Unused for 90+ days.' for r in rows)


# --- the checks end to end ----------------------------------------------------------------------------------------------------

class Inventory:
    """``search_all_iam_policies`` answers the empty query with ``policies`` and the public query with ``images``."""
    def __init__(self, policies=(), error=None, images=(), search_error=None):
        self.policies, self.error, self.images, self.search_error, self.requests = list(policies), error, list(images), search_error, []

    def search_all_iam_policies(self, request):
        self.requests.append(request)
        if request.get('query') == ih.PUBLIC_QUERY:
            assert request['asset_types'] == ih.IMAGE_TYPES
            if self.search_error:
                raise self.search_error
            return iter(self.images)
        if self.error:
            raise self.error
        return iter(self.policies)


class Crm:
    def __init__(self, display_name='example.test', error=None):
        self.display_name, self.error, self.names = display_name, error, []

    def organizations(self):
        return self

    def get(self, name):
        self.names.append(name)
        return self

    def execute(self):
        if self.error:
            raise self.error
        return {'name': self.names[-1], 'displayName': self.display_name}


def test_check_identity_hygiene_end_to_end(gcp, monkeypatch):
    policies = [policy('projects', PROJECT, binding('roles/compute.admin', DEFAULT), binding('roles/viewer', 'user:contractor@partner.example', 'user:dev@example.test')),
                policy('folders', FOLDER), policy('organizations', ORG, binding('roles/browser', 'group:cloud-admins@example.test'))]
    image = SimpleNamespace(resource=f'//compute.googleapis.com/projects/{PROJECT}/global/images/golden', policy=SimpleNamespace(bindings=[SimpleNamespace(role='roles/compute.imageUser', members=['allUsers'])]))
    inventory, crm = Inventory(policies, images=[image]), Crm()
    monkeypatch.setattr(ih.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(ih.gcp, 'api_build', lambda *args, **kwargs: crm)
    sink = Sink()
    ih.check_identity_hygiene('organization', ORG, JOB, sink=sink)
    records = sink.by_check()
    assert {name: record['Status'] for name, record in records.items()} == {'Service Account Privileges': AR, 'External Principals': AR}
    assert [(r['Resource'], r['Principal'], r['Role']) for r in records['Service Account Privileges']['Finding']] == [(f'projects/{PROJECT}', DEFAULT, 'roles/compute.admin')]
    assert [(r['Resource'], r['Principal'], r['Issue']) for r in records['External Principals']['Finding']] == [
        (f'projects/{PROJECT}', 'user:contractor@partner.example', 'User outside the organization.'), (f'image golden ({PROJECT})', 'allUsers', 'Image open to the public.')]
    assert inventory.requests[0] == {'scope': f'organizations/{ORG}', 'asset_types': ih.POLICY_TYPES, 'page_size': 500}  # the policies come from the search index
    assert crm.names == [f'organizations/{ORG}'] and sink.not_checked() == []
    assert all('_status' not in r for record in records.values() for r in record['Finding'])
    # TRUSTED_DOMAINS: the partner's domain is the organization's for the rule.
    monkeypatch.setattr(ih, 'get_settings', lambda: make_settings(TRUSTED_DOMAINS='partner.example'))
    sink = Sink()
    ih.check_identity_hygiene('organization', ORG, JOB, sink=sink)
    assert [r['Principal'] for r in sink.by_check()['External Principals']['Finding']] == ['allUsers']
    monkeypatch.setattr(ih, 'get_settings', lambda: make_settings())
    # The side reads failing: the external-domain rule is skipped, the image rule is skipped — each said under Projects not checked.
    inventory = Inventory(policies, search_error=RuntimeError('403 denied'))
    monkeypatch.setattr(ih.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(ih.gcp, 'api_build', lambda *args, **kwargs: Crm(error=RuntimeError('403 organizations.get')))
    sink = Sink()
    ih.check_identity_hygiene('project', PROJECT, JOB, sink=sink)
    records = sink.by_check()
    assert [r['Resource'] for r in records['Service Account Privileges']['Finding']] == [f'projects/{PROJECT}'] and records['External Principals']['Status'] == C
    assert [r['Skipped check'] for r in sink.not_checked()] == [
        'Service Account Privileges (external-domain rule: the organization\'s domain could not be read)',
        'Service Account Privileges (public images rule: the IAM policy search failed)']
    # Nothing in scope: two all-clear rows. A listing that fails: two Errors.
    monkeypatch.setattr(ih.gcp, 'asset_client', lambda credentials=None: Inventory())
    monkeypatch.setattr(ih.gcp, 'api_build', lambda *args, **kwargs: Crm())
    sink = Sink()
    ih.check_identity_hygiene('folder', FOLDER, JOB, sink=sink)
    assert {name: record['Finding'] for name, record in sink.by_check().items()} == {'Service Account Privileges': [{'Status': ih.SA_PRIVILEGES_ALL_CLEAR}], 'External Principals': [{'Status': ih.EXTERNAL_ALL_CLEAR}]}
    monkeypatch.setattr(ih.gcp, 'asset_client', lambda credentials=None: Inventory(error=RuntimeError('503 inventory unavailable')))
    sink = Sink()
    ih.check_identity_hygiene('folder', FOLDER, JOB, sink=sink)
    assert {name: record['Status'] for name, record in sink.by_check().items()} == {'Service Account Privileges': 'Error', 'External Principals': 'Error'}


def test_check_unused_service_accounts_per_project(gcp, monkeypatch):
    class Recommender:
        def __init__(self):
            self.parents = []

        def list_insights(self, request):
            self.parents.append(request['parent'])
            if 'denied' in request['parent']:
                raise RuntimeError('403 recommender.iamServiceAccountInsights.list denied')
            return iter([insight(f'gcs-accessor@{PROJECT}.iam.gserviceaccount.com', '2025-09-24T07:00:00Z')] if PROJECT in request['parent'] else [])
    client = Recommender()
    monkeypatch.setattr(ih.gcp, 'recommender_client', lambda credentials=None: client)
    sink = Sink()
    ih.check_unused_service_accounts(ORG, [{'projectId': PROJECT}, {'projectId': 'stark-vm-dev'}, {'projectId': 'denied-proj'}], JOB, sink=sink)
    record = sink.by_check()['Unused Service Accounts']
    assert record['Status'] == IR and [(r['Project'], r['Service Account']) for r in record['Finding']] == [(PROJECT, f'gcs-accessor@{PROJECT}.iam.gserviceaccount.com')]
    assert client.parents == [f'projects/{p}/locations/global/insightTypes/{ih.INSIGHT_TYPE}' for p in (PROJECT, 'stark-vm-dev', 'denied-proj')]
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [('denied-proj', 'Unused Service Accounts')]
    sink = Sink()
    ih.check_unused_service_accounts(ORG, [{'projectId': 'stark-vm-dev'}], JOB, sink=sink)
    assert sink.by_check()['Unused Service Accounts'] == {'Check': 'Unused Service Accounts', 'Finding': [{'Status': ih.UNUSED_SA_ALL_CLEAR}], 'Status': C}


def test_the_three_names_enter_the_changes_card_as_new_checks():
    assert ih.IDENTITY_CHECKS == ('Service Account Privileges', 'External Principals', 'Unused Service Accounts')
    assert not any(name in RESHAPED_CHECKS for name in ih.IDENTITY_CHECKS)
