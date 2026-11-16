"""
v18.7 — Folders, keys and privileged grants, the secrets: the rules of ``app.checks.secrets`` on fixtures of the shapes the inventory search returns
(secrets named by project number, versions with state and creation time), the reach per resource level, and the check end to end.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.checks import secrets as sm
from app.checks.identity_hygiene import policy_facts
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS

JOB = 'job-187'
AR, IR, INFO, C = 'Action Required', 'Investigation Recommended', 'Informational', 'Compliant'
ORG, FOLDER, OTHER_FOLDER, PROJECT, NUMBER, OTHER_NUMBER = '987654321', '1061000000000', '1061000000009', 'stark-sec-prod', '208800000000', '208800000001'
NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)


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
    return SimpleNamespace(role=role, members=list(members), condition=SimpleNamespace(title=condition, expression=f'expr({condition})') if condition else None)


def policy(kind, ident, *bindings, number=NUMBER, folder=FOLDER):
    return SimpleNamespace(resource=f'//cloudresourcemanager.googleapis.com/{kind}/{ident}', asset_type=f'cloudresourcemanager.googleapis.com/{kind[:-1].capitalize()}',
                           project=f'projects/{number}' if kind == 'projects' else '', folders=[f'folders/{folder}'] if kind != 'organizations' else [],
                           organization=f'organizations/{ORG}', policy=SimpleNamespace(bindings=list(bindings)))


def secret_result(short, number=NUMBER, folder=FOLDER, replication=None, rotation=None, days_ago=120):
    data = {'name': f'projects/{number}/secrets/{short}', 'replication': replication or {'automatic': {}}, 'createTime': (NOW - timedelta(days=days_ago)).strftime('%Y-%m-%dT%H:%M:%SZ'), 'etag': 'x'}
    if rotation:
        data['rotation'] = rotation
    return SimpleNamespace(name=f'//secretmanager.googleapis.com/projects/{number}/secrets/{short}', asset_type=sm.SECRET_TYPE, project=f'projects/{number}',
                           folders=[f'folders/{folder}'], create_time=NOW - timedelta(days=days_ago), versioned_resources=[{'version': 'v1', 'resource': data}])


def version_result(short, index, state='ENABLED', days_ago=100, number=NUMBER):
    created = NOW - timedelta(days=days_ago)
    data = {'name': f'projects/{number}/secrets/{short}/versions/{index}', 'state': state, 'createTime': created.strftime('%Y-%m-%dT%H:%M:%SZ')}
    return SimpleNamespace(name=f'//secretmanager.googleapis.com/projects/{number}/secrets/{short}/versions/{index}', asset_type=sm.VERSION_TYPE, project=f'projects/{number}',
                           folders=[f'folders/{FOLDER}'], create_time=created, versioned_resources=[{'version': 'v1', 'resource': data}])


SECRETS = [secret_result('db-password'), secret_result('api-key', number=OTHER_NUMBER, folder=OTHER_FOLDER), secret_result('regional', replication={'userManaged': {'replicas': [{'location': 'us-central1'}]}}),
           secret_result('rotated', rotation={'nextRotationTime': '2027-01-01T00:00:00Z', 'rotationPeriod': '7776000s'}), secret_result('empty')]
VERSIONS = [version_result('db-password', 1, days_ago=400), version_result('db-password', 2, days_ago=95), version_result('api-key', 1, days_ago=10, number=OTHER_NUMBER),
            version_result('regional', 1, days_ago=200), version_result('rotated', 1, days_ago=300), version_result('empty', 1, state='DESTROYED', days_ago=5),
            version_result('db-password', 3, state='DISABLED', days_ago=1)]


class Inventory:
    def __init__(self, secrets=(), versions=(), policies=(), projects=(), error=None, project_error=None):
        self.secrets, self.versions, self.policies, self.projects, self.error, self.project_error, self.requests = list(secrets), list(versions), list(policies), list(projects), error, project_error, []

    def search_all_resources(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        if 'cloudresourcemanager.googleapis.com/Project' in request['asset_types']:
            if self.project_error:
                raise self.project_error
            return iter([SimpleNamespace(name=f'//cloudresourcemanager.googleapis.com/projects/{pid}', project=f'projects/{number}', folders=[], state='ACTIVE', additional_attributes={'projectId': pid})
                         for pid, number in self.projects])
        return iter(self.secrets + self.versions)

    def search_all_iam_policies(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return iter(self.policies)


# --- the inventory ------------------------------------------------------------------------------------------------------------

def test_search_secrets_splits_secrets_and_versions():
    secrets, versions = sm.search_secrets(Inventory(SECRETS, VERSIONS), f'organizations/{ORG}')
    assert [s['short'] for s in secrets] == ['db-password', 'api-key', 'regional', 'rotated', 'empty'] and len(versions) == 7
    assert secrets[0] == {'name': f'projects/{NUMBER}/secrets/db-password', 'short': 'db-password', 'project': NUMBER, 'folders': [FOLDER], 'create_time': NOW - timedelta(days=120),
                          'data': SECRETS[0].versioned_resources[0]['resource']}
    assert versions[0]['name'] == f'projects/{NUMBER}/secrets/db-password/versions/1' and versions[0]['data']['state'] == 'ENABLED'


def test_secrets_in_reach_per_level():
    secrets, _ = sm.search_secrets(Inventory(SECRETS), f'organizations/{ORG}')
    assert sm.secrets_in_reach(secrets, policy_facts(policy('organizations', ORG))) == 5
    assert sm.secrets_in_reach(secrets, policy_facts(policy('folders', FOLDER))) == 4 and sm.secrets_in_reach(secrets, policy_facts(policy('folders', OTHER_FOLDER))) == 1
    assert sm.secrets_in_reach(secrets, policy_facts(policy('projects', PROJECT))) == 4 and sm.secrets_in_reach(secrets, policy_facts(policy('projects', 'other', number=OTHER_NUMBER))) == 1
    assert sm.secrets_in_reach(secrets, policy_facts(policy('projects', 'none', number='1'))) == 0


# --- Secret Access Scope ------------------------------------------------------------------------------------------------------

def test_secret_scope_rows_by_kind_and_reach():
    secrets, _ = sm.search_secrets(Inventory(SECRETS), f'organizations/{ORG}')
    policies = [policy_facts(p) for p in (
        policy('projects', PROJECT, binding('roles/secretmanager.secretAccessor', f'serviceAccount:app@{PROJECT}.iam.gserviceaccount.com', 'user:dev@example.test', 'allUsers',
                                            f'serviceAccount:service-{NUMBER}@gcp-sa-secretmanager.iam.gserviceaccount.com'),
               binding('roles/secretmanager.admin', 'group:platform@example.test', condition='temp'), binding('roles/secretmanager.viewer', 'user:auditor@example.test'),
               binding('roles/owner', 'user:lead@example.test')),
        policy('projects', 'none', binding('roles/secretmanager.secretAccessor', 'user:dev@example.test', f'serviceAccount:{NUMBER}-compute@developer.gserviceaccount.com'), number='1'),
        policy('organizations', ORG, binding('roles/secretmanager.secretVersionManager', 'domain:example.test', 'user:someone@gmail.com')))]
    rows = sm.secret_scope_rows(policies, secrets, ('example.test',))
    assert [(r['Resource'], r['Principal'].split(':')[-1].split('@')[0], r['Role'].split('.')[-1], r['Secrets in reach'], r['_status']) for r in rows] == [
        (f'projects/{PROJECT}', 'app', 'secretAccessor', 4, IR), (f'projects/{PROJECT}', 'dev', 'secretAccessor', 4, IR), (f'projects/{PROJECT}', 'allUsers', 'secretAccessor', 4, AR),
        (f'projects/{PROJECT}', 'platform', 'admin', 4, IR),
        ('projects/none', 'dev', 'secretAccessor', 0, INFO), ('projects/none', f'{NUMBER}-compute', 'secretAccessor', 0, IR),  # a person with nothing in reach; an account still a look
        (f'organizations/{ORG}', 'example.test', 'secretVersionManager', 5, AR), (f'organizations/{ORG}', 'someone', 'secretVersionManager', 5, AR)]
    assert rows[0]['Fix'] == (f'gcloud projects remove-iam-policy-binding {PROJECT} --member=serviceAccount:app@{PROJECT}.iam.gserviceaccount.com --role=roles/secretmanager.secretAccessor && '
                              f'gcloud secrets add-iam-policy-binding SECRET --project={PROJECT} --member=serviceAccount:app@{PROJECT}.iam.gserviceaccount.com --role=roles/secretmanager.secretAccessor  # per secret the principal needs')
    assert rows[3]['Condition'] == 'temp' and "--condition='expression=expr(temp),title=temp'" in rows[3]['Fix']
    assert rows[6]['Fix'].startswith(f'gcloud organizations remove-iam-policy-binding {ORG} ') and ' --project=' not in rows[6]['Fix']
    assert set(rows[0]) == {'Resource', 'Principal', 'Type', 'Role', 'Secrets in reach', 'Condition', 'Fix', '_status'}


# --- Secret Manager Posture ---------------------------------------------------------------------------------------------------

def test_secret_posture_rows():
    secrets, versions = sm.search_secrets(Inventory(SECRETS, VERSIONS), f'organizations/{ORG}')
    rows = sm.secret_posture_rows(secrets, versions, {NUMBER: PROJECT}, now=NOW)
    assert [(r['Project'], r['Secret'], r['Issue'], r['_status']) for r in rows] == [
        (PROJECT, 'db-password', 'Stale secret without a rotation schedule.', IR),  # the newest *enabled* version is 95 days old (the disabled one of yesterday does not count)
        (PROJECT, 'regional', 'Stale secret without a rotation schedule.', IR), (PROJECT, 'regional', 'Single-location replication.', INFO),
        (PROJECT, 'empty', 'No enabled version.', INFO)]  # api-key is 10 days old; rotated has a schedule
    assert rows[0]['Detail'].startswith('The newest enabled version is 95 days old') and rows[0]['Fix'].startswith(f'gcloud secrets versions add db-password --project={PROJECT} --data-file=')
    assert '--rotation-period=90d' in rows[0]['Fix'] and rows[2]['Detail'].startswith('Replicated in us-central1 only')
    assert rows[3]['Fix'] == f'gcloud secrets delete empty --project={PROJECT}'
    # Without the project names, the number stands in.
    assert sm.secret_posture_rows(secrets, versions, now=NOW)[0]['Project'] == NUMBER
    # At exactly 90 days nothing fires; a day later it does.
    secrets90, versions90 = sm.search_secrets(Inventory([secret_result('s')], [version_result('s', 1, days_ago=90)]), f'organizations/{ORG}')
    assert sm.secret_posture_rows(secrets90, versions90, now=NOW) == []
    assert [r['Issue'] for r in sm.secret_posture_rows(secrets90, versions90, now=NOW + timedelta(days=1))] == ['Stale secret without a rotation schedule.']


# --- the check -----------------------------------------------------------------------------------------------------------------

class Crm:
    def __init__(self, error=None):
        self.error, self.names = error, []

    def organizations(self):
        return self

    def get(self, name):
        self.names.append(name)
        return self

    def execute(self):
        if self.error:
            raise self.error
        return {'name': self.names[-1], 'displayName': 'example.test'}


def test_check_secret_posture_end_to_end(gcp, monkeypatch):
    policies = [policy('projects', PROJECT, binding('roles/secretmanager.secretAccessor', 'user:contractor@partner.example', 'user:dev@example.test'))]
    inventory = Inventory(SECRETS, VERSIONS, policies, projects=[(PROJECT, NUMBER), ('other', OTHER_NUMBER)])
    crm = Crm()
    monkeypatch.setattr(sm.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(sm.gcp, 'api_build', lambda *args, **kwargs: crm)
    sink = Sink()
    sm.check_secret_posture('organization', ORG, JOB, sink=sink, now=NOW)
    records = sink.by_check()
    assert {name: record['Status'] for name, record in records.items()} == {'Secret Access Scope': IR, 'Secret Manager Posture': IR}
    assert [(r['Principal'], r['Type'], r['Secrets in reach']) for r in records['Secret Access Scope']['Finding']] == [
        ('user:contractor@partner.example', 'user (outside the primary domain)', 4), ('user:dev@example.test', 'user', 4)]
    assert [(r['Project'], r['Secret']) for r in records['Secret Manager Posture']['Finding']] == [(PROJECT, 'db-password'), (PROJECT, 'regional'), (PROJECT, 'regional'), (PROJECT, 'empty')]
    assert inventory.requests[0]['asset_types'] == [sm.SECRET_TYPE, sm.VERSION_TYPE] and inventory.requests[0]['read_mask'] == '*'
    assert inventory.requests[1]['query'] == sm.SECRET_ROLES_QUERY and inventory.requests[1]['asset_types'] == sm.POLICY_TYPES
    assert crm.names == [f'organizations/{ORG}'] and sink.not_checked() == []
    assert all('_status' not in r for record in records.values() for r in record['Finding'])
    # The side reads failing: the domain rule is skipped (a line), the project names fall back to numbers (no line).
    monkeypatch.setattr(sm.gcp, 'api_build', lambda *args, **kwargs: Crm(error=RuntimeError('403 organizations.get')))
    inventory = Inventory(SECRETS, VERSIONS, policies, project_error=RuntimeError('403 projects'))
    monkeypatch.setattr(sm.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    sm.check_secret_posture('folder', FOLDER, JOB, sink=sink, now=NOW)
    records = sink.by_check()
    assert [r['Type'] for r in records['Secret Access Scope']['Finding']] == ['user', 'user'] and records['Secret Manager Posture']['Finding'][0]['Project'] == NUMBER
    assert [r['Skipped check'] for r in sink.not_checked()] == ["Secret Access Scope (external-domain rule: the organization's domain could not be read)"]
    # Nothing in scope: two all-clear rows, no side reads. A search that fails: two Errors.
    inventory = Inventory()
    monkeypatch.setattr(sm.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    sm.check_secret_posture('project', PROJECT, JOB, sink=sink)
    assert {name: record['Finding'] for name, record in sink.by_check().items()} == {'Secret Access Scope': [{'Status': sm.SECRET_SCOPE_ALL_CLEAR}], 'Secret Manager Posture': [{'Status': sm.SECRET_POSTURE_ALL_CLEAR}]}
    assert len(inventory.requests) == 2
    monkeypatch.setattr(sm.gcp, 'asset_client', lambda credentials=None: Inventory(error=RuntimeError('503 inventory unavailable')))
    sink = Sink()
    sm.check_secret_posture('project', PROJECT, JOB, sink=sink)
    assert {name: record['Status'] for name, record in sink.by_check().items()} == {'Secret Access Scope': 'Error', 'Secret Manager Posture': 'Error'}


def test_the_two_names_enter_the_changes_card_as_new_checks():
    assert sm.SECRET_CHECKS == ('Secret Access Scope', 'Secret Manager Posture') and not any(name in RESHAPED_CHECKS for name in sm.SECRET_CHECKS)
