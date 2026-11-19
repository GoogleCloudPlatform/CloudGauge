"""
v19.1 — Detection: the Admin Activity log reader of ``app.checks.detection`` (paging, the cap), the principal and address classes, the GKE
and service-account rules on fixture entries, and the two scope-level checks end to end with their failure paths.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

from app.checks import detection
from app.checks.detection import (ENTRY_CAP, GKE_ACTIVITY_CHECK, GKE_ALL_CLEAR, GKE_METHODS, SA_ALL_CLEAR, SA_METHODS, SA_SIGNALS_CHECK, WINDOW_DAYS, check_gke_activity, check_sa_signals,
                                  entry_facts, gke_action, gke_rows, gke_status, ip_class, is_google_principal, is_service_account, log_filter, parent_flag, read_entries, sa_action,
                                  sa_rows, sa_status)
from app.checks.gke_operations import ACTION_REQUIRED as AR, COMPLIANT, INFORMATIONAL as INFO, INVESTIGATION as IR
from app.checks.not_checked import NOT_CHECKED
from fakes import ORG_ID as ORG, _execute

JOB = 'job-191'
P, N = 'stark-gke-prod', '111111111111'
USER = 'admin@example.com'
DEPLOYER = f'deployer@{P}.iam.gserviceaccount.com'
DEFAULT_SA = f'{N}-compute@developer.gserviceaccount.com'
KSA = 'system:serviceaccount:default:app'
EXTERNAL, INTERNAL = '198.51.100.7', '10.128.0.9'
EXEC = 'io.k8s.core.v1.pods.exec.create'
BINDING = 'io.k8s.authorization.rbac.v1.clusterrolebindings.create'
DAEMONSET = 'io.k8s.apps.v1.daemonsets.create'
WEBHOOK = 'io.k8s.admissionregistration.k8s.io.v1.mutatingwebhookconfigurations.create'


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


class FakeLogging:
    """``logging v2`` ``entries().list(body=...)``, answered per parent from ``body['resourceNames']``: ``data`` maps a parent to its pages (a list of
    entry lists — the last page carries no token) or to an exception; a parent not in ``data`` has no entries. ``FakeLogging(pages...)`` answers
    the same pages to every parent."""

    def __init__(self, *pages, data=None):
        self.data = data
        self.default = list(pages) or [[]]
        self.bodies = []
        self.served = {}

    def entries(self):
        def list_entries(body):
            self.bodies.append(body)
            parent = body['resourceNames'][0]
            pages = self.data.get(parent, [[]]) if self.data is not None else self.default
            if isinstance(pages, Exception):
                return _execute(pages)
            index = self.served.get(parent, 0)
            self.served[parent] = index + 1
            page = pages[min(index, len(pages) - 1)]
            more = index < len(pages) - 1
            return _execute({'entries': page, **({'nextPageToken': f'page-{index + 1}'} if more else {})})
        return SimpleNamespace(list=list_entries)


PROJECTS = [{'projectId': P, 'projectNumber': N}, {'projectId': 'stark-quiet', 'projectNumber': '333333333333'}]


def entry(method, principal, ip=EXTERNAL, resource='core/v1/namespaces/default/pods/web-0/exec', project=P, cluster='prod', timestamp='2026-11-16T10:30:00Z', request=None, log_parent=None,
          labels=None, denied=False):
    resource_labels = {'project_id': project, 'cluster_name': cluster, 'location': 'asia-south1'} if project else {}
    resource_labels.update(labels or {})
    return {'timestamp': timestamp, 'logName': f'{log_parent or f"projects/{project}"}/logs/cloudaudit.googleapis.com%2Factivity', 'resource': {'type': 'k8s_cluster', 'labels': resource_labels},
            'protoPayload': {'methodName': method, 'resourceName': resource, 'authenticationInfo': {'principalEmail': principal}, 'requestMetadata': {'callerIp': ip},
                             **({'request': request} if request else {}), **({'status': {'code': 7, 'message': 'denied'}} if denied else {})}}


# --- the reader and the classes ---

def test_log_filter_names_the_window_the_activity_log_and_the_methods():
    text = log_filter('2026-11-10T00:00:00Z', GKE_METHODS)
    assert text.startswith('timestamp>="2026-11-10T00:00:00Z" AND logName:"cloudaudit.googleapis.com%2Factivity" AND (')
    assert 'pods.(exec|attach|portforward).(create|get)' in text and 'clusterrolebindings.(create|patch|update)' in text and 'webhookconfigurations' in text
    assert 'CreateServiceAccountKey$' in log_filter('x', SA_METHODS) and 'SetIamPolicy$' in log_filter('x', SA_METHODS)


def test_read_entries_pages_until_the_last_page_and_stops_at_the_cap():
    api = FakeLogging([1, 2], [3, 4], [5])
    assert read_entries(api, f'organizations/{ORG}', 'f', cap=10, page_size=2) == ([1, 2, 3, 4, 5], False)
    assert [b['pageSize'] for b in api.bodies] == [2, 2, 2] and api.bodies[0]['resourceNames'] == [f'organizations/{ORG}'] and api.bodies[0]['orderBy'] == 'timestamp desc'
    assert 'pageToken' not in api.bodies[0] and api.bodies[1]['pageToken'] == 'page-1' and api.bodies[2]['pageToken'] == 'page-2'
    api = FakeLogging([1, 2], [3, 4], [5])
    assert read_entries(api, f'projects/{P}', 'f', cap=3, page_size=2) == ([1, 2, 3], True)  # the second page is asked for the one entry left; a token remains
    assert [b['pageSize'] for b in api.bodies] == [2, 1]
    assert read_entries(FakeLogging([]), 'projects/p', 'f') == ([], False)


def test_is_google_principal_keeps_the_customers_accounts_and_workload_identities():
    assert is_google_principal('system:addon-manager') and is_google_principal('system:kube-controller-manager') and is_google_principal('system:node:gke-prod-pool-1')
    assert is_google_principal(f'service-{N}@gcp-sa-ktd-hpsa.iam.gserviceaccount.com') and is_google_principal('latchkey-automation@system.gserviceaccount.com')
    assert is_google_principal(f'service-{N}@container-engine-robot.iam.gserviceaccount.com') and is_google_principal(f'{N}@cloudservices.gserviceaccount.com')
    assert is_google_principal('system:serviceaccount:kube-system:kube-dns') and is_google_principal('system:serviceaccount:gke-managed-system:x') and is_google_principal('system:serviceaccount:gmp-system:collector')
    assert not is_google_principal(KSA) and not is_google_principal('system:anonymous')  # a workload's own account, and nobody's
    assert not is_google_principal(USER) and not is_google_principal(DEPLOYER) and not is_google_principal(DEFAULT_SA) and not is_google_principal('')
    assert is_service_account(DEPLOYER) and is_service_account(DEFAULT_SA) and is_service_account(KSA) and not is_service_account(USER) and not is_service_account('')


def test_ip_class_reads_the_apis_words_and_the_internal_networks():
    assert ip_class('') == 'unknown' and ip_class(None) == 'unknown' and ip_class('not-an-address') == 'unknown'
    assert ip_class('private') == 'internal' and ip_class('gce-internal-ip') == 'internal'
    for address in ('10.1.2.3', '172.20.0.1', '192.168.1.1', '100.64.0.1', '127.0.0.1', '169.254.169.254', 'fe80::1', '::1', 'fd00::1'):
        assert ip_class(address) == 'internal', address
    for address in (EXTERNAL, '34.93.10.20', '203.0.113.5', '2001:db8::1', '172.32.0.1'):
        assert ip_class(address) == 'external', address


def test_entry_facts_and_parent_flag_name_the_project_or_the_organization():
    fact = entry_facts(entry(EXEC, USER))
    assert (fact['method'], fact['principal'], fact['ip'], fact['ip_class'], fact['project'], fact['cluster'], fact['location']) == (EXEC, USER, EXTERNAL, 'external', P, 'prod', 'asia-south1')
    org_entry = entry('SetIamPolicy', DEPLOYER, project=None, log_parent=f'organizations/{ORG}', resource=f'organizations/{ORG}')
    assert entry_facts(org_entry)['project'] == f'organizations/{ORG}' and entry_facts({})['ip_class'] == 'unknown'
    assert not fact['denied'] and entry_facts(entry(EXEC, USER, denied=True))['denied'] and not entry_facts({'protoPayload': {'status': {'code': 0}}})['denied']
    assert parent_flag(P) == f'--project={P}' and parent_flag(f'organizations/{ORG}') == f'--organization={ORG}' and parent_flag('folders/1061') == '--folder=1061'
    assert entry_facts(entry(EXEC, USER, project=None, log_parent=f'projects/{P}'))['project'] == P  # the log name when the labels lack the project


# --- GKE Control Plane Activity ---

def test_gke_action_recognizes_the_judged_shapes_only():
    assert gke_action(entry_facts(entry(EXEC, USER))) == 'exec' and gke_action(entry_facts(entry('io.k8s.core.v1.pods.portforward.create', USER))) == 'exec'
    assert gke_action(entry_facts(entry('io.k8s.core.v1.pods.exec.get', USER))) == 'exec'  # the WebSocket exec (kubectl ≥ 1.31, client libraries) is a GET — the sandbox probe's shape
    assert gke_action(entry_facts(entry('io.k8s.core.v1.pods.get', USER))) is None and gke_action(entry_facts(entry('io.k8s.core.v1.pods.log.get', USER))) is None
    assert gke_action(entry_facts(entry(DAEMONSET, USER, resource='apps/v1/namespaces/kube-system/daemonsets/x'))) == 'kube-system workload'
    assert gke_action(entry_facts(entry('io.k8s.batch.v1.cronjobs.create', USER, resource='batch/v1/namespaces/kube-system/cronjobs/x'))) == 'kube-system workload'
    assert gke_action(entry_facts(entry(DAEMONSET, USER, resource='apps/v1/namespaces/default/daemonsets/x'))) is None
    assert gke_action(entry_facts(entry(BINDING, USER, resource='rbac.authorization.k8s.io/v1/clusterrolebindings/ops', request={'roleRef': {'name': 'cluster-admin'}}))) == 'cluster-admin binding'
    assert gke_action(entry_facts(entry(BINDING, USER, resource='rbac.authorization.k8s.io/v1/clusterrolebindings/ops', request={'roleRef': {'name': 'view'}}))) is None
    assert gke_action(entry_facts(entry(BINDING.replace('create', 'patch'), USER, resource='rbac.authorization.k8s.io/v1/clusterrolebindings/cluster-admin'))) == 'cluster-admin binding'
    assert gke_action(entry_facts(entry(WEBHOOK, USER, resource='admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/x'))) == 'webhook change'
    assert gke_action(entry_facts(entry('io.k8s.core.v1.pods.create', USER))) is None


def test_gke_status_ladder():
    assert gke_status('exec', False, True) == INFO and gke_status('exec', True, False) == IR and gke_status('exec', True, True) == AR
    assert gke_status('cluster-admin binding', False, False) == IR and gke_status('cluster-admin binding', True, False) == AR and gke_status('cluster-admin binding', False, True) == IR  # a user from a laptop
    assert gke_status('kube-system workload', False, True) == IR and gke_status('kube-system workload', True, False) == IR and gke_status('kube-system workload', True, True) == AR
    assert gke_status('webhook change', True, True) == AR and gke_status('webhook change', False, False) == IR


def test_gke_rows_group_by_cluster_action_principal_and_address_and_leave_google_out():
    entries = [entry(EXEC, USER, timestamp='2026-11-16T10:30:00Z'), entry(EXEC, USER, resource='core/v1/namespaces/default/pods/web-1/exec', timestamp='2026-11-15T09:00:00Z'),
               entry(EXEC, DEPLOYER, ip=EXTERNAL), entry(EXEC, KSA, ip=INTERNAL),
               entry(DAEMONSET, 'system:addon-manager', ip='private', resource='apps/v1/namespaces/kube-system/daemonsets/fluentbit'),
               entry(DAEMONSET, f'service-{N}@gcp-sa-ktd-hpsa.iam.gserviceaccount.com', ip='private', resource='apps/v1/namespaces/kube-system/daemonsets/ktd'),
               entry(BINDING, USER, ip=INTERNAL, resource='rbac.authorization.k8s.io/v1/clusterrolebindings/ops', request={'roleRef': {'name': 'cluster-admin'}}),
               entry(DAEMONSET, USER, resource='apps/v1/namespaces/default/daemonsets/agent')]
    rows = gke_rows(entries)
    assert [(r['Action'], r['Principal'], r['From'], r['Count'], r['_status']) for r in rows] == [
        ('exec', USER, 'external', 2, INFO), ('cluster-admin binding', USER, 'internal', 1, IR), ('exec', DEPLOYER, 'external', 1, AR),
        ('exec', KSA, 'internal', 1, IR)]
    first = rows[0]
    assert first['Project'] == P and first['Cluster'] == 'prod' and first['Latest'] == '2026-11-16 10:30' and first['Issue'] == 'Shell into a pod.'
    assert first['Detail'] == f'2 exec events by the user {USER} from external address ({EXTERNAL}) in the last {WINDOW_DAYS} days: namespaces/default/pods/web-0/exec, namespaces/default/pods/web-1/exec.'
    assert first['Fix'].startswith(f'gcloud logging read \'resource.type="k8s_cluster" AND resource.labels.cluster_name="prod" AND protoPayload.authenticationInfo.principalEmail="{USER}"\' --project={P} --freshness={WINDOW_DAYS}d')
    assert gke_rows([]) == [] and gke_rows(entries[4:6]) == []
    assert gke_rows(entries[:1], capped=True)[0]['Detail'].endswith(' The read stopped at the cap; older events are not counted.')
    # Refused calls are counted and said: an attempt is a signal.
    denied = gke_rows([entry(EXEC, DEPLOYER, denied=True), entry(EXEC, DEPLOYER), entry(EXEC, DEPLOYER, denied=True)], capped=True)[0]
    assert denied['Count'] == 3 and denied['_status'] == AR and denied['Detail'].endswith('pods/web-0/exec. 2 of them were denied. The read stopped at the cap; older events are not counted.')
    assert gke_rows([entry(EXEC, DEPLOYER, denied=True)])[0]['Detail'].endswith(' All of them were denied.')


def test_check_gke_activity_reads_every_project(gcp, monkeypatch):
    monkeypatch.setattr(detection, 'utcnow', lambda: datetime(2026, 11, 17, 8, 0, tzinfo=timezone.utc))
    api = FakeLogging(data={f'projects/{P}': [[entry(EXEC, DEPLOYER, ip=EXTERNAL)], [entry(EXEC, USER, ip=INTERNAL)]],
                            'projects/stark-quiet': [[entry(DAEMONSET, 'system:addon-manager', ip='private', resource='apps/v1/namespaces/kube-system/daemonsets/x', project='stark-quiet')]]})
    gcp.discovery.apis['logging'] = api
    s = Sink()
    check_gke_activity(ORG, PROJECTS, JOB, sink=s)
    record = s.by_check()[GKE_ACTIVITY_CHECK]
    assert record['Status'] == AR and [(r['Project'], r['Principal'], r['From']) for r in record['Finding']] == [(P, USER, 'internal'), (P, DEPLOYER, 'external')]  # equal counts: by key
    assert all('_status' not in r for r in record['Finding']) and s.not_checked() == []
    # One read per project — the organization itself is never a parent: entries.list on it returns the organization's own entries, not its projects'.
    assert sorted(b['resourceNames'][0] for b in api.bodies) == [f'projects/{P}', f'projects/{P}', 'projects/stark-quiet'] and api.bodies[0]['pageSize'] == detection.PAGE_SIZE
    assert all(b['filter'].startswith('resource.type="k8s_cluster" AND timestamp>="2026-11-10T08:00:00Z" AND logName:"cloudaudit.googleapis.com%2Factivity" AND (') for b in api.bodies)
    # Google's own churn alone is the all-clear, with the Data Access caveat.
    gcp.discovery.apis['logging'] = FakeLogging([entry(DAEMONSET, 'system:addon-manager', ip='private', resource='apps/v1/namespaces/kube-system/daemonsets/x')])
    s = Sink()
    check_gke_activity('1061', PROJECTS[:1], JOB, sink=s)
    record = s.by_check()[GKE_ACTIVITY_CHECK]
    assert record['Status'] == COMPLIANT and record['Finding'] == [{'Status': GKE_ALL_CLEAR}] and 'secrets reads are Data Access logs' in GKE_ALL_CLEAR
    # A project whose read fails goes under Projects not checked; the others stand.
    gcp.discovery.apis['logging'] = FakeLogging(data={f'projects/{P}': PermissionError('logging.logEntries.list denied'), 'projects/stark-quiet': [[entry(EXEC, USER, project='stark-quiet')]]})
    s = Sink()
    check_gke_activity(ORG, PROJECTS, JOB, sink=s)
    record = s.by_check()[GKE_ACTIVITY_CHECK]
    assert record['Status'] == INFO and [r['Project'] for r in record['Finding']] == ['stark-quiet']
    assert [(row['Project'], GKE_ACTIVITY_CHECK in str(row)) for row in s.not_checked()] == [(P, True)] and 'denied' in str(s.not_checked()[0])


def test_check_gke_activity_says_when_the_read_stopped_at_the_cap(gcp, monkeypatch):
    monkeypatch.setattr(detection, 'ENTRY_CAP', 3)
    monkeypatch.setattr(detection, 'PAGE_SIZE', 2)
    gcp.discovery.apis['logging'] = api = FakeLogging([entry(EXEC, USER), entry(EXEC, USER)], [entry(EXEC, USER), entry(EXEC, USER)], [entry(EXEC, USER)])
    s = Sink()
    check_gke_activity(ORG, PROJECTS[:1], JOB, sink=s)
    row = s.by_check()[GKE_ACTIVITY_CHECK]['Finding'][0]
    assert row['Count'] == 3 and row['Detail'].endswith('older events are not counted.') and [b['pageSize'] for b in api.bodies] == [2, 1]
    assert ENTRY_CAP == 2000  # the module constant is untouched


# --- Service Account Activity Signals ---

def test_sa_action_and_status():
    assert sa_action('google.iam.admin.v1.CreateServiceAccountKey') == 'key created' and sa_action('SetIamPolicy') == 'IAM policy changed'
    assert sa_action('v1.compute.projects.setCommonInstanceMetadata') == 'metadata written' and sa_action('v1.compute.instances.setMetadata') == 'metadata written'
    assert sa_action('google.iam.admin.v1.CreateServiceAccount') == 'service account created' and sa_action('google.iam.admin.v1.DeleteServiceAccountKey') is None
    assert sa_status('key created', True) == AR and sa_status('key created', False) == IR
    assert sa_status('IAM policy changed', True) == AR and sa_status('metadata written', False) == IR
    assert sa_status('service account created', True) == INFO


def sa_entry(method, principal, ip=EXTERNAL, resource='', project=P, timestamp='2026-11-16T10:30:00Z', log_parent=None, labels=None, denied=False):
    return entry(method, principal, ip=ip, resource=resource, project=project, cluster='', timestamp=timestamp, log_parent=log_parent, labels=labels, denied=denied)


def test_sa_rows_judge_the_customers_service_accounts_only():
    entries = [sa_entry('google.iam.admin.v1.CreateServiceAccountKey', DEPLOYER, resource='projects/-/serviceAccounts/1029384756', labels={'email_id': DEPLOYER}),
               sa_entry('SetIamPolicy', DEPLOYER, ip=INTERNAL, resource=f'projects/{P}', timestamp='2026-11-14T00:00:00Z'),
               sa_entry('SetIamPolicy', DEPLOYER, ip=INTERNAL, resource=f'projects/{P}', timestamp='2026-11-15T12:00:00Z'),
               sa_entry('google.iam.admin.v1.CreateServiceAccount', DEPLOYER, resource=f'projects/{P}/serviceAccounts/new-app@{P}.iam.gserviceaccount.com'),
               sa_entry('SetIamPolicy', USER, resource=f'projects/{P}'),  # a user: not this record's
               sa_entry('SetIamPolicy', 'latchkey-automation@system.gserviceaccount.com', ip='private', project=None, log_parent=f'organizations/{ORG}', resource=f'organizations/{ORG}'),
               sa_entry('SetIamPolicy', DEFAULT_SA, ip=EXTERNAL, project=None, log_parent=f'organizations/{ORG}', resource=f'organizations/{ORG}'),
               sa_entry('google.iam.admin.v1.DeleteServiceAccountKey', DEPLOYER)]
    rows = sa_rows(entries)
    assert [(r['Project'], r['Principal'], r['Action'], r['From'], r['Count'], r['_status']) for r in rows] == [
        (P, DEPLOYER, 'IAM policy changed', 'internal', 2, IR), (f'organizations/{ORG}', DEFAULT_SA, 'IAM policy changed', 'external', 1, AR),
        (P, DEPLOYER, 'key created', 'external', 1, AR), (P, DEPLOYER, 'service account created', 'external', 1, INFO)]
    assert rows[0]['Latest'] == '2026-11-15 12:00' and rows[0]['Target'] == f'projects/{P}' and rows[0]['Detail'] == f'2 times in the last {WINDOW_DAYS} days from internal address ({INTERNAL}).'
    assert rows[0]['Fix'].endswith(f'(gcloud projects remove-iam-policy-binding {P} --member=serviceAccount:{DEPLOYER} --role=<role>)') and f'--project={P}' in rows[0]['Fix']
    assert f'--organization={ORG}' in rows[1]['Fix'] and 'remove-iam-policy-binding' not in rows[1]['Fix']  # no project to name
    assert rows[2]['Target'] == DEPLOYER and rows[2]['Issue'] == 'Key created by a service account.' and rows[3]['Target'] == f'new-app@{P}.iam.gserviceaccount.com'
    assert sa_rows([]) == [] and sa_rows(entries[4:6]) == []
    # A key creation refused by an organization policy (iam.disableServiceAccountKeyCreation) is still the attempt it was.
    refused = sa_rows([sa_entry('google.iam.admin.v1.CreateServiceAccountKey', DEPLOYER, denied=True), sa_entry('google.iam.admin.v1.CreateServiceAccountKey', DEPLOYER)])[0]
    assert refused['Count'] == 2 and refused['_status'] == AR and refused['Detail'] == f'2 times in the last {WINDOW_DAYS} days from external address ({EXTERNAL}). 1 of them was denied.'


def test_check_sa_signals_reads_the_scope_and_every_project(gcp, monkeypatch):
    monkeypatch.setattr(detection, 'utcnow', lambda: datetime(2026, 11, 17, 8, 0, tzinfo=timezone.utc))
    org_churn = sa_entry('SetIamPolicy', 'latchkey-automation@system.gserviceaccount.com', ip='private', project=None, log_parent=f'organizations/{ORG}', resource=f'organizations/{ORG}')
    org_sa = sa_entry('SetIamPolicy', DEFAULT_SA, ip=EXTERNAL, project=None, log_parent=f'organizations/{ORG}', resource=f'organizations/{ORG}')
    data = {f'organizations/{ORG}': [[org_churn, org_sa]], f'projects/{P}': [[sa_entry('SetIamPolicy', DEPLOYER, ip=INTERNAL, resource=f'projects/{P}')]]}
    gcp.discovery.apis['logging'] = api = FakeLogging(data=data)
    s = Sink()
    check_sa_signals('organization', ORG, PROJECTS, JOB, sink=s)
    record = s.by_check()[SA_SIGNALS_CHECK]
    assert record['Status'] == AR and [(r['Project'], r['Principal'], r['From']) for r in record['Finding']] == [(f'organizations/{ORG}', DEFAULT_SA, 'external'), (P, DEPLOYER, 'internal')]
    assert '_status' not in record['Finding'][0] and s.not_checked() == []
    assert sorted(b['resourceNames'][0] for b in api.bodies) == [f'organizations/{ORG}', f'projects/{P}', 'projects/stark-quiet']  # the organization's own entries, then every project's
    assert api.bodies[0]['filter'].startswith('protoPayload.authenticationInfo.principalEmail=~"gserviceaccount.com$" AND timestamp>="2026-11-10T08:00:00Z" AND ')
    # The split halves: the scope shard reads the parent alone, the project shards their projects alone; a project scan has no scope half.
    gcp.discovery.apis['logging'] = api = FakeLogging(data=data)
    check_sa_signals('organization', ORG, PROJECTS, JOB, sink=Sink(), project_level=False)
    assert [b['resourceNames'][0] for b in api.bodies] == [f'organizations/{ORG}']
    gcp.discovery.apis['logging'] = api = FakeLogging(data=data)
    check_sa_signals('folder', '1061', PROJECTS, JOB, sink=Sink(), scope_level=False)
    assert sorted(b['resourceNames'][0] for b in api.bodies) == [f'projects/{P}', 'projects/stark-quiet']
    gcp.discovery.apis['logging'] = api = FakeLogging(data=data)
    s = Sink()
    check_sa_signals('project', P, PROJECTS[:1], JOB, sink=s)
    assert [b['resourceNames'][0] for b in api.bodies] == [f'projects/{P}'] and s.by_check()[SA_SIGNALS_CHECK]['Status'] == IR
    # Google's own churn alone is the all-clear, with the token-minting caveat; a failed parent goes under Projects not checked.
    gcp.discovery.apis['logging'] = FakeLogging(data={f'organizations/{ORG}': [[org_churn]], f'projects/{P}': RuntimeError('logging down')})
    s = Sink()
    check_sa_signals('organization', ORG, PROJECTS, JOB, sink=s)
    record = s.by_check()[SA_SIGNALS_CHECK]
    assert record['Status'] == COMPLIANT and record['Finding'] == [{'Status': SA_ALL_CLEAR}] and 'token minting' in SA_ALL_CLEAR
    assert [row['Project'] for row in s.not_checked()] == [P] and 'logging down' in str(s.not_checked()[0])
