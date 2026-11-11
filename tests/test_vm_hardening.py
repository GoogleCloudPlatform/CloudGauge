"""
v18.5 — VM hardening & identities, the Compute half: the rules of ``app.checks.vm_hardening`` on fixtures of the shapes Asset
Inventory returns for instances and compute projects (the production VMs as read in the survey, names changed), and the check
end to end.
"""
from types import SimpleNamespace

from google.cloud import asset_v1

from app.checks import vm_hardening as vh
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS

JOB = 'job-185'
AR, IR, C = 'Action Required', 'Investigation Recommended', 'Compliant'
PROJECT, NUMBER = 'stark-vm-prod', '208800000000'
DEFAULT = f'{NUMBER}-compute@developer.gserviceaccount.com'
SCOPE = 'https://www.googleapis.com/auth/'
DEFAULT_SCOPES = [SCOPE + s for s in ('devstorage.read_only', 'logging.write', 'monitoring.write', 'service.management.readonly', 'servicecontrol', 'trace.append')]
SHIELDED = {'enableSecureBoot': True, 'enableVtpm': True, 'enableIntegrityMonitoring': True}


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


def instance(name, account=DEFAULT, scopes=None, status='RUNNING', zone='asia-south1-b', metadata=None, labels=None, ip_forward=False, shielded=SHIELDED, project=PROJECT):
    data = {'name': name, 'status': status, 'zone': f'https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}', 'canIpForward': ip_forward,
            'labels': labels or {}, 'metadata': {'items': [{'key': k, 'value': v} for k, v in (metadata or {}).items()]},
            'serviceAccounts': [{'email': account, 'scopes': DEFAULT_SCOPES if scopes is None else scopes}] if account else []}
    if shielded is not None:
        data['shieldedInstanceConfig'] = dict(shielded)
    return SimpleNamespace(name=f'//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{name}', resource=SimpleNamespace(data=data))


def compute_project(metadata, project=PROJECT):
    return SimpleNamespace(name=f'//compute.googleapis.com/projects/{project}', resource=SimpleNamespace(data={
        'name': project, 'defaultServiceAccount': DEFAULT, 'commonInstanceMetadata': {'items': [{'key': k, 'value': v} for k, v in metadata.items()]}}))


def facts(*assets):
    return [vh.instance_facts(fact) for fact in vh.by_kind(list(assets)).get('instances', [])]


# --- the facts -----------------------------------------------------------------------------------------------------------

def test_instance_facts_read_accounts_scopes_metadata_shielded_and_fleets():
    vm = facts(instance('web-1', metadata={'enable-oslogin': 'true', 'created-by': f'projects/{PROJECT}/zones/asia-south1-b/instanceGroupManagers/web-mig'}))[0]
    assert (vm['project_id'], vm['name'], vm['zone'], vm['status'], vm['managed'], vm['ip_forwarding']) == (PROJECT, 'web-1', 'asia-south1-b', 'RUNNING', False, False)
    assert vm['accounts'] == [(DEFAULT, ['devstorage.read_only', 'logging.write', 'monitoring.write', 'service.management.readonly', 'servicecontrol', 'trace.append'])]
    assert vm['metadata'] == {'enable-oslogin': 'true', 'created-by': f'projects/{PROJECT}/zones/asia-south1-b/instanceGroupManagers/web-mig'} and vm['created_by'].endswith('web-mig')
    assert vm['shielded'] == SHIELDED
    assert facts(instance('legacy', shielded=None))[0]['shielded'] is None
    assert facts(instance('gke-prod-pool-9babab6f-u0x5', labels={'goog-gke-node': ''}))[0]['managed'] is True  # the label
    assert facts(instance('gke-prod-pool-9babab6f-u0x5'))[0]['managed'] is True  # the name, when the label is missing
    assert facts(instance('dp-w-0', labels={'goog-dataproc-cluster-name': 'etl'}))[0]['managed'] is True
    assert facts(instance('nb-1', labels={'goog-caip-notebook': ''}))[0]['managed'] and not facts(instance('plain', labels={'env': 'prod'}))[0]['managed']
    assert vh.is_default_account(DEFAULT) and vh.is_default_account(f'{PROJECT}@appspot.gserviceaccount.com') and not vh.is_default_account(f'app@{PROJECT}.iam.gserviceaccount.com')
    assert vh.default_accounts_in_use(facts(instance('a'), instance('b', account=f'app@{PROJECT}.iam.gserviceaccount.com'), instance('c'), instance('d', account=''))) == [DEFAULT]


# --- VM Service Accounts -------------------------------------------------------------------------------------------------

def test_vm_service_account_rows_by_scopes_roles_and_fleet():
    vms = facts(instance('web-1'), instance('batch-2', scopes=[SCOPE + 'cloud-platform']), instance('db-3', status='TERMINATED'),
                instance('app-4', account=f'app@{PROJECT}.iam.gserviceaccount.com', scopes=[SCOPE + 'cloud-platform']), instance('gke-pool-1', labels={'goog-gke-node': ''}),
                instance('mig-5', metadata={'created-by': f'projects/{PROJECT}/zones/asia-south1-b/instanceGroupManagers/web-mig'}))
    # The default account holds compute.admin and container.admin (what the survey read): every VM on it is Action Required.
    rows = vh.vm_service_account_rows(vms, {DEFAULT: {'roles/compute.admin', 'roles/container.admin', 'roles/logging.logWriter'}})
    assert [(r['Instance'], r['Status'], r['Issue'], r['_status']) for r in rows] == [
        ('web-1', 'RUNNING', 'Default service account.', AR), ('batch-2', 'RUNNING', 'Default service account with full API access.', AR),
        ('db-3', 'TERMINATED', 'Default service account.', AR), ('mig-5', 'RUNNING', 'Default service account.', AR)]
    assert rows[0]['Detail'] == ('The account holds roles/container.admin on the project; the scopes limit a stolen token to devstorage.read_only, logging.write, '
                                 'monitoring.write, service.management.readonly, servicecontrol, trace.append, not whose roles it carries (CIS 4.1).')  # v17.1's order: container.admin first
    assert rows[1]['Detail'] == 'Every role of the account is reachable from the VM (scope cloud-platform); it holds roles/container.admin, roles/compute.admin on the project (CIS 4.2).'
    assert rows[0]['Fix'] == (f'gcloud compute instances stop web-1 --zone=asia-south1-b --project={PROJECT} && gcloud compute instances set-service-account web-1 --zone=asia-south1-b '
                              f'--project={PROJECT} --service-account=<dedicated account> --scopes=cloud-platform  # create the account with the roles the workload needs first')
    assert rows[3]['Fix'].startswith('the instance was created by web-mig: give its instance template a dedicated service account')
    assert rows[0]['Service Account'] == DEFAULT and rows[1]['Scopes'] == 'cloud-platform'
    assert all(set(r) == {'Project', 'Instance', 'Zone', 'Status', 'Service Account', 'Scopes', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    # No privileged role: Investigation with limited scopes, Action Required with cloud-platform. Roles not read: said so.
    rows = vh.vm_service_account_rows(vms[:2], {DEFAULT: {'roles/logging.logWriter'}})
    assert [(r['Instance'], r['_status']) for r in rows] == [('web-1', IR), ('batch-2', AR)]
    assert rows[0]['Detail'].startswith('The account holds no privileged role; scopes devstorage.read_only') and 'no privileged role' in rows[1]['Detail']
    rows = vh.vm_service_account_rows(vms[:1], {DEFAULT: None})
    assert rows[0]['_status'] == IR and rows[0]['Detail'].startswith("The account's roles could not be read; the scopes are devstorage.read_only")
    assert vh.vm_service_account_rows(facts(instance('app', account=f'app@{PROJECT}.iam.gserviceaccount.com', scopes=[SCOPE + 'cloud-platform'])), {}) == []


# --- VM Hardening --------------------------------------------------------------------------------------------------------

def test_vm_hardening_project_rows_for_os_login_project_keys_and_serial():
    keys = 'ops:ssh-ed25519 AAAA ops@example.test\nci:ssh-rsa BBBB ci@example.test'
    vms = facts(instance('web-1'), instance('web-2', metadata={'block-project-ssh-keys': 'TRUE'}), instance('web-3', metadata={'enable-oslogin': 'TRUE'}),
                instance('gke-pool-1', labels={'goog-gke-node': ''}))
    rows = vh.vm_hardening_rows(vms, {PROJECT: {'enable-oslogin': 'FALSE', 'ssh-keys': keys, 'serial-port-enable': 'true'}})
    assert [(r['Instance'], r['Issue'], r['Detail']) for r in rows] == [
        (vh.PROJECT_ROW, 'OS Login off for the project.', '3 instance(s); 1 enable it themselves, the rest authenticate with metadata SSH keys (CIS 4.4).'),
        (vh.PROJECT_ROW, 'Project-wide SSH keys in use.', '2 key(s) in the project metadata reach 1 instance(s) without block-project-ssh-keys (CIS 4.3).'),
        (vh.PROJECT_ROW, 'Serial console enabled for the project.', 'Every instance answers on the interactive serial console (CIS 4.5).')]
    assert rows[0]['Fix'] == f'gcloud compute project-info add-metadata --project={PROJECT} --metadata=enable-oslogin=TRUE' and rows[0]['Zone'] == '' and rows[0]['Status'] == ''
    assert rows[2]['Fix'] == f'gcloud compute project-info remove-metadata --project={PROJECT} --keys=serial-port-enable'
    assert all(r['_status'] == IR and r['Project'] == PROJECT for r in rows)
    # OS Login on for the project (the production projects): no project row; only an instance that opts out is a row.
    rows = vh.vm_hardening_rows(facts(instance('web-1'), instance('legacy-2', metadata={'enable-oslogin': 'false'})), {PROJECT: {'enable-oslogin': 'true', 'ssh-keys': keys}})
    assert [(r['Instance'], r['Issue']) for r in rows] == [('legacy-2', 'OS Login off on the instance.')]
    assert rows[0]['Fix'] == f'gcloud compute instances remove-metadata legacy-2 --zone=asia-south1-b --project={PROJECT} --keys=enable-oslogin'
    # A project without common metadata in the listing counts as OS Login off; one without judged instances is no row.
    assert [r['Issue'] for r in vh.vm_hardening_rows(facts(instance('web-1')), {})] == ['OS Login off for the project.']
    assert vh.vm_hardening_rows(facts(instance('gke-pool-1', labels={'goog-gke-node': ''})), {PROJECT: {}}) == []


def test_vm_hardening_instance_rows_for_serial_ip_forwarding_and_shielded():
    oslogin = {PROJECT: {'enable-oslogin': 'TRUE'}}
    vms = facts(instance('serial-1', metadata={'serial-port-enable': 'TRUE'}), instance('router-2', ip_forward=True), instance('legacy-3', shielded=None),
                instance('novtpm-4', shielded={'enableSecureBoot': False, 'enableVtpm': False, 'enableIntegrityMonitoring': True}),
                instance('nosb-5', shielded={'enableSecureBoot': False, 'enableVtpm': True, 'enableIntegrityMonitoring': True}),
                instance('good-6'), instance('gke-pool-7', labels={'goog-gke-node': ''}, ip_forward=True, shielded={'enableSecureBoot': False, 'enableVtpm': True, 'enableIntegrityMonitoring': True}))
    rows = vh.vm_hardening_rows(vms, oslogin)
    assert [(r['Instance'], r['Issue']) for r in rows] == [('serial-1', 'Serial console enabled.'), ('router-2', 'IP forwarding on.'), ('legacy-3', 'Shielded VM off.'),
                                                            ('novtpm-4', 'Shielded VM off.'), ('nosb-5', 'Secure Boot off.')]
    assert rows[0]['Fix'] == f'gcloud compute instances remove-metadata serial-1 --zone=asia-south1-b --project={PROJECT} --keys=serial-port-enable'
    assert rows[1]['Fix'] == 'recreate the instance without --can-ip-forward, or document the appliance' and 'cannot be changed' in rows[1]['Detail']
    assert rows[2]['Detail'].startswith('The image is not Shielded-capable') and rows[2]['Fix'].startswith('migrate to a Shielded VM image')
    assert rows[3]['Detail'] == 'vTPM off (CIS 4.8).' and rows[3]['Fix'] == f'gcloud compute instances update novtpm-4 --zone=asia-south1-b --project={PROJECT} --shielded-vtpm --shielded-integrity-monitoring  # the instance must be stopped'
    assert rows[4]['Fix'] == f'gcloud compute instances update nosb-5 --zone=asia-south1-b --project={PROJECT} --shielded-secure-boot  # the instance must be stopped'
    assert all(set(r) == {'Project', 'Instance', 'Zone', 'Status', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)


# --- the check end to end ----------------------------------------------------------------------------------------------------

class Inventory:
    def __init__(self, assets=(), bindings=None, error=None, search_error=None):
        self.assets, self.bindings, self.error, self.search_error, self.requests, self.queries = list(assets), bindings or {}, error, search_error, [], []

    def list_assets(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return list(self.assets)

    def search_all_iam_policies(self, request):
        self.queries.append(request['query'])
        if self.search_error:
            raise self.search_error
        email = request['query'].split('"')[1]
        bindings = [SimpleNamespace(role=role, members=[f'serviceAccount:{email}']) for role in self.bindings.get(email, [])]
        return iter([SimpleNamespace(asset_type='cloudresourcemanager.googleapis.com/Project', resource=f'//cloudresourcemanager.googleapis.com/projects/{PROJECT}',
                                     policy=SimpleNamespace(bindings=bindings))] if bindings else [])


class Compute:
    """``projects().get(project=...)``: the common instance metadata per project (the inventory's copy omits ssh-keys);
    ``instances().aggregatedList(project=...)``: the project's instances (``None``: the inventory's copy stands)."""
    def __init__(self, metadata, error=None, instances=None, instances_error=None):
        self.metadata, self.error, self.fresh, self.instances_error, self.asked, self.listed = metadata, error, instances, instances_error, [], []
        self._mode = None

    def projects(self):
        self._mode = 'project'
        return self

    def instances(self):
        self._mode = 'instances'
        return self

    def get(self, project):
        self.asked.append(project)
        return self

    def aggregatedList(self, project):
        self.listed.append(project)
        return self

    def aggregatedList_next(self, previous_request, previous_response):
        return None

    def execute(self):
        if self._mode == 'instances':
            if self.instances_error:
                raise self.instances_error
            assets = self.fresh if self.fresh is not None else INVENTORY_INSTANCES
            return {'items': {'zones/asia-south1-b': {'instances': [dict(a.resource.data) for a in assets if a.name.split('/')[4] == self.listed[-1]]}}}
        if self.error:
            raise self.error
        return {'name': self.asked[-1], 'commonInstanceMetadata': {'items': [{'key': k, 'value': v} for k, v in self.metadata.get(self.asked[-1], {}).items()]}}


INVENTORY_INSTANCES = [instance('web-1'), instance('win-2', status='TERMINATED'), instance('app-3', account=f'app@{PROJECT}.iam.gserviceaccount.com', shielded={'enableSecureBoot': False, 'enableVtpm': True, 'enableIntegrityMonitoring': True}),
                       instance('gke-pool-4', labels={'goog-gke-node': ''}, ip_forward=True)]


def test_check_vm_posture_end_to_end(gcp, monkeypatch):
    assets = INVENTORY_INSTANCES + [compute_project({'enable-oslogin': 'true'})]
    inventory = Inventory(assets, {DEFAULT: ['roles/editor', 'roles/compute.admin']})
    compute = Compute({PROJECT: {'enable-oslogin': 'true'}})  # the API agrees with the inventory
    monkeypatch.setattr(vh.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(vh.gcp, 'api_build', lambda *args, **kwargs: compute)
    sink = Sink()
    vh.check_vm_posture('organization', '987654321', JOB, sink=sink)
    records = sink.by_check()
    assert {name: record['Status'] for name, record in records.items()} == {'VM Service Accounts': AR, 'VM Hardening': IR}
    assert [(r['Instance'], r['Status']) for r in records['VM Service Accounts']['Finding']] == [('web-1', 'RUNNING'), ('win-2', 'TERMINATED')]
    assert records['VM Service Accounts']['Finding'][0]['Detail'].startswith('The account holds roles/editor on the project')
    assert [(r['Instance'], r['Issue']) for r in records['VM Hardening']['Finding']] == [('app-3', 'Secure Boot off.')]
    assert inventory.requests == [{'parent': 'organizations/987654321', 'asset_types': vh.VM_TYPES, 'content_type': asset_v1.ContentType.RESOURCE}]
    assert inventory.queries == [f'policy:"{DEFAULT}"'] and compute.asked == [PROJECT] and compute.listed == [PROJECT] and sink.not_checked() == []
    assert all('_status' not in r for record in records.values() for r in record['Finding'])
    # The API is the copy of record: web-1 moved to a dedicated account and win-2 was deleted since the inventory's snapshot; a new VM appeared;
    # the project turned OS Login off and holds a key the inventory never shows.
    fresh = [instance('web-1', account=f'web@{PROJECT}.iam.gserviceaccount.com'), instance('app-3', account=f'app@{PROJECT}.iam.gserviceaccount.com'),
             instance('new-5', metadata={'serial-port-enable': 'TRUE'}), instance('gke-pool-4', labels={'goog-gke-node': ''}, ip_forward=True)]
    compute = Compute({PROJECT: {'enable-oslogin': 'FALSE', 'ssh-keys': 'ops:ssh-ed25519 AAAA ops@example.test'}}, instances=fresh)
    monkeypatch.setattr(vh.gcp, 'api_build', lambda *args, **kwargs: compute)
    sink = Sink()
    vh.check_vm_posture('organization', '987654321', JOB, sink=sink)
    records = sink.by_check()
    assert [(r['Instance'], r['Issue']) for r in records['VM Service Accounts']['Finding']] == [('new-5', 'Default service account.')]
    assert [(r['Instance'], r['Issue']) for r in records['VM Hardening']['Finding']] == [
        (vh.PROJECT_ROW, 'OS Login off for the project.'), (vh.PROJECT_ROW, 'Project-wide SSH keys in use.'), ('new-5', 'Serial console enabled.')]
    assert '1 key(s) in the project metadata reach 3 instance(s)' in records['VM Hardening']['Finding'][1]['Detail']
    # The API reads failing: the inventory's copy serves, and Projects not checked says what that means.
    monkeypatch.setattr(vh.gcp, 'api_build', lambda *args, **kwargs: Compute({}, error=RuntimeError('403 compute.projects.get denied'), instances_error=RuntimeError('403 compute.instances.list denied')))
    sink = Sink()
    vh.check_vm_posture('organization', '987654321', JOB, sink=sink)
    assert [(r['Instance'], r['Issue']) for r in sink.by_check()['VM Hardening']['Finding']] == [('app-3', 'Secure Boot off.')]  # OS Login on, per the inventory
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [
        (PROJECT, "VM Hardening (project metadata: the Compute API read failed; the inventory's copy was used, which lags and omits ssh-keys)"),
        (PROJECT, "VM Hardening (instances: the Compute API read failed; the inventory's copy was used, which can lag changes by hours)")]
    monkeypatch.setattr(vh.gcp, 'api_build', lambda *args, **kwargs: Compute({PROJECT: {'enable-oslogin': 'true'}}))
    # The roles search failing: the VM rows stand (Investigation, "could not be read") and Projects not checked says why.
    inventory = Inventory(assets, search_error=RuntimeError('429 quota'))
    monkeypatch.setattr(vh.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    vh.check_vm_posture('project', PROJECT, JOB, sink=sink)
    assert sink.by_check()['VM Service Accounts']['Status'] == IR and 'could not be read' in sink.by_check()['VM Service Accounts']['Finding'][0]['Detail']
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [(f'projects/{PROJECT}', f'VM Service Accounts (roles of {DEFAULT}: the IAM search failed)')]
    # Nothing in scope: two all-clear rows, no API read. A listing that fails: two Errors.
    compute = Compute({})
    monkeypatch.setattr(vh.gcp, 'asset_client', lambda credentials=None: Inventory())
    monkeypatch.setattr(vh.gcp, 'api_build', lambda *args, **kwargs: compute)
    sink = Sink()
    vh.check_vm_posture('folder', '42', JOB, sink=sink)
    assert {name: record['Finding'] for name, record in sink.by_check().items()} == {'VM Service Accounts': [{'Status': vh.VM_SA_ALL_CLEAR}], 'VM Hardening': [{'Status': vh.VM_HARDENING_ALL_CLEAR}]}
    assert compute.asked == [] and compute.listed == []
    monkeypatch.setattr(vh.gcp, 'asset_client', lambda credentials=None: Inventory(error=RuntimeError('503 inventory unavailable')))
    sink = Sink()
    vh.check_vm_posture('folder', '42', JOB, sink=sink)
    assert {name: record['Status'] for name, record in sink.by_check().items()} == {'VM Service Accounts': 'Error', 'VM Hardening': 'Error'}


def test_the_two_names_enter_the_changes_card_as_new_checks():
    assert vh.VM_CHECKS == ('VM Service Accounts', 'VM Hardening') and not any(name in RESHAPED_CHECKS for name in vh.VM_CHECKS)
