"""
v19 — Findings and vulnerabilities, VM Manager and the exposure join: the rules of ``app.checks.vulnerabilities`` on fixture reports,
instances, firewall rules and policies, and the two checks end to end with their failure paths.
"""
from types import SimpleNamespace

from googleapiclient.errors import HttpError

from app.checks import vulnerabilities as vul
from app.checks.vulnerabilities import (EXPOSED_VM_CHECK, OS_VULN_CHECK, check_exposed_vms, check_os_vulnerabilities, exposed_vm_rows, instance_exposure_facts, is_precondition,
                                        open_rules, precondition_row, privileged_identity, reaching_rule, report_facts, roles_by_member, running_zones, vulnerability_rows)
from app.checks.identity_hygiene import policy_facts
from app.checks.not_checked import NOT_CHECKED
from fakes import ORG_ID as ORG, _execute

JOB = 'job-190'
P, N = 'stark-vm-prod', '111111111111'
DEFAULT_SA = f'{N}-compute@developer.gserviceaccount.com'
CP = 'https://www.googleapis.com/auth/cloud-platform'
RO = 'https://www.googleapis.com/auth/devstorage.read_only'


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


def http_error(status, message):
    return HttpError(SimpleNamespace(status=status, reason=message), message.encode(), uri='https://x/')


def vuln(cve, severity, score, fix=True):
    return {'details': {'cve': cve, 'severity': severity, 'cvssV3': {'baseScore': score}}, **({'availableInventoryItemIds': ['pkg']} if fix else {})}


def report(instance, vulns):
    return {'name': f'projects/{P}/locations/asia-south1-b/instances/{instance}/vulnerabilityReport', 'vulnerabilities': vulns}


def instance(name, zone='asia-south1-b', external='203.0.113.10', email=DEFAULT_SA, scopes=(CP,), tags=(), status='RUNNING', network='vpc-main', labels=None, project=P, access_name='External NAT'):
    data = {'name': name, 'status': status, 'zone': f'https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}', 'labels': labels or {},
            'serviceAccounts': [{'email': email, 'scopes': list(scopes)}] if email else [], 'tags': {'items': list(tags)},
            'networkInterfaces': [{'name': 'nic0', 'network': f'https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}',
                                   **({'accessConfigs': [{'name': access_name, 'natIP': external}]} if external else {})}]}
    return SimpleNamespace(name=f'//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{name}', resource=SimpleNamespace(data=data))


def firewall(name, sources=('0.0.0.0/0',), ports=('22',), protocol='tcp', tags=(), accounts=(), disabled=False, direction='INGRESS', network='vpc-main', deny=False, project=P):
    data = {'name': name, 'network': f'https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}', 'direction': direction, 'disabled': disabled, 'sourceRanges': list(sources),
            ('denied' if deny else 'allowed'): [{'IPProtocol': protocol, **({'ports': list(ports)} if ports else {})}], 'targetTags': list(tags), 'targetServiceAccounts': list(accounts)}
    return SimpleNamespace(name=f'//compute.googleapis.com/projects/{project}/global/firewalls/{name}', resource=SimpleNamespace(data=data))


def policy(resource, bindings, asset_type='cloudresourcemanager.googleapis.com/Project'):
    return SimpleNamespace(resource=f'//cloudresourcemanager.googleapis.com/{resource}', asset_type=asset_type, project=f'projects/{N}', folders=[], organization=f'organizations/{ORG}',
                           policy=SimpleNamespace(bindings=[SimpleNamespace(role=role, members=list(members), condition=None) for role, members in bindings]))


# --- OS Vulnerabilities ---

def test_running_zones_skip_stopped_and_managed_instances():
    response = {'items': {'zones/asia-south1-b': {'instances': [{'id': '1', 'name': 'web', 'status': 'RUNNING'}, {'id': '2', 'name': 'off', 'status': 'TERMINATED'},
                                                               {'id': '3', 'name': 'gke-node', 'status': 'RUNNING', 'labels': {'goog-gke-node': ''}}]},
                          'zones/asia-south1-c': {'instances': [{'id': '4', 'name': 'db', 'status': 'RUNNING'}]}, 'zones/empty': {'warning': {'code': 'NO_RESULTS_ON_PAGE'}}}}
    assert running_zones(response) == {'asia-south1-b': {'1': 'web'}, 'asia-south1-c': {'4': 'db'}}
    assert running_zones({}) == {}


def test_report_facts_and_rows_rank_fixable_critical_and_high():
    facts = report_facts(report('7001', [vuln('CVE-2026-1', 'HIGH', 7.5), vuln('CVE-2026-2', 'CRITICAL', 9.8), vuln('CVE-2026-3', 'CRITICAL', 9.1, fix=False), vuln('CVE-2026-4', 'MEDIUM', 5.0),
                                         vuln('CVE-2026-5', 'LOW', 2.0, fix=False), {'details': {}}]), {'7001': 'web'})
    assert (facts['instance'], facts['critical'], facts['high'], facts['other'], facts['fixable'], facts['critical_fixable'], facts['high_fixable']) == ('web', 2, 1, 3, 3, 1, 1)
    assert facts['top'] == [('CRITICAL', 9.8, 'CVE-2026-2', True), ('CRITICAL', 9.1, 'CVE-2026-3', False), ('HIGH', 7.5, 'CVE-2026-1', True)]
    rows = vulnerability_rows(P, 'asia-south1-b', [facts, report_facts(report('7002', [vuln('CVE-2026-9', 'HIGH', 8.0)]), {'7002': 'api'}),
                                                   report_facts(report('7003', [vuln('CVE-2026-8', 'CRITICAL', 9.0, fix=False), vuln('CVE-2026-7', 'MEDIUM', 4.0)]), {})])
    assert [(r['Instance'], r['Issue'], r['_status']) for r in rows] == [('web', '1 critical CVE with a fix available.', 'Action Required'), ('api', '1 high CVE with a fix available.', 'Investigation Recommended')]
    assert rows[0]['Detail'] == 'VM Manager reports 6 CVEs (2 critical, 1 high), 3 with a fix available. Worst: CVE-2026-2 (critical, CVSS 9.8, fix available); CVE-2026-3 (critical, CVSS 9.1); CVE-2026-1 (high, CVSS 7.5, fix available).'
    assert rows[0]['Fix'] == f'gcloud compute os-config patch-jobs execute --project={P} --instance-filter-names=zones/asia-south1-b/instances/web --reboot-config=default'
    assert (rows[0]['Critical'], rows[0]['High'], rows[0]['Fixable']) == (2, 1, 3)
    assert vulnerability_rows(P, 'z', []) == []
    note = precondition_row(P, 4)
    assert (note['Instance'], note['Issue'], note['_status']) == ('4 VMs', 'VM Manager not fully enabled.', 'Informational') and '--metadata=enable-osconfig=TRUE' in note['Fix']
    assert is_precondition(http_error(400, 'Vulnerability reports are disabled in this project. To view these reports, enable full VM Manager functionality.'))
    assert not is_precondition(http_error(403, 'Permission denied')) and not is_precondition(http_error(400, 'bad zone'))


class FakeCompute:
    def __init__(self, items=None, error=None):
        self.items, self.error = items or {}, error  # items: the aggregated listing of P; other projects run nothing

    def instances(self):
        return SimpleNamespace(aggregatedList=lambda project, **kw: _execute(self.error or {'items': self.items if project == P else {}}))


class FakeOsConfig:
    def __init__(self, reports=None, errors=None):
        self.reports, self.errors, self.parents = reports or {}, errors or {}, []

    def projects(self):
        def list_(parent, pageSize=None):
            self.parents.append(parent)
            zone = parent.split('/locations/')[1].split('/')[0]
            return _execute(self.errors.get(zone) or {'vulnerabilityReports': self.reports.get(zone, [])})
        reports = SimpleNamespace(list=list_, list_next=lambda previous_request, previous_response: None)
        return SimpleNamespace(locations=lambda: SimpleNamespace(instances=lambda: SimpleNamespace(vulnerabilityReports=lambda: reports)))


def test_check_os_vulnerabilities_end_to_end(gcp):
    items = {'zones/asia-south1-b': {'instances': [{'id': '7001', 'name': 'web', 'status': 'RUNNING'}, {'id': '7002', 'name': 'off', 'status': 'TERMINATED'}]},
             'zones/asia-south1-c': {'instances': [{'id': '7003', 'name': 'db', 'status': 'RUNNING'}]}}
    gcp.discovery.apis['compute'] = FakeCompute(items)
    gcp.discovery.apis['osconfig'] = FakeOsConfig({'asia-south1-b': [report('7001', [vuln('CVE-2026-2', 'CRITICAL', 9.8)])], 'asia-south1-c': [report('7003', [vuln('CVE-2026-4', 'MEDIUM', 5.0)])]})
    s = Sink()
    check_os_vulnerabilities(ORG, [{'projectId': P}, {'projectId': 'no-vms'}], JOB, sink=s)
    record = s.by_check()[OS_VULN_CHECK]
    assert record['Status'] == 'Action Required' and [(r['Project'], r['Instance'], r['Zone']) for r in record['Finding']] == [(P, 'web', 'asia-south1-b')]
    assert gcp.discovery.apis['osconfig'].parents == [f'projects/{P}/locations/asia-south1-b/instances/-', f'projects/{P}/locations/asia-south1-c/instances/-'] and s.not_checked() == []
    # VM Manager not enabled: one Informational row for the project, the other zones not asked.
    gcp.discovery.apis['osconfig'] = FakeOsConfig(errors={'asia-south1-b': http_error(400, 'Vulnerability reports are disabled in this project. To view these reports, enable full VM Manager functionality.')})
    s = Sink()
    check_os_vulnerabilities(ORG, [{'projectId': P}], JOB, sink=s)
    record = s.by_check()[OS_VULN_CHECK]
    assert record['Status'] == 'Informational' and [(r['Instance'], r['Issue']) for r in record['Finding']] == [('2 VMs', 'VM Manager not fully enabled.')]
    assert gcp.discovery.apis['osconfig'].parents == [f'projects/{P}/locations/asia-south1-b/instances/-']
    # Nothing fixable: all clear. Failures: the instance listing (Compute disabled → logged, not a row; another error → a row), a zone's report read.
    gcp.discovery.apis['osconfig'] = FakeOsConfig({'asia-south1-b': [report('7001', [vuln('CVE-2026-9', 'CRITICAL', 9.0, fix=False)])]})
    s = Sink()
    check_os_vulnerabilities(ORG, [{'projectId': P}], JOB, sink=s)
    assert s.by_check()[OS_VULN_CHECK] == {'Check': OS_VULN_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': vul.OS_VULN_ALL_CLEAR}]}
    gcp.discovery.apis['compute'] = FakeCompute(error=http_error(403, 'Compute Engine API has not been used in project stark-vm-prod before or it is disabled'))
    s = Sink()
    check_os_vulnerabilities(ORG, [{'projectId': P}], JOB, sink=s)
    assert s.not_checked() == []
    gcp.discovery.apis['compute'] = FakeCompute(items)
    gcp.discovery.apis['osconfig'] = FakeOsConfig(errors={'asia-south1-b': RuntimeError('osconfig down')})
    s = Sink()
    check_os_vulnerabilities(ORG, [{'projectId': P}], JOB, sink=s)
    assert [(r['Project'], r['Skipped check'], r['Reason']) for r in s.not_checked()] == [(P, f'{OS_VULN_CHECK} (zone asia-south1-b)', 'osconfig down')]


# --- Exposed Privileged VMs ---

def test_instance_facts_identity_and_rules():
    vm = instance_exposure_facts({'project_id': P, 'name': 'web', 'region': 'asia-south1-b', 'data': instance('web', tags=('web',)).resource.data})
    assert (vm['external'], vm['accounts'], vm['tags'], vm['networks'], vm['status'], vm['managed']) == ([('203.0.113.10', 'External NAT')], [(DEFAULT_SA, ['cloud-platform'])], ['web'], ['vpc-main'], 'RUNNING', False)
    roles = roles_by_member([policy_facts(policy(f'projects/{P}', [('roles/owner', [f'serviceAccount:admin@{P}.iam.gserviceaccount.com', 'user:me@example.com']), ('roles/viewer', [f'serviceAccount:ro@{P}.iam.gserviceaccount.com'])])),
                             policy_facts(policy(f'folders/1061', [('roles/editor', ['serviceAccount:x@y'])], 'cloudresourcemanager.googleapis.com/Folder'))])
    assert roles == {P: {f'admin@{P}.iam.gserviceaccount.com': {'roles/owner'}, f'ro@{P}.iam.gserviceaccount.com': {'roles/viewer'}}}
    assert privileged_identity(vm, roles[P]) == f'{DEFAULT_SA} (default account) with the cloud-platform scope'
    assert privileged_identity({'accounts': [(DEFAULT_SA, ['devstorage.read_only'])]}, {}) == ''
    assert privileged_identity({'accounts': [(f'admin@{P}.iam.gserviceaccount.com', ['devstorage.read_only'])]}, roles[P]) == f'admin@{P}.iam.gserviceaccount.com holds roles/owner'
    assert privileged_identity({'accounts': [(f'ro@{P}.iam.gserviceaccount.com', ['cloud-platform'])]}, roles[P]) == ''
    assert privileged_identity({'accounts': [('ci@x', [])]}, {'ci@x': {'roles/iam.serviceAccountTokenCreator', 'roles/compute.admin'}}) == 'ci@x holds roles/compute.admin, roles/iam.serviceAccountTokenCreator'
    rules = open_rules({'firewalls': [{'name': 'ssh', 'data': firewall('ssh').resource.data}, {'name': 'internal', 'data': firewall('internal', sources=('10.0.0.0/8',)).resource.data},
                                      {'name': 'off', 'data': firewall('off', disabled=True).resource.data}, {'name': 'egress', 'data': firewall('egress', direction='EGRESS').resource.data},
                                      {'name': 'deny', 'data': firewall('deny', deny=True).resource.data}, {'name': 'tagged', 'data': firewall('tagged', tags=('web',), network='other').resource.data}],
                        'firewallPolicies': [{'name': 'p', 'data': {'name': '900001', 'displayName': 'edge-policy', 'associations': [{'attachmentTarget': f'projects/{P}/global/networks/vpc-main'}],
                                                                   'rules': [{'priority': 100, 'direction': 'INGRESS', 'action': 'allow', 'match': {'srcIpRanges': ['0.0.0.0/0'], 'layer4Configs': [{'ipProtocol': 'tcp', 'ports': ['3389']}]}},
                                                                             {'priority': 200, 'direction': 'INGRESS', 'action': 'deny', 'match': {'srcIpRanges': ['0.0.0.0/0'], 'layer4Configs': [{'ipProtocol': 'all'}]}}]}}]})
    assert [(network, rule['name']) for network, rule in rules] == [('vpc-main', 'ssh'), ('other', 'tagged'), ('vpc-main', 'edge-policy #100')]
    assert reaching_rule(vm, rules)['name'] == 'ssh'
    assert reaching_rule({**vm, 'networks': ['other'], 'tags': []}, rules) is None and reaching_rule({**vm, 'networks': ['other']}, rules)['name'] == 'tagged'
    assert reaching_rule({**vm, 'tags': []}, rules[1:])['name'] == 'edge-policy #100'
    hierarchical = open_rules({'firewallPolicies': [{'name': 'h', 'data': {'name': '1', 'displayName': 'org-policy', 'rules': [{'priority': 1, 'action': 'allow', 'match': {'srcIpRanges': ['::/0'], 'layer4Configs': [{'ipProtocol': 'all'}]}}]}}]})
    assert hierarchical[0][0] == '' and reaching_rule({**vm, 'networks': ['anything']}, hierarchical)['name'] == 'org-policy #1'


def test_exposed_vm_rows_need_all_three_legs():
    vms = [instance_exposure_facts({'project_id': P, 'name': n, 'region': 'z', 'data': i.resource.data}) for n, i in [
        ('exposed', instance('exposed', access_name='external-nat')), ('internal', instance('internal', external=None)), ('plain', instance('plain', scopes=(RO,))), ('stopped', instance('stopped', status='TERMINATED')),
        ('gke', instance('gke', labels={'goog-gke-node': ''})), ('admin', instance('admin', email=f'admin@{P}.iam.gserviceaccount.com', scopes=(RO,))), ('shielded', instance('shielded', network='private'))]]
    rules = open_rules({'firewalls': [{'name': 'ssh', 'data': firewall('ssh').resource.data}]})
    roles = {P: {f'admin@{P}.iam.gserviceaccount.com': {'roles/editor'}}}
    rows = exposed_vm_rows(vms, rules, roles)
    assert [(r['Instance'], r['External IP'], r['Identity'], r['Open rule'], r['_status']) for r in rows] == [
        ('exposed', '203.0.113.10', f'{DEFAULT_SA} (default account) with the cloud-platform scope', 'ssh (tcp:22 from 0.0.0.0/0)', 'Action Required'),
        ('admin', '203.0.113.10', f'admin@{P}.iam.gserviceaccount.com holds roles/editor', 'ssh (tcp:22 from 0.0.0.0/0)', 'Action Required')]
    assert rows[0]['Fix'] == f'gcloud compute instances delete-access-config exposed --zone=asia-south1-b --project={P} --access-config-name="external-nat"  # or narrow ssh to your CIDRs / the IAP range, or move the VM to a dedicated, least-privilege service account'  # the config's own name (gcloud: external-nat; console: External NAT)
    assert rows[1]['Fix'].startswith(f'gcloud compute instances delete-access-config admin --zone=asia-south1-b --project={P} --access-config-name="External NAT"')
    assert exposed_vm_rows(vms, [], roles) == [] and exposed_vm_rows(vms, rules, {}) == rows[:1]


def test_check_exposed_vms_end_to_end(gcp):
    for asset in (instance('exposed'), instance('internal', external=None), firewall('ssh')):
        gcp.assets.add_asset(asset.name.split('/')[2].replace('.googleapis.com', '.googleapis.com/') + ('Instance' if '/instances/' in asset.name else 'Firewall'), asset.name, asset.resource.data, project_number=N)
    gcp.assets.add_iam_policy('cloudresourcemanager.googleapis.com/Project', f'//cloudresourcemanager.googleapis.com/projects/{P}', [('roles/viewer', ['group:readers@example.com'])], project_number=N)
    s = Sink()
    check_exposed_vms('organization', ORG, JOB, sink=s)
    record = s.by_check()[EXPOSED_VM_CHECK]
    assert record['Status'] == 'Action Required' and [(r['Project'], r['Instance']) for r in record['Finding']] == [(P, 'exposed')] and s.not_checked() == []
    assert gcp.assets.list_requests[-1]['asset_types'] == vul.EXPOSURE_TYPES and gcp.assets.iam_queries[-1] == ''
    # The IAM search failing: only the default account with cloud-platform counts, with a note. No external VM: no search at all.
    gcp.assets.iam_error = RuntimeError('search down')
    s = Sink()
    check_exposed_vms('organization', ORG, JOB, sink=s)
    assert [r['Instance'] for r in s.by_check()[EXPOSED_VM_CHECK]['Finding']] == ['exposed']
    assert [(r['Project'], r['Reason']) for r in s.not_checked()] == [(f'organizations/{ORG}', 'search down')]
    gcp.assets.assets = [a for a in gcp.assets.assets if 'exposed' not in a.name]
    queries = len(gcp.assets.iam_queries)
    s = Sink()
    check_exposed_vms('project', P, JOB, sink=s)
    assert s.by_check()[EXPOSED_VM_CHECK] == {'Check': EXPOSED_VM_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': vul.EXPOSED_VM_ALL_CLEAR}]} and len(gcp.assets.iam_queries) == queries
    gcp.assets.list_errors['compute.googleapis.com/Instance'] = RuntimeError('inventory down')
    s = Sink()
    check_exposed_vms('organization', ORG, JOB, sink=s)
    assert s.by_check()[EXPOSED_VM_CHECK] == {'Check': EXPOSED_VM_CHECK, 'Status': 'Error', 'Finding': [{'Error': 'inventory down'}]}
