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
"""GKE security posture (v17.1, ``app.checks.gke_security``): the metadata mode, node account and exposure of every
node pool, the control plane's exposure, the hardening gaps, threat detection and logging — the rules on cluster
JSON, then the check against a fake Asset Inventory, IAM search, Security Command Center settings and project policy."""
from types import SimpleNamespace

import pytest
from google.api_core import exceptions as core_exceptions

from app.checks.gke_security import (
    CONTROL_PLANE_CHECK,
    CREDENTIAL_EXPOSURE_CHECK,
    GKE_SECURITY_CHECKS,
    NODE_HARDENING_CHECK,
    THREAT_DETECTION_CHECK,
    check_gke_security,
    cluster_facts,
    control_plane_issues,
    credential_rows,
    data_access_logging,
    exposure,
    hardening_issues,
    legacy_endpoints_enabled,
    logging_gaps,
    node_service_account,
    pool_metadata_mode,
    pool_scopes,
)
from app.checks.not_checked import NOT_CHECKED
from fakes import _execute

JOB = 'job-171'
CLUSTER_ASSET = 'container.googleapis.com/Cluster'
DEFAULT_SCOPES = ['https://www.googleapis.com/auth/devstorage.read_only', 'https://www.googleapis.com/auth/logging.write']


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


def pool(name='default-pool', *, metadata=None, account=None, scopes=None, legacy=None, secure_boot=True, image='COS_CONTAINERD', private=None):
    config = {'oauthScopes': scopes if scopes is not None else DEFAULT_SCOPES, 'imageType': image,
              'shieldedInstanceConfig': {'enableSecureBoot': secure_boot, 'enableIntegrityMonitoring': True}, 'metadata': {}}
    if metadata:
        config['workloadMetadataConfig'] = {'mode': metadata}
    if account:
        config['serviceAccount'] = account
    if legacy is not None:
        config['metadata']['disable-legacy-endpoints'] = legacy
    entry = {'name': name, 'config': config, 'status': 'RUNNING'}
    if private is not None:
        entry['networkConfig'] = {'enablePrivateNodes': private}
    return entry


def cluster(name='prod-a', **overrides):
    """A hardened Standard cluster; ``overrides`` replace top-level fields."""
    data = {'name': name, 'location': 'europe-west1', 'status': 'RUNNING', 'nodePools': [pool(metadata='GKE_METADATA', account='gke-nodes@p1.iam.gserviceaccount.com')],
            'workloadIdentityConfig': {'workloadPool': 'p1.svc.id.goog'}, 'privateClusterConfig': {'enablePrivateNodes': True, 'enablePrivateEndpoint': True},
            'masterAuthorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '10.0.0.0/8'}]}, 'legacyAbac': {},
            'masterAuth': {'clusterCaCertificate': 'x'}, 'shieldedNodes': {'enabled': True}, 'networkConfig': {'datapathProvider': 'ADVANCED_DATAPATH'},
            'binaryAuthorization': {'evaluationMode': 'PROJECT_SINGLETON_POLICY_ENFORCE'},
            'securityPostureConfig': {'mode': 'BASIC', 'vulnerabilityMode': 'VULNERABILITY_BASIC'}, 'databaseEncryption': {'state': 'ENCRYPTED'},
            'loggingConfig': {'componentConfig': {'enableComponents': ['SYSTEM_COMPONENTS', 'WORKLOADS']}},
            'anonymousAuthenticationConfig': {'mode': 'LIMITED'}, 'rbacBindingConfig': {}}
    data.update(overrides)
    return data


def fact(data, project_id='p1', project_number='111'):
    asset = SimpleNamespace(name=f'//container.googleapis.com/projects/{project_id}/locations/{data["location"]}/clusters/{data["name"]}',
                            resource=SimpleNamespace(data=data, parent=f'//cloudresourcemanager.googleapis.com/projects/{project_number}'),
                            ancestors=[f'projects/{project_number}', 'organizations/987654321'])
    return cluster_facts(asset)


# --- the rules ---

def test_metadata_mode_account_scopes_and_legacy_endpoints():
    standard = cluster()
    assert pool_metadata_mode(standard, pool(metadata='GKE_METADATA')) == 'GKE'
    assert pool_metadata_mode(standard, pool()) == 'GCE'  # no workloadMetadataConfig at all: the node's own metadata server
    assert pool_metadata_mode(standard, pool(metadata='GCE_METADATA')) == 'GCE'
    assert pool_metadata_mode(standard, {'config': {'workloadMetadataConfig': {'nodeMetadata': 'SECURE'}}}) == 'GCE'  # concealment hides kube-env only
    assert pool_metadata_mode(standard, {'config': {'workloadMetadataConfig': {'nodeMetadata': 'GKE_METADATA_SERVER'}}}) == 'GKE'
    assert pool_metadata_mode(cluster(autopilot={'enabled': True}), pool()) == 'GKE'
    # The API writes "default" for the Compute Engine default account; the project number spells it out.
    assert node_service_account(pool(), '111') == ('111-compute@developer.gserviceaccount.com', True)
    assert node_service_account(pool(account='111-compute@developer.gserviceaccount.com'), '111') == ('111-compute@developer.gserviceaccount.com', True)
    assert node_service_account(pool(account='gke-nodes@p1.iam.gserviceaccount.com'), '111') == ('gke-nodes@p1.iam.gserviceaccount.com', False)
    assert node_service_account(pool(), '') == ('default', True)
    assert pool_scopes(pool(scopes=['https://www.googleapis.com/auth/cloud-platform', 'openid'])) == ['cloud-platform', 'openid']
    assert legacy_endpoints_enabled(pool()) is False  # the default since 1.12
    assert legacy_endpoints_enabled(pool(legacy='true')) is False
    assert legacy_endpoints_enabled(pool(legacy='false')) is True


@pytest.mark.parametrize('metadata, is_default, roles, scopes, expected', [
    ('GCE', True, {'roles/editor', 'roles/logging.logWriter'}, ['cloud-platform'],
     ('Action Required', 'One SSRF from roles/editor on p1: pods reach the node\'s metadata server and a stolen token carries every role of the account.')),
    ('GCE', True, {'roles/container.clusterAdmin'}, ['devstorage.read_only', 'logging.write'],
     ('Action Required', "One SSRF from roles/container.clusterAdmin on p1: pods reach the node's metadata server; the pool's OAuth scopes limit what a "
                         "stolen token can call (devstorage.read_only, logging.write), not whose roles it carries.")),
    ('GCE', False, set(), ['cloud-platform'], ('Investigation Recommended', "Pods reach the node's metadata server (the node token and kube-env); the account holds no privileged role.")),
    ('GCE', True, set(), DEFAULT_SCOPES, ('Investigation Recommended', "Pods reach the node's metadata server (the node token and kube-env); the node runs as the Compute Engine default service account.")),
    ('GCE', False, None, [], ('Investigation Recommended', "Pods reach the node's metadata server (the node token and kube-env); the account's roles could not be read.")),
    ('GKE', True, {'roles/editor'}, ['cloud-platform'], ('Investigation Recommended', 'Pods use the GKE metadata server, but the nodes still run as the Compute Engine default service account.')),
    ('GKE', False, {'roles/editor'}, ['cloud-platform'], None),
])
def test_exposure_verdicts(metadata, is_default, roles, scopes, expected):
    assert exposure(metadata, is_default, roles, scopes, 'p1') == expected


def test_exposure_notes_legacy_endpoints():
    status, text = exposure('GCE', False, set(), [], 'p1', legacy_endpoints=True)
    assert status == 'Investigation Recommended' and text.endswith('Legacy metadata endpoints are enabled.')
    assert exposure('GKE', False, set(), [], 'p1', legacy_endpoints=True) == ('Investigation Recommended', 'Legacy metadata endpoints are enabled on this pool.')


def test_credential_rows_per_pool_with_fixes_and_autopilot_skipped():
    data = cluster(nodePools=[pool('default-pool'), pool('wi-pool', metadata='GKE_METADATA', account='gke-nodes@p1.iam.gserviceaccount.com')],
                   workloadIdentityConfig=None)
    rows = credential_rows(fact(data), {'111-compute@developer.gserviceaccount.com': {'roles/editor'}, 'gke-nodes@p1.iam.gserviceaccount.com': set()})
    assert [(r['Node Pool'], r['Metadata'], r['_status']) for r in rows] == [('default-pool', 'GCE', 'Action Required')]
    row = rows[0]
    assert row['Service Account'] == '111-compute@developer.gserviceaccount.com (default)' and row['Roles'] == ['roles/editor']
    assert row['Scopes'] == ['devstorage.read_only', 'logging.write'] and row['Exposure'].startswith('One SSRF from roles/editor on p1')
    fixes = row['Fix'].split('\n')
    assert fixes[0] == 'gcloud container clusters update prod-a --location=europe-west1 --project=p1 --workload-pool=p1.svc.id.goog'
    assert fixes[1] == 'gcloud container node-pools update default-pool --cluster=prod-a --location=europe-west1 --project=p1 --workload-metadata=GKE_METADATA'
    assert 'roles/container.defaultNodeServiceAccount' in fixes[2]
    # Roles that could not be read show as such; Autopilot clusters have no pool rows.
    assert credential_rows(fact(cluster(nodePools=[pool()], workloadIdentityConfig=None)), {})[0]['Roles'] == ['not read']
    assert credential_rows(fact(cluster(autopilot={'enabled': True}, nodePools=[pool()])), {}) == []


def test_control_plane_issues_new_and_classic_fields():
    assert control_plane_issues(cluster()) == []
    # Classic fields: public endpoint, authorized networks off.
    issues = control_plane_issues(cluster(privateClusterConfig={'enablePrivateNodes': True}, masterAuthorizedNetworksConfig={}))
    assert [(s, i.split(':')[0]) for s, i, _ in issues] == [('Action Required', 'Public control plane endpoint with authorized networks off')]
    # 0.0.0.0/0 among the authorized networks is as public.
    issues = control_plane_issues(cluster(privateClusterConfig={}, masterAuthorizedNetworksConfig={'enabled': True, 'cidrBlocks': [{'cidrBlock': '0.0.0.0/0'}]}))
    assert issues[0][0] == 'Action Required' and '0.0.0.0/0' in issues[0][1]
    # The newer controlPlaneEndpointsConfig wins when present; Google Cloud public IPs admitted is Investigation.
    new = cluster(controlPlaneEndpointsConfig={'ipEndpointsConfig': {'enabled': True, 'enablePublicEndpoint': True,
                                                                     'authorizedNetworksConfig': {'enabled': True, 'gcpPublicCidrsAccessEnabled': True}}})
    assert [s for s, _, _ in control_plane_issues(new)] == ['Investigation Recommended']
    private_new = cluster(controlPlaneEndpointsConfig={'ipEndpointsConfig': {'enabled': True, 'enablePublicEndpoint': False, 'authorizedNetworksConfig': {}}})
    assert control_plane_issues(private_new) == []
    # ABAC, client certificates, basic auth; anonymous and system-group bindings in one Investigation row.
    issues = control_plane_issues(cluster(legacyAbac={'enabled': True}, masterAuth={'clientCertificateConfig': {'issueClientCertificate': True}, 'username': 'admin'},
                                          anonymousAuthenticationConfig={'mode': 'ENABLED'},
                                          rbacBindingConfig={'enableInsecureBindingSystemAuthenticated': True, 'enableInsecureBindingSystemUnauthenticated': True}))
    assert [s for s, _, _ in issues] == ['Action Required', 'Action Required', 'Action Required', 'Investigation Recommended']
    assert issues[3][1] == 'Allowed: anonymous authentication, bindings to system:unauthenticated, bindings to system:authenticated.'
    assert '--no-enable-legacy-authorization' in issues[0][2] and '--no-issue-client-certificate' in issues[1][2]


def test_hardening_issues_standard_and_autopilot():
    assert hardening_issues(cluster()) == []
    weak = cluster(networkConfig={}, networkPolicy={}, shieldedNodes={}, privateClusterConfig={}, binaryAuthorization={},
                   securityPostureConfig={'mode': 'DISABLED', 'vulnerabilityMode': 'VULNERABILITY_DISABLED'}, databaseEncryption={'state': 'DECRYPTED'},
                   nodePools=[pool('a', secure_boot=False, image='UBUNTU_CONTAINERD'), pool('b', private=True)])
    issues = hardening_issues(weak)
    assert [(p, i.split(' ')[0]) for p, i, _ in issues] == [
        ('', 'No'), ('', 'Shielded'), ('a', 'Nodes'), ('a', 'Secure'), ('a', 'Node'), ('', 'Binary'), ('', 'Security'), ('', 'Workload'), ('', 'Application-layer')]
    assert issues[2][2] == '--enable-private-nodes' and issues[4][1] == 'Node image UBUNTU_CONTAINERD is not Container-Optimized OS.'
    # Pool b is private by its own setting; the classic networkPolicy.enabled counts as enforcement.
    assert all(p != 'b' for p, _, _ in issues)
    assert not any('network policy' in i for _, i, _ in hardening_issues(cluster(networkConfig={}, networkPolicy={'enabled': True})))
    # Autopilot: only the cluster-level items that apply.
    auto = hardening_issues(cluster(autopilot={'enabled': True}, networkConfig={}, shieldedNodes={}, binaryAuthorization={}, nodePools=[pool(secure_boot=False)]))
    assert [i.split(':')[0] for _, i, _ in auto] == ['Binary Authorization off']


def test_logging_gaps_and_data_access_logging():
    assert logging_gaps(cluster()) == []
    assert logging_gaps(cluster(loggingConfig={'componentConfig': {'enableComponents': ['SYSTEM_COMPONENTS']}})) == ['WORKLOADS']
    assert logging_gaps(cluster(loggingConfig={})) == ['SYSTEM_COMPONENTS', 'WORKLOADS']
    assert data_access_logging([{'service': 'container.googleapis.com', 'auditLogConfigs': [{'logType': 'DATA_READ'}, {'logType': 'DATA_WRITE'}]}]) is True
    assert data_access_logging([{'service': 'allServices', 'auditLogConfigs': [{'logType': 'DATA_READ'}, {'logType': 'DATA_WRITE'}, {'logType': 'ADMIN_READ'}]}]) is True
    assert data_access_logging([{'service': 'container.googleapis.com', 'auditLogConfigs': [{'logType': 'DATA_WRITE'}]}]) is False
    assert data_access_logging([{'service': 'storage.googleapis.com', 'auditLogConfigs': [{'logType': 'DATA_READ'}, {'logType': 'DATA_WRITE'}]}]) is False
    assert data_access_logging(None) is False


def test_cluster_facts_take_the_project_number_from_the_parent_or_the_ancestors():
    data = cluster()
    assert fact(data)['project_number'] == '111' and fact(data)['project_id'] == 'p1' and fact(data)['location'] == 'europe-west1'
    asset = SimpleNamespace(name='//container.googleapis.com/projects/p2/locations/us-central1-a/clusters/c', resource=SimpleNamespace(data={'name': 'c'}),
                            ancestors=['projects/222', 'organizations/1'])
    facts = cluster_facts(asset)
    assert (facts['project_id'], facts['project_number'], facts['location']) == ('p2', '222', 'us-central1-a')


# --- the check ---

class FakeScc:
    """``securitycenter v1beta2``: Container Threat Detection per cluster, Event Threat Detection per project."""

    def __init__(self, ctd=None, etd=None, error=None):
        self.ctd, self.etd, self.error, self.names = ctd or {}, etd or {}, error, []

    def projects(self):
        scc = self

        def calculate_ctd(name):
            scc.names.append(name)
            cluster_name = name.split('/clusters/')[1].split('/')[0]
            return _execute(scc.error or {'serviceEnablementState': scc.ctd.get(cluster_name, 'ENABLED')})

        def calculate_etd(name):
            scc.names.append(name)
            project = name.split('/')[1]
            return _execute(scc.error or {'serviceEnablementState': scc.etd.get(project, 'ENABLED')})

        clusters = SimpleNamespace(containerThreatDetectionSettings=lambda: SimpleNamespace(calculate=calculate_ctd))
        return SimpleNamespace(locations=lambda: SimpleNamespace(clusters=lambda: clusters),
                               eventThreatDetectionSettings=lambda: SimpleNamespace(calculate=calculate_etd))


class FakeCrm:
    """``cloudresourcemanager v1``: ``projects().getIamPolicy()`` with audit configs per project."""

    def __init__(self, audit=None, error=None):
        self.audit, self.error = audit or {}, error

    def projects(self):
        crm = self

        def get_iam_policy(resource, body=None):
            return _execute(crm.error or {'bindings': [], 'auditConfigs': crm.audit.get(resource, [])})
        return SimpleNamespace(getIamPolicy=get_iam_policy)


def add_cluster(gcp, data, project_id='p1', project_number='111'):
    gcp.assets.add_asset(CLUSTER_ASSET, f'//container.googleapis.com/projects/{project_id}/locations/{data["location"]}/clusters/{data["name"]}', data,
                         project_number=project_number)


def test_the_check_writes_the_four_findings_from_one_listing(gcp):
    exposed = cluster('legacy', nodePools=[pool(scopes=['https://www.googleapis.com/auth/cloud-platform'])], workloadIdentityConfig=None,
                      privateClusterConfig={'enablePrivateNodes': True}, masterAuthorizedNetworksConfig={},
                      loggingConfig={'componentConfig': {'enableComponents': ['SYSTEM_COMPONENTS']}})
    add_cluster(gcp, exposed)
    add_cluster(gcp, cluster('hardened'), project_id='p2', project_number='222')
    gcp.assets.add_iam_policy('cloudresourcemanager.googleapis.com/Project', '//cloudresourcemanager.googleapis.com/projects/p1',
                              [('roles/editor', ['serviceAccount:111-compute@developer.gserviceaccount.com', 'user:dev@example.com'])], project_number='111')
    gcp.assets.add_iam_policy('storage.googleapis.com/Bucket', '//storage.googleapis.com/projects/_/buckets/b',  # a bucket binding is not a role of the account
                              [('roles/storage.admin', ['serviceAccount:111-compute@developer.gserviceaccount.com'])], project_number='111')
    gcp.discovery.apis['securitycenter'] = FakeScc(ctd={'legacy': 'DISABLED'}, etd={'p1': 'DISABLED'})
    gcp.discovery.apis['cloudresourcemanager'] = FakeCrm(audit={'p2': [{'service': 'allServices', 'auditLogConfigs': [{'logType': 'DATA_READ'}, {'logType': 'DATA_WRITE'}]}]})
    sink = Sink()
    check_gke_security('organization', '987654321', JOB, sink=sink)
    findings = sink.by_check()
    assert set(findings) == set(GKE_SECURITY_CHECKS)
    # One listing under the organization; one IAM search per node account.
    assert [r['parent'] for r in gcp.assets.list_requests] == ['organizations/987654321']
    assert gcp.assets.iam_queries == ['policy:"111-compute@developer.gserviceaccount.com"', 'policy:"gke-nodes@p1.iam.gserviceaccount.com"']
    credential = findings[CREDENTIAL_EXPOSURE_CHECK]
    assert credential['Status'] == 'Action Required' and len(credential['Finding']) == 1
    row = credential['Finding'][0]
    assert (row['Project'], row['Cluster'], row['Metadata'], row['Roles'], row['Scopes']) == ('p1', 'legacy', 'GCE', ['roles/editor'], ['cloud-platform'])
    assert row['Exposure'].startswith('One SSRF from roles/editor on p1')
    control = findings[CONTROL_PLANE_CHECK]
    assert control['Status'] == 'Action Required' and [r['Cluster'] for r in control['Finding']] == ['legacy']
    assert control['Finding'][0]['Fix'].startswith('gcloud container clusters update legacy --location=europe-west1 --project=p1 --enable-master-authorized-networks')
    assert findings[NODE_HARDENING_CHECK]['Finding'] == [{'Status': 'Every cluster has private, Shielded, COS nodes, network policy enforcement, Binary Authorization, '
                                                                    'posture scanning and secrets encryption.'}]
    threat = findings[THREAT_DETECTION_CHECK]
    assert threat['Status'] == 'Action Required'
    assert [(r['Cluster'], r['Signal'], r['State']) for r in threat['Finding']] == [
        ('legacy', 'Container Threat Detection', 'DISABLED'), ('legacy', 'Event Threat Detection', 'DISABLED'),
        ('legacy', 'Cloud Logging', 'missing WORKLOADS'), ('legacy', 'Data-access audit logs', 'off for container.googleapis.com')]
    assert sink.not_checked() == []


def test_the_check_reports_a_failed_listing_and_partial_failures(gcp):
    gcp.assets.list_errors[CLUSTER_ASSET] = core_exceptions.PermissionDenied('no cloudasset.assets.listResource')
    sink = Sink()
    check_gke_security('project', 'p1', JOB, sink=sink)
    assert all(record['Status'] == 'Error' and 'listResource' in record['Finding'][0]['Error'] for record in sink.by_check().values())
    assert set(sink.by_check()) == set(GKE_SECURITY_CHECKS)
    # The roles of a node account that cannot be searched, and SCC settings that cannot be read, land on Projects not checked.
    gcp.assets.list_errors.clear()
    add_cluster(gcp, cluster('c', nodePools=[pool()], workloadIdentityConfig=None))
    gcp.assets.iam_error = core_exceptions.PermissionDenied('no searchAllIamPolicies')
    gcp.discovery.apis['securitycenter'] = FakeScc(error=core_exceptions.PermissionDenied('no settings'))
    gcp.discovery.apis['cloudresourcemanager'] = FakeCrm()
    sink = Sink()
    check_gke_security('project', 'p1', JOB, sink=sink)
    findings = sink.by_check()
    assert findings[CREDENTIAL_EXPOSURE_CHECK]['Finding'][0]['Roles'] == ['not read']
    assert findings[CREDENTIAL_EXPOSURE_CHECK]['Status'] == 'Investigation Recommended'
    skipped = sink.not_checked()
    assert [(row['Project'], row['Skipped check']) for row in skipped] == [
        ('p1', f'{CREDENTIAL_EXPOSURE_CHECK} (roles of 111-compute@developer.gserviceaccount.com)'),
        ('p1', f'{THREAT_DETECTION_CHECK} (Security Command Center settings)')]
    assert 'no searchAllIamPolicies' in skipped[0]['Reason'] and 'no settings' in skipped[1]['Reason']
    # Audit logs were still read: the row is there.
    assert [r['Signal'] for r in findings[THREAT_DETECTION_CHECK]['Finding']] == ['Data-access audit logs']


def test_all_clear_rows_when_every_cluster_is_hardened(gcp):
    add_cluster(gcp, cluster(autopilot={'enabled': True}, nodePools=[pool()]))
    gcp.discovery.apis['securitycenter'] = FakeScc()
    gcp.discovery.apis['cloudresourcemanager'] = FakeCrm(audit={'p1': [{'service': 'container.googleapis.com', 'auditLogConfigs': [{'logType': 'DATA_READ'}, {'logType': 'DATA_WRITE'}]}]})
    sink = Sink()
    check_gke_security('folder', '42', JOB, sink=sink)
    assert {record['Status'] for record in sink.by_check().values()} == {'Compliant'}
    assert gcp.assets.iam_queries == []  # Autopilot: no node accounts to look up
