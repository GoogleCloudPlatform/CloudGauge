"""
v18.2 — GKE upgrade readiness & hygiene: the rules of ``app.checks.gke_operations`` on fixtures of the real shapes (the
production cluster as read in the plan, an Autopilot cluster, the probe cluster), the PodDisruptionBudget assets as
Asset Inventory shows them, the status ladder with Informational, and the two checks end to end.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.checks import gke_operations as ops
from app.checks.gke_security import hardening_issues
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS, RULE_CHANGED

JOB = 'job-182'
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
AR, IR, INFO, C = 'Action Required', 'Investigation Recommended', 'Informational', 'Compliant'


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


def stamp(days):
    return (NOW + timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')


def production_cluster(**overrides):
    """``cluster-stark`` as the plan read it: Extended channel, no window, notifications off, surge 1/0, nodes at the control plane's version."""
    data = {'name': 'cluster-stark', 'location': 'asia-south1', 'status': 'RUNNING', 'autopilot': {}, 'currentMasterVersion': '1.32.13-gke.2662000',
            'currentNodeVersion': '1.32.13-gke.2662000', 'releaseChannel': {'channel': 'EXTENDED'}, 'maintenancePolicy': {'resourceVersion': 'e3b0c442'},
            'notificationConfig': {'pubsub': {}}, 'ipAllocationPolicy': {'useIpAliases': True},
            'addonsConfig': {'dnsCacheConfig': {'enabled': True}, 'gcePersistentDiskCsiDriverConfig': {'enabled': True}},
            'monitoringConfig': {'componentConfig': {'enableComponents': ['SYSTEM_COMPONENTS', 'STATEFULSET', 'JOBSET', 'STORAGE', 'HPA', 'POD', 'DAEMONSET',
                                                                          'DEPLOYMENT', 'CADVISOR', 'KUBELET', 'DCGM']},
                                 'managedPrometheusConfig': {'enabled': True}},
            'nodePools': [{'name': 'default-pool', 'version': '1.32.13-gke.2662000', 'initialNodeCount': 1, 'management': {'autoRepair': True, 'autoUpgrade': True},
                           'upgradeSettings': {'maxSurge': 1, 'strategy': 'SURGE'},
                           'config': {'shieldedInstanceConfig': {'enableIntegrityMonitoring': True, 'enableSecureBoot': True}}}]}
    data.update(overrides)
    return data


def ready_cluster(**overrides):
    """A cluster with nothing to say: a window, full notifications, control-plane metrics, everything on."""
    ready = {'maintenancePolicy': {'window': {'recurringWindow': {'window': {'startTime': '2026-01-03T18:00:00Z', 'endTime': '2026-01-03T22:00:00Z'}, 'recurrence': 'FREQ=WEEKLY;BYDAY=SA,SU'}}},
             'notificationConfig': {'pubsub': {'enabled': True, 'topic': 'projects/p/topics/gke'}},
             'monitoringConfig': {'componentConfig': {'enableComponents': ['SYSTEM_COMPONENTS', 'APISERVER', 'SCHEDULER', 'CONTROLLER_MANAGER']}, 'managedPrometheusConfig': {'enabled': True}}}
    return production_cluster(**{**ready, **overrides})


def fact(data, project_id='p1'):
    return {'project_id': project_id, 'project_number': '111', 'name': data['name'], 'location': data['location'], 'data': data}


def pdb_asset(namespace, name, spec, status=None, project='p1', cluster='cluster-stark', location='asia-south1'):
    data = {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': {'name': name, 'namespace': namespace}, 'spec': spec}
    if status is not None:
        data['status'] = status
    return SimpleNamespace(name=f'//container.googleapis.com/projects/{project}/locations/{location}/clusters/{cluster}/k8s/namespaces/{namespace}/policy/poddisruptionbudgets/{name}',
                           resource=SimpleNamespace(data=data))


# --- the cluster facts ---------------------------------------------------------------------------------------------

def test_parse_time_reads_gke_timestamps():
    assert ops.parse_time('2026-11-21T00:00:00Z') == datetime(2026, 11, 21, tzinfo=timezone.utc)
    assert ops.parse_time('2026-11-21T00:00:00.123456Z') == datetime(2026, 11, 21, 0, 0, 0, 123456, tzinfo=timezone.utc)
    assert ops.parse_time('2026-11-21T05:30:00+05:30') == datetime(2026, 11, 21, tzinfo=timezone.utc)
    assert ops.parse_time('') is None and ops.parse_time('soon') is None


def test_maintenance_window_and_active_exclusions():
    assert ops.maintenance_window(production_cluster()) is None  # resourceVersion alone is no window
    assert ops.maintenance_window(ready_cluster()) is not None
    assert ops.maintenance_window(production_cluster(maintenancePolicy={'window': {'dailyMaintenanceWindow': {'startTime': '03:00', 'duration': 'PT4H0M0S'}}})) is not None
    exclusions = {'freeze': {'startTime': stamp(-1), 'endTime': stamp(13), 'maintenanceExclusionOptions': {'scope': 'NO_MINOR_OR_NODE_UPGRADES'}},
                  'over': {'startTime': stamp(-30), 'endTime': stamp(-2), 'maintenanceExclusionOptions': {'scope': 'NO_UPGRADES'}},
                  'patches-only': {'startTime': stamp(-1), 'endTime': stamp(20)},  # no options: the default scope, NO_UPGRADES
                  'broken': {'startTime': stamp(-1)}}
    cluster = production_cluster(maintenancePolicy={'window': {'maintenanceExclusions': exclusions}})
    assert [(name, scope, end.date().isoformat()) for name, scope, end in ops.active_exclusions(cluster, NOW)] == [
        ('freeze', 'NO_MINOR_OR_NODE_UPGRADES', '2026-11-20'), ('patches-only', 'NO_UPGRADES', '2026-11-27')]


def test_notification_gap():
    assert ops.notification_gap(production_cluster()) == 'off'  # pubsub: {}
    assert ops.notification_gap(production_cluster(notificationConfig={})) == 'off'
    assert ops.notification_gap(ready_cluster()) is None  # enabled, no filter: everything
    filtered = ready_cluster(notificationConfig={'pubsub': {'enabled': True, 'topic': 't', 'filter': {'eventType': ['UPGRADE_AVAILABLE_EVENT']}}})
    assert ops.notification_gap(filtered) == ['UPGRADE_EVENT', 'SECURITY_BULLETIN_EVENT']
    full = ready_cluster(notificationConfig={'pubsub': {'enabled': True, 'topic': 't', 'filter': {'eventType': ['UPGRADE_EVENT', 'SECURITY_BULLETIN_EVENT']}}})
    assert ops.notification_gap(full) is None


def test_surge_and_version_skew():
    assert ops.surge_issue({'upgradeSettings': {'maxSurge': 1, 'strategy': 'SURGE'}}) is None
    assert ops.surge_issue({'upgradeSettings': {'maxSurge': 0, 'maxUnavailable': 2}}) == (0, 2)  # strategy absent = SURGE
    assert ops.surge_issue({'upgradeSettings': {'strategy': 'BLUE_GREEN', 'maxUnavailable': 1}}) is None
    assert ops.surge_issue({}) is None
    assert ops.version_minor('1.32.13-gke.2662000') == (1, 32) and ops.version_minor('v1') is None and ops.version_minor('') is None
    assert ops.minors_behind('1.30.5-gke.1014001', '1.32.13-gke.2662000') == 2
    assert ops.minors_behind('1.32.1-gke.1', '1.32.13-gke.2662000') == 0
    assert ops.minors_behind('1.33.0-gke.1', '1.32.13-gke.2662000') == 0  # ahead: never
    assert ops.minors_behind(None, '1.32.13-gke.2662000') == 0


def test_upgrade_readiness_rows_of_the_production_cluster_and_of_a_ready_one():
    rows = ops.upgrade_readiness_rows(fact(production_cluster()), NOW)
    assert [(r['Node Pool'], r['Issue'], r['_status']) for r in rows] == [
        ('(cluster)', 'No maintenance window.', IR), ('(cluster)', 'Upgrade notifications off.', IR)]
    assert rows[0]['Fix'].startswith('gcloud container clusters update cluster-stark --location=asia-south1 --project=p1 --maintenance-window-start=')
    assert '--notification-config=pubsub=ENABLED,pubsub-topic=projects/p1/topics/gke-notifications' in rows[1]['Fix']
    assert ops.upgrade_readiness_rows(fact(ready_cluster()), NOW) == []


def test_upgrade_readiness_rows_pools_exclusions_and_autopilot():
    pools = [{'name': 'a', 'version': '1.30.5-gke.1', 'management': {'autoUpgrade': False}, 'upgradeSettings': {'maxSurge': 0, 'maxUnavailable': 1}},
             {'name': 'b', 'version': '1.30.5-gke.1', 'management': {'autoUpgrade': True}, 'upgradeSettings': {'strategy': 'BLUE_GREEN'}},
             {'name': 'c', 'version': '1.32.13-gke.2662000', 'management': {'autoUpgrade': True}}]
    exclusion = {'window': {'recurringWindow': {'window': {'startTime': '2026-01-03T18:00:00Z', 'endTime': '2026-01-03T22:00:00Z'}, 'recurrence': 'FREQ=WEEKLY;BYDAY=SA'},
                            'maintenanceExclusions': {'freeze': {'startTime': stamp(-1), 'endTime': stamp(13), 'maintenanceExclusionOptions': {'scope': 'NO_MINOR_OR_NODE_UPGRADES'}}}}}
    cluster = ready_cluster(nodePools=pools, maintenancePolicy=exclusion)
    rows = ops.upgrade_readiness_rows(fact(cluster), NOW)
    assert [(r['Node Pool'], r['Issue'], r['_status']) for r in rows] == [
        ('(cluster)', 'Maintenance exclusion freeze in force.', INFO),
        ('a', 'Capacity drops during upgrades.', IR), ('a', 'Node pool 2 minors behind the control plane.', IR),
        ('b', 'Node pool 2 minors behind the control plane.', INFO)]
    assert rows[0]['Detail'] == 'no minor or node upgrades until 2026-11-20: upgrades resume then.' and rows[0]['Fix'] == ''
    assert rows[1]['Fix'] == 'gcloud container node-pools update a --cluster=cluster-stark --location=asia-south1 --project=p1 --max-surge-upgrade=1 --max-unavailable-upgrade=0'
    assert rows[2]['Detail'].endswith('auto-upgrade is off, so the control plane cannot take its next minor until the pool moves.')
    assert rows[2]['Fix'] == 'gcloud container clusters upgrade cluster-stark --node-pool=a --cluster-version=1.32.13-gke.2662000 --location=asia-south1 --project=p1'
    assert rows[3]['Detail'].endswith('GKE will upgrade it in the next window (expect node recreation).')
    # Autopilot: the cluster rows, never the pool rows.
    auto = ops.upgrade_readiness_rows(fact(production_cluster(autopilot={'enabled': True}, nodePools=pools)), NOW)
    assert [r['Issue'] for r in auto] == ['No maintenance window.', 'Upgrade notifications off.']


# --- PodDisruptionBudgets ------------------------------------------------------------------------------------------

def test_pdb_facts_from_the_asset_name_and_a_zonal_cluster():
    facts = ops.pdb_facts(pdb_asset('payments', 'api-pdb', {'maxUnavailable': 0}, {'disruptionsAllowed': 0, 'expectedPods': 2}))
    assert (facts['project_id'], facts['location'], facts['cluster'], facts['namespace'], facts['name']) == ('p1', 'asia-south1', 'cluster-stark', 'payments', 'api-pdb')
    zonal = pdb_asset('web', 'x', {}, location='us-central1-a')
    zonal.name = zonal.name.replace('/locations/', '/zones/')
    assert ops.pdb_facts(zonal)['location'] == 'us-central1-a'
    assert ops.pdb_facts(SimpleNamespace(name='', resource=None)) == {'project_id': '', 'location': '', 'cluster': '', 'namespace': '', 'name': '', 'spec': {}, 'status': {}}


def test_pdb_assessment_spec_forms_and_status():
    unsatisfiable = 'No pod of this workload may ever be evicted: node drains stall (GKE waits up to an hour per node), scale-down never happens.'
    assert ops.pdb_assessment({'maxUnavailable': 0}, {}) == (AR, unsatisfiable)
    assert ops.pdb_assessment({'maxUnavailable': '0%'}, {'disruptionsAllowed': 0, 'expectedPods': 3}) == (AR, unsatisfiable)
    assert ops.pdb_assessment({'minAvailable': '100%'}, {}) == (AR, unsatisfiable)
    assert ops.pdb_assessment({'minAvailable': 3}, {'disruptionsAllowed': 0, 'currentHealthy': 3, 'expectedPods': 3}) == (
        AR, 'The budget keeps 3 of 3 pods: none may be evicted until the workload runs more replicas.')
    assert ops.pdb_assessment({'minAvailable': 2}, {'disruptionsAllowed': 0, 'currentHealthy': 2, 'expectedPods': 3}) == (
        IR, 'Allows no disruption right now: 2 of 3 pods healthy, a drain would block today.')
    assert ops.pdb_assessment({'minAvailable': 2}, {}) == (None, '')  # no status: an absolute minimum cannot be judged
    assert ops.pdb_assessment({'maxUnavailable': 1}, {'disruptionsAllowed': 1, 'expectedPods': 2}) == (None, '')
    assert ops.pdb_assessment({'maxUnavailable': '25%'}, {'disruptionsAllowed': 0, 'expectedPods': 0}) == (None, '')  # nothing scheduled: nothing to drain


def test_pdb_numbers_arrive_as_struct_floats_from_asset_inventory():
    """The inventory delivers Kubernetes numbers as protobuf Struct floats (``0.0``, ``2.0``): the first canary read none of the budgets."""
    status = {'disruptionsAllowed': 0.0, 'currentHealthy': 1.0, 'desiredHealthy': 1.0, 'expectedPods': 1.0, 'observedGeneration': 1.0}
    assert ops.pdb_assessment({'maxUnavailable': 0.0}, status)[0] == AR
    assert ops.pdb_assessment({'minAvailable': 2.0}, {'disruptionsAllowed': 0.0, 'currentHealthy': 2.0, 'expectedPods': 3.0}) == (
        IR, 'Allows no disruption right now: 2 of 3 pods healthy, a drain would block today.')
    assert ops.pdb_assessment({'minAvailable': 3.0}, {'disruptionsAllowed': 0.0, 'currentHealthy': 3.0, 'expectedPods': 3.0})[1] == \
        'The budget keeps 3 of 3 pods: none may be evicted until the workload runs more replicas.'
    assert ops.pdb_assessment({'maxUnavailable': 1.0}, {'disruptionsAllowed': 1.0, 'expectedPods': 2.0}) == (None, '')
    rows = ops.pdb_rows([pdb_asset('payments', 'api-pdb', {'maxUnavailable': 0.0}, status)])
    assert rows[0]['Detail'].startswith('maxUnavailable: 0 · disruptions allowed 0 · 1 of 1 pods healthy: ')
    assert ops.pdb_budget({'maxUnavailable': '25%'}) == 'maxUnavailable: 25%' and ops.pdb_budget({'minAvailable': 2.0}) == 'minAvailable: 2'


def test_pdb_rows_skip_the_system_namespaces_and_carry_the_fix():
    assets = [pdb_asset('kube-system', 'kube-dns-pdb', {'maxUnavailable': 0}, {'disruptionsAllowed': 0, 'expectedPods': 2}),
              pdb_asset('gmp-system', 'collector', {'maxUnavailable': 0}),
              pdb_asset('payments', 'api-pdb', {'maxUnavailable': 0}, {'disruptionsAllowed': 0, 'currentHealthy': 2, 'expectedPods': 2}),
              pdb_asset('web', 'frontend-pdb', {'minAvailable': 2}, {'disruptionsAllowed': 0, 'currentHealthy': 2, 'expectedPods': 3}),
              pdb_asset('web', 'worker-pdb', {'maxUnavailable': '25%'}, {'disruptionsAllowed': 1, 'expectedPods': 4})]
    rows = ops.pdb_rows(assets)
    # The same seven columns as the cluster rows (one table, one CSV header): the budget's identity in Node Pool, its spec and status in Detail.
    assert [(r['Node Pool'], r['Issue'], r['_status']) for r in rows] == [
        ('payments/api-pdb', 'PodDisruptionBudget can never be satisfied.', AR), ('web/frontend-pdb', 'PodDisruptionBudget allows no disruption right now.', IR)]
    assert rows[0]['Detail'] == ('maxUnavailable: 0 · disruptions allowed 0 · 2 of 2 pods healthy: No pod of this workload may ever be evicted: '
                                 'node drains stall (GKE waits up to an hour per node), scale-down never happens.')
    assert rows[1]['Detail'] == 'minAvailable: 2 · disruptions allowed 0 · 2 of 3 pods healthy: Allows no disruption right now: 2 of 3 pods healthy, a drain would block today.'
    assert rows[0]['Fix'] == 'kubectl -n payments edit pdb api-pdb  # maxUnavailable: 1, or run more replicas than the budget protects'
    assert (rows[0]['Project'], rows[0]['Cluster'], rows[0]['Location']) == ('p1', 'cluster-stark', 'asia-south1')
    assert {tuple(sorted(r)) for r in rows} == {tuple(sorted(ops.upgrade_readiness_rows(fact(production_cluster()), NOW)[0]))}  # one shape
    assert ops.is_system_namespace('config-management-system') and not ops.is_system_namespace('payments')


# --- observability -------------------------------------------------------------------------------------------------

def test_observability_issues():
    assert [(s, st) for s, _, _, st in ops.observability_issues(production_cluster())] == [('Control-plane metrics', IR)]
    assert ops.observability_issues(ready_cluster()) == []
    bare = production_cluster(monitoringConfig={'componentConfig': {'enableComponents': []}, 'managedPrometheusConfig': {}}, addonsConfig={})
    issues = ops.observability_issues(bare)
    assert [(s, st) for s, _, _, st in issues] == [('System metrics', AR), ('Control-plane metrics', IR), ('Managed Service for Prometheus', IR), ('NodeLocal DNSCache', IR)]
    assert issues[0][2] == '--monitoring=SYSTEM,API_SERVER,SCHEDULER,CONTROLLER_MANAGER'
    # The fix keeps what is on; the legacy monitoringService field is read when the new config is absent.
    assert ops.gcloud_monitoring({'SYSTEM_COMPONENTS', 'POD', 'HPA'}) == '--monitoring=SYSTEM,API_SERVER,SCHEDULER,CONTROLLER_MANAGER,HPA,POD'
    legacy_off = production_cluster(monitoringConfig={}, monitoringService='none')
    legacy_on = production_cluster(monitoringConfig={}, monitoringService='monitoring.googleapis.com/kubernetes')
    assert ops.monitoring_components(legacy_off) == set() and ops.monitoring_components(legacy_on) == {'SYSTEM_COMPONENTS'}
    # Autopilot: Managed Prometheus and the DNS cache are Google's.
    auto = ops.observability_issues(production_cluster(autopilot={'enabled': True}, monitoringConfig={'componentConfig': {'enableComponents': ['SYSTEM_COMPONENTS']}}, addonsConfig={}))
    assert [s for s, _, _, _ in auto] == ['Control-plane metrics']


def test_worst_status_knows_informational():
    assert ops.worst_status([]) == C
    assert ops.worst_status([{'_status': INFO}]) == INFO
    assert ops.worst_status([{'_status': INFO}, {'_status': IR}]) == IR
    assert ops.worst_status([{'_status': IR}, {'_status': AR}, {'_status': INFO}]) == AR


# --- the check end to end ------------------------------------------------------------------------------------------

def cluster_asset(data, project='p1'):
    return SimpleNamespace(name=f'//container.googleapis.com/projects/{project}/locations/{data["location"]}/clusters/{data["name"]}',
                           resource=SimpleNamespace(data=data, parent='//cloudresourcemanager.googleapis.com/projects/111'), ancestors=['projects/111'])


class FakeContainer:
    """``container.projects().locations().clusters().list(parent=...).execute()``: fresh clusters per project, or an error."""
    def __init__(self, by_project=None, error=None):
        self.by_project, self.error, self.parents = by_project or {}, error, []

    def projects(self):
        return self

    def locations(self):
        return self

    def clusters(self):
        return self

    def list(self, parent):
        self.parents.append(parent)
        if self.error:
            raise self.error
        return SimpleNamespace(execute=lambda: {"clusters": self.by_project.get(parent.split("/")[1], [])})


def test_the_check_writes_both_records_from_two_listings(gcp, monkeypatch):
    listings = []
    monkeypatch.setattr(ops.gcp, 'api_build', lambda *args, **kwargs: FakeContainer({'p1': [production_cluster()]}))

    class Assets:
        def list_assets(self, request):
            listings.append((request['parent'], tuple(request['asset_types'])))
            if request['asset_types'] == ['container.googleapis.com/Cluster']:
                return [cluster_asset(production_cluster()), cluster_asset(ready_cluster(name='ready', status='STOPPING'))]
            return [pdb_asset('payments', 'api-pdb', {'maxUnavailable': 0}, {'disruptionsAllowed': 0, 'expectedPods': 2}),
                    pdb_asset('kube-system', 'kube-dns-pdb', {'maxUnavailable': 0})]
    monkeypatch.setattr(ops.gcp, 'asset_client', lambda credentials=None: Assets())
    sink = Sink()
    ops.check_gke_operations('organization', '987654321', JOB, sink=sink, now=NOW)
    assert listings == [('organizations/987654321', ('container.googleapis.com/Cluster',)), ('organizations/987654321', ('policy.k8s.io/PodDisruptionBudget',))]
    records = sink.by_check()
    readiness = records['GKE Upgrade Readiness']
    assert readiness['Status'] == AR and [(r['Cluster'], r['Issue'][:23]) for r in readiness['Finding']] == [
        ('cluster-stark', 'No maintenance window.'), ('cluster-stark', 'Upgrade notifications o'), ('cluster-stark', 'PodDisruptionBudget can')]
    assert all('_status' not in r for r in readiness['Finding']) and 'Fix' in readiness['Finding'][2]
    observability = records['GKE Observability']
    assert observability['Status'] == IR and [(r['Signal'], r['State'][:3]) for r in observability['Finding']] == [('Control-plane metrics', 'off')]
    assert sink.not_checked() == []


def test_the_fresh_cluster_state_comes_from_the_gke_api(gcp, monkeypatch):
    """The inventory's copy of a cluster can lag a maintenance-policy change by hours: the GKE API's listing wins, per project;
    a project whose listing fails keeps the inventory copy and is noted."""
    class Assets:
        def list_assets(self, request):
            if request['asset_types'] == ['container.googleapis.com/Cluster']:
                return [cluster_asset(production_cluster()), cluster_asset(production_cluster(name='other'), project='p2')]
            return []
    monkeypatch.setattr(ops.gcp, 'asset_client', lambda credentials=None: Assets())
    container = FakeContainer({'p1': [ready_cluster()], 'p2': []})  # p1: the window and the notifications were set since the inventory looked
    monkeypatch.setattr(ops.gcp, 'api_build', lambda *args, **kwargs: container)
    sink = Sink()
    ops.check_gke_operations('organization', '987654321', JOB, sink=sink, now=NOW)
    assert sorted(container.parents) == ['projects/p1/locations/-', 'projects/p2/locations/-']
    rows = sink.by_check()['GKE Upgrade Readiness']['Finding']
    assert [(r['Cluster'], r['Issue']) for r in rows] == [('other', 'No maintenance window.'), ('other', 'Upgrade notifications off.')]  # p1 is clean now; p2's copy stands
    assert sink.not_checked() == []
    monkeypatch.setattr(ops.gcp, 'api_build', lambda *args, **kwargs: FakeContainer(error=RuntimeError('403 container.clusters.list denied')))
    sink = Sink()
    ops.check_gke_operations('organization', '987654321', JOB, sink=sink, now=NOW)
    assert len(sink.by_check()['GKE Upgrade Readiness']['Finding']) == 4  # the inventory copies of both clusters
    assert [(r['Project'], r['Skipped check'].split(' (')[0]) for r in sink.not_checked()] == [('p1', 'GKE Upgrade Readiness'), ('p2', 'GKE Upgrade Readiness')]
    assert 'inventory copy' in sink.not_checked()[0]['Skipped check']


def test_the_check_without_clusters_and_with_a_failed_budget_listing(gcp, monkeypatch):
    monkeypatch.setattr(ops.gcp, 'api_build', lambda *args, **kwargs: FakeContainer())

    class Empty:
        def list_assets(self, request):
            return []
    monkeypatch.setattr(ops.gcp, 'asset_client', lambda credentials=None: Empty())
    sink = Sink()
    ops.check_gke_operations('project', 'p1', JOB, sink=sink, now=NOW)
    records = sink.by_check()
    assert records['GKE Upgrade Readiness'] == {'Check': 'GKE Upgrade Readiness', 'Finding': [{'Status': ops.UPGRADE_ALL_CLEAR}], 'Status': C}
    assert records['GKE Observability']['Status'] == C

    class Flaky:
        def list_assets(self, request):
            if request['asset_types'] == ['policy.k8s.io/PodDisruptionBudget']:
                raise RuntimeError('403 the inventory may not be read')
            return [cluster_asset(ready_cluster())]
    monkeypatch.setattr(ops.gcp, 'asset_client', lambda credentials=None: Flaky())
    sink = Sink()
    ops.check_gke_operations('folder', '42', JOB, sink=sink, now=NOW)
    assert sink.by_check()['GKE Upgrade Readiness']['Status'] == C  # the cluster rows stand
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [('folders/42', 'GKE Upgrade Readiness (PodDisruptionBudgets (the drain rule could not be applied))')]

    class Down:
        def list_assets(self, request):
            raise RuntimeError('503 inventory unavailable')
    monkeypatch.setattr(ops.gcp, 'asset_client', lambda credentials=None: Down())
    sink = Sink()
    ops.check_gke_operations('organization', '1', JOB, sink=sink, now=NOW)
    assert {name: record['Status'] for name, record in sink.by_check().items()} == {'GKE Upgrade Readiness': 'Error', 'GKE Observability': 'Error'}


# --- the hardening additions draw their line at 18.2 ---------------------------------------------------------------

def test_hardening_additions_and_the_rule_changed_line():
    cluster = production_cluster(networkConfig={'enableIntraNodeVisibility': False}, shieldedNodes={'enabled': True}, privateClusterConfig={'enablePrivateNodes': True},
                                 binaryAuthorization={'enabled': True}, securityPostureConfig={'mode': 'BASIC', 'vulnerabilityMode': 'VULNERABILITY_BASIC'},
                                 databaseEncryption={'state': 'ENCRYPTED'}, networkPolicy={'enabled': True})
    cluster['nodePools'][0]['config']['imageType'] = 'COS_CONTAINERD'
    assert [(p, i) for p, i, _ in hardening_issues(cluster)] == [
        ('', 'Intra-node visibility off: pod-to-pod traffic on one node is invisible to VPC flow logs and firewall rules.')]
    assert RESHAPED_CHECKS['GKE Node Hardening'] == ('18.2', RULE_CHANGED)
    assert 'GKE Upgrade Readiness' not in RESHAPED_CHECKS and 'GKE Observability' not in RESHAPED_CHECKS  # new checks: "new check" by the existing rule
