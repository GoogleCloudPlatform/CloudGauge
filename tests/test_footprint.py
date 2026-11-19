"""
v19.1 — Platform Footprint: the lines of ``app.checks.footprint`` from fixture search results (projects, regions, enabled APIs, the product
families, versions, Other), and the briefing end to end with its failure paths.
"""
from types import SimpleNamespace

from google.cloud import asset_v1

from app.checks import footprint
from app.checks.footprint import (FAMILIES, FAMILY_OF, FOOTPRINT_CHECK, LEAD_OF, PROJECT_TYPE, SERVICE_TYPE, VERSIONED_TYPES, asset_facts, check_platform_footprint, family_of, footprint_rows,
                                  label_of, project_names, singular, versions_of)
from app.checks.not_checked import NOT_CHECKED
from fakes import ORG_ID as ORG

JOB = 'job-192'
P1, N1, P2, N2 = 'stark-web-prod', '111111111111', 'stark-data', '222222222222'
PARENT = f'organizations/{ORG}'


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_check(self):
        return {record['Check']: record for _, record in self.records if record['Check'] != NOT_CHECKED}


def result(asset_type, name, location='asia-south1', project=N1, state='', versioned=None):
    return SimpleNamespace(asset_type=asset_type, name=name, location=location, project=f'projects/{project}' if project else '', state=state,
                           versioned_resources=[{'version': 'v1', 'resource': versioned}] if versioned is not None else [])


def project(project_id, number):
    return result(PROJECT_TYPE, f'//cloudresourcemanager.googleapis.com/projects/{project_id}', location='global', project=number, state='ACTIVE')


def service(name, project=N1):
    return result(SERVICE_TYPE, f'//serviceusage.googleapis.com/projects/{project}/services/{name}', location='global', project=project, state='ENABLED')


def inventory():
    return [project(P1, N1), project(P2, N2),
            result('compute.googleapis.com/Instance', f'//compute.googleapis.com/projects/{P1}/zones/asia-south1-b/instances/web-1', 'asia-south1-b'),
            result('compute.googleapis.com/Instance', f'//compute.googleapis.com/projects/{P1}/zones/asia-south1-b/instances/web-2', 'asia-south1-b'),
            result('compute.googleapis.com/Disk', f'//compute.googleapis.com/projects/{P1}/zones/asia-south1-b/disks/web-1', 'asia-south1-b'),
            result('container.googleapis.com/Cluster', f'//container.googleapis.com/projects/{P1}/locations/asia-south1/clusters/prod'),
            result('run.googleapis.com/Service', f'//run.googleapis.com/projects/{P1}/locations/asia-south1/services/api'),
            result('sqladmin.googleapis.com/Instance', f'//cloudsql.googleapis.com/projects/{P2}/instances/orders-db', 'us-central1', N2),
            result('storage.googleapis.com/Bucket', f'//storage.googleapis.com/orders-archive', 'us', N2),
            result('bigquery.googleapis.com/Dataset', f'//bigquery.googleapis.com/projects/{P2}/datasets/sales', 'US', N2),
            result('bigquery.googleapis.com/Table', f'//bigquery.googleapis.com/projects/{P2}/datasets/sales/tables/orders', 'US', N2),
            result('iam.googleapis.com/ServiceAccount', f'//iam.googleapis.com/projects/{P1}/serviceAccounts/1', 'global'),
            result('osconfig.googleapis.com/PatchDeployment', f'//osconfig.googleapis.com/projects/{P1}/patchDeployments/weekly', 'global'),
            result('cloudbilling.googleapis.com/ProjectBillingInfo', f'//cloudbilling.googleapis.com/projects/{P2}/billingInfo', 'global', N2),
            result('rbac.authorization.k8s.io/ClusterRole', f'//container.googleapis.com/projects/{P1}/locations/asia-south1/clusters/prod/k8s/clusterroles/admin'),
            result('rbac.authorization.k8s.io/ClusterRole', f'//container.googleapis.com/projects/{P1}/locations/asia-south1/clusters/prod/k8s/clusterroles/view'),
            result('k8s.io/Pod', f'//container.googleapis.com/projects/{P1}/locations/asia-south1/clusters/prod/k8s/namespaces/default/pods/web-0'),
            result('cloudresourcemanager.googleapis.com/Organization', f'//cloudresourcemanager.googleapis.com/organizations/{ORG}', 'global', project=None)]


def contents():
    return [result('container.googleapis.com/Cluster', f'//container.googleapis.com/projects/{P1}/locations/asia-south1/clusters/prod',
                   versioned={'currentMasterVersion': '1.32.13-gke.2701000', 'releaseChannel': {'channel': 'EXTENDED'}, 'currentNodeCount': 2.0}),
            result('sqladmin.googleapis.com/Instance', f'//cloudsql.googleapis.com/projects/{P2}/instances/orders-db', 'us-central1', N2, versioned={'databaseVersion': 'POSTGRES_15', 'settings': {'tier': 'db-custom-2-7680'}}),
            result('compute.googleapis.com/Instance', f'//compute.googleapis.com/projects/{P1}/zones/asia-south1-b/instances/web-1', 'asia-south1-b',
                   versioned={'machineType': 'https://www.googleapis.com/compute/v1/projects/x/zones/asia-south1-b/machineTypes/e2-medium', 'status': 'RUNNING'}),
            result('compute.googleapis.com/Instance', f'//compute.googleapis.com/projects/{P1}/zones/asia-south1-b/instances/web-2', 'asia-south1-b',
                   versioned={'machineType': 'https://www.googleapis.com/compute/v1/projects/x/zones/asia-south1-b/machineTypes/n2-standard-4', 'status': 'TERMINATED'}),
            result('compute.googleapis.com/Instance', f'//compute.googleapis.com/projects/{P1}/zones/asia-south1-b/instances/no-content', 'asia-south1-b')]


def services():
    return [service('compute.googleapis.com'), service('compute.googleapis.com', N2), service('container.googleapis.com'), service('bigquery.googleapis.com', N2), service('logging.googleapis.com'),
            service('logging.googleapis.com', N2)]


def lines(rows):
    return {row['Line']: row for row in rows}


def test_family_map_is_consistent_and_covers_the_versioned_types():
    assert all(asset_type in FAMILY_OF for asset_type in VERSIONED_TYPES)
    assert [singular(x) for x in ('disks', 'policies', 'addresses', 'node pools', 'functions (gen 1)', 'MIGs')] == ['disk', 'policy', 'address', 'node pool', 'functions (gen 1)', 'MIG']
    assert LEAD_OF['Compute Engine'] == 'compute.googleapis.com/Instance' and LEAD_OF['Cloud Run'] == 'run.googleapis.com/Service' and LEAD_OF['GKE'] == 'container.googleapis.com/Cluster'
    assert family_of('k8s.io/Pod') == 'Kubernetes objects' and family_of('rbac.authorization.k8s.io/ClusterRoleBinding') == 'Kubernetes objects' and family_of('dataplex.googleapis.com/EntryGroup') == 'Other'
    assert family_of('notk8s.io/Thing') == 'Other'  # v20: the group is k8s.io or one of its subdomains, not any name ending in those letters
    assert [label_of(t) for t in ('k8s.io/Pod', 'rbac.authorization.k8s.io/ClusterRoleBinding', 'networking.k8s.io/Ingress', 'networking.k8s.io/NetworkPolicy', 'k8s.io/Endpoints', 'compute.googleapis.com/Disk')] == [
        'Pods', 'ClusterRoleBindings', 'Ingresses', 'NetworkPolicies', 'Endpoints', 'disks']
    assert len(FAMILY_OF) == sum(len(types) for types in FAMILIES.values())  # no type in two families
    assert FAMILY_OF['compute.googleapis.com/Instance'] == 'Compute Engine' and FAMILY_OF['run.googleapis.com/Service'] == 'Cloud Run' and FAMILY_OF['sqladmin.googleapis.com/Instance'] == 'Databases'


def test_asset_facts_project_names_and_versions():
    facts = asset_facts(inventory())
    assert facts[2] == {'type': 'compute.googleapis.com/Instance', 'name': f'//compute.googleapis.com/projects/{P1}/zones/asia-south1-b/instances/web-1', 'location': 'asia-south1-b', 'project': f'projects/{N1}', 'state': ''}
    assert asset_facts([SimpleNamespace(asset_type='x', name='y', location='', project='', state='')])[0]['location'] == '—'
    assert project_names(facts) == {f'projects/{N1}': P1, f'projects/{N2}': P2}
    versions = versions_of(contents())
    assert versions['container.googleapis.com/Cluster'] == [('prod', '1.32.13-gke.2701000 (extended channel, Standard, 2 nodes)')]
    assert versions['sqladmin.googleapis.com/Instance'] == [('orders-db', 'POSTGRES_15 db-custom-2-7680')]
    assert versions['compute.googleapis.com/Instance'] == [('web-1', 'e2-medium running'), ('web-2', 'n2-standard-4 terminated')]  # the result without content is skipped
    autopilot = asset_v1.ResourceSearchResult(name='//container.googleapis.com/projects/p/locations/l/clusters/ap', asset_type='container.googleapis.com/Cluster',
                                              versioned_resources=[asset_v1.VersionedResource(version='v1', resource={'currentMasterVersion': '1.33.1-gke.1', 'autopilot': {'enabled': True}})])
    assert versions_of([autopilot]) == {'container.googleapis.com/Cluster': [('ap', '1.33.1-gke.1 (no channel channel, Autopilot, 0 nodes)')]}  # the proto shape of the real client
    redis = result('redis.googleapis.com/Instance', '//redis.googleapis.com/projects/p/locations/l/instances/cache', versioned={'redisVersion': 'REDIS_7_0', 'tier': 'STANDARD_HA', 'memorySizeGb': 5})
    spanner = result('spanner.googleapis.com/Instance', '//spanner.googleapis.com/projects/p/instances/ledger', versioned={'config': 'projects/p/instanceConfigs/regional-asia-south1', 'processingUnits': 100})
    assert versions_of([redis, spanner]) == {'redis.googleapis.com/Instance': [('cache', 'REDIS_7_0 STANDARD_HA 5 GB')], 'spanner.googleapis.com/Instance': [('ledger', 'regional-asia-south1 100')]}


def test_footprint_rows_write_the_projects_regions_apis_families_and_other():
    rows = footprint_rows(PARENT, asset_facts(inventory()), contents(), services())
    by_line = lines(rows)
    assert list(by_line) == ['Projects', 'Regions', 'Enabled APIs', 'Compute Engine', 'GKE', 'Cloud Run', 'Databases', 'Storage', 'BigQuery', 'Identity and secrets', 'Kubernetes objects', 'Other']
    assert by_line['Projects']['Value'] == '2 projects' and by_line['Projects']['Detail'] == f'{P2}, {P1}.'
    assert by_line['Projects']['Fix'] == f"gcloud asset search-all-resources --scope={PARENT} --asset-types={PROJECT_TYPE} --format='table(name,assetType,location,project)'"
    regions = by_line['Regions']
    assert regions['Value'] == '6 locations' and regions['Detail'].startswith('asia-south1 — 5 (Kubernetes objects, GKE, Cloud Run); asia-south1-b — 3 (Compute Engine); ') and 'US — 2 (BigQuery)' in regions['Detail']
    apis = by_line['Enabled APIs']
    assert apis['Value'] == '4 distinct services' and apis['Detail'].startswith(f'{P1}: 3; {P2}: 3. On in every project: compute.googleapis.com, logging.googleapis.com. On in one project only: bigquery.googleapis.com, container.googleapis.com.')
    compute = by_line['Compute Engine']
    assert compute['Value'] == '2 VMs, 3 resources' and compute['Detail'] == f'2 VMs (1 running, 1 terminated; e2, n2 families); 1 disk. Locations: asia-south1-b ×3. Projects: {P1} ×3.'
    assert compute['Fix'].endswith("--asset-types=compute.googleapis.com/Instance,compute.googleapis.com/Disk --format='table(name,assetType,location,project)'")
    assert by_line['GKE']['Detail'] == f'1 cluster. Locations: asia-south1. Projects: {P1}. Clusters: prod — 1.32.13-gke.2701000 (extended channel, Standard, 2 nodes).'
    assert by_line['Databases']['Detail'] == f'1 Cloud SQL instance. Locations: us-central1. Projects: {P2}. Cloud SQL instances: orders-db — POSTGRES_15 db-custom-2-7680.'
    assert by_line['BigQuery']['Value'] == '1 dataset, 2 resources' and by_line['Storage']['Value'] == '1 bucket' and by_line['GKE']['Value'] == '1 cluster' and by_line['Cloud Run']['Detail'].startswith('1 service.')
    kubernetes = by_line['Kubernetes objects']
    assert kubernetes['Value'] == '3 resources' and kubernetes['Detail'] == f'2 ClusterRoles; 1 Pod. Locations: asia-south1 ×3. Projects: {P1} ×3.'
    assert kubernetes['Fix'].endswith("--asset-types=k8s.io/Pod,rbac.authorization.k8s.io/ClusterRole --format='table(name,assetType,location,project)'")
    many = asset_facts([project(P1, N1)] + [result(f'k8s.io/Kind{i}', f'//container.googleapis.com/projects/{P1}/locations/l/clusters/c/k8s/kind{i}/x') for i in range(14)])
    assert lines(footprint_rows(PARENT, many))['Kubernetes objects']['Detail'].startswith('1 Kind0; 1 Kind1; ') and '; +2 more types. Locations:' in lines(footprint_rows(PARENT, many))['Kubernetes objects']['Detail']
    other = by_line['Other']
    assert other['Value'] == '2 resources of 2 types' and other['Detail'] == 'Largest: PatchDeployment (osconfig), ProjectBillingInfo (cloudbilling).' and other['Fix'] == f"gcloud asset search-all-resources --scope={PARENT} --format='table(name,assetType,location,project)'"
    assert all(set(row) == {'Line', 'Value', 'Detail', 'Fix'} for row in rows) and all(row['Fix'].startswith('gcloud asset search-all-resources --scope=') for row in rows)


def test_footprint_rows_lead_with_the_familys_own_type():
    facts = asset_facts([project(P1, N1)] + [result('run.googleapis.com/Revision', f'//run.googleapis.com/projects/{P1}/locations/asia-south1/revisions/api-{i}') for i in range(5)]
                        + [result('run.googleapis.com/Service', f'//run.googleapis.com/projects/{P1}/locations/asia-south1/services/api')]
                        + [result('compute.googleapis.com/Snapshot', f'//compute.googleapis.com/projects/{P1}/global/snapshots/s{i}', 'asia') for i in range(3)]
                        + [result('compute.googleapis.com/Instance', f'//compute.googleapis.com/projects/{P1}/zones/asia-south1-b/instances/web-1', 'asia-south1-b')])
    by_line = lines(footprint_rows(PARENT, facts, contents()[2:3]))  # web-1's content alone
    assert by_line['Cloud Run']['Value'] == '1 service, 6 resources' and by_line['Cloud Run']['Detail'].startswith('1 service; 5 revisions. ')
    assert by_line['Compute Engine']['Value'] == '1 VM, 4 resources' and by_line['Compute Engine']['Detail'].startswith('1 VM (1 running; e2 families); 3 snapshots. ')  # the states on the VM part, whatever leads


def test_footprint_rows_on_an_empty_scope_and_without_the_bonus_searches():
    rows = footprint_rows('projects/empty', [])
    assert [(r['Line'], r['Value'], r['Detail']) for r in rows] == [('Projects', '0 projects', 'No project in scope.'), ('Regions', '0 locations', 'Nothing indexed.')]
    rows = footprint_rows(PARENT, asset_facts(inventory()))  # no content, no services: counts only, no versions, no API line
    by_line = lines(rows)
    assert 'Enabled APIs' not in by_line and by_line['Compute Engine']['Detail'] == f'2 VMs; 1 disk. Locations: asia-south1-b ×3. Projects: {P1} ×3.' and 'Clusters:' not in by_line['GKE']['Detail']
    one = footprint_rows(f'projects/{N1}', asset_facts([project(P1, N1)]), services=[service('compute.googleapis.com')])
    assert lines(one)['Enabled APIs']['Detail'] == f'{P1}: 1.' and lines(one)['Projects']['Value'] == '1 project'  # one project: no every/only clauses


def test_check_platform_footprint_end_to_end(gcp, monkeypatch):
    gcp.assets.resources += inventory() + services()
    s = Sink()
    check_platform_footprint('organization', ORG, JOB, sink=s)
    record = s.by_check()[FOOTPRINT_CHECK]
    assert record['Status'] == 'Informational' and [r['Line'] for r in record['Finding']][:3] == ['Projects', 'Regions', 'Enabled APIs'] and len(s.records) == 1
    assert [(r['scope'], r.get('asset_types'), r['read_mask']) for r in gcp.assets.requests] == [
        (PARENT, None, 'name,assetType,location,project,state'), (PARENT, VERSIONED_TYPES, 'name,assetType,location,project,versionedResources'), (PARENT, [SERVICE_TYPE], 'name,project,state')]
    assert lines(record['Finding'])['Enabled APIs']['Value'] == '4 distinct services'
    # The inventory search failing is an Error record; a failed content or service search costs the versions or the API line, not the briefing.
    gcp.assets.error = PermissionError('cloudasset.assets.searchAllResources denied')
    s = Sink()
    check_platform_footprint('project', P1, JOB, sink=s)
    record = s.by_check()[FOOTPRINT_CHECK]
    assert record['Status'] == 'Error' and 'denied' in record['Finding'][0]['Error']
    gcp.assets.error = None

    class Flaky:
        def search_all_resources(self, request):
            if request.get('asset_types'):
                raise RuntimeError('content search down')
            return inventory()

    monkeypatch.setattr(footprint.gcp, 'asset_client', lambda credentials=None: Flaky())
    s = Sink()
    check_platform_footprint('folder', '1061', JOB, sink=s)
    record = s.by_check()[FOOTPRINT_CHECK]
    assert record['Status'] == 'Informational' and 'Enabled APIs' not in lines(record['Finding']) and 'Clusters:' not in lines(record['Finding'])['GKE']['Detail']
    assert lines(record['Finding'])['Projects']['Fix'].startswith('gcloud asset search-all-resources --scope=folders/1061 ')
