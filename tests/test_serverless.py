"""
v18.6 — Serverless and edge exposure, the serverless half: the rules of ``app.checks.serverless`` on fixtures of the shapes Asset
Inventory and the Cloud Run v2 API return (the production services as read in the survey, names changed), and the checks end to end.
"""
from types import SimpleNamespace

from app.checks import registry, serverless as sl
from app.checks.categories import CATEGORY_MAP
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS

JOB = 'job-186'
AR, IR, C = 'Action Required', 'Investigation Recommended', 'Compliant'
PROJECT, NUMBER, REGION = 'stark-run-prod', '208800000000', 'asia-south1'
DEFAULT = f'{NUMBER}-compute@developer.gserviceaccount.com'
DEDICATED = f'web@{PROJECT}.iam.gserviceaccount.com'
COMPUTE = f'https://www.googleapis.com/compute/v1/projects/{PROJECT}'


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


def resource_name(name, kind='services', project=PROJECT, region=REGION, service='run'):
    return f'//{service}.googleapis.com/projects/{project}/locations/{region}/{kind}/{name}'


def service(name, ingress='all', account=DEFAULT, iap=None, no_iam=None, labels=None, project=PROJECT, region=REGION):
    """A Cloud Run service as the inventory shows it (Knative v1: annotations on the metadata, the account in the template)."""
    annotations = {'run.googleapis.com/ingress': ingress, 'run.googleapis.com/ingress-status': ingress}
    if iap is not None:
        annotations['run.googleapis.com/iap-enabled'] = str(iap).lower()
    if no_iam is not None:
        annotations['run.googleapis.com/invoker-iam-disabled'] = str(no_iam).lower()
    data = {'apiVersion': 'serving.knative.dev/v1', 'kind': 'Service',
            'metadata': {'name': name, 'namespace': NUMBER, 'annotations': annotations, 'labels': {'cloud.googleapis.com/location': region, **(labels or {})}},
            'spec': {'template': {'spec': {'serviceAccountName': account, 'containers': [{'image': f'gcr.io/{project}/{name}'}]}}, 'traffic': [{'percent': 100, 'latestRevision': True}]},
            'status': {'url': f'https://{name}-m5pcizyabq-el.a.run.app'}}
    return SimpleNamespace(name=resource_name(name, project=project, region=region), resource=SimpleNamespace(data=data))


def v2_service(name, ingress='INGRESS_TRAFFIC_ALL', account=DEFAULT, iap=None, no_iam=None, labels=None, project=PROJECT, region=REGION):
    """The same service from the v2 API."""
    data = {'name': f'projects/{project}/locations/{region}/services/{name}', 'ingress': ingress, 'template': {'serviceAccount': account}, 'labels': labels or {},
            'uri': f'https://{name}-m5pcizyabq-el.a.run.app'}
    if iap is not None:
        data['iapEnabled'] = iap
    if no_iam is not None:
        data['invokerIamDisabled'] = no_iam
    return data


def run_job(name, account=DEFAULT, project=PROJECT, region=REGION):
    data = {'apiVersion': 'run.googleapis.com/v1', 'kind': 'Job', 'metadata': {'name': name, 'namespace': NUMBER},
            'spec': {'template': {'spec': {'template': {'spec': {'serviceAccountName': account, 'containers': [{'image': 'x'}]}}}}}}
    return SimpleNamespace(name=resource_name(name, 'jobs', project=project, region=region), resource=SimpleNamespace(data=data))


def function_gen1(name, ingress='ALLOW_ALL', account=f'{PROJECT}@appspot.gserviceaccount.com', http=True, project=PROJECT, region=REGION):
    data = {'name': f'projects/{project}/locations/{region}/functions/{name}', 'status': 'ACTIVE', 'ingressSettings': ingress, 'serviceAccountEmail': account, 'runtime': 'python312'}
    data['httpsTrigger' if http else 'eventTrigger'] = {'url': f'https://{region}-{project}.cloudfunctions.net/{name}'} if http else {'eventType': 'google.storage.object.finalize'}
    return SimpleNamespace(name=resource_name(name, 'functions', project=project, region=region, service='cloudfunctions'), resource=SimpleNamespace(data=data))


def function_gen2(name, service_name, project=PROJECT, region=REGION):
    data = {'name': f'projects/{project}/locations/{region}/functions/{name}', 'environment': 'GEN_2', 'state': 'ACTIVE',
            'serviceConfig': {'service': f'projects/{project}/locations/{region}/services/{service_name}', 'serviceAccountEmail': DEFAULT, 'ingressSettings': 'ALLOW_ALL',
                              'uri': f'https://{service_name}-m5pcizyabq-el.a.run.app'}}
    return SimpleNamespace(name=resource_name(name, 'functions', project=project, region=region, service='cloudfunctions'), resource=SimpleNamespace(data=data))


def neg(name, service_name=None, function_name=None, url_mask=None, project=PROJECT, region=REGION):
    data = {'name': name, 'networkEndpointType': 'SERVERLESS', 'selfLink': f'{COMPUTE}/regions/{region}/networkEndpointGroups/{name}', 'region': f'{COMPUTE}/regions/{region}'}
    if service_name:
        data['cloudRun'] = {'service': service_name}
    if url_mask:
        data['cloudRun'] = {'urlMask': url_mask}
    if function_name:
        data['cloudFunction'] = {'function': function_name}
    return SimpleNamespace(name=f'//compute.googleapis.com/projects/{project}/regions/{region}/networkEndpointGroups/{name}', resource=SimpleNamespace(data=data))


def backend_service(name, *neg_names, scheme='EXTERNAL_MANAGED', project=PROJECT, region=REGION):
    data = {'name': name, 'loadBalancingScheme': scheme, 'protocol': 'HTTPS', 'selfLink': f'{COMPUTE}/global/backendServices/{name}',
            'backends': [{'group': f'{COMPUTE}/regions/{region}/networkEndpointGroups/{n}'} for n in neg_names], 'securityPolicy': f'{COMPUTE}/global/securityPolicies/edge'}
    return SimpleNamespace(name=f'//compute.googleapis.com/projects/{project}/global/backendServices/{name}', resource=SimpleNamespace(data=data))


def policy_result(resource, role, members, asset_type='run.googleapis.com/Service'):
    return SimpleNamespace(asset_type=asset_type, resource=resource, policy=SimpleNamespace(bindings=[SimpleNamespace(role=role, members=list(members))]))


def grouped_of(*assets):
    return sl.by_kind(list(assets))


# --- facts -----------------------------------------------------------------------------------------------------------------

def test_service_facts_from_the_inventory_and_from_the_v2_api_agree():
    asset = service('web', ingress='all', iap=True, labels={'goog-managed-by': 'cloudfunctions'})
    fact = sl.service_facts(PROJECT, asset.resource.data, asset.name)
    assert fact == {'kind': sl.FUNCTION_2, 'project_id': PROJECT, 'name': 'web', 'location': REGION, 'resource': resource_name('web'), 'ingress': 'all', 'iap': True,
                    'invoker_iam_disabled': False, 'account': DEFAULT, 'project_number': NUMBER}
    fresh = sl.service_facts(PROJECT, v2_service('web', 'INGRESS_TRAFFIC_ALL', iap=True, labels={'goog-managed-by': 'cloudfunctions'}), f'projects/{PROJECT}/locations/{REGION}/services/web')
    assert {k: v for k, v in fresh.items() if k != 'project_number'} == {k: v for k, v in fact.items() if k != 'project_number'} and fresh['project_number'] == ''
    # The three ingress spellings, the two public settings, an unset account.
    assert sl.service_facts(PROJECT, v2_service('a', 'INGRESS_TRAFFIC_INTERNAL_ONLY', no_iam=True))['ingress'] == 'internal'
    assert sl.service_facts(PROJECT, v2_service('a', 'INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER'))['ingress'] == 'internal-and-cloud-load-balancing'
    assert sl.service_facts(PROJECT, service('b', ingress='internal-and-cloud-load-balancing', no_iam=True).resource.data, resource_name('b'))['invoker_iam_disabled'] is True
    assert sl.service_facts(PROJECT, service('c', account='').resource.data, resource_name('c'))['account'] == '' and sl.ingress_of(None) == 'all'
    job = sl.job_facts(PROJECT, run_job('nightly').resource.data, resource_name('nightly', 'jobs'))
    assert (job['kind'], job['name'], job['location'], job['account'], job['project_number']) == (sl.JOB, 'nightly', REGION, DEFAULT, NUMBER)
    assert sl.job_facts(PROJECT, {'name': f'projects/{PROJECT}/locations/{REGION}/jobs/j2', 'template': {'template': {'serviceAccount': DEDICATED}}})['account'] == DEDICATED
    gen1 = sl.function_facts(PROJECT, function_gen1('hook').resource.data, resource_name('hook', 'functions', service='cloudfunctions'))
    assert (gen1['kind'], gen1['ingress'], gen1['account'], gen1['http'], gen1['resource']) == (sl.FUNCTION_1, 'all', f'{PROJECT}@appspot.gserviceaccount.com', True,
                                                                                                  resource_name('hook', 'functions', service='cloudfunctions'))
    assert sl.function_facts(PROJECT, function_gen1('worker', http=False).resource.data, '')['http'] is False
    gen2 = sl.function_facts(PROJECT, function_gen2('api', 'api-svc').resource.data, '')
    assert (gen2['kind'], gen2['service'], gen2['account']) == (sl.FUNCTION_2, f'projects/{PROJECT}/locations/{REGION}/services/api-svc', DEFAULT)
    # From the v2 Functions API both generations come under serviceConfig; environment tells them apart.
    assert sl.function_facts(PROJECT, {'name': f'projects/{PROJECT}/locations/{REGION}/functions/f', 'environment': 'GEN_1', 'serviceConfig': {'ingressSettings': 'ALLOW_INTERNAL_ONLY', 'uri': 'https://x'}})['kind'] == sl.FUNCTION_1
    assert sl.function_facts(PROJECT, {'name': f'projects/{PROJECT}/locations/{REGION}/functions/f', 'environment': 'GEN_2', 'serviceConfig': {'uri': 'https://x'}})['kind'] == sl.FUNCTION_2


def test_workloads_from_the_inventory_label_gen2_services_and_join_load_balancers():
    grouped = grouped_of(service('web'), service('api-svc', account=DEFAULT), function_gen2('api', 'api-svc'), function_gen1('hook'), run_job('nightly'),
                         neg('neg-web', 'web'), neg('neg-hook', function_name='hook'), neg('neg-mask', url_mask='<service>.example.test'),
                         backend_service('bes-ext', 'neg-web', 'neg-mask'), backend_service('bes-fn', 'neg-hook'), backend_service('bes-int', 'neg-web', scheme='INTERNAL_MANAGED'))
    workloads = sl.workloads_from_inventory(grouped)
    assert {w['name']: w['kind'] for w in workloads.values()} == {'web': sl.SERVICE, 'api-svc': sl.FUNCTION_2, 'hook': sl.FUNCTION_1, 'nightly': sl.JOB}
    assert sl.behind_load_balancers(grouped) == {resource_name('web'): 'bes-ext', resource_name('hook', 'functions', service='cloudfunctions'): 'bes-fn'}
    assert sl.behind_load_balancers(grouped_of(neg('neg-web', 'web'), backend_service('bes-int', 'neg-web', scheme='INTERNAL_MANAGED'))) == {}
    invokers = sl.public_invokers(sl.public_policy_rows([policy_result(resource_name('web'), 'roles/run.invoker', ['allUsers']),
                                                          policy_result(resource_name('api-svc'), 'roles/run.viewer', ['allAuthenticatedUsers']),
                                                          policy_result(resource_name('hook', 'functions', service='cloudfunctions'), 'roles/cloudfunctions.invoker', ['user:a@example.test', 'allAuthenticatedUsers'])]))
    assert invokers == {resource_name('web'): 'allUsers', resource_name('hook', 'functions', service='cloudfunctions'): 'allAuthenticatedUsers'}


# --- Serverless Exposure ---------------------------------------------------------------------------------------------------

def test_exposure_rows_by_binding_setting_iap_ingress_and_load_balancer():
    grouped = grouped_of(service('open-binding'), service('open-setting', no_iam=True), service('iap-front', iap=True, no_iam=False), service('worker', ingress='internal', no_iam=True),
                         service('behind-lb'), service('behind-lb-locked', ingress='internal-and-cloud-load-balancing'), service('behind-lb-iap', iap=True),
                         service('private'), function_gen1('hook'), function_gen1('event', http=False), run_job('nightly'),
                         neg('neg-1', 'behind-lb'), neg('neg-2', 'behind-lb-locked'), neg('neg-3', 'behind-lb-iap'), backend_service('bes', 'neg-1', 'neg-2', 'neg-3'))
    workloads, fronted = sl.workloads_from_inventory(grouped), sl.behind_load_balancers(grouped)
    invokers = {resource_name('open-binding'): 'allUsers', resource_name('behind-lb-locked'): 'allUsers', resource_name('iap-front'): 'allUsers',
                resource_name('hook', 'functions', service='cloudfunctions'): 'allAuthenticatedUsers'}
    rows = sl.exposure_rows(workloads, fronted, invokers)
    assert [(r['Workload'], r['Kind'], r['Issue'], r['Invoker'], r['_status']) for r in rows] == [
        ('hook', sl.FUNCTION_1, 'Public endpoint.', 'public', IR), ('behind-lb', sl.SERVICE, 'Load balancer bypassed.', 'IAM', AR),
        ('behind-lb-iap', sl.SERVICE, 'Load balancer bypassed.', 'IAM', IR), ('open-binding', sl.SERVICE, 'Public endpoint.', 'public', IR),
        ('open-setting', sl.SERVICE, 'Public endpoint.', 'public', IR)]
    by_name = {r['Workload']: r for r in rows}
    assert by_name['behind-lb']['Detail'] == ('Behind backend service bes but ingress is all: the run.app URL answers directly, around the load balancer and any Cloud Armor policy on it '
                                             '(callers need the invoker role).')
    assert by_name['behind-lb']['Fix'] == f'gcloud run services update behind-lb --region={REGION} --project={PROJECT} --ingress=internal-and-cloud-load-balancing'
    assert 'IAP on the service still authenticates callers' in by_name['behind-lb-iap']['Detail']
    assert by_name['open-binding']['Detail'] == ('Anyone on the internet reaches the run.app URL (allUsers holds the invoker role; ingress all; IAP off). Legitimate for a public site — '
                                                'otherwise put IAP or an authenticated caller in front.')
    assert by_name['open-binding']['Fix'] == (f'gcloud run services remove-iam-policy-binding open-binding --region={REGION} --project={PROJECT} --member=allUsers --role=roles/run.invoker'
                                             f'  # or front it with IAP: gcloud run services update open-binding --region={REGION} --project={PROJECT} --iap')
    assert by_name['open-setting']['Detail'].startswith('Anyone on the internet reaches the run.app URL (the invoker IAM check is disabled;')
    assert by_name['open-setting']['Fix'] == (f'gcloud run services update open-setting --region={REGION} --project={PROJECT} --invoker-iam-check  # then grant roles/run.invoker to the callers, '
                                             f'or front it with IAP: gcloud run services update open-setting --region={REGION} --project={PROJECT} --iap')
    assert by_name['hook']['Detail'].startswith('Anyone on the internet reaches the cloudfunctions.net URL (allAuthenticatedUsers holds the invoker role;')
    assert by_name['hook']['Fix'] == f'gcloud functions remove-invoker-policy-binding hook --region={REGION} --project={PROJECT} --member=allAuthenticatedUsers  # then grant the invoker role to the callers'
    assert all(set(r) == {'Project', 'Workload', 'Location', 'Kind', 'Ingress', 'Invoker', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    # A gen-1 function behind a load balancer with ingress all: the same bypass, the functions fix.
    grouped = grouped_of(function_gen1('hook'), neg('neg-f', function_name='hook'), backend_service('bes', 'neg-f'))
    rows = sl.exposure_rows(sl.workloads_from_inventory(grouped), sl.behind_load_balancers(grouped), {})
    assert [(r['Issue'], r['_status'], r['Fix']) for r in rows] == [('Load balancer bypassed.', AR, f'gcloud functions deploy hook --region={REGION} --project={PROJECT} --ingress-settings=internal-and-gclb')]


# --- Serverless Service Accounts -------------------------------------------------------------------------------------------

def test_service_account_rows_by_account_roles_and_kind():
    grouped = grouped_of(service('quiz'), service('web', account=DEDICATED), service('unset', account=''), service('legacy', account=f'{PROJECT}@appspot.gserviceaccount.com'),
                         service('api-svc'), function_gen2('api', 'api-svc'), function_gen1('hook'), run_job('nightly'))
    workloads = sl.workloads_from_inventory(grouped)
    assert sl.default_accounts_in_use(workloads) == [f'{PROJECT}@appspot.gserviceaccount.com', DEFAULT]
    rows = sl.service_account_rows(workloads, {DEFAULT: {'roles/run.admin', 'roles/compute.admin', 'roles/logging.logWriter'}, f'{PROJECT}@appspot.gserviceaccount.com': set()})
    assert [(r['Workload'], r['Kind'], r['Service Account'], r['_status']) for r in rows] == [
        ('hook', sl.FUNCTION_1, f'{PROJECT}@appspot.gserviceaccount.com', IR), ('api-svc', sl.FUNCTION_2, DEFAULT, AR), ('nightly', sl.JOB, DEFAULT, AR),
        ('legacy', sl.SERVICE, f'{PROJECT}@appspot.gserviceaccount.com', IR), ('quiz', sl.SERVICE, DEFAULT, AR), ('unset', sl.SERVICE, DEFAULT, AR)]
    by_name = {r['Workload']: r for r in rows}
    assert by_name['quiz']['Detail'] == ('Runs as the Compute Engine default service account, which holds roles/compute.admin on the project — every role is reachable from the '
                                        'container (a Cloud Run token has no scope limit).')
    assert by_name['quiz']['Fix'] == (f'gcloud iam service-accounts create run-quiz --project={PROJECT} && gcloud run services update quiz --region={REGION} --project={PROJECT} '
                                     f'--service-account=run-quiz@{PROJECT}.iam.gserviceaccount.com  # grant it the roles the workload needs first')
    assert by_name['hook']['Detail'].startswith('Runs as the App Engine default service account (no privileged role today)')
    assert by_name['hook']['Fix'].startswith(f'gcloud iam service-accounts create fn-hook --project={PROJECT} && gcloud functions deploy hook --region={REGION}')
    assert by_name['nightly']['Fix'].split(' && ')[1].startswith(f'gcloud run jobs update nightly --region={REGION} --project={PROJECT} --service-account=job-nightly@')
    assert all(set(r) == {'Project', 'Workload', 'Location', 'Kind', 'Service Account', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    # Roles not read: Investigation and said so; an unset account whose project number is unknown is named as such.
    rows = sl.service_account_rows(sl.workloads_from_inventory(grouped_of(service('quiz'))), {DEFAULT: None})
    assert rows[0]['_status'] == IR and 'its roles could not be read' in rows[0]['Detail']
    unknown = {'r': {**sl.service_facts(PROJECT, v2_service('x', account=''), f'projects/{PROJECT}/locations/{REGION}/services/x')}}
    assert [(r['Service Account'], r['_status']) for r in sl.service_account_rows(unknown, {})] == [('(not set: the Compute Engine default)', IR)]
    assert sl.service_account_rows(sl.workloads_from_inventory(grouped_of(service('web', account=DEDICATED))), {}) == []


# --- the checks end to end ------------------------------------------------------------------------------------------------------

class Inventory:
    def __init__(self, assets=(), public=(), bindings=None, error=None, search_error=None, resources=None, resource_error=None):
        self.assets, self.public, self.bindings, self.error, self.search_error = list(assets), list(public), bindings or {}, error, search_error
        self.resources, self.resource_error, self.requests, self.queries, self.searches = resources or {}, resource_error, [], [], []

    def list_assets(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return [a for a in self.assets if any(a.name.startswith('//' + t.split('/')[0]) for t in request['asset_types'])]

    def search_all_iam_policies(self, request):
        self.queries.append(request['query'])
        if self.search_error:
            raise self.search_error
        if request['query'].startswith('memberTypes:'):
            return iter(self.public)
        email = request['query'].split('"')[1]
        bindings = [SimpleNamespace(role=role, members=[f'serviceAccount:{email}']) for role in self.bindings.get(email, [])]
        return iter([SimpleNamespace(asset_type='cloudresourcemanager.googleapis.com/Project', resource=f'//cloudresourcemanager.googleapis.com/projects/{PROJECT}',
                                     policy=SimpleNamespace(bindings=bindings))] if bindings else [])

    def search_all_resources(self, request):
        self.searches.append(request)
        if self.resource_error:
            raise self.resource_error
        return iter(self.resources.get(tuple(request['asset_types']), []))


class _Call:
    def __init__(self, api, path, **kwargs):
        self.api, self.path, self.kwargs = api, path, kwargs

    def execute(self):
        return self.api.answer(self.path, self.kwargs)


class RunApi:
    """``projects().locations().services().list/list_next/getIamPolicy`` and ``jobs().list`` of the Cloud Run v2 API; ``functions().list`` of Cloud Functions v2."""
    def __init__(self, services=(), jobs=(), functions=(), policies=None, error=None, policy_error=None):
        self.data = {'services': list(services), 'jobs': list(jobs), 'functions': list(functions)}
        self.policies, self.error, self.policy_error, self.calls = policies or {}, error, policy_error, []

    def projects(self):
        return self

    def locations(self):
        return self

    def services(self):
        return _Collection(self, 'services')

    def jobs(self):
        return _Collection(self, 'jobs')

    def functions(self):
        return _Collection(self, 'functions')

    def answer(self, path, kwargs):
        self.calls.append((path, kwargs))
        if path == 'getIamPolicy':
            if self.policy_error:
                raise self.policy_error
            return {'bindings': [{'role': 'roles/run.invoker', 'members': members}] for members in [self.policies.get(kwargs['resource'])] if members} or {'etag': 'x'}
        if self.error:
            raise self.error
        if path == 'jobs':
            return {'jobs': [j for j in self.data['jobs'] if j['name'].startswith(kwargs['parent'] + '/')]}
        return {path: self.data[path]}


class _Collection:
    def __init__(self, api, path):
        self.api, self.path = api, path

    def list(self, parent):
        return _Call(self.api, self.path, parent=parent)

    def list_next(self, previous_request, previous_response):
        return None

    def getIamPolicy(self, resource):
        return _Call(self.api, 'getIamPolicy', resource=resource)


INVENTORY = [service('quiz', no_iam=True), service('web', ingress='all', iap=True, account=DEDICATED), service('worker', ingress='internal', account=DEDICATED),
             service('demo', account=DEDICATED), run_job('nightly', account=DEDICATED), function_gen1('hook', account=DEDICATED, ingress='ALLOW_INTERNAL_ONLY')]
PUBLIC = [policy_result(resource_name('demo'), 'roles/run.invoker', ['allUsers'])]


def test_check_serverless_posture_end_to_end(gcp, monkeypatch):
    inventory = Inventory(INVENTORY, PUBLIC, {DEFAULT: ['roles/editor']})
    apis = {'run': RunApi(services=[v2_service('quiz', no_iam=True), v2_service('web', iap=True, account=DEDICATED), v2_service('worker', 'INGRESS_TRAFFIC_INTERNAL_ONLY', account=DEDICATED),
                                    v2_service('demo', account=DEDICATED)],
                          jobs=[{'name': f'projects/{PROJECT}/locations/{REGION}/jobs/nightly', 'template': {'template': {'serviceAccount': DEDICATED}}}],
                          policies={f'projects/{PROJECT}/locations/{REGION}/services/demo': ['allUsers']}),
            'cloudfunctions': RunApi(functions=[{'name': f'projects/{PROJECT}/locations/{REGION}/functions/hook', 'environment': 'GEN_1',
                                                 'serviceConfig': {'ingressSettings': 'ALLOW_INTERNAL_ONLY', 'serviceAccountEmail': DEDICATED, 'uri': 'https://x'}}])}
    monkeypatch.setattr(sl.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(sl.gcp, 'api_build', lambda name, version, **kwargs: apis[name])
    sink = Sink()
    sl.check_serverless_posture('organization', '987654321', JOB, sink=sink)
    records = sink.by_check()
    assert {name: record['Status'] for name, record in records.items()} == {'Serverless Exposure': IR, 'Serverless Service Accounts': AR}
    assert [(r['Workload'], r['Issue'], r['Invoker']) for r in records['Serverless Exposure']['Finding']] == [('demo', 'Public endpoint.', 'public'), ('quiz', 'Public endpoint.', 'public')]
    assert [(r['Workload'], r['Service Account']) for r in records['Serverless Service Accounts']['Finding']] == [('quiz', DEFAULT)]
    assert records['Serverless Service Accounts']['Finding'][0]['Detail'].startswith('Runs as the Compute Engine default service account, which holds roles/editor')
    assert inventory.requests[0]['asset_types'] == sl.SERVERLESS_TYPES and inventory.queries == [sl.PUBLIC_QUERY, f'policy:"{DEFAULT}"'] and sink.not_checked() == []
    assert [c[0] for c in apis['run'].calls] == ['services', 'jobs', 'getIamPolicy', 'getIamPolicy', 'getIamPolicy', 'getIamPolicy'] and [c[0] for c in apis['cloudfunctions'].calls] == ['functions']
    assert all('_status' not in r for record in records.values() for r in record['Finding'])
    # The API is the copy of record: quiz turned its invoker check back on and moved to a dedicated account, demo lost its public binding, a new public service appeared.
    apis['run'] = RunApi(services=[v2_service('quiz', account=DEDICATED), v2_service('web', iap=True, account=DEDICATED), v2_service('demo', account=DEDICATED), v2_service('new', no_iam=True)],
                         jobs=[{'name': f'projects/{PROJECT}/locations/{REGION}/jobs/nightly', 'template': {'template': {'serviceAccount': DEDICATED}}}])
    sink = Sink()
    sl.check_serverless_posture('organization', '987654321', JOB, sink=sink)
    records = sink.by_check()
    assert [(r['Workload'], r['Issue']) for r in records['Serverless Exposure']['Finding']] == [('new', 'Public endpoint.')]
    assert [(r['Workload'], r['Service Account']) for r in records['Serverless Service Accounts']['Finding']] == [('new', DEFAULT)]
    # The API reads failing: the inventory's copy serves, and Projects not checked says so.
    apis = {'run': RunApi(error=RuntimeError('403 run.services.list denied')), 'cloudfunctions': RunApi(error=RuntimeError('403 Cloud Functions API has not been used in project'))}
    sink = Sink()
    sl.check_serverless_posture('organization', '987654321', JOB, sink=sink)
    assert [(r['Workload'], r['Issue']) for r in sink.by_check()['Serverless Exposure']['Finding']] == [('demo', 'Public endpoint.'), ('quiz', 'Public endpoint.')]
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [
        (PROJECT, "Serverless Exposure (Cloud Run services and jobs: the API read failed; the inventory's copy was used, which can lag changes by hours)"),
        (PROJECT, "Serverless Exposure (Cloud Functions: the API read failed; the inventory's copy was used, which can lag changes by hours)")]
    # A policy read failing keeps the search's copy; the public search failing is noted; the roles search failing is noted under the other record.
    apis = {'run': RunApi(services=[v2_service('demo', account=DEDICATED), v2_service('quiz', no_iam=True)], policy_error=RuntimeError('429 quota')), 'cloudfunctions': RunApi()}
    inventory = Inventory([service('demo', account=DEDICATED), service('quiz', no_iam=True)], PUBLIC, search_error=RuntimeError('503 search'))
    monkeypatch.setattr(sl.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    sl.check_serverless_posture('project', PROJECT, JOB, sink=sink)
    assert [(r['Workload'], r['Invoker']) for r in sink.by_check()['Serverless Exposure']['Finding']] == [('quiz', 'public')]  # demo's binding is unknown without the search
    assert 'could not be read' in sink.by_check()['Serverless Service Accounts']['Finding'][0]['Detail']
    assert [r['Skipped check'] for r in sink.not_checked()] == [
        'Serverless Exposure (public invokers: the IAM policy search failed; only the invoker-check setting and the API policies were read)',
        "Serverless Exposure (invoker policy of demo: the API read failed; the IAM search's copy was used)",
        "Serverless Exposure (invoker policy of quiz: the API read failed; the IAM search's copy was used)",
        f'Serverless Service Accounts (roles of {DEFAULT}: the IAM search failed)']
    # Nothing in scope: two all-clear rows and no API call. A listing that fails: two Errors.
    api = RunApi()
    monkeypatch.setattr(sl.gcp, 'asset_client', lambda credentials=None: Inventory())
    monkeypatch.setattr(sl.gcp, 'api_build', lambda name, version, **kwargs: api)
    sink = Sink()
    sl.check_serverless_posture('folder', '42', JOB, sink=sink)
    assert {name: record['Finding'] for name, record in sink.by_check().items()} == {'Serverless Exposure': [{'Status': sl.EXPOSURE_ALL_CLEAR}],
                                                                                      'Serverless Service Accounts': [{'Status': sl.SERVERLESS_SA_ALL_CLEAR}]}
    assert api.calls == []
    monkeypatch.setattr(sl.gcp, 'asset_client', lambda credentials=None: Inventory(error=RuntimeError('503 inventory unavailable')))
    sink = Sink()
    sl.check_serverless_posture('folder', '42', JOB, sink=sink)
    assert {name: record['Status'] for name, record in sink.by_check().items()} == {'Serverless Exposure': 'Error', 'Serverless Service Accounts': 'Error'}


class ComputeEdge:
    """``networkEndpointGroups().aggregatedList`` and ``backendServices().aggregatedList`` per project: the API's copy of the load balancers."""
    def __init__(self, negs=(), backends=(), error=None):
        self.negs, self.backends, self.error, self.listed, self._collection = list(negs), list(backends), error, [], None

    def networkEndpointGroups(self):
        self._collection = 'networkEndpointGroups'
        return self

    def backendServices(self):
        self._collection = 'backendServices'
        return self

    def aggregatedList(self, project):
        self.listed.append((self._collection, project))
        return self

    def aggregatedList_next(self, previous_request, previous_response):
        return None

    def execute(self):
        if self.error:
            raise self.error
        items = self.negs if self._collection == 'networkEndpointGroups' else self.backends
        return {'items': {f'regions/{REGION}': {self._collection: [dict(a.resource.data) for a in items]}}}


def test_refresh_load_balancers_reads_the_api_copy_and_falls_back(gcp, monkeypatch):
    """The first v18.6 canary: the index showed the backend service as created — ``backends: []`` — minutes after its NEG was added; the API has it."""
    stale = grouped_of(service('behind-lb'), neg('neg-1', 'behind-lb'), SimpleNamespace(name=f'//compute.googleapis.com/projects/{PROJECT}/global/backendServices/bes',
                                                                                        resource=SimpleNamespace(data={'name': 'bes', 'loadBalancingScheme': 'EXTERNAL_MANAGED', 'selfLink': f'{COMPUTE}/global/backendServices/bes', 'backends': []})))
    assert sl.behind_load_balancers(stale) == {}
    fresh_backend = backend_service('bes', 'neg-1')
    compute = ComputeEdge([neg('neg-1', 'behind-lb')], [fresh_backend])
    skipped = sl.NotChecked(sl.EXPOSURE_CHECK)
    refreshed = sl.refresh_load_balancers(dict(stale), compute, skipped)
    assert sl.behind_load_balancers(refreshed) == {resource_name('behind-lb'): 'bes'} and compute.listed == [('backendServices', PROJECT)]  # the NEGs stay the inventory's
    # A refused read keeps the inventory's copy and says so; a project without a serverless NEG is never asked.
    skipped = sl.NotChecked(sl.EXPOSURE_CHECK)
    refreshed = sl.refresh_load_balancers(dict(stale), ComputeEdge(error=RuntimeError('403 compute.backendServices.list denied')), skipped)
    assert sl.behind_load_balancers(refreshed) == {} and [(r['Project'], r['Skipped check']) for r in skipped.rows] == [
        (PROJECT, "Serverless Exposure (load balancers: the Compute API read failed; the inventory's copy was used, which can lag changes by hours)")]
    compute = ComputeEdge()
    sl.refresh_load_balancers(grouped_of(service('web')), compute, sl.NotChecked(sl.EXPOSURE_CHECK))
    assert compute.listed == []
    # End to end: the check asks the Compute API when the inventory shows a serverless NEG, and the bypass row follows the API's copy.
    inventory = Inventory([service('behind-lb', account=DEDICATED), neg('neg-1', 'behind-lb'), stale['backendServices'][0] and SimpleNamespace(
        name=f'//compute.googleapis.com/projects/{PROJECT}/global/backendServices/bes', resource=SimpleNamespace(data={'name': 'bes', 'loadBalancingScheme': 'EXTERNAL_MANAGED', 'selfLink': f'{COMPUTE}/global/backendServices/bes', 'backends': []}))])
    apis = {'run': RunApi(services=[v2_service('behind-lb', account=DEDICATED)]), 'compute': ComputeEdge([neg('neg-1', 'behind-lb')], [fresh_backend])}
    monkeypatch.setattr(sl.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(sl.gcp, 'api_build', lambda name, version, **kwargs: apis[name])
    sink = Sink()
    sl.check_serverless_posture('project', PROJECT, JOB, sink=sink)
    assert [(r['Workload'], r['Issue']) for r in sink.by_check()['Serverless Exposure']['Finding']] == [('behind-lb', 'Load balancer bypassed.')] and sink.not_checked() == []


# --- Container Scanning Enabled ---------------------------------------------------------------------------------------------

def repository(project, number, location, name, fmt='DOCKER', mode='STANDARD_REPOSITORY', searched=True):
    full = f'//artifactregistry.googleapis.com/projects/{project}/locations/{location}/repositories/{name}'
    data = {'name': f'projects/{project}/locations/{location}/repositories/{name}', 'format': fmt, 'mode': mode}
    if searched:
        return SimpleNamespace(name=full, asset_type=sl.REPOSITORY, project=f'projects/{number}', versioned_resources=[{'version': 'v1', 'resource': data}])
    return SimpleNamespace(name=full, resource=SimpleNamespace(data=data, parent=f'//cloudresourcemanager.googleapis.com/projects/{number}'))


def scanning_service(number, state='ENABLED'):
    return SimpleNamespace(name=f'//serviceusage.googleapis.com/projects/{number}/services/{sl.SCANNING_API}', asset_type=sl.SERVICE_USAGE, project=f'projects/{number}', state=state)


def test_scanning_rows_per_project_with_standard_docker_repositories():
    repos = [sl.repository_facts(r) for r in (repository('p-a', '1', 'us', 'gcr.io'), repository('p-a', '1', 'asia-south1', 'images'), repository('p-a', '1', 'us', 'pypi', fmt='PYTHON'),
                                               repository('p-b', '2', 'us', 'mirror', mode='REMOTE_REPOSITORY'), repository('p-c', '3', 'europe-west1', 'apps'), repository('p-d', '4', 'us', 'svc', searched=False))]
    assert repos[0] == ('p-a', '1', 'gcr.io', 'DOCKER', 'STANDARD_REPOSITORY') and repos[5] == ('p-d', '4', 'svc', 'DOCKER', 'STANDARD_REPOSITORY')
    rows = sl.scanning_rows(repos, {'3'})
    assert [(r['Project'], r['Repositories'], r['_status']) for r in rows] == [('p-a', '2 Docker: gcr.io, images', IR), ('p-d', '1 Docker: svc', IR)]
    assert rows[0]['Fix'] == f'gcloud services enable {sl.SCANNING_API} --project=p-a' and rows[0]['Issue'] == 'Container scanning off.'
    assert sl.scanning_rows(repos, {'1', '3', '4'}) == [] and sl.scanning_rows([], set()) == []


class ServiceUsage:
    """``services().get(name=projects/P/services/S)``: the state per project (``None``: the API refuses)."""
    def __init__(self, states=None, error=None):
        self.states, self.error, self.asked = states or {}, error, []

    def services(self):
        return self

    def get(self, name):
        self.asked.append(name)
        return self

    def execute(self):
        if self.error:
            raise self.error
        project_id = self.asked[-1].split('/')[1]
        number = {PROJECT: NUMBER, 'stark-sandbox': '3'}.get(project_id, project_id)
        return {'name': f'projects/{number}/services/{sl.SCANNING_API}', 'state': self.states.get(project_id, 'DISABLED')}


def test_check_container_scanning_end_to_end(gcp, monkeypatch):
    repos = [repository(PROJECT, NUMBER, 'us', 'gcr.io'), repository('stark-sandbox', '3', 'us', 'gcr.io')]
    inventory = Inventory(resources={(sl.REPOSITORY,): repos, (sl.SERVICE_USAGE,): [scanning_service('3'), scanning_service('4', state='DISABLED')]})
    usage = ServiceUsage({'stark-sandbox': 'ENABLED'})  # the API agrees with the index
    monkeypatch.setattr(sl.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(sl.gcp, 'api_build', lambda *args, **kwargs: usage)
    sink = Sink()
    sl.check_container_scanning('organization', '987654321', JOB, sink=sink)
    record = sink.by_check()['Container Scanning Enabled']
    assert record['Status'] == IR and [r['Project'] for r in record['Finding']] == [PROJECT] and sink.not_checked() == []
    assert inventory.searches[1]['query'] == f'name:{sl.SCANNING_API}' and inventory.searches[0]['asset_types'] == [sl.REPOSITORY]
    assert usage.asked == [f'projects/{PROJECT}/services/{sl.SCANNING_API}', f'projects/stark-sandbox/services/{sl.SCANNING_API}']
    # The API is the copy of record: enabled since the index's snapshot (the closed loop), or disabled since.
    monkeypatch.setattr(sl.gcp, 'api_build', lambda *args, **kwargs: ServiceUsage({PROJECT: 'ENABLED', 'stark-sandbox': 'DISABLED'}))
    sink = Sink()
    sl.check_container_scanning('organization', '987654321', JOB, sink=sink)
    assert [r['Project'] for r in sink.by_check()['Container Scanning Enabled']['Finding']] == ['stark-sandbox']
    # The API refused: the index's answer stands, and Projects not checked says so.
    monkeypatch.setattr(sl.gcp, 'api_build', lambda *args, **kwargs: ServiceUsage(error=RuntimeError('403 serviceusage.services.get denied')))
    sink = Sink()
    sl.check_container_scanning('organization', '987654321', JOB, sink=sink)
    assert [r['Project'] for r in sink.by_check()['Container Scanning Enabled']['Finding']] == [PROJECT]
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [(p, "Container Scanning Enabled (Artifact Analysis: the Service Usage read failed; the inventory's answer was used, which can lag an enablement by minutes)") for p in (PROJECT, 'stark-sandbox')]
    # The repository search failing: the listing serves (project numbers from the assets' parents). No repositories: all clear, nothing else read.
    inventory = Inventory([repository(PROJECT, NUMBER, 'us', 'gcr.io', searched=False)], resource_error=RuntimeError('400 read mask'))
    monkeypatch.setattr(sl.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    sl.check_container_scanning('project', PROJECT, JOB, sink=sink)
    assert sink.by_check()['Container Scanning Enabled']['Status'] == 'Error'  # the service search fails too under this fake
    inventory, usage = Inventory(resources={(sl.REPOSITORY,): []}), ServiceUsage()
    monkeypatch.setattr(sl.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(sl.gcp, 'api_build', lambda *args, **kwargs: usage)
    sink = Sink()
    sl.check_container_scanning('folder', '42', JOB, sink=sink)
    assert sink.by_check()['Container Scanning Enabled']['Finding'] == [{'Status': sl.SCANNING_ALL_CLEAR}] and len(inventory.searches) == 1 and usage.asked == []


def test_the_three_names_are_catalogued_scope_level_and_new():
    for name in (*sl.SERVERLESS_CHECKS, sl.SCANNING_CHECK):
        assert CATEGORY_MAP[name] == 'Security & Identity' and name not in RESHAPED_CHECKS
    assert sl.EXPOSURE_CHECK in registry.SCOPE_LEVEL_CHECKS and sl.SCANNING_CHECK in registry.SCOPE_LEVEL_CHECKS
    names = [spec.name for spec in registry.build_check_plan('folder', '42', JOB, [], [], [])]
    assert sl.EXPOSURE_CHECK in names and sl.SCANNING_CHECK in names and sl.SERVERLESS_SA_CHECK not in names  # the second record shares the first's spec
