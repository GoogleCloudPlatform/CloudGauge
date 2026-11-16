"""
v18.9 — Logging pipeline and alerting hygiene, the alerting: the rules of ``app.checks.alerting`` on fixture policies, channels, uptime checks,
services and SLOs, and the two checks end to end with their failure paths.
"""
from types import SimpleNamespace

from app.checks import alerting
from app.checks.alerting import (CHANNELS_CHECK, SYNTHETIC_CHECK, channel_label, channel_rows, channel_state, check_alert_channels, check_synthetic_coverage,
                                 lb_watched, publisher_grant_found, slo_alerted, synthetic_rows, topic_present, uptime_alerted, uptime_targets, workload_facts)
from app.checks.not_checked import NOT_CHECKED
from fakes import ORG_ID as ORG, _execute

JOB = 'job-189'
P, N = 'stark-web-prod', '111111111111'
AGENT = f'service-{N}@gcp-sa-monitoring-notification.iam.gserviceaccount.com'
TOPIC = f'projects/{P}/topics/alerts'


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


def policy(name, channels=(), enabled=True, condition=None, display=None):
    return {'name': f'projects/{P}/alertPolicies/{name}', 'displayName': display or name, 'enabled': enabled,
            'conditions': [condition or {'conditionThreshold': {'filter': 'metric.type="compute.googleapis.com/instance/cpu/utilization"'}}],
            'notificationChannels': [f'projects/{P}/notificationChannels/{c}' for c in channels]}


def channel(name, kind='email', enabled=True, status='VERIFIED', **labels):
    labels = labels or ({'email_address': 'ops@example.com'} if kind == 'email' else {})
    return {'name': f'projects/{P}/notificationChannels/{name}', 'type': kind, 'displayName': f'{name} channel', 'enabled': enabled, 'verificationStatus': status, 'labels': labels}


def uptime(check_id, host, display=None):
    return {'name': f'projects/{P}/uptimeCheckConfigs/{check_id}', 'displayName': display or check_id, 'monitoredResource': {'type': 'uptime_url', 'labels': {'host': host, 'project_id': P}}}


def slo(service, name):
    return {'name': f'projects/{P}/services/{service}/serviceLevelObjectives/{name}', 'displayName': name, 'goal': 0.995}


def asset(name, data=None):
    return SimpleNamespace(name=name, resource=SimpleNamespace(data=data or {}))


def iam(resource, role, member=f'serviceAccount:{AGENT}'):
    return SimpleNamespace(resource=resource, policy=SimpleNamespace(bindings=[SimpleNamespace(role=role, members=[member])]))


# --- channels ---

def test_channel_state_and_label():
    assert channel_state(channel('a')) == 'working' and channel_state(channel('a', status='VERIFICATION_STATUS_UNSPECIFIED')) == 'working'
    assert channel_state(channel('a', enabled=False)) == 'disabled' and channel_state(channel('a', status='UNVERIFIED')) == 'unverified'
    assert channel_state(channel('a', enabled=False, status='UNVERIFIED')) == 'disabled'
    assert channel_label(channel('a')) == 'email ops@example.com'
    assert channel_label(channel('t', kind='pubsub', topic=TOPIC)) == 'pubsub alerts'
    assert channel_label(channel('s', kind='slack', channel_name='#ops')) == 'slack #ops'
    assert channel_label({'type': 'webhook_tokenauth', 'labels': {'url': 'https://hooks.example/x'}}) == 'webhook_tokenauth https://hooks.example/x'
    assert channel_label({'displayName': 'pager'}) == 'channel pager' and channel_label({}) == 'channel'


def test_channel_rows_judge_missing_dead_and_pubsub_channels_and_mql():
    channels = [channel('ok'), channel('dead', enabled=False), channel('unverified', status='UNVERIFIED'), channel('ps', kind='pubsub', topic=TOPIC),
                channel('ps-gone', kind='pubsub', topic=f'projects/{P}/topics/gone'), channel('ps-ungranted', kind='pubsub', topic=f'projects/{P}/topics/quiet')]
    policies = [policy('nobody'), policy('dead-ends', ['dead', 'unverified', 'missing']), policy('fine', ['ok', 'dead']), policy('off', enabled=False),
                policy('mql', ['ok'], condition={'conditionMonitoringQueryLanguage': {'query': 'fetch gce_instance | metric cpu'}}),
                policy('ps-user', ['ps', 'ps-gone', 'ps-ungranted']), policy('ps-user-2', ['ps-gone'])]
    facts = {TOPIC: {'exists': True, 'granted': True, 'agent': AGENT}, f'projects/{P}/topics/gone': {'exists': False, 'granted': None, 'agent': AGENT},
             f'projects/{P}/topics/quiet': {'exists': True, 'granted': False, 'agent': AGENT}}
    rows = channel_rows(P, policies, channels, lambda topic, c: facts[topic])
    assert [(r['Policy'], r['Channels'], r['Issue'], r['_status']) for r in rows] == [
        ('nobody', 'none', 'Fires to nobody.', 'Investigation Recommended'),
        ('dead-ends', 'email ops@example.com, email ops@example.com, missing', 'No working channel.', 'Investigation Recommended'),
        ('mql', 'email ops@example.com', 'MQL condition.', 'Informational'),
        ('ps-user, ps-user-2', 'pubsub gone', 'Pub/Sub topic gone.', 'Action Required'),
        ('ps-user', 'pubsub quiet', 'Notification agent cannot publish.', 'Investigation Recommended')]
    assert rows[0]['Fix'] == f'gcloud alpha monitoring policies update nobody --project={P} --add-notification-channels=<channel>'
    assert rows[1]['Detail'] == 'Every channel of the policy is out of service (email ops@example.com: disabled; email ops@example.com: unverified; missing: gone): the alert is not delivered.'
    assert rows[3]['Fix'] == f'gcloud pubsub topics create gone --project={P}  # or point the channel at a topic that exists'
    assert rows[4]['Fix'] == f'gcloud pubsub topics add-iam-policy-binding quiet --project={P} --member=serviceAccount:{AGENT} --role=roles/pubsub.publisher'
    assert rows[4]['Detail'] == f'{AGENT} holds no roles/pubsub.publisher on projects/{P}/topics/quiet: Monitoring cannot deliver to the topic.'
    # Unknown topic facts (None) judge nothing; without a topic reader the Pub/Sub rules are skipped; a Pub/Sub channel used by no enabled policy is not judged.
    assert channel_rows(P, [policy('ps-user', ['ps-gone'])], channels, lambda topic, c: {'exists': None, 'granted': None}) == []
    assert channel_rows(P, [policy('ps-user', ['ps-gone'])], channels) == []
    assert channel_rows(P, [policy('off', ['ps-gone'], enabled=False)], channels, lambda topic, c: facts[topic]) == []
    assert channel_rows(P, [], channels, lambda topic, c: facts[topic]) == []
    many = [policy(f'p{i}', ['ps-gone']) for i in range(5)]
    assert channel_rows(P, many, channels, lambda topic, c: facts[topic])[0]['Policy'] == 'p0, p1, p2 +2 more'


def test_topic_present_and_publisher_grant():
    names = [f'//pubsub.googleapis.com/{TOPIC}', f'//pubsub.googleapis.com/projects/{P}/topics/other']
    assert topic_present(names, TOPIC) and topic_present(names, f'projects/{N}/topics/alerts') and not topic_present(names, f'projects/{P}/topics/gone')
    assert publisher_grant_found([iam(f'//pubsub.googleapis.com/{TOPIC}', 'roles/pubsub.publisher')], TOPIC)
    assert publisher_grant_found([iam(f'//cloudresourcemanager.googleapis.com/projects/{P}', 'roles/pubsub.editor')], TOPIC)
    assert not publisher_grant_found([iam(f'//pubsub.googleapis.com/projects/{P}/topics/other', 'roles/pubsub.publisher')], TOPIC)
    assert not publisher_grant_found([iam(f'//pubsub.googleapis.com/{TOPIC}', 'roles/pubsub.viewer')], TOPIC)
    assert not publisher_grant_found([], TOPIC)


# --- synthetic coverage ---

def test_workload_facts_group_external_load_balancers_services_and_clusters_by_project():
    assets = [asset(f'//compute.googleapis.com/projects/{P}/global/forwardingRules/edge-fr', {'name': 'edge-fr', 'loadBalancingScheme': 'EXTERNAL_MANAGED', 'IPAddress': '34.1.2.3'}),
              asset(f'//compute.googleapis.com/projects/{P}/regions/asia-south1/forwardingRules/ilb', {'name': 'ilb', 'loadBalancingScheme': 'INTERNAL', 'IPAddress': '10.0.0.5'}),
              asset(f'//compute.googleapis.com/projects/{P}/regions/asia-south1/forwardingRules/legacy', {}),  # no scheme: external by default
              asset(f'//run.googleapis.com/projects/{P}/locations/asia-south1/services/web'), asset(f'//container.googleapis.com/projects/other/locations/asia-south1/clusters/c1'),
              asset('//compute.googleapis.com/global/odd')]
    assert workload_facts(assets) == {P: {'lbs': [('edge-fr', '34.1.2.3'), ('legacy', '')], 'services': ['web'], 'clusters': []},
                                      'other': {'lbs': [], 'services': [], 'clusters': ['c1']}}
    assert workload_facts([]) == {}


def test_uptime_and_slo_matching():
    targets = uptime_targets([uptime('edge', '34.1.2.3'), uptime('site', 'www.example.com'), {'name': f'projects/{P}/uptimeCheckConfigs/group', 'resourceGroup': {'groupId': 'g'}}])
    assert targets == [('edge', '34.1.2.3', 'edge'), ('site', 'www.example.com', 'site'), ('group', '', 'group')]
    assert lb_watched('34.1.2.3', targets[:1]) and not lb_watched('34.1.2.4', targets[:1]) and not lb_watched('34.1.2.4', targets[2:])
    assert lb_watched('34.1.2.4', targets[1:2])  # a hostname check: taken as covering
    assert not lb_watched('', []) and not lb_watched('2600:1901::1', [('x', '2600:1901::2', 'x')]) and lb_watched('2600:1901::1', [('x', '2600:1901::1', 'x')])
    texts = ['metric.type="monitoring.googleapis.com/uptime_check/check_passed" and metric.labels.check_id="edge" and resource.type="uptime_url"']
    assert uptime_alerted('edge', texts) and not uptime_alerted('site', texts)
    assert uptime_alerted('site', ['metric.type="monitoring.googleapis.com/uptime_check/check_passed"'])  # every check
    assert not uptime_alerted('site', []) and not uptime_alerted('site', ['metric.type="compute.googleapis.com/instance/cpu/utilization"'])
    name = f'projects/{P}/services/web/serviceLevelObjectives/availability'
    assert slo_alerted(name, [f'select_slo_burn_rate("{name}", "60m") > 10']) and slo_alerted(name, [f'select_slo_health("{name}")'])
    assert not slo_alerted(name, [f'select_slo_burn_rate("projects/{P}/services/web/serviceLevelObjectives/latency", "60m")']) and not slo_alerted(name, ['availability'])


def test_synthetic_rows_judge_load_balancers_uptime_checks_slos_and_their_absence():
    facts = {'lbs': [('edge-fr', '34.1.2.3'), ('api-fr', '34.1.2.4')], 'services': ['web'], 'clusters': []}
    checks = [uptime('edge', '34.1.2.3', 'edge check'), uptime('old', '34.9.9.9')]
    slos = {f'projects/{P}/services/web': [slo('web', 'availability'), slo('web', 'latency')]}
    policies = [policy('edge-alert', condition={'conditionThreshold': {'filter': 'metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND metric.labels.check_id="edge" AND resource.type="uptime_url"'}}),
                policy('burn', condition={'conditionThreshold': {'filter': f'select_slo_burn_rate("projects/{P}/services/web/serviceLevelObjectives/availability", "60m") > 10'}}),
                policy('disabled-old', enabled=False, condition={'conditionThreshold': {'filter': 'check_passed AND metric.labels.check_id="old"'}})]
    rows = synthetic_rows(P, facts, checks, slos, policies)
    assert [(r['Resource'], r['Kind'], r['Issue'], r['_status']) for r in rows] == [
        ('api-fr', 'external load balancer', 'No uptime check.', 'Investigation Recommended'), ('old', 'uptime check', 'No alert policy.', 'Investigation Recommended'),
        ('web / latency', 'SLO', 'No burn-rate alert.', 'Investigation Recommended')]
    assert rows[0]['Fix'] == f'gcloud monitoring uptime create api-fr-uptime --project={P} --resource-type=uptime-url --resource-labels=host=34.1.2.4,project_id={P} --protocol=https --port=443 --path=/'
    assert rows[1]['Detail'] == 'The uptime check on 34.9.9.9 fails silently: no enabled alert policy watches check_passed for it.'
    assert 'metric.labels.check_id="old"' in rows[1]['Fix'] and 'select_slo_burn_rate' in rows[2]['Fix']
    # No SLO at all in a project that runs something: Informational; nothing running: nothing.
    rows = synthetic_rows(P, {'lbs': [], 'services': ['web', 'api'], 'clusters': ['c1']}, [], {}, [])
    assert [(r['Kind'], r['Issue'], r['_status']) for r in rows] == [('SLO', 'No SLO.', 'Informational')]
    assert rows[0]['Detail'] == 'The project runs 2 Cloud Run service(s), 1 GKE cluster(s) and defines no service-level objective: there is no agreed target to alert on.'
    assert synthetic_rows(P, {'lbs': [], 'services': [], 'clusters': []}, [], {}, []) == []
    assert synthetic_rows(P, {'lbs': [('x', '1.2.3.4')], 'services': [], 'clusters': []}, [uptime('any', 'www.example.com')], {'s': [slo('s', 'a')]},
                          [policy('u', condition={'conditionThreshold': {'filter': 'check_passed'}}), policy('b', condition={'conditionThreshold': {'filter': f'select_slo_burn_rate("projects/{P}/services/s/serviceLevelObjectives/a", "1h")'}})]) == []


# --- the checks ---

class FakeMonitoring:
    def __init__(self, policies=None, channels=None, uptime=None, services=None, slos=None, errors=None):
        self.policies_, self.channels_, self.uptime_, self.services_, self.slos_ = policies or {}, channels or {}, uptime or {}, services or {}, slos or {}
        self.errors = errors or {}  # method -> error
        self.calls = []

    def _list(self, method, store, key, kwargs):
        self.calls.append((method, kwargs.get('name') or kwargs.get('parent')))
        if method in self.errors:
            return _execute(self.errors[method])
        return _execute({key: store.get((kwargs.get('name') or kwargs.get('parent')).split('/')[1], [])})

    def projects(self):
        none = lambda previous_request, previous_response: None  # noqa: E731
        return SimpleNamespace(alertPolicies=lambda: SimpleNamespace(list=lambda **kw: self._list('policies', self.policies_, 'alertPolicies', kw), list_next=none),
                               notificationChannels=lambda: SimpleNamespace(list=lambda **kw: self._list('channels', self.channels_, 'notificationChannels', kw), list_next=none),
                               uptimeCheckConfigs=lambda: SimpleNamespace(list=lambda **kw: self._list('uptime', self.uptime_, 'uptimeCheckConfigs', kw), list_next=none))

    def services(self):
        none = lambda previous_request, previous_response: None  # noqa: E731

        def slos_list(**kw):
            self.calls.append(('slos', kw.get('parent')))
            return _execute(self.errors.get('slos') or {'serviceLevelObjectives': self.slos_.get(kw.get('parent'), [])})
        return SimpleNamespace(list=lambda **kw: self._list('services', self.services_, 'services', kw), list_next=none,
                               serviceLevelObjectives=lambda: SimpleNamespace(list=slos_list, list_next=none))


def test_check_alert_channels_end_to_end(gcp):
    channels = [channel('ok'), channel('ps', kind='pubsub', topic=TOPIC), channel('ps-gone', kind='pubsub', topic=f'projects/{P}/topics/gone'), channel('ps-quiet', kind='pubsub', topic=f'projects/{P}/topics/quiet')]
    gcp.discovery.apis['monitoring'] = FakeMonitoring(policies={P: [policy('nobody'), policy('fine', ['ok']), policy('ps-user', ['ps', 'ps-gone', 'ps-quiet'])], 'quiet-project': [policy('off', ['x'], enabled=False)]},
                                                      channels={P: channels})
    gcp.assets.add_asset('pubsub.googleapis.com/Topic', f'//pubsub.googleapis.com/{TOPIC}', {}, project_number=N)
    gcp.assets.add_asset('pubsub.googleapis.com/Topic', f'//pubsub.googleapis.com/projects/{P}/topics/quiet', {}, project_number=N)
    gcp.assets.add_iam_policy('pubsub.googleapis.com/Topic', f'//pubsub.googleapis.com/{TOPIC}', [('roles/pubsub.publisher', [f'serviceAccount:{AGENT}'])], project_number=N)
    s = Sink()
    check_alert_channels(ORG, [{'projectId': P, 'projectNumber': N}, {'projectId': 'quiet-project', 'projectNumber': '2'}], JOB, sink=s)
    record = s.by_check()[CHANNELS_CHECK]
    assert record['Status'] == 'Action Required'
    assert [(r['Project'], r['Policy'], r['Issue']) for r in record['Finding']] == [(P, 'nobody', 'Fires to nobody.'), (P, 'ps-user', 'Pub/Sub topic gone.'), (P, 'ps-user', 'Notification agent cannot publish.')]
    assert all('_status' not in r for r in record['Finding']) and s.not_checked() == []
    monitoring = gcp.discovery.apis['monitoring']
    assert [c for c in monitoring.calls] == [('policies', f'projects/{P}'), ('channels', f'projects/{P}'), ('policies', 'projects/quiet-project')]  # no channel read without a policy that names one
    assert [r['parent'] for r in gcp.assets.list_requests] == [f'projects/{P}'] and gcp.assets.iam_queries == [f'policy:"{AGENT}"']  # one topic listing and one search per topic project
    # Nothing to route: all clear. A project without a number: the topic is verified, the grant is not.
    gcp.discovery.apis['monitoring'] = FakeMonitoring(policies={P: [policy('ps-user', ['ps-quiet'])]}, channels={P: channels})
    s = Sink()
    check_alert_channels(ORG, [{'projectId': P}], JOB, sink=s)
    assert s.by_check()[CHANNELS_CHECK] == {'Check': CHANNELS_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': alerting.CHANNELS_ALL_CLEAR}]}
    gcp.discovery.apis['monitoring'] = FakeMonitoring(policies={P: []})
    s = Sink()
    check_alert_channels(ORG, [{'projectId': P, 'projectNumber': N}], JOB, sink=s)
    assert s.by_check()[CHANNELS_CHECK]['Status'] == 'Compliant'


def test_check_alert_channels_failures(gcp):
    gcp.discovery.apis['monitoring'] = FakeMonitoring(errors={'policies': RuntimeError('monitoring down')})
    s = Sink()
    check_alert_channels(ORG, [{'projectId': P, 'projectNumber': N}], JOB, sink=s)
    assert s.by_check()[CHANNELS_CHECK]['Status'] == 'Compliant'
    assert [(r['Project'], r['Skipped check'], r['Reason']) for r in s.not_checked()] == [(P, CHANNELS_CHECK, 'monitoring down')]
    # The topic listing and the IAM search fail: the Pub/Sub channel is not judged, each failure noted once.
    gcp.discovery.apis['monitoring'] = FakeMonitoring(policies={P: [policy('a', ['ps']), policy('b', ['ps'])]}, channels={P: [channel('ps', kind='pubsub', topic=TOPIC)]})
    gcp.assets.list_errors['pubsub.googleapis.com/Topic'] = RuntimeError('listing down')
    s = Sink()
    check_alert_channels(ORG, [{'projectId': P, 'projectNumber': N}], JOB, sink=s)
    assert s.by_check()[CHANNELS_CHECK]['Status'] == 'Compliant'
    assert [(r['Skipped check'], r['Reason']) for r in s.not_checked()] == [(f"{CHANNELS_CHECK} (the topics of {P} could not be listed; the Pub/Sub channel's topic is not verified)", 'listing down')]
    gcp.assets.list_errors.clear()
    gcp.assets.add_asset('pubsub.googleapis.com/Topic', f'//pubsub.googleapis.com/{TOPIC}', {}, project_number=N)
    gcp.assets.iam_error = RuntimeError('search down')
    s = Sink()
    check_alert_channels(ORG, [{'projectId': P, 'projectNumber': N}], JOB, sink=s)
    assert s.by_check()[CHANNELS_CHECK]['Status'] == 'Compliant'
    assert [(r['Skipped check'], r['Reason']) for r in s.not_checked()] == [(f"{CHANNELS_CHECK} (the IAM-policy search in {P} failed; the notification agent's grant is not verified)", 'search down')]


def test_check_synthetic_coverage_end_to_end(gcp):
    gcp.assets.add_asset('compute.googleapis.com/GlobalForwardingRule', f'//compute.googleapis.com/projects/{P}/global/forwardingRules/edge-fr', {'name': 'edge-fr', 'loadBalancingScheme': 'EXTERNAL', 'IPAddress': '34.1.2.3'}, project_number=N)
    gcp.assets.add_asset('compute.googleapis.com/ForwardingRule', f'//compute.googleapis.com/projects/{P}/regions/asia-south1/forwardingRules/ilb', {'name': 'ilb', 'loadBalancingScheme': 'INTERNAL'}, project_number=N)
    gcp.assets.add_asset('run.googleapis.com/Service', '//run.googleapis.com/projects/222/locations/asia-south1/services/web', {}, project_number='222')
    gcp.assets.add_asset('container.googleapis.com/Cluster', '//container.googleapis.com/projects/stark-gke/locations/asia-south1/clusters/c1', {}, project_number='333')
    gcp.assets.add('projects', 'stark-run', 'Run', project_number='222', organization=ORG)
    service = f'projects/{P}/services/web'
    gcp.discovery.apis['monitoring'] = FakeMonitoring(uptime={P: [uptime('edge', '34.1.2.3')]}, services={P: [{'name': service}]}, slos={service: [slo('web', 'availability')]},
                                                      policies={P: [policy('burn', condition={'conditionThreshold': {'filter': f'select_slo_burn_rate("{service}/serviceLevelObjectives/availability", "60m")'}})]})
    s = Sink()
    check_synthetic_coverage('organization', ORG, JOB, sink=s)
    record = s.by_check()[SYNTHETIC_CHECK]
    assert record['Status'] == 'Investigation Recommended'
    assert [(r['Project'], r['Resource'], r['Issue']) for r in record['Finding']] == [('stark-gke', '—', 'No SLO.'), ('stark-run', '—', 'No SLO.'), (P, 'edge', 'No alert policy.')]
    assert s.not_checked() == []
    assert gcp.assets.list_requests[0]['asset_types'] == list(alerting.SYNTHETIC_TYPES) and gcp.assets.list_requests[0]['parent'] == f'organizations/{ORG}'
    calls = gcp.discovery.apis['monitoring'].calls
    assert calls[:3] == [('uptime', 'projects/stark-gke'), ('services', 'projects/stark-gke'), ('uptime', 'projects/stark-run')]  # the service named by number was renamed
    assert ('policies', f'projects/{P}') in calls and ('policies', 'projects/stark-gke') not in calls  # policies read only where an uptime check or SLO needs them
    assert ('slos', service) in calls
    # Nothing running: all clear with no Monitoring call.
    gcp.assets.assets.clear()
    gcp.discovery.apis['monitoring'] = FakeMonitoring()
    s = Sink()
    check_synthetic_coverage('project', P, JOB, sink=s)
    assert s.by_check()[SYNTHETIC_CHECK] == {'Check': SYNTHETIC_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': alerting.SYNTHETIC_ALL_CLEAR}]}
    assert gcp.discovery.apis['monitoring'].calls == []


def test_check_synthetic_coverage_failures(gcp):
    gcp.assets.list_errors['compute.googleapis.com/ForwardingRule'] = RuntimeError('inventory down')
    s = Sink()
    check_synthetic_coverage('organization', ORG, JOB, sink=s)
    assert s.by_check()[SYNTHETIC_CHECK] == {'Check': SYNTHETIC_CHECK, 'Status': 'Error', 'Finding': [{'Error': 'inventory down'}]}
    gcp.assets.list_errors.clear()
    gcp.assets.add_asset('compute.googleapis.com/GlobalForwardingRule', f'//compute.googleapis.com/projects/{P}/global/forwardingRules/edge-fr', {'name': 'edge-fr', 'IPAddress': '34.1.2.3'}, project_number=N)
    gcp.assets.add_asset('run.googleapis.com/Service', '//run.googleapis.com/projects/222/locations/asia-south1/services/web', {}, project_number='222')
    gcp.assets.error = RuntimeError('search down')  # the project search for the number-named project fails: it stays named by number
    gcp.discovery.apis['monitoring'] = FakeMonitoring(errors={'uptime': RuntimeError('monitoring down')})
    s = Sink()
    check_synthetic_coverage('organization', ORG, JOB, sink=s)
    assert s.by_check()[SYNTHETIC_CHECK]['Status'] == 'Compliant'
    assert [(r['Project'], r['Skipped check'], r['Reason']) for r in s.not_checked()] == [
        (f'organizations/{ORG}', f'{SYNTHETIC_CHECK} (project names: the project search failed; the projects named by number stay so)', 'search down'),
        ('222', SYNTHETIC_CHECK, 'monitoring down'), (P, SYNTHETIC_CHECK, 'monitoring down')]
