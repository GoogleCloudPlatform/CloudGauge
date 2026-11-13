"""
v18.6 — Serverless and edge exposure, the edge half: the rules of ``app.checks.edge_security`` (Cloud Armor Policy Content, SSL
Certificate Health) on fixtures of the shapes Asset Inventory and the Compute API return, the bundled ruleset table, and the check
end to end; plus the v18.6 IAP-over-HTTP row of Load Balancer Edge.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.checks import edge_security as es, network_edge as ne, registry
from app.checks.categories import CATEGORY_MAP
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS

JOB = 'job-186'
AR, IR, INFO, C = 'Action Required', 'Investigation Recommended', 'Informational', 'Compliant'
PROJECT = 'stark-edge-prod'
COMPUTE = f'https://www.googleapis.com/compute/v1/projects/{PROJECT}'
NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
DEFAULT_RULE = {'priority': 2147483647, 'action': 'allow', 'match': {'versionedExpr': 'SRC_IPS_V1', 'config': {'srcIpRanges': ['*']}}, 'preview': False}


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


def asset(path, data, project=PROJECT):
    data = {'selfLink': f'https://www.googleapis.com/compute/v1/projects/{project}/{path}', **data}
    return SimpleNamespace(name=f'//compute.googleapis.com/projects/{project}/{path}', resource=SimpleNamespace(data=data))


def waf_rule(priority, expression, action='deny-403', preview=False, exclusions=None):
    rule = {'priority': priority, 'action': action, 'preview': preview, 'match': {'expr': {'expression': expression}}}
    if exclusions:
        rule['preconfiguredWafConfig'] = {'exclusions': exclusions}
    return rule


def ip_rule(priority, action='deny-403', preview=False, ranges=('203.0.113.0/24',)):
    return {'priority': priority, 'action': action, 'preview': preview, 'match': {'versionedExpr': 'SRC_IPS_V1', 'config': {'srcIpRanges': list(ranges)}}}


def policy(name, rules, kind='CLOUD_ARMOR', adaptive=False, region=None, **extra):
    data = {'name': name, 'type': kind, 'rules': [*rules, DEFAULT_RULE] if not any(r['priority'] == 2147483647 for r in rules) else list(rules), **extra}
    if adaptive:
        data['adaptiveProtectionConfig'] = {'layer7DdosDefenseConfig': {'enable': True}}
    return asset(f'regions/{region}/securityPolicies/{name}' if region else f'global/securityPolicies/{name}', data)


def backend(name, policy_name=None, scheme='EXTERNAL_MANAGED', iap=False, region=None):
    data = {'name': name, 'loadBalancingScheme': scheme, 'protocol': 'HTTPS', 'logConfig': {'enable': True}}
    if policy_name:
        data['securityPolicy'] = f'{COMPUTE}/global/securityPolicies/{policy_name}'
    if iap:
        data['iap'] = {'enabled': True}
    return asset(f'regions/{region}/backendServices/{name}' if region else f'global/backendServices/{name}', data)


def certificate(name, kind='SELF_MANAGED', expires_in=None, status=None, domains=('www.example.test',), created_days_ago=10, region=None):
    data = {'name': name, 'type': kind, 'creationTimestamp': (NOW - timedelta(days=created_days_ago)).isoformat()}
    if expires_in is not None:
        data['expireTime'] = (NOW + timedelta(days=expires_in)).isoformat()
    if kind == 'MANAGED':
        data['managed'] = {'domains': list(domains), 'status': status or 'ACTIVE', 'domainStatus': {d: ('FAILED_NOT_VISIBLE' if status and status.startswith('PROVISIONING_FAILED') else 'ACTIVE') for d in domains}}
    else:
        data['subjectAlternativeNames'] = list(domains)
    return asset(f'regions/{region}/sslCertificates/{name}' if region else f'global/sslCertificates/{name}', data)


def https_proxy(name, *cert_names, region=None):
    scope = f'regions/{region}' if region else 'global'
    return asset(f'{scope}/targetHttpsProxies/{name}', {'name': name, 'urlMap': f'{COMPUTE}/{scope}/urlMaps/{name}-map', 'sslCertificates': [f'{COMPUTE}/{scope}/sslCertificates/{c}' for c in cert_names]})


def grouped_of(*assets):
    return es.by_kind(list(assets))


# --- the ruleset table ---------------------------------------------------------------------------------------------------------

def test_the_bundled_ruleset_table_is_complete_and_consistent():
    table = es.rulesets()
    assert table['current'] == 'v422' and all(new.split('-')[1] == 'v422' for new in table['legacy'].values())
    assert {name.split('-')[0] for name in table['legacy']} >= {'sqli', 'xss', 'lfi', 'rfi', 'rce', 'methodenforcement', 'scannerdetection', 'protocolattack', 'php', 'sessionfixation', 'java', 'nodejs'}
    assert table['legacy']['nodejs-v33-stable'] == 'generic-v422-stable' and table['legacy']['sqli-stable'] == 'sqli-v422-stable' and len(table['retired_ids']) == 15
    assert table['signatures']['rce'] == {'3.0': 11, '3.3': 15, 'current': 44} and 'cve-canary' in table['standalone']


# --- Cloud Armor Policy Content ------------------------------------------------------------------------------------------------

def test_legacy_rulesets_retired_ids_and_signature_notes():
    table = es.rulesets()
    legacy = waf_rule(1000, "evaluatePreconfiguredExpr('sqli-stable', ['owasp-crs-v030001-id942110-sqli', 'owasp-crs-v030001-id942120-sqli']) || evaluatePreconfiguredWaf('xss-v33-stable')")
    assert es.legacy_rulesets(legacy, table) == [('sqli-stable', 'sqli-v422-stable'), ('xss-v33-stable', 'xss-v422-stable')]
    assert es.retired_ids(legacy, table) == ['942110']
    assert es.legacy_rulesets(waf_rule(1, "evaluatePreconfiguredWaf('sqli-v422-stable', {'sensitivity': 2})"), table) == []
    assert es.legacy_rulesets(waf_rule(1, "evaluatePreconfiguredExpr('cve-canary') || evaluatePreconfiguredExpr('sourceiplist-cloudflare')"), table) == []  # standalone rulesets never count
    assert es.legacy_rulesets(waf_rule(1, "evaluatePreconfiguredExpr('sqli-v422-stable')"), table) == [('sqli-v422-stable', 'sqli-v422-stable')]  # legacy syntax on a current name
    excluded = waf_rule(1, "evaluatePreconfiguredWaf('rce-v422-stable')", exclusions=[{'targetRuleSet': 'rce-v33-stable', 'targetRuleIds': ['owasp-crs-v030301-id932100-rce']}])
    assert es.legacy_rulesets(excluded, table) == [('rce-v33-stable', 'rce-v422-stable')] and es.retired_ids(excluded, table) == ['932100']
    assert es.signature_note('rce-v33-stable', 'rce-v422-stable', table) == 'rce: 15 → 44 signatures' and es.signature_note('sqli-stable', 'sqli-v422-stable', table) == 'sqli: 38 → 60 signatures'
    assert es.signature_note('sessionfixation-stable', 'sessionfixation-v422-stable', table) == 'sessionfixation: same signatures, current syntax'
    assert es.signature_note('sqli-v422-stable', 'sqli-v422-stable', table) == '' and es.signature_note('nodejs-v33-stable', 'generic-v422-stable', table) == 'nodejs: 1 → 10 signatures'


def test_armor_rows_for_legacy_empty_preview_and_quota_on_attached_l7_policies():
    grouped = grouped_of(
        policy('legacy', [waf_rule(1000, "evaluatePreconfiguredExpr('sqli-stable', ['owasp-crs-v030001-id942110-sqli'])", preview=True),
                          waf_rule(2000, "evaluatePreconfiguredWaf('methodenforcement-v33-stable')"), ip_rule(3000, action='allow')]),
        policy('empty', []), policy('geo', [ip_rule(100, action='allow', ranges=('10.0.0.0/8',))]), policy('blocklist', [ip_rule(100)]),
        policy('allowlist', [ip_rule(100, action='allow')], rules_default='deny-403'),
        policy('preview-only', [waf_rule(1000, "evaluatePreconfiguredWaf('sqli-v422-stable')", preview=True), waf_rule(1100, "evaluatePreconfiguredWaf('xss-v422-stable')", preview=True)]),
        policy('modern', [waf_rule(1000, "evaluatePreconfiguredWaf('sqli-v422-stable')"), waf_rule(1100, "evaluatePreconfiguredWaf('xss-v422-stable')", preview=True)]),
        policy('big', [waf_rule(1000 + i, "evaluatePreconfiguredWaf('sqli-v422-stable')") for i in range(185)]),
        policy('unattached', [waf_rule(1000, "evaluatePreconfiguredExpr('sqli-stable')")]),
        policy('netpol', [], kind='CLOUD_ARMOR_NETWORK'), policy('ddos', [], kind='CLOUD_ARMOR_NETWORK', ddosProtectionConfig={'ddosProtection': 'ADVANCED'}),
        backend('bes-legacy', 'legacy'), backend('bes-empty', 'empty'), backend('bes-geo', 'geo'), backend('bes-block', 'blocklist'), backend('bes-allow', 'allowlist'),
        backend('bes-preview', 'preview-only'), backend('bes-modern', 'modern'), backend('bes-big', 'big'), backend('bes-net', 'netpol'), backend('bes-ddos', 'ddos'),
        backend('bes-internal', 'unattached', scheme='INTERNAL_MANAGED'))
    # The 'allowlist' policy: a default deny with an allow rule is an allowlist — protective, no row.
    for p in grouped['securityPolicies']:
        if p['name'] == 'allowlist':
            p['data']['rules'][-1] = {**DEFAULT_RULE, 'action': 'deny-403'}
    rows = es.armor_rows(grouped)
    assert [(r['Policy'], r['Rule'], r['Issue'], r['_status']) for r in rows] == [
        ('legacy', '1000 (deny-403, preview)', 'Legacy WAF ruleset.', IR), ('legacy', '2000 (deny-403)', 'Legacy WAF ruleset.', IR), ('legacy', '1000', 'Preview rules left behind.', INFO),
        ('empty', '—', 'Policy protects nothing.', IR), ('geo', '—', 'Policy protects nothing.', IR),
        ('preview-only', '1000, 1100', 'WAF not enforcing.', IR), ('modern', '1100', 'Preview rules left behind.', INFO), ('big', '—', 'Near the rule quota.', INFO)]
    by_rule = {(r['Policy'], r['Rule']): r for r in rows}
    legacy = by_rule[('legacy', '1000 (deny-403, preview)')]
    assert legacy['Detail'] == ('Uses sqli-stable — OWASP CRS 3.0 (sqli: 38 → 60 signatures); the current generation is sqli-v422-stable and evaluatePreconfiguredExpr is being retired. '
                                'Drop the retired signature IDs 942110 from the opt-out list.')
    assert legacy['Fix'] == (f"gcloud compute security-policies rules create 999 --security-policy=legacy --project={PROJECT} --expression=\"evaluatePreconfiguredWaf('sqli-v422-stable')\" "
                             f"--action=deny-403 --preview  # watch the logs, then gcloud compute security-policies rules update 999 --security-policy=legacy --project={PROJECT} --no-preview "
                             f"&& gcloud compute security-policies rules delete 1000 --security-policy=legacy --project={PROJECT}")
    assert 'methodenforcement blocks PUT, PATCH and DELETE' in by_rule[('legacy', '2000 (deny-403)')]['Detail'] and legacy['Attached to'] == 'bes-legacy'
    assert by_rule[('empty', '—')]['Detail'].startswith('only the default rule: no WAF ruleset, no deny or throttle rule, Layer-7 DDoS defense off')
    assert by_rule[('geo', '—')]['Detail'].startswith('1 allow rule(s) over a default allow')
    assert by_rule[('empty', '—')]['Fix'].startswith(f"gcloud compute security-policies rules create 1000 --security-policy=empty --project={PROJECT} --expression=\"evaluatePreconfiguredWaf('sqli-v422-stable')")
    assert by_rule[('empty', '—')]['Fix'].endswith(f'gcloud compute security-policies update empty --project={PROJECT} --enable-layer7-ddos-defense')
    assert by_rule[('preview-only', '1000, 1100')]['Fix'] == f'gcloud compute security-policies rules update 1000 --security-policy=preview-only --project={PROJECT} --no-preview  # after reviewing the preview matches in the load balancer logs'
    assert by_rule[('big', '—')]['Detail'] == '186 of 200 rules: a preview-mode upgrade needs headroom for its parallel rules.'
    assert all(set(r) == {'Project', 'Policy', 'Attached to', 'Rule', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    # Adaptive protection alone counts as protection; a regional policy carries --region in its fixes; nothing attached → no rows.
    regional = grouped_of(policy('edge', [], adaptive=True, region='asia-south1'), backend('bes', region='asia-south1'))
    regional['backendServices'][0]['data']['securityPolicy'] = f'{COMPUTE}/regions/asia-south1/securityPolicies/edge'
    assert es.armor_rows(regional) == []
    regional = grouped_of(policy('edge', [waf_rule(1000, "evaluatePreconfiguredExpr('xss-stable')")], region='asia-south1'), backend('bes', region='asia-south1'))
    regional['backendServices'][0]['data']['securityPolicy'] = f'{COMPUTE}/regions/asia-south1/securityPolicies/edge'
    assert es.armor_rows(regional)[0]['Fix'].startswith(f'gcloud compute security-policies rules create 999 --security-policy=edge --project={PROJECT} --region=asia-south1 --expression=')
    assert es.armor_rows(grouped_of(policy('lonely', []))) == []
    # The API spells a rule's action deny(403); the row and its Fix use gcloud's deny-403 (the first canary read the API's spelling).
    api_shape = grouped_of(policy('legacy', [waf_rule(1000, "evaluatePreconfiguredExpr('sqli-stable')", action='deny(403)', preview=True)]), backend('bes', 'legacy'))
    rows = es.armor_rows(api_shape)
    assert [r['Rule'] for r in rows] == ['1000 (deny-403, preview)', '1000'] and '--action=deny-403 --preview' in rows[0]['Fix']
    assert es.gcloud_action('deny(404)') == 'deny-404' and es.gcloud_action('throttle') == 'throttle' and es.gcloud_action(None) == 'deny-403'


# --- SSL Certificate Health ------------------------------------------------------------------------------------------------------

def test_certificate_rows_by_type_expiry_status_and_attachment():
    grouped = grouped_of(certificate('soon', expires_in=20), certificate('critical', expires_in=5), certificate('gone', expires_in=-3), certificate('fine', expires_in=200),
                         certificate('orphan-expired', expires_in=-40), certificate('orphan-soon', expires_in=3),
                         certificate('managed-ok', 'MANAGED', expires_in=60), certificate('managed-failed', 'MANAGED', status='PROVISIONING_FAILED'),
                         certificate('managed-renewal', 'MANAGED', status='RENEWAL_FAILED', expires_in=10), certificate('managed-stuck', 'MANAGED', status='PROVISIONING', created_days_ago=3),
                         certificate('managed-fresh', 'MANAGED', status='PROVISIONING', created_days_ago=0),
                         https_proxy('edge', 'soon', 'critical', 'gone', 'fine', 'managed-ok', 'managed-failed', 'managed-renewal', 'managed-stuck', 'managed-fresh'))
    rows = es.certificate_rows(grouped, NOW)
    assert [(r['Certificate'], r['Type'], r['Issue'], r['_status']) for r in rows] == [
        ('soon', 'self-managed', 'Certificate expiring.', IR), ('critical', 'self-managed', 'Certificate expiring.', AR), ('gone', 'self-managed', 'Certificate expired.', AR),
        ('orphan-expired', 'self-managed', 'Expired certificate left behind.', INFO),
        ('managed-failed', 'Google-managed', 'Managed certificate failed.', AR), ('managed-renewal', 'Google-managed', 'Managed certificate failed.', AR),
        ('managed-stuck', 'Google-managed', 'Managed certificate stuck provisioning.', IR)]
    by_name = {r['Certificate']: r for r in rows}
    assert by_name['soon']['Expires / Status'] == 'in 20 day(s)' and by_name['gone']['Expires / Status'] == 'expired 3 day(s) ago' and by_name['soon']['Attached to'] == 'edge'
    assert by_name['soon']['Fix'] == (f'gcloud compute ssl-certificates create soon-202611 --domains=www.example.test --global --project={PROJECT} && gcloud compute target-https-proxies update edge '
                                      f'--ssl-certificates=soon-202611 --global --project={PROJECT}  # Google-managed renews itself')
    assert by_name['managed-failed']['Detail'].startswith('Status PROVISIONING_FAILED; domains www.example.test (FAILED_NOT_VISIBLE) on edge: the certificate will not issue or renew')
    assert by_name['managed-failed']['Fix'].startswith('point the DNS records of www.example.test at the load balancer')
    assert by_name['orphan-expired']['Fix'] == f'gcloud compute ssl-certificates delete orphan-expired --global --project={PROJECT} --quiet'
    assert all(set(r) == {'Project', 'Certificate', 'Type', 'Attached to', 'Expires / Status', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    # Regional certificates and proxies carry --region; a Compute timestamp with an offset parses.
    regional = grouped_of(certificate('r-soon', expires_in=2, region='asia-south1'), https_proxy('r-edge', 'r-soon', region='asia-south1'))
    assert es.certificate_rows(regional, NOW)[0]['Fix'].startswith(f'gcloud compute ssl-certificates create r-soon-202611 --domains=www.example.test --region=asia-south1 --project={PROJECT}')
    assert es.parse_time('2026-12-01T00:00:00.000-08:00') == datetime(2026, 12, 1, 8, tzinfo=timezone.utc) and es.parse_time('') is None and es.parse_time('soon') is None


# --- the check end to end ------------------------------------------------------------------------------------------------------------

class Inventory:
    def __init__(self, assets=(), error=None):
        self.assets, self.error, self.requests = list(assets), error, []

    def list_assets(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return list(self.assets)


class Compute:
    """``securityPolicies().aggregatedList`` and ``sslCertificates().aggregatedList`` per project (``None`` for a collection: the inventory's copy stands)."""
    def __init__(self, policies=None, certificates=None, error=None):
        self.policies, self.certificates, self.error, self.listed = policies, certificates, error, []
        self._collection = None

    def securityPolicies(self):
        self._collection = 'securityPolicies'
        return self

    def sslCertificates(self):
        self._collection = 'sslCertificates'
        return self

    def aggregatedList(self, project):
        self.listed.append((self._collection, project))
        return self

    def aggregatedList_next(self, previous_request, previous_response):
        return None

    def execute(self):
        if self.error:
            raise self.error
        items = self.policies if self._collection == 'securityPolicies' else self.certificates
        if items is None:
            items = [a for a in INVENTORY if f'/{self._collection}/' in a.name]
        return {'items': {'global': {self._collection: [dict(a.resource.data) for a in items]}}}


INVENTORY = [policy('legacy', [waf_rule(1000, "evaluatePreconfiguredExpr('sqli-stable')")]), backend('bes', 'legacy'),
             certificate('soon', expires_in=20), https_proxy('edge', 'soon')]


def test_check_edge_security_end_to_end(gcp, monkeypatch):
    inventory, compute = Inventory(INVENTORY), Compute()
    monkeypatch.setattr(es.gcp, 'asset_client', lambda credentials=None: inventory)
    monkeypatch.setattr(es.gcp, 'api_build', lambda *args, **kwargs: compute)
    sink = Sink()
    es.check_edge_security('organization', '987654321', JOB, sink=sink, now=NOW)
    records = sink.by_check()
    assert {name: record['Status'] for name, record in records.items()} == {'Cloud Armor Policy Content': IR, 'SSL Certificate Health': IR}
    assert [(r['Policy'], r['Issue']) for r in records['Cloud Armor Policy Content']['Finding']] == [('legacy', 'Legacy WAF ruleset.')]
    assert [(r['Certificate'], r['Issue']) for r in records['SSL Certificate Health']['Finding']] == [('soon', 'Certificate expiring.')]
    assert inventory.requests[0]['asset_types'] == es.EDGE_SECURITY_TYPES and compute.listed == [('securityPolicies', PROJECT), ('sslCertificates', PROJECT)] and sink.not_checked() == []
    assert all('_status' not in r for record in records.values() for r in record['Finding'])
    # The API is the copy of record: the policy was upgraded and the certificate replaced since the inventory's snapshot.
    compute = Compute(policies=[policy('legacy', [waf_rule(1000, "evaluatePreconfiguredWaf('sqli-v422-stable')")])], certificates=[certificate('soon', expires_in=300)])
    monkeypatch.setattr(es.gcp, 'api_build', lambda *args, **kwargs: compute)
    sink = Sink()
    es.check_edge_security('organization', '987654321', JOB, sink=sink, now=NOW)
    assert {name: record['Finding'] for name, record in sink.by_check().items()} == {'Cloud Armor Policy Content': [{'Status': es.ARMOR_ALL_CLEAR}], 'SSL Certificate Health': [{'Status': es.CERTIFICATE_ALL_CLEAR}]}
    # The API reads failing: the inventory's copy serves, and Projects not checked says so.
    monkeypatch.setattr(es.gcp, 'api_build', lambda *args, **kwargs: Compute(error=RuntimeError('403 compute.securityPolicies.list denied')))
    sink = Sink()
    es.check_edge_security('project', PROJECT, JOB, sink=sink, now=NOW)
    assert [r['Policy'] for r in sink.by_check()['Cloud Armor Policy Content']['Finding']] == ['legacy']
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [
        (PROJECT, "Cloud Armor Policy Content (Cloud Armor policies: the Compute API read failed; the inventory's copy was used, which can lag changes by hours)"),
        (PROJECT, "Cloud Armor Policy Content (certificates: the Compute API read failed; the inventory's copy was used, which can lag changes by hours)")]
    # Nothing in scope: two all-clear rows and no API read. A listing that fails: two Errors.
    compute = Compute()
    monkeypatch.setattr(es.gcp, 'asset_client', lambda credentials=None: Inventory())
    monkeypatch.setattr(es.gcp, 'api_build', lambda *args, **kwargs: compute)
    sink = Sink()
    es.check_edge_security('folder', '42', JOB, sink=sink)
    assert {record['Status'] for record in sink.by_check().values()} == {C} and compute.listed == []
    monkeypatch.setattr(es.gcp, 'asset_client', lambda credentials=None: Inventory(error=RuntimeError('503 inventory unavailable')))
    sink = Sink()
    es.check_edge_security('folder', '42', JOB, sink=sink)
    assert {name: record['Status'] for name, record in sink.by_check().items()} == {'Cloud Armor Policy Content': 'Error', 'SSL Certificate Health': 'Error'}


# --- Load Balancer Edge: IAP over HTTP (v18.6) ------------------------------------------------------------------------------------------

def test_load_balancer_edge_flags_iap_behind_an_http_only_load_balancer():
    def forwarding(name, proxy_kind, proxy, port):
        return asset(f'global/forwardingRules/{name}', {'name': name, 'loadBalancingScheme': 'EXTERNAL_MANAGED', 'portRange': f'{port}-{port}', 'target': f'{COMPUTE}/global/{proxy_kind}/{proxy}'})

    def url_map(name, default, paths=()):
        return asset(f'global/urlMaps/{name}', {'name': name, 'defaultService': f'{COMPUTE}/global/backendServices/{default}',
                                                 'pathMatchers': [{'name': 'm', 'defaultService': f'{COMPUTE}/global/backendServices/{default}',
                                                                   'pathRules': [{'paths': ['/api/*'], 'service': f'{COMPUTE}/global/backendServices/{s}'} for s in paths]}]})
    grouped = ne.by_kind([
        forwarding('fr-http', 'targetHttpProxies', 'proxy-http', 80), asset('global/targetHttpProxies/proxy-http', {'name': 'proxy-http', 'urlMap': f'{COMPUTE}/global/urlMaps/map-http'}),
        url_map('map-http', 'bes-iap', ['bes-plain']),
        forwarding('fr-both-http', 'targetHttpProxies', 'proxy-both-http', 80), forwarding('fr-both-https', 'targetHttpsProxies', 'proxy-both-https', 443),
        asset('global/targetHttpProxies/proxy-both-http', {'name': 'proxy-both-http', 'urlMap': f'{COMPUTE}/global/urlMaps/map-both'}),
        asset('global/targetHttpsProxies/proxy-both-https', {'name': 'proxy-both-https', 'urlMap': f'{COMPUTE}/global/urlMaps/map-both', 'sslPolicy': f'{COMPUTE}/global/sslPolicies/modern'}),
        asset('global/sslPolicies/modern', {'name': 'modern', 'profile': 'MODERN', 'minTlsVersion': 'TLS_1_2'}), url_map('map-both', 'bes-iap-tls'),
        backend('bes-iap', 'edge', iap=True), backend('bes-plain', 'edge'), backend('bes-iap-tls', 'edge', iap=True)])
    rows = ne.edge_rows(grouped)
    assert [(r['Load Balancer'], r['Issue']) for r in rows] == [('fr-http', 'HTTP-only load balancer.'), ('bes-iap', 'IAP over HTTP.')]
    assert rows[1]['Detail'].startswith('backend service bes-iap has Identity-Aware Proxy on, behind an HTTP-only load balancer') and rows[1]['Fix'].startswith('add an HTTPS forwarding rule')
    assert 'compute.googleapis.com/UrlMap' in ne.EDGE_TYPES
    assert ne.url_map_services({'defaultService': 'a', 'pathMatchers': [{'defaultService': 'b', 'pathRules': [{'service': 'c'}], 'routeRules': [{'service': 'd', 'routeAction': {'weightedBackendServices': [{'backendService': 'e'}]}}]}]}) == ['a', 'b', 'c', 'd', 'e']


def test_the_two_names_are_catalogued_scope_level_and_new():
    assert CATEGORY_MAP[es.ARMOR_CHECK] == 'Security & Identity' and CATEGORY_MAP[es.CERTIFICATE_CHECK] == 'Reliability & Resilience'
    assert es.ARMOR_CHECK in registry.SCOPE_LEVEL_CHECKS and not any(name in RESHAPED_CHECKS for name in es.EDGE_SECURITY_CHECKS)
    assert 'Load Balancer Edge' not in RESHAPED_CHECKS  # the IAP row is a new kind of row; the existing rows keep their identity
