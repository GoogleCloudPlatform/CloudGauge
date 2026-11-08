"""
v18.3 — Network edge & reachability: the rules of ``app.checks.network_edge`` on fixtures of the real shapes read from the inventory
in the plan (the production tunnel, gateway, routers, subnets, zone, forwarding rule), the fresh tunnel read, the five checks end to end,
and the firewall-policy and legacy-network extensions of ``security``.
"""
from types import SimpleNamespace

from app.checks import network_edge as edge
from app.checks import security
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS, RULE_CHANGED

JOB = 'job-183'
AR, IR, INFO, C = 'Action Required', 'Investigation Recommended', 'Informational', 'Compliant'
P = 'https://www.googleapis.com/compute/v1/projects/stark-nw-prod'


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


def asset(path, data, service='compute', project='stark-nw-prod'):
    return SimpleNamespace(name=f'//{service}.googleapis.com/projects/{project}/{path}', resource=SimpleNamespace(data=data))


# --- the production shapes ---------------------------------------------------------------------------------------------

def tunnel(name='vbbn', status='NO_INCOMING_PACKETS', detail='No incoming packets from peer', interface=0, gateway='allow-image'):
    return asset(f'regions/asia-south1/vpnTunnels/{name}', {'name': name, 'status': status, 'detailedStatus': detail, 'vpnGatewayInterface': interface,
                                                             'vpnGateway': f'{P}/regions/asia-south1/vpnGateways/{gateway}', 'router': f'{P}/regions/asia-south1/routers/vpn',
                                                             'region': f'{P}/regions/asia-south1'})


def gateway(name='allow-image'):
    return asset(f'regions/asia-south1/vpnGateways/{name}', {'name': name, 'network': f'{P}/global/networks/stark-nw-prod-shared-vpc', 'vpnInterfaces': [{'id': 0}, {'id': 1}],
                                                              'selfLink': f'{P}/regions/asia-south1/vpnGateways/{name}'})


def router(name='vpn', peers=1, nats=()):
    return asset(f'regions/asia-south1/routers/{name}', {'name': name, 'network': f'{P}/global/networks/stark-nw-prod-shared-vpc', 'bgp': {'asn': 65534},
                                                          'bgpPeers': [{'name': f'peer-{i}', 'enable': 'TRUE'} for i in range(peers)], 'nats': list(nats),
                                                          'selfLink': f'{P}/regions/asia-south1/routers/{name}'})


PROD_NAT = {'name': 'prod-nat', 'enableDynamicPortAllocation': False, 'logConfig': {'enable': False, 'filter': 'ALL'}, 'natIpAllocateOption': 'AUTO_ONLY'}
SWG_NAT = {'name': 'swg-autogen-nat', 'logConfig': {'enable': True, 'filter': 'ERRORS_ONLY'}, 'natIpAllocateOption': 'AUTO_ONLY'}


def network(name, mtu=None, peerings=(), project='stark-nw-prod', **extra):
    data = {'name': name, 'selfLink': f'https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{name}', 'peerings': list(peerings), **extra}
    if mtu:
        data['mtu'] = mtu
    return asset(f'global/networks/{name}', data, project=project)


def peering(peer_project, peer_network, state='ACTIVE', name=None):
    return {'name': name or f'to-{peer_network}', 'network': f'https://www.googleapis.com/compute/v1/projects/{peer_project}/global/networks/{peer_network}', 'state': state}


def subnet(name, region='asia-south1', purpose='PRIVATE', flow_logs=False, **extra):
    return asset(f'regions/{region}/subnetworks/{name}', {'name': name, 'region': f'{P}/regions/{region}', 'network': f'{P}/global/networks/stark-nw-prod-shared-vpc',
                                                           'purpose': purpose, 'enableFlowLogs': flow_logs, 'logConfig': {'enable': flow_logs}, **extra})


def zone(name='aura-public-zone', dns_name='example-org.test.', visibility='public', state=None, algorithm=None):
    config = {}
    if state:
        config['state'] = state
    if algorithm:
        config['defaultKeySpecs'] = [{'algorithm': algorithm, 'keyType': 'keySigning'}, {'algorithm': algorithm, 'keyType': 'zoneSigning'}]
    return asset(f'managedZones/{name}', {'name': name, 'dnsName': dns_name, 'visibility': visibility, 'dnssecConfig': config}, service='dns')


def dns_policy(networks, logging=True):
    return asset('policies/dns-logging', {'name': 'dns-logging', 'enableLogging': logging, 'networks': [{'networkUrl': f'{P}/global/networks/{n}'} for n in networks]}, service='dns')


# --- facts -------------------------------------------------------------------------------------------------------------

def test_asset_fact_reads_kind_project_region_and_link():
    fact = edge.asset_fact(tunnel())
    assert (fact['kind'], fact['project_id'], fact['region'], fact['name']) == ('vpnTunnels', 'stark-nw-prod', 'asia-south1', 'vbbn')
    assert edge.asset_fact(network('x'))['region'] == 'global' and edge.asset_fact(zone())['kind'] == 'managedZones'
    assert edge.key('https://www.googleapis.com/compute/beta/projects/p/global/networks/n') == edge.key(f'{P}/global/networks/n'.replace('stark-nw-prod', 'p')) == 'p/global/networks/n'
    assert edge.same_link(f'{P}/regions/r/routers/a', 'https://www.googleapis.com/compute/beta/projects/stark-nw-prod/regions/r/routers/a')
    grouped = edge.by_kind([tunnel(), gateway(), router()])
    assert sorted(grouped) == ['routers', 'vpnGateways', 'vpnTunnels']


# --- Hybrid Connectivity -----------------------------------------------------------------------------------------------

def test_hybrid_rows_of_the_production_gateway_and_of_a_redundant_one():
    rows = edge.hybrid_rows(edge.by_kind([tunnel(), gateway(), router()]))
    assert [(r['Resource'], r['Issue'], r['_status']) for r in rows] == [
        ('tunnel vbbn', 'VPN tunnel not established.', AR), ('HA VPN gateway allow-image', 'Tunnels on one interface only.', AR)]
    assert rows[0]['Detail'] == 'NO_INCOMING_PACKETS: No incoming packets from peer.' and rows[0]['Network'] == 'stark-nw-prod-shared-vpc'
    assert rows[1]['Detail'].startswith('interface 0 only: no redundancy') and '--interface=1' in rows[1]['Fix']
    redundant = [tunnel('t0', 'ESTABLISHED', 'Tunnel is up and running.', 0), tunnel('t1', 'ESTABLISHED', 'Tunnel is up and running.', 1), gateway(), router(peers=2)]
    assert edge.hybrid_rows(edge.by_kind(redundant)) == []
    # Two established tunnels on one BGP peer: the second link carries no routes.
    one_peer = edge.hybrid_rows(edge.by_kind(redundant[:3] + [router(peers=1)]))
    assert [(r['Resource'], r['Issue'], r['_status']) for r in one_peer] == [('Cloud Router vpn', 'One BGP session for two links.', IR)]
    # A gateway without any tunnel; a Classic gateway.
    bare = edge.hybrid_rows(edge.by_kind([gateway('idle'), asset('regions/asia-south1/targetVpnGateways/old', {'name': 'old', 'network': f'{P}/global/networks/n'})]))
    assert [(r['Issue'], r['_status']) for r in bare] == [('HA VPN gateway without a tunnel.', AR), ('Classic VPN gateway.', IR)]


def test_hybrid_rows_interconnect_attachments():
    def attachment(name, domain, status='OS_ACTIVE', router_name='ic'):
        return asset(f'regions/asia-south1/interconnectAttachments/{name}', {'name': name, 'edgeAvailabilityDomain': domain, 'operationalStatus': status,
                                                                             'router': f'{P}/regions/asia-south1/routers/{router_name}'})
    single = edge.hybrid_rows(edge.by_kind([attachment('a1', 'AVAILABILITY_DOMAIN_1')]))
    assert [(r['Issue'], r['_status']) for r in single] == [('Interconnect without a redundant attachment.', AR)] and 'a single attachment' in single[0]['Detail']
    same_domain = edge.hybrid_rows(edge.by_kind([attachment('a1', 'AVAILABILITY_DOMAIN_1'), attachment('a2', 'AVAILABILITY_DOMAIN_1')]))
    assert 'all attachments in AVAILABILITY_DOMAIN_1' in same_domain[0]['Detail']
    assert edge.hybrid_rows(edge.by_kind([attachment('a1', 'AVAILABILITY_DOMAIN_1'), attachment('a2', 'AVAILABILITY_DOMAIN_2'), router('ic', peers=2)])) == []
    down = edge.hybrid_rows(edge.by_kind([attachment('a1', 'AVAILABILITY_DOMAIN_1', 'OS_UNPROVISIONED'), attachment('a2', 'AVAILABILITY_DOMAIN_2')]))
    assert [r['Issue'] for r in down] == ['Interconnect attachment not active.']


def test_the_tunnel_state_is_refreshed_from_the_compute_api():
    class FakeCompute:
        def __init__(self, items=None, error=None):
            self.items, self.error, self.projects = items or {}, error, []

        def vpnTunnels(self):
            return self

        def aggregatedList(self, project):
            self.projects.append(project)
            if self.error:
                raise self.error
            return SimpleNamespace(execute=lambda: {'items': self.items})

        def aggregatedList_next(self, previous_request, previous_response):
            return None
    tunnels = [edge.asset_fact(tunnel())]
    compute = FakeCompute({'regions/asia-south1': {'vpnTunnels': [{'name': 'vbbn', 'status': 'ESTABLISHED', 'detailedStatus': 'Tunnel is up and running.'}]}})
    skipped = security.NotChecked(edge.HYBRID_CHECK)
    edge.refresh_tunnels(tunnels, compute, skipped)
    assert compute.projects == ['stark-nw-prod'] and tunnels[0]['data']['status'] == 'ESTABLISHED'
    assert edge.hybrid_rows({'vpnTunnels': tunnels, 'vpnGateways': [edge.asset_fact(gateway())]})[0]['Issue'] == 'Tunnels on one interface only.'  # the down row is gone
    failing = [edge.asset_fact(tunnel())]
    edge.refresh_tunnels(failing, FakeCompute(error=RuntimeError('403 compute.vpnTunnels.list denied')), skipped)
    assert failing[0]['data']['status'] == 'NO_INCOMING_PACKETS'  # the inventory copy stands
    assert [r['Project'] for r in skipped.rows] == ['stark-nw-prod'] and 'inventory copy' in skipped.rows[0]['Skipped check']


# --- Load Balancer Edge ------------------------------------------------------------------------------------------------

def forwarding_rule(name, target, scheme='EXTERNAL', port='80-80'):
    return asset(f'global/forwardingRules/{name}', {'name': name, 'loadBalancingScheme': scheme, 'portRange': port, 'IPProtocol': 'TCP', 'target': f'{P}/global/{target}'})


def proxy(kind, name, url_map='edge-map', ssl_policy=None):
    collection = {'http': 'targetHttpProxies', 'https': 'targetHttpsProxies', 'ssl': 'targetSslProxies'}[kind]
    data = {'name': name, 'selfLink': f'{P}/global/{collection}/{name}', 'urlMap': f'{P}/global/urlMaps/{url_map}'}
    if ssl_policy:
        data['sslPolicy'] = f'{P}/global/sslPolicies/{ssl_policy}'
    return asset(f'global/{collection}/{name}', data)


def ssl_policy(name, profile='MODERN', minimum='TLS_1_2'):
    return asset(f'global/sslPolicies/{name}', {'name': name, 'selfLink': f'{P}/global/sslPolicies/{name}', 'profile': profile, 'minTlsVersion': minimum})


def backend(name, scheme='EXTERNAL', armor=False, logging=False, region=None):
    data = {'name': name, 'loadBalancingScheme': scheme, 'protocol': 'HTTP', 'logConfig': {'enable': logging}}
    if armor:
        data['securityPolicy'] = f'{P}/global/securityPolicies/edge'
    return asset((f'regions/{region}/backendServices/{name}' if region else f'global/backendServices/{name}'), data)


def test_edge_rows_http_only_weak_tls_armor_and_logging():
    grouped = edge.by_kind([forwarding_rule('web-80', 'targetHttpProxies/web-http'), proxy('http', 'web-http'), backend('web-bes')])
    rows = edge.edge_rows(grouped)
    assert [(r['Load Balancer'], r['Issue'], r['_status']) for r in rows] == [
        ('web-80', 'HTTP-only load balancer.', IR), ('web-bes', 'No Cloud Armor policy.', IR), ('web-bes', 'Load balancer logging off.', IR)]
    assert 'target-https-proxies create web-http-https --url-map=edge-map' in rows[0]['Fix'] and '--security-policy=edge --global' in rows[1]['Fix']
    # The same URL map with an HTTPS rule: no HTTP-only row; the HTTPS proxy without a policy is weak TLS.
    both = edge.by_kind([forwarding_rule('web-80', 'targetHttpProxies/web-http'), proxy('http', 'web-http'),
                         forwarding_rule('web-443', 'targetHttpsProxies/web-https', port='443-443'), proxy('https', 'web-https'), backend('web-bes', armor=True, logging=True)])
    rows = edge.edge_rows(both)
    assert [(r['Load Balancer'], r['Issue']) for r in rows] == [('web-443', 'Weak TLS at the edge.')]
    assert rows[0]['Detail'] == 'web-https: no SSL policy: the default allows TLS 1.0 and the COMPATIBLE cipher set.' and '--ssl-policy=modern-tls' in rows[0]['Fix']
    # Policies: COMPATIBLE or TLS 1.0/1.1 minimum are weak, MODERN/RESTRICTED at 1.2+ are not.
    assert edge.ssl_policy_issue({'profile': 'COMPATIBLE', 'minTlsVersion': 'TLS_1_2'}) == 'profile COMPATIBLE'
    assert edge.ssl_policy_issue({'profile': 'MODERN', 'minTlsVersion': 'TLS_1_1'}) == 'minimum TLS 1.1'
    assert edge.ssl_policy_issue({'profile': 'RESTRICTED', 'minTlsVersion': 'TLS_1_2'}) is None and edge.ssl_policy_issue({'profile': 'MODERN', 'minTlsVersion': 'TLS_1_3'}) is None
    modern = edge.by_kind([forwarding_rule('web-443', 'targetHttpsProxies/web-https', port='443-443'), proxy('https', 'web-https', ssl_policy='modern-tls'), ssl_policy('modern-tls'),
                           backend('web-bes', armor=True, logging=True)])
    assert edge.edge_rows(modern) == []
    # Internal load balancers and internal backend services are not judged; a regional external backend service is, with --region.
    internal = edge.by_kind([forwarding_rule('ilb', 'targetHttpProxies/web-http', scheme='INTERNAL_MANAGED'), proxy('http', 'web-http'), backend('ibes', scheme='INTERNAL_MANAGED')])
    assert edge.edge_rows(internal) == []
    regional = edge.edge_rows(edge.by_kind([backend('nlb-bes', region='asia-south1')]))
    assert [r['Issue'] for r in regional] == ['No Cloud Armor policy.', 'Load balancer logging off.'] and '--region=asia-south1' in regional[0]['Fix']


# --- DNS Posture -------------------------------------------------------------------------------------------------------

def test_dns_rows_dnssec_rsasha1_and_logging():
    grouped = edge.by_kind([zone(), network('stark-nw-prod-shared-vpc'), network('delhi-vpc')])
    rows = edge.dns_rows(grouped)
    assert [(r['Resource'], r['Issue'], r['_status']) for r in rows] == [
        ('zone aura-public-zone (example-org.test.)', 'DNSSEC off on a public zone.', IR),
        ('network stark-nw-prod-shared-vpc', 'Cloud DNS logging off.', IR), ('network delhi-vpc', 'Cloud DNS logging off.', IR)]
    assert rows[0]['Fix'] == 'gcloud dns managed-zones update aura-public-zone --dnssec-state=on --project=stark-nw-prod  # then publish the DS record at the registrar'
    assert rows[1]['Fix'] == 'gcloud dns policies create dns-logging-stark-nw-prod-shared-vpc --networks=stark-nw-prod-shared-vpc --enable-logging --project=stark-nw-prod'
    signed = edge.dns_rows(edge.by_kind([zone(state='on', algorithm='ecdsap256sha256'), network('v'), dns_policy(['v'])]))
    assert signed == []
    weak = edge.dns_rows(edge.by_kind([zone(state='on', algorithm='rsasha1')]))
    assert [(r['Issue'], r['_status']) for r in weak] == [('DNSSEC signing with RSASHA1.', AR)] and '--ksk-algorithm=ecdsap256sha256' in weak[0]['Fix']
    assert edge.dns_rows(edge.by_kind([zone(visibility='private')])) == []  # private zones have no DNSSEC to turn on
    assert [r['Resource'] for r in edge.dns_rows(edge.by_kind([network('v'), dns_policy(['v'], logging=False)]))] == ['network v']  # a policy without logging does not count


# --- VPC Flow Logs -----------------------------------------------------------------------------------------------------

def test_flow_log_rows():
    rows = edge.flow_log_rows(edge.by_kind([subnet('delhi-subnet', 'asia-south2'), subnet('prod-stark'), subnet('swp-pos', purpose='REGIONAL_MANAGED_PROXY'),
                                            subnet('logged', flow_logs=True), subnet('gke-x-pe-subnet', description='Control Plane Endpoint Subnetwork')]))
    assert [(r['Network / Subnet'], r['Region'], r['_status']) for r in rows] == [
        ('stark-nw-prod-shared-vpc / delhi-subnet', 'asia-south2', IR), ('stark-nw-prod-shared-vpc / prod-stark', 'asia-south1', IR)]
    assert rows[0]['Fix'] == ('gcloud compute networks subnets update delhi-subnet --region=asia-south2 --project=stark-nw-prod --enable-flow-logs '
                              '--logging-aggregation-interval=interval-5-sec --logging-flow-sampling=0.5 --logging-metadata=include-all')
    legacy_field = subnet('old')
    legacy_field.resource.data.pop('logConfig')
    legacy_field.resource.data['enableFlowLogs'] = True
    assert edge.flow_log_rows(edge.by_kind([legacy_field])) == []


# --- VPC Peering & Cloud NAT -------------------------------------------------------------------------------------------

def test_peering_nat_rows():
    nets = [network('stark-nw-prod-shared-vpc', 1460, [peering('p-google', 'sn', name='servicenetworking-googleapis-com')]), network('delhi-vpc')]
    rows = edge.peering_nat_rows(edge.by_kind(nets + [router('cloud-nat-prod-router', nats=[PROD_NAT]), router('swg', nats=[SWG_NAT])]))
    assert [(r['Resource'], r['Issue'], r['_status']) for r in rows] == [
        ('NAT prod-nat', 'Cloud NAT logging off.', IR), ('NAT prod-nat', 'Static NAT port allocation at the default.', IR)]
    assert rows[1]['Detail'].startswith('64 ports per VM, fixed') and '--enable-dynamic-port-allocation' in rows[1]['Fix'] and rows[0]['Network'] == 'stark-nw-prod-shared-vpc'
    tuned = {'name': 'nat', 'enableDynamicPortAllocation': True, 'minPortsPerVm': 64, 'maxPortsPerVm': 4096, 'logConfig': {'enable': True, 'filter': 'ERRORS_ONLY'}}
    assert edge.peering_nat_rows(edge.by_kind([router('r', nats=[tuned])])) == []
    big_static = {'name': 'nat', 'minPortsPerVm': 1024, 'logConfig': {'enable': True}}
    assert edge.peering_nat_rows(edge.by_kind([router('r', nats=[big_static])])) == []  # static but generous: no row
    # Peerings: an inactive one, and an MTU mismatch reported once per pair; a peer outside the listing is not judged for MTU.
    a = network('a', 1500, [peering('stark-nw-prod', 'b'), peering('stark-nw-prod', 'c', state='INACTIVE')])
    b = network('b', 1460, [peering('stark-nw-prod', 'a')])
    rows = edge.peering_nat_rows(edge.by_kind([a, b]))
    assert [(r['Network'], r['Resource'], r['Issue']) for r in rows] == [('a', 'peering to-b', 'MTU mismatch across a peering.'), ('a', 'peering to-c', 'Peering not active.')]
    assert rows[0]['Detail'].startswith('a 1500 ⇄ b 1460: packets above 1460 bytes') and '--mtu=1460' in rows[0]['Fix'] and 'update a ' in rows[0]['Fix']
    assert rows[1]['Detail'].startswith('state INACTIVE towards stark-nw-prod/global/networks/c')


# --- the checks end to end -----------------------------------------------------------------------------------------------

class Assets:
    def __init__(self, assets, error=None):
        self.assets, self.error, self.requests = assets, error, []

    def list_assets(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return [a for a in self.assets if a.name.split('/')[-2] in self.wanted(request['asset_types'])]

    COLLECTIONS = {'VpnTunnel': 'vpnTunnels', 'VpnGateway': 'vpnGateways', 'Router': 'routers', 'TargetVpnGateway': 'targetVpnGateways',
                   'InterconnectAttachment': 'interconnectAttachments', 'ForwardingRule': 'forwardingRules', 'GlobalForwardingRule': 'forwardingRules',
                   'TargetHttpProxy': 'targetHttpProxies', 'TargetHttpsProxy': 'targetHttpsProxies', 'TargetSslProxy': 'targetSslProxies',
                   'RegionTargetHttpProxy': 'targetHttpProxies', 'RegionTargetHttpsProxy': 'targetHttpsProxies', 'UrlMap': 'urlMaps', 'RegionUrlMap': 'urlMaps',
                   'SslPolicy': 'sslPolicies', 'BackendService': 'backendServices', 'RegionBackendService': 'backendServices',
                   'ManagedZone': 'managedZones', 'Policy': 'policies', 'Network': 'networks', 'Subnetwork': 'subnetworks'}

    @classmethod
    def wanted(cls, types):
        """The collections an asset-type list selects (the fake filters by the collection in the asset name)."""
        return {cls.COLLECTIONS[t.rsplit('/', 1)[-1]] for t in types}


def test_the_five_checks_end_to_end(gcp, monkeypatch):
    assets = [tunnel(), gateway(), router(), router('cloud-nat-prod-router', nats=[PROD_NAT]), network('stark-nw-prod-shared-vpc', 1460), network('delhi-vpc'),
              subnet('prod-stark'), subnet('swp-pos', purpose='REGIONAL_MANAGED_PROXY'), zone(), forwarding_rule('web-80', 'targetHttpProxies/web-http'), proxy('http', 'web-http'), backend('web-bes')]
    inventory = Assets(assets)
    monkeypatch.setattr(edge.gcp, 'asset_client', lambda credentials=None: inventory)

    class FakeCompute:
        def vpnTunnels(self):
            return self

        def aggregatedList(self, project):
            return SimpleNamespace(execute=lambda: {'items': {'regions/asia-south1': {'vpnTunnels': [{'name': 'vbbn', 'status': 'NO_INCOMING_PACKETS', 'detailedStatus': 'No incoming packets from peer'}]}}})

        def aggregatedList_next(self, previous_request, previous_response):
            return None
    monkeypatch.setattr(edge.gcp, 'api_build', lambda *args, **kwargs: FakeCompute())
    sink = Sink()
    for check in (edge.check_hybrid_connectivity, edge.check_load_balancer_edge, edge.check_dns_posture, edge.check_flow_logs, edge.check_peering_and_nat):
        check('organization', '987654321', JOB, sink=sink)
    records = sink.by_check()
    assert {name: record['Status'] for name, record in records.items()} == {
        'Hybrid Connectivity': AR, 'Load Balancer Edge': IR, 'DNS Posture': IR, 'VPC Flow Logs': IR, 'VPC Peering & Cloud NAT': IR}
    assert [r['Issue'] for r in records['Hybrid Connectivity']['Finding']] == ['VPN tunnel not established.', 'Tunnels on one interface only.']
    assert [r['Issue'] for r in records['DNS Posture']['Finding']] == ['DNSSEC off on a public zone.', 'Cloud DNS logging off.', 'Cloud DNS logging off.']
    assert [r['Network / Subnet'] for r in records['VPC Flow Logs']['Finding']] == ['stark-nw-prod-shared-vpc / prod-stark']
    assert all('_status' not in r for record in records.values() for r in record['Finding']) and sink.not_checked() == []
    assert [sorted(r['asset_types'])[:1] for r in inventory.requests] == [['compute.googleapis.com/InterconnectAttachment'], ['compute.googleapis.com/BackendService'],
                                                                         ['compute.googleapis.com/Network'], ['compute.googleapis.com/Subnetwork'], ['compute.googleapis.com/Network']]
    # Nothing in scope: five all-clear rows. A listing that fails: that check's Error.
    monkeypatch.setattr(edge.gcp, 'asset_client', lambda credentials=None: Assets([]))
    sink = Sink()
    edge.check_dns_posture('project', 'p', JOB, sink=sink)
    assert sink.by_check()['DNS Posture'] == {'Check': 'DNS Posture', 'Finding': [{'Status': edge.DNS_ALL_CLEAR}], 'Status': C}
    monkeypatch.setattr(edge.gcp, 'asset_client', lambda credentials=None: Assets([], error=RuntimeError('503 inventory unavailable')))
    sink = Sink()
    edge.check_flow_logs('folder', '42', JOB, sink=sink)
    assert sink.by_check()['VPC Flow Logs']['Status'] == 'Error'


def test_a_listing_refused_for_one_asset_type_is_retried_type_by_type():
    """The first canary named RegionTargetHttpProxy, which is no asset type, and the whole check read Error."""
    class Picky:
        def __init__(self):
            self.requests = []

        def list_assets(self, request):
            self.requests.append(list(request['asset_types']))
            if 'compute.googleapis.com/Bogus' in request['asset_types']:
                raise RuntimeError('400 No RESOURCE found that matches asset type compute.googleapis.com/Bogus for consumer project: 1')
            return [zone()] if 'dns.googleapis.com/ManagedZone' in request['asset_types'] else []
    client = Picky()
    found = edge.list_assets(client, 'organizations/1', ['dns.googleapis.com/ManagedZone', 'compute.googleapis.com/Bogus', 'compute.googleapis.com/Network'])
    assert [a.name.split('/')[-1] for a in found] == ['aura-public-zone']
    assert client.requests == [['dns.googleapis.com/ManagedZone', 'compute.googleapis.com/Bogus', 'compute.googleapis.com/Network'],
                               ['dns.googleapis.com/ManagedZone'], ['compute.googleapis.com/Bogus'], ['compute.googleapis.com/Network']]

    class Down:
        def list_assets(self, request):
            raise RuntimeError('503 unavailable')
    try:
        edge.list_assets(Down(), 'organizations/1', ['a', 'b'])
    except RuntimeError as error:
        assert '503' in str(error)  # any other failure is still the check's Error
    else:
        raise AssertionError('a 503 must propagate')


# --- the security extensions -------------------------------------------------------------------------------------------

def test_firewall_policy_rules_are_judged_like_vpc_rules():
    policy = {'name': '900001', 'displayName': 'edge-policy', 'associations': [{'name': 'vpc-main', 'attachmentTarget': 'projects/p1/global/networks/vpc-main'}],
              'rules': [{'priority': 100, 'direction': 'INGRESS', 'action': 'allow', 'match': {'srcIpRanges': ['0.0.0.0/0'], 'layer4Configs': [{'ipProtocol': 'tcp', 'ports': ['22']}]}},
                        {'priority': 200, 'direction': 'INGRESS', 'action': 'allow', 'match': {'srcIpRanges': ['0.0.0.0/0'], 'layer4Configs': [{'ipProtocol': 'tcp', 'ports': ['443']}]}},
                        {'priority': 300, 'direction': 'INGRESS', 'action': 'deny', 'match': {'srcIpRanges': ['0.0.0.0/0'], 'layer4Configs': [{'ipProtocol': 'all'}]}},
                        {'priority': 400, 'direction': 'EGRESS', 'action': 'allow', 'match': {'srcIpRanges': ['0.0.0.0/0'], 'layer4Configs': [{'ipProtocol': 'all'}]}},
                        {'priority': 500, 'direction': 'INGRESS', 'action': 'allow', 'disabled': True, 'match': {'srcIpRanges': ['0.0.0.0/0'], 'layer4Configs': [{'ipProtocol': 'all'}]}},
                        {'priority': 2147483647, 'direction': 'INGRESS', 'action': 'goto_next', 'match': {'srcIpRanges': ['0.0.0.0/0'], 'layer4Configs': [{'ipProtocol': 'all'}]}}]}
    rows = security.firewall_policy_rows('//compute.googleapis.com/projects/p1/global/firewallPolicies/900001', policy)
    assert [(r['Rule'], r['Protocols/Ports'], r['VPC'], r['_status']) for r in rows] == [
        ('edge-policy #100', 'tcp:22', 'policy → networks/vpc-main', AR), ('edge-policy #200', 'tcp:443', 'policy → networks/vpc-main', IR)]
    assert rows[0]['Fix'] == 'gcloud compute network-firewall-policies rules update 100 --firewall-policy=900001 --src-ip-ranges=<your CIDRs> --global-firewall-policy --project=p1'
    hierarchical = security.firewall_policy_rows('//compute.googleapis.com/locations/global/firewallPolicies/555', {**policy, 'associations': [{'name': 'org', 'attachmentTarget': 'organizations/1'}]})
    assert hierarchical[0]['Project'] == '(hierarchical)' and hierarchical[0]['VPC'] == 'policy → organizations/1' and hierarchical[0]['Fix'].startswith('gcloud compute firewall-policies rules update 100 --firewall-policy=900001')
    regional = security.firewall_policy_rows('//compute.googleapis.com/projects/p1/regions/asia-south1/firewallPolicies/7', policy)
    assert '--region=asia-south1' in regional[0]['Fix']


def test_legacy_networks_are_action_required_and_the_lines_moved_to_18_3():
    rows = security.vpc_rows('p', [{'name': 'old-net', 'IPv4Range': '10.240.0.0/16', 'selfLink': 'https://www.googleapis.com/compute/v1/projects/p/global/networks/old-net'},
                                   {'name': 'vpc-main', 'selfLink': 'https://www.googleapis.com/compute/v1/projects/p/global/networks/vpc-main'}], [])
    assert [(r['Network / Subnet'], r['_status']) for r in rows] == [('old-net (legacy network)', AR)] and rows[0]['Fix'].startswith('Create a VPC network')
    assert RESHAPED_CHECKS['Open Firewall Rules'] == ('18.3', RULE_CHANGED) and RESHAPED_CHECKS['VPC Configuration'] == ('18.3', RULE_CHANGED)
    assert not any(name in RESHAPED_CHECKS for name in edge.NETWORK_EDGE_CHECKS)  # new checks: "new check" by the existing rule
