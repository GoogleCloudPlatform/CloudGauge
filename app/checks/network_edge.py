"""
Network edge & reachability (v18.3).

The widest networking clusters in the case evidence are Interconnect and VPN
outages and VM-to-VM connectivity, and CIS §3 is the largest block of the
benchmark the tool did not read. Every item is a setting in Cloud Asset
Inventory — one read per check under the scanned scope: the search index,
which reflects changes within minutes, with the listing as the fallback (v18.5;
``list_assets``) — except the *state* of a VPN tunnel, which is re-read from
the Compute API per project that has tunnels (the v18.2 lesson):

- **Hybrid Connectivity** (Reliability): tunnels that are not established,
  HA VPN gateways with tunnels on one interface, Classic VPN gateways,
  Interconnect attachments without a second one in another edge availability
  domain or not active, Cloud Routers with one BGP peer for two links.
- **Load Balancer Edge** (Security): HTTP-only external load balancers, HTTPS
  and SSL proxies without a modern SSL policy, external backend services
  without Cloud Armor or without logging; v18.6: IAP on a backend service an
  HTTP-only load balancer serves.
- **DNS Posture** (Security): public zones without DNSSEC, zones signing with
  RSASHA1, networks without a Cloud DNS logging policy.
- **VPC Flow Logs** (Operations): VM subnets without flow logs.
- **VPC Peering & Cloud NAT** (Reliability): peerings that are not active,
  peered networks with different MTUs, NATs without logging or with the static
  64 ports per VM.

Google-managed resources — Secure Web Proxy's auto-generated NATs, private
services access peerings — are not judged. Every check reaches a verdict or an
all-clear row; a listing that fails is the check's Error.
"""
import logging
import re
from types import SimpleNamespace

from google.cloud import asset_v1

from app.checks.gke_operations import ACTION_REQUIRED, INVESTIGATION, write_rows
from app.checks.not_checked import NotChecked
from app.checks.security import subnet_is_exempt
from app.config import SCOPES
from app.services import gcp

HYBRID_CHECK = "Hybrid Connectivity"
EDGE_CHECK = "Load Balancer Edge"
DNS_CHECK = "DNS Posture"
FLOW_LOGS_CHECK = "VPC Flow Logs"
PEERING_NAT_CHECK = "VPC Peering & Cloud NAT"
NETWORK_EDGE_CHECKS = (HYBRID_CHECK, EDGE_CHECK, DNS_CHECK, FLOW_LOGS_CHECK, PEERING_NAT_CHECK)

COMPUTE = "compute.googleapis.com/"
HYBRID_TYPES = [COMPUTE + t for t in ("VpnGateway", "VpnTunnel", "TargetVpnGateway", "InterconnectAttachment", "Router")]
# Regional target proxies and URL maps are indexed under the plain types (their names carry /regions/); the first canary's listing was
# refused for naming RegionTargetHttpProxy, which is no asset type.
EDGE_TYPES = [COMPUTE + t for t in ("ForwardingRule", "GlobalForwardingRule", "TargetHttpProxy", "TargetHttpsProxy", "TargetSslProxy", "SslPolicy",
                                    "BackendService", "RegionBackendService", "UrlMap")]  # v18.6: URL maps, to tell which backend services an HTTP-only map serves
DNS_TYPES = ["dns.googleapis.com/ManagedZone", "dns.googleapis.com/Policy", COMPUTE + "Network"]
FLOW_LOG_TYPES = [COMPUTE + "Subnetwork"]
PEERING_NAT_TYPES = [COMPUTE + "Network", COMPUTE + "Router"]

EXTERNAL_SCHEMES = ("EXTERNAL", "EXTERNAL_MANAGED")
MODERN_TLS = ("TLS_1_2", "TLS_1_3")
DEFAULT_MTU = 1460
DEFAULT_NAT_PORTS = 64
GOOGLE_MANAGED_NAT_PREFIXES = ("swg-autogen-",)  # Secure Web Proxy's own NAT
GOOGLE_MANAGED_PEERINGS = ("servicenetworking-googleapis-com", "cloudsql-", "gke-", "redis-", "netapp-")  # private services access and friends
RSASHA1 = "rsasha1"
HYBRID_ALL_CLEAR = ("Every VPN tunnel is established on an HA VPN gateway using both interfaces, every Interconnect has a second attachment "
                    "in another availability domain, and no Classic VPN gateway remains.")
EDGE_ALL_CLEAR = "Every external load balancer serves HTTPS with a modern SSL policy, behind a Cloud Armor policy, with logging on."
DNS_ALL_CLEAR = "Every public zone is signed with DNSSEC (no RSASHA1) and every VPC network has a Cloud DNS logging policy."
FLOW_LOGS_ALL_CLEAR = "Every VM subnet has VPC flow logs on."
PEERING_NAT_ALL_CLEAR = "Every peering is active with matching MTUs, and every Cloud NAT logs and allocates ports dynamically."


# --- assets ----------------------------------------------------------------------------------------------------------

UNSUPPORTED_SEARCH_TYPE = re.compile(r"No supported asset type matches: ([\w.]+/\w+)")


def search_assets(asset_client, parent, asset_types):
    """The resources of ``asset_types`` under ``parent`` from the **search index**, per type: ``{asset_type: [record]}``, each record
    shaped like a listed asset (``name``, ``asset_type``, ``resource.data``, ``update_time``) from its versioned resource. A type the
    index returns without content maps to ``None``: the listing has to serve it.

    v18.5: the index reflects a change within minutes (its ``createTime`` is the real one); ``listAssets`` is refreshed by periodic
    snapshots and was observed hours behind (a new VM after 95 minutes, a project's metadata the next morning).

    v18.6: a type the index does not search (``compute.googleapis.com/RegionBackendService`` — the index files regional backend
    services under ``BackendService``, as it does regional proxies) made the whole search fail, and every type fell back to the
    listing; such a type is dropped and the search retried, the listing serving it alone (:func:`list_assets` drops the duplicates).
    """
    asset_types = list(asset_types)
    found = {asset_type: [] for asset_type in asset_types}
    searched = list(asset_types)
    for _ in range(len(asset_types)):
        try:
            results = list(asset_client.search_all_resources(request={"scope": parent, "asset_types": searched, "read_mask": "*", "page_size": 500}))
            break
        except Exception as e:
            match = UNSUPPORTED_SEARCH_TYPE.search(str(e))
            if not match or match.group(1) not in searched or len(searched) < 2:
                raise
            logging.info(f"The asset search does not support {match.group(1)}; searching the other types, the listing serves it")
            searched.remove(match.group(1))
            found[match.group(1)] = None
    else:
        raise RuntimeError("no searchable asset type left")
    for result in results:
        asset_type = str(getattr(result, "asset_type", "") or "")
        versions = list(getattr(result, "versioned_resources", None) or [])
        if not versions or found.get(asset_type) is None:
            found[asset_type] = None
            continue
        version = versions[0]
        data = version.get("resource") if isinstance(version, dict) else asset_v1.VersionedResource.to_dict(version).get("resource")
        found[asset_type].append(SimpleNamespace(name=str(getattr(result, "name", "") or ""), asset_type=asset_type, update_time=getattr(result, "update_time", None),
                                                 resource=SimpleNamespace(data=data or {}, parent=str(getattr(result, "parent_full_resource_name", "") or ""))))
    return found


def list_assets(asset_client, parent, asset_types):
    """The resources of ``asset_types`` under ``parent``: from the search index where it carries their content (fresh), from the
    inventory listing for the rest — the types the index returns no content for, the types it has nothing of (the listing confirms),
    and everything when the search fails. A listing the API refuses for one of its asset types (``No RESOURCE found that matches
    asset type``) is retried type by type, the refused type left out — a release that names a type the inventory has retired must
    not take the whole check down."""
    asset_types = list(asset_types)
    try:
        indexed = search_assets(asset_client, parent, asset_types)
    except Exception as e:
        logging.warning(f"Asset search under {parent} failed ({e}); reading the listing instead")
        indexed = {}
    found, listed_types = [], []
    for asset_type in asset_types:
        records = indexed.get(asset_type)
        if records:
            found += records
        else:
            listed_types.append(asset_type)
    if listed_types:
        found += _list_assets(asset_client, parent, listed_types)
    seen, unique = set(), []  # v18.6: the listing of a type the search does not know can repeat what the search returned under another type
    for asset in found:
        name = str(getattr(asset, "name", "") or "")
        if name and name in seen:
            continue
        seen.add(name)
        unique.append(asset)
    return unique


def _list_assets(asset_client, parent, asset_types):
    """One inventory listing of ``asset_types`` under ``parent``, as a list, with the type-by-type retry of :func:`list_assets`."""
    request = {"parent": parent, "asset_types": list(asset_types), "content_type": asset_v1.ContentType.RESOURCE}
    try:
        return list(asset_client.list_assets(request=request))
    except Exception as e:
        if "asset type" not in str(e) or len(asset_types) < 2:
            raise
        logging.warning(f"Asset Inventory refused a type in {asset_types}: {e}; listing type by type")
        found = []
        for asset_type in asset_types:
            try:
                found += list(asset_client.list_assets(request={**request, "asset_types": [asset_type]}))
            except Exception as inner:
                if "asset type" not in str(inner):
                    raise
        return found


def asset_fact(asset):
    """``{kind, project_id, region, name, link, data}`` from an asset: ``kind`` is the collection in its name (``subnetworks``,
    ``vpnTunnels``, ``managedZones``, …), ``link`` the resource's self link (what other resources point at)."""
    name = getattr(asset, "name", "") or ""
    parts = name.split("/")

    def after(key):
        return parts[parts.index(key) + 1] if key in parts and parts.index(key) + 1 < len(parts) else ""
    data = getattr(getattr(asset, "resource", None), "data", None) or {}
    region = after("regions") or after("locations") or ("global" if "global" in parts else "")
    link = data.get("selfLink") or ("https://www.googleapis.com/" + "/".join(["compute/v1"] + parts[3:]) if parts[2:3] == ["compute.googleapis.com"] else name)
    return {"kind": parts[-2] if len(parts) > 1 else "", "project_id": after("projects"), "region": region,
            "name": data.get("name") or parts[-1], "link": link, "data": data}


def by_kind(assets):
    """``{collection: [fact]}`` over the listing."""
    grouped = {}
    for asset in assets:
        fact = asset_fact(asset)
        grouped.setdefault(fact["kind"], []).append(fact)
    return grouped


def tail(link, n=1):
    """The last ``n`` segments of a self link, joined: ``tail(url, 2)`` → ``networks/prod``."""
    return "/".join(str(link or "").rstrip("/").split("/")[-n:])


def key(link):
    """``projects/p/regions/r/vpnTunnels/t`` — a self link without its host and API version (the API mixes ``v1`` and ``beta``)."""
    text = str(link or "").rstrip("/")
    return text.split("projects/", 1)[-1] if "projects/" in text else text


def same_link(a, b):
    """Two self links name the same resource."""
    return bool(a) and bool(b) and key(a) == key(b)


# --- Hybrid Connectivity ----------------------------------------------------------------------------------------------

def fresh_tunnel_states(compute, project_id):
    """``{(region, name): (status, detailedStatus)}`` from ``vpnTunnels.aggregatedList`` — the tunnel state as the API has it now."""
    states, request = {}, compute.vpnTunnels().aggregatedList(project=project_id)
    while request:
        response = request.execute()
        for scope_name, scoped in (response.get("items") or {}).items():
            for tunnel in scoped.get("vpnTunnels") or []:
                states[(scope_name.rsplit("/", 1)[-1], tunnel.get("name"))] = (tunnel.get("status"), tunnel.get("detailedStatus"))
        request = compute.vpnTunnels().aggregatedList_next(previous_request=request, previous_response=response)
    return states


def refresh_tunnels(tunnels, compute, skipped):
    """Overwrites the inventory's tunnel ``status``/``detailedStatus`` with the API's, one call per project; a failed call keeps the copy."""
    for project_id in sorted({t["project_id"] for t in tunnels}):
        try:
            states = fresh_tunnel_states(compute, project_id)
        except Exception as e:
            skipped.add(project_id, e, detail="the tunnels' current state from the Compute API (the inventory copy was read instead; it can lag)")
            continue
        for tunnel in tunnels:
            if tunnel["project_id"] == project_id and (tunnel["region"], tunnel["name"]) in states:
                status, detail = states[(tunnel["region"], tunnel["name"])]
                tunnel["data"] = {**tunnel["data"], "status": status, "detailedStatus": detail}
    return tunnels


def hybrid_rows(grouped):
    """The *Hybrid Connectivity* rows from the listing's tunnels, gateways, attachments and routers."""
    rows = []

    def row(fact, resource, issue, detail, fix, status, network=""):
        rows.append({"Project": fact["project_id"], "Network": network or tail(fact["data"].get("network")), "Region": fact["region"],
                     "Resource": resource, "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    tunnels = grouped.get("vpnTunnels", [])
    gateways = grouped.get("vpnGateways", [])
    gateway_networks = {key(g["link"]): tail(g["data"].get("network")) for g in gateways}
    for tunnel in tunnels:
        data = tunnel["data"]
        if str(data.get("status") or "").upper() != "ESTABLISHED":
            row(tunnel, f"tunnel {tunnel['name']}", "VPN tunnel not established.", f"{data.get('status') or 'unknown'}: {data.get('detailedStatus') or 'no detail'}.",
                f"gcloud compute vpn-tunnels describe {tunnel['name']} --region={tunnel['region']} --project={tunnel['project_id']} --format='value(status,detailedStatus)'  "
                "# then the peer's IKE, shared secret and routes", ACTION_REQUIRED, network=gateway_networks.get(key(data.get("vpnGateway")), ""))
    for gateway in gateways:
        interfaces = {int(t["data"].get("vpnGatewayInterface") or 0) for t in tunnels if same_link(t["data"].get("vpnGateway"), gateway["link"])}
        available = len(gateway["data"].get("vpnInterfaces") or [{}, {}])
        if available >= 2 and len(interfaces) < 2:
            used = f"interface {next(iter(interfaces))} only" if interfaces else "no tunnel at all"
            row(gateway, f"HA VPN gateway {gateway['name']}", "Tunnels on one interface only." if interfaces else "HA VPN gateway without a tunnel.",
                f"{used}: no redundancy and no SLA — maintenance on that interface takes the link down.",
                f"gcloud compute vpn-tunnels create {gateway['name']}-if{1 if interfaces == {0} else 0} --vpn-gateway={gateway['name']} --interface={1 if interfaces == {0} else 0} "
                f"--region={gateway['region']} --project={gateway['project_id']} --peer-external-gateway=<peer> --peer-external-gateway-interface=<n> "
                "--router=<router> --ike-version=2 --shared-secret=<secret>", ACTION_REQUIRED)
    for classic in grouped.get("targetVpnGateways", []):
        row(classic, f"Classic VPN gateway {classic['name']}", "Classic VPN gateway.",
            "Deprecated: no 99.99 % SLA, policy-based tunnels without dynamic routing.", "Migrate to HA VPN: gcloud compute vpn-gateways create … (two interfaces, Cloud Router, BGP).", INVESTIGATION)
    attachments = grouped.get("interconnectAttachments", [])
    groups = {}
    for attachment in attachments:
        groups.setdefault((attachment["project_id"], attachment["region"], tail(attachment["data"].get("router"))), []).append(attachment)
        if str(attachment["data"].get("operationalStatus") or "").upper() not in ("OS_ACTIVE", ""):
            row(attachment, f"attachment {attachment['name']}", "Interconnect attachment not active.", f"operational status {attachment['data'].get('operationalStatus')}.",
                f"gcloud compute interconnects attachments describe {attachment['name']} --region={attachment['region']} --project={attachment['project_id']}  "
                "# state, pairing key (Partner), the provider's side", ACTION_REQUIRED)
    for (project_id, region, router), members in groups.items():
        domains = {str(m["data"].get("edgeAvailabilityDomain") or "") for m in members}
        if len(members) < 2 or len(domains) < 2:
            first = members[0]
            why = "a single attachment" if len(members) < 2 else f"all attachments in {next(iter(domains)) or 'the same availability domain'}"
            row(first, f"attachments on router {router or '-'}", "Interconnect without a redundant attachment.",
                f"{why}: Google's 99.9 % topology needs two attachments in different edge availability domains (99.99 %: four across two metros).",
                f"gcloud compute interconnects attachments dedicated create {first['name']}-2 --region={region} --project={project_id} --router={router} "
                "--interconnect=<second interconnect> --edge-availability-domain=availability-domain-2  # Partner: a second VLAN attachment from the provider", ACTION_REQUIRED)
    for router in grouped.get("routers", []):
        links = [t for t in tunnels if same_link(t["data"].get("router"), router["link"])] + [a for a in attachments if same_link(a["data"].get("router"), router["link"])]
        peers = router["data"].get("bgpPeers") or []
        if len(links) >= 2 and len(peers) < 2:
            row(router, f"Cloud Router {router['name']}", "One BGP session for two links.", f"{len(links)} tunnels/attachments, {len(peers)} BGP peer(s): the second link carries no routes.",
                f"gcloud compute routers add-bgp-peer {router['name']} --region={router['region']} --project={router['project_id']} --peer-name=<peer-2> --interface=<if-2> "
                "--peer-ip-address=<ip> --peer-asn=<asn>", INVESTIGATION)
    return rows


# --- Load Balancer Edge -----------------------------------------------------------------------------------------------

def is_external(data):
    return str(data.get("loadBalancingScheme") or "EXTERNAL").upper() in EXTERNAL_SCHEMES


def ssl_policy_issue(policy):
    """Why an SSL policy is weak, or ``None``: profile ``COMPATIBLE`` (TLS 1.0 and old ciphers) or a minimum below TLS 1.2."""
    if policy is None:
        return "no SSL policy: the default allows TLS 1.0 and the COMPATIBLE cipher set"
    minimum, profile = str(policy.get("minTlsVersion") or "TLS_1_0").upper(), str(policy.get("profile") or "COMPATIBLE").upper()
    reasons = []
    if minimum not in MODERN_TLS:
        reasons.append(f"minimum {minimum.replace('_', ' ', 1).replace('_', '.')}")
    if profile == "COMPATIBLE":
        reasons.append("profile COMPATIBLE")
    return ", ".join(reasons) if reasons else None


def url_map_services(data):
    """Every backend service a URL map can route to: its default, each path matcher's default, path rules and route rules."""
    found = [data.get("defaultService")]
    for matcher in data.get("pathMatchers") or []:
        found.append(matcher.get("defaultService"))
        found += [rule.get("service") for rule in matcher.get("pathRules") or []]
        for rule in matcher.get("routeRules") or []:
            found.append(rule.get("service"))
            found += [w.get("backendService") for w in (rule.get("routeAction") or {}).get("weightedBackendServices") or []]
    return [key(link) for link in found if link]


def edge_rows(grouped):
    """The *Load Balancer Edge* rows: HTTP-only, weak TLS, no Cloud Armor, logging off — external load balancers only; v18.6: IAP on a
    backend service that an HTTP-only load balancer serves (its session cookie and identity headers travel in clear)."""
    rows = []
    proxies = {}
    for kind, proxy_kind in (("targetHttpProxies", "http"), ("targetHttpsProxies", "https"), ("targetSslProxies", "ssl")):
        for proxy in grouped.get(kind, []):
            proxies[key(proxy["link"])] = (proxy_kind, proxy)
    policies = {key(p["link"]): p["data"] for p in grouped.get("sslPolicies", [])}
    external_rules = [r for r in grouped.get("forwardingRules", []) if is_external(r["data"])]
    https_maps, http_maps = set(), set()
    for rule in external_rules:
        kind, proxy = proxies.get(key(rule["data"].get("target")), (None, None))
        if kind == "https":
            https_maps.add(key(proxy["data"].get("urlMap")))
        elif kind == "http":
            http_maps.add(key(proxy["data"].get("urlMap")))
    http_only_services = set()
    for url_map in grouped.get("urlMaps", []):
        if key(url_map["link"]) in http_maps - https_maps:
            http_only_services.update(url_map_services(url_map["data"]))

    def row(fact, lb, issue, detail, fix, status):
        rows.append({"Project": fact["project_id"], "Load Balancer": lb, "Scheme": str(fact["data"].get("loadBalancingScheme") or "EXTERNAL"),
                     "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    for rule in external_rules:
        kind, proxy = proxies.get(key(rule["data"].get("target")), (None, None))
        if kind == "http" and key(proxy["data"].get("urlMap")) not in https_maps:
            row(rule, rule["name"], "HTTP-only load balancer.", f"port {rule['data'].get('portRange') or ','.join(rule['data'].get('ports') or [])} to {proxy['name']} without an HTTPS forwarding rule on the same URL map: cleartext at the edge.",
                f"gcloud compute target-https-proxies create {proxy['name']}-https --url-map={tail(proxy['data'].get('urlMap'))} --ssl-certificates=<cert> --project={rule['project_id']} "
                f"&& gcloud compute forwarding-rules create {rule['name']}-443 --target-https-proxy={proxy['name']}-https --ports=443 --address=<same IP> --global --project={rule['project_id']}  "
                "# then redirect 80 → 443 on the URL map", INVESTIGATION)
        elif kind in ("https", "ssl"):
            issue = ssl_policy_issue(policies.get(key(proxy["data"].get("sslPolicy"))) if proxy["data"].get("sslPolicy") else None)
            if issue:
                flag = "target-https-proxies" if kind == "https" else "target-ssl-proxies"
                row(rule, rule["name"], "Weak TLS at the edge.", f"{proxy['name']}: {issue}.",
                    f"gcloud compute ssl-policies create modern-tls --profile=MODERN --min-tls-version=1.2 --project={rule['project_id']} && "
                    f"gcloud compute {flag} update {proxy['name']} --ssl-policy=modern-tls --project={rule['project_id']}", INVESTIGATION)
    for service in grouped.get("backendServices", []):
        data = service["data"]
        if not is_external(data):
            continue
        scope_flag = "--global" if service["region"] in ("global", "") else f"--region={service['region']}"
        if not data.get("securityPolicy"):
            row(service, service["name"], "No Cloud Armor policy.", f"backend service {service['name']} ({data.get('protocol') or 'TCP'}): no WAF rules, rate limiting or adaptive protection at the edge.",
                f"gcloud compute security-policies create edge --project={service['project_id']} && gcloud compute backend-services update {service['name']} --security-policy=edge {scope_flag} --project={service['project_id']}",
                INVESTIGATION)
        if not (data.get("logConfig") or {}).get("enable", False):
            row(service, service["name"], "Load balancer logging off.", f"backend service {service['name']}: requests and 5xx answers leave no trace.",
                f"gcloud compute backend-services update {service['name']} --enable-logging --logging-sample-rate=1 {scope_flag} --project={service['project_id']}", INVESTIGATION)
        if (data.get("iap") or {}).get("enabled") and key(service["link"]) in http_only_services:
            row(service, service["name"], "IAP over HTTP.", f"backend service {service['name']} has Identity-Aware Proxy on, behind an HTTP-only load balancer: the IAP session cookie "
                "and identity headers cross the internet in clear.",
                "add an HTTPS forwarding rule on the URL map (the HTTP-only row's Fix) and redirect 80 → 443", INVESTIGATION)
    return rows


# --- DNS Posture ------------------------------------------------------------------------------------------------------

def dns_rows(grouped):
    rows = []

    def row(fact, resource, issue, detail, fix, status):
        rows.append({"Project": fact["project_id"], "Resource": resource, "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    for zone in grouped.get("managedZones", []):
        data = zone["data"]
        if str(data.get("visibility") or "public").lower() != "public":
            continue
        config = data.get("dnssecConfig") or {}
        algorithms = {str(spec.get("algorithm") or "").lower() for spec in config.get("defaultKeySpecs") or []}
        if str(config.get("state") or "off").lower() != "on":
            row(zone, f"zone {zone['name']} ({data.get('dnsName')})", "DNSSEC off on a public zone.", "Resolvers cannot verify the answers: cache poisoning of the customer's names.",
                f"gcloud dns managed-zones update {zone['name']} --dnssec-state=on --project={zone['project_id']}  # then publish the DS record at the registrar", INVESTIGATION)
        elif RSASHA1 in algorithms:
            row(zone, f"zone {zone['name']} ({data.get('dnsName')})", "DNSSEC signing with RSASHA1.", "A deprecated algorithm: the signatures are not trusted by modern resolvers.",
                f"gcloud dns managed-zones update {zone['name']} --dnssec-state=off --project={zone['project_id']} && gcloud dns managed-zones update {zone['name']} --dnssec-state=on "
                f"--ksk-algorithm=ecdsap256sha256 --ksk-key-length=256 --zsk-algorithm=ecdsap256sha256 --zsk-key-length=256 --project={zone['project_id']}", ACTION_REQUIRED)
    logged = set()
    for policy in grouped.get("policies", []):
        if policy["data"].get("enableLogging"):
            for network in policy["data"].get("networks") or []:
                logged.add(key(network.get("networkUrl")))
    for network in grouped.get("networks", []):
        if key(network["link"]) not in logged:
            row(network, f"network {network['name']}", "Cloud DNS logging off.", "No record of what resolved what: the first thing an exfiltration or DNS-failure investigation needs.",
                f"gcloud dns policies create dns-logging-{network['name']} --networks={network['name']} --enable-logging --project={network['project_id']}", INVESTIGATION)
    return rows


# --- VPC Flow Logs ----------------------------------------------------------------------------------------------------

def flow_log_rows(grouped):
    rows = []
    for subnet in grouped.get("subnetworks", []):
        data = subnet["data"]
        if subnet_is_exempt(data):
            continue
        if data.get("enableFlowLogs") or (data.get("logConfig") or {}).get("enable"):
            continue
        rows.append({"Project": subnet["project_id"], "Network / Subnet": f"{tail(data.get('network'))} / {subnet['name']}", "Region": subnet["region"],
                     "Issue": "VPC flow logs off.",
                     "Fix": f"gcloud compute networks subnets update {subnet['name']} --region={subnet['region']} --project={subnet['project_id']} --enable-flow-logs "
                            "--logging-aggregation-interval=interval-5-sec --logging-flow-sampling=0.5 --logging-metadata=include-all",
                     "_status": INVESTIGATION})
    return rows


# --- VPC Peering & Cloud NAT -------------------------------------------------------------------------------------------

def is_google_managed_peering(peering):
    name = str(peering.get("name") or "")
    return name.startswith(GOOGLE_MANAGED_PEERINGS)


def peering_nat_rows(grouped):
    rows = []

    def row(fact, network, resource, issue, detail, fix, status):
        rows.append({"Project": fact["project_id"], "Network": network, "Resource": resource, "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    networks = grouped.get("networks", [])
    by_link = {key(n["link"]): n for n in networks}
    seen_pairs = set()
    for network in networks:
        mtu = int(network["data"].get("mtu") or DEFAULT_MTU)
        for peering in network["data"].get("peerings") or []:
            if is_google_managed_peering(peering):
                continue
            peer_key = key(peering.get("network"))
            if str(peering.get("state") or "").upper() != "ACTIVE":
                row(network, network["name"], f"peering {peering.get('name')}", "Peering not active.",
                    f"state {peering.get('state') or 'unknown'} towards {peer_key}: the other network has not peered back, no traffic flows.",
                    f"gcloud compute networks peerings create {network['name']}-back --network={peer_key.rsplit('/', 1)[-1]} --peer-network={network['name']} "
                    f"--peer-project={network['project_id']} --project=<the other project>", INVESTIGATION)
            peer = by_link.get(peer_key)
            if peer is None:
                continue
            pair = tuple(sorted([key(network["link"]), peer_key]))
            peer_mtu = int(peer["data"].get("mtu") or DEFAULT_MTU)
            if peer_mtu != mtu and pair not in seen_pairs:
                seen_pairs.add(pair)
                row(network, network["name"], f"peering {peering.get('name')}", "MTU mismatch across a peering.",
                    f"{network['name']} {mtu} ⇄ {peer['name']} {peer_mtu}: packets above {min(mtu, peer_mtu)} bytes are dropped or fragmented — resets, timeouts, DNS failures.",
                    f"gcloud compute networks update {network['name'] if mtu > peer_mtu else peer['name']} --mtu={min(mtu, peer_mtu)} --project=<its project>  # the lower MTU wins; restart the VMs",
                    INVESTIGATION)
    for router in grouped.get("routers", []):
        for nat in router["data"].get("nats") or []:
            name = str(nat.get("name") or "")
            if name.startswith(GOOGLE_MANAGED_NAT_PREFIXES):
                continue
            base = f"gcloud compute routers nats update {name} --router={router['name']} --region={router['region']} --project={router['project_id']}"
            if not (nat.get("logConfig") or {}).get("enable", False):
                row(router, tail(router["data"].get("network")), f"NAT {name}", "Cloud NAT logging off.", "Dropped connections and port exhaustion are invisible.",
                    f"{base} --enable-logging --log-filter=ERRORS_ONLY", INVESTIGATION)
            ports = int(nat.get("minPortsPerVm") or DEFAULT_NAT_PORTS)
            if not nat.get("enableDynamicPortAllocation", False) and ports <= DEFAULT_NAT_PORTS:
                row(router, tail(router["data"].get("network")), f"NAT {name}", "Static NAT port allocation at the default.",
                    f"{ports} ports per VM, fixed: connection-heavy VMs run out of NAT ports (OUT_OF_RESOURCES drops).",
                    f"{base} --enable-dynamic-port-allocation --min-ports-per-vm=64 --max-ports-per-vm=4096", INVESTIGATION)
    return rows


# --- the checks -------------------------------------------------------------------------------------------------------

def _run(check, types, rows_of, scope, scope_id, job_id, sink, all_clear, refresh=None):
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        grouped = by_kind(list_assets(gcp.asset_client(credentials), parent, types))
    except Exception as e:
        logging.error(f"[{job_id}] {check}: could not list under {parent}: {e}")
        sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped = NotChecked(check)
    if refresh is not None:
        refresh(grouped, credentials, skipped)
    write_rows(sink, job_id, check, rows_of(grouped), all_clear)
    skipped.write(sink, job_id)


def _refresh_tunnels(grouped, credentials, skipped):
    if grouped.get("vpnTunnels"):
        refresh_tunnels(grouped["vpnTunnels"], gcp.api_build("compute", "v1", credentials=credentials), skipped)


def check_hybrid_connectivity(scope, scope_id, job_id, *, sink):
    print(f"🔗 [{job_id}] Checking {HYBRID_CHECK} under {scope} {scope_id}...")
    _run(HYBRID_CHECK, HYBRID_TYPES, hybrid_rows, scope, scope_id, job_id, sink, HYBRID_ALL_CLEAR, refresh=_refresh_tunnels)


def check_load_balancer_edge(scope, scope_id, job_id, *, sink):
    print(f"🛡️ [{job_id}] Checking {EDGE_CHECK} under {scope} {scope_id}...")
    _run(EDGE_CHECK, EDGE_TYPES, edge_rows, scope, scope_id, job_id, sink, EDGE_ALL_CLEAR)


def check_dns_posture(scope, scope_id, job_id, *, sink):
    print(f"🌐 [{job_id}] Checking {DNS_CHECK} under {scope} {scope_id}...")
    _run(DNS_CHECK, DNS_TYPES, dns_rows, scope, scope_id, job_id, sink, DNS_ALL_CLEAR)


def check_flow_logs(scope, scope_id, job_id, *, sink):
    print(f"📈 [{job_id}] Checking {FLOW_LOGS_CHECK} under {scope} {scope_id}...")
    _run(FLOW_LOGS_CHECK, FLOW_LOG_TYPES, flow_log_rows, scope, scope_id, job_id, sink, FLOW_LOGS_ALL_CLEAR)


def check_peering_and_nat(scope, scope_id, job_id, *, sink):
    print(f"🔀 [{job_id}] Checking {PEERING_NAT_CHECK} under {scope} {scope_id}...")
    _run(PEERING_NAT_CHECK, PEERING_NAT_TYPES, peering_nat_rows, scope, scope_id, job_id, sink, PEERING_NAT_ALL_CLEAR)
