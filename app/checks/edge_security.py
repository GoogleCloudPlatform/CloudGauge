"""
Serverless and edge exposure, the edge half (v18.6).

*Load Balancer Edge* (v18.3) stops at "a Cloud Armor policy is attached": this
is the first look inside the edge the tool already lists. One Cloud Asset
Inventory read under the scope (security policies, SSL certificates, the backend
services and target proxies that attach them — the search index first, the
listing as the fallback), with **fresh reads** from the Compute API
(``securityPolicies`` and ``sslCertificates`` ``aggregatedList``) per project
that has any, so a fix shows on the next scan; a refused read leaves the
inventory's copy and a line under *Projects not checked*.

- **Cloud Armor Policy Content** (Security): on the **attached L7 policies**
  (``type`` ``CLOUD_ARMOR``; network and edge policies carry no WAF rules by
  design, Google's advanced-DDoS policies are its own) — a rule on a ruleset of
  an older generation or on the legacy ``evaluatePreconfiguredExpr`` syntax, a
  policy whose rules protect nothing (only the default rule; or no WAF rule, no
  rate limit and Layer-7 DDoS defense off), a policy whose deny rules are all
  in preview, and the housekeeping rows (preview rules, the 200-rule quota).
  The ruleset generations, the retired signature IDs and the signature counts
  the Detail quotes come from ``assets/cloud_armor_rulesets.json`` (the
  google/skills Cloud Armor upgrade reference); a newer generation is one
  table change.
- **SSL Certificate Health** (Reliability): a self-managed certificate on a
  target proxy expiring within 30 days (Action Required within 7, or expired),
  a Google-managed one that failed to provision or renew (or stuck
  provisioning for a day), an unattached expired certificate (housekeeping).
  Certificate Manager certificates are a different asset and not read here.
"""
import functools
import json
import logging
import pathlib
import re
from datetime import datetime, timedelta, timezone

from app.checks.gke_operations import ACTION_REQUIRED, INFORMATIONAL, INVESTIGATION, write_rows
from app.checks.network_edge import by_kind, is_external, key, list_assets, tail
from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp

ARMOR_CHECK = "Cloud Armor Policy Content"
CERTIFICATE_CHECK = "SSL Certificate Health"
EDGE_SECURITY_CHECKS = (ARMOR_CHECK, CERTIFICATE_CHECK)

COMPUTE = "compute.googleapis.com/"
EDGE_SECURITY_TYPES = [COMPUTE + t for t in ("SecurityPolicy", "SslCertificate", "BackendService", "RegionBackendService", "TargetHttpsProxy", "TargetSslProxy")]
RULESETS_PATH = pathlib.Path(__file__).resolve().parents[2] / "assets" / "cloud_armor_rulesets.json"

L7_POLICY, DEFAULT_PRIORITY = "CLOUD_ARMOR", 2147483647
PRECONFIGURED = re.compile(r"evaluatePreconfigured(Expr|Waf)\(\s*'([^']+)'")
SIGNATURE_ID = re.compile(r"owasp-crs-(v\d{6})-id(\d{6})")
ENFORCING_ACTIONS = ("deny", "throttle", "rate_based_ban", "redirect")
RULE_QUOTA, RULE_QUOTA_WARNING = 200, 180
METHOD_ENFORCEMENT = "methodenforcement"

MANAGED_FAILED = ("PROVISIONING_FAILED", "PROVISIONING_FAILED_PERMANENTLY", "RENEWAL_FAILED")
CERT_WARNING_DAYS, CERT_CRITICAL_DAYS, PROVISIONING_GRACE = 30, 7, timedelta(days=1)

ARMOR_ALL_CLEAR = ("Every attached Cloud Armor policy enforces current-generation WAF rules or rate limits, with nothing left in preview "
                   "(or no L7 policy is attached in scope).")
CERTIFICATE_ALL_CLEAR = "Every certificate on a target proxy is valid for more than 30 days or renews itself, and none has failed to provision."


@functools.lru_cache(maxsize=1)
def rulesets():
    """The bundled Cloud Armor ruleset table (``RULESETS_PATH``)."""
    return json.loads(RULESETS_PATH.read_text(encoding="utf-8"))


# --- Cloud Armor Policy Content ----------------------------------------------------------------------------------------

def gcloud_action(action):
    """A rule action as gcloud spells it: the API's ``deny(403)`` is ``--action=deny-403``; ``allow``, ``throttle``, ``rate_based_ban`` and ``redirect`` are unchanged."""
    return str(action or "deny-403").replace("(", "-").replace(")", "")


def is_l7_policy(data):
    return str(data.get("type") or L7_POLICY).upper() == L7_POLICY and not data.get("ddosProtectionConfig")


def attachments(grouped):
    """``{policy key: [backend service name]}`` of the security policies external backend services carry."""
    found = {}
    for service in grouped.get("backendServices", []):
        data = service["data"]
        if data.get("securityPolicy") and is_external(data):
            found.setdefault(key(data["securityPolicy"]), []).append(service["name"])
    return found


def rule_rulesets(rule):
    """``[(syntax, ruleset name)]`` the rule evaluates: from its CEL expression and from its WAF exclusions."""
    found = [(syntax, name) for syntax, name in PRECONFIGURED.findall(str(((rule.get("match") or {}).get("expr") or {}).get("expression") or ""))]
    for exclusion in (rule.get("preconfiguredWafConfig") or {}).get("exclusions") or []:
        if exclusion.get("targetRuleSet"):
            found.append(("Waf", str(exclusion["targetRuleSet"])))
    return found


def legacy_rulesets(rule, table):
    """``[(name, current name)]`` of the older-generation rulesets the rule uses; ``(name, name)`` for a current ruleset on the legacy
    ``evaluatePreconfiguredExpr`` syntax. Standalone rulesets (CVE canary, named IP lists) never count."""
    legacy, standalone, prefixes = table["legacy"], set(table["standalone"]), tuple(table["standalone_prefixes"])
    found = []
    for syntax, name in rule_rulesets(rule):
        if name in standalone or name.startswith(prefixes):
            continue
        if name in legacy:
            found.append((name, legacy[name]))
        elif syntax == "Expr":
            found.append((name, name))
    return found


def retired_ids(rule, table):
    """The retired signature IDs the rule names (in its expression or its exclusions): to drop from the opt-out list when upgrading."""
    text = json.dumps(rule, sort_keys=True)
    retired = set(table["retired_ids"])
    return sorted({sig for _, sig in SIGNATURE_ID.findall(text) if sig in retired})


def generation_of(name):
    return "3.3" if "-v33-" in name else "3.0"


def signature_note(name, current, table):
    """What the upgrade buys, from the bundled counts: ``rce 15 → 44 signatures``."""
    category = name.split("-")[0]
    counts = table["signatures"].get(category)
    if not counts or table["current"] in name or generation_of(name) not in counts:
        return ""
    before, after = counts[generation_of(name)], counts["current"]
    return f"{category}: {before} → {after} signatures" if after != before else f"{category}: same signatures, current syntax"


def armor_rows(grouped, table=None):
    table = table or rulesets()
    attached = attachments(grouped)
    rows = []

    def row(policy, attached_to, rule, issue, detail, fix, status):
        rows.append({"Project": policy["project_id"], "Policy": policy["name"], "Attached to": attached_to, "Rule": rule, "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    for policy in grouped.get("securityPolicies", []):
        data = policy["data"]
        if not is_l7_policy(data) or key(policy["link"]) not in attached:
            continue
        project, name = policy["project_id"], policy["name"]
        attached_to = ", ".join(attached[key(policy["link"])])
        scope_flag = f"--region={policy['region']}" if policy["region"] not in ("global", "") else ""
        base = f"gcloud compute security-policies rules {{verb}} {{priority}} --security-policy={name} --project={project}" + (f" {scope_flag}" if scope_flag else "")
        rules = data.get("rules") or []
        user_rules = [r for r in rules if int(r.get("priority") or 0) != DEFAULT_PRIORITY]
        waf_rules = [r for r in rules if rule_rulesets(r)]
        enforcing = [r for r in user_rules if str(r.get("action") or "").lower().startswith(ENFORCING_ACTIONS)]
        preview = [r for r in user_rules if r.get("preview")]
        adaptive = bool(((data.get("adaptiveProtectionConfig") or {}).get("layer7DdosDefenseConfig") or {}).get("enable"))
        for rule in rules:
            legacy = legacy_rulesets(rule, table)
            if not legacy:
                continue
            priority = int(rule.get("priority") or 0)
            notes = "; ".join(filter(None, (signature_note(old, new, table) for old, new in legacy)))
            dropped = retired_ids(rule, table)
            caveat = " methodenforcement blocks PUT, PATCH and DELETE in the current generation: exempt the API paths that need them." if any(METHOD_ENFORCEMENT in old for old, _ in legacy) else ""
            drop = f" Drop the retired signature IDs {', '.join(dropped)} from the opt-out list." if dropped else ""
            action = gcloud_action(rule.get("action"))
            row(policy, attached_to, f"{priority} ({action}{', preview' if rule.get('preview') else ''})", "Legacy WAF ruleset.",
                f"Uses {', '.join(old for old, _ in legacy)} — OWASP CRS {generation_of(legacy[0][0])}" + (f" ({notes})" if notes else "") +
                f"; the current generation is {', '.join(sorted({new for _, new in legacy}))} and evaluatePreconfiguredExpr is being retired.{caveat}{drop}",
                base.format(verb="create", priority=max(priority - 1, 0)) + f" --expression=\"evaluatePreconfiguredWaf('{legacy[0][1]}')\" --action={action} --preview"
                f"  # watch the logs, then {base.format(verb='update', priority=max(priority - 1, 0))} --no-preview && {base.format(verb='delete', priority=priority)}", INVESTIGATION)
        default_rule = next((r for r in rules if int(r.get("priority") or 0) == DEFAULT_PRIORITY), {})
        default_allows = str(default_rule.get("action") or "allow").lower().startswith("allow")
        if default_allows and not enforcing and not waf_rules and not adaptive:
            what = "only the default rule" if not user_rules else f"{len(user_rules)} allow rule(s) over a default allow"
            row(policy, attached_to, "—", "Policy protects nothing.", f"{what}: no WAF ruleset, no deny or throttle rule, Layer-7 DDoS defense off — attached, but nothing is filtered.",
                base.format(verb="create", priority=1000) + " --expression=\"evaluatePreconfiguredWaf('sqli-v422-stable') || evaluatePreconfiguredWaf('xss-v422-stable')\" --action=deny-403 --preview && "
                + base.format(verb="create", priority=2000) + " --src-ip-ranges='*' --action=throttle --rate-limit-threshold-count=100 --rate-limit-threshold-interval-sec=60 --conform-action=allow --exceed-action=deny-429 --enforce-on-key=IP && "
                + f"gcloud compute security-policies update {name} --project={project}{(' ' + scope_flag) if scope_flag else ''} --enable-layer7-ddos-defense", INVESTIGATION)
        elif enforcing and all(r.get("preview") for r in enforcing):
            first = min(int(r.get("priority") or 0) for r in enforcing)
            row(policy, attached_to, ", ".join(str(r.get("priority")) for r in enforcing[:5]), "WAF not enforcing.",
                f"Every deny or throttle rule ({len(enforcing)}) is in preview: matches are logged, nothing is blocked.",
                base.format(verb="update", priority=first) + " --no-preview  # after reviewing the preview matches in the load balancer logs", INVESTIGATION)
        elif preview:
            row(policy, attached_to, ", ".join(str(r.get("priority")) for r in preview[:5]), "Preview rules left behind.",
                f"{len(preview)} rule(s) in preview (audit-only): each is billed and counts against the quota while blocking nothing — promote or delete them.",
                base.format(verb="update", priority=int(preview[0].get("priority") or 0)) + " --no-preview  # or: " + base.format(verb="delete", priority=int(preview[0].get("priority") or 0)), INFORMATIONAL)
        if len(rules) >= RULE_QUOTA_WARNING:
            row(policy, attached_to, "—", "Near the rule quota.", f"{len(rules)} of {RULE_QUOTA} rules: a preview-mode upgrade needs headroom for its parallel rules.",
                base.format(verb="delete", priority="<unused priority>"), INFORMATIONAL)
    return rows


# --- SSL Certificate Health ------------------------------------------------------------------------------------------------

def parse_time(text):
    """A Compute API timestamp (RFC 3339 with an offset, e.g. ``2026-12-01T00:00:00.000-08:00``) as an aware datetime, or ``None``."""
    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def certificate_proxies(grouped):
    """``{certificate key: [proxy name]}`` of the certificates target HTTPS and SSL proxies serve."""
    found = {}
    for kind in ("targetHttpsProxies", "targetSslProxies"):
        for proxy in grouped.get(kind, []):
            for link in proxy["data"].get("sslCertificates") or []:
                found.setdefault(key(link), []).append(proxy["name"])
    return found


def certificate_rows(grouped, now=None):
    now = now or datetime.now(timezone.utc)
    served = certificate_proxies(grouped)
    rows = []
    for cert in grouped.get("sslCertificates", []):
        data, project, name = cert["data"], cert["project_id"], cert["name"]
        managed = data.get("managed") or {}
        kind = "Google-managed" if (str(data.get("type") or "").upper() == "MANAGED" or managed) else "self-managed"
        proxies = served.get(key(cert["link"]), [])
        expires = parse_time(data.get("expireTime"))
        regional = cert["region"] not in ("global", "")
        scope_flag = f"--region={cert['region']}" if regional else "--global"
        days = (expires - now).days if expires else None

        def row(issue, detail, fix, status, when=None):
            rows.append({"Project": project, "Certificate": name, "Type": kind, "Attached to": ", ".join(proxies) or "(none)",
                         "Expires / Status": when or (expires.strftime("%Y-%m-%d") if expires else ""), "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

        if proxies and kind == "self-managed" and days is not None and days <= CERT_WARNING_DAYS:
            domains = ",".join(data.get("subjectAlternativeNames") or []) or "<domains>"
            proxy_flag = "target-https-proxies" if proxies[0] in {p["name"] for p in grouped.get("targetHttpsProxies", [])} else "target-ssl-proxies"
            when = f"expired {-days} day(s) ago" if days < 0 else f"in {days} day(s)"
            row("Certificate expiring." if days >= 0 else "Certificate expired.",
                f"Self-managed certificate on {', '.join(proxies)} {'expired' if days < 0 else 'expires'} {expires:%Y-%m-%d} ({when}): past that date every client refuses the connection.",
                f"gcloud compute ssl-certificates create {name}-{now:%Y%m} --domains={domains} {scope_flag} --project={project} && gcloud compute {proxy_flag} update {proxies[0]} "
                f"--ssl-certificates={name}-{now:%Y%m} {scope_flag} --project={project}  # Google-managed renews itself", ACTION_REQUIRED if days <= CERT_CRITICAL_DAYS else INVESTIGATION, when)
        elif proxies and kind == "Google-managed":
            status = str(managed.get("status") or "")
            failed_domains = [d for d, s in (managed.get("domainStatus") or {}).items() if str(s).startswith("FAILED")]
            created = parse_time(data.get("creationTimestamp"))
            if status in MANAGED_FAILED or failed_domains:
                domain_states = managed.get("domainStatus") or {}
                domains_text = "; domains " + ", ".join(f"{d} ({domain_states.get(d)})" for d in failed_domains) if failed_domains else ""
                row("Managed certificate failed.", f"Status {status}{domains_text} on {', '.join(proxies)}: the certificate will not issue or renew until the domain's A/AAAA records point "
                    "at the load balancer's address; the old certificate serves until it expires, then nothing.",
                    f"point the DNS records of {', '.join(failed_domains) or 'the domains'} at the load balancer's IP; the certificate retries on its own (gcloud compute ssl-certificates describe {name} {scope_flag} --project={project})",
                    ACTION_REQUIRED, status)
            elif status == "PROVISIONING" and created and now - created > PROVISIONING_GRACE:
                row("Managed certificate stuck provisioning.", f"PROVISIONING since {created:%Y-%m-%d} on {', '.join(proxies)}: issuance takes minutes once the DNS records resolve to the load balancer.",
                    f"check the domains' A/AAAA records and the forwarding rule's address (gcloud compute ssl-certificates describe {name} {scope_flag} --project={project})", INVESTIGATION, status)
        elif not proxies and days is not None and days < 0:
            row("Expired certificate left behind.", f"Expired {expires:%Y-%m-%d}, attached to no proxy.", f"gcloud compute ssl-certificates delete {name} {scope_flag} --project={project} --quiet", INFORMATIONAL,
                f"expired {-days} day(s) ago")
    return rows


# --- fresh reads ------------------------------------------------------------------------------------------------------------

def api_facts(compute, project_id, collection, kind, item_key):
    """The project's resources of one aggregated collection from the Compute API, as :func:`network_edge.asset_fact`-shaped facts."""
    found, request = [], getattr(compute, collection)().aggregatedList(project=project_id)
    while request:
        response = request.execute()
        for scoped in (response.get("items") or {}).values():
            for data in scoped.get(item_key) or []:
                link = str(data.get("selfLink") or "")
                found.append({"kind": kind, "project_id": project_id, "region": tail(data.get("region")) if data.get("region") else "global", "name": data.get("name") or tail(link), "link": link, "data": data})
        request = getattr(compute, collection)().aggregatedList_next(previous_request=request, previous_response=response)
    return found


def refresh_from_api(grouped, compute, skipped):
    """The security policies and certificates of every project that has any, re-read from the Compute API (the inventory's copy stands when a
    read fails, noted under *Projects not checked*)."""
    for kind, collection, item_key, what in (("securityPolicies", "securityPolicies", "securityPolicies", "Cloud Armor policies"), ("sslCertificates", "sslCertificates", "sslCertificates", "certificates")):
        for project_id in sorted({fact["project_id"] for fact in grouped.get(kind, [])}):
            try:
                fresh = api_facts(compute, project_id, collection, kind, item_key)
            except Exception as e:
                skipped.add(project_id, e, detail=f"{what}: the Compute API read failed; the inventory's copy was used, which can lag changes by hours")
                continue
            grouped[kind] = [fact for fact in grouped.get(kind, []) if fact["project_id"] != project_id] + fresh
    return grouped


# --- the check ------------------------------------------------------------------------------------------------------------------

def check_edge_security(scope, scope_id, job_id, *, sink, now=None):
    """Writes *Cloud Armor Policy Content* and *SSL Certificate Health*: the scope's policies, certificates, backend services and proxies from the
    inventory, then each project's policies and certificates from the Compute API."""
    print(f"🧱 [{job_id}] Checking {ARMOR_CHECK} and {CERTIFICATE_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        grouped = by_kind(list_assets(gcp.asset_client(credentials), parent, EDGE_SECURITY_TYPES))
    except Exception as e:
        logging.error(f"[{job_id}] {ARMOR_CHECK}: could not list under {parent}: {e}")
        for check in EDGE_SECURITY_CHECKS:
            sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped = NotChecked(ARMOR_CHECK)
    if grouped.get("securityPolicies") or grouped.get("sslCertificates"):
        grouped = refresh_from_api(grouped, gcp.api_build("compute", "v1", credentials=credentials), skipped)
    write_rows(sink, job_id, ARMOR_CHECK, armor_rows(grouped), ARMOR_ALL_CLEAR)
    write_rows(sink, job_id, CERTIFICATE_CHECK, certificate_rows(grouped, now), CERTIFICATE_ALL_CLEAR)
    skipped.write(sink, job_id)
