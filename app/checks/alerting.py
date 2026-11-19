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
"""Alerting hygiene (v18.9): whether an alert reaches anybody, and whether anything watches the edge.

Two records from the Monitoring API (alert policies, notification channels, uptime checks, services and
SLOs — ``roles/monitoring.viewer``) and the inventory (external load balancers, Cloud Run services and GKE
clusters; Pub/Sub topics and their IAM — ``roles/cloudasset.viewer``):

- **Alert Notification Channels** (Operational Excellence, per project): an enabled alert policy with no
  notification channel, or whose channels are all disabled, unverified (``verificationStatus`` ``UNVERIFIED``:
  the API's word for a channel that does not deliver) or gone (Investigation); a Pub/Sub channel whose topic
  is not in the inventory (**Action Required**) or on which the project's Monitoring notification agent holds
  no publisher role (Investigation); a policy with an MQL condition (Informational — MQL is deprecated in
  favour of PromQL). *Monitoring Alert Coverage* says whether a project has alert policies at all; this
  record asks whether the ones it has reach anybody.
- **Synthetic and SLO Coverage** (Reliability, scope-level with per-project reads): an external load balancer
  with no uptime check targeting its address — or any hostname, which the scanner cannot resolve — in its
  project (Investigation); an uptime check with no enabled alert policy on it (Investigation); an SLO with
  no burn-rate alert (Investigation); a project running external load balancers, Cloud Run services or GKE
  clusters with no SLO at all (Informational). The Monitoring reads are made in the projects that run one of
  those; uptime checks and SLOs kept in a metrics scoping project are not seen.
"""
import logging
import re

from app.checks.data_governance import project_ids_by_number
from app.checks.gke_operations import ACTION_REQUIRED, INFORMATIONAL, INVESTIGATION, write_rows
from app.checks.network_edge import is_external, list_assets
from app.checks.not_checked import NotChecked
from app.checks.operations import ALERT_CONDITION_FIELDS
from app.config import SCOPES
from app.services import gcp
from app.utils import service_of

CHANNELS_CHECK = "Alert Notification Channels"
SYNTHETIC_CHECK = "Synthetic and SLO Coverage"
ALERTING_CHECKS = (CHANNELS_CHECK, SYNTHETIC_CHECK)

TOPIC_TYPE = "pubsub.googleapis.com/Topic"
SYNTHETIC_TYPES = ("compute.googleapis.com/ForwardingRule", "compute.googleapis.com/GlobalForwardingRule", "run.googleapis.com/Service", "container.googleapis.com/Cluster")
NOTIFICATION_AGENT = "service-{number}@gcp-sa-monitoring-notification.iam.gserviceaccount.com"
PUBLISHER_ROLES = ("roles/pubsub.publisher", "roles/pubsub.editor", "roles/pubsub.admin", "roles/editor", "roles/owner")
MQL_CONDITION = "conditionMonitoringQueryLanguage"
CHANNEL_TARGET_LABELS = ("email_address", "number", "topic", "channel_name", "url", "service_key")
CHANNELS_ALL_CLEAR = "Every enabled alert policy reaches at least one working notification channel."
SYNTHETIC_ALL_CLEAR = "Every external load balancer has an uptime check, and every uptime check and SLO an alert policy."

_IP_LITERAL = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9a-f:]+:[0-9a-f:]*$", re.I)


# --- reads ------------------------------------------------------------------------------------------------------------

def _paged(collection, key, **kwargs):
    found, request = [], collection.list(**kwargs)
    while request:
        response = request.execute() or {}
        found += response.get(key) or []
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def list_policies(monitoring, project_id):
    return _paged(monitoring.projects().alertPolicies(), "alertPolicies", name=f"projects/{project_id}")


def list_channels(monitoring, project_id):
    return _paged(monitoring.projects().notificationChannels(), "notificationChannels", name=f"projects/{project_id}")


def list_uptime_checks(monitoring, project_id):
    return _paged(monitoring.projects().uptimeCheckConfigs(), "uptimeCheckConfigs", parent=f"projects/{project_id}")


def list_services(monitoring, project_id):
    return _paged(monitoring.services(), "services", parent=f"projects/{project_id}")


def list_slos(monitoring, service_name):
    return _paged(monitoring.services().serviceLevelObjectives(), "serviceLevelObjectives", parent=service_name)


# --- facts ------------------------------------------------------------------------------------------------------------

def tail(name):
    return str(name or "").rsplit("/", 1)[-1]


def policy_label(policy):
    return str(policy.get("displayName") or tail(policy.get("name")) or "?")


def is_enabled(policy):
    return policy.get("enabled") is not False


def condition_texts(policy):
    """The filters and queries of a policy's conditions, lower-cased."""
    texts = []
    for condition in policy.get("conditions") or []:
        for kind, field in ALERT_CONDITION_FIELDS:
            text = (condition.get(kind) or {}).get(field)
            if text:
                texts.append(str(text).lower())
    return texts


def channel_state(channel):
    """``working`` | ``disabled`` | ``unverified``."""
    if channel.get("enabled") is False:
        return "disabled"
    if str(channel.get("verificationStatus") or "").upper() == "UNVERIFIED":
        return "unverified"
    return "working"


def channel_label(channel):
    """``email ops@example.com``, ``pubsub alerts``, ``slack #ops`` — the type and where it goes."""
    labels = channel.get("labels") or {}
    target = str(next((labels[k] for k in CHANNEL_TARGET_LABELS if labels.get(k)), channel.get("displayName") or ""))
    return f"{channel.get('type') or 'channel'} {tail(target) if target.startswith('projects/') else target}".strip()


def channel_rows(project_id, policies, channels, topic_facts=None):
    """The Alert Notification Channels rows of one project. ``topic_facts(topic, channel)`` returns ``{"exists": bool | None, "granted":
    bool | None}`` for a Pub/Sub channel's topic (None: not verifiable); a Pub/Sub channel is judged when an enabled policy uses it."""
    by_name = {str(c.get("name") or ""): c for c in channels}
    rows, pubsub_users = [], {}
    for policy in policies:
        if not is_enabled(policy):
            continue
        label = policy_label(policy)
        base = {"Project": project_id, "Policy": label}
        refs = [str(r) for r in policy.get("notificationChannels") or []]
        if not refs:
            rows.append({**base, "Channels": "none", "Issue": "Fires to nobody.", "Detail": "The policy has no notification channel: an incident opens in the console and nobody is told.",
                         "Fix": f"gcloud alpha monitoring policies update {tail(policy.get('name'))} --project={project_id} --add-notification-channels=<channel>", "_status": INVESTIGATION})
        else:
            states = [(by_name.get(ref), channel_state(by_name[ref]) if ref in by_name else "gone") for ref in refs]
            if all(state != "working" for _, state in states):
                described = "; ".join(f"{channel_label(c) if c else tail(ref)}: {state}" for (c, state), ref in zip(states, refs))
                rows.append({**base, "Channels": ", ".join(channel_label(c) if c else tail(ref) for (c, _), ref in zip(states, refs)),
                             "Issue": "No working channel.", "Detail": f"Every channel of the policy is out of service ({described}): the alert is not delivered.",
                             "Fix": f"gcloud alpha monitoring channels update <channel> --project={project_id} --enabled  # or verify the channel, or attach a working one", "_status": INVESTIGATION})
            for channel, state in states:
                if channel is not None and channel.get("type") == "pubsub" and state == "working":
                    pubsub_users.setdefault(str(channel.get("name")), []).append(label)
        if any(MQL_CONDITION in condition for condition in policy.get("conditions") or []):
            rows.append({**base, "Channels": ", ".join(channel_label(by_name[r]) if r in by_name else tail(r) for r in refs) or "none",
                         "Issue": "MQL condition.", "Detail": "The policy's condition is written in Monitoring Query Language, which Google Cloud has deprecated in favour of PromQL: it keeps working, but new alerting features (long lookbacks, dynamic thresholds) are PromQL-only.",
                         "Fix": f"gcloud alpha monitoring policies update {tail(policy.get('name'))} --project={project_id} --policy-from-file=<policy.json>  # the same condition as conditionPrometheusQueryLanguage",
                         "_status": INFORMATIONAL})
    if topic_facts is not None:
        for name, users in pubsub_users.items():
            channel = by_name[name]
            topic = str((channel.get("labels") or {}).get("topic") or "")
            facts = topic_facts(topic, channel)
            policies_text = ", ".join(users[:3]) + (f" +{len(users) - 3} more" if len(users) > 3 else "")
            base = {"Project": project_id, "Policy": policies_text, "Channels": channel_label(channel)}
            if facts.get("exists") is False:
                rows.append({**base, "Issue": "Pub/Sub topic gone.", "Detail": f"The channel publishes to {topic}, which is not in the inventory: every notification through it is lost.",
                             "Fix": f"gcloud pubsub topics create {tail(topic)} --project={topic.split('/')[1] if topic.count('/') >= 3 else project_id}  # or point the channel at a topic that exists",
                             "_status": ACTION_REQUIRED})
            elif facts.get("exists") and facts.get("granted") is False:
                agent = facts.get("agent") or "the Monitoring notification agent"
                rows.append({**base, "Issue": "Notification agent cannot publish.", "Detail": f"{agent} holds no roles/pubsub.publisher on {topic}: Monitoring cannot deliver to the topic.",
                             "Fix": f"gcloud pubsub topics add-iam-policy-binding {tail(topic)} --project={topic.split('/')[1] if topic.count('/') >= 3 else project_id} --member=serviceAccount:{agent} --role=roles/pubsub.publisher",
                             "_status": INVESTIGATION})
    return rows


def topic_present(asset_names, topic):
    """Whether a topic (``projects/p/topics/t``) is among the inventory names of its project's topics."""
    return any(str(n).endswith("/topics/" + tail(topic)) for n in asset_names)


def publisher_grant_found(policies, topic):
    """Whether the IAM-policy search results for the notification agent hold a publisher role on the topic or its project."""
    project = topic.split("/")[1] if topic.count("/") >= 3 else ""
    for result in policies:
        resource = str(getattr(result, "resource", "") or "")
        bindings = getattr(getattr(result, "policy", None), "bindings", None) or []
        if not {str(getattr(b, "role", "") or "") for b in bindings} & set(PUBLISHER_ROLES):
            continue
        if resource.endswith("/" + topic) or resource.endswith("/topics/" + tail(topic)):
            return True
        if project and service_of(resource) == "cloudresourcemanager.googleapis.com" and resource.endswith(f"/projects/{project}"):
            return True
    return False


def check_alert_channels(scope_id, all_projects, job_id, *, sink):
    """Writes *Alert Notification Channels* for every project (module docstring)."""
    print(f"📣 [{job_id}] Checking {CHANNELS_CHECK} in {len(all_projects)} projects...")
    skipped, rows = NotChecked(CHANNELS_CHECK), []
    topics, grants = {}, {}
    for project in all_projects:
        project_id, number = project["projectId"], str(project.get("projectNumber") or "")
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            monitoring = gcp.api_build("monitoring", "v3", credentials=credentials)
            policies = list_policies(monitoring, project_id)
            channels = list_channels(monitoring, project_id) if any(is_enabled(p) and p.get("notificationChannels") for p in policies) else []
        except Exception as e:
            skipped.add(project_id, e)
            continue
        asset_client = gcp.asset_client(credentials)

        def topic_facts(topic, channel, project_id=project_id, number=number):
            topic_project = topic.split("/")[1] if topic.count("/") >= 3 else project_id
            if topic_project not in topics:
                try:
                    topics[topic_project] = [str(getattr(a, "name", "") or "") for a in list_assets(asset_client, f"projects/{topic_project}", [TOPIC_TYPE])]
                except Exception as e:  # noqa: BLE001 — a topic in a project the scanner cannot read
                    skipped.add(project_id, e, detail=f"the topics of {topic_project} could not be listed; the Pub/Sub channel's topic is not verified")
                    topics[topic_project] = None
            facts = {"exists": None if topics[topic_project] is None else topic_present(topics[topic_project], topic), "granted": None, "agent": ""}
            if facts["exists"] and number:
                agent = NOTIFICATION_AGENT.format(number=number)
                facts["agent"] = agent
                key = (topic_project, agent)
                if key not in grants:
                    try:
                        grants[key] = list(asset_client.search_all_iam_policies(request={"scope": f"projects/{topic_project}", "query": f'policy:"{agent}"', "page_size": 500}))
                    except Exception as e:  # noqa: BLE001
                        skipped.add(project_id, e, detail=f"the IAM-policy search in {topic_project} failed; the notification agent's grant is not verified")
                        grants[key] = None
                if grants[key] is not None:
                    facts["granted"] = publisher_grant_found(grants[key], topic)
            return facts

        rows += channel_rows(project_id, policies, channels, topic_facts)
    write_rows(sink, job_id, CHANNELS_CHECK, rows, CHANNELS_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- Synthetic and SLO Coverage --------------------------------------------------------------------------------------------

def workload_facts(assets):
    """``{project: {"lbs": [(name, address)], "services": [names], "clusters": [names]}}`` over the listing: the external forwarding
    rules (regional and global), the Cloud Run services, the GKE clusters."""
    found = {}
    for asset in assets:
        name = str(getattr(asset, "name", "") or "")
        parts = name.split("/")
        if "projects" not in parts or parts.index("projects") + 1 >= len(parts):
            continue
        project = parts[parts.index("projects") + 1]
        data = getattr(getattr(asset, "resource", None), "data", None) or {}
        entry = found.setdefault(project, {"lbs": [], "services": [], "clusters": []})
        if "forwardingRules" in parts:
            if is_external(data):
                entry["lbs"].append((data.get("name") or parts[-1], str(data.get("IPAddress") or "")))
        elif "services" in parts:
            entry["services"].append(parts[-1])
        elif "clusters" in parts:
            entry["clusters"].append(parts[-1])
    return found


def uptime_targets(checks):
    """``[(check id, host or "", display name)]`` of uptime checks — the host of a ``uptime_url`` monitored resource, ``""`` for groups."""
    targets = []
    for check in checks:
        labels = (check.get("monitoredResource") or {}).get("labels") or {}
        targets.append((tail(check.get("name")), str(labels.get("host") or ""), str(check.get("displayName") or tail(check.get("name")))))
    return targets


def lb_watched(address, targets):
    """An uptime check targets the address — or a hostname, which may resolve to it (the scanner does not resolve names)."""
    for _, host, _ in targets:
        if host and (host == address or not _IP_LITERAL.match(host)):
            return True
    return False


def uptime_alerted(check_id, texts):
    """An enabled policy names the check (``check_id="…"``), or watches every check (``check_passed`` / ``uptime_url`` with no check named)."""
    check_id = check_id.lower()
    return any(check_id in t for t in texts) or any(("check_passed" in t or "uptime_url" in t) and "check_id" not in t for t in texts)


def slo_alerted(slo_name, texts):
    """An enabled policy selects the SLO's burn rate, health or budget (``select_slo_*("…/serviceLevelObjectives/ID", …)``)."""
    slo_id = tail(slo_name).lower()
    return any("select_slo_" in t and slo_id in t for t in texts)


def synthetic_rows(project_id, facts, checks, slos_by_service, policies):
    """The rows of one project: ``facts`` from :func:`workload_facts`, ``checks`` its uptime checks, ``slos_by_service`` ``{service name:
    [SLOs]}``, ``policies`` its alert policies."""
    rows = []
    targets = uptime_targets(checks)
    texts = [t for p in policies if is_enabled(p) for t in condition_texts(p)]
    for name, address in facts.get("lbs") or []:
        if not lb_watched(address, targets):
            rows.append({"Project": project_id, "Resource": name, "Kind": "external load balancer", "Issue": "No uptime check.",
                         "Detail": f"Nothing probes {address or 'the load balancer'} from outside: an outage is noticed by its users first.",
                         "Fix": f"gcloud monitoring uptime create {name}-uptime --project={project_id} --resource-type=uptime-url --resource-labels=host={address or '<address>'},project_id={project_id} --protocol=https --port=443 --path=/",
                         "_status": INVESTIGATION})
    for check_id, host, display in targets:
        if not uptime_alerted(check_id, texts):
            rows.append({"Project": project_id, "Resource": display, "Kind": "uptime check", "Issue": "No alert policy.",
                         "Detail": f"The uptime check{f' on {host}' if host else ''} fails silently: no enabled alert policy watches check_passed for it.",
                         "Fix": f"gcloud alpha monitoring policies create --project={project_id} --policy-from-file=<policy.json>  # a conditionThreshold on "
                                f"metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND metric.labels.check_id=\"{check_id}\", count_false, 2 regions",
                         "_status": INVESTIGATION})
    total_slos = 0
    for service, slos in slos_by_service.items():
        for slo in slos:
            total_slos += 1
            if not slo_alerted(slo.get("name"), texts):
                rows.append({"Project": project_id, "Resource": f"{tail(service)} / {slo.get('displayName') or tail(slo.get('name'))}", "Kind": "SLO", "Issue": "No burn-rate alert.",
                             "Detail": "The SLO has no enabled alert policy on its error-budget burn rate: a breach is seen in the dashboard, after the fact.",
                             "Fix": f"gcloud alpha monitoring policies create --project={project_id} --policy-from-file=<policy.json>  # a conditionThreshold on "
                                    f"select_slo_burn_rate(\"{slo.get('name')}\", \"60m\") > 10",
                             "_status": INVESTIGATION})
    if total_slos == 0 and (facts.get("lbs") or facts.get("services") or facts.get("clusters")):
        running = [f"{len(v)} {k}" for k, v in (("external load balancer(s)", facts.get("lbs") or []), ("Cloud Run service(s)", facts.get("services") or []), ("GKE cluster(s)", facts.get("clusters") or [])) if v]
        rows.append({"Project": project_id, "Resource": "—", "Kind": "SLO", "Issue": "No SLO.",
                     "Detail": f"The project runs {', '.join(running)} and defines no service-level objective: there is no agreed target to alert on.",
                     "Fix": f"gcloud alpha monitoring services create --project={project_id} ...  # then an SLO (services.serviceLevelObjectives.create) and a burn-rate policy", "_status": INFORMATIONAL})
    return rows


def check_synthetic_coverage(scope, scope_id, job_id, *, sink):
    """Writes *Synthetic and SLO Coverage* (module docstring): one listing of the scope's external load balancers, Cloud Run services and
    GKE clusters; uptime checks, services, SLOs and alert policies from the Monitoring API of each project that runs one of them."""
    print(f"🛰️  [{job_id}] Checking {SYNTHETIC_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        facts_by_project = workload_facts(list_assets(asset_client, parent, list(SYNTHETIC_TYPES)))
    except Exception as e:
        logging.error(f"[{job_id}] {SYNTHETIC_CHECK}: could not list under {parent}: {e}")
        sink.write_finding(job_id, SYNTHETIC_CHECK.replace(" ", "_"), {"Check": SYNTHETIC_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped = NotChecked(SYNTHETIC_CHECK)
    if any(p.isdigit() for p in facts_by_project):  # the inventory names some resources by project number; the report names projects by ID
        try:
            ids = project_ids_by_number(asset_client, parent)
            renamed = {}
            for number, facts in facts_by_project.items():
                target = renamed.setdefault(ids.get(number, number), {"lbs": [], "services": [], "clusters": []})
                for key in target:
                    target[key] += facts[key]
            facts_by_project = renamed
        except Exception as e:
            skipped.add(parent, e, detail="project names: the project search failed; the projects named by number stay so")
    rows = []
    for project_id in sorted(facts_by_project):
        facts = facts_by_project[project_id]
        try:
            monitoring = gcp.api_build("monitoring", "v3", credentials=credentials)
            checks = list_uptime_checks(monitoring, project_id)
            slos_by_service = {str(s.get("name") or ""): list_slos(monitoring, str(s.get("name") or "")) for s in list_services(monitoring, project_id)}
            policies = list_policies(monitoring, project_id) if checks or any(slos_by_service.values()) else []
        except Exception as e:
            skipped.add(project_id, e)
            continue
        rows += synthetic_rows(project_id, facts, checks, slos_by_service, policies)
    write_rows(sink, job_id, SYNTHETIC_CHECK, rows, SYNTHETIC_ALL_CLEAR)
    skipped.write(sink, job_id)
