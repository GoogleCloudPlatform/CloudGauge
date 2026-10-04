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
"""The synthetic Google Cloud provider: answers every data-plane API the checks
call from a :class:`~app.synthetic.world.SyntheticOrg`, with simulated latency,
optional 429s, and call metrics.

Installed through ``app.services.gcp.install_provider``. It stands in for:

- Discovery clients (``gcp.api_build``): Resource Manager, Compute, IAM, SQL
  Admin, GKE, Recommender (REST), Monitoring, Logging, SCC, Essential Contacts,
  Advisory Notifications and Org Policy calls. Unknown methods answer ``{}`` and
  are counted, so a new check degrades to "nothing found" instead of failing.
  The Cloud Run Admin API (``run``) is passed through to the real library: it
  is infrastructure (worker URL discovery), not scan data.
- Cloud Asset Inventory, Recommender (gRPC), OS Config, per-project Storage and
  the plain HTTP GETs: the best-practices CSV and the Service Health events of a
  project (``servicehealth.googleapis.com/v1/projects/{id}/locations/global/events``).

Every API call goes through :meth:`SyntheticGcp.call`, which records it,
raises for denied projects or an injected 429, then sleeps for a log-normal
latency around ``latency_ms`` (scaled per API, and per page for list calls).
The same request always gets the same data; only latency and injected errors
are random.
"""
import json
import logging
import math
import random
import re
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import google.auth
import google.auth.exceptions
import httplib2
from google.api_core import exceptions as core_exceptions
from google.cloud import recommender_v1
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from app.checks.cost import COST_RECOMMENDERS
from app.checks.network import NETWORK_INSIGHT_TYPES
from app.synthetic.world import (ADVISORY_TYPES, BEST_PRACTICES_CSV, GKE_CHANNEL_MINORS, GKE_MINORS, GKE_VERSIONS, HOST_PROJECT,
                                 INCIDENTS, ORG_ADVISORIES, PROJECT_ADVISORY, QUOTA_METRICS, REGIONS, SyntheticOrg, gke_version)

# Median latency of each API relative to ``latency_ms``.
API_LATENCY_SCALE = {
    "cloudresourcemanager": 0.8, "compute": 1.0, "iam": 1.0, "sqladmin": 1.2, "container": 1.5,
    "recommender": 1.6, "monitoring": 1.2, "logging": 1.0, "securitycenter": 1.0, "essentialcontacts": 1.0,
    "asset": 2.0, "osconfig": 0.8, "storage": 0.8, "http": 1.0, "servicehealth": 1.2, "advisorynotifications": 1.0,
}
LATENCY_SIGMA = 0.45  # log-normal spread: p95 is about 2x the median
PASSTHROUGH_SERVICES = ("run",)  # infrastructure APIs the synthetic provider never fakes
PAGE_SIZE = 100
COST_RECOMMENDER_IDS = {rec_id: check for check, (rec_id, _) in COST_RECOMMENDERS.items()}
NETWORK_INSIGHT_IDS = {insight_id: check for check, insight_id in NETWORK_INSIGHT_TYPES.items()}
UNATTENDED_RECOMMENDER = "google.resourcemanager.projectUtilization.Recommender"
RECENT_CHANGE_INSIGHT = "google.cloud.RecentChangeInsight"


class CallMetrics:
    """Thread-safe counters for the synthetic API calls."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.calls = Counter()  # (api, method) -> count
            self.errors = Counter()  # (api, status) -> count
            self.pages = 0
            self.slept_seconds = 0.0
            self.in_flight = 0
            self.max_in_flight = 0
            self.started_at = time.monotonic()

    def start(self, api, method, pages):
        with self._lock:
            self.calls[(api, method)] += 1
            self.pages += pages
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)

    def finish(self, slept):
        with self._lock:
            self.in_flight -= 1
            self.slept_seconds += slept

    def error(self, api, status):
        with self._lock:
            self.errors[(api, status)] += 1

    def snapshot(self):
        """A plain-dict summary: totals, per-API and per-method counts, errors, concurrency."""
        with self._lock:
            by_api = Counter()
            for (api, _), count in self.calls.items():
                by_api[api] += count
            return {
                "total_calls": sum(self.calls.values()),
                "total_pages": self.pages,
                "by_api": dict(by_api.most_common()),
                "by_method": {f"{api}.{method}": count for (api, method), count in self.calls.most_common()},
                "errors": {f"{api}:{status}": count for (api, status), count in self.errors.most_common()},
                "simulated_wait_seconds": round(self.slept_seconds, 3),
                "max_in_flight": self.max_in_flight,
                "elapsed_seconds": round(time.monotonic() - self.started_at, 1),
            }


class SyntheticCredentials:
    """Stands in for ADC. Never sent anywhere: every API that would use it is synthetic."""

    token = "synthetic-access-token"

    def refresh(self, request):
        pass


def _http_error(status, message, uri="https://synthetic.googleapis.com/"):
    content = json.dumps({"error": {"code": status, "message": message, "status": {403: "PERMISSION_DENIED", 404: "NOT_FOUND", 429: "RESOURCE_EXHAUSTED"}.get(status, "ERROR")}}).encode()
    return HttpError(httplib2.Response({"status": status, "reason": message}), content, uri=uri)


def _grpc_error(status, message):
    if status == 403:
        return core_exceptions.PermissionDenied(message)
    if status == 404:
        return core_exceptions.NotFound(message)
    if status == 429:
        return core_exceptions.ResourceExhausted(message)
    return core_exceptions.GoogleAPICallError(message)


def _project_of(resource_name):
    """The project ID in ``projects/<id>/...`` or ``//.../projects/<id>/...``, else ``None``."""
    parts = resource_name.split("/")
    return parts[parts.index("projects") + 1] if "projects" in parts else None


def _iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class SyntheticGcp:
    """The provider installed by the synthetic profile. See the module docstring."""

    name = "synthetic"

    def __init__(self, n_projects, seed=42, latency_ms=150.0, error_rate=0.0, denied_fraction=0.02):
        self.world = SyntheticOrg(n_projects, seed=seed, denied_fraction=denied_fraction)
        self.latency_ms = float(latency_ms)
        self.error_rate = float(error_rate)
        self.metrics = CallMetrics()
        self._random = random.Random(seed)  # latency and injected errors; data never depends on it
        self._unknown = set()
        self._credentials = None
        self._credentials_lock = threading.Lock()

    def describe(self):
        return {"projects": self.world.n_projects, "seed": self.world.seed, "latency_ms": self.latency_ms,
                "error_rate": self.error_rate, "denied_fraction": self.world.denied_fraction}

    # --- the one place every call goes through ---

    def call(self, api, method, project_id=None, pages=1, style="grpc"):
        """Records the call, raises injected errors, then waits the simulated latency."""
        self.metrics.start(api, method, pages)
        slept = 0.0
        try:
            if project_id is not None:
                profile = self.world.project(project_id)
                if profile is None:
                    self.metrics.error(api, 404)
                    raise self._error(style, 404, f"Project {project_id} not found")
                if profile.denied:
                    self.metrics.error(api, 403)
                    raise self._error(style, 403, f"Permission denied on project {project_id} (synthetic)")
            if self.error_rate and self._random.random() < self.error_rate:
                self.metrics.error(api, 429)
                raise self._error(style, 429, f"Quota exceeded for {api}.{method} (synthetic)")
            if self.latency_ms > 0:
                median = self.latency_ms / 1000.0 * API_LATENCY_SCALE.get(api, 1.0)
                slept = sum(self._random.lognormvariate(math.log(median), LATENCY_SIGMA) for _ in range(pages))
                time.sleep(slept)
        finally:
            self.metrics.finish(slept)

    @staticmethod
    def _error(style, status, message):
        return _http_error(status, message) if style == "http" else _grpc_error(status, message)

    # --- gcp provider interface ---

    def auth_default(self, scopes=None, **kwargs):
        """Real Application Default Credentials when they exist, synthetic ones otherwise.

        The provider fakes *data*, not identity: the calls that pass through
        (Cloud Run Admin for the worker URL, IAM signing for the CSV link) need
        real credentials on a deployed synthetic revision. Offline (the harness,
        tests) nothing consumes them, so a stand-in is enough. Resolved once:
        the checks ask for credentials per project, and ``google.auth.default``
        probes the environment every time.
        """
        if self._credentials is None:
            with self._credentials_lock:
                if self._credentials is None:
                    try:
                        self._credentials, _ = google.auth.default(scopes=scopes, **kwargs)
                    except google.auth.exceptions.DefaultCredentialsError:
                        logging.info("Synthetic provider: no Application Default Credentials; using synthetic credentials")
                        self._credentials = SyntheticCredentials()
        return self._credentials, HOST_PROJECT

    def api_build(self, serviceName, version, **kwargs):
        if serviceName in PASSTHROUGH_SERVICES:
            return discovery.build(serviceName, version, **kwargs)
        return _DiscoveryStub(self, serviceName, version)

    def project_storage_client(self, project_id):
        return _StorageStub(self, project_id)

    def asset_client(self, credentials=None):
        return _AssetStub(self)

    def recommender_client(self, credentials=None):
        return _RecommenderStub(self)

    def osconfig_client(self):
        return _OsConfigStub(self)

    def http_get(self, url, **kwargs):
        if "servicehealth.googleapis.com/" in url:
            return self._service_health_events(url, kwargs.get("params") or {})
        self.call("http", "GET", style="http")
        text = BEST_PRACTICES_CSV if url.lower().endswith(".csv") else "{}"
        return _HttpResponse(200, text)

    def _service_health_events(self, url, params):
        """``GET .../v1/projects/{id}/locations/global/events``: the project's view of the organization's incidents."""
        project_id = _project_of(url.split("?")[0])
        try:
            self.call("servicehealth", "events.list", project_id=project_id, style="http")
        except HttpError as e:  # a denied project or an injected 429, as requests would deliver it
            return _HttpResponse(e.resp.status, e.content.decode() if isinstance(e.content, bytes) else str(e.content))
        profile = self.world.project(project_id)
        if profile.servicehealth_disabled:
            message = (f"Service Health API has not been used in project {project_id} before or it is disabled. Enable it by visiting "
                       f"https://console.developers.google.com/apis/api/servicehealth.googleapis.com/overview?project={project_id} then retry.")
            return _HttpResponse(403, json.dumps({"error": {"code": 403, "message": message, "status": "PERMISSION_DENIED"}}))
        match = re.search(r'update_time\s*>=\s*"([^"]+)"', str(params.get("filter", "")))
        since = match.group(1) if match else ""
        events = []
        for incident_id, title, product, location, state, started, ended in INCIDENTS:
            relevance = profile.incident_relevance.get(incident_id)
            updated = _iso(ended if ended is not None else 0)
            if relevance is None or updated < since:
                continue
            events.append({
                "name": f"projects/{project_id}/locations/global/events/{incident_id}", "title": title,
                "category": "INCIDENT", "detailedCategory": "CONFIRMED_INCIDENT", "state": state,
                "detailedState": "CONFIRMED" if state == "ACTIVE" else "RESOLVED", "relevance": relevance,
                "eventImpacts": [{"product": {"productName": product, "id": product.lower().replace(" ", "-")},
                                  "location": {"locationName": location}}],
                "updateTime": updated, "startTime": _iso(started), **({"endTime": _iso(ended)} if ended is not None else {}),
            })
        return _HttpResponse(200, json.dumps({"events": events}))

    # --- Discovery API handlers: "service.resource.method" -> response dict ---

    def dispatch(self, service, path, kwargs):
        method = ".".join(path)
        handler = getattr(self, "_h_" + f"{service}.{method}".replace(".", "_"), None)
        project_id = kwargs.get("project") or kwargs.get("projectId")
        if project_id is None:
            for key in ("name", "parent"):  # projects/<id>/..., as in GKE's parent=projects/<id>/locations/-
                value = str(kwargs.get(key, ""))
                if value.startswith("projects/"):
                    project_id = _project_of(value)
                    break
        if project_id is None and "resource" in kwargs and not str(kwargs["resource"]).count("/"):
            project_id = kwargs["resource"]
        if project_id is not None and str(project_id).isdigit():  # addressed by number (Advisory Notifications)
            project_id = self.world.project_id_for_number(project_id) or project_id
        if project_id == HOST_PROJECT:
            project_id = None
        if handler is None:
            key = f"{service}.{method}"
            if key not in self._unknown:
                self._unknown.add(key)
                logging.warning(f"Synthetic provider: no handler for {key}; answering {{}}")
            self.call(service, method + "?", project_id=project_id, style="http")
            return {}
        return handler(kwargs, project_id)

    def _h_cloudresourcemanager_projects_get(self, kw, project_id):
        self.call("cloudresourcemanager", "projects.get", style="http")
        profile = self.world.project(kw["projectId"])
        if profile is None:
            raise _http_error(404, f"Project {kw['projectId']} not found")
        return {"projectId": profile.project_id, "name": profile.display_name, "lifecycleState": "ACTIVE",
                "projectNumber": profile.project_number}

    def _h_cloudresourcemanager_projects_getIamPolicy(self, kw, project_id):
        self.call("cloudresourcemanager", "projects.getIamPolicy", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        bindings = [{"role": "roles/viewer", "members": ["group:readers@example.com"]}]
        by_role = {}
        for role, member in profile.primitive_bindings:
            by_role.setdefault(role, []).append(member)
        bindings += [{"role": role, "members": members} for role, members in by_role.items()]
        return {"bindings": bindings, "etag": "synthetic"}

    def _h_cloudresourcemanager_projects_getAncestry(self, kw, project_id):
        self.call("cloudresourcemanager", "projects.getAncestry", style="http")
        pid = kw["projectId"]
        ancestors = [{"resourceId": {"type": "project", "id": pid}}]
        profile = self.world.project(pid)
        if profile is not None:
            ancestors.append({"resourceId": {"type": "folder", "id": profile.folder_id}})
        ancestors.append({"resourceId": {"type": "organization", "id": self.world.org_id}})
        return {"ancestor": ancestors}

    def _h_cloudresourcemanager_organizations_getIamPolicy(self, kw, project_id):
        self.call("cloudresourcemanager", "organizations.getIamPolicy", style="http")
        return {"bindings": self.world.org_iam_bindings()}

    def _list_org_policies(self, kw, project_id):
        self.call("cloudresourcemanager", "listOrgPolicies", project_id=project_id, style="http")
        return {"policies": self.world.org_policies(kw["resource"])}

    _h_cloudresourcemanager_organizations_listOrgPolicies = _list_org_policies
    _h_cloudresourcemanager_folders_listOrgPolicies = _list_org_policies
    _h_cloudresourcemanager_projects_listOrgPolicies = _list_org_policies

    def _h_cloudresourcemanager_folders_get(self, kw, project_id):
        self.call("cloudresourcemanager", "folders.get", style="http")
        return {"name": kw["name"], "parent": f"organizations/{self.world.org_id}", "displayName": "Synthetic folder"}

    def _h_compute_instances_aggregatedList(self, kw, project_id):
        self.call("compute", "instances.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        for vm in profile.vms:
            instance = {
                "name": vm.name, "status": "RUNNING",
                "zone": f"https://www.googleapis.com/compute/v1/projects/{project_id}/zones/{vm.zone}",
                "networkInterfaces": [{"network": "vpc-main", **({"accessConfigs": [{"natIP": "203.0.113.10"}]} if vm.external_ip else {})}],
                "labels": {}, "metadata": {"items": ([{"key": "created-by", "value": f"mig-{vm.zone}"}] if vm.in_mig else [])},
            }
            items.setdefault(f"zones/{vm.zone}", {"instances": []})["instances"].append(instance)
        return {"items": items}

    def _h_compute_addresses_aggregatedList(self, kw, project_id):
        self.call("compute", "addresses.aggregatedList", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": {f"regions/{r}": {"addresses": [{"name": f"ip-{r}", "status": "RESERVED"}]} for r in profile.addresses_regions}}

    def _h_compute_forwardingRules_aggregatedList(self, kw, project_id):
        self.call("compute", "forwardingRules.aggregatedList", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": {f"regions/{r}": {"forwardingRules": [{"name": f"lb-{r}"}]} for r in profile.forwarding_rule_regions}}

    def _h_compute_firewalls_list(self, kw, project_id):
        self.call("compute", "firewalls.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": name, "network": f"projects/{project_id}/global/networks/vpc-main",
                           "sourceRanges": ["0.0.0.0/0"] if open_rule else ["10.0.0.0/8"], "disabled": disabled}
                          for name, open_rule, disabled in profile.firewall_rules]}

    def _h_compute_networks_list(self, kw, project_id):
        self.call("compute", "networks.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": "vpc-main"}] + ([{"name": "default"}] if profile.has_default_vpc else [])}

    def _h_compute_regions_list(self, kw, project_id):
        self.call("compute", "regions.list", project_id=project_id, style="http")
        return {"items": [{"name": region} for region in REGIONS]}

    def _h_compute_regions_get(self, kw, project_id):
        self.call("compute", "regions.get", project_id=project_id, style="http")
        profile, region = self.world.project(project_id), kw["region"]
        hot = {metric: (usage, limit) for r, metric, usage, limit in profile.hot_quotas if r == region}
        return {"name": region, "quotas": [{"metric": m, "usage": float(hot.get(m, (3, 100))[0]), "limit": float(hot.get(m, (3, 100))[1])}
                                           for m in QUOTA_METRICS]}

    def _h_compute_subnetworks_list(self, kw, project_id):
        self.call("compute", "subnetworks.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": name, "region": region, "privateIpGoogleAccess": pga}
                          for name, region, pga in profile.subnets if region == kw["region"]]}

    def _h_iam_projects_serviceAccounts_list(self, kw, project_id):
        self.call("iam", "serviceAccounts.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"accounts": [{"name": f"projects/{project_id}/serviceAccounts/{sa.email}", "email": sa.email}
                             for sa in profile.service_accounts]}

    def _h_iam_projects_serviceAccounts_keys_list(self, kw, project_id):
        self.call("iam", "serviceAccounts.keys.list", project_id=project_id, style="http")
        profile, email = self.world.project(project_id), kw["name"].rsplit("/", 1)[-1]
        for sa in profile.service_accounts:
            if sa.email == email:
                return {"keys": [{"name": f"{kw['name']}/keys/{i}", "validAfterTime": _iso(age), "keyType": "USER_MANAGED"}
                                 for i, age in enumerate(sa.key_ages_days)]}
        return {"keys": []}

    def _h_sqladmin_instances_list(self, kw, project_id):
        self.call("sqladmin", "instances.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": sql.name, "settings": {"ipConfiguration": {"ipv4Enabled": sql.public_ip, "requireSsl": sql.require_ssl}}}
                          for sql in profile.sql_instances]}

    def _h_container_projects_locations_clusters_list(self, kw, project_id):
        self.call("container", "clusters.list", project_id=project_id, style="http")
        profile, clusters = self.world.project(project_id), []
        for cluster in profile.gke_clusters:
            entry = {"name": cluster.name, "location": cluster.location,
                     "currentMasterVersion": cluster.master_version, "currentNodeVersion": cluster.node_pools[0][2],
                     "nodePools": [{"name": name, "version": version, "management": {"autoUpgrade": auto}}
                                   for name, auto, version in cluster.node_pools]}
            if cluster.release_channel:
                entry["releaseChannel"] = {"channel": "REGULAR"}
            clusters.append(entry)
        return {"clusters": clusters}

    def _h_container_projects_locations_getServerConfig(self, kw, project_id):
        """The versions GKE offers in a location (the same everywhere): the static lists and the REGULAR channel's."""
        self.call("container", "projects.locations.getServerConfig", project_id=project_id, style="http")
        channel_versions = [v for v in GKE_VERSIONS if v.rsplit(".", 2)[0] in GKE_CHANNEL_MINORS]
        return {"defaultClusterVersion": gke_version(GKE_MINORS[1]),
                "validMasterVersions": list(GKE_VERSIONS), "validNodeVersions": list(GKE_VERSIONS),
                "channels": [{"channel": "REGULAR", "defaultVersion": gke_version(GKE_MINORS[1]), "validVersions": channel_versions}]}

    def _h_recommender_projects_locations_recommenders_recommendations_list(self, kw, project_id):
        parent = kw["parent"]
        project_id = _project_of(parent)
        self.call("recommender", "recommendations.list(rest)", project_id=project_id, style="http")
        profile, location = self.world.project(project_id), parent.split("/locations/")[1].split("/")[0]
        recos = [{"name": f"{parent}/recommendations/{i}", "description": text}
                 for cluster in profile.gke_clusters if cluster.location == location
                 for i, text in enumerate(cluster.recommendations)]
        return {"recommendations": recos}

    def _h_monitoring_projects_alertPolicies_list(self, kw, project_id):
        self.call("monitoring", "alertPolicies.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"alertPolicies": [{"displayName": f"alert-{i}", "conditions": [{"conditionThreshold": {"filter": f'metric.type="{f}"'}}]}
                                  for i, f in enumerate(profile.alert_filters)]}

    def _h_logging_organizations_sinks_list(self, kw, project_id):
        self.call("logging", "sinks.list", style="http")
        return {"sinks": [{"name": "org-audit-sink", "destination": f"bigquery.googleapis.com/projects/{HOST_PROJECT}/datasets/audit_logs"}]}

    def _h_securitycenter_organizations_getOrganizationSettings(self, kw, project_id):
        self.call("securitycenter", "getOrganizationSettings", style="http")
        return {"name": kw["name"], "tier": "STANDARD"}

    def _h_essentialcontacts_organizations_contacts_list(self, kw, project_id):
        self.call("essentialcontacts", "contacts.list", style="http")
        return {"contacts": [{"email": "security@example.com", "notificationCategorySubscriptions": ["SECURITY"]},
                             {"email": "ops@example.com", "notificationCategorySubscriptions": ["TECHNICAL"]}]}

    # --- Advisory Notifications ---

    @staticmethod
    def _notification(parent, index, advisory):
        kind, subject, days_ago, body, attachments = advisory
        return {
            "name": f"{parent}/notifications/syn-notification-{index}", "notificationType": kind, "createTime": _iso(days_ago),
            "subject": {"text": {"enText": subject, "localizedText": subject, "localizationState": "LOCALIZATION_STATE_NOT_APPLICABLE"}},
            "messages": [{
                "createTime": _iso(days_ago), "localizationTime": _iso(days_ago),
                "body": {"text": {"enText": body, "localizedText": body, "localizationState": "LOCALIZATION_STATE_NOT_APPLICABLE"}},
                "attachments": [{"displayName": name, "csv": {"headers": list(headers), "dataRows": [{"entries": list(row)} for row in rows]}}
                                for name, headers, rows in attachments],
            }],
        }

    def _h_advisorynotifications_organizations_locations_notifications_list(self, kw, project_id):
        self.call("advisorynotifications", "notifications.list(organization)", style="http")
        parent = kw["parent"]
        return {"notifications": [self._notification(parent, i, advisory) for i, advisory in enumerate(ORG_ADVISORIES)]}

    def _h_advisorynotifications_organizations_locations_getSettings(self, kw, project_id):
        self.call("advisorynotifications", "getSettings(organization)", style="http")
        return {"name": kw["name"], "etag": "synthetic", "notificationSettings": {kind: {"enabled": True} for kind in ADVISORY_TYPES}}

    def _h_advisorynotifications_projects_locations_notifications_list(self, kw, project_id):
        self.call("advisorynotifications", "notifications.list(project)", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"notifications": [self._notification(kw["parent"], 0, PROJECT_ADVISORY)] if profile.has_project_advisory else []}

    def _h_advisorynotifications_projects_locations_getSettings(self, kw, project_id):
        self.call("advisorynotifications", "getSettings(project)", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"name": kw["name"], "etag": "synthetic",
                "notificationSettings": {kind: {"enabled": kind not in profile.advisory_types_disabled} for kind in ADVISORY_TYPES}}

    # --- Asset Inventory ---

    def search_all_resources(self, request):
        scope, asset_types = request["scope"], request.get("asset_types", [])
        folder_id = scope.split("/")[1] if scope.startswith("folders/") else None
        results = []
        if "cloudresourcemanager.googleapis.com/Folder" in asset_types and folder_id is None:
            results += [SimpleNamespace(name=f"//cloudresourcemanager.googleapis.com/folders/{fid}", display_name=f"Synthetic folder {i}",
                                        asset_type="cloudresourcemanager.googleapis.com/Folder", project="")
                        for i, fid in enumerate(self.world.folder_ids)]
        if "cloudresourcemanager.googleapis.com/Project" in asset_types:
            results += [SimpleNamespace(name=f"//cloudresourcemanager.googleapis.com/projects/{p.project_id}", display_name=p.display_name,
                                        asset_type="cloudresourcemanager.googleapis.com/Project", project=f"projects/{p.project_number}")
                        for p in self.world.projects(folder_id)]
        self.call("asset", "searchAllResources", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
        return results

    def list_assets(self, request):
        parent, asset_types = request["parent"], set(request.get("asset_types", []))
        if parent.startswith("projects/"):
            project_id = parent.split("/", 1)[1]
            self.call("asset", "listAssets(project)", project_id=project_id)
            profile = self.world.project(project_id)
            found = []
            if "sqladmin.googleapis.com/Instance" in asset_types:
                found += [self._sql_asset(profile, sql) for sql in profile.sql_instances]
            if "container.googleapis.com/Cluster" in asset_types:
                found += [SimpleNamespace(name=f"//container.googleapis.com/projects/{project_id}/locations/{c.location}/clusters/{c.name}",
                                          resource=SimpleNamespace(data={"name": c.name})) for c in profile.gke_clusters]
            if "compute.googleapis.com/ForwardingRule" in asset_types:
                found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{project_id}/regions/{r}/forwardingRules/lb-{r}",
                                          resource=SimpleNamespace(data={"name": f"lb-{r}"})) for r in profile.forwarding_rule_regions]
            return found
        # Organization-wide listing: one pass over every project.
        found = []
        for profile in self.world.projects():
            if "sqladmin.googleapis.com/Instance" in asset_types:
                found += [self._sql_asset(profile, sql) for sql in profile.sql_instances]
            if "compute.googleapis.com/InstanceGroupManager" in asset_types:
                found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/zones/{zone}/instanceGroupManagers/mig-{zone}",
                                          resource=SimpleNamespace(data={"name": f"mig-{zone}", "zone": zone})) for zone in profile.mig_zones]
            if "compute.googleapis.com/Snapshot" in asset_types:
                found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/global/snapshots/snap-{i}",
                                          resource=SimpleNamespace(data={"name": f"snap-{i}", "storageLocations": ["us-central1"]}))
                          for i in range(profile.single_region_snapshots)]
        self.call("asset", "listAssets(org)", pages=max(1, math.ceil(len(found) / PAGE_SIZE)))
        return found

    @staticmethod
    def _sql_asset(profile, sql):
        data = {"name": sql.name, "settings": {
            "availabilityType": "ZONAL" if sql.zonal else "REGIONAL",
            "backupConfiguration": {"enabled": sql.backups, "pointInTimeRecoveryEnabled": sql.pitr, "retainedBackupsCount": sql.retained_backups}}}
        return SimpleNamespace(name=f"//cloudsql.googleapis.com/projects/{profile.project_id}/instances/{sql.name}",
                               resource=SimpleNamespace(data=data))

    # --- Recommender (gRPC) ---

    def list_recommendations(self, parent):
        project_id = _project_of(parent)
        self.call("recommender", "recommendations.list", project_id=project_id)
        recommender_id = parent.rsplit("/recommenders/", 1)[-1]
        if project_id is None:
            if recommender_id != UNATTENDED_RECOMMENDER:
                return []
            return [recommender_v1.Recommendation({
                "name": f"{parent}/recommendations/{i}", "recommender_subtype": "CLEANUP_PROJECT",
                "description": f"Project `{pid}` has been unattended for 90 days. Consider cleaning it up.",
                "content": {"operation_groups": [{"operations": [{"action": "remove", "resource": f"//cloudresourcemanager.googleapis.com/projects/{pid}"}]}]},
            }) for i, pid in enumerate(self.world.unattended_project_ids())]
        check = COST_RECOMMENDER_IDS.get(recommender_id)
        location = parent.split("/locations/")[1].split("/")[0]
        profile = self.world.project(project_id)
        recos = profile.cost_recommendations.get((check, location), []) if check else []
        return [recommender_v1.Recommendation({
            "name": f"{parent}/recommendations/{i}", "description": description, "recommender_subtype": subtype,
            "primary_impact": {"category": "COST", "cost_projection": {"cost": {"currency_code": "USD", "units": -usd, "nanos": 0}}},
            "content": {"overview": {"resourceName": resource},
                        "operation_groups": [{"operations": [{"action": "replace", "resource": f"//compute.googleapis.com/projects/{project_id}/zones/{location}/instances/{resource}"}]}]},
        }) for i, (resource, subtype, description, usd) in enumerate(recos)]

    def list_insights(self, parent):
        project_id = _project_of(parent)
        self.call("recommender", "insights.list", project_id=project_id)
        insight_type = parent.rsplit("/insightTypes/", 1)[-1]
        location = parent.split("/locations/")[1].split("/")[0]
        if project_id is None:
            if insight_type != RECENT_CHANGE_INSIGHT:
                return []
            return [recommender_v1.Insight({"name": f"{parent}/insights/1", "description": "Organization IAM policy changed: added roles/owner for group:cloud-admins@example.com"})]
        profile = self.world.project(project_id)
        if insight_type == RECENT_CHANGE_INSIGHT:
            return [recommender_v1.Insight({"name": f"{parent}/insights/{i}", "description": text}) for i, text in enumerate(profile.recent_changes)]
        check = NETWORK_INSIGHT_IDS.get(insight_type)
        insights = []
        for i, (kind, payload) in enumerate(profile.network_insights.get((check, location), []) if check else []):
            if kind == "ip":
                insights.append(recommender_v1.Insight({
                    "name": f"{parent}/insights/{i}", "description": f"Subnet range {payload['prefix']} is {payload['ratio']:.0%} allocated.",
                    "target_resources": [f"//compute.googleapis.com/{payload['subnet']}"],
                    "content": {"ipUtilizationSummaryInfo": [{"networkStats": [{"networkUri": payload["network"], "subnetStats": [
                        {"subnetUri": payload["subnet"], "subnetRangeStats": [{"subnetRangePrefix": payload["prefix"], "allocationRatio": payload["ratio"]}]}]}]}]}}))
            elif kind == "sa":
                insights.append(recommender_v1.Insight({
                    "name": f"{parent}/insights/{i}", "description": "GKE node service account has the Editor role.",
                    "target_resources": [f"//container.googleapis.com/{payload['cluster_uri']}"],
                    "content": {"nodeServiceAccountInsight": {"clusterUri": payload["cluster_uri"], "serviceAccount": "default"}}}))
            else:
                insights.append(recommender_v1.Insight({"name": f"{parent}/insights/{i}", "description": payload["description"]}))
        return insights

    # --- OS Config ---

    def get_inventory(self, request):
        name = request["name"]
        project_id, instance = _project_of(name), name.split("/instances/")[1].split("/")[0]
        self.call("osconfig", "getInventory", project_id=project_id)
        profile = self.world.project(project_id)
        if profile.osconfig_disabled:
            raise core_exceptions.FailedPrecondition("OS inventory management is disabled for this project")
        for vm in profile.vms:
            if vm.name == instance:
                if vm.os_reporting:
                    return SimpleNamespace(name=name)
                break
        raise core_exceptions.NotFound(f"Inventory not found for {name}")

    # --- Storage (per-project) ---

    def list_buckets(self, project_id):
        self.call("storage", "buckets.list", project_id=project_id)
        return [_BucketStub(self, project_id, bucket) for bucket in self.world.project(project_id).buckets]

    def bucket_iam_policy(self, project_id, bucket):
        self.call("storage", "buckets.getIamPolicy", project_id=project_id)
        if bucket.public:
            return SimpleNamespace(bindings=[{"role": "roles/storage.objectViewer", "members": {"allUsers"}}])
        return SimpleNamespace(bindings=[{"role": "roles/storage.admin", "members": {f"projectOwner:{project_id}"}}])


# --- client stand-ins -------------------------------------------------------

class _DiscoveryStub:
    """What ``api_build`` returns: ``service.resource().method(**kw).execute()`` chains."""

    def __init__(self, provider, service, version):
        self._provider, self._service, self._version = provider, service, version

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return _ResourceCall(self._provider, self._service, (name,))


class _ResourceCall:
    """``service.resource`` or ``...method`` before it is called."""

    def __init__(self, provider, service, path):
        self._provider, self._service, self._path = provider, service, path

    def __call__(self, **kwargs):
        if self._path[-1].endswith("_next"):  # list_next / aggregatedList_next: single page, no next request
            return None
        return _Request(self._provider, self._service, self._path, kwargs)


class _Request:
    """A resource (``projects()``) or a prepared method call (``...list(project=...)``)."""

    def __init__(self, provider, service, path, kwargs):
        self._provider, self._service, self._path, self._kwargs = provider, service, path, kwargs

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return _ResourceCall(self._provider, self._service, self._path + (name,))

    def execute(self, num_retries=0, **kwargs):
        return self._provider.dispatch(self._service, self._path, self._kwargs)


class _AssetStub:
    def __init__(self, provider):
        self._p = provider

    def search_all_resources(self, request):
        return self._p.search_all_resources(request)

    def list_assets(self, request):
        return self._p.list_assets(request)


class _RecommenderStub:
    def __init__(self, provider):
        self._p = provider

    def list_recommendations(self, parent):
        return self._p.list_recommendations(parent)

    def list_insights(self, parent):
        return self._p.list_insights(parent)


class _OsConfigStub:
    def __init__(self, provider):
        self._p = provider

    def get_inventory(self, request):
        return self._p.get_inventory(request)


class _StorageStub:
    def __init__(self, provider, project_id):
        self._p, self.project = provider, project_id

    def list_buckets(self):
        return self._p.list_buckets(self.project)


class _BucketStub:
    def __init__(self, provider, project_id, bucket):
        self._p, self._project, self._bucket = provider, project_id, bucket
        self.name = bucket.name
        self.versioning_enabled = bucket.versioning
        self.iam_configuration = SimpleNamespace(uniform_bucket_level_access_enabled=bucket.ubla)

    def get_iam_policy(self, requested_policy_version=None):
        return self._p.bucket_iam_policy(self._project, self._bucket)


class _HttpResponse:
    def __init__(self, status_code, text):
        self.status_code, self.text = status_code, text

    def json(self):
        return json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")
