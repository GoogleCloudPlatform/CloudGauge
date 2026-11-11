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
                                 INCIDENTS, ORG_ADVISORIES, ORG_IAM_RECOMMENDATION, PROJECT_ADVISORY, QUOTA_METRICS, REGIONS,
                                 SyntheticOrg, gke_version)

# Median latency of each API relative to ``latency_ms``.
API_LATENCY_SCALE = {
    "cloudresourcemanager": 0.8, "compute": 1.0, "iam": 1.0, "sqladmin": 1.2, "container": 1.5,
    "recommender": 1.6, "monitoring": 1.2, "logging": 1.0, "securitycenter": 1.0, "essentialcontacts": 1.0,
    "asset": 2.0, "osconfig": 0.8, "storage": 0.8, "http": 1.0, "servicehealth": 1.2, "advisorynotifications": 1.0,
    "accesscontextmanager": 1.0,
}
LATENCY_SIGMA = 0.45  # log-normal spread: p95 is about 2x the median
PASSTHROUGH_SERVICES = ("run",)  # infrastructure APIs the synthetic provider never fakes
PAGE_SIZE = 100
COST_RECOMMENDER_IDS = {rec_id: check for check, (rec_id, _) in COST_RECOMMENDERS.items()}
NETWORK_INSIGHT_IDS = {insight_id: check for check, insight_id in NETWORK_INSIGHT_TYPES.items()}
UNATTENDED_RECOMMENDER = "google.resourcemanager.projectUtilization.Recommender"
RECENT_CHANGE_INSIGHT = "google.cloud.RecentChangeInsight"
# v17
IAM_RECOMMENDER = "google.iam.policy.Recommender"
QUOTA_RECOMMENDER = "google.resourcemanager.serviceLimit.Recommender"
MACHINE_TYPE_URL = "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/machineTypes/{machine_type}"


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

    def policy_table(self):
        """The synthetic organization's small policy table (v18.1: what the bundled table is in a real deployment)."""
        self.call("policy_table", "read", style="http")
        return BEST_PRACTICES_CSV

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
                "projectNumber": profile.project_number, "labels": dict(profile.labels)}

    def _h_cloudresourcemanager_projects_getIamPolicy(self, kw, project_id):
        self.call("cloudresourcemanager", "projects.getIamPolicy", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        policy = {"bindings": self._project_policy_bindings(profile), "etag": "synthetic"}
        if profile.data_access_logs:  # v17.1
            policy["auditConfigs"] = [{"service": "container.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]
        if profile.project_audit_configs:  # v18.1: the project turns the three Data Access log types on for every service
            policy.setdefault("auditConfigs", []).append({"service": "allServices", "auditLogConfigs": [{"logType": t} for t in ("ADMIN_READ", "DATA_READ", "DATA_WRITE")]})
        return policy

    def _project_policy_bindings(self, profile):
        """A project's IAM bindings: a reader group, the primitive bindings and (v17.1) the impersonation table's project-level
        entries, the custom roles, the privileged node account and a Google-managed service agent."""
        bindings = [{"role": "roles/viewer", "members": ["group:readers@example.com"]}]
        by_role = {}
        for role, member in profile.primitive_bindings:
            by_role.setdefault(role, []).append(member)
        bindings += [{"role": role, "members": members} for role, members in by_role.items()]
        return bindings + self._project_level_impersonation(profile)

    def _project_level_impersonation(self, profile):
        """v17.1: the project-level bindings of the impersonation table, the custom roles, the privileged node account."""
        extra = {}
        for level, resource, role, member in profile.impersonation_bindings:
            if level == "project":
                extra.setdefault(role, []).append(member)
        for role, member in profile.custom_role_bindings:
            extra.setdefault(role, []).append(member)
        if any(h.privileged_node_account and not h.autopilot for h in profile.gke_hardening.values()):
            extra.setdefault("roles/editor", []).append(f"serviceAccount:{profile.project_number}-compute@developer.gserviceaccount.com")
        extra.setdefault("roles/compute.serviceAgent", []).append(f"serviceAccount:service-{profile.project_number}@compute-system.iam.gserviceaccount.com")
        return [{"role": role, "members": members} for role, members in extra.items()]

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
        # v18.1: a partial Data Access configuration at the organization (ADMIN_READ and DATA_WRITE for all services).
        return {"bindings": self.world.org_iam_bindings(),
                "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}, {"logType": "DATA_WRITE"}]}]}

    def _list_org_policies(self, kw, project_id):
        self.call("cloudresourcemanager", "listOrgPolicies", project_id=project_id, style="http")
        return {"policies": self.world.org_policies(kw["resource"])}

    _h_cloudresourcemanager_organizations_listOrgPolicies = _list_org_policies
    _h_cloudresourcemanager_folders_listOrgPolicies = _list_org_policies
    _h_cloudresourcemanager_projects_listOrgPolicies = _list_org_policies

    def _h_cloudresourcemanager_folders_get(self, kw, project_id):
        self.call("cloudresourcemanager", "folders.get", style="http")
        return {"name": kw["name"], "parent": f"organizations/{self.world.org_id}", "displayName": "Synthetic folder"}

    def _h_cloudresourcemanager_projects_list(self, kw, project_id):
        """v3 ``projects.list``: a folder's direct children (the world has one level of folders). The folder
        scan's membership check compares them with Asset Search, and finds them the same."""
        self.call("cloudresourcemanager", "projects.list", style="http")
        parent = str(kw.get("parent", ""))
        if not parent.startswith("folders/"):
            return {}
        return {"projects": [{"name": f"projects/{p.project_number}", "parent": parent, "projectId": p.project_id,
                              "displayName": p.display_name, "state": "ACTIVE"}
                             for p in self.world.projects(parent.split("/", 1)[1])]}

    def _h_compute_instances_aggregatedList(self, kw, project_id):
        self.call("compute", "instances.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        running_only = 'RUNNING' in str(kw.get("filter", ""))
        for index, vm in enumerate(profile.vms):
            stopped = vm.name in profile.stopped_vms  # v18: a stopped VM keeps its access config, not its ephemeral address
            if stopped and running_only:
                continue
            access = [{"name": "External NAT", "type": "ONE_TO_ONE_NAT", **({} if stopped else {"natIP": "203.0.113.10"})}] if vm.external_ip else None
            instance = {
                "name": vm.name, "id": str(self._instance_id(profile, index)), "status": "TERMINATED" if stopped else "RUNNING",
                "zone": f"https://www.googleapis.com/compute/v1/projects/{project_id}/zones/{vm.zone}",
                "machineType": MACHINE_TYPE_URL.format(project=project_id, zone=vm.zone, machine_type=vm.machine_type),
                "networkInterfaces": [{"name": "nic0", "network": "vpc-main", **({"accessConfigs": access} if access else {})}],
                "labels": {}, "metadata": {"items": ([{"key": "created-by", "value": f"projects/{project_id}/zones/{vm.zone}/instanceGroupManagers/mig-{vm.zone}"}] if vm.in_mig else [])},
            }
            items.setdefault(f"zones/{vm.zone}", {"instances": []})["instances"].append(instance)
        return {"items": items}

    @staticmethod
    def _instance_id(profile, index):
        """A VM's numeric ID, as Compute Engine and the OS inventory name it."""
        return 7000000000000000000 + int(profile.project_number) * 1000 + index

    # --- v17: reservations, commitments and the capacity log ---

    def _h_compute_reservations_aggregatedList(self, kw, project_id):
        self.call("compute", "reservations.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        for i, (zone, machine_type, count, in_use) in enumerate(profile.reservations):
            items.setdefault(f"zones/{zone}", {"reservations": []})["reservations"].append({
                "name": f"reservation-{i}", "zone": f"https://www.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}", "status": "READY",
                "specificReservation": {"count": str(count), "inUseCount": str(in_use),
                                        "instanceProperties": {"machineType": machine_type}}})
        return {"items": items}

    def _h_compute_futureReservations_aggregatedList(self, kw, project_id):
        self.call("compute", "futureReservations.aggregatedList", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        if not profile.future_reservation:
            return {"items": {}}
        zone = profile.zones[0]
        return {"items": {f"zones/{zone}": {"futureReservations": [{
            "name": "future-0", "zone": zone, "status": {"procurementStatus": "APPROVED"},
            "timeWindow": {"startTime": _iso(-30), "endTime": _iso(-395)},
            "specificSkuProperties": {"totalCount": "8", "instanceProperties": {"machineType": "a2-highgpu-1g",
                                                                                 "guestAccelerators": [{"acceleratorType": "nvidia-tesla-a100", "acceleratorCount": 1}]}}}]}}}

    def _h_compute_regionCommitments_aggregatedList(self, kw, project_id):
        self.call("compute", "regionCommitments.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        for i, (region, plan, vcpus, memory_gb, days_left, auto_renew) in enumerate(profile.commitments):
            items.setdefault(f"regions/{region}", {"commitments": []})["commitments"].append({
                "name": f"commitment-{i}", "region": region, "plan": plan, "status": "ACTIVE", "autoRenew": auto_renew,
                "startTimestamp": _iso(365 - days_left), "endTimestamp": _iso(-days_left),
                "resources": [{"type": "VCPU", "amount": str(vcpus)}, {"type": "MEMORY", "amount": str(memory_gb * 1024)}]})
        return {"items": items}

    def _h_logging_entries_list(self, kw, project_id):
        """``entries.list`` over one project: the Compute Engine operations that failed for capacity or quota (v17)."""
        body = kw.get("body") or {}
        names = [name for name in body.get("resourceNames", []) if str(name).startswith("projects/")]
        project_id = names[0].split("/", 1)[1] if names else None
        self.call("logging", "entries.list", project_id=project_id, style="http")
        profile = self.world.project(project_id) if project_id else None
        entries = []
        for zone, machine_type, kind, days_ago, count in (profile.capacity_events if profile else ()):
            message = (f"ZONE_RESOURCE_POOL_EXHAUSTED: The zone '{zone}' does not have enough resources available to fulfill the request."
                       if kind == "stockout" else f"QUOTA_EXCEEDED: Quota 'CPUS' exceeded in region {'-'.join(zone.split('-')[:-1])}.")
            for n in range(count):
                entries.append({
                    "timestamp": _iso(days_ago + n / 24), "logName": f"projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity",
                    "resource": {"type": "gce_instance", "labels": {"project_id": project_id, "zone": zone}},
                    "protoPayload": {"methodName": "v1.compute.instances.insert", "status": {"code": 8, "message": message},
                                     "resourceName": f"projects/{project_id}/zones/{zone}/instances/vm-new-{n}",
                                     "request": {"machineType": MACHINE_TYPE_URL.format(project=project_id, zone=zone, machine_type=machine_type)}}})
        return {"entries": entries}

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
        rules = [{"name": name, "network": f"projects/{project_id}/global/networks/vpc-main", "direction": "INGRESS", "priority": 1000,
                  "sourceRanges": ["0.0.0.0/0"] if open_rule else ["10.0.0.0/8"], "disabled": disabled,
                  "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}] if open_rule else [{"IPProtocol": "tcp", "ports": ["8080"]}]}
                 for name, open_rule, disabled in profile.firewall_rules]
        # v18: the hardening pattern every network should have — a deny-all from the internet — is never a finding.
        rules.append({"name": "deny-all-ingress", "network": f"projects/{project_id}/global/networks/vpc-main", "direction": "INGRESS", "priority": 65000,
                      "sourceRanges": ["0.0.0.0/0"], "disabled": False, "denied": [{"IPProtocol": "all"}]})
        return {"items": rules}

    def _h_compute_networks_list(self, kw, project_id):
        self.call("compute", "networks.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": "vpc-main", "selfLink": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/vpc-main"}]
                + ([{"name": "default", "selfLink": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/default", "autoCreateSubnetworks": True}] if profile.has_default_vpc else [])}

    def _h_compute_regions_list(self, kw, project_id):
        self.call("compute", "regions.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": region, "quotas": self._region_quotas(profile, region)} for region in REGIONS]}

    @staticmethod
    def _region_quotas(profile, region):
        hot = {metric: (usage, limit) for r, metric, usage, limit in profile.hot_quotas if r == region}
        quotas = [{"metric": m, "usage": float(hot.get(m, (3, 100))[0]), "limit": float(hot.get(m, (3, 100))[1])} for m in QUOTA_METRICS]
        quotas += [{"metric": metric, "usage": float(usage), "limit": float(limit)} for r, metric, usage, limit in profile.gpu_quota if r == region]
        quotas.append({"metric": "COMMITTED_CPUS", "usage": 64.0, "limit": 64.0})  # v18: consumed by the commitments, never a row
        return quotas

    def _h_compute_regions_get(self, kw, project_id):
        self.call("compute", "regions.get", project_id=project_id, style="http")
        profile, region = self.world.project(project_id), kw["region"]
        return {"name": region, "quotas": self._region_quotas(profile, region)}

    def _h_compute_subnetworks_list(self, kw, project_id):
        self.call("compute", "subnetworks.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": name, "region": region, "privateIpGoogleAccess": pga}
                          for name, region, pga in profile.subnets if region == kw["region"]]}

    def _h_compute_subnetworks_aggregatedList(self, kw, project_id):
        """Every subnet of the project in one call (v18.1), with ``purpose`` and ``network``; a proxy-only subnet for some projects."""
        self.call("compute", "subnetworks.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        for name, region, pga in profile.subnets:
            items.setdefault(f"regions/{region}", {"subnetworks": []})["subnetworks"].append(
                {"name": name, "region": f"https://www.googleapis.com/compute/v1/projects/{project_id}/regions/{region}", "privateIpGoogleAccess": pga,
                 "purpose": "PRIVATE", "network": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/vpc-main"})
        if profile.proxy_subnet and profile.subnets:
            region = profile.subnets[0][1]
            items.setdefault(f"regions/{region}", {"subnetworks": []})["subnetworks"].append(
                {"name": "proxy-only", "region": f"https://www.googleapis.com/compute/v1/projects/{project_id}/regions/{region}", "privateIpGoogleAccess": False,
                 "purpose": "REGIONAL_MANAGED_PROXY", "role": "ACTIVE", "network": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/vpc-main"})
        if profile.has_default_vpc and profile.subnets:
            region = profile.subnets[0][1]
            items.setdefault(f"regions/{region}", {"subnetworks": []})["subnetworks"].append(
                {"name": "default", "region": f"https://www.googleapis.com/compute/v1/projects/{project_id}/regions/{region}", "privateIpGoogleAccess": False,
                 "purpose": "PRIVATE", "network": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/default"})
        return {"items": items}

    def _h_compute_projects_get(self, kw, project_id):
        """The project's global Compute quotas (v18.1): FIREWALLS near its limit for the projects with many rules."""
        self.call("compute", "projects.get", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        rules = len(profile.firewall_rules) + 1
        return {"name": project_id, "quotas": [{"metric": "FIREWALLS", "usage": float(rules), "limit": 200.0},
                                               {"metric": "NETWORKS", "usage": 2.0, "limit": 15.0}, {"metric": "IMAGES", "usage": 3.0, "limit": 2000.0}]}

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
                oldest = max(sa.key_ages_days) if sa.key_ages_days else None
                return {"keys": [{"name": f"{kw['name']}/keys/{i}", "validAfterTime": _iso(age), "validBeforeTime": "9999-12-31T23:59:59Z",
                                  "keyType": "USER_MANAGED", "keyOrigin": "GOOGLE_PROVIDED",
                                  **({"disabled": True} if (age == oldest and email in profile.disabled_key_accounts) else {})}
                                 for i, age in enumerate(sa.key_ages_days)]}
        return {"keys": []}

    def _h_sqladmin_instances_list(self, kw, project_id):
        self.call("sqladmin", "instances.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        return {"items": [{"name": sql.name, "databaseVersion": sql.database_version, "instanceType": "CLOUD_SQL_INSTANCE",
                           "settings": {"ipConfiguration": {
                               "ipv4Enabled": sql.public_ip, "requireSsl": False,
                               "sslMode": "ENCRYPTED_ONLY" if sql.require_ssl else "ALLOW_UNENCRYPTED_AND_ENCRYPTED",  # v18: the field that decides
                               "authorizedNetworks": [{"value": "0.0.0.0/0", "name": "everywhere"}] if sql.name in profile.sql_open_networks else []}}}
                          for sql in profile.sql_instances]}

    def _h_container_projects_locations_clusters_list(self, kw, project_id):
        self.call("container", "clusters.list", project_id=project_id, style="http")
        profile, clusters = self.world.project(project_id), []
        for cluster in profile.gke_clusters:
            # v18.2: the GKE API and the inventory show the same cluster (the API adds auto-repair and the node version).
            entry = dict(self._cluster_asset(profile, cluster).resource.data)
            entry["currentNodeVersion"] = cluster.node_pools[0][2]
            repairs = profile.gke_auto_repair.get(cluster.name, (True,) * len(cluster.node_pools))
            entry["nodePools"] = [{**pool, "management": {**pool.get("management", {}), "autoRepair": repair}} for pool, repair in zip(entry["nodePools"], repairs)]
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
        recos = [{"name": f"{parent}/recommendations/{i}", "description": text, "stateInfo": {"state": "ACTIVE"},
                  "targetResources": [f"//container.googleapis.com/projects/{project_id}/locations/{location}/clusters/{cluster.name}"]}
                 for cluster in profile.gke_clusters if cluster.location == location
                 for i, text in enumerate(cluster.recommendations)]
        return {"recommendations": recos}

    def _h_monitoring_projects_alertPolicies_list(self, kw, project_id):
        self.call("monitoring", "alertPolicies.list", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        # v18: filters as Cloud Monitoring writes them (the legacy world's filters contained the check's own needles).
        filters = {"serviceruntime.googleapis.com/quota": 'metric.type="serviceruntime.googleapis.com/quota/allocation/usage" AND resource.type="consumer_quota"',
                   "cloud_sql": 'metric.type="cloudsql.googleapis.com/database/cpu/utilization" AND resource.type="cloudsql_database"',
                   "gke_cluster": 'metric.type="kubernetes.io/container/restart_count" AND resource.type="k8s_container"'}
        return {"alertPolicies": [{"displayName": f"alert-{i}", "enabled": True,
                                   "conditions": [{"conditionThreshold": {"filter": filters.get(f, f'metric.type="{f}"')}}]}
                                  for i, f in enumerate(profile.alert_filters)]}

    def _h_logging_organizations_sinks_list(self, kw, project_id):
        self.call("logging", "sinks.list", style="http")
        return {"sinks": [{"name": "org-audit-sink", "destination": f"bigquery.googleapis.com/projects/{HOST_PROJECT}/datasets/audit_logs"}]}

    def _h_securitycenter_projects_locations_clusters_containerThreatDetectionSettings_calculate(self, kw, project_id):
        self.call("securitycenter", "containerThreatDetectionSettings.calculate", project_id=project_id, style="http")
        profile, cluster_name = self.world.project(project_id), kw["name"].split("/clusters/", 1)[1].split("/", 1)[0]
        hardening = profile.gke_hardening.get(cluster_name)
        return {"name": kw["name"], "serviceEnablementState": "ENABLED" if (hardening is None or hardening.ctd_enabled) else "DISABLED"}

    def _h_securitycenter_projects_eventThreatDetectionSettings_calculate(self, kw, project_id):
        self.call("securitycenter", "eventThreatDetectionSettings.calculate", project_id=project_id, style="http")
        return {"name": kw["name"], "serviceEnablementState": "ENABLED" if self.world.project(project_id).etd_enabled else "DISABLED"}

    def _h_iam_projects_roles_get(self, kw, project_id):
        self.call("iam", "roles.get", project_id=project_id, style="http")
        return {"name": kw["name"], "includedPermissions": ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.get"]}

    def _h_accesscontextmanager_accessPolicies_list(self, kw, project_id):
        self.call("accesscontextmanager", "accessPolicies.list", style="http")
        return {"accessPolicies": [{"name": "accessPolicies/100", "parent": kw.get("parent", ""), "title": "synthetic policy"}]}

    def _h_accesscontextmanager_accessPolicies_servicePerimeters_list(self, kw, project_id):
        self.call("accesscontextmanager", "servicePerimeters.list", style="http")
        perimeters = []
        for p in self.world.perimeters():
            config = {"resources": list(p["resources"]), "restrictedServices": list(p["restricted"])}
            entry = {"name": f"{kw.get('parent', 'accessPolicies/100')}/servicePerimeters/{p['name']}", "title": p["title"],
                     "perimeterType": "PERIMETER_TYPE_REGULAR" if p["regular"] else "PERIMETER_TYPE_BRIDGE"}
            if p["dry_run"]:
                entry.update(spec=config, useExplicitDryRunSpec=True)
            else:
                entry["status"] = config
            perimeters.append(entry)
        return {"servicePerimeters": perimeters}

    def _h_securitycenter_organizations_getOrganizationSettings(self, kw, project_id):
        self.call("securitycenter", "getOrganizationSettings", style="http")
        return {"name": kw["name"], "enableAssetDiscovery": False, "assetDiscoveryConfig": {}}  # no tier here (v18)

    def _h_securitycenter_organizations_getSubscription(self, kw, project_id):
        """``v1beta2 organizations.getSubscription``: the organization's tier (v18)."""
        self.call("securitycenter", "getSubscription", style="http")
        return {"name": kw["name"], "tier": "STANDARD", "details": {"type": "STANDARD"}}

    def _h_cloudresourcemanager_organizations_get(self, kw, project_id):
        self.call("cloudresourcemanager", "organizations.get", style="http")
        return {"name": kw["name"], "displayName": "example.com", "lifecycleState": "ACTIVE"}

    def _h_cloudresourcemanager_projects_getEffectiveOrgPolicy(self, kw, project_id):
        """The effective policy of one constraint on a project (v18: storage.publicAccessPrevention, read for public buckets)."""
        self.call("cloudresourcemanager", "projects.getEffectiveOrgPolicy", project_id=project_id, style="http")
        return {"constraint": (kw.get("body") or {}).get("constraint", ""), "booleanPolicy": {"enforced": False}}

    ORG_CONTACTS = [{"email": "security@example.com", "notificationCategorySubscriptions": ["SECURITY"], "validationState": "VALID"},
                    {"email": "ops@example.com", "notificationCategorySubscriptions": ["TECHNICAL"], "validationState": "VALID"},
                    {"email": "legal-old@example.com", "notificationCategorySubscriptions": ["LEGAL"], "validationState": "INVALID"}]  # v18.1: bounced

    def _h_essentialcontacts_organizations_contacts_list(self, kw, project_id):
        self.call("essentialcontacts", "contacts.list", style="http")
        return {"contacts": list(self.ORG_CONTACTS)}

    def _h_essentialcontacts_projects_contacts_compute(self, kw, project_id):
        """The effective contacts of a project (v18.1): the organization's, plus the project's own when it has one."""
        self.call("essentialcontacts", "contacts.compute(project)", project_id=project_id, style="http")
        profile = self.world.project(project_id)
        own = [{"email": f"owner@{profile.project_id}.example.com", "notificationCategorySubscriptions": ["SUSPENSION", "LEGAL"], "validationState": "VALID"}] if profile.project_contact else []
        return {"contacts": list(self.ORG_CONTACTS) + own}

    def _h_essentialcontacts_folders_contacts_compute(self, kw, project_id):
        self.call("essentialcontacts", "contacts.compute(folder)", style="http")
        return {"contacts": list(self.ORG_CONTACTS)}

    def _h_cloudresourcemanager_folders_getIamPolicy(self, kw, project_id):
        """A folder's IAM policy (v3; v18.1): no bindings of note, no audit configuration."""
        self.call("cloudresourcemanager", "folders.getIamPolicy", style="http")
        return {"bindings": [], "etag": "synthetic"}

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
        # The picker's ``query`` ("state:ACTIVE", v15.6) is accepted: nothing synthetic is pending deletion.
        scope, asset_types = request["scope"], request.get("asset_types", [])
        folder_id = scope.split("/")[1] if scope.startswith("folders/") else None
        results = []
        if "cloudresourcemanager.googleapis.com/Folder" in asset_types and folder_id is None:
            results += [SimpleNamespace(name=f"//cloudresourcemanager.googleapis.com/folders/{fid}", display_name=f"Synthetic folder {i}",
                                        asset_type="cloudresourcemanager.googleapis.com/Folder", project="",
                                        parent_full_resource_name=f"//cloudresourcemanager.googleapis.com/organizations/{self.world.org_id}")
                        for i, fid in enumerate(self.world.folder_ids)]
        if "cloudresourcemanager.googleapis.com/Project" in asset_types:
            results += [SimpleNamespace(name=f"//cloudresourcemanager.googleapis.com/projects/{p.project_id}", display_name=p.display_name,
                                        asset_type="cloudresourcemanager.googleapis.com/Project", project=f"projects/{p.project_number}",
                                        parent_full_resource_name=f"//cloudresourcemanager.googleapis.com/folders/{p.folder_id}",
                                        folders=[f"folders/{p.folder_id}"], organization=f"organizations/{self.world.org_id}")
                        for p in ([self.world.project(scope.split("/", 1)[1])] if scope.startswith("projects/") else self.world.projects(folder_id))]
        if "iam.googleapis.com/ServiceAccount" in asset_types:  # v17.1: the accounts in scope, the default compute account included
            project_id = scope.split("/", 1)[1] if scope.startswith("projects/") else None
            for p in ([self.world.project(project_id)] if project_id else self.world.projects(folder_id)):
                emails = [sa.email for sa in p.service_accounts] + [f"{p.project_number}-compute@developer.gserviceaccount.com"]
                results += [SimpleNamespace(name=f"//iam.googleapis.com/projects/{p.project_id}/serviceAccounts/{e}", display_name=e.split("@")[0],
                                            asset_type="iam.googleapis.com/ServiceAccount", project=f"projects/{p.project_number}",
                                            folders=[f"folders/{p.folder_id}"], organization=f"organizations/{self.world.org_id}",
                                            parent_full_resource_name=f"//cloudresourcemanager.googleapis.com/projects/{p.project_id}") for e in emails]
        self.call("asset", "searchAllResources", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
        return results

    def list_assets(self, request):
        """The assets of the requested types under ``projects/``, ``folders/`` (its projects) or the organization (every project)."""
        parent, asset_types = request["parent"], set(request.get("asset_types", []))
        if parent.startswith("projects/"):
            project_id = parent.split("/", 1)[1]
            self.call("asset", "listAssets(project)", project_id=project_id)
            profile = self.world.project(project_id)
            found = self._resilience_assets(profile, asset_types)
            if "container.googleapis.com/Cluster" in asset_types:
                found += [self._cluster_asset(profile, c) for c in profile.gke_clusters]
            if "logging.googleapis.com/LogSink" in asset_types:
                found += self._sink_assets(profile)
            if "policy.k8s.io/PodDisruptionBudget" in asset_types:
                found += [a for c in profile.gke_clusters for a in self._pdb_assets(profile, c)]
            found += self._edge_assets(profile, asset_types)
            found += self._governance_assets(profile, asset_types)
            return found
        # Folder- or organization-wide listing: one pass over the projects in scope.
        folder_id = parent.split("/", 1)[1] if parent.startswith("folders/") else None
        found = []
        for profile in self.world.projects(folder_id):
            found += self._resilience_assets(profile, asset_types)
            if "container.googleapis.com/Cluster" in asset_types:
                found += [self._cluster_asset(profile, c) for c in profile.gke_clusters]
            if "logging.googleapis.com/LogSink" in asset_types:
                found += self._sink_assets(profile)
            if "policy.k8s.io/PodDisruptionBudget" in asset_types:
                found += [a for c in profile.gke_clusters for a in self._pdb_assets(profile, c)]
            found += self._edge_assets(profile, asset_types)
            found += self._governance_assets(profile, asset_types)
        self.call("asset", "listAssets(folder)" if folder_id else "listAssets(org)", pages=max(1, math.ceil(len(found) / PAGE_SIZE)))
        return found

    @staticmethod
    def _sink_assets(profile):
        """The project's log sinks (v18.1): one per bucket the world marks as a sink destination."""
        return [SimpleNamespace(name=f"//logging.googleapis.com/projects/{profile.project_id}/sinks/sink-{i}",
                                resource=SimpleNamespace(data={"name": f"sink-{i}", "destination": f"storage.googleapis.com/{bucket}"}))
                for i, bucket in enumerate(profile.sink_buckets)]

    def _edge_assets(self, profile, asset_types):
        """The project's network-edge assets (v18.3) for the asset types asked: its ``vpc-main`` network and subnets, a legacy network,
        a Cloud Router with a NAT, HA or Classic VPN, Interconnect attachments, an external load balancer, DNS zones and policies, a
        firewall policy — as Asset Inventory shows them (``NetworkEdge``). ``ForwardingRule`` assets double as the Incident Exposure
        footprint of earlier releases (``forwarding_rule_regions``)."""
        edge, project_id, number = profile.network_edge, profile.project_id, profile.project_number
        if edge is None:
            return []
        compute = f"https://www.googleapis.com/compute/v1/projects/{project_id}"
        region = profile.subnets[0][1] if profile.subnets else "us-central1"
        found = []

        def asset(service, path, data):
            found.append(SimpleNamespace(name=f"//{service}.googleapis.com/projects/{project_id}/{path}",
                                         resource=SimpleNamespace(data=data, parent=f"//cloudresourcemanager.googleapis.com/projects/{number}")))

        if "compute.googleapis.com/Network" in asset_types:
            peerings = []
            if edge.peer_index >= 0:
                peer_id = self.world.project_id(edge.peer_index)
                peerings.append({"name": f"to-{peer_id}", "network": f"https://www.googleapis.com/compute/v1/projects/{peer_id}/global/networks/vpc-main",
                                 "state": "ACTIVE" if edge.peering_active else "INACTIVE"})
            peerings.append({"name": "servicenetworking-googleapis-com", "network": "https://www.googleapis.com/compute/v1/projects/p-google/global/networks/sn", "state": "ACTIVE"})
            asset("compute", "global/networks/vpc-main", {"name": "vpc-main", "selfLink": f"{compute}/global/networks/vpc-main", "mtu": edge.mtu, "peerings": peerings})
            if edge.legacy_network:
                asset("compute", "global/networks/legacy-net", {"name": "legacy-net", "selfLink": f"{compute}/global/networks/legacy-net", "IPv4Range": "10.240.0.0/16"})
        if "compute.googleapis.com/Subnetwork" in asset_types:
            for (name, subnet_region, pga), logs in zip(profile.subnets, edge.flow_logs):
                asset("compute", f"regions/{subnet_region}/subnetworks/{name}",
                      {"name": name, "region": f"{compute}/regions/{subnet_region}", "network": f"{compute}/global/networks/vpc-main", "purpose": "PRIVATE",
                       "privateIpGoogleAccess": pga, "enableFlowLogs": logs, "logConfig": {"enable": logs}})
            if profile.proxy_subnet and profile.subnets:
                asset("compute", f"regions/{region}/subnetworks/proxy-only", {"name": "proxy-only", "region": f"{compute}/regions/{region}", "purpose": "REGIONAL_MANAGED_PROXY",
                                                                             "network": f"{compute}/global/networks/vpc-main", "enableFlowLogs": False})
        if "compute.googleapis.com/Router" in asset_types and (edge.nat != "none" or edge.vpn.startswith("ha") or edge.interconnect != "none"):
            nats = [] if edge.nat == "none" else [{"name": "nat-main", "natIpAllocateOption": "AUTO_ONLY", "logConfig": {"enable": edge.nat == "tuned", "filter": "ERRORS_ONLY"},
                                                   **({"enableDynamicPortAllocation": True, "minPortsPerVm": 64, "maxPortsPerVm": 4096} if edge.nat == "tuned" else {})}]
            if edge.nat != "none":
                nats.append({"name": "swg-autogen-nat", "natIpAllocateOption": "AUTO_ONLY", "logConfig": {"enable": True, "filter": "ERRORS_ONLY"}})
            peers = [{"name": "peer-0", "enable": "TRUE"}] + ([{"name": "peer-1", "enable": "TRUE"}] if edge.vpn == "ha-two" or edge.interconnect == "redundant" else [])
            asset("compute", f"regions/{region}/routers/router-main", {"name": "router-main", "region": f"{compute}/regions/{region}", "network": f"{compute}/global/networks/vpc-main",
                                                                        "selfLink": f"{compute}/regions/{region}/routers/router-main", "bgp": {"asn": 65001}, "bgpPeers": peers, "nats": nats})
        router = f"{compute}/regions/{region}/routers/router-main"
        if "compute.googleapis.com/VpnGateway" in asset_types and edge.vpn.startswith("ha"):
            asset("compute", f"regions/{region}/vpnGateways/vpn-gw", {"name": "vpn-gw", "region": f"{compute}/regions/{region}", "network": f"{compute}/global/networks/vpc-main",
                                                                       "selfLink": f"{compute}/regions/{region}/vpnGateways/vpn-gw", "vpnInterfaces": [{"id": 0}, {"id": 1}]})
        if "compute.googleapis.com/VpnTunnel" in asset_types and edge.vpn.startswith("ha"):
            for interface in ([0] if edge.vpn == "ha-one" else [0, 1]):
                asset("compute", f"regions/{region}/vpnTunnels/tunnel-{interface}",
                      {"name": f"tunnel-{interface}", "region": f"{compute}/regions/{region}", "vpnGateway": f"{compute}/regions/{region}/vpnGateways/vpn-gw",
                       "vpnGatewayInterface": interface, "router": router, **self._tunnel_state(edge, interface)})
        if "compute.googleapis.com/TargetVpnGateway" in asset_types and edge.vpn == "classic":
            asset("compute", f"regions/{region}/targetVpnGateways/classic-gw", {"name": "classic-gw", "region": f"{compute}/regions/{region}", "network": f"{compute}/global/networks/vpc-main"})
        if "compute.googleapis.com/InterconnectAttachment" in asset_types and edge.interconnect != "none":
            for n, domain in enumerate(["AVAILABILITY_DOMAIN_1"] + (["AVAILABILITY_DOMAIN_2"] if edge.interconnect == "redundant" else [])):
                asset("compute", f"regions/{region}/interconnectAttachments/attach-{n}", {"name": f"attach-{n}", "region": f"{compute}/regions/{region}", "router": router,
                                                                                         "edgeAvailabilityDomain": domain, "operationalStatus": "OS_ACTIVE", "type": "DEDICATED"})
        if "compute.googleapis.com/ForwardingRule" in asset_types:
            for r in profile.forwarding_rule_regions:  # the Incident Exposure footprint: internal passthrough rules, no edge rows
                asset("compute", f"regions/{r}/forwardingRules/lb-{r}", {"name": f"lb-{r}", "loadBalancingScheme": "INTERNAL", "region": f"{compute}/regions/{r}"})
        if edge.lb != "none" and "compute.googleapis.com/GlobalForwardingRule" in asset_types:
            proxy_kind = "targetHttpProxies" if edge.lb == "http" else "targetHttpsProxies"
            asset("compute", "global/forwardingRules/edge-fr", {"name": "edge-fr", "loadBalancingScheme": "EXTERNAL", "portRange": "80-80" if edge.lb == "http" else "443-443",
                                                               "IPProtocol": "TCP", "target": f"{compute}/global/{proxy_kind}/edge-proxy"})
        if edge.lb == "http" and "compute.googleapis.com/TargetHttpProxy" in asset_types:
            asset("compute", "global/targetHttpProxies/edge-proxy", {"name": "edge-proxy", "selfLink": f"{compute}/global/targetHttpProxies/edge-proxy", "urlMap": f"{compute}/global/urlMaps/edge-map"})
        if edge.lb.startswith("https") and "compute.googleapis.com/TargetHttpsProxy" in asset_types:
            asset("compute", "global/targetHttpsProxies/edge-proxy", {"name": "edge-proxy", "selfLink": f"{compute}/global/targetHttpsProxies/edge-proxy", "urlMap": f"{compute}/global/urlMaps/edge-map",
                                                                     **({"sslPolicy": f"{compute}/global/sslPolicies/modern-tls"} if edge.lb == "https-modern" else {})})
        if edge.lb == "https-modern" and "compute.googleapis.com/SslPolicy" in asset_types:
            asset("compute", "global/sslPolicies/modern-tls", {"name": "modern-tls", "selfLink": f"{compute}/global/sslPolicies/modern-tls", "profile": "MODERN", "minTlsVersion": "TLS_1_2"})
        if edge.lb != "none" and "compute.googleapis.com/BackendService" in asset_types:
            armored = edge.lb == "https-modern"
            asset("compute", "global/backendServices/edge-bes", {"name": "edge-bes", "loadBalancingScheme": "EXTERNAL", "protocol": "HTTP", "logConfig": {"enable": armored},
                                                                **({"securityPolicy": f"{compute}/global/securityPolicies/edge"} if armored else {})})
        if edge.dns_zone != "none" and "dns.googleapis.com/ManagedZone" in asset_types:
            config = {"none": {}, "plain": {"state": "off"}, "signed": {"state": "on", "defaultKeySpecs": [{"algorithm": "ecdsap256sha256", "keyType": "keySigning"}]},
                      "rsasha1": {"state": "on", "defaultKeySpecs": [{"algorithm": "rsasha1", "keyType": "keySigning"}, {"algorithm": "rsasha1", "keyType": "zoneSigning"}]}}[edge.dns_zone]
            asset("dns", "managedZones/public-zone", {"name": "public-zone", "dnsName": f"{project_id}.example.", "visibility": "public", "dnssecConfig": config})
        if edge.dns_logging and "dns.googleapis.com/Policy" in asset_types:
            asset("dns", "policies/dns-logging", {"name": "dns-logging", "enableLogging": True, "networks": [{"networkUrl": f"{compute}/global/networks/vpc-main"}]})
        if edge.firewall_policy and "compute.googleapis.com/FirewallPolicy" in asset_types:
            asset("compute", "global/firewallPolicies/900001", {"name": "900001", "displayName": "edge-policy", "shortName": "edge-policy",
                                                              "associations": [{"name": "vpc-main", "attachmentTarget": f"projects/{project_id}/global/networks/vpc-main"}],
                                                              "rules": [{"priority": 100, "direction": "INGRESS", "action": "allow", "disabled": False,
                                                                         "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]}},
                                                                        {"priority": 2147483647, "direction": "INGRESS", "action": "goto_next", "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "all"}]}}]})
        return found

    @staticmethod
    def _tunnel_state(edge, interface):
        """The state of a synthetic tunnel: established on an ``ha-two`` gateway, waiting on an ``ha-one`` one."""
        if edge.vpn == "ha-two":
            return {"status": "ESTABLISHED", "detailedStatus": "Tunnel is up and running."}
        return {"status": "NO_INCOMING_PACKETS", "detailedStatus": "No incoming packets from peer"}

    def _h_compute_vpnTunnels_aggregatedList(self, kw, project_id):
        """The tunnels' current state (v18.3: *Hybrid Connectivity* re-reads it from the API; the synthetic world agrees with its inventory)."""
        self.call("compute", "vpnTunnels.aggregatedList", project_id=project_id, style="http")
        profile, items = self.world.project(project_id), {}
        edge = profile.network_edge
        if edge and edge.vpn.startswith("ha"):
            region = profile.subnets[0][1] if profile.subnets else "us-central1"
            items[f"regions/{region}"] = {"vpnTunnels": [{"name": f"tunnel-{i}", **self._tunnel_state(edge, i)} for i in ([0] if edge.vpn == "ha-one" else [0, 1])]}
        return {"items": items}

    def _governance_assets(self, profile, asset_types):
        """The project's data-governance assets (v18.4): BigQuery datasets, an AlloyDB cluster and instance, KMS keys, API keys."""
        g, project_id, number = profile.data_governance, profile.project_id, profile.project_number
        if g is None:
            return []
        region = profile.subnets[0][1] if profile.subnets else "us-central1"
        found = []

        def asset(service, path, data):
            found.append(SimpleNamespace(name=f"//{service}.googleapis.com/projects/{project_id}/{path}",
                                         resource=SimpleNamespace(data=data, parent=f"//cloudresourcemanager.googleapis.com/projects/{number}")))

        if "bigquery.googleapis.com/Dataset" in asset_types:
            for dataset_id, hours, public in g.datasets:
                access = [{"role": "OWNER", "specialGroup": "projectOwners"}, {"role": "READER", "specialGroup": "projectReaders"}]
                if public:
                    access.append({"role": "READER", "specialGroup": "allAuthenticatedUsers"})
                asset("bigquery", f"datasets/{dataset_id}", {"datasetReference": {"datasetId": dataset_id, "projectId": project_id}, "access": access,
                                                             **({"maxTimeTravelHours": str(hours)} if hours != 168 else {}), "location": "US"})
        if g.alloydb != "none":
            good = g.alloydb == "regional-good"
            if "alloydb.googleapis.com/Cluster" in asset_types:
                asset("alloydb", f"locations/{region}/clusters/alloy-main", {"name": f"projects/{project_id}/locations/{region}/clusters/alloy-main",
                                                                           "automatedBackupPolicy": {"enabled": good}, "continuousBackupConfig": {"enabled": good}})
            if "alloydb.googleapis.com/Instance" in asset_types:
                asset("alloydb", f"locations/{region}/clusters/alloy-main/instances/alloy-primary",
                      {"name": f"projects/{project_id}/locations/{region}/clusters/alloy-main/instances/alloy-primary", "instanceType": "PRIMARY",
                       "availabilityType": "REGIONAL" if good else "ZONAL", "networkConfig": {"enablePublicIp": not good},
                       "clientConnectionConfig": {"sslConfig": {"sslMode": "ENCRYPTED_ONLY" if good else "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}},
                       "databaseFlags": {"log_connections": "on", "log_disconnections": "on"} if good else {}})
        if g.kms != "none" and "cloudkms.googleapis.com/CryptoKey" in asset_types:
            asset("cloudkms", f"locations/{region}/keyRings/ring-main/cryptoKeys/data-key",
                  {"name": f"projects/{project_id}/locations/{region}/keyRings/ring-main/cryptoKeys/data-key", "purpose": "ENCRYPT_DECRYPT", "primary": {"state": "ENABLED"},
                   **({"rotationPeriod": "7776000s", "nextRotationTime": _iso(-30)} if g.kms == "rotated" else {})})
            asset("cloudkms", f"locations/{region}/keyRings/ring-main/cryptoKeys/signing-key",
                  {"name": f"projects/{project_id}/locations/{region}/keyRings/ring-main/cryptoKeys/signing-key", "purpose": "ASYMMETRIC_SIGN", "primary": {"state": "ENABLED"}})
        if "apikeys.googleapis.com/Key" in asset_types:
            for i, (display, restricted, age) in enumerate(g.api_keys):  # the inventory names API keys by project number
                found.append(SimpleNamespace(name=f"//apikeys.googleapis.com/projects/{number}/locations/global/keys/{project_id}-k{i}",
                                             resource=SimpleNamespace(parent=f"//cloudresourcemanager.googleapis.com/projects/{number}", data={
                                                 "name": f"projects/{number}/locations/global/keys/{project_id}-k{i}", "uid": f"{project_id}-k{i}", "displayName": display, "createTime": _iso(age),
                                                 "restrictions": ({"apiTargets": [{"service": "storage.googleapis.com"}], "serverKeyRestrictions": {"allowedIps": ["203.0.113.0/24"]}} if restricted else {})})))
        return found

    @staticmethod
    def _pdb_assets(profile, cluster):
        """The cluster's ``policy.k8s.io/PodDisruptionBudget`` assets (v18.2), as the inventory shows Kubernetes objects: spec and status."""
        o = profile.gke_operations.get(cluster.name)
        # Numbers as the inventory delivers them: protobuf Struct floats (the first v18.2 canary read none of the budgets for that).
        shapes = {"system": ({"maxUnavailable": 1.0}, {"disruptionsAllowed": 1.0, "currentHealthy": 2.0, "desiredHealthy": 1.0, "expectedPods": 2.0}),
                  "blocking": ({"maxUnavailable": 0.0}, {"disruptionsAllowed": 0.0, "currentHealthy": 2.0, "desiredHealthy": 2.0, "expectedPods": 2.0}),
                  "exhausted": ({"minAvailable": 2.0}, {"disruptionsAllowed": 0.0, "currentHealthy": 2.0, "desiredHealthy": 2.0, "expectedPods": 3.0}),
                  "healthy": ({"maxUnavailable": "25%"}, {"disruptionsAllowed": 1.0, "currentHealthy": 4.0, "desiredHealthy": 3.0, "expectedPods": 4.0})}
        assets = []
        for namespace, name, kind in (o.pdbs if o else ()):
            spec, status = shapes[kind]
            assets.append(SimpleNamespace(
                name=f"//container.googleapis.com/projects/{profile.project_id}/locations/{cluster.location}/clusters/{cluster.name}/k8s/namespaces/{namespace}/policy/poddisruptionbudgets/{name}",
                resource=SimpleNamespace(data={"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": {"name": name, "namespace": namespace},
                                               "spec": {**spec, "selector": {"matchLabels": {"app": name.rsplit("-", 1)[0]}}}, "status": status},
                                         parent=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_number}")))
        return assets

    def _cluster_asset(self, profile, cluster):
        """A ``container.googleapis.com/Cluster`` asset with the fields the v17.1 checks read, from the cluster's GkeHardening."""
        h = profile.gke_hardening.get(cluster.name)
        o = profile.gke_operations.get(cluster.name)  # v18.2
        project_id = profile.project_id
        scopes = ["https://www.googleapis.com/auth/cloud-platform"] if (h and h.cloud_platform_scope) else [
            "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring"]
        pools = []
        for i, (name, auto, version) in enumerate(cluster.node_pools):
            gke_metadata = bool(h and i < len(h.gke_metadata_pools) and h.gke_metadata_pools[i])
            config = {"serviceAccount": "default" if (h is None or h.default_service_account) else f"gke-nodes@{project_id}.iam.gserviceaccount.com",
                      "oauthScopes": scopes, "metadata": {"disable-legacy-endpoints": "true"},
                      "imageType": "COS_CONTAINERD" if (h is None or h.cos_image) else "UBUNTU_CONTAINERD",
                      "shieldedInstanceConfig": {"enableSecureBoot": bool(h and h.secure_boot), "enableIntegrityMonitoring": o is None or o.integrity_monitoring}}
            if gke_metadata:
                config["workloadMetadataConfig"] = {"mode": "GKE_METADATA"}
            zones = (profile.gke_pool_zones.get(cluster.name) or ())
            if o and o.lagging_pool and i == 0:  # v18.2: two minors behind the control plane
                major, minor, rest = cluster.master_version.split(".", 2)
                version = f"{major}.{int(minor) - 2}.{rest}"
            unavailable = o.max_unavailable[i] if (o and i < len(o.max_unavailable)) else 0
            pools.append({"name": name, "version": version, "config": config, "management": {"autoUpgrade": auto},
                          **({"locations": list(zones[i])} if i < len(zones) else {}),  # v17.3
                          "upgradeSettings": {"strategy": "SURGE", "maxSurge": 1, **({"maxUnavailable": unavailable} if unavailable else {})},  # v18.2
                          "networkConfig": {"enablePrivateNodes": bool(h and h.private_nodes)}})
        data = {"name": cluster.name, "location": cluster.location, "status": "RUNNING", "currentMasterVersion": cluster.master_version,
                "nodePools": pools, "legacyAbac": {"enabled": bool(h and h.legacy_abac)}, "masterAuth": {"clusterCaCertificate": "c3ludGhldGlj"},
                "loggingConfig": {"componentConfig": {"enableComponents": ["SYSTEM_COMPONENTS"] + (["WORKLOADS"] if (h is None or h.workload_logs) else [])}},
                "databaseEncryption": {"state": "ENCRYPTED" if (h and h.secrets_encryption) else "DECRYPTED"},
                "securityPostureConfig": {"mode": "BASIC" if (h is None or h.security_posture) else "DISABLED",
                                          "vulnerabilityMode": "VULNERABILITY_BASIC" if (h and h.vulnerability_scanning) else "VULNERABILITY_DISABLED"},
                "shieldedNodes": {"enabled": h is None or h.shielded_nodes}, "anonymousAuthenticationConfig": {"mode": "LIMITED"},
                "privateClusterConfig": {"enablePrivateNodes": bool(h and h.private_nodes), "enablePrivateEndpoint": not (h is None or h.public_endpoint)},
                "masterAuthorizedNetworksConfig": {"enabled": bool(h and h.authorized_networks),
                                                   "cidrBlocks": ([{"cidrBlock": "0.0.0.0/0"}] if (h and h.open_authorized_networks) else [{"cidrBlock": "10.0.0.0/8"}])}}
        if cluster.release_channel:
            data["releaseChannel"] = {"channel": "REGULAR"}
        if h and h.autopilot:
            data["autopilot"] = {"enabled": True}
        if h and h.workload_identity:
            data["workloadIdentityConfig"] = {"workloadPool": f"{project_id}.svc.id.goog"}
        if h and h.client_certificate:
            data["masterAuth"]["clientCertificateConfig"] = {"issueClientCertificate": True}
        if h and h.network_policy:
            data["networkConfig"] = {"datapathProvider": "ADVANCED_DATAPATH"}
        if h and h.binary_authorization:
            data["binaryAuthorization"] = {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"}
        # v18.2: what the upgrade-readiness, observability and the three new hardening rules read.
        data["ipAllocationPolicy"] = {"useIpAliases": True}
        data.setdefault("networkConfig", {})["enableIntraNodeVisibility"] = bool(h and h.autopilot) or (o is None or o.intranode_visibility)
        components = (["SYSTEM_COMPONENTS"] if (o is None or o.system_metrics) else []) + (["APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"] if (o and o.control_plane_metrics) else [])
        data["monitoringConfig"] = {"componentConfig": {"enableComponents": components},
                                    "managedPrometheusConfig": {"enabled": bool(h and h.autopilot) or (o is None or o.managed_prometheus)}}
        data["addonsConfig"] = {"dnsCacheConfig": {"enabled": o is None or o.dns_cache}, "gcePersistentDiskCsiDriverConfig": {"enabled": True}}
        policy = {"resourceVersion": "e3b0c442"}
        if o and o.maintenance_window:
            policy["window"] = {"recurringWindow": {"window": {"startTime": "2026-01-03T18:00:00Z", "endTime": "2026-01-03T22:00:00Z"}, "recurrence": "FREQ=WEEKLY;BYDAY=SA,SU"}}
        if o and o.exclusion:
            policy.setdefault("window", {})["maintenanceExclusions"] = {"change-freeze": {
                "startTime": _iso(1), "endTime": _iso(-14), "maintenanceExclusionOptions": {"scope": "NO_MINOR_OR_NODE_UPGRADES"}}}
        data["maintenancePolicy"] = policy
        notifications = o.notifications if o else "on"
        data["notificationConfig"] = {"pubsub": {"enabled": True, "topic": f"projects/{project_id}/topics/gke-notifications",
                                                 **({"filter": {"eventType": ["UPGRADE_AVAILABLE_EVENT"]}} if notifications == "partial" else {})}
                                      if notifications != "off" else {}}
        return SimpleNamespace(name=f"//container.googleapis.com/projects/{project_id}/locations/{cluster.location}/clusters/{cluster.name}",
                               resource=SimpleNamespace(data=data, parent=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_number}"),
                               ancestors=[f"projects/{profile.project_number}", f"folders/{profile.folder_id}", f"organizations/{self.world.org_id}"])

    def search_all_iam_policies(self, request):
        """v17.1: the IAM policies that mention a service account (``policy:\"email\"``) or that open an impersonation path."""
        scope, query = request["scope"], request.get("query", "")
        folder_id = scope.split("/")[1] if scope.startswith("folders/") else None
        profiles = [self.world.project(scope.split("/", 1)[1])] if scope.startswith("projects/") else self.world.projects(folder_id)
        email = query.split('"')[1] if query.startswith('policy:"') else None
        results = []
        if query.startswith("memberTypes:") or query.startswith("roles:(roles/cloudkms"):  # v18.4: public access; KMS separation of duties
            for profile in profiles:
                g = profile.data_governance
                if g is None:
                    continue
                common = {"project": f"projects/{profile.project_number}", "organization": f"organizations/{self.world.org_id}", "folders": [f"folders/{profile.folder_id}"]}
                if query.startswith("memberTypes:"):
                    for dataset_id, hours, public in g.datasets:
                        if public and "bigquery.googleapis.com/Dataset" in (request.get("asset_types") or ["bigquery.googleapis.com/Dataset"]):
                            results.append(SimpleNamespace(asset_type="bigquery.googleapis.com/Dataset", resource=f"//bigquery.googleapis.com/projects/{profile.project_id}/datasets/{dataset_id}",
                                                           policy=SimpleNamespace(bindings=[SimpleNamespace(role="roles/bigquery.dataViewer", members=["allAuthenticatedUsers"])]), **common))
                elif g.kms_role_separation:
                    results.append(SimpleNamespace(asset_type="cloudresourcemanager.googleapis.com/Project", resource=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_id}",
                                                   policy=SimpleNamespace(bindings=[SimpleNamespace(role="roles/cloudkms.admin", members=["user:dba@example.com"]),
                                                                                    SimpleNamespace(role="roles/cloudkms.cryptoKeyEncrypterDecrypter", members=["user:dba@example.com", "serviceAccount:app@x.iam.gserviceaccount.com"])]), **common))
            self.call("asset", "searchAllIamPolicies", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
            return results
        for profile in profiles:
            project_bindings = self._project_policy_bindings(profile)
            common = {"project": f"projects/{profile.project_number}", "organization": f"organizations/{self.world.org_id}", "folders": [f"folders/{profile.folder_id}"]}
            if email is None:
                wanted = [b for b in project_bindings if b["role"] in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser", "roles/compute.serviceAgent")
                          or "/roles/" in b["role"]]
            else:
                wanted = [b for b in project_bindings if f"serviceAccount:{email}" in b["members"]]
            if wanted:
                results.append(SimpleNamespace(asset_type="cloudresourcemanager.googleapis.com/Project", resource=f"//cloudresourcemanager.googleapis.com/projects/{profile.project_id}",
                                               policy=SimpleNamespace(bindings=[SimpleNamespace(role=b["role"], members=list(b["members"])) for b in wanted]), **common))
            by_target = {}
            for level, resource, role, member in profile.impersonation_bindings:
                if level == "service account" and (email is None or email == resource):
                    by_target.setdefault(resource, []).append(SimpleNamespace(role=role, members=[member]))
            for target, bindings in by_target.items():
                results.append(SimpleNamespace(asset_type="iam.googleapis.com/ServiceAccount", resource=f"//iam.googleapis.com/projects/{profile.project_id}/serviceAccounts/{target}",
                                               policy=SimpleNamespace(bindings=bindings), **common))
        self.call("asset", "searchAllIamPolicies", pages=max(1, math.ceil(len(results) / PAGE_SIZE)))
        return results

    def _resilience_assets(self, profile, asset_types):
        """A project's Cloud SQL instances, managed instance groups, snapshots (single-region and, since v16.1,
        multi-region; v17: old and orphaned ones too) and disks (v17), as Asset Inventory lists them."""
        found = []
        if "sqladmin.googleapis.com/Instance" in asset_types:
            found += [self._sql_asset(profile, sql) for sql in profile.sql_instances]
        if "compute.googleapis.com/InstanceGroupManager" in asset_types:
            found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/zones/{zone}/instanceGroupManagers/mig-{zone}",
                                      resource=SimpleNamespace(data={"name": f"mig-{zone}", "zone": zone})) for zone in profile.mig_zones]
        if "compute.googleapis.com/Snapshot" in asset_types:
            # (name, storage location, age in days, source disk): the source is the project's first VM's boot disk,
            # or a disk that no longer exists for an orphan.
            disk = self._disk_url(profile, profile.vms[0]) if profile.vms else ""
            snapshots = [(f"snap-{i}", "us-central1", 10 + i, disk) for i in range(profile.single_region_snapshots)]
            snapshots += [(f"snap-mr-{i}", ("asia", "us", "eu")[i % 3], 20 + i, disk) for i in range(profile.multi_region_snapshots)]
            snapshots += [(name, "us", age, disk) for name, age in profile.old_snapshots]
            snapshots += [(name, "us", 30, f"https://www.googleapis.com/compute/v1/projects/{profile.project_id}/zones/{profile.zones[0]}/disks/deleted-disk")
                          for name in profile.orphan_snapshots]
            found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/global/snapshots/{name}",
                                      resource=SimpleNamespace(data={"name": name, "storageLocations": [location], "creationTimestamp": _iso(age),
                                                                     "diskSizeGb": "50", "sourceDisk": source, "status": "READY"}))
                      for name, location, age, source in snapshots]
        if "compute.googleapis.com/Disk" in asset_types:
            found += [SimpleNamespace(name=f"//compute.googleapis.com/projects/{profile.project_id}/zones/{vm.zone}/disks/{vm.name}",
                                      resource=SimpleNamespace(data={"name": vm.name, "selfLink": self._disk_url(profile, vm), "sizeGb": "50"}))
                      for vm in profile.vms]
        return found

    @staticmethod
    def _disk_url(profile, vm):
        return f"https://www.googleapis.com/compute/v1/projects/{profile.project_id}/zones/{vm.zone}/disks/{vm.name}"

    @staticmethod
    def _sql_asset(profile, sql):
        region = profile.subnets[0][1] if profile.subnets else "us-central1"  # v17.3: the instance's region, as the API reports it
        data = {"name": sql.name, "databaseVersion": sql.database_version, "region": region, "settings": {
            "availabilityType": "ZONAL" if sql.zonal else "REGIONAL",
            "backupConfiguration": {"enabled": sql.backups, "pointInTimeRecoveryEnabled": sql.pitr, "retainedBackupsCount": sql.retained_backups}}}
        governance = profile.data_governance  # v18.4: the CIS flag pack, or the engine defaults
        if governance and governance.sql_flags == "pack":
            packs = {"POSTGRES": [("log_connections", "on"), ("log_disconnections", "on"), ("log_statement", "ddl"), ("cloudsql.enable_pgaudit", "on")],
                     "MYSQL": [("local_infile", "off"), ("skip_show_database", "on")],
                     "SQLSERVER": [("remote access", "off"), ("3625", "on")]}
            engine = next((e for e in packs if sql.database_version.upper().startswith(e)), "POSTGRES")
            data["settings"]["databaseFlags"] = [{"name": n, "value": v} for n, v in packs[engine]]
        return SimpleNamespace(name=f"//cloudsql.googleapis.com/projects/{profile.project_id}/instances/{sql.name}",
                               resource=SimpleNamespace(data=data))

    # --- Recommender (gRPC) ---

    def list_recommendations(self, parent=None, filter=None, request=None):
        parent = parent or (request or {}).get("parent")
        project_id = _project_of(parent)
        self.call("recommender", "recommendations.list", project_id=project_id)
        recommender_id = parent.rsplit("/recommenders/", 1)[-1]
        if recommender_id == IAM_RECOMMENDER:
            return self._iam_recommendations(parent, project_id)
        if project_id is None:
            if recommender_id != UNATTENDED_RECOMMENDER:
                return []
            return [recommender_v1.Recommendation({
                "name": f"{parent}/recommendations/{i}", "recommender_subtype": "CLEANUP_PROJECT", "state_info": {"state": "ACTIVE"},
                "description": f"Project `{pid}` has been unattended for 90 days. Consider cleaning it up.",
                "target_resources": [f"//cloudresourcemanager.googleapis.com/projects/{pid}"],
                "content": {"operation_groups": [{"operations": [{"action": "remove", "resource": f"//cloudresourcemanager.googleapis.com/projects/{pid}"}]}]},
            }) for i, pid in enumerate(self.world.unattended_project_ids())]
        profile = self.world.project(project_id)
        if recommender_id == QUOTA_RECOMMENDER:
            if not profile.quota_recommendation:
                return []
            return [recommender_v1.Recommendation({"name": f"{parent}/recommendations/0", "recommender_subtype": "REVIEW_HIGH_QUOTA_UTILIZATION",
                                                   "description": f"Increase the CPUS quota in {REGIONS[0]} from 100 to 200: usage is approaching the limit.",
                                                   "content": {"overview": {"serviceName": "compute.googleapis.com", "quotaName": "CPUS",
                                                                            "metric": "compute.googleapis.com/cpus", "currentLimit": 100,
                                                                            "dimensions": f"region:{REGIONS[0]}", "allowsQuotaIncreaseRequest": True}}})]
        check = COST_RECOMMENDER_IDS.get(recommender_id)
        location = parent.split("/locations/")[1].split("/")[0]
        recos = profile.cost_recommendations.get((check, location), []) if check else []
        return [recommender_v1.Recommendation({
            "name": f"{parent}/recommendations/{i}", "description": description, "recommender_subtype": subtype,
            "priority": "P2" if usd >= 50 else "P4", "state_info": {"state": "ACTIVE"},  # v18.1: the priority decides the verdict
            "primary_impact": {"category": "COST", "cost_projection": {"cost": {"currency_code": "USD", "units": -usd, "nanos": 0}}},
            "content": {"overview": {"resourceName": resource},
                        "operation_groups": [{"operations": [{"action": "replace", "resource": f"//compute.googleapis.com/projects/{project_id}/zones/{location}/instances/{resource}"}]}]},
        }) for i, (resource, subtype, description, usd) in enumerate(recos)]

    def _iam_recommendations(self, parent, project_id):
        """The IAM recommender's recommendations (v17): the project's unused primitive roles; one at the organization; none for a folder."""
        if project_id is not None:
            resource, items = f"//cloudresourcemanager.googleapis.com/projects/{project_id}", self.world.project(project_id).iam_recommendations
        elif parent.startswith("organizations/"):
            resource, items = f"//cloudresourcemanager.googleapis.com/organizations/{self.world.org_id}", (ORG_IAM_RECOMMENDATION,)
        else:
            return []
        recommendations = []
        for i, (member, role, replacement) in enumerate(items):
            operations = [{"action": "remove", "resource_type": "cloudresourcemanager.googleapis.com/Project", "resource": resource,
                           "path": "/iamPolicy/bindings/*/members/*",
                           "path_filters": {"/iamPolicy/bindings/*/role": role, "/iamPolicy/bindings/*/members/*": member}}]
            if replacement:
                operations.append({"action": "add", "resource_type": "cloudresourcemanager.googleapis.com/Project", "resource": resource,
                                   "path": "/iamPolicy/bindings/*/members/-", "value": member,
                                   "path_filters": {"/iamPolicy/bindings/*/role": replacement}})
            description = (f"Replace the current role {role} with a smaller role {replacement} to cover the permissions needed by {member}."
                           if replacement else f"Remove the role {role} from {member}: no permission of it was used in the last 90 days.")
            recommendations.append(recommender_v1.Recommendation({
                "name": f"{parent}/recommendations/{i}", "recommender_subtype": "REPLACE_ROLE" if replacement else "REMOVE_ROLE",
                "description": description, "content": {"operation_groups": [{"operations": operations}]}}))
        return recommendations

    def list_insights(self, parent=None, filter=None, request=None):
        parent = parent or (request or {}).get("parent")
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
                    "severity": "HIGH" if payload["ratio"] >= 0.9 else "MEDIUM", "state_info": {"state": "ACTIVE"},
                    "target_resources": [f"//compute.googleapis.com/{payload['subnet']}"],
                    "content": {"ipUtilizationSummaryInfo": [{"networkStats": [{"networkUri": payload["network"], "subnetStats": [
                        {"subnetUri": payload["subnet"], "subnetRangeStats": [{"subnetRangePrefix": payload["prefix"], "allocationRatio": payload["ratio"]}]}]}]}]}}))
            elif kind == "sa":
                insights.append(recommender_v1.Insight({
                    "name": f"{parent}/insights/{i}", "description": "GKE node service account has the Editor role.", "severity": "MEDIUM", "state_info": {"state": "ACTIVE"},
                    "target_resources": [f"//container.googleapis.com/{payload['cluster_uri']}"],
                    "content": {"nodeServiceAccountInsight": {"clusterUri": payload["cluster_uri"], "serviceAccount": "default"}}}))
            else:
                insights.append(recommender_v1.Insight({"name": f"{parent}/insights/{i}", "description": payload["description"], "severity": "LOW", "state_info": {"state": "ACTIVE"}}))
        return insights

    # --- OS Config ---

    def list_inventories(self, request):
        """``OsConfigZonalServiceClient.list_inventories`` (v18): the inventories of one zone, named by instance ID; FailedPrecondition
        when the project has OS inventory management off."""
        parent = request["parent"]
        if not parent.endswith("/instances/-"):  # the API's pattern: projects/{project}/locations/{zone}/instances/-
            raise core_exceptions.InvalidArgument("Violation in ListInventoriesRequest.parent: The 'parent' field does not match the expected pattern.")
        project_id, zone = _project_of(parent), parent.rsplit("/locations/", 1)[-1].split("/", 1)[0]
        self.call("osconfig", "listInventories", project_id=project_id)
        profile = self.world.project(project_id)
        if profile.osconfig_disabled:
            raise core_exceptions.FailedPrecondition("OS inventory management has been disabled in this project.")
        return [SimpleNamespace(name=f"projects/{profile.project_number}/locations/{zone}/instances/{self._instance_id(profile, index)}/inventory",
                                os_info=SimpleNamespace(hostname=vm.name))
                for index, vm in enumerate(profile.vms) if vm.zone == zone and vm.os_reporting and vm.name not in profile.stopped_vms]

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

    def search_all_iam_policies(self, request):
        return self._p.search_all_iam_policies(request)


class _RecommenderStub:
    def __init__(self, provider):
        self._p = provider

    def list_recommendations(self, parent=None, filter=None, request=None):
        return self._p.list_recommendations(parent, filter=filter, request=request)

    def list_insights(self, parent=None, filter=None, request=None):
        return self._p.list_insights(parent, filter=filter, request=request)


class _OsConfigStub:
    def __init__(self, provider):
        self._p = provider

    def get_inventory(self, request):
        return self._p.get_inventory(request)

    def list_inventories(self, request):
        return self._p.list_inventories(request)


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
        self.iam_configuration = SimpleNamespace(uniform_bucket_level_access_enabled=bucket.ubla,
                                                 public_access_prevention="enforced" if bucket.name in provider.world.project(project_id).pap_enforced_buckets else "inherited")
        # v17: lifecycle rules and Autoclass, as google-cloud-storage exposes them
        self.lifecycle_rules = [{"action": {"type": "SetStorageClass", "storageClass": "NEARLINE"}, "condition": {"age": 30}}] if bucket.lifecycle else []
        self.autoclass_enabled = bucket.autoclass
        self.storage_class = "STANDARD"
        # v18.1: soft delete (the 7-day default, or off for the unprotected buckets) and a retention policy on some
        profile = provider.world.project(project_id)
        self.soft_delete_policy = SimpleNamespace(retention_duration_seconds=0 if bucket.name in profile.unprotected_buckets else 604800)
        self.retention_period = 86400 * 30 if bucket.name in profile.retention_buckets else None

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
