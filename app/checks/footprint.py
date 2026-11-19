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
"""Platform Footprint (v19.1): what runs where, on one page — a briefing, never scored.

One all-types search of the inventory under the scope (``searchAllResources`` with no asset type: names, types,
locations, projects — 1,908 assets in 2 s on the reference organization), one content search for the resources
whose version matters (GKE clusters, Cloud SQL instances, Cloud Run services, VMs), and the enabled-service assets
(the APIs on in each project). The lines, in the Spend Briefing's shape (``Line, Value, Detail, Fix``): the projects,
the regions, the enabled APIs, then one line per product family (``FAMILIES``, its own type first and counted in the
Value), one for the Kubernetes objects GKE indexes (``*.k8s.io`` types, by rule) and *Other* for the rest — every Fix the
``gcloud asset search-all-resources`` that lists the line. Informational: nothing here is a verdict. The index
counts what it indexes; a folder or project scan reads its own subtree.
"""
import logging
from collections import Counter

from google.cloud import asset_v1

from app.checks.gke_operations import INFORMATIONAL
from app.config import SCOPES
from app.services import gcp

FOOTPRINT_CHECK = "Platform Footprint"
PROJECT_TYPE = "cloudresourcemanager.googleapis.com/Project"
SERVICE_TYPE = "serviceusage.googleapis.com/Service"
VERSIONED_TYPES = ["container.googleapis.com/Cluster", "sqladmin.googleapis.com/Instance", "compute.googleapis.com/Instance", "alloydb.googleapis.com/Cluster",
                   "spanner.googleapis.com/Instance", "redis.googleapis.com/Instance", "bigtableadmin.googleapis.com/Instance"]
HIDDEN_TYPES = (PROJECT_TYPE, SERVICE_TYPE, "cloudresourcemanager.googleapis.com/Folder", "cloudresourcemanager.googleapis.com/Organization")  # counted on their own lines
# Product family → the asset types it gathers (name → short label). Everything not here is Other.
FAMILIES = {
    "Compute Engine": {"compute.googleapis.com/Instance": "VMs", "compute.googleapis.com/Disk": "disks", "compute.googleapis.com/Snapshot": "snapshots", "compute.googleapis.com/Image": "images",
                       "compute.googleapis.com/InstanceTemplate": "instance templates", "compute.googleapis.com/InstanceGroupManager": "MIGs", "compute.googleapis.com/Reservation": "reservations",
                       "compute.googleapis.com/Commitment": "commitments"},
    "GKE": {"container.googleapis.com/Cluster": "clusters", "container.googleapis.com/NodePool": "node pools"},
    "Cloud Run": {"run.googleapis.com/Service": "services", "run.googleapis.com/Job": "jobs", "cloudfunctions.googleapis.com/Function": "functions", "cloudfunctions.googleapis.com/CloudFunction": "functions (gen 1)",
                  "run.googleapis.com/Revision": "revisions", "appengine.googleapis.com/Service": "App Engine services"},
    "Databases": {"sqladmin.googleapis.com/Instance": "Cloud SQL instances", "alloydb.googleapis.com/Cluster": "AlloyDB clusters", "alloydb.googleapis.com/Instance": "AlloyDB instances",
                  "spanner.googleapis.com/Instance": "Spanner instances", "spanner.googleapis.com/Database": "Spanner databases", "bigtableadmin.googleapis.com/Instance": "Bigtable instances",
                  "redis.googleapis.com/Instance": "Memorystore instances", "firestore.googleapis.com/Database": "Firestore databases", "memcache.googleapis.com/Instance": "Memcached instances"},
    "Storage": {"storage.googleapis.com/Bucket": "buckets", "file.googleapis.com/Instance": "Filestore instances", "netapp.googleapis.com/Volume": "NetApp volumes"},
    "BigQuery": {"bigquery.googleapis.com/Dataset": "datasets", "bigquery.googleapis.com/Table": "tables", "bigquery.googleapis.com/Model": "models", "bigquery.googleapis.com/Routine": "routines",
                 "bigquery.googleapis.com/Reservation": "reservations"},
    "Data processing and messaging": {"pubsub.googleapis.com/Topic": "topics", "pubsub.googleapis.com/Subscription": "subscriptions", "dataflow.googleapis.com/Job": "Dataflow jobs",
                                      "dataproc.googleapis.com/Cluster": "Dataproc clusters", "composer.googleapis.com/Environment": "Composer environments", "dataform.googleapis.com/Repository": "Dataform repositories",
                                      "datalineage.googleapis.com/Process": "Data Lineage processes", "datafusion.googleapis.com/Instance": "Data Fusion instances"},
    "Vertex AI": {"aiplatform.googleapis.com/Endpoint": "endpoints", "aiplatform.googleapis.com/Model": "models", "aiplatform.googleapis.com/Dataset": "datasets", "aiplatform.googleapis.com/NotebookRuntime": "notebook runtimes",
                  "notebooks.googleapis.com/Instance": "Workbench instances", "aiplatform.googleapis.com/FeatureStore": "feature stores", "aiplatform.googleapis.com/ReasoningEngine": "reasoning engines",
                  "discoveryengine.googleapis.com/Collection": "Discovery Engine collections", "discoveryengine.googleapis.com/DataStore": "Discovery Engine data stores", "discoveryengine.googleapis.com/Engine": "Discovery Engine engines"},
    "Networking": {"compute.googleapis.com/Network": "VPC networks", "compute.googleapis.com/Subnetwork": "subnets", "compute.googleapis.com/ForwardingRule": "forwarding rules",
                   "compute.googleapis.com/GlobalForwardingRule": "global forwarding rules", "compute.googleapis.com/Router": "routers", "compute.googleapis.com/VpnTunnel": "VPN tunnels",
                   "compute.googleapis.com/InterconnectAttachment": "Interconnect attachments", "compute.googleapis.com/Address": "addresses", "compute.googleapis.com/GlobalAddress": "global addresses",
                   "dns.googleapis.com/ManagedZone": "DNS zones", "compute.googleapis.com/Firewall": "firewall rules", "compute.googleapis.com/BackendService": "backend services",
                   "compute.googleapis.com/SecurityPolicy": "Cloud Armor policies", "vpcaccess.googleapis.com/Connector": "VPC Access connectors"},
    "Identity and secrets": {"iam.googleapis.com/ServiceAccount": "service accounts", "iam.googleapis.com/ServiceAccountKey": "user-managed keys", "iam.googleapis.com/Role": "custom roles",
                             "secretmanager.googleapis.com/Secret": "secrets", "cloudkms.googleapis.com/CryptoKey": "KMS keys", "cloudkms.googleapis.com/KeyRing": "key rings", "apikeys.googleapis.com/Key": "API keys"},
    "Registries and build": {"artifactregistry.googleapis.com/Repository": "Artifact Registry repositories", "artifactregistry.googleapis.com/DockerImage": "Artifact Registry images",
                             "containerregistry.googleapis.com/Image": "Container Registry images", "cloudbuild.googleapis.com/BuildTrigger": "Cloud Build triggers"},
    "Operations": {"logging.googleapis.com/LogSink": "log sinks", "logging.googleapis.com/LogBucket": "log buckets", "monitoring.googleapis.com/AlertPolicy": "alert policies",
                   "monitoring.googleapis.com/NotificationChannel": "notification channels", "monitoring.googleapis.com/UptimeCheckConfig": "uptime checks", "cloudtasks.googleapis.com/Queue": "Cloud Tasks queues",
                   "cloudscheduler.googleapis.com/Job": "Cloud Scheduler jobs", "orgpolicy.googleapis.com/Policy": "organization policies", "cloudasset.googleapis.com/Feed": "asset feeds"},
}
FAMILY_OF = {asset_type: family for family, types in FAMILIES.items() for asset_type in types}
LABEL_OF = {asset_type: label for types in FAMILIES.values() for asset_type, label in types.items()}
LEAD_OF = {family: next(iter(types)) for family, types in FAMILIES.items()}  # the type a family is counted by in its Value (first in its map)
KUBERNETES = "Kubernetes objects"  # the in-cluster inventory GKE indexes: k8s.io, apps.k8s.io, rbac.authorization.k8s.io, … — a family by rule, not by map
TOP = 5


def family_of(asset_type):
    if asset_type in FAMILY_OF:
        return FAMILY_OF[asset_type]
    group = asset_type.split("/")[0]  # "k8s.io/Pod", "apps.k8s.io/Deployment": the Kubernetes API group is k8s.io or one of its subdomains
    return KUBERNETES if group == "k8s.io" or group.endswith(".k8s.io") else "Other"


def label_of(asset_type):
    """``disks``, ``Cloud SQL instances``; a Kubernetes kind pluralised (``ClusterRoleBindings``, ``Ingresses``, ``NetworkPolicies``)."""
    if asset_type in LABEL_OF:
        return LABEL_OF[asset_type]
    kind = asset_type.rsplit("/", 1)[-1]
    if kind.endswith("y"):
        return kind[:-1] + "ies"
    if kind.endswith("ss"):
        return kind + "es"
    return kind if kind.endswith("s") else kind + "s"  # Endpoints stays Endpoints


def tail(name):
    return str(name or "").rsplit("/", 1)[-1]


def search_line(parent, asset_types=None):
    types = f" --asset-types={','.join(asset_types)}" if asset_types else ""
    return f"gcloud asset search-all-resources --scope={parent}{types} --format='table(name,assetType,location,project)'"


def asset_facts(results):
    """``[{type, name, location, project, state}]`` of the all-types search's results (``project`` as ``projects/<number>``)."""
    facts = []
    for result in results:
        facts.append({"type": str(getattr(result, "asset_type", "") or ""), "name": str(getattr(result, "name", "") or ""), "location": str(getattr(result, "location", "") or "") or "—",
                      "project": str(getattr(result, "project", "") or ""), "state": str(getattr(result, "state", "") or "")})
    return facts


def project_names(facts):
    """``{projects/<number>: project id}`` from the Project assets in the search (named by ID)."""
    return {fact["project"]: tail(fact["name"]) for fact in facts if fact["type"] == PROJECT_TYPE and fact["project"]}


def named(project, names):
    return names.get(project, tail(project) or "?")


def counted(items, limit=TOP, noun=""):
    """``"a ×3, b ×2 +4 more"`` over a Counter, most common first."""
    common = items.most_common()
    text = ", ".join(f"{key} ×{count}" if count != 1 else str(key) for key, count in common[:limit])
    return text + (f" +{len(common) - limit} more" if len(common) > limit else "") + (f" {noun}" if noun else "")


def singular(label):
    """``disks`` → ``disk``, ``policies`` → ``policy``, ``addresses`` → ``address``; a label that does not end in *s* is left alone."""
    if label.endswith("ies"):
        return label[:-3] + "y"
    if label.endswith("sses"):
        return label[:-2]
    return label[:-1] if label.endswith("s") else label


def plural(count, label):
    return f"{count:,} {label if count != 1 else singular(label)}"


def versions_of(contents):
    """``{asset type: [(name, version text)]}`` from the content search of ``VERSIONED_TYPES``."""
    found = {}
    for result in contents:
        asset_type = str(getattr(result, "asset_type", "") or "")
        versions = list(getattr(result, "versioned_resources", None) or [])
        if not versions:
            continue
        version = versions[0]
        data = version.get("resource") if isinstance(version, dict) else asset_v1.VersionedResource.to_dict(version).get("resource")
        data = data or {}
        name = tail(getattr(result, "name", ""))
        if asset_type == "container.googleapis.com/Cluster":
            channel = str(((data.get("releaseChannel") or {}).get("channel")) or "no channel").lower().replace("_", " ")
            kind = "Autopilot" if (data.get("autopilot") or {}).get("enabled") else "Standard"
            text = f"{data.get('currentMasterVersion') or '?'} ({channel} channel, {kind}, {int(float(data.get('currentNodeCount') or 0))} nodes)"
        elif asset_type == "sqladmin.googleapis.com/Instance":
            text = f"{data.get('databaseVersion') or '?'} {((data.get('settings') or {}).get('tier')) or ''}".strip()
        elif asset_type == "compute.googleapis.com/Instance":
            text = f"{tail(data.get('machineType')) or '?'} {str(data.get('status') or '').lower()}".strip()
        elif asset_type == "alloydb.googleapis.com/Cluster":
            text = str(data.get("databaseVersion") or "?")
        elif asset_type == "redis.googleapis.com/Instance":
            text = f"{data.get('redisVersion') or '?'} {data.get('tier') or ''} {data.get('memorySizeGb') or ''} GB".strip()
        elif asset_type == "spanner.googleapis.com/Instance":
            text = f"{data.get('config', '').rsplit('/', 1)[-1] or '?'} {data.get('nodeCount') or data.get('processingUnits') or ''}".strip()
        else:
            text = str(data.get("state") or "")
        found.setdefault(asset_type, []).append((name, text))
    return found


def footprint_rows(parent, facts, contents=(), services=()):
    """The briefing's lines from the all-types search (``facts``), the content search (``contents``) and the enabled-service assets."""
    names = project_names(facts)
    projects = sorted({fact["project"] for fact in facts if fact["type"] == PROJECT_TYPE} | {fact["project"] for fact in facts if fact["project"]})
    versions = versions_of(contents)
    rows = []
    # Projects
    listed = sorted(named(p, names) for p in projects)
    rows.append({"Line": "Projects", "Value": f"{len(projects)} project{'s' if len(projects) != 1 else ''}",
                 "Detail": ", ".join(listed[:TOP]) + (f" +{len(listed) - TOP} more" if len(listed) > TOP else "") + "." if listed else "No project in scope.",
                 "Fix": search_line(parent, [PROJECT_TYPE])})
    # Regions
    visible = [fact for fact in facts if fact["type"] not in HIDDEN_TYPES]
    by_location = Counter(fact["location"] for fact in visible)
    leading = {}
    for location in by_location:
        families = Counter(family_of(fact["type"]) for fact in visible if fact["location"] == location)
        leading[location] = ", ".join(f for f, _ in families.most_common(3))
    detail = "; ".join(f"{location} — {count:,} ({leading[location]})" for location, count in by_location.most_common(8)) + (f"; +{len(by_location) - 8} more locations" if len(by_location) > 8 else "")
    rows.append({"Line": "Regions", "Value": f"{len(by_location)} location{'s' if len(by_location) != 1 else ''}", "Detail": (detail + ".") if detail else "Nothing indexed.", "Fix": search_line(parent)})
    # Enabled APIs
    service_facts = [(str(getattr(s, "project", "") or ""), tail(getattr(s, "name", ""))) for s in services]
    if service_facts:
        per_project = Counter(project for project, _ in service_facts)
        per_service = Counter(service for _, service in service_facts)
        everywhere = sorted(service for service, count in per_service.items() if count == len(per_project) and len(per_project) > 1)
        lonely = sorted(service for service, count in per_service.items() if count == 1 and len(per_project) > 1)
        detail = "; ".join(f"{named(p, names)}: {c}" for p, c in per_project.most_common(TOP)) + (f"; +{len(per_project) - TOP} more projects" if len(per_project) > TOP else "")
        if everywhere:
            detail += f". On in every project: {', '.join(everywhere[:TOP])}" + (f" +{len(everywhere) - TOP} more" if len(everywhere) > TOP else "")
        if lonely:
            detail += f". On in one project only: {', '.join(lonely[:TOP])}" + (f" +{len(lonely) - TOP} more" if len(lonely) > TOP else "")
        rows.append({"Line": "Enabled APIs", "Value": f"{len(per_service)} distinct service{'s' if len(per_service) != 1 else ''}", "Detail": detail + ".", "Fix": search_line(parent, [SERVICE_TYPE])})
    # Families, then the Kubernetes objects, then Other
    kubernetes = sorted({fact["type"] for fact in visible if family_of(fact["type"]) == KUBERNETES})
    for family, types in list(FAMILIES.items()) + [(KUBERNETES, kubernetes)]:
        members = [fact for fact in visible if fact["type"] in types]
        if not members:
            continue
        by_type = Counter(fact["type"] for fact in members)
        lead = LEAD_OF.get(family)
        ordered = ([lead] if lead in by_type else []) + [t for t, _ in by_type.most_common() if t != lead]  # the family's own type first, the rest by count
        parts = {t: plural(by_type[t], label_of(t)) for t in ordered}
        vm_type = "compute.googleapis.com/Instance"
        if vm_type in by_type and versions.get(vm_type):
            states = Counter(text.rsplit(" ", 1)[-1] for _, text in versions[vm_type])
            machines = Counter(text.split(" ")[0].split("-")[0] for _, text in versions[vm_type])
            parts[vm_type] += f" ({', '.join(f'{c} {s}' for s, c in states.most_common())}; {counted(machines, 3)} families)"
        locations = Counter(fact["location"] for fact in members)
        projects_in = Counter(named(fact["project"], names) for fact in members if fact["project"])
        listed = "; ".join(parts[t] for t in ordered[:12]) + (f"; +{len(ordered) - 12} more types" if len(ordered) > 12 else "")
        detail = f"{listed}. Locations: {counted(locations)}. Projects: {counted(projects_in)}."
        for asset_type in types:
            if asset_type in versions and asset_type != vm_type:
                items = versions[asset_type]
                detail += f" {LABEL_OF[asset_type][:1].upper()}{LABEL_OF[asset_type][1:]}: " + "; ".join(f"{n} — {v}" for n, v in items[:TOP]) + (f" +{len(items) - TOP} more" if len(items) > TOP else "") + "."
        value = f"{len(members):,} resource{'s' if len(members) != 1 else ''}"
        if lead in by_type:
            value = plural(by_type[lead], LABEL_OF[lead]) + (f", {len(members):,} resources" if len(members) != by_type[lead] else "")
        rows.append({"Line": family, "Value": value, "Detail": detail, "Fix": search_line(parent, [t for t in types if t in by_type])})
    # Other
    other = [fact for fact in visible if family_of(fact["type"]) == "Other"]
    if other:
        by_type = Counter(fact["type"] for fact in other)
        rows.append({"Line": "Other", "Value": f"{len(other):,} resources of {len(by_type)} types",
                     "Detail": "Largest: " + ", ".join(f"{t.split('/')[-1]} ({t.split('/')[0].split('.')[0]})" + (f" ×{c}" if c != 1 else "") for t, c in by_type.most_common(10)) + ".", "Fix": search_line(parent)})
    return rows


def check_platform_footprint(scope, scope_id, job_id, *, sink):
    """Writes *Platform Footprint* (module docstring)."""
    print(f"🗺️  [{job_id}] Checking {FOOTPRINT_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        facts = asset_facts(asset_client.search_all_resources(request={"scope": parent, "read_mask": "name,assetType,location,project,state", "page_size": 500}))
    except Exception as e:
        logging.error(f"[{job_id}] {FOOTPRINT_CHECK}: the inventory search under {parent} failed: {e}")
        sink.write_finding(job_id, FOOTPRINT_CHECK.replace(" ", "_"), {"Check": FOOTPRINT_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    contents, services = [], []
    try:
        contents = list(asset_client.search_all_resources(request={"scope": parent, "asset_types": VERSIONED_TYPES, "read_mask": "name,assetType,location,project,versionedResources", "page_size": 500}))
    except Exception as e:  # noqa: BLE001 — the versions are a bonus
        logging.info(f"[{job_id}] {FOOTPRINT_CHECK}: the content search failed: {e}")
    try:
        services = list(asset_client.search_all_resources(request={"scope": parent, "asset_types": [SERVICE_TYPE], "read_mask": "name,project,state", "page_size": 500}))
    except Exception as e:  # noqa: BLE001
        logging.info(f"[{job_id}] {FOOTPRINT_CHECK}: the enabled-service search failed: {e}")
    rows = footprint_rows(parent, facts, contents, services)
    sink.write_finding(job_id, FOOTPRINT_CHECK.replace(" ", "_"), {"Check": FOOTPRINT_CHECK, "Finding": rows, "Status": INFORMATIONAL})
