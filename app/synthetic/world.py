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
"""A deterministic, generated Google Cloud organization for load tests.

``SyntheticOrg(n_projects, seed)`` describes an organization with ``n_projects``
projects spread over a few folders. Every project's inventory (VMs, buckets, IAM
bindings, service-account keys, firewall rules, networks, Cloud SQL, GKE,
alerting, recommendations, insights) is derived from ``(seed, project index)``
only, so the same settings always produce the same organization, in any call
order and from any thread. Profiles are generated lazily and cached.

The mix is tuned so that every check finds *something* in a large enough
organization (a realistic report, not an all-green one) while most projects
stay small, which is what enterprise estates look like.

Nothing here talks to the network. ``app.synthetic.provider`` turns these
profiles into API responses.
"""
import functools
import random
from dataclasses import dataclass, field

ORG_ID = "100000000001"
FOLDER_COUNT = 6
FOLDER_IDS = [str(200000000001 + i) for i in range(FOLDER_COUNT)]
HOST_PROJECT = "synthetic-host"  # the project that "runs" CloudGauge (auth_default's project)

# Zones the generated VMs live in (6 zones, 4 regions); the location discovery
# finds these plus the regions of addresses and forwarding rules.
ZONES = ["us-central1-a", "us-central1-b", "us-east1-b", "europe-west1-b", "asia-south1-a", "asia-south1-b"]
# What compute.regions().list() returns: every project sees the same 10 regions.
REGIONS = ["us-central1", "us-east1", "us-west1", "europe-west1", "europe-west2",
           "asia-south1", "asia-southeast1", "asia-east1", "australia-southeast1", "southamerica-east1"]
QUOTA_METRICS = ["CPUS", "IN_USE_ADDRESSES", "INSTANCES", "DISKS_TOTAL_GB"]
PRIMITIVE_MEMBERS = ["user:alice@example.com", "user:bob@example.com", "group:devs@example.com",
                     "serviceAccount:deployer@%s.iam.gserviceaccount.com"]
ORG_POLICY_CONSTRAINTS = {
    # constraint id -> enforced at the organization level
    "compute.vmExternalIpAccess": True,
    "iam.disableServiceAccountKeyCreation": False,
    "storage.uniformBucketLevelAccess": True,
    "compute.requireOsLogin": False,
    "sql.restrictPublicIp": True,
    "compute.skipDefaultNetworkCreation": False,
}
BEST_PRACTICES_CSV = """Category,ID,Policy Display Name,Recommended to set *
Networking,,,
,compute.vmExternalIpAccess,Define allowed external IPs for VM instances,Should have
,compute.skipDefaultNetworkCreation,Skip default network creation,Should have
Identity,,,
,iam.disableServiceAccountKeyCreation,Disable service account key creation,Must have
,compute.requireOsLogin,Require OS Login,Should have
Storage and Data,,,
,storage.uniformBucketLevelAccess,Enforce uniform bucket-level access,Should have
,sql.restrictPublicIp,Restrict Public IP access on Cloud SQL instances,Should have
"""


def _rng(seed, *parts):
    """A ``random.Random`` seeded from ``seed`` and the given parts (stable across processes)."""
    return random.Random(f"{seed}|" + "|".join(str(p) for p in parts))


def _chance(rng, probability):
    return rng.random() < probability


@dataclass(frozen=True)
class Vm:
    name: str
    zone: str
    external_ip: bool
    in_mig: bool
    gke: bool
    os_reporting: bool


@dataclass(frozen=True)
class Bucket:
    name: str
    public: bool
    ubla: bool
    versioning: bool


@dataclass(frozen=True)
class ServiceAccount:
    email: str
    key_ages_days: tuple  # user-managed keys, by age


@dataclass(frozen=True)
class SqlInstance:
    name: str
    public_ip: bool
    require_ssl: bool
    zonal: bool
    backups: bool
    pitr: bool
    retained_backups: int


@dataclass(frozen=True)
class GkeCluster:
    name: str
    location: str
    release_channel: bool
    node_pools: tuple  # (name, auto_upgrade)
    recommendations: tuple


@dataclass(frozen=True)
class ProjectProfile:
    index: int
    project_id: str
    display_name: str
    folder_id: str
    denied: bool  # every API answers 403 (missing permissions / disabled APIs)
    osconfig_disabled: bool
    vms: tuple
    buckets: tuple
    primitive_bindings: tuple  # (role, member)
    service_accounts: tuple
    firewall_rules: tuple  # (name, open_to_world, disabled)
    has_default_vpc: bool
    subnets: tuple  # (name, region, private_google_access)
    hot_quotas: tuple  # (region, metric, usage, limit)
    sql_instances: tuple
    gke_clusters: tuple
    alert_filters: tuple  # substrings present in the project's alert policy filters
    addresses_regions: tuple
    forwarding_rule_regions: tuple
    cost_recommendations: dict = field(default_factory=dict)  # (check name, location) -> [(resource, subtype, description, usd)]
    network_insights: dict = field(default_factory=dict)  # (check name, location) -> [(kind, payload)]
    recent_changes: tuple = ()
    mig_zones: tuple = ()
    single_region_snapshots: int = 0

    @property
    def zones(self):
        return sorted({vm.zone for vm in self.vms})


class SyntheticOrg:
    """The generated organization. Profiles come from :meth:`project` / :meth:`projects`."""

    def __init__(self, n_projects, seed=42, denied_fraction=0.02):
        if n_projects < 1:
            raise ValueError("n_projects must be at least 1")
        self.n_projects = int(n_projects)
        self.seed = int(seed)
        self.denied_fraction = float(denied_fraction)
        self.org_id = ORG_ID
        self.folder_ids = list(FOLDER_IDS)
        self._project = functools.lru_cache(maxsize=None)(self._build_project)  # thread-safe; profiles are immutable

    # --- identity ---

    def project_id(self, index):
        return f"syn-{self.seed}-{index:05d}"

    def index_of(self, project_id):
        """The index of a generated project ID, or ``None`` for an unknown ID."""
        prefix = f"syn-{self.seed}-"
        if not project_id or not str(project_id).startswith(prefix):
            return None
        try:
            index = int(project_id[len(prefix):])
        except ValueError:
            return None
        return index if 0 <= index < self.n_projects else None

    def project(self, project_id):
        """The :class:`ProjectProfile` for ``project_id``, or ``None`` if it isn't in the organization."""
        index = self.index_of(project_id)
        return None if index is None else self._project(index)

    def projects(self, folder_id=None):
        """Every project profile, or those in ``folder_id``, in index order."""
        profiles = (self._project(i) for i in range(self.n_projects))
        if folder_id is None:
            return list(profiles)
        return [p for p in profiles if p.folder_id == folder_id]

    def folder_of(self, index):
        return self.folder_ids[index % len(self.folder_ids)]

    # --- generation ---

    def _build_project(self, index):
        seed, project_id = self.seed, self.project_id(index)
        rng = _rng(seed, "project", index)

        denied = _chance(rng, self.denied_fraction)
        # Size class: most projects are small; a few are big (they dominate the findings).
        size = rng.choices(["empty", "small", "medium", "large"], weights=[25, 45, 22, 8])[0]
        vm_count = {"empty": 0, "small": rng.randint(1, 3), "medium": rng.randint(3, 8), "large": rng.randint(8, 25)}[size]
        zones = rng.sample(ZONES, k=min(len(ZONES), 1 if size in ("empty", "small") else 2 if size == "medium" else 3))

        vms = []
        for v in range(vm_count):
            gke = _chance(rng, 0.25)
            vms.append(Vm(
                name=(f"gke-cluster-1-pool-{v}" if gke else f"vm-{v}"),
                zone=rng.choice(zones),
                external_ip=(not gke) and _chance(rng, 0.35),
                in_mig=gke or _chance(rng, 0.3),
                gke=gke,
                os_reporting=_chance(rng, 0.55),
            ))

        bucket_count = {"empty": rng.randint(0, 1), "small": rng.randint(0, 2), "medium": rng.randint(1, 4), "large": rng.randint(3, 8)}[size]
        buckets = tuple(Bucket(
            name=f"{project_id}-bucket-{b}",
            public=_chance(rng, 0.06),
            ubla=_chance(rng, 0.7),
            versioning=_chance(rng, 0.4),
        ) for b in range(bucket_count))

        primitive = []
        if _chance(rng, 0.35):
            for _ in range(rng.randint(1, 3)):
                member = rng.choice(PRIMITIVE_MEMBERS)
                primitive.append((rng.choice(["roles/owner", "roles/editor"]), member % project_id if "%s" in member else member))

        service_accounts = []
        for s in range(rng.randint(1, 4)):
            keys = tuple(rng.choice([5, 40, 120, 400]) for _ in range(rng.randint(0, 2)))
            service_accounts.append(ServiceAccount(f"sa-{s}@{project_id}.iam.gserviceaccount.com", keys))

        rule_count = rng.randint(3, 8) if not (size == "large" and _chance(rng, 0.3)) else rng.randint(151, 180)
        firewall_rules = tuple((f"fw-rule-{r}", r == 0 and _chance(rng, 0.2), _chance(rng, 0.1)) for r in range(rule_count))

        subnets = tuple((f"subnet-{region}", region, _chance(rng, 0.6)) for region in sorted({'-'.join(z.split('-')[:-1]) for z in zones}))
        hot_quotas = tuple((rng.choice(REGIONS), rng.choice(QUOTA_METRICS), 85 + rng.randint(0, 14), 100)
                           for _ in range(1 if _chance(rng, 0.08) else 0))

        sql_instances = tuple(SqlInstance(
            name=f"sql-{i}", public_ip=_chance(rng, 0.5), require_ssl=_chance(rng, 0.4), zonal=_chance(rng, 0.6),
            backups=_chance(rng, 0.7), pitr=_chance(rng, 0.5), retained_backups=rng.choice([7, 14, 30, 60]),
        ) for i in range(rng.randint(1, 2) if (size != "empty" and _chance(rng, 0.12)) else 0))

        gke_clusters = tuple(GkeCluster(
            name=f"cluster-{c}", location=rng.choice(zones), release_channel=_chance(rng, 0.6),
            node_pools=(("default-pool", _chance(rng, 0.7)), ("spot-pool", _chance(rng, 0.5))),
            recommendations=tuple(["Upgrade to a supported GKE version."] if _chance(rng, 0.3) else []),
        ) for c in range(1 if (any(vm.gke for vm in vms) and _chance(rng, 0.8)) else 0))

        alert_filters = []
        if _chance(rng, 0.5):
            alert_filters.append("serviceruntime.googleapis.com/quota")
        if sql_instances and _chance(rng, 0.5):
            alert_filters.append("cloud_sql")
        if gke_clusters and _chance(rng, 0.5):
            alert_filters.append("gke_cluster")

        cost_recommendations = {}
        for vm in vms:
            if vm.gke:
                continue
            if _chance(rng, 0.15):
                cost_recommendations.setdefault(("VM Rightsizing", vm.zone), []).append(
                    (vm.name, "CHANGE_MACHINE_TYPE", "Save cost by changing machine type from n1-standard-4 to e2-standard-2.", rng.randint(8, 90)))
            if _chance(rng, 0.08):
                cost_recommendations.setdefault(("Low Utilization VMs", vm.zone), []).append(
                    (vm.name, "STOP_VM", f"VM '{vm.name}' has had low utilization for 14 days; consider stopping it.", rng.randint(20, 200)))
            if _chance(rng, 0.06):
                cost_recommendations.setdefault(("Idle Persistent Disks", vm.zone), []).append(
                    (f"{vm.name}-data", "SNAPSHOT_AND_DELETE_DISK", "Snapshot and delete the idle persistent disk.", rng.randint(2, 40)))
        addresses_regions = tuple(sorted({'-'.join(z.split('-')[:-1]) for z in zones})) if _chance(rng, 0.4) else ()
        for region in addresses_regions:
            if _chance(rng, 0.5):
                cost_recommendations.setdefault(("Unassociated IPs", region), []).append(
                    (f"ip-{region}", "DELETE_ADDRESS", "Delete the unassociated static IP address.", rng.randint(5, 10)))
        for sql in sql_instances:
            if _chance(rng, 0.3):
                cost_recommendations.setdefault(("Idle Cloud SQL Instances", subnets[0][1] if subnets else REGIONS[0]), []).append(
                    (sql.name, "STOP_SQL_INSTANCE", f"Cloud SQL instance '{sql.name}' is idle.", rng.randint(30, 300)))

        network_insights = {}
        for subnet_name, region, _ in subnets:
            if _chance(rng, 0.3):
                network_insights.setdefault(("VPC IP Address Utilization", region), []).append(
                    ("ip", {"network": "projects/%s/global/networks/vpc-main" % project_id,
                            "subnet": f"projects/{project_id}/regions/{region}/subnetworks/{subnet_name}",
                            "prefix": "10.%d.0.0/24" % rng.randint(0, 250), "ratio": round(rng.uniform(0.75, 0.99), 2)}))
        for cluster in gke_clusters:
            if _chance(rng, 0.5):
                network_insights.setdefault(("GKE Service Account", cluster.location), []).append(
                    ("sa", {"cluster_uri": f"projects/{project_id}/locations/{cluster.location}/clusters/{cluster.name}"}))
        if forwarding := (tuple(sorted({'-'.join(z.split('-')[:-1]) for z in zones})) if (size in ("medium", "large") and _chance(rng, 0.5)) else ()):
            for region in forwarding:
                if _chance(rng, 0.3):
                    network_insights.setdefault(("Load Balancer Health", region), []).append(
                        ("general", {"description": f"Load balancer in {region} has unhealthy backends."}))

        recent_changes = tuple(f"IAM policy of project {project_id} changed: {rng.choice(['added', 'removed'])} roles/editor for {rng.choice(PRIMITIVE_MEMBERS[:3])}"
                               for _ in range(rng.randint(1, 2) if _chance(rng, 0.2) else 0))
        mig_zones = tuple(sorted({vm.zone for vm in vms if vm.in_mig and not vm.gke}))

        return ProjectProfile(
            index=index, project_id=project_id, display_name=f"Synthetic Project {index}",
            folder_id=self.folder_of(index), denied=denied, osconfig_disabled=_chance(rng, 0.05),
            vms=tuple(vms), buckets=buckets, primitive_bindings=tuple(primitive),
            service_accounts=tuple(service_accounts), firewall_rules=firewall_rules,
            has_default_vpc=_chance(rng, 0.5), subnets=subnets, hot_quotas=hot_quotas,
            sql_instances=sql_instances, gke_clusters=gke_clusters, alert_filters=tuple(alert_filters),
            addresses_regions=addresses_regions, forwarding_rule_regions=forwarding,
            cost_recommendations=cost_recommendations, network_insights=network_insights,
            recent_changes=recent_changes, mig_zones=mig_zones,
            single_region_snapshots=rng.randint(0, 3) if vms else 0,
        )

    # --- organization-level data ---

    def org_iam_bindings(self):
        return [
            {"role": "roles/owner", "members": ["user:cto@example.com", "group:cloud-admins@example.com"]},
            {"role": "roles/resourcemanager.organizationAdmin", "members": ["group:cloud-admins@example.com"]},
            {"role": "roles/viewer", "members": ["domain:example.com"]},
        ]

    def org_policies(self, resource):
        """``listOrgPolicies`` for ``organizations/...``, ``folders/...`` or ``projects/...``."""
        if resource.startswith("organizations/"):
            return [{"constraint": f"constraints/{cid}", "booleanPolicy": {"enforced": enforced}}
                    for cid, enforced in ORG_POLICY_CONSTRAINTS.items()]
        rng = _rng(self.seed, "orgpolicy", resource)
        if _chance(rng, 0.3):  # some folders/projects override one constraint
            cid = rng.choice(list(ORG_POLICY_CONSTRAINTS))
            return [{"constraint": f"constraints/{cid}", "booleanPolicy": {"enforced": not ORG_POLICY_CONSTRAINTS[cid]}}]
        return []

    def unattended_project_ids(self):
        """Projects the Recommender flags as unattended: every 40th project."""
        return [self.project_id(i) for i in range(0, self.n_projects, 40)]

    def summary(self):
        """Totals over the generated organization (for logs and the load-test report)."""
        profiles = self.projects()
        return {
            "projects": len(profiles),
            "denied_projects": sum(p.denied for p in profiles),
            "vms": sum(len(p.vms) for p in profiles),
            "buckets": sum(len(p.buckets) for p in profiles),
            "sql_instances": sum(len(p.sql_instances) for p in profiles),
            "gke_clusters": sum(len(p.gke_clusters) for p in profiles),
            "zones": sorted({z for p in profiles for z in p.zones}),
        }
