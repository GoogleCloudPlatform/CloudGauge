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
PROJECT_NUMBER_BASE = 300000000000  # project i has number PROJECT_NUMBER_BASE + i

# Google Cloud incidents of the last quarter (Service Health). Every project is impacted by,
# related to, or untouched by each one; the first is still active.
# (id, title, product, location, state, started days ago, ended days ago)
INCIDENTS = (
    ("syn-inc-001", "Elevated error rates with Cloud Run in us-central1", "Cloud Run", "us-central1", "ACTIVE", 1, None),
    ("syn-inc-002", "Cloud SQL connectivity issues in europe-west1", "Cloud SQL", "europe-west1", "CLOSED", 12, 11),
    ("syn-inc-003", "Increased latency for Cloud Storage in asia-south1", "Cloud Storage", "asia-south1", "CLOSED", 38, 38),
    ("syn-inc-004", "GKE control plane unavailable in us-east1", "Google Kubernetes Engine", "us-east1", "CLOSED", 70, 69),
    ("syn-inc-005", "Compute Engine VM creation failures in europe-west2", "Compute Engine", "europe-west2", "CLOSED", 140, 139),  # outside a 90-day window
)
INCIDENT_RELEVANCES = ("IMPACTED", "RELATED", "PARTIALLY_RELATED")
# GKE versions the synthetic ``getServerConfig`` offers (GKE Supported Versions judges clusters against them):
# the supported minors newest first, as the API lists them, two patches each; the REGULAR channel offers the
# newer three. ``GKE_RETIRED_VERSION`` is the minor some clusters still run after it left the lists.
GKE_MINORS = ("1.33", "1.32", "1.31", "1.30")
GKE_CHANNEL_MINORS = GKE_MINORS[:3]
GKE_VERSIONS = tuple(f"{minor}.{patch}-gke.{build}" for minor in GKE_MINORS for patch, build in ((4, 1289000), (1, 1035000)))
GKE_RETIRED_VERSION = "1.29.8-gke.1057000"


def gke_version(minor):
    """The newest offered version of ``minor``."""
    return GKE_VERSIONS[GKE_MINORS.index(minor) * 2]


def gke_cluster_versions(index):
    """``(control plane version, node pool versions)`` of project ``index``'s cluster: most run a current minor
    with one pool a minor behind; one project in ten runs the retired minor, two in ten the oldest supported one."""
    bucket = index % 10
    if bucket == 0:
        return GKE_RETIRED_VERSION, (GKE_RETIRED_VERSION, GKE_RETIRED_VERSION)
    if bucket in (1, 2):
        return gke_version("1.30"), (gke_version("1.30"), GKE_RETIRED_VERSION if bucket == 1 else gke_version("1.30"))
    return gke_version("1.32"), (gke_version("1.32"), gke_version("1.31"))
# Advisory Notifications of the organization: (type, subject, days ago, HTML body, ((attachment name, headers, rows), ...)).
ADVISORY_TYPES = ("NOTIFICATION_TYPE_SECURITY_MSA", "NOTIFICATION_TYPE_SECURITY_PRIVACY_ADVISORY",
                  "NOTIFICATION_TYPE_SENSITIVE_ACTIONS", "NOTIFICATION_TYPE_THREAT_HORIZONS")
ORG_ADVISORIES = (
    ("NOTIFICATION_TYPE_SECURITY_MSA", "Mandatory Service Announcement: Cloud SQL instances must move off TLS 1.0 and 1.1", 20,
     "<p>Google Cloud will stop accepting TLS 1.0 and 1.1 connections to Cloud SQL on the date below.</p>"
     "<p>Action required: update the clients of the instances listed in the attachment.</p>",
     (("affected_instances.csv", ("Project", "Instance", "Region"), (("syn-prod-db", "sql-0", "europe-west1"), ("syn-analytics", "sql-1", "us-central1"))),)),
    ("NOTIFICATION_TYPE_SENSITIVE_ACTIONS", "Sensitive actions were taken in your organization", 5,
     '<div class="report-intro"><p>The following sensitive actions were detected.</p></div>'
     "<h2>Organization policy updated</h2><p>Policy: constraints/iam.allowedPolicyMemberDomains</p><p>Policy action: Updated</p>"
     "<p>This action was taken 4 times</p><p>By: admin@example.com</p><p>By: ops-lead@example.com</p>"
     "<h2>Owner role granted at the organization</h2><p>This action was taken 1 time</p><p>By: admin@example.com</p>", ()),
    ("NOTIFICATION_TYPE_SECURITY_PRIVACY_ADVISORY", "Security advisory: GKE node vulnerability CVE-2026-0101", 60,
     "<p>A vulnerability in the GKE node image allows container escape. Upgrade the node pools listed in the attachment.</p>",
     (("affected_clusters.csv", ("Project", "Cluster", "Location"), (("syn-platform", "cluster-0", "us-central1-a"),)),)),
    ("NOTIFICATION_TYPE_THREAT_HORIZONS", "Threat Horizons Report Q3", 400, "<p>Quarterly threat intelligence.</p>", ()),  # older than a year
)
# The security advisory above, as seen from an affected project (folder and project scans read per project).
PROJECT_ADVISORY = ORG_ADVISORIES[2]

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
    master_version: str
    node_pools: tuple  # (name, auto_upgrade, version)
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
    # v14: Service Health and Advisory Notifications
    servicehealth_disabled: bool = False  # the Service Health API is not enabled (no personalized incidents)
    incident_relevance: dict = field(default_factory=dict)  # incident id -> the project's relevance to it
    advisory_types_disabled: tuple = ()  # notification types turned off in the project's Advisory Notifications settings
    has_project_advisory: bool = False  # the project-level security advisory applies to it

    @property
    def project_number(self):
        return str(PROJECT_NUMBER_BASE + self.index)

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

    def project_number(self, index):
        return str(PROJECT_NUMBER_BASE + index)

    def project_id_for_number(self, number):
        """The project ID of a generated project number, or ``None`` for an unknown number."""
        try:
            index = int(str(number)) - PROJECT_NUMBER_BASE
        except (TypeError, ValueError):
            return None
        return self.project_id(index) if 0 <= index < self.n_projects else None

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

        # Versions come from the project index, not ``rng``: they were added later (v15) and must not shift
        # the attributes drawn after them.
        master_version, (default_version, spot_version) = gke_cluster_versions(index)
        gke_clusters = tuple(GkeCluster(
            name=f"cluster-{c}", location=rng.choice(zones), release_channel=_chance(rng, 0.6), master_version=master_version,
            node_pools=(("default-pool", _chance(rng, 0.7), default_version), ("spot-pool", _chance(rng, 0.5), spot_version)),
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
        osconfig_disabled = _chance(rng, 0.05)
        has_default_vpc = _chance(rng, 0.5)
        single_region_snapshots = rng.randint(0, 3) if vms else 0

        # v14 (drawn last, so the inventory above is the same as before for a given seed)
        servicehealth_disabled = _chance(rng, 0.08)
        incident_relevance = {}
        for incident_id, *_ in INCIDENTS:
            if size != "empty" and _chance(rng, 0.3):
                incident_relevance[incident_id] = rng.choices(INCIDENT_RELEVANCES, weights=[3, 4, 3])[0]
        advisory_types_disabled = ("NOTIFICATION_TYPE_THREAT_HORIZONS",) if _chance(rng, 0.05) else ()
        has_project_advisory = bool(gke_clusters) and _chance(rng, 0.5)

        return ProjectProfile(
            index=index, project_id=project_id, display_name=f"Synthetic Project {index}",
            folder_id=self.folder_of(index), denied=denied, osconfig_disabled=osconfig_disabled,
            vms=tuple(vms), buckets=buckets, primitive_bindings=tuple(primitive),
            service_accounts=tuple(service_accounts), firewall_rules=firewall_rules,
            has_default_vpc=has_default_vpc, subnets=subnets, hot_quotas=hot_quotas,
            sql_instances=sql_instances, gke_clusters=gke_clusters, alert_filters=tuple(alert_filters),
            addresses_regions=addresses_regions, forwarding_rule_regions=forwarding,
            cost_recommendations=cost_recommendations, network_insights=network_insights,
            recent_changes=recent_changes, mig_zones=mig_zones,
            single_region_snapshots=single_region_snapshots,
            servicehealth_disabled=servicehealth_disabled, incident_relevance=incident_relevance,
            advisory_types_disabled=advisory_types_disabled, has_project_advisory=has_project_advisory,
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
