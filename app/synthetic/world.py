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
from dataclasses import dataclass, field, replace

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
# v18: the table carries the constraint's Type, and two list constraints — one the organization configures
# (allowed domains), one nobody sets (resource locations) — so the report's list-policy evaluation is exercised.
BEST_PRACTICES_CSV = """Category,ID,Type,Policy Display Name,Recommended to set *
Networking,,,,
,compute.vmExternalIpAccess,List,Define allowed external IPs for VM instances,Should have
,compute.skipDefaultNetworkCreation,Boolean,Skip default network creation,Should have
Identity,,,,
,iam.disableServiceAccountKeyCreation,Boolean,Disable service account key creation,Must have
,compute.requireOsLogin,Boolean,Require OS Login,Should have
,iam.allowedPolicyMemberDomains,List,Domain restricted sharing,Should have
Storage and Data,,,,
,storage.uniformBucketLevelAccess,Boolean,Enforce uniform bucket-level access,Should have
,sql.restrictPublicIp,Boolean,Restrict Public IP access on Cloud SQL instances,Should have
,gcp.resourceLocations,List,Resource location restriction,Should have
"""
# The list policies the synthetic organization sets (``org_policies``): the external-IP allow list and the domain restriction.
ORG_LIST_POLICIES = {
    "compute.vmExternalIpAccess": {"allValues": "DENY"},
    "iam.allowedPolicyMemberDomains": {"allowedValues": ["C0synthetic"]},
}
# v17: the FinOps and capacity facts. Label keys every synthetic project may carry (COST_ALLOCATION_LABELS names
# them in a synthetic deployment); the machine types the VMs run; the Cloud SQL versions (some in extended
# support); the organization-level IAM recommendation.
LABEL_KEYS = ("cost-center", "environment", "owner")
MACHINE_TYPES = ("e2-medium", "e2-standard-4", "n2-standard-8", "n2-standard-16", "a2-highgpu-1g")
SQL_VERSIONS = ("POSTGRES_17", "POSTGRES_15", "MYSQL_8_0", "MYSQL_5_7", "POSTGRES_12", "SQLSERVER_2019_STANDARD")
ORG_IAM_RECOMMENDATION = ("user:cto@example.com", "roles/owner", None)  # (member, role held, replacement or None to remove)


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
    machine_type: str = "e2-medium"  # v17


@dataclass(frozen=True)
class Bucket:
    name: str
    public: bool
    ubla: bool
    versioning: bool
    lifecycle: bool = False  # v17: has lifecycle rules
    autoclass: bool = False  # v17


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
    database_version: str = "POSTGRES_17"  # v17


@dataclass(frozen=True)
class GkeCluster:
    name: str
    location: str
    release_channel: bool
    master_version: str
    node_pools: tuple  # (name, auto_upgrade, version)
    recommendations: tuple


@dataclass(frozen=True)
class GkeHardening:
    """v17.1: a cluster's security posture, as the Asset Inventory resource shows it (``provider._cluster_asset``)."""
    autopilot: bool
    workload_identity: bool  # the cluster has a workload pool
    gke_metadata_pools: tuple  # per node pool: True = GKE_METADATA, False = GCE metadata
    default_service_account: bool  # nodes run as the Compute Engine default account
    privileged_node_account: bool  # the node account holds roles/editor on the project
    cloud_platform_scope: bool
    public_endpoint: bool
    authorized_networks: bool
    open_authorized_networks: bool  # 0.0.0.0/0 among the authorized networks
    legacy_abac: bool
    client_certificate: bool
    private_nodes: bool
    network_policy: bool
    shielded_nodes: bool
    secure_boot: bool
    cos_image: bool
    binary_authorization: bool
    security_posture: bool
    vulnerability_scanning: bool
    secrets_encryption: bool
    workload_logs: bool
    ctd_enabled: bool  # Container Threat Detection, effective state


@dataclass(frozen=True)
class GkeOperations:
    """v18.2: what the upgrade-readiness and observability rules read from a cluster asset (``provider._cluster_asset``) and its budgets."""
    maintenance_window: bool
    exclusion: bool  # an active NO_MINOR_OR_NODE_UPGRADES exclusion ending in two weeks
    notifications: str  # "off" | "partial" (a filter without security bulletins) | "on"
    max_unavailable: tuple  # per node pool: maxUnavailable (0 = the default, no row)
    lagging_pool: bool  # the first node pool two minors behind the control plane
    integrity_monitoring: bool
    intranode_visibility: bool
    system_metrics: bool
    control_plane_metrics: bool
    managed_prometheus: bool
    dns_cache: bool
    pdbs: tuple  # (namespace, name, kind): kind in blocking / exhausted / healthy / system


@dataclass(frozen=True)
class NetworkEdge:
    """v18.3: what the network-edge rules read from a project's ``vpc-main`` and its edge (``provider._edge_assets``)."""
    flow_logs: tuple  # per subnet (the profile's order): flow logs on
    mtu: int  # of vpc-main: 1460 or 1500
    peer_index: int  # -1: no peering; else the project whose vpc-main this one peers with
    peering_active: bool  # the other side peered back
    nat: str  # "none" | "default" (logging off, static 64 ports) | "tuned"
    vpn: str  # "none" | "ha-one" (one tunnel on interface 0, not established) | "ha-two" (both interfaces, established) | "classic"
    interconnect: str  # "none" | "single" (one attachment) | "redundant" (two, in two availability domains)
    lb: str  # "none" | "http" (HTTP-only, no Cloud Armor, logging off) | "https-weak" (no SSL policy) | "https-modern"
    dns_zone: str  # "none" | "plain" (public, DNSSEC off) | "signed" | "rsasha1"
    dns_logging: bool  # a DNS policy with logging on vpc-main
    firewall_policy: bool  # a network firewall policy with an open tcp:22 rule, attached to vpc-main
    legacy_network: bool  # a legacy (subnet-less) network besides vpc-main


@dataclass(frozen=True)
class DataGovernance:
    """v18.4: what the data-governance rules read (``provider._governance_assets``)."""
    datasets: tuple  # (dataset id, time-travel hours, public)
    sql_flags: str  # "bare" (engine defaults) | "pack" (the CIS flags set)
    alloydb: str  # "none" | "zonal-bare" (zonal, backups off, public IP, TLS not enforced) | "regional-good"
    kms: str  # "none" | "unrotated" | "rotated"
    kms_role_separation: bool  # a user holding both cloudkms.admin and cryptoKeyEncrypterDecrypter on the project
    api_keys: tuple  # (display name, restricted, age in days)


@dataclass(frozen=True)
class Posture:
    """v18.5: what the VM and identity rules read (``provider._posture_assets``, the IAM-policy listing, the service-account insights)."""
    vm_accounts: tuple  # per VM, in ``vms`` order: "dedicated" | "default" | "default-full" (the default account with cloud-platform)
    vm_loose: tuple  # per VM: the flags set from ("serial", "ipfwd", "no-secure-boot", "no-shielded", "oslogin-off")
    project_oslogin: bool  # enable-oslogin=TRUE in the project's common instance metadata
    project_ssh_keys: bool  # project-wide ssh-keys in the common instance metadata
    admin_sa_roles: tuple  # (role, member): administrative roles held by service accounts in the project's IAM policy
    separation_member: str  # a principal holding iam.serviceAccountAdmin and iam.serviceAccountUser on the project ("" for none)
    external_members: tuple  # (role, member): principals outside example.com in the project's IAM policy
    unused_accounts: tuple  # (email, days since the last authentication, or None for never): the recommender's SERVICE_ACCOUNT_USAGE insights


@dataclass(frozen=True)
class Serverless:
    """v18.6: what the serverless and edge rules read (``provider._serverless_assets``, the Cloud Run, Functions and Compute handlers, the
    public-principal IAM search, the repository and service searches)."""
    services: tuple  # (name, exposure, account): exposure "iam" | "public-binding" | "public-setting" | "iap" | "internal" | "behind-lb" | "behind-lb-locked"; account "dedicated" | "default"
    job_account: str  # "" (no job) | "dedicated" | "default"
    function: str  # "none" | "gen1-public" | "gen1-internal" | "gen2"
    armor: str  # the content of the edge load balancer's Cloud Armor policy (when it has one): "legacy" | "empty" | "preview" | "modern"
    certificate: str  # the edge HTTPS proxy's certificate: "none" | "fine" | "expiring" | "expired" | "managed-failed"
    repositories: int  # Docker repositories in Artifact Registry
    scanning: bool  # Artifact Analysis (container scanning) enabled in the project


@dataclass(frozen=True)
class Privileges:
    """v18.7: what the folder, grant, secret and custom-role rules read (``provider._secret_results``, the IAM-policy searches, the IAM roles,
    PAM and deny-policy handlers)."""
    secret_roles: tuple  # (role, member): resource-wide secret roles in the project's IAM policy
    secrets: tuple  # (name, kind): kind "fresh" | "stale" | "rotated" | "regional" | "empty"
    custom_role: str  # "" | "powers-held" | "powers-dormant" | "retired-bound": a custom role defined on the project
    pam: str  # "" (PAM not enabled) | "approved" | "unapproved" | "unapproved-standing": an entitlement on the project


@dataclass(frozen=True)
class CostLevers:
    """v18.8: what the log, serverless and lifecycle cost rules read (the Logging, Monitoring, Compute, Cloud Run and VPC Access handlers,
    the bucket stubs) and the scale of the project's spend in the synthetic billing export (``SyntheticOrg.daily_spend``)."""
    log_retention: int  # retention days of the _Default log bucket: 30 (the included days) or more
    audit_bucket: bool  # a locked "audit" log bucket kept 400 days
    flow_sampling: tuple  # per subnet (the profile's order): the flow-log sampling rate where flow logs are on
    flow_verbose: bool  # the sampled subnets also keep all metadata at a 5-second interval
    log_volume_gib: float  # the project's 30-day log volume
    debug_share: float  # the DEBUG share of it
    debug_exclusion: bool  # the _Default sink drops DEBUG entries
    connector: str  # "" | "idle" | "used": a Serverless VPC Access connector, the first service routed through it when used
    cross_region_sql: bool  # the first service names a Cloud SQL instance in another region
    pruned_buckets: tuple  # the versioned buckets whose lifecycle deletes noncurrent versions
    spend_scale: float  # multiplies the project's daily spend


@dataclass(frozen=True)
class Observability:
    """v18.9: what the log-pipeline and alerting rules read (the Logging sinks, buckets and views handlers; the Monitoring channels, uptime
    checks, services and SLOs; the topic listing and the IAM searches for the sink writers and the notification agent)."""
    sink: str  # "" | "narrow" | "complete" | "topic" | "dataset-gone": the project's customer sink — activity alone into a 30-day unlocked bucket;
    #            every audit log into the locked 400-day audit bucket; into a Pub/Sub topic its writer cannot publish to; into a dataset that is gone
    default_disabled: bool  # the _Default sink is disabled (the project's logs are discarded)
    analytics: bool  # the _Default bucket is upgraded to Log Analytics
    open_view: bool  # the _Default view's filter no longer excludes the Data Access logs
    channels: tuple  # the project's notification channels: "email" | "email-unverified" | "disabled" | "pubsub" | "pubsub-ungranted" | "pubsub-gone"
    policy_channels: tuple  # per alert policy (alert_filters' order): the indexes into `channels` it notifies — () fires to nobody
    mql: bool  # the first alert policy's condition is written in MQL
    uptime: str  # "" | "silent" | "alerted": an uptime check on the external load balancer's address, without or with an alert policy
    slo: str  # "" | "silent" | "alerted": an SLO on the first Cloud Run service, without or with a burn-rate policy


@dataclass(frozen=True)
class Findings:
    """v19: what the SCC and vulnerability rules read (the SCC v2 and Security Center Management REST answers, VM Manager's reports)."""
    scc: str  # "" | "misconfig" | "critical" | "threats" | "mixed": the project's active findings
    muted: int  # muted findings, which the filter must leave out
    detectors: str  # "inherited" (every service effective DISABLED) | "standard" (SHA on, the threat detectors off) | "premium" (all on)
    vm_manager: bool  # full VM Manager on: vulnerability reports exist for the project's VMs
    cves: tuple  # per VM (the profile's order): (critical CVEs with a fix, high CVEs with a fix, other CVEs)


@dataclass(frozen=True)
class Detection:
    """v19.1: the Admin Activity entries the detective rules read, and Google's own that they must leave out (``entries.list``)."""
    user_exec: int  # pods.exec.create by a user from an office address (Informational)
    sa_exec: int  # pods.exec.create by a customer service account from an external address (Action Required)
    admin_binding: str  # "" | "user" | "sa": a clusterrolebinding to cluster-admin created by a user from inside, or by a service account from outside
    google_daemonset: bool  # the Kubernetes Threat Detection agent creating its DaemonSet in kube-system (left out)
    sa_key: int  # CreateServiceAccountKey by a customer service account from an external address (Action Required)
    factory_iam: int  # SetIamPolicy by the project-factory account from a private address (Investigation)
    google_churn: int  # SetIamPolicy by service-agent-manager@system (left out)


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
    multi_region_snapshots: int = 0  # v16.1: snapshots in asia/us/eu, which the resilience check passes
    # v14: Service Health and Advisory Notifications
    servicehealth_disabled: bool = False  # the Service Health API is not enabled (no personalized incidents)
    incident_relevance: dict = field(default_factory=dict)  # incident id -> the project's relevance to it
    advisory_types_disabled: tuple = ()  # notification types turned off in the project's Advisory Notifications settings
    has_project_advisory: bool = False  # the project-level security advisory applies to it
    # v17: FinOps and capacity
    labels: dict = field(default_factory=dict)  # the project's labels (a subset of LABEL_KEYS, with values)
    old_snapshots: tuple = ()  # (name, age in days): snapshots older than the default SNAPSHOT_MAX_AGE_DAYS
    orphan_snapshots: tuple = ()  # names of snapshots whose source disk is gone
    reservations: tuple = ()  # (zone, machine type, count, in use)
    commitments: tuple = ()  # (region, plan, vCPUs, memory GB, days until it ends, auto-renew)
    capacity_events: tuple = ()  # (zone, machine type, kind: "stockout" | "quota", days ago, count)
    iam_recommendations: tuple = ()  # (member, role held, replacement role or None to remove)
    gpu_quota: tuple = ()  # (region, metric, usage, limit): an accelerator quota near its limit
    quota_recommendation: bool = False  # the quota recommender suggests an increase
    future_reservation: bool = False  # a future reservation in the project's first zone
    # v17.1: the SSRF chain
    gke_hardening: dict = field(default_factory=dict)  # cluster name -> GkeHardening
    impersonation_bindings: tuple = ()  # (level, resource, role, member): level is 'project' or 'service account' (resource = the target email)
    custom_role_bindings: tuple = ()  # (role name, member): a custom role on the project that carries token permissions
    etd_enabled: bool = True  # Event Threat Detection, effective state in the project
    data_access_logs: bool = False  # DATA_READ/DATA_WRITE audit logs for container.googleapis.com
    gke_pool_zones: dict = field(default_factory=dict)  # v17.3: cluster name -> per node pool, the zones its nodes live in
    # v18: the facts the revalidated legacy checks read
    stopped_vms: tuple = ()  # VMs that are TERMINATED: their access config stays, the ephemeral address is released
    disabled_key_accounts: tuple = ()  # service accounts whose oldest user-managed key is disabled
    sql_open_networks: tuple = ()  # Cloud SQL instances with 0.0.0.0/0 among their authorized networks
    pap_enforced_buckets: tuple = ()  # public buckets whose Public Access Prevention is enforced (the binding is dormant)
    # v18.1: what the loose rules read
    unprotected_buckets: tuple = ()  # buckets with soft delete turned off (a row when nothing else protects them)
    sink_buckets: tuple = ()  # buckets a log sink writes to (versioning expected)
    retention_buckets: tuple = ()  # buckets under a retention policy (protected by it; never asked for versioning)
    proxy_subnet: bool = False  # a proxy-only subnet (never a PGA row)
    gke_auto_repair: dict = field(default_factory=dict)  # cluster name -> per node pool, auto-repair on
    project_audit_configs: bool = False  # the project turns Data Access logs on for every service
    project_contact: bool = False  # the project has an Essential Contact of its own (SUSPENSION, LEGAL)
    gke_operations: dict = field(default_factory=dict)  # v18.2: cluster name -> GkeOperations
    network_edge: NetworkEdge = None  # v18.3
    data_governance: DataGovernance = None  # v18.4
    posture: Posture = None  # v18.5
    serverless: Serverless = None  # v18.6
    privileges: Privileges = None  # v18.7
    cost_levers: CostLevers = None  # v18.8
    observability: Observability = None  # v18.9
    findings: Findings = None  # v19
    detection: Detection = None  # v19.1

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

        # v16.1 (drawn last, for the same reason): snapshots kept in a multi-region, which pass the resilience check
        multi_region_snapshots = rng.randint(0, 2) if vms else 0

        # v17 (drawn last, for the same reason): the FinOps and capacity facts. Fields of the VMs, buckets and SQL
        # instances built above are added with ``replace`` so the earlier draws stay where they were.
        labels = {key: value for key, value in (("cost-center", f"cc-{rng.randint(100, 999)}"), ("environment", rng.choice(["prod", "dev", "test"])),
                                                ("owner", rng.choice(["platform", "data", "web"]))) if _chance(rng, 0.8)}
        vms = [replace(vm, machine_type="e2-medium" if vm.gke else rng.choices(MACHINE_TYPES, weights=[4, 3, 3, 2, 1])[0]) for vm in vms]
        buckets = tuple(replace(bucket, lifecycle=_chance(rng, 0.5), autoclass=_chance(rng, 0.2)) for bucket in buckets)
        sql_instances = tuple(replace(sql, database_version=rng.choices(SQL_VERSIONS, weights=[3, 3, 2, 1, 1, 1])[0]) for sql in sql_instances)
        old_snapshots = tuple((f"snap-old-{i}", rng.randint(120, 400)) for i in range(rng.randint(0, 2) if vms else 0))
        orphan_snapshots = ("snap-orphan-0",) if vms and _chance(rng, 0.15) else ()
        reservations = ()
        if vms and size in ("medium", "large") and _chance(rng, 0.3):
            count = rng.randint(2, 4)
            reservations = ((rng.choice(zones), "e2-standard-4", count, rng.randint(1, count)),)
        commitments = ()
        if size in ("medium", "large") and _chance(rng, 0.25):
            commitments = (("-".join(zones[0].split("-")[:-1]), rng.choice(["TWELVE_MONTH", "THIRTY_SIX_MONTH"]), rng.choice([8, 16, 32]),
                            rng.choice([32, 64, 128]), rng.randint(30, 400), _chance(rng, 0.3)),)
        capacity_events = ()
        if vms and _chance(rng, 0.12):
            capacity_events = ((rng.choice(zones), rng.choice(["n2-standard-8", "a2-highgpu-1g"]), rng.choice(["stockout", "stockout", "quota"]),
                                rng.randint(1, 25), rng.randint(1, 6)),)
        iam_recommendations = ()
        if primitive and _chance(rng, 0.5):
            role, member = primitive[0]
            iam_recommendations = ((member, role, "roles/viewer" if role == "roles/editor" else None),)
        gpu_quota = ((rng.choice(REGIONS), "NVIDIA_T4_GPUS", 96 + rng.randint(0, 4), 100),) if _chance(rng, 0.06) else ()
        quota_recommendation = _chance(rng, 0.08)
        future_reservation = bool(vms) and size == "large" and _chance(rng, 0.2)

        # v17.1 (drawn after every v17 draw): the clusters' security posture, who may become which service account,
        # threat detection and audit logging. Fictional names only.
        gke_hardening = {}
        for cluster in gke_clusters:
            autopilot = _chance(rng, 0.2)
            workload_identity = autopilot or _chance(rng, 0.55)
            gke_hardening[cluster.name] = GkeHardening(
                autopilot=autopilot, workload_identity=workload_identity,
                gke_metadata_pools=tuple(workload_identity and _chance(rng, 0.8) for _ in cluster.node_pools),
                default_service_account=_chance(rng, 0.5), privileged_node_account=_chance(rng, 0.5), cloud_platform_scope=_chance(rng, 0.4),
                public_endpoint=_chance(rng, 0.7), authorized_networks=_chance(rng, 0.6), open_authorized_networks=_chance(rng, 0.15),
                legacy_abac=_chance(rng, 0.05), client_certificate=_chance(rng, 0.1), private_nodes=_chance(rng, 0.6), network_policy=_chance(rng, 0.5),
                shielded_nodes=_chance(rng, 0.8), secure_boot=_chance(rng, 0.7), cos_image=_chance(rng, 0.9), binary_authorization=_chance(rng, 0.2),
                security_posture=_chance(rng, 0.6), vulnerability_scanning=_chance(rng, 0.3), secrets_encryption=_chance(rng, 0.2),
                workload_logs=_chance(rng, 0.85), ctd_enabled=_chance(rng, 0.5))
        impersonation_bindings = []
        if service_accounts and _chance(rng, 0.08):  # the dangerous one: token minting granted on the whole project to an account
            impersonation_bindings.append(('project', project_id, 'roles/iam.serviceAccountTokenCreator', f'serviceAccount:{service_accounts[0].email}'))
        if service_accounts and _chance(rng, 0.2):  # a person who may mint tokens for one account (Investigation)
            impersonation_bindings.append(('service account', service_accounts[-1].email, 'roles/iam.serviceAccountTokenCreator', 'user:ops-lead@example.com'))
        if len(service_accounts) >= 2 and _chance(rng, 0.1):  # an account-to-account chain
            impersonation_bindings.append(('service account', service_accounts[0].email, 'roles/iam.serviceAccountTokenCreator', f'serviceAccount:{service_accounts[1].email}'))
        if service_accounts and gke_clusters and _chance(rng, 0.3):  # Workload Identity for the default Kubernetes account
            impersonation_bindings.append(('service account', service_accounts[0].email, 'roles/iam.workloadIdentityUser', f'serviceAccount:{project_id}.svc.id.goog[default/default]'))
        if service_accounts and _chance(rng, 0.05):  # a principal from outside the organization
            impersonation_bindings.append(('service account', service_accounts[0].email, 'roles/iam.serviceAccountTokenCreator', 'serviceAccount:deploy@outside-example.iam.gserviceaccount.com'))
        if _chance(rng, 0.1):  # act-as for everyone in the project (deploy pipelines often get this)
            impersonation_bindings.append(('project', project_id, 'roles/iam.serviceAccountUser', 'group:deployers@example.com'))
        custom_role_bindings = ((f'projects/{project_id}/roles/tokenMinter', 'serviceAccount:ci@example-ci.iam.gserviceaccount.com'),) if _chance(rng, 0.04) else ()
        etd_enabled = _chance(rng, 0.6)
        data_access_logs = _chance(rng, 0.25)

        # Cost recommendations of the v17 recommenders (merged after the draws, so the dict above is as it was).
        extra_recommendations = {}
        if vms and _chance(rng, 0.1):
            extra_recommendations[("Idle Images", "global")] = [(f"{project_id}-image-0", "DELETE_IMAGE", "Delete the idle custom image.", rng.randint(1, 15))]
        if buckets and _chance(rng, 0.1):
            extra_recommendations[("Cloud Storage Soft Delete", "global")] = [
                (buckets[0].name, "DISABLE_SOFT_DELETE", f"Disable soft delete on bucket '{buckets[0].name}': its objects are rarely deleted.", rng.randint(2, 30))]
        if size == "large" and _chance(rng, 0.3):
            extra_recommendations[("BigQuery Slot Commitments", "US")] = [(f"{project_id}-slots", "PURCHASE_COMMITMENT", "Purchase a 100-slot annual commitment in US.", rng.randint(200, 900))]
        if size in ("medium", "large") and _chance(rng, 0.2):
            region = "-".join(zones[0].split("-")[:-1])
            extra_recommendations[("Cloud Run Cost", region)] = [(f"svc-{project_id}", "CPU_ALLOCATION", "Allocate CPU only during request processing for the service.", rng.randint(5, 60))]
        if size in ("medium", "large") and _chance(rng, 0.25):
            region = "-".join(zones[0].split("-")[:-1])
            extra_recommendations[("Resource-Based Commitment Recommendations", region)] = [
                (f"{region}-cud", "PURCHASE_COMMITMENT", f"Purchase a 1 year new standard CUD for 16 vCPUs and 64 GB in {region}.", rng.randint(100, 600))]
        for sql in sql_instances:
            if _chance(rng, 0.3):
                region = subnets[0][1] if subnets else REGIONS[0]
                extra_recommendations.setdefault(("Overprovisioned Cloud SQL Instances", region), []).append(
                    (sql.name, "CHANGE_MACHINE_TYPE", f"Cloud SQL instance '{sql.name}' is overprovisioned: move to a smaller tier.", rng.randint(40, 400)))
        cost_recommendations = {**cost_recommendations, **extra_recommendations}

        # v17.3 (drawn last, so earlier seeds keep their organizations): the zones of each node pool. Synthetic clusters
        # are zonal (their location is a zone); a pool spans the region's three zones or sits in the cluster's one.
        gke_pool_zones = {}
        for cluster in gke_clusters:
            region = "-".join(cluster.location.split("-")[:-1])
            gke_pool_zones[cluster.name] = tuple(
                (cluster.location,) if _chance(rng, 0.4) else (f"{region}-a", f"{region}-b", f"{region}-c") for _ in cluster.node_pools)

        # v18 (drawn last, for the same reason): what the revalidated legacy checks read.
        stopped_vms = tuple(vm.name for vm in vms if vm.external_ip and _chance(rng, 0.3))
        disabled_key_accounts = tuple(sa.email for sa in service_accounts if sa.key_ages_days and _chance(rng, 0.3))
        sql_open_networks = tuple(sql.name for sql in sql_instances if sql.public_ip and _chance(rng, 0.3))
        pap_enforced_buckets = tuple(bucket.name for bucket in buckets if bucket.public and _chance(rng, 0.4))

        # v18.1 (drawn last, for the same reason): what the loose rules read.
        unprotected_buckets = tuple(bucket.name for bucket in buckets if not bucket.versioning and _chance(rng, 0.25))
        sink_buckets = tuple(bucket.name for bucket in buckets if _chance(rng, 0.1))
        retention_buckets = tuple(bucket.name for bucket in buckets if _chance(rng, 0.1) and not bucket.versioning)  # the two exclude each other
        proxy_subnet = size in ("medium", "large") and _chance(rng, 0.4)
        gke_auto_repair = {cluster.name: tuple(_chance(rng, 0.8) for _ in cluster.node_pools) for cluster in gke_clusters}
        project_audit_configs = _chance(rng, 0.15)
        project_contact = _chance(rng, 0.2)
        # v18.2 (drawn last again): upgrade readiness and observability, per cluster.
        gke_operations = {}
        for cluster in gke_clusters:
            pdbs = []
            if _chance(rng, 0.5):
                pdbs.append(("kube-system", "kube-dns-pdb", "system"))
            if _chance(rng, 0.3):
                pdbs.append(("payments", "api-pdb", "blocking"))
            if _chance(rng, 0.2):
                pdbs.append(("web", "frontend-pdb", "exhausted"))
            if _chance(rng, 0.6):
                pdbs.append(("web", "worker-pdb", "healthy"))
            gke_operations[cluster.name] = GkeOperations(
                maintenance_window=_chance(rng, 0.5), exclusion=_chance(rng, 0.15),
                notifications=rng.choice(["off", "off", "partial", "on"]),
                max_unavailable=tuple(1 if _chance(rng, 0.25) else 0 for _ in cluster.node_pools), lagging_pool=_chance(rng, 0.15),
                integrity_monitoring=_chance(rng, 0.85), intranode_visibility=_chance(rng, 0.4), system_metrics=_chance(rng, 0.92),
                control_plane_metrics=_chance(rng, 0.3), managed_prometheus=_chance(rng, 0.6), dns_cache=_chance(rng, 0.4), pdbs=tuple(pdbs))

        # v18.3 (drawn last again): the network edge.
        network_edge = NetworkEdge(
            flow_logs=tuple(_chance(rng, 0.4) for _ in subnets), mtu=rng.choice([1460, 1460, 1500]),
            peer_index=(index + 1) % self.n_projects if self.n_projects > 1 and _chance(rng, 0.35) else -1, peering_active=_chance(rng, 0.8),
            nat=rng.choice(["none", "default", "default", "tuned"]), vpn=rng.choice(["none", "none", "ha-one", "ha-two", "classic"]),
            interconnect=rng.choice(["none", "none", "none", "single", "redundant"]), lb=rng.choice(["none", "none", "http", "https-weak", "https-modern"]),
            dns_zone=rng.choice(["none", "none", "plain", "signed", "rsasha1"]), dns_logging=_chance(rng, 0.3),
            firewall_policy=_chance(rng, 0.15), legacy_network=_chance(rng, 0.05))

        # v18.4 (drawn last again): data governance.
        datasets = tuple((f"ds_{i}", rng.choice([168, 168, 48]), _chance(rng, 0.1)) for i in range(rng.choice([0, 1, 2])))
        data_governance = DataGovernance(
            datasets=datasets, sql_flags=rng.choice(["bare", "bare", "pack"]), alloydb=rng.choice(["none", "none", "none", "zonal-bare", "regional-good"]),
            kms=rng.choice(["none", "none", "unrotated", "rotated"]), kms_role_separation=_chance(rng, 0.2),
            api_keys=tuple((f"key-{i}", _chance(rng, 0.4), rng.choice([10, 120])) for i in range(rng.choice([0, 0, 1, 2]))))

        # v18.5 (drawn last again): VM posture and identity hygiene.
        number, admin_sa_roles = self.project_number(index), []
        if _chance(rng, 0.3):
            admin_sa_roles.append(("roles/compute.admin", f"serviceAccount:{number}-compute@developer.gserviceaccount.com"))
        if _chance(rng, 0.3):
            admin_sa_roles.append(("roles/storage.admin", f"serviceAccount:app@{project_id}.iam.gserviceaccount.com"))
        if _chance(rng, 0.15):
            admin_sa_roles.append(("roles/iam.securityAdmin", f"serviceAccount:ci@{project_id}.iam.gserviceaccount.com"))
        external_members = []
        if _chance(rng, 0.3):
            external_members.append(("roles/viewer", "user:contractor@partner.example"))
        if _chance(rng, 0.1):
            external_members.append(("roles/logging.viewer", "user:someone@gmail.com"))
        if _chance(rng, 0.1):
            external_members.append(("roles/viewer", "group:ops@acquired.example"))
        if _chance(rng, 0.1):
            external_members.append(("roles/viewer", "deleted:user:gone@example.com?uid=123456789"))
        posture = Posture(
            vm_accounts=tuple(rng.choice(["dedicated", "default", "default", "default-full"]) for _ in vms),
            vm_loose=tuple(tuple(flag for flag in ("serial", "ipfwd", "no-secure-boot", "no-shielded", "oslogin-off") if _chance(rng, 0.1)) for _ in vms),
            project_oslogin=_chance(rng, 0.6), project_ssh_keys=_chance(rng, 0.4), admin_sa_roles=tuple(admin_sa_roles),
            separation_member="user:platform@example.com" if _chance(rng, 0.15) else "", external_members=tuple(external_members),
            unused_accounts=tuple((sa.email, rng.choice([None, 120, 200])) for sa in service_accounts if _chance(rng, 0.3)))

        # v18.6 (drawn last again): serverless and edge exposure.
        exposures = ["iam", "iam", "public-binding", "public-setting", "iap", "internal", "behind-lb", "behind-lb-locked"]
        serverless = Serverless(
            services=tuple((name, rng.choice(exposures), rng.choice(["dedicated", "dedicated", "default"])) for name in ("web", "api", "worker", "admin")[:rng.choice([0, 1, 2, 3])]),
            job_account=rng.choice(["", "", "dedicated", "default"]), function=rng.choice(["none", "none", "gen1-public", "gen1-internal", "gen2"]),
            armor=rng.choice(["legacy", "empty", "preview", "modern", "modern"]), certificate=rng.choice(["none", "fine", "fine", "expiring", "expired", "managed-failed"]),
            repositories=rng.choice([0, 0, 1, 2]), scanning=_chance(rng, 0.3))

        # v18.7 (drawn last again): folders, keys and privileged grants — the project's share (the folders' and the organization's are fixed).
        secret_roles = []
        if _chance(rng, 0.12):
            secret_roles.append(("roles/secretmanager.secretAccessor", f"serviceAccount:app@{project_id}.iam.gserviceaccount.com"))
        if _chance(rng, 0.08):
            secret_roles.append(("roles/secretmanager.admin", "group:platform@example.com"))
        if _chance(rng, 0.03):
            secret_roles.append(("roles/secretmanager.secretAccessor", "allAuthenticatedUsers"))
        privileges = Privileges(
            secret_roles=tuple(secret_roles),
            secrets=tuple((name, rng.choice(["fresh", "fresh", "stale", "rotated", "regional", "empty"])) for name in ("db-password", "api-key", "signing-key")[:rng.choice([0, 0, 1, 2, 3])]),
            custom_role=rng.choice(["", "", "", "powers-held", "powers-dormant", "retired-bound"]),
            pam=rng.choice(["", "", "", "approved", "unapproved", "unapproved-standing"]))

        # v18.8 (drawn last again): the cost levers — log retention and volume, flow-log sampling, a connector, a cross-region database,
        # the versioned buckets that prune, and the project's weight in the synthetic billing export.
        cost_levers = CostLevers(
            log_retention=rng.choice([30, 30, 30, 90, 180, 400]), audit_bucket=_chance(rng, 0.1),
            flow_sampling=tuple(rng.choice([0.5, 0.5, 1.0]) for _ in subnets), flow_verbose=_chance(rng, 0.5),
            log_volume_gib=rng.choice([2.0, 8.0, 20.0, 120.0, 400.0]), debug_share=rng.choice([0.02, 0.02, 0.15, 0.4]), debug_exclusion=_chance(rng, 0.3),
            connector=rng.choice(["", "", "", "idle", "used"]) if serverless.services else rng.choice(["", "", "", "", "idle"]),
            cross_region_sql=bool(serverless.services) and _chance(rng, 0.2),
            pruned_buckets=tuple(bucket.name for bucket in buckets if bucket.versioning and bucket.lifecycle and _chance(rng, 0.6)),
            spend_scale=rng.choice([0.5, 1.0, 1.0, 2.0, 5.0]))

        # v18.9 (drawn last again): the logging pipeline and the alerting — a customer sink in one of four shapes, a disabled _Default sink,
        # Log Analytics, an open default view; channels of every state and which policies reach them, an MQL condition; an uptime check on the
        # external load balancer and an SLO on the first Cloud Run service, each with or without its alert policy.
        channels = tuple(rng.choice(["email", "email", "email-unverified", "disabled", "pubsub", "pubsub-ungranted", "pubsub-gone"]) for _ in range(rng.choice([0, 1, 1, 2, 3])))
        policy_channels = []
        for _ in alert_filters:
            count = min(len(channels), rng.choice([0, 1, 1, 2]))
            policy_channels.append(tuple(sorted(rng.sample(range(len(channels)), count))) if count else ())
        observability = Observability(
            sink=rng.choice(["", "", "", "narrow", "complete", "topic", "dataset-gone"]), default_disabled=_chance(rng, 0.05), analytics=_chance(rng, 0.3), open_view=_chance(rng, 0.1),
            channels=channels, policy_channels=tuple(policy_channels), mql=bool(alert_filters) and _chance(rng, 0.1),
            uptime=rng.choice(["", "silent", "alerted"]) if network_edge.lb != "none" else "",
            slo=rng.choice(["", "", "silent", "alerted"]) if serverless.services else "")

        # v19 (drawn last again): what Security Command Center and VM Manager say about the project.
        findings = Findings(
            scc=rng.choice(["", "", "misconfig", "misconfig", "critical", "threats", "mixed"]), muted=rng.choice([0, 0, 1, 3]),
            detectors=rng.choice(["inherited", "inherited", "standard", "standard", "premium"]), vm_manager=_chance(rng, 0.4),
            cves=tuple((rng.choice([0, 0, 0, 1, 2]), rng.choice([0, 0, 1, 4]), rng.choice([3, 12, 40])) for _ in vms))

        # v19.1 (drawn last again): the week's Admin Activity entries the detective rules read.
        detection = Detection(
            user_exec=rng.choice([0, 0, 2, 5]) if gke_clusters else 0, sa_exec=rng.choice([0, 0, 0, 1]) if gke_clusters else 0,
            admin_binding=rng.choice(["", "", "user", "sa"]) if gke_clusters else "", google_daemonset=bool(gke_clusters) and _chance(rng, 0.5),
            sa_key=rng.choice([0, 0, 0, 1, 3]), factory_iam=rng.choice([0, 1, 1, 4]), google_churn=rng.choice([0, 2, 16]))

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
            single_region_snapshots=single_region_snapshots, multi_region_snapshots=multi_region_snapshots,
            servicehealth_disabled=servicehealth_disabled, incident_relevance=incident_relevance,
            advisory_types_disabled=advisory_types_disabled, has_project_advisory=has_project_advisory,
            labels=labels, old_snapshots=old_snapshots, orphan_snapshots=orphan_snapshots, reservations=reservations,
            commitments=commitments, capacity_events=capacity_events, iam_recommendations=iam_recommendations,
            gpu_quota=gpu_quota, quota_recommendation=quota_recommendation, future_reservation=future_reservation,
            gke_hardening=gke_hardening, impersonation_bindings=tuple(impersonation_bindings), custom_role_bindings=custom_role_bindings,
            etd_enabled=etd_enabled, data_access_logs=data_access_logs, gke_pool_zones=gke_pool_zones,
            stopped_vms=stopped_vms, disabled_key_accounts=disabled_key_accounts, sql_open_networks=sql_open_networks,
            pap_enforced_buckets=pap_enforced_buckets,
            unprotected_buckets=unprotected_buckets, sink_buckets=sink_buckets, retention_buckets=retention_buckets, proxy_subnet=proxy_subnet,
            gke_auto_repair=gke_auto_repair, project_audit_configs=project_audit_configs, project_contact=project_contact,
            gke_operations=gke_operations, network_edge=network_edge, data_governance=data_governance, posture=posture, serverless=serverless, privileges=privileges,
            cost_levers=cost_levers, observability=observability, findings=findings, detection=detection,
        )

    # --- the synthetic billing export (v18.8) ---

    def daily_spend(self, profile, day_offset):
        """``[(service, cost, credit, committed-use credit)]`` of a project on the day ``day_offset`` days before today (1 = yesterday): steady
        per-service costs from the inventory with mild deterministic noise, scaled by the project's ``spend_scale``; a Compute Engine spike
        over the last week in every seventh project, a new BigQuery line in every eleventh, Cloud SQL stopped two weeks ago in every
        thirteenth; sustained-use credits on Compute Engine, committed-use credits where the project holds commitments."""
        index, levers = profile.index, profile.cost_levers
        scale = levers.spend_scale if levers else 1.0
        base = {"Compute Engine": 1.0 * len(profile.vms), "Cloud Storage": 0.05 * len(profile.buckets), "Networking": 0.3 * len(profile.vms),
                "Cloud SQL": 2.5 * len(profile.sql_instances), "Kubernetes Engine": 2.4 * len(profile.gke_clusters)}
        if index % 13 == 2 and day_offset <= 14:
            base["Cloud SQL"] = 0.0
        if index % 7 == 3 and day_offset <= 7:
            base["Compute Engine"] *= 2.5
        if index % 11 == 5 and day_offset <= 7:
            base["BigQuery"] = 12.0
        lines = []
        for service, amount in base.items():
            if amount <= 0:
                continue
            cost = amount * scale * (1 + ((index * 31 + day_offset * 17 + len(service)) % 21 - 10) / 100)
            credit = cud = 0.0
            if service == "Compute Engine":
                cud = -0.3 * cost if profile.commitments else 0.0
                credit = cud if profile.commitments else -0.2 * cost
            lines.append((service, round(cost, 6), round(credit, 6), round(cud, 6)))
        return lines

    # --- organization-level data ---

    def org_iam_bindings(self):
        return [
            {"role": "roles/owner", "members": ["user:cto@example.com", "group:cloud-admins@example.com"]},
            {"role": "roles/resourcemanager.organizationAdmin", "members": ["group:cloud-admins@example.com",
                                                                             "serviceAccount:org-automation@system.gserviceaccount.com"]},  # v18: a Google-managed agent, not a row
            {"role": "roles/viewer", "members": ["domain:example.com"]},
            # v18.7: the whole domain creates projects (Action Required), a finance group holds a billing role at the organization (Investigation),
            # an operations group holds the custom role that writes IAM policies (Custom Roles With IAM Powers).
            {"role": "roles/resourcemanager.projectCreator", "members": ["domain:example.com", "serviceAccount:project-factory@tooling.iam.gserviceaccount.com"]},
            {"role": "roles/billing.user", "members": ["group:finance@example.com"]},
            {"role": f"organizations/{self.org_id}/roles/policy_automation", "members": ["group:ops-robots@example.com"]},
        ]

    def org_custom_roles(self):
        """v18.7: the organization's custom roles (``roles.list`` with ``view=FULL``): one with IAM powers, one plain, one deprecated and unbound."""
        prefix = f"organizations/{self.org_id}/roles"
        return [{"name": f"{prefix}/policy_automation", "title": "policy automation", "stage": "GA", "includedPermissions": ["resourcemanager.projects.setIamPolicy", "resourcemanager.projects.get"], "etag": "s"},
                {"name": f"{prefix}/minimal_viewer", "title": "minimal viewer", "stage": "GA", "includedPermissions": ["compute.instances.get"], "etag": "s"},
                {"name": f"{prefix}/old_auditor", "title": "old auditor", "stage": "DEPRECATED", "includedPermissions": ["logging.logEntries.list"], "etag": "s"}]

    def folder_iam_bindings(self, folder_id):
        """v18.7: a folder's own bindings — the first folder has a person as Owner and a project-factory group, the second an Editor service account."""
        index = self.folder_ids.index(folder_id) if folder_id in self.folder_ids else -1
        if index == 0:
            return [{"role": "roles/owner", "members": ["user:platform-lead@example.com"]}, {"role": "roles/resourcemanager.projectCreator", "members": ["group:project-factory@example.com"]}]
        if index == 1:
            return [{"role": "roles/editor", "members": ["serviceAccount:deployer@tooling.iam.gserviceaccount.com"]}]
        return []

    def org_policies(self, resource):
        """``listOrgPolicies`` for ``organizations/...``, ``folders/...`` or ``projects/...``."""
        if resource.startswith("organizations/"):
            return ([{"constraint": f"constraints/{cid}", "booleanPolicy": {"enforced": enforced}}
                     for cid, enforced in ORG_POLICY_CONSTRAINTS.items() if cid != "compute.vmExternalIpAccess"]
                    + [{"constraint": f"constraints/{cid}", "listPolicy": dict(policy)} for cid, policy in ORG_LIST_POLICIES.items()])
        rng = _rng(self.seed, "orgpolicy", resource)
        if _chance(rng, 0.3):  # some folders/projects override one constraint
            cid = rng.choice(list(ORG_POLICY_CONSTRAINTS))
            if cid in ORG_LIST_POLICIES:  # v18: the external-IP constraint is a list constraint; an override allows everything
                return [{"constraint": f"constraints/{cid}", "listPolicy": {"allValues": "ALLOW"}}]
            return [{"constraint": f"constraints/{cid}", "booleanPolicy": {"enforced": not ORG_POLICY_CONSTRAINTS[cid]}}]
        return []

    def unattended_project_ids(self):
        """Projects the Recommender flags as unattended: every 40th project."""
        return [self.project_id(i) for i in range(0, self.n_projects, 40)]

    def perimeters(self):
        """The organization's VPC Service Controls perimeters (v17.1): one enforced perimeter around the first folder's
        projects that leaves two replay services unrestricted, one dry-run perimeter around the second folder's."""
        first = [p for p in self.projects(self.folder_ids[0])]
        second = [p for p in self.projects(self.folder_ids[1])] if len(self.folder_ids) > 1 else []
        return [
            {"name": "prod_perimeter", "title": "prod perimeter", "regular": True, "dry_run": False,
             "resources": [f"projects/{p.project_number}" for p in first],
             "restricted": ["storage.googleapis.com", "secretmanager.googleapis.com", "container.googleapis.com", "sqladmin.googleapis.com", "bigquery.googleapis.com"]},
            {"name": "staging_perimeter", "title": "staging perimeter (dry run)", "regular": True, "dry_run": True,
             "resources": [f"projects/{p.project_number}" for p in second[:3]], "restricted": ["storage.googleapis.com"]},
        ]

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
