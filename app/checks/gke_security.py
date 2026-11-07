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
"""GKE security posture (v17.1): the configuration behind the SSRF chain.

An SSRF in an internet-facing pod reaches the node's metadata server, steals the
token of the node's service account, replays it from outside and drives a public
control plane. Each link is a cluster or node-pool setting this module reads from
one Cloud Asset Inventory listing of ``container.googleapis.com/Cluster`` under
the scanned scope (a scope-level check) and judges with pure functions:

- **GKE Credential Exposure** (``credential_rows``): per node pool, whether pods
  reach the GCE metadata server or the GKE metadata server, the node service
  account and its roles, the OAuth scopes, and the resulting exposure — *one
  SSRF from roles/editor on project X* when the GCE metadata server meets a
  privileged account (Action Required); a lesser gap (GCE metadata with a
  least-privilege account, GKE metadata with the Compute Engine default account)
  is Investigation Recommended.
- **GKE Control Plane Exposure** (``control_plane_issues``): a public endpoint
  without authorized networks or with ``0.0.0.0/0`` in them, legacy ABAC, client
  certificates, basic authentication (Action Required); anonymous authentication
  and system-group bindings (Investigation).
- **GKE Node Hardening** (``hardening_issues``): public node IPs, no network
  policy enforcement, Shielded nodes and Secure Boot off, a non-COS image,
  Binary Authorization off, security posture and vulnerability scanning off,
  secrets encryption off (Investigation Recommended).
- **GKE Threat Detection** (``check_gke_security``): Container Threat Detection
  per cluster and Event Threat Detection per project (Security Command Center
  settings, effective state), the cluster's logging components and the project's
  data-access audit logs for the Kubernetes API.

Autopilot clusters: nodes are Google-managed (GKE metadata server, Shielded
nodes, COS), so the node-pool rows do not apply to them. Every finding reaches a
verdict or an all-clear row; a listing that fails is the findings' Error.
"""
import logging
import re

from google.cloud import asset_v1

from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp

CREDENTIAL_EXPOSURE_CHECK = "GKE Credential Exposure"
CONTROL_PLANE_CHECK = "GKE Control Plane Exposure"
NODE_HARDENING_CHECK = "GKE Node Hardening"
THREAT_DETECTION_CHECK = "GKE Threat Detection"
CLUSTER_RESILIENCE_CHECK = "GKE Cluster Resilience"  # v17.3: Reliability, from the same listing
GKE_SECURITY_CHECKS = (CREDENTIAL_EXPOSURE_CHECK, CONTROL_PLANE_CHECK, NODE_HARDENING_CHECK, THREAT_DETECTION_CHECK, CLUSTER_RESILIENCE_CHECK)
CLUSTER_ASSET = "container.googleapis.com/Cluster"
# Resource levels whose bindings count as an account's roles.
RESOURCE_LEVELS = {"cloudresourcemanager.googleapis.com/Project": "project", "cloudresourcemanager.googleapis.com/Folder": "folder",
                   "cloudresourcemanager.googleapis.com/Organization": "organization"}
# Roles that make a stolen node token a project-wide problem (primitive roles, cluster and IAM administration,
# the token-minting role, the data stores). Order matters: the first one held is the one the exposure names.
PRIVILEGED_ROLES = ("roles/owner", "roles/editor", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin",
                    "roles/iam.serviceAccountAdmin", "roles/iam.serviceAccountKeyAdmin", "roles/iam.serviceAccountTokenCreator",
                    "roles/container.admin", "roles/container.clusterAdmin", "roles/container.developer", "roles/compute.admin",
                    "roles/storage.admin", "roles/secretmanager.admin")
CLOUD_PLATFORM_SCOPE = "cloud-platform"
SCOPE_PREFIX = "https://www.googleapis.com/auth/"
PUBLIC_CIDRS = ("0.0.0.0/0", "::/0")
ENABLED_STATE = "ENABLED"
LOGGING_COMPONENTS = ("SYSTEM_COMPONENTS", "WORKLOADS")
KUBERNETES_API = "container.googleapis.com"
ZONE_PATTERN = re.compile(r"^[a-z]+-[a-z]+\d+-[a-z]$")
DATA_ACCESS_LOG_TYPES = {"DATA_READ", "DATA_WRITE"}


# --- facts about a cluster -------------------------------------------------------------------------------------

def is_autopilot(cluster):
    return bool((cluster.get("autopilot") or {}).get("enabled"))


def is_zone(location):
    """``asia-south1-a`` is a zone, ``asia-south1`` a region: a zone has the region's two parts and a one-letter suffix."""
    return bool(ZONE_PATTERN.match(str(location or "")))


def pool_zones(cluster, pool):
    """The zones a node pool's nodes live in: the pool's ``locations``, else the cluster's, else its own location."""
    zones = pool.get("locations") or cluster.get("locations") or ([cluster.get("location")] if cluster.get("location") else [])
    return [str(zone) for zone in zones if zone]


def resilience_issues(cluster):
    """The *GKE Cluster Resilience* issues of a cluster: ``(pool name or None, issue, fix)``. A zonal control plane (the
    cluster's location is a zone) and each node pool whose nodes are all in one zone: the two shapes one zone's incident
    takes down. Autopilot clusters are regional with nodes across the region's zones, so they have none (v17.3)."""
    if is_autopilot(cluster):
        return []
    issues, location = [], str(cluster.get("location") or "")
    if is_zone(location):
        region = location.rsplit("-", 1)[0]
        issues.append((None, "Zonal control plane",
                       f"A zonal control plane cannot be made regional in place: create a regional cluster (gcloud container clusters create "
                       f"{cluster.get('name')} --region={region} ...) and migrate the workloads."))
    for pool in cluster.get("nodePools") or []:
        zones = pool_zones(cluster, pool)
        if len(zones) == 1:
            region = zones[0].rsplit("-", 1)[0] if is_zone(zones[0]) else zones[0]
            issues.append((pool.get("name"), f"Single-zone node pool ({zones[0]})",
                           f"--node-locations={region}-a,{region}-b,{region}-c  # the region's zones: gcloud compute zones list --filter=region:{region}"))
    return issues


def workload_identity_pool(cluster):
    return (cluster.get("workloadIdentityConfig") or {}).get("workloadPool") or ""


def pool_metadata_mode(cluster, pool):
    """``"GKE"`` when the pool's pods talk to the GKE metadata server (Workload Identity Federation), ``"GCE"``
    when they reach the node's own metadata server — the node's token and ``kube-env`` included. Metadata
    concealment (``SECURE``) hides ``kube-env`` only, so it still counts as ``GCE``."""
    if is_autopilot(cluster):
        return "GKE"
    config = (pool.get("config") or {}).get("workloadMetadataConfig") or {}
    if config.get("mode") == "GKE_METADATA" or config.get("nodeMetadata") == "GKE_METADATA_SERVER":
        return "GKE"
    return "GCE"


def legacy_endpoints_enabled(pool):
    """The v0.1/v1beta1 metadata endpoints, disabled by default since GKE 1.12, enabled again on this pool."""
    metadata = (pool.get("config") or {}).get("metadata") or {}
    return str(metadata.get("disable-legacy-endpoints", "true")).lower() != "true"


def node_service_account(pool, project_number):
    """``(email, is_default)`` of the pool's node service account; the API writes ``"default"`` for the Compute
    Engine default account, which the project number spells out."""
    account = (pool.get("config") or {}).get("serviceAccount") or "default"
    if account == "default":
        account = f"{project_number}-compute@developer.gserviceaccount.com" if project_number else "default"
        return account, True
    return account, account.endswith("-compute@developer.gserviceaccount.com")


def pool_scopes(pool):
    """The pool's OAuth scopes without the ``https://www.googleapis.com/auth/`` prefix."""
    return [scope[len(SCOPE_PREFIX):] if scope.startswith(SCOPE_PREFIX) else scope for scope in (pool.get("config") or {}).get("oauthScopes") or []]


def privileged_roles(roles):
    """The roles of ``PRIVILEGED_ROLES`` in ``roles``, in that order."""
    held = set(roles or ())
    return [role for role in PRIVILEGED_ROLES if role in held]


def exposure(metadata, is_default, roles, scopes, project_id, legacy_endpoints=False):
    """``(status, text)`` for a node pool, or ``None`` when there is nothing to say.

    ``roles`` is the account's roles at project, folder or organization level (``None``: not read).
    """
    privileged = privileged_roles(roles)
    if metadata == "GCE":
        if privileged:
            lead = f"One SSRF from {privileged[0]} on {project_id}"
            if CLOUD_PLATFORM_SCOPE in scopes:
                text = f"{lead}: pods reach the node's metadata server and a stolen token carries every role of the account."
            else:
                text = (f"{lead}: pods reach the node's metadata server; the pool's OAuth scopes limit what a stolen token can call "
                        f"({', '.join(scopes) or 'none'}), not whose roles it carries.")
            status = "Action Required"
        elif roles is None:
            text, status = ("Pods reach the node's metadata server (the node token and kube-env); the account's roles could not be read.",
                            "Investigation Recommended")
        else:
            text = "Pods reach the node's metadata server (the node token and kube-env)"
            text += "; the node runs as the Compute Engine default service account." if is_default else "; the account holds no privileged role."
            status = "Investigation Recommended"
        if legacy_endpoints:
            text += " Legacy metadata endpoints are enabled."
        return status, text
    if is_default:
        return "Investigation Recommended", "Pods use the GKE metadata server, but the nodes still run as the Compute Engine default service account."
    if legacy_endpoints:
        return "Investigation Recommended", "Legacy metadata endpoints are enabled on this pool."
    return None


def credential_rows(fact, roles_by_account):
    """The *GKE Credential Exposure* rows of one cluster (``fact`` from :func:`cluster_facts`): one per node pool with
    something to say, each with a ``_status``."""
    cluster, rows = fact["data"], []
    if is_autopilot(cluster):
        return rows
    project_id, project_number = fact["project_id"], fact["project_number"]
    for pool in cluster.get("nodePools") or []:
        account, is_default = node_service_account(pool, project_number)
        metadata, scopes, legacy = pool_metadata_mode(cluster, pool), pool_scopes(pool), legacy_endpoints_enabled(pool)
        roles = roles_by_account.get(account)
        verdict = exposure(metadata, is_default, roles, scopes, project_id, legacy)
        if verdict is None:
            continue
        status, text = verdict
        fixes = []
        if metadata == "GCE":
            if not workload_identity_pool(cluster):
                fixes.append(f"gcloud container clusters update {fact['name']} --location={fact['location']} --project={project_id} "
                             f"--workload-pool={project_id}.svc.id.goog")
            fixes.append(f"gcloud container node-pools update {pool.get('name')} --cluster={fact['name']} --location={fact['location']} "
                         f"--project={project_id} --workload-metadata=GKE_METADATA")
        if is_default or privileged_roles(roles):
            fixes.append(f"Create a least-privilege node account (roles/container.defaultNodeServiceAccount) and a new node pool with "
                         f"--service-account=gke-nodes@{project_id}.iam.gserviceaccount.com; an existing pool's account cannot be changed.")
        rows.append({"Project": project_id, "Cluster": fact["name"], "Node Pool": pool.get("name"), "Metadata": metadata,
                     "Service Account": account + (" (default)" if is_default else ""),
                     "Roles": ", ".join(sorted(roles)) if roles else ("not read" if roles is None else ""),
                     "Scopes": ", ".join(scopes), "Exposure": text, "Fix": "\n".join(fixes), "_status": status})
    return rows


def control_plane_issues(cluster):
    """``[(status, issue, fix flags)]`` for a cluster's control plane."""
    issues = []
    endpoints = (cluster.get("controlPlaneEndpointsConfig") or {}).get("ipEndpointsConfig") or {}
    private = cluster.get("privateClusterConfig") or {}
    if endpoints:
        public = endpoints.get("enabled", True) and endpoints.get("enablePublicEndpoint", True)
        authorized = endpoints.get("authorizedNetworksConfig") or {}
    else:
        public = not private.get("enablePrivateEndpoint", False)
        authorized = cluster.get("masterAuthorizedNetworksConfig") or {}
    cidrs = [block.get("cidrBlock", "") for block in authorized.get("cidrBlocks") or []]
    if public and not authorized.get("enabled", False):
        issues.append(("Action Required", "Public control plane endpoint with authorized networks off: the Kubernetes API answers any IP.",
                       "--enable-master-authorized-networks --master-authorized-networks=<CIDRs>"))
    elif public and any(cidr in PUBLIC_CIDRS for cidr in cidrs):
        issues.append(("Action Required", "Authorized networks allow 0.0.0.0/0: the public endpoint is open to the internet.",
                       "--master-authorized-networks=<CIDRs>"))
    elif public and authorized.get("gcpPublicCidrsAccessEnabled", False):
        issues.append(("Investigation Recommended", "Authorized networks admit every Google Cloud public IP address.",
                       "--no-enable-google-cloud-access"))
    if (cluster.get("legacyAbac") or {}).get("enabled", False):
        issues.append(("Action Required", "Legacy ABAC enabled: authorization outside Kubernetes RBAC and IAM.", "--no-enable-legacy-authorization"))
    auth = cluster.get("masterAuth") or {}
    if (auth.get("clientCertificateConfig") or {}).get("issueClientCertificate", False) or auth.get("clientCertificate"):
        issues.append(("Action Required", "A client certificate is issued: a non-revocable credential outside IAM.", "--no-issue-client-certificate"))
    if auth.get("username") or auth.get("password"):
        issues.append(("Action Required", "Basic authentication enabled.", "--no-enable-basic-auth"))
    rbac = cluster.get("rbacBindingConfig") or {}
    loose = []
    if (cluster.get("anonymousAuthenticationConfig") or {}).get("mode") == "ENABLED":
        loose.append("anonymous authentication")
    if rbac.get("enableInsecureBindingSystemUnauthenticated", False):
        loose.append("bindings to system:unauthenticated")
    if rbac.get("enableInsecureBindingSystemAuthenticated", False):
        loose.append("bindings to system:authenticated")
    if loose:
        issues.append(("Investigation Recommended", f"Allowed: {', '.join(loose)}.",
                       "--anonymous-authentication-config=LIMITED --no-enable-insecure-binding-system-unauthenticated "
                       "--no-enable-insecure-binding-system-authenticated"))
    return issues


def hardening_issues(cluster):
    """``[(node pool or "", issue, fix)]`` — the defence-in-depth gaps of a cluster and its pools (Standard
    clusters; Autopilot manages its nodes). A fix is the flags of a ``clusters update`` / ``node-pools update``
    line, or — when nothing can be changed in place (v18.2: a routes-based or an alpha cluster) — a sentence."""
    issues = []
    autopilot = is_autopilot(cluster)
    network = cluster.get("networkConfig") or {}
    if not autopilot:
        if not ((cluster.get("networkPolicy") or {}).get("enabled", False) or network.get("datapathProvider") == "ADVANCED_DATAPATH"):
            issues.append(("", "No network policy enforcement (neither NetworkPolicy nor Dataplane V2): pod egress to the metadata server cannot be blocked.",
                           "--enable-dataplane-v2 (new clusters) or --enable-network-policy"))
        if not (cluster.get("shieldedNodes") or {}).get("enabled", False):
            issues.append(("", "Shielded GKE nodes off.", "--enable-shielded-nodes"))
        private_default = (cluster.get("privateClusterConfig") or {}).get("enablePrivateNodes", False) or network.get("defaultEnablePrivateNodes", False)
        for pool in cluster.get("nodePools") or []:
            name, config = pool.get("name"), pool.get("config") or {}
            pool_private = (pool.get("networkConfig") or {}).get("enablePrivateNodes")
            if not (private_default if pool_private is None else pool_private):
                issues.append((name, "Nodes have public IP addresses.", "--enable-private-nodes"))
            shielded = config.get("shieldedInstanceConfig") or {}
            if not shielded.get("enableSecureBoot", False):
                issues.append((name, "Secure Boot off.", "--shielded-secure-boot"))
            if not shielded.get("enableIntegrityMonitoring", False):  # v18.2: SHA INTEGRITY_MONITORING_DISABLED
                issues.append((name, "Integrity monitoring off.", "--shielded-integrity-monitoring"))
            image = config.get("imageType") or ""
            if not image.upper().startswith("COS"):
                issues.append((name, f"Node image {image or 'unknown'} is not Container-Optimized OS.", "--image-type=COS_CONTAINERD"))
    binauthz = cluster.get("binaryAuthorization") or {}
    if not (binauthz.get("enabled", False) or binauthz.get("evaluationMode") in ("PROJECT_SINGLETON_POLICY_ENFORCE", "POLICY_BINDINGS",
                                                                               "POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE")):
        issues.append(("", "Binary Authorization off: unsigned images run.", "--binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE"))
    posture = cluster.get("securityPostureConfig") or {}
    if posture.get("mode") not in ("BASIC", "ENTERPRISE"):
        issues.append(("", "Security posture dashboard off.", "--security-posture=standard"))
    if posture.get("vulnerabilityMode") not in ("VULNERABILITY_BASIC", "VULNERABILITY_ENTERPRISE"):
        issues.append(("", "Workload vulnerability scanning off.", "--workload-vulnerability-scanning=standard"))
    if (cluster.get("databaseEncryption") or {}).get("state") != "ENCRYPTED":
        issues.append(("", "Application-layer secrets encryption off.", "--database-encryption-key=<KMS key>"))
    if not autopilot:  # v18.2: three more Security Health Analytics detectors, all cluster-level, Standard clusters (Autopilot has none of them)
        if not network.get("enableIntraNodeVisibility", False):
            issues.append(("", "Intra-node visibility off: pod-to-pod traffic on one node is invisible to VPC flow logs and firewall rules.", "--enable-intra-node-visibility"))
        if not (cluster.get("ipAllocationPolicy") or {}).get("useIpAliases", False):
            issues.append(("", "Routes-based cluster (not VPC-native).",
                           "Create a VPC-native cluster (--enable-ip-alias) and migrate the workloads: a routes-based cluster cannot be converted in place."))
        if cluster.get("enableKubernetesAlpha", False):
            issues.append(("", "Alpha cluster: alpha APIs on, deleted 30 days after creation; not for production.",
                           "Recreate the cluster without --enable-kubernetes-alpha: the setting cannot be changed."))
    return issues


def hardening_fix(fact, pool, flags):
    """The fix line of a hardening issue: a ``node-pools update`` for a pool, a ``clusters update`` for the cluster, the sentence as is when it is one."""
    if not flags.startswith("--"):
        return flags
    if pool:
        return f"gcloud container node-pools update {pool} --cluster={fact['name']} --location={fact['location']} --project={fact['project_id']} {flags}"
    return cluster_update(fact, flags)


def logging_gaps(cluster):
    """The logging components a cluster does not send to Cloud Logging."""
    enabled = set(((cluster.get("loggingConfig") or {}).get("componentConfig") or {}).get("enableComponents") or [])
    return [component for component in LOGGING_COMPONENTS if component not in enabled]


def data_access_logging(audit_configs):
    """Whether a project's ``auditConfigs`` record DATA_READ and DATA_WRITE for the Kubernetes API."""
    for config in audit_configs or []:
        if config.get("service") in ("allServices", KUBERNETES_API):
            types = {entry.get("logType") for entry in config.get("auditLogConfigs") or []}
            if DATA_ACCESS_LOG_TYPES <= types:
                return True
    return False


def cluster_facts(asset):
    """What the checks need from a cluster asset: project ID and number, name, location, the resource data."""
    name = getattr(asset, "name", "") or ""
    parts = name.split("/")
    project_id = parts[parts.index("projects") + 1] if "projects" in parts else "unknown"
    resource = getattr(asset, "resource", None)
    data = getattr(resource, "data", None) or {}
    parent = getattr(resource, "parent", "") or ""
    project_number = parent.rsplit("/", 1)[-1] if "/projects/" in parent else ""
    if not project_number:
        for ancestor in getattr(asset, "ancestors", None) or []:
            if str(ancestor).startswith("projects/"):
                project_number = str(ancestor).split("/", 1)[1]
                break
    return {"project_id": project_id, "project_number": project_number, "name": data.get("name") or parts[-1],
            "location": data.get("location") or (parts[parts.index("locations") + 1] if "locations" in parts else ""), "data": data}


def cluster_update(fact, flags):
    return f"gcloud container clusters update {fact['name']} --location={fact['location']} --project={fact['project_id']} {flags}"


# --- the check ------------------------------------------------------------------------------------------------------

def account_roles(asset_client, parent, account):
    """The roles ``account`` holds at project, folder or organization level under ``parent``, from one IAM search."""
    member, roles = f"serviceAccount:{account}", set()
    for result in asset_client.search_all_iam_policies(request={"scope": parent, "query": f'policy:"{account}"'}):
        if getattr(result, "asset_type", "") not in RESOURCE_LEVELS:
            continue
        for binding in getattr(getattr(result, "policy", None), "bindings", None) or []:
            if member in list(getattr(binding, "members", None) or []):
                roles.add(getattr(binding, "role", ""))
    return roles


def _write_rows(sink, job_id, check, rows, all_clear):
    statuses = {row.pop("_status") for row in rows}
    if "Action Required" in statuses:
        result = {"Check": check, "Finding": rows, "Status": "Action Required"}
    elif rows:
        result = {"Check": check, "Finding": rows, "Status": "Investigation Recommended"}
    else:
        result = {"Check": check, "Finding": [{"Status": all_clear}], "Status": "Compliant"}
    sink.write_finding(job_id, check.replace(" ", "_"), result)


def _write_error(sink, job_id, check, error):
    sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(error)}], "Status": "Error"})


def list_cluster_facts(asset_client, parent):
    """The ``cluster_facts`` of every running cluster under ``parent`` (one Asset Inventory listing; stopping clusters left out).
    Shared with ``app.checks.gke_operations`` (v18.2)."""
    request = {"parent": parent, "asset_types": [CLUSTER_ASSET], "content_type": asset_v1.ContentType.RESOURCE}
    facts = [cluster_facts(asset) for asset in asset_client.list_assets(request=request)]
    return [fact for fact in facts if (fact["data"].get("status") or "RUNNING") not in ("STOPPING", "DEGRADED_STOPPING")]


def check_gke_security(scope, scope_id, job_id, *, sink):
    """The four GKE security findings from one Asset Inventory listing of the scope's clusters (v17.1)."""
    print(f"🛡️ [{job_id}] Checking GKE security posture under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        facts = list_cluster_facts(asset_client, parent)
    except Exception as e:
        logging.error(f"[{job_id}] GKE security posture: could not list the clusters under {parent}: {e}")
        for check in GKE_SECURITY_CHECKS:
            _write_error(sink, job_id, check, e)
        return

    # 1. Credential exposure: the roles of every node account, one search each.
    skipped = NotChecked(CREDENTIAL_EXPOSURE_CHECK)
    roles_by_account = {}
    for fact in facts:
        if is_autopilot(fact["data"]):
            continue
        for pool in fact["data"].get("nodePools") or []:
            account, _ = node_service_account(pool, fact["project_number"])
            if account in roles_by_account:
                continue
            try:
                roles_by_account[account] = account_roles(asset_client, parent, account)
            except Exception as e:
                roles_by_account[account] = None
                skipped.add(fact["project_id"], e, detail=f"roles of {account}")
    rows = [row for fact in facts for row in credential_rows(fact, roles_by_account)]
    _write_rows(sink, job_id, CREDENTIAL_EXPOSURE_CHECK, rows,
                "Every node pool serves its pods the GKE metadata server and runs as a least-privilege service account.")
    skipped.write(sink, job_id)

    # 2. Control plane exposure.
    rows = []
    for fact in facts:
        for status, issue, flags in control_plane_issues(fact["data"]):
            rows.append({"Project": fact["project_id"], "Cluster": fact["name"], "Location": fact["location"], "Issue": issue,
                         "Fix": cluster_update(fact, flags), "_status": status})
    _write_rows(sink, job_id, CONTROL_PLANE_CHECK, rows,
                "No cluster exposes its control plane: private endpoints or authorized networks, RBAC only, no client certificates.")

    # 3. Node hardening.
    rows = []
    for fact in facts:
        for pool, issue, flags in hardening_issues(fact["data"]):
            rows.append({"Project": fact["project_id"], "Cluster": fact["name"], "Node Pool": pool or "(cluster)", "Issue": issue,
                         "Fix": hardening_fix(fact, pool, flags), "_status": "Investigation Recommended"})
    _write_rows(sink, job_id, NODE_HARDENING_CHECK, rows,
                "Every cluster is VPC-native with private, Shielded, COS nodes (Secure Boot and integrity monitoring on), network policy "
                "enforcement, intra-node visibility, Binary Authorization, posture scanning and secrets encryption; no alpha cluster.")

    # 4. Threat detection and logging.
    skipped = NotChecked(THREAT_DETECTION_CHECK)
    rows, etd_by_project, audit_by_project = [], {}, {}
    scc = crm = None
    for fact in facts:
        project_id, cluster = fact["project_id"], fact["data"]
        try:
            if scc is None:
                scc = gcp.api_build("securitycenter", "v1beta2", credentials=credentials)
            name = f"projects/{project_id}/locations/{fact['location']}/clusters/{fact['name']}/containerThreatDetectionSettings"
            state = scc.projects().locations().clusters().containerThreatDetectionSettings().calculate(name=name).execute().get("serviceEnablementState", "")
            if state != ENABLED_STATE:
                rows.append({"Project": project_id, "Cluster": fact["name"], "Signal": "Container Threat Detection", "State": state or "unknown",
                             "Fix": "Security Command Center › Settings › Container Threat Detection: enable for the project or organization (Premium or Enterprise tier).",
                             "_status": "Action Required"})
            if project_id not in etd_by_project:
                etd_by_project[project_id] = scc.projects().eventThreatDetectionSettings().calculate(
                    name=f"projects/{project_id}/eventThreatDetectionSettings").execute().get("serviceEnablementState", "")
            if etd_by_project[project_id] != ENABLED_STATE:
                rows.append({"Project": project_id, "Cluster": fact["name"], "Signal": "Event Threat Detection", "State": etd_by_project[project_id] or "unknown",
                             "Fix": "Security Command Center › Settings › Event Threat Detection: enable for the project or organization (Premium or Enterprise tier).",
                             "_status": "Action Required"})
        except Exception as e:
            skipped.add(project_id, e, detail="Security Command Center settings")
        gaps = logging_gaps(cluster)
        if gaps:
            rows.append({"Project": project_id, "Cluster": fact["name"], "Signal": "Cloud Logging", "State": f"missing {', '.join(gaps)}",
                         "Fix": cluster_update(fact, "--logging=SYSTEM,WORKLOAD"), "_status": "Investigation Recommended"})
        try:
            if project_id not in audit_by_project:
                if crm is None:
                    crm = gcp.api_build("cloudresourcemanager", "v1", credentials=credentials)
                policy = crm.projects().getIamPolicy(resource=project_id, body={"options": {"requestedPolicyVersion": 3}}).execute()
                audit_by_project[project_id] = data_access_logging(policy.get("auditConfigs"))
            if not audit_by_project[project_id]:
                rows.append({"Project": project_id, "Cluster": fact["name"], "Signal": "Data-access audit logs", "State": "off for container.googleapis.com",
                             "Fix": f"gcloud projects set-iam-policy {project_id} with an auditConfig for container.googleapis.com (DATA_READ, DATA_WRITE)",
                             "_status": "Investigation Recommended"})
        except Exception as e:
            skipped.add(project_id, e, detail="audit configuration")
    _write_rows(sink, job_id, THREAT_DETECTION_CHECK, rows,
                "Container and Event Threat Detection cover every cluster; workload and system logs and data-access audit logs are on.")
    skipped.write(sink, job_id)

    # 5. Cluster resilience (Reliability, v17.3): zonal control planes and single-zone node pools, the footprint
    #    Incident Exposure meets GKE incidents with.
    rows = []
    for fact in facts:
        for pool, issue, fix in resilience_issues(fact["data"]):
            if pool:
                fix = f"gcloud container node-pools update {pool} --cluster={fact['name']} --location={fact['location']} --project={fact['project_id']} {fix}"
            rows.append({"Project": fact["project_id"], "Cluster": fact["name"], "Location": fact["location"], "Node Pool": pool or "(control plane)",
                         "Issue": issue, "Fix": fix, "_status": "Action Required"})
    _write_rows(sink, job_id, CLUSTER_RESILIENCE_CHECK, rows, "No zonal control planes or single-zone node pools found.")
