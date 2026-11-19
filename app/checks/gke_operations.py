"""
GKE upgrade readiness and observability (v18.2).

The widest GKE cluster in the case evidence is *upgrades*: node pools upgraded in
business hours because no maintenance window was set, freezes that nobody
declared as an exclusion, upgrades that stall on a PodDisruptionBudget no drain
can satisfy, security bulletins nobody was told about. None of its causes is a
runtime event; every one is a setting readable from Cloud Asset Inventory —
the cluster resource ``gke_security`` already lists, and the Kubernetes
``policy.k8s.io/PodDisruptionBudget`` objects the inventory indexes for every
GKE cluster — so the module reads two listings under the scanned scope and
judges with pure functions:

- **GKE Upgrade Readiness** (Reliability): no maintenance window, active
  maintenance exclusions (the calendar, Informational), upgrade notifications
  off or without security bulletins, node pools that lose capacity during an
  upgrade (``maxUnavailable`` ≥ 1), node pools two minors behind their control
  plane, and PodDisruptionBudgets that can never be satisfied (Action Required)
  or allow no disruption right now (Investigation).
- **GKE Observability** (Operations): system metrics off (Action Required),
  control-plane metrics off, Managed Service for Prometheus off, NodeLocal
  DNSCache off on Standard clusters.

Autopilot clusters get the cluster-level rows (window, exclusions,
notifications, metrics, budgets) and no node-pool rows: Google manages their
pools. System namespaces' budgets (``kube-*``, ``gke-*``, ``gmp-*``,
``config-management-*``) are Google's and are not judged. Every finding reaches
a verdict or an all-clear row; a cluster listing that fails is both checks'
Error; a budget listing that fails leaves the budget rule under *Projects not
checked* and the rest of the check standing.
"""
import logging
from datetime import datetime, timezone

from google.cloud import asset_v1

from app.checks.gke_security import cluster_update, is_autopilot, list_cluster_facts
from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp

UPGRADE_READINESS_CHECK = "GKE Upgrade Readiness"
OBSERVABILITY_CHECK = "GKE Observability"
GKE_OPERATIONS_CHECKS = (UPGRADE_READINESS_CHECK, OBSERVABILITY_CHECK)
PDB_ASSET = "policy.k8s.io/PodDisruptionBudget"

ACTION_REQUIRED, INVESTIGATION, INFORMATIONAL, COMPLIANT = "Action Required", "Investigation Recommended", "Informational", "Compliant"
STATUS_RANK = {ACTION_REQUIRED: 3, INVESTIGATION: 2, INFORMATIONAL: 1}
# Exclusion scopes that hold back minor or node upgrades (NO_UPGRADES is the default scope and holds back everything).
BLOCKING_EXCLUSION_SCOPES = ("NO_UPGRADES", "NO_MINOR_UPGRADES", "NO_MINOR_OR_NODE_UPGRADES")
# The notification events a filter must admit to be worth having: the upgrades themselves and the security bulletins.
REQUIRED_NOTIFICATION_EVENTS = ("UPGRADE_EVENT", "SECURITY_BULLETIN_EVENT")
NOTIFICATION_FILTER = "UpgradeEvent|UpgradeAvailableEvent|UpgradeInfoEvent|SecurityBulletinEvent"
SYSTEM_METRICS = "SYSTEM_COMPONENTS"
CONTROL_PLANE_METRICS = ("APISERVER", "SCHEDULER", "CONTROLLER_MANAGER")
# Monitoring component names: the API's → gcloud's --monitoring values.
GCLOUD_COMPONENT = {"SYSTEM_COMPONENTS": "SYSTEM", "APISERVER": "API_SERVER"}
SYSTEM_NAMESPACE_PREFIXES = ("kube-", "gke-", "gmp-", "config-management-")
UPGRADE_ALL_CLEAR = ("Every cluster has a maintenance window and upgrade notifications, every node pool upgrades without losing capacity, "
                     "and no PodDisruptionBudget blocks a drain.")
OBSERVABILITY_ALL_CLEAR = ("Every cluster sends system and control-plane metrics to Cloud Monitoring and runs Managed Service for Prometheus; "
                           "every Standard cluster runs NodeLocal DNSCache.")
EXAMPLE_WINDOW = "--maintenance-window-start=2026-01-03T18:00:00Z --maintenance-window-end=2026-01-03T22:00:00Z --maintenance-window-recurrence='FREQ=WEEKLY;BYDAY=SA,SU'"


# --- facts about a cluster -------------------------------------------------------------------------------------

def parse_time(text):
    """A GKE timestamp (RFC 3339, ``Z`` or an offset, with or without fractions) as an aware datetime; ``None`` when unreadable."""
    if not text:
        return None
    try:
        value = str(text).strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def maintenance_window(cluster):
    """The cluster's maintenance window (daily or recurring), or ``None`` when GKE picks the time."""
    window = (cluster.get("maintenancePolicy") or {}).get("window") or {}
    return window.get("dailyMaintenanceWindow") or window.get("recurringWindow") or None


def active_exclusions(cluster, now):
    """``[(name, scope, end)]`` of the maintenance exclusions still in force at ``now`` whose scope holds back minor or node upgrades."""
    exclusions = ((cluster.get("maintenancePolicy") or {}).get("window") or {}).get("maintenanceExclusions") or {}
    found = []
    for name, exclusion in sorted(exclusions.items()):
        end = parse_time((exclusion or {}).get("endTime"))
        scope = str(((exclusion or {}).get("maintenanceExclusionOptions") or {}).get("scope") or "NO_UPGRADES").upper()
        if end is not None and end > now and scope in BLOCKING_EXCLUSION_SCOPES:
            found.append((name, scope, end))
    return found


def notification_gap(cluster):
    """``"off"`` when upgrade notifications are not published, the missing event types when the filter leaves them out, ``None`` when fine."""
    pubsub = (cluster.get("notificationConfig") or {}).get("pubsub") or {}
    if not pubsub.get("enabled", False):
        return "off"
    events = {str(event).upper() for event in ((pubsub.get("filter") or {}).get("eventType") or [])}
    if not events:  # no filter: every event is published
        return None
    missing = [event for event in REQUIRED_NOTIFICATION_EVENTS if event not in events]
    return missing or None


def surge_issue(pool):
    """``(maxSurge, maxUnavailable)`` when a surge-strategy pool loses capacity during an upgrade (``maxUnavailable`` ≥ 1), else ``None``."""
    settings = pool.get("upgradeSettings") or {}
    if str(settings.get("strategy") or "SURGE").upper() != "SURGE":
        return None
    unavailable = int(settings.get("maxUnavailable") or 0)
    return (int(settings.get("maxSurge") or 0), unavailable) if unavailable >= 1 else None


def version_minor(version):
    """``(1, 32)`` for ``1.32.13-gke.2662000``; ``None`` when the string is not a version."""
    parts = str(version or "").split("-", 1)[0].split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return None


def minors_behind(pool_version, master_version):
    """How many minors a node pool trails its control plane by (0 when at the same minor or unreadable)."""
    pool, master = version_minor(pool_version), version_minor(master_version)
    if pool is None or master is None or pool[0] != master[0]:
        return 0
    return max(0, master[1] - pool[1])


def upgrade_readiness_rows(fact, now):
    """The *GKE Upgrade Readiness* rows of one cluster (its budgets come from ``pdb_rows``)."""
    cluster, rows = fact["data"], []
    base = {"Project": fact["project_id"], "Cluster": fact["name"], "Location": fact["location"]}

    def row(pool, issue, detail, fix, status):
        rows.append({**base, "Node Pool": pool or "(cluster)", "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    if maintenance_window(cluster) is None:
        row(None, "No maintenance window.", "GKE chooses the time: control-plane and node upgrades can land in business hours.",
            cluster_update(fact, EXAMPLE_WINDOW) + "  # an example window: Saturday and Sunday 18:00-22:00 UTC", INVESTIGATION)
    for name, scope, end in active_exclusions(cluster, now):
        row(None, f"Maintenance exclusion {name} in force.", f"{scope.replace('_', ' ').lower()} until {end:%Y-%m-%d}: upgrades resume then.", "", INFORMATIONAL)
    gap = notification_gap(cluster)
    if gap == "off":
        row(None, "Upgrade notifications off.", "Nobody is told of upgrades, new versions or security bulletins.",
            cluster_update(fact, f"--notification-config=pubsub=ENABLED,pubsub-topic=projects/{fact['project_id']}/topics/gke-notifications,filter=\"{NOTIFICATION_FILTER}\"")
            + "  # create the topic first", INVESTIGATION)
    elif gap:
        row(None, f"Upgrade notifications leave out {', '.join(gap)}.", "The filter admits neither the upgrades themselves nor the security bulletins." if len(gap) == 2
            else f"The filter leaves out {gap[0]}.", cluster_update(fact, f"--notification-config=pubsub=ENABLED,filter=\"{NOTIFICATION_FILTER}\""), INVESTIGATION)
    if not is_autopilot(cluster):
        master = cluster.get("currentMasterVersion") or ""
        for pool in cluster.get("nodePools") or []:
            name = pool.get("name")
            surge = surge_issue(pool)
            if surge:
                row(name, "Capacity drops during upgrades.", f"maxSurge {surge[0]}, maxUnavailable {surge[1]}: the pool loses {surge[1]} node(s) while each batch upgrades.",
                    f"gcloud container node-pools update {name} --cluster={fact['name']} --location={fact['location']} --project={fact['project_id']} "
                    f"--max-surge-upgrade=1 --max-unavailable-upgrade=0", INVESTIGATION)
            behind = minors_behind(pool.get("version"), master)
            if behind >= 2:
                auto = bool((pool.get("management") or {}).get("autoUpgrade", False))
                row(name, f"Node pool {behind} minors behind the control plane.",
                    f"{pool.get('version')} against {master}: " + ("GKE will upgrade it in the next window (expect node recreation)." if auto
                                                                  else "auto-upgrade is off, so the control plane cannot take its next minor until the pool moves."),
                    f"gcloud container clusters upgrade {fact['name']} --node-pool={name} --cluster-version={master} --location={fact['location']} --project={fact['project_id']}",
                    INFORMATIONAL if auto else INVESTIGATION)
    return rows


# --- PodDisruptionBudgets ---------------------------------------------------------------------------------------

def pdb_facts(asset):
    """Project, location, cluster, namespace and name from a budget asset's name, with its ``spec`` and ``status``."""
    name = getattr(asset, "name", "") or ""
    parts = name.split("/")

    def after(key):
        return parts[parts.index(key) + 1] if key in parts and parts.index(key) + 1 < len(parts) else ""
    data = getattr(getattr(asset, "resource", None), "data", None) or {}
    return {"project_id": after("projects"), "location": after("locations") or after("zones"), "cluster": after("clusters"),
            "namespace": after("namespaces") or ((data.get("metadata") or {}).get("namespace") or ""),
            "name": parts[-1] if parts else "", "spec": data.get("spec") or {}, "status": data.get("status") or {}}


def is_system_namespace(namespace):
    return str(namespace or "").startswith(SYSTEM_NAMESPACE_PREFIXES)


def _as_int(value):
    """``0``, ``0.0`` (Asset Inventory delivers Kubernetes numbers as Struct floats), ``"2"`` and ``"25%"`` as an int; ``None`` otherwise."""
    try:
        return int(float(str(value).rstrip("%")))
    except (TypeError, ValueError):
        return None


def _number_text(value):
    """``0.0`` → ``"0"``, ``"25%"`` → ``"25%"``: a Kubernetes count or percentage as people write it."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def pdb_budget(spec):
    """``"maxUnavailable: 0"`` / ``"minAvailable: 100%"`` — the budget as written."""
    if "maxUnavailable" in spec:
        return f"maxUnavailable: {_number_text(spec['maxUnavailable'])}"
    if "minAvailable" in spec:
        return f"minAvailable: {_number_text(spec['minAvailable'])}"
    return "(no budget)"


def pdb_assessment(spec, status):
    """``(status, issue)`` for a budget: Action Required when it can never be satisfied, Investigation when it allows no disruption
    right now, ``(None, "")`` otherwise.

    Unsatisfiable: ``maxUnavailable`` 0 (or ``0%``), ``minAvailable`` ``100%``, or an absolute ``minAvailable`` not below the pods the
    budget expects. Exhausted: ``status.disruptionsAllowed`` 0 with pods expected — a snapshot (the inventory lags the cluster).
    """
    expected = _as_int(status.get("expectedPods"))
    if "maxUnavailable" in spec and _as_int(spec["maxUnavailable"]) == 0:
        return ACTION_REQUIRED, "No pod of this workload may ever be evicted: node drains stall (GKE waits up to an hour per node), scale-down never happens."
    if "minAvailable" in spec:
        minimum = _number_text(spec["minAvailable"])
        if minimum.endswith("%") and _as_int(minimum) is not None and _as_int(minimum) >= 100:
            return ACTION_REQUIRED, "No pod of this workload may ever be evicted: node drains stall (GKE waits up to an hour per node), scale-down never happens."
        if not minimum.endswith("%") and expected and _as_int(minimum) is not None and _as_int(minimum) >= expected:
            return ACTION_REQUIRED, f"The budget keeps {minimum} of {expected} pods: none may be evicted until the workload runs more replicas."
    if expected and _as_int(status.get("disruptionsAllowed")) == 0:
        return INVESTIGATION, f"Allows no disruption right now: {_as_int(status.get('currentHealthy')) or 0} of {expected} pods healthy, a drain would block today."
    return None, ""


def pdb_rows(assets):
    """The budget rows of *GKE Upgrade Readiness* — the same seven columns as the cluster rows (one table, one CSV header, one export
    schema): the budget is named in ``Node Pool`` as ``namespace/name``, its spec and status in ``Detail``."""
    rows = []
    for asset in assets:
        fact = pdb_facts(asset)
        if is_system_namespace(fact["namespace"]):
            continue
        status, issue = pdb_assessment(fact["spec"], fact["status"])
        if status is None:
            continue
        allowed = fact["status"].get("disruptionsAllowed")
        healthy, expected = _as_int(fact["status"].get("currentHealthy")), _as_int(fact["status"].get("expectedPods"))
        state = f"{pdb_budget(fact['spec'])} · disruptions allowed {'unknown' if allowed is None else _number_text(allowed)}"
        if healthy is not None and expected is not None:
            state += f" · {healthy} of {expected} pods healthy"
        rows.append({"Project": fact["project_id"], "Cluster": fact["cluster"], "Location": fact["location"], "Node Pool": f"{fact['namespace']}/{fact['name']}",
                     "Issue": "PodDisruptionBudget can never be satisfied." if status == ACTION_REQUIRED else "PodDisruptionBudget allows no disruption right now.",
                     "Detail": f"{state}: {issue}",
                     "Fix": f"kubectl -n {fact['namespace']} edit pdb {fact['name']}  # maxUnavailable: 1, or run more replicas than the budget protects",
                     "_status": status})
    return rows


# --- observability -----------------------------------------------------------------------------------------------

def monitoring_components(cluster):
    """The monitoring components a cluster sends (the legacy ``monitoringService`` read as SYSTEM_COMPONENTS when the new config is absent)."""
    config = (cluster.get("monitoringConfig") or {}).get("componentConfig")
    if config is not None:
        return {str(component).upper() for component in (config.get("enableComponents") or [])}
    return set() if str(cluster.get("monitoringService") or "").lower() == "none" else {SYSTEM_METRICS}


def gcloud_monitoring(components):
    """The ``--monitoring=`` value that keeps ``components`` and adds the control-plane metrics."""
    wanted = [SYSTEM_METRICS, *CONTROL_PLANE_METRICS] + sorted(c for c in components if c not in (SYSTEM_METRICS, *CONTROL_PLANE_METRICS))
    return "--monitoring=" + ",".join(GCLOUD_COMPONENT.get(c, c) for c in wanted)


def observability_issues(cluster):
    """``[(signal, state, fix flags, status)]`` of a cluster's metrics and DNS posture."""
    issues, components = [], monitoring_components(cluster)
    if SYSTEM_METRICS not in components:
        issues.append(("System metrics", "off: no node, pod or container metrics reach Cloud Monitoring", gcloud_monitoring(components), ACTION_REQUIRED))
    if not any(metric in components for metric in CONTROL_PLANE_METRICS):
        issues.append(("Control-plane metrics", "off: API server, scheduler and controller-manager metrics (free of charge) are not collected",
                       gcloud_monitoring(components), INVESTIGATION))
    if not is_autopilot(cluster):
        if not ((cluster.get("monitoringConfig") or {}).get("managedPrometheusConfig") or {}).get("enabled", False):
            issues.append(("Managed Service for Prometheus", "off", "--enable-managed-prometheus", INVESTIGATION))
        if not ((cluster.get("addonsConfig") or {}).get("dnsCacheConfig") or {}).get("enabled", False):
            issues.append(("NodeLocal DNSCache", "off: every DNS lookup crosses the node to kube-dns",
                           "--update-addons=NodeLocalDNS=ENABLED  # nodes are recreated in the next maintenance window", INVESTIGATION))
    return issues


def observability_rows(fact):
    return [{"Project": fact["project_id"], "Cluster": fact["name"], "Location": fact["location"], "Signal": signal, "State": state,
             "Fix": cluster_update(fact, flags), "_status": status} for signal, state, flags, status in observability_issues(fact["data"])]


# --- the check ------------------------------------------------------------------------------------------------------

def worst_status(rows):
    """Action Required > Investigation Recommended > Informational, over the rows' ``_status``."""
    return max((row.get("_status", INFORMATIONAL) for row in rows), key=lambda status: STATUS_RANK.get(status, 0), default=COMPLIANT)


def write_rows(sink, job_id, check, rows, all_clear):
    status = worst_status(rows)
    for row in rows:
        row.pop("_status", None)
    result = {"Check": check, "Finding": rows, "Status": status} if rows else {"Check": check, "Finding": [{"Status": all_clear}], "Status": COMPLIANT}
    sink.write_finding(job_id, check.replace(" ", "_"), result)


def fresh_clusters(container, project_id):
    """``{(location, name): cluster}`` from the GKE API itself (``clusters.list``, the call GKE Hygiene makes): the inventory's copy of
    a cluster can lag a maintenance-policy change by hours (the v18.2 probe cluster's exclusion was still absent half an hour later)."""
    response = container.projects().locations().clusters().list(parent=f"projects/{project_id}/locations/-").execute()
    return {(str(cluster.get("location") or ""), cluster.get("name")): cluster for cluster in response.get("clusters") or []}


def refresh_facts(facts, container, skipped):
    """Replaces each fact's inventory copy with the GKE API's, one listing per project; a project whose listing fails keeps the inventory
    copy and is noted under *Projects not checked* (the copy may lag)."""
    by_project = {}
    for fact in facts:
        by_project.setdefault(fact["project_id"], []).append(fact)
    for project_id, project_facts in by_project.items():
        try:
            fresh = fresh_clusters(container, project_id)
        except Exception as e:
            skipped.add(project_id, e, detail="the clusters' current state from the GKE API (the inventory copy was read instead; it can lag a maintenance-policy change)")
            continue
        for fact in project_facts:
            data = fresh.get((fact["location"], fact["name"]))
            if data is not None:
                fact["data"] = data
    return facts


def check_gke_operations(scope, scope_id, job_id, *, sink, now=None):
    """*GKE Upgrade Readiness* and *GKE Observability* from the scope's cluster and PodDisruptionBudget listings (v18.2)."""
    print(f"🔧 [{job_id}] Checking GKE upgrade readiness and observability under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        facts = list_cluster_facts(asset_client, parent)
    except Exception as e:
        logging.error(f"[{job_id}] GKE operations: could not list the clusters under {parent}: {e}")
        for check in GKE_OPERATIONS_CHECKS:
            sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    now = now or datetime.now(timezone.utc)
    skipped = NotChecked(UPGRADE_READINESS_CHECK)
    if facts:
        refresh_facts(facts, gcp.api_build("container", "v1", credentials=credentials), skipped)
    rows = [row for fact in facts for row in upgrade_readiness_rows(fact, now)]
    if facts:  # no cluster, no budget to read
        try:
            request = {"parent": parent, "asset_types": [PDB_ASSET], "content_type": asset_v1.ContentType.RESOURCE}
            rows += pdb_rows(list(asset_client.list_assets(request=request)))
        except Exception as e:
            skipped.add(parent, e, detail="PodDisruptionBudgets (the drain rule could not be applied)")
    write_rows(sink, job_id, UPGRADE_READINESS_CHECK, rows, UPGRADE_ALL_CLEAR)
    skipped.write(sink, job_id)
    write_rows(sink, job_id, OBSERVABILITY_CHECK, [row for fact in facts for row in observability_rows(fact)], OBSERVABILITY_ALL_CLEAR)
