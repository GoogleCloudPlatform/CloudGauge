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
"""GKE Supported Versions (v15): clusters and node pools on versions GKE no longer offers.

``GKE Hygiene`` says whether a cluster is on a release channel and auto-upgrades;
this check says whether what it runs is still supported. The reference is the
server's own view, ``projects.locations.getServerConfig``: the versions it still
offers in that location, as a static list (``validMasterVersions`` /
``validNodeVersions``) and per release channel (``channels[].validVersions``).
A cluster on a channel is judged against its channel's list, a cluster without
one against the static lists. The end-of-support *date* is not in the API (it
is on the release-schedule page), so the check speaks of what is offered:

- **Action Required** - the control plane or a node pool runs a minor that is
  no longer in its list ("1.27 is no longer offered; the oldest supported minor
  is 1.29").
- **Investigation Recommended** - it runs the oldest minor in the list: the
  next to leave support.
- A minor newer than anything in the list (a preview, a list that lags) is not
  flagged: the check never invents an alarm.

One row per component (``Project · Cluster · Location · Component · Version ·
Issue``) with a ``Fix`` per row: the ``gcloud container clusters upgrade``
command to the newest patch of the oldest supported minor (the next minor for
the Investigation rows), which the report shows once per distinct command in
the Fix block under the table. GKE upgrades a control plane one minor at a
time, so a plane more than one minor behind says so in its row. A node pool's
target never exceeds its control plane's version.

The server config is read once per location (it does not vary by project).
A project in which the GKE API is disabled has no clusters and is left out;
any other failure is reported as "Projects not checked". The row identity
used by *Changes since last scan* leaves the ``Version`` column out
(``app.reporting.changes``): a pool is the same finding after a patch, and a
different one once it is on another kind of issue.
"""
import re

from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp

CHECK_NAME = "GKE Supported Versions"
CONTAINER_API = "container.googleapis.com"
CONTROL_PLANE = "Control plane"
# GKE version strings: "1.29.12-gke.1234567"; the minor is "1.29".
VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:-gke\.(\d+))?")


def minor_of(version):
    """``"1.29"`` of ``"1.29.12-gke.1234567"``, or ``None`` when the version does not parse."""
    match = VERSION.match(str(version or ""))
    return f"{match.group(1)}.{match.group(2)}" if match else None


def version_key(version):
    """Sort key of a GKE version: numeric major, minor, patch and gke build (``None`` for an unparsable one)."""
    match = VERSION.match(str(version or ""))
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def minor_key(minor):
    return version_key(minor)[:2]


def channel_versions(server_config, channel):
    """The ``validVersions`` of ``channel`` in the server config, or ``None`` when it is not a channel the config knows."""
    if channel and channel != "UNSPECIFIED":
        for entry in server_config.get("channels", []):
            if entry.get("channel") == channel:
                return list(entry.get("validVersions", []))
    return None


def supported_versions(server_config, channel, component):
    """The versions GKE still offers to ``component`` (``"master"`` or ``"node"``) of a cluster on ``channel``.

    The channel's ``validVersions`` when the cluster is on a channel the server
    config knows; otherwise the static list for the component.
    """
    versions = channel_versions(server_config, channel)
    if versions is not None:
        return versions
    return list(server_config.get("validMasterVersions" if component == "master" else "validNodeVersions", []))


def newest_patch(minor, versions):
    """The newest offered version of ``minor`` among ``versions``, or ``None``."""
    candidates = [v for v in versions if minor_of(v) == minor and version_key(v)]
    return max(candidates, key=version_key) if candidates else None


def assess(version, versions, where=""):
    """``(status, issue, target version)`` for a component on ``version`` given the ``versions`` offered, or ``None`` when it is fine.

    ``where`` names the list when it is a channel's (``" on the Regular channel"``),
    so the row says why a minor still offered elsewhere counts as gone. ``target
    version`` is where an upgrade should go (``None`` when the list offers nothing
    newer); the caller turns it into the ``gcloud`` command.
    """
    minor = minor_of(version)
    minors = sorted({m for m in (minor_of(v) for v in versions) if m}, key=minor_key)
    if minor is None or not minors:
        return None  # nothing to judge, or nothing to judge against
    oldest = minors[0]
    if minor not in minors:
        if minor_key(minor) > minor_key(minors[-1]):
            return None  # newer than anything offered: not an end-of-support problem
        return "Action Required", f"{minor} is no longer offered{where}; the oldest supported minor is {oldest}.", newest_patch(oldest, versions)
    if minor == oldest:
        target = newest_patch(minors[1], versions) if len(minors) > 1 else None
        return "Investigation Recommended", f"{minor} is the oldest supported minor{where}: the next to leave support.", target
    return None


def upgrade_command(project_id, cluster, location, target, node_pool=None):
    """The ``gcloud`` command that upgrades the control plane (or ``node_pool``) of ``cluster`` to ``target``."""
    what = f"--node-pool={node_pool}" if node_pool else "--master"
    return f"gcloud container clusters upgrade {cluster} --location={location} --project={project_id} {what} --cluster-version={target}"


def more_than_one_minor_apart(version, target):
    """Whether upgrading ``version`` to ``target`` crosses more than one minor (a control plane cannot do that in one step)."""
    (major, minor), (target_major, target_minor) = minor_key(minor_of(version)), minor_key(minor_of(target))
    return target_major > major or target_minor - minor > 1


def cluster_rows(project_id, cluster, server_config):
    """The finding rows of one cluster (empty when every component runs a supported, not-oldest minor)."""
    name, location = cluster.get("name"), cluster.get("location")
    channel = (cluster.get("releaseChannel") or {}).get("channel")
    where = f" on the {channel.capitalize()} channel" if channel_versions(server_config, channel) is not None else ""
    master_version = cluster.get("currentMasterVersion")
    rows = []

    def row(component, version, verdict, node_pool=None):
        status, issue, target = verdict
        if node_pool and target and version_key(master_version) and version_key(target) > version_key(master_version):
            # A node pool cannot run ahead of its control plane: go as far as the
            # plane allows, or nowhere when the plane is on the same minor.
            if minor_key(minor_of(master_version)) > minor_key(minor_of(version)):
                target = master_version
            else:
                target, issue = None, issue + " Upgrade the control plane first."
        if not node_pool and target and more_than_one_minor_apart(version, target):
            issue += " Control planes upgrade one minor at a time."
        fix = upgrade_command(project_id, name, location, target, node_pool) if target else ""
        rows.append({"Project": project_id, "Cluster": name, "Location": location, "Component": component,
                     "Version": version, "Issue": issue, "Fix": fix, "_status": status})

    verdict = assess(master_version, supported_versions(server_config, channel, "master"), where)
    if verdict:
        row(CONTROL_PLANE, master_version, verdict)
    node_versions = supported_versions(server_config, channel, "node")
    for pool in cluster.get("nodePools", []):
        verdict = assess(pool.get("version"), node_versions, where)
        if verdict:
            row(f"Node pool {pool.get('name')}", pool.get("version"), verdict, node_pool=pool.get("name"))
    return rows


def check_gke_supported_versions(scope_id, all_projects, job_id, *, sink):
    """Writes the check's record (and the projects it could not check) for every project in ``all_projects``."""
    print(f"🚢 [{job_id}] Checking {CHECK_NAME} in {len(all_projects)} projects...")
    skipped = NotChecked(CHECK_NAME, resource_apis=(CONTAINER_API,))
    credentials, _ = gcp.auth_default(scopes=SCOPES)
    container = gcp.api_build("container", "v1", credentials=credentials)
    configs = {}  # location -> server config: the same in every project

    def server_config(project_id, location):
        if location not in configs:
            configs[location] = container.projects().locations().getServerConfig(name=f"projects/{project_id}/locations/{location}").execute()
        return configs[location]

    rows = []
    for project in all_projects:
        project_id = project["projectId"]
        try:
            clusters = container.projects().locations().clusters().list(parent=f"projects/{project_id}/locations/-").execute().get("clusters", [])
        except Exception as e:
            skipped.add(project_id, e)
            continue
        for cluster in clusters:
            try:
                config = server_config(project_id, cluster.get("location"))
            except Exception as e:
                skipped.add(project_id, e, detail=f"clusters in {cluster.get('location')}")
                continue
            rows.extend(cluster_rows(project_id, cluster, config))

    statuses = {row.pop("_status") for row in rows}
    if "Action Required" in statuses:
        result = {"Check": CHECK_NAME, "Finding": rows, "Status": "Action Required"}
    elif rows:
        result = {"Check": CHECK_NAME, "Finding": rows, "Status": "Investigation Recommended"}
    else:
        # One note, without counts: the notes of a sharded scan merge into one (app.checks.categories).
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All GKE clusters and node pools run supported versions."}], "Status": "Compliant"}
    sink.write_finding(job_id, CHECK_NAME.replace(" ", "_"), result)
    skipped.write(sink, job_id)
