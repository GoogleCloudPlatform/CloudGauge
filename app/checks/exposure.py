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
"""Incident Exposure (v17.3): what the customer ran, without failover, in a location where the
product it ran had an incident.

A Google Cloud incident is not the customer's configuration, so the Service Health
briefing never counts toward the score. What *is* the customer's is a zonal Cloud SQL
instance, a zonal MIG, a zonal GKE control plane or a single-zone node pool, a snapshot
kept in one region - and Personalized Service Health says, per incident, which products
and which locations it touched. Joined, the two make one finding the customer can act on:
*this asset had no failover, and on this date its location had an incident in its product*.

The check is **derived**: ``with_incident_exposure`` runs at categorization
(``app.checks.categories.categorize_findings``, the one place both a sharded and an
inline scan pass through) over records already in the scan - the *Service Health
Incidents* rows on one side, the resilience checks' rows on the other - so it costs no
API call. Rows are asset-centric: one per asset (snapshots grouped per project and
location) with the incidents as evidence, so the row count is the number of exposed
assets and the Scorecard's Stability line can say so. An asset's identity is the asset,
not its incidents (``app.reporting.changes.EXCLUDED_COLUMNS``): the window slides, the
finding stays.

Matching rules:

- an incident is *location-specific* when its locations cover at least one and fewer
  than ``categories.GLOBAL_REGION_COUNT`` regions; a global product incident matches
  nothing, because no failover answers it, and one with no location given has nothing
  to meet;
- the incident's **product** must map to the asset's kind (``PRODUCT_CHECKS``): a Compute
  Engine incident meets zonal MIGs and single-region snapshots, not Cloud SQL instances.
  Incidents in products the tool has no footprint for are counted in the note under the
  table, never matched by location alone;
- the asset's **project** is one the incident touched, and its **location** is one of the
  incident's: a zone counts for its region on both sides.

Statuses: *Action Required* with rows; *Compliant* when location-specific incidents in a
mapped product touched the scanned projects and every asset there had failover;
*Informational* when none did (nothing to assess - the six Resilience checks keep
flagging the assets). The briefing's ``Error`` is this check's ``Error``; with the briefing
switched off (``SERVICE_HEALTH_INCIDENTS=off``) the check does not exist.
"""
from app.checks import categories
from app.config import get_settings

INCIDENT_EXPOSURE_CHECK = "Incident Exposure"
INCIDENTS_CHECK = "Service Health Incidents"  # app.checks.service_health.INCIDENTS_CHECK (kept literal: no import of that module here)
GKE_RESILIENCE_CHECK = "GKE Cluster Resilience"
# The footprint: check name -> (asset kind, name column, location column). The kind of a GKE row is its Issue.
FOOTPRINT = {
    "Cloud SQL High Availability": ("zonal Cloud SQL instance", "Instance", "Region"),
    "MIG Resilience (Zonal)": ("zonal MIG", "MIG Name", "Zone"),
    "Disk Snapshot Resilience": ("single-region snapshot", "Snapshot", "Location"),
    GKE_RESILIENCE_CHECK: (None, "Cluster", "Location"),
}
SNAPSHOT_CHECK = "Disk Snapshot Resilience"
# Personalized Service Health product names (matched case-insensitively as substrings) -> the footprint they meet.
PRODUCT_CHECKS = {
    "compute engine": ("MIG Resilience (Zonal)", SNAPSHOT_CHECK),
    "persistent disk": ("MIG Resilience (Zonal)", SNAPSHOT_CHECK),
    "kubernetes engine": (GKE_RESILIENCE_CHECK,),
    "cloud sql": ("Cloud SQL High Availability",),
}
MAPPED_PRODUCTS_TEXT = "Compute Engine, Persistent Disk, Google Kubernetes Engine or Cloud SQL"
INCIDENTS_COLUMN = "Incidents"
ASSET_COLUMN = "Asset"
MAX_INCIDENTS_LISTED = 5


def mapped_checks(products):
    """The footprint checks the incident's ``products`` (comma-separated text) meet, in ``FOOTPRINT`` order."""
    names = [p.strip().lower() for p in str(products or "").split(",") if p.strip()]
    found = {check for name in names for key, checks in PRODUCT_CHECKS.items() if key in name for check in checks}
    return [check for check in FOOTPRINT if check in found]


def location_matches(incident_locations, asset_location):
    """Whether ``asset_location`` (a zone or a region) is one of the incident's: a zone counts for its region."""
    asset_location = str(asset_location or "").strip()
    if not asset_location:
        return False
    locations = set(categories._split_list(incident_locations))
    return asset_location in locations or any(region in categories.regions_of(incident_locations) for region in categories.regions_of([asset_location]))


def incident_label(row):
    """``"2026-10-13 Google Compute Engine, Google Kubernetes Engine (asia-south1, one of 11 regions)"``."""
    started = str(row.get(categories.INCIDENT_STARTED) or "")[:10]
    regions = categories.regions_of(row.get("Locations"))
    where = regions[0] if len(regions) == 1 else (f"{len(regions)} regions" if regions else "no location")
    return f"{started} {row.get('Products') or row.get('Incident') or ''} ({where})".strip()


def fix_for(check, project, name, location, row):
    """The remediation line of an exposed asset: the owning check's, or the mechanical one for its kind."""
    if row.get("Fix"):
        return str(row["Fix"])
    region = (categories.regions_of([location]) or [location])[0]
    if check == "Cloud SQL High Availability":
        return f"gcloud sql instances patch {name} --project={project} --availability-type=REGIONAL"
    if check == "MIG Resilience (Zonal)":
        return (f"Recreate {name} as a regional MIG: gcloud compute instance-groups managed create {name} --project={project} "
                f"--region={region} --template=<template> --size=<size>; a zonal group cannot be made regional in place.")
    if check == SNAPSHOT_CHECK:
        return ("Store new snapshots in a multi-region: --storage-location=asia, eu or us on gcloud compute snapshots create and on "
                "the snapshot schedule; existing snapshots cannot be moved.")
    return ""


def footprint_rows(findings):
    """``{check name: [row, ...]}`` for the footprint checks, from the records in ``findings`` (all-clear rows left out)."""
    rows = {check: [] for check in FOOTPRINT}
    for record in findings:
        check = record.get("Check")
        if check not in FOOTPRINT or not isinstance(record.get("Finding"), list):
            continue
        name_column = FOOTPRINT[check][1]
        rows[check].extend(row for row in record["Finding"] if isinstance(row, dict) and row.get(name_column))
    return rows


def incident_rows(findings):
    """The briefing's incident rows (those with an incident ID), and whether the briefing is in ``Error``."""
    rows, error = [], None
    for record in findings:
        if record.get("Check") != INCIDENTS_CHECK:
            continue
        if record.get("Status") == "Error":
            error = next((str(row.get("Error")) for row in record.get("Finding") or [] if isinstance(row, dict) and row.get("Error")), "the incidents could not be read")
        for row in record.get("Finding") or []:
            if isinstance(row, dict) and row.get(categories.INCIDENT_ID):
                rows.append(row)
    return rows, error


def exposure_rows(incidents, footprint):
    """The asset-centric rows, the count of location-specific incidents that met a footprint and the products
    without one: ``(rows, assessed, unmapped)``."""
    exposures, assessed, unmapped = {}, 0, []
    for incident in incidents:
        if not categories.is_location_specific(incident.get("Locations")):  # global, or no location given: nothing to meet
            continue
        checks = mapped_checks(incident.get("Products"))
        if not checks:
            unmapped.append(incident)
            continue
        assessed += 1
        projects = set(categories._split_list(incident.get(categories.INCIDENT_PROJECTS)))
        label = incident_label(incident)
        for check in checks:
            kind, name_column, location_column = FOOTPRINT[check]
            for row in footprint[check]:
                project, location = str(row.get("Project") or ""), str(row.get(location_column) or "")
                if project not in projects or not location_matches(incident.get("Locations"), location):
                    continue
                name, issue = str(row.get(name_column)), str(row.get("Issue") or "")
                # One row per asset: snapshots are grouped per project and location; a cluster has one row per issue.
                key = (project, check, location, "" if check == SNAPSHOT_CHECK else (f"{name} {issue}" if kind is None else name))
                entry = exposures.setdefault(key, {"row": row, "incidents": [], "names": set(), "name": name, "issue": issue})
                entry["names"].add(name)
                if label not in entry["incidents"]:
                    entry["incidents"].append(label)
    rows = []
    for (project, check, location, _), entry in exposures.items():
        kind = FOOTPRINT[check][0]
        if check == SNAPSHOT_CHECK:
            count = len(entry["names"])
            asset = f"{count} single-region snapshot{'s' if count != 1 else ''}"
        elif kind is None:
            asset = f"cluster {entry['name']} ({entry['issue'].lower()})" if entry["issue"] else f"cluster {entry['name']}"
        else:
            asset = f"{kind} {entry['name']}"
        name = entry["name"]
        listed = entry["incidents"][:MAX_INCIDENTS_LISTED]
        more = len(entry["incidents"]) - len(listed)
        rows.append({"Project": project, ASSET_COLUMN: asset, "Location": location,
                     INCIDENTS_COLUMN: "; ".join(listed) + (f"; and {more} more" if more else ""),
                     "Fix": fix_for(check, project, name, location, entry["row"])})
    rows.sort(key=lambda r: (r["Project"], r["Location"], r[ASSET_COLUMN]))
    return rows, assessed, unmapped


def with_incident_exposure(findings):
    """``findings`` plus the Incident Exposure record, when the scan has a Service Health briefing (idempotent)."""
    findings = list(findings)
    if not any(record.get("Check") == INCIDENTS_CHECK for record in findings) or any(record.get("Check") == INCIDENT_EXPOSURE_CHECK for record in findings):
        return findings
    incidents, error = incident_rows(findings)
    if error:
        findings.append({"Check": INCIDENT_EXPOSURE_CHECK, "Finding": [{"Error": error}], "Status": "Error"})
        return findings
    rows, assessed, unmapped = exposure_rows(incidents, footprint_rows(findings))
    days = get_settings().service_health_window_days
    if rows:
        record = {"Check": INCIDENT_EXPOSURE_CHECK, "Finding": rows, "Status": "Action Required"}
    elif assessed:
        record = {"Check": INCIDENT_EXPOSURE_CHECK, "Status": "Compliant",
                  "Finding": [{"Status": f"{assessed} location-specific incident{'s' if assessed != 1 else ''} in {MAPPED_PRODUCTS_TEXT} "
                                         f"touched the scanned projects in the last {days} days; every asset there had failover."}]}
    else:
        record = {"Check": INCIDENT_EXPOSURE_CHECK, "Status": "Informational",
                  "Finding": [{"Summary": f"No location-specific incident in {MAPPED_PRODUCTS_TEXT} touched the scanned projects in the "
                                          f"last {days} days: nothing to assess. The six Resilience checks cover the footprint itself."}]}
    if unmapped:
        products = sorted({p.strip() for incident in unmapped for p in str(incident.get("Products") or "").split(",") if p.strip()})
        record[categories.NOTE_KEY] = (f"{len(unmapped)} location-specific incident{'s' if len(unmapped) != 1 else ''} in products this check "
                                       f"has no footprint for ({', '.join(products)}) {'are' if len(unmapped) != 1 else 'is'} listed under "
                                       f"Service Health Incidents.")
    findings.append(record)
    return findings
