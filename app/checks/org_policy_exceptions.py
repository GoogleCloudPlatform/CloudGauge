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
"""Organization Policy Exceptions (v19.3): the guardrails the scanned resource holds that a folder or project below it weakens.

*Organization Policies* judges the policies as *effective at the scanned resource* — true, and blind to everything below: a
folder or project can set ``enforce: false``, ``reset``, ``allowAll``, add allowed values or cut inheritance, and an organization
scan still reads Compliant. This record closes that: **one Asset Inventory listing** of ``orgpolicy.googleapis.com/Policy``
under the scope (every policy set at every level, each with its ``ancestors``), the folders and projects under the scope (one
more listing, for their ancestry and names), and the **effective policy of every container computed in memory** with Resource
Manager's own rules — boolean nearest-wins and ``reset``; list ``inheritFromParent`` merge against replace, ``allowAll`` /
``denyAll``; rules with a tag condition apply to tagged resources only. No per-project call, no new role or API
(``roles/cloudasset.viewer``). Policy Analyzer is not used (Premium-only, quota-bound; dropped by decision).

One row per policy set below the scanned resource that **weakens** the effective verdict of a constraint the bundled
best-practice table names and the scanned resource holds: unconditional → **Action Required** (the organization believes
the guardrail holds; it does not, in those projects); conditional (a tag) → Investigation. An override of a constraint the
scanned resource does not set is not a row — the gap is the scanned resource's, counted once in the Organization Policies
table. Policies set below that tighten, and policies on constraints outside the table, are one Informational count line, so
the all-clear is evidence. A project scan has nothing below it and says so. **One check in the score whatever it lists**;
the Organization Policies tally is unchanged — the exception is a different fact, a folder's or project's policy.
"""
import logging

from google.cloud import asset_v1

from app.checks.gke_operations import ACTION_REQUIRED, COMPLIANT, INFORMATIONAL, INVESTIGATION
from app.config import SCOPES
from app.services import gcp
from app.services.org_policies import POLICY_TABLE_META, fetch_best_practices, get_effective_org_policies

EXCEPTIONS_CHECK = "Organization Policy Exceptions"
POLICY_TYPE = "orgpolicy.googleapis.com/Policy"
PROJECT_TYPE = "cloudresourcemanager.googleapis.com/Project"
FOLDER_TYPE = "cloudresourcemanager.googleapis.com/Folder"
COLUMNS = ("Constraint", "Set on", "Above", "Below", "Reaches", "Issue", "Detail", "Fix")
TOP = 3
NOTHING_BELOW_PROJECT = "A project has nothing below it: the Organization Policies table is its effective policy."


def tail(name):
    return str(name or "").rsplit("/", 1)[-1]


# --- shapes: the inventory's v2 spec, the evaluator's v1 policy ---------------------------------------------------------------

def v2_to_v1(spec):
    """``(policy, conditional)`` — the v1 shape (``booleanPolicy`` / ``listPolicy`` / ``restoreDefault``) of a v2 ``spec``'s **unconditional**
    rules, or ``None`` when it has none; ``conditional`` is the v1 shape of its first rule that carries a tag condition (what it would do
    to tagged resources), or ``None``. ``inheritFromParent`` rides on the list policy as v1 carried it."""
    spec = spec or {}
    rules = spec.get("rules") or []
    unconditional = [rule for rule in rules if not rule.get("condition")]
    conditional = [rule for rule in rules if rule.get("condition")]

    def convert(rule_list):
        if spec.get("reset"):
            return {"restoreDefault": {}}
        if not rule_list:
            return None
        rule = rule_list[0]
        if "enforce" in rule:
            return {"booleanPolicy": {"enforced": bool(rule.get("enforce"))}}
        list_policy = {}
        if rule.get("allowAll"):
            list_policy["allValues"] = "ALLOW"
        elif rule.get("denyAll"):
            list_policy["allValues"] = "DENY"
        values = rule.get("values") or {}
        if values.get("allowedValues"):
            list_policy["allowedValues"] = list(values["allowedValues"])
        if values.get("deniedValues"):
            list_policy["deniedValues"] = list(values["deniedValues"])
        if spec.get("inheritFromParent"):
            list_policy["inheritFromParent"] = True
        return {"listPolicy": list_policy}

    policy = convert(unconditional) if (unconditional or spec.get("reset")) else None
    tagged = convert(conditional) if conditional and not spec.get("reset") else None
    return policy, tagged


def merge(effective, constraint, policy):
    """Applies ``policy`` (v1 shape) set on a nearer container to the ``effective`` policies (constraint → v1 policy), Resource Manager's way:
    a boolean replaces; ``restoreDefault`` removes (back to the constraint's default); a list policy with ``inheritFromParent`` merges its
    values with the parent's effective policy, without it replaces."""
    if policy is None:
        return
    if "restoreDefault" in policy:
        effective.pop(constraint, None)
        return
    if "listPolicy" in policy and policy["listPolicy"].get("inheritFromParent") and "listPolicy" in (effective.get(constraint) or {}):
        parent, child = effective[constraint]["listPolicy"], policy["listPolicy"]
        merged = {"allowedValues": sorted(set(parent.get("allowedValues") or []) | set(child.get("allowedValues") or [])),
                  "deniedValues": sorted(set(parent.get("deniedValues") or []) | set(child.get("deniedValues") or []))}
        if child.get("allValues") or parent.get("allValues"):
            merged["allValues"] = child.get("allValues") or parent.get("allValues")
        effective[constraint] = {"listPolicy": {key: value for key, value in merged.items() if value}}
        return
    effective[constraint] = policy


def judge(row, policy):
    """The Organization Policies verdict of one best-practice row against one effective policy (v1 shape or None) — the same reading as
    the report's ``evaluate_org_policies``: Compliant, Non-compliant, Not Configured."""
    expected_true = str(row.get("expectedValue", "")).lower() == "true"
    if not policy:
        return "Not Configured" if expected_true else COMPLIANT
    if row.get("type") == "List":
        list_policy = policy.get("listPolicy") or {}
        if "restoreDefault" in policy or not list_policy:
            return "Not Configured" if expected_true else COMPLIANT
        if list_policy.get("allValues") == "ALLOW":
            return "Non-compliant" if expected_true else COMPLIANT
        return COMPLIANT if expected_true else "Non-compliant"
    if "booleanPolicy" in policy:
        return COMPLIANT if str(bool(policy["booleanPolicy"].get("enforced", False))).lower() == str(row.get("expectedValue", "")).lower() else "Non-compliant"
    if "restoreDefault" in policy:
        return "Not Configured" if expected_true else COMPLIANT
    return "Unsupported"


def describe(policy):
    """``enforced`` / ``not enforced`` / ``default restored`` / ``allows all values`` / ``allows 3 values: a, b, c`` / ``not set``."""
    if not policy:
        return "not set"
    if "restoreDefault" in policy:
        return "default restored"
    if "booleanPolicy" in policy:
        return "enforced" if policy["booleanPolicy"].get("enforced") else "not enforced"
    list_policy = policy.get("listPolicy") or {}
    if list_policy.get("allValues") == "ALLOW":
        return "allows all values"
    if list_policy.get("allValues") == "DENY":
        return "denies all values"
    parts = []
    for key, verb in (("allowedValues", "allows"), ("deniedValues", "denies")):
        values = list_policy.get(key) or []
        if values:
            parts.append(f"{verb} {len(values)} value{'s' if len(values) != 1 else ''}: {', '.join(values[:TOP])}{' …' if len(values) > TOP else ''}")
    text = "; ".join(parts) or "set, no values"
    return text + (" (merged with the parent's)" if list_policy.get("inheritFromParent") else "")


# --- the hierarchy ---------------------------------------------------------------------------------------------------------------

def container_facts(assets):
    """``{container name: {"kind", "id", "label", "path"}}`` from the Project and Folder assets: ``path`` is the ancestry top-down ending in the
    container itself (``organizations/1`` → ``folders/2`` → ``projects/3``); inactive containers are left out."""
    containers = {}
    for asset in assets:
        data = getattr(getattr(asset, "resource", None), "data", None) or {}
        state = str(data.get("state") or data.get("lifecycleState") or "ACTIVE")
        if state not in ("ACTIVE", "LIFECYCLE_STATE_UNSPECIFIED"):
            continue
        ancestors = [str(a) for a in (getattr(asset, "ancestors", None) or [])]
        name = ancestors[0] if ancestors else "/".join(str(getattr(asset, "name", "")).split("/")[-2:])
        kind = name.split("/", 1)[0][:-1]
        identifier = str(data.get("projectId") or data.get("displayName") or tail(name))
        label = f"projects/{identifier}" if kind == "project" else f"{name} ({identifier})" if identifier != tail(name) else name
        containers[name] = {"kind": kind, "id": identifier, "label": label, "path": list(reversed(ancestors)) or [name]}
    return containers


def policies_by_container(assets):
    """``{container name: {constraint: (v1 policy or None, conditional v1 policy or None)}}`` from the ``orgpolicy.googleapis.com/Policy`` assets."""
    found = {}
    for asset in assets:
        name = str(getattr(asset, "name", "") or "")  # //orgpolicy.googleapis.com/<container>/policies/<constraint>
        path = name.split("//orgpolicy.googleapis.com/", 1)[-1]
        if "/policies/" not in path:
            continue
        container, constraint = path.split("/policies/", 1)
        data = getattr(getattr(asset, "resource", None), "data", None) or {}
        found.setdefault(container, {})[constraint] = v2_to_v1(data.get("spec"))
    return found


def effective_below(baseline, path_below, set_policies):
    """The effective policies (constraint → v1 policy) at the end of ``path_below`` — the containers between the scanned resource (exclusive)
    and the container itself (inclusive), top-down — starting from ``baseline`` (effective at the scanned resource)."""
    effective = dict(baseline)
    for container in path_below:
        for constraint, (policy, _) in (set_policies.get(container) or {}).items():
            merge(effective, constraint, policy)
    return effective


def restore_command(container, kind, identifier, constraint):
    flag = {"folder": f"--folder={tail(container)}", "project": f"--project={identifier}", "organization": f"--organization={tail(container)}"}[kind]
    return f"gcloud org-policies delete {constraint} {flag}"


def exception_rows(scope_name, best_practices, baseline, containers, set_policies):
    """The rows (module docstring). ``scope_name`` is the scanned container (``organizations/1`` …); ``baseline`` its effective policies."""
    table = [row for category, rows in best_practices.items() if category != POLICY_TABLE_META for row in (rows or [])]
    by_constraint = {row["policyId"]: row for row in table if row.get("policyId")}
    below = {name: facts for name, facts in containers.items() if scope_name in facts["path"] and name != scope_name}
    for facts in below.values():
        facts["below"] = facts["path"][facts["path"].index(scope_name) + 1:]
    groups, conditional = {}, {}  # (constraint, the container whose policy is the cause) → the projects it reaches
    for name, facts in below.items():
        if facts["kind"] != "project":
            continue
        effective = effective_below(baseline, facts["below"], set_policies)
        setters, tagged_setters = {}, {}  # constraint → the nearest container on the path that sets it (top-down: the later wins)
        for container in facts["below"]:
            for constraint, (policy, tagged) in (set_policies.get(container) or {}).items():
                if policy is not None:
                    setters[constraint] = container
                if tagged is not None:
                    tagged_setters.setdefault(constraint, []).append(container)
        for constraint, container in setters.items():
            row = by_constraint.get(constraint)
            if row is None or judge(row, baseline.get(constraint)) != COMPLIANT:
                continue  # outside the table, or the scanned resource's own gap (counted in its table)
            if judge(row, effective.get(constraint)) != COMPLIANT:
                groups.setdefault((constraint, container), set()).add(name)
        for constraint, places in tagged_setters.items():
            row = by_constraint.get(constraint)
            if row is None or judge(row, baseline.get(constraint)) != COMPLIANT:
                continue
            for container in places:
                probe = effective_below(baseline, facts["below"][:facts["below"].index(container)], set_policies)
                merge(probe, constraint, set_policies[container][constraint][1])
                if judge(row, probe.get(constraint)) != COMPLIANT:
                    conditional.setdefault((constraint, container), set()).add(name)
    rows = []
    for (constraint, container), projects in sorted(groups.items()):
        facts = containers.get(container) or {"kind": container.split("/", 1)[0][:-1], "id": tail(container), "label": container}
        policy, _ = set_policies[container][constraint]
        names = sorted(containers[p]["id"] for p in projects)
        reaches = (f"{len(names)} project{'s' if len(names) != 1 else ''}: {', '.join(names[:TOP])}{f' +{len(names) - TOP}' if len(names) > TOP else ''}"
                   if facts["kind"] == "folder" else "the project itself")
        rows.append({"Constraint": constraint, "Set on": facts["label"], "Above": describe(baseline.get(constraint)), "Below": describe(policy), "Reaches": reaches,
                     "Issue": "Guardrail weakened below the scanned resource.",
                     "Detail": f"{by_constraint[constraint].get('displayName', constraint)}: {describe(baseline.get(constraint))} at {scope_name}, {describe(policy)} on {facts['label']} — "
                               f"the organization believes the guardrail holds; it does not for {reaches}.",
                     "Fix": restore_command(container, facts["kind"], facts["id"], constraint) + "  # back to inheritance; a deliberate exception belongs in a rule with a tag condition, where it is scoped and visible",
                     "_status": ACTION_REQUIRED})
    for (constraint, container), projects in sorted(conditional.items()):
        if (constraint, container) in groups:
            continue
        facts = containers.get(container) or {"kind": container.split("/", 1)[0][:-1], "id": tail(container), "label": container}
        _, tagged = set_policies[container][constraint]
        names = sorted(containers[p]["id"] for p in projects if p in containers)
        rows.append({"Constraint": constraint, "Set on": facts["label"], "Above": describe(baseline.get(constraint)), "Below": f"{describe(tagged)} for tagged resources",
                     "Reaches": f"tagged resources in {len(names)} project{'s' if len(names) != 1 else ''}", "Issue": "Conditional exception below the scanned resource.",
                     "Detail": f"{by_constraint[constraint].get('displayName', constraint)}: a rule with a tag condition on {facts['label']} reads {describe(tagged)} for the resources it matches — "
                               f"a scoped exception by design; confirm the tag and who can attach it.",
                     "Fix": f"gcloud org-policies describe {constraint} {restore_command(container, facts['kind'], facts['id'], constraint).split(' ')[-1]}  # review the condition and the tag's IAM",
                     "_status": INVESTIGATION})
    # The policies set below that weaken nothing: one Informational line that names them (v20 — the line used to show "—" for
    # the constraint and a bare count, which read like a finding with a hole in it).
    other = sorted((constraint, container) for container in below for constraint in set_policies.get(container, {})
                   if (constraint, container) not in groups and (constraint, container) not in conditional)
    if other:
        def label(container):
            return containers[container]["label"] if container in containers else container
        constraints = sorted({constraint for constraint, _ in other})
        places = sorted({label(container) for _, container in other})
        listing = "; ".join(f"{constraint} on {label(container)}" for constraint, container in other[:10])
        if len(other) > 10:
            listing += f"; and {len(other) - 10} more"
        rows.append({"Constraint": constraints[0] if len(constraints) == 1 else f"{len(constraints)} constraints",
                     "Set on": places[0] if len(places) == 1 else f"{len(places)} resources below",
                     "Above": "—", "Below": "set — weakens nothing", "Reaches": "—",
                     "Issue": f"{len(other)} polic{'y' if len(other) == 1 else 'ies'} set below that weaken no guardrail.",
                     "Detail": f"{listing}. Each tightens or restates the scanned resource's policy, names a constraint the best-practice table does not, "
                               "addresses a gap the scanned resource has itself (counted in the Organization Policies table), or reaches no project. Nothing to fix.",
                     "Fix": f"gcloud asset list --{scope_name.split('/')[0][:-1]}={tail(scope_name)} --asset-types={POLICY_TYPE} --content-type=resource", "_status": INFORMATIONAL})
    return rows


def check_org_policy_exceptions(scope, scope_id, job_id, *, sink):
    """Writes *Organization Policy Exceptions* (module docstring)."""
    print(f"🪜 [{job_id}] Checking {EXCEPTIONS_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    record_name = EXCEPTIONS_CHECK.replace(" ", "_")
    if scope == "project":
        row = {column: "—" for column in COLUMNS}
        row.update({"Issue": "Nothing below a project.", "Detail": NOTHING_BELOW_PROJECT, "Fix": "—"})
        sink.write_finding(job_id, record_name, {"Check": EXCEPTIONS_CHECK, "Finding": [row], "Status": INFORMATIONAL})
        return
    try:
        best_practices = fetch_best_practices()
        baseline = get_effective_org_policies(scope, scope_id)
        if not isinstance(best_practices, dict) or not isinstance(baseline, dict):
            raise RuntimeError(f"best practices: {best_practices}" if not isinstance(best_practices, dict) else f"effective policies: {baseline}")
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        policies = list(asset_client.list_assets(request={"parent": parent, "asset_types": [POLICY_TYPE], "content_type": asset_v1.ContentType.RESOURCE}))
        hierarchy = list(asset_client.list_assets(request={"parent": parent, "asset_types": [PROJECT_TYPE, FOLDER_TYPE], "content_type": asset_v1.ContentType.RESOURCE}))
    except Exception as e:
        logging.error(f"[{job_id}] {EXCEPTIONS_CHECK}: the read under {parent} failed: {e}")
        sink.write_finding(job_id, record_name, {"Check": EXCEPTIONS_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    containers = container_facts(hierarchy)
    scope_name = parent
    if scope == "folder":  # the inventory names folders by number; a folder scan is addressed by number too
        scope_name = f"folders/{scope_id}"
    rows = exception_rows(scope_name, best_practices, baseline, containers, policies_by_container(policies))
    status = min((row["_status"] for row in rows), key={ACTION_REQUIRED: 0, INVESTIGATION: 1, INFORMATIONAL: 2}.get) if rows else COMPLIANT
    for row in rows:
        row.pop("_status", None)
    finding = rows or [{"Status": f"No policy set below {parent} weakens a guardrail it holds; nothing is set below it at all."}]
    sink.write_finding(job_id, record_name, {"Check": EXCEPTIONS_CHECK, "Finding": finding, "Status": status})


def exceptions_by_constraint(findings):
    """``{constraint: "2 exceptions (folders/…, projects/…)"}`` from a scan's findings — what the Organization Policies table shows in its
    *Below* column (``app.reporting.context``)."""
    found = {}
    for record in findings or []:
        if record.get("Check") != EXCEPTIONS_CHECK:
            continue
        for row in record.get("Finding") or []:
            constraint, where = row.get("Constraint"), row.get("Set on")
            if row.get("Above") == "—":  # the Informational line about the policies that weaken nothing (v20 names them; it is not an exception)
                continue
            if constraint and constraint != "—" and where:
                found.setdefault(constraint, []).append(where)
    return {constraint: f"{len(places)} exception{'s' if len(places) != 1 else ''} ({', '.join(places[:TOP])}{f' +{len(places) - TOP}' if len(places) > TOP else ''})" for constraint, places in found.items()}
