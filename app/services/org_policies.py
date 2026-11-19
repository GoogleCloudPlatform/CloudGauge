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
"""Organization-policy data: the best-practices CSV and effective policies.

Moved from ``cloudgauge.py`` (Phase 1). The legacy ``get_best_practices_from_gcs``
is split into ``fetch_best_practices`` (the download, which now has a timeout)
and the pure ``parse_best_practices_csv``.
"""
import csv
import hashlib
import traceback


from app.config import BEST_PRACTICES_FETCH_TIMEOUT_SECONDS, BUNDLED_POLICY_TABLE, POLICY_OVERRIDES_OBJECT, get_settings, SCOPES
from app.services import gcp
from app.utils import call_api_with_backoff, find_col_index


BOOLEAN, LIST = "Boolean", "List"
# The reserved key under which the policy table carries its provenance (v18.1): the source it came from, its digest and
# row count, and the overrides applied. ``evaluate_org_policies`` skips it; the report's Organization Policies item shows it.
POLICY_TABLE_META = "__policy_table__"
SKIP = "skip"  # an override row whose "Recommended to set" says Skip removes the bundled row of that constraint


def parse_best_practices_csv(csv_text, overrides=False):
    """
    Parses the best-practices CSV into organization policies grouped by category.
    This is the parsing half of the legacy ``get_best_practices_from_gcs``; it does no I/O.

    v18: each policy carries its ``type`` — ``Boolean`` or ``List``, from the CSV's *Type*
    column (``Boolean`` when the column is missing or blank). The report evaluates the two
    kinds differently (``app.reporting.context.evaluate_org_policies``); before v18 every
    row was evaluated as boolean, which 62 list constraints could never satisfy.

    v18.1: ``overrides=True`` parses an operator's overrides table (``POLICY_OVERRIDES_OBJECT``):
    the same columns, plus *Skip* in "Recommended to set", which yields ``{"policyId": ..., "skip": True}``.

    Args:
        csv_text (str): The contents of the CSV file.
        overrides (bool): Whether *Skip* rows are kept (as skips) instead of dropped.

    Returns:
        dict: A dictionary of best practices grouped by category.

    Raises:
        KeyError: If none of the names for a required column is in the header.
    """
    reader = csv.reader(csv_text.splitlines())
    header_map = {h.strip().lower(): i for i, h in enumerate(next(reader))}
    
    id_col = find_col_index(header_map, ['id', 'constraint'])
    name_col = find_col_index(header_map, ['display name', 'policy', 'policy name', 'name', 'policy display name', 'displayname'])
    rec_col = find_col_index(header_map, ['recommended to set *'])
    type_col = header_map.get('type')

    best_practices_by_category = {}
    current_category = "Uncategorized"
    policies_added = 0 

    for row in reader:
        if len([c for c in row if c.strip()]) == 1:
            current_category = row[0].strip()
            if current_category not in best_practices_by_category:
                best_practices_by_category[current_category] = []
            continue
            
        if len(row) > max(id_col, name_col, rec_col) and row[id_col].strip():
            
            
            recommendation_text = row[rec_col].strip().lower()
            expected_value = None

            if "should have" in recommendation_text or "must have" in recommendation_text or "could have" in recommendation_text:
                expected_value = "True"
            elif "wont have" in recommendation_text or "won't have" in recommendation_text:
                expected_value = "False"
            elif overrides and recommendation_text == SKIP:
                best_practices_by_category.setdefault(current_category, []).append({"policyId": row[id_col].strip(), SKIP: True})
                continue
            
            # We still use "is not None" to correctly include policies that are "False"
            if expected_value is not None:
                if current_category not in best_practices_by_category: 
                    best_practices_by_category[current_category] = []
                
                kind = row[type_col].strip().capitalize() if type_col is not None and len(row) > type_col else ""
                best_practices_by_category[current_category].append({
                    "policyId": row[id_col].strip(), 
                    "displayName": row[name_col].strip(), 
                    "expectedValue": expected_value,
                    "type": LIST if kind == LIST else BOOLEAN,
                })
                policies_added += 1
            

    print(f"✅ CSV parsing complete. Loaded {policies_added} policies into the checker.")
    return best_practices_by_category


def read_policy_table(source, timeout=BEST_PRACTICES_FETCH_TIMEOUT_SECONDS):
    """The text of the policy table at ``source``: the bundled file (``BUNDLED_POLICY_TABLE``), a ``gs://bucket/object``
    read with the scanner's own identity, or an ``https://`` URL fetched anonymously (the legacy way)."""
    if source in (None, "", BUNDLED_POLICY_TABLE):
        return gcp.policy_table()
    if source.startswith("gs://"):
        bucket_name, _, object_name = source[len("gs://"):].partition("/")
        return gcp.storage_client().bucket(bucket_name).blob(object_name).download_as_text()
    response = gcp.http_get(source, timeout=timeout)
    response.raise_for_status()
    return response.text


def read_policy_overrides(results_bucket):
    """The operator's overrides table from the results bucket (``POLICY_OVERRIDES_OBJECT``), or ``None`` when there is none.

    An object that exists but cannot be read is an error, not a table silently scored without it: the operator put it there.
    """
    if not results_bucket:
        return None
    blob = gcp.storage_client().bucket(results_bucket).blob(POLICY_OVERRIDES_OBJECT)
    if not blob.exists():
        return None
    try:
        return blob.download_as_text()
    except Exception as e:
        raise RuntimeError(f"could not read the policy overrides at gs://{results_bucket}/{POLICY_OVERRIDES_OBJECT}: {e}") from e


def apply_policy_overrides(best_practices, overrides):
    """Merges an overrides table into the policy table, by constraint ID (v18.1).

    A *Skip* row removes the constraint wherever it is; any other row replaces the constraint's entry in place
    (its category stays) or, for a constraint the table does not have, adds it under the override's category.
    Returns ``(table, applied, skipped)``.
    """
    table = {category: list(policies) for category, policies in best_practices.items() if category != POLICY_TABLE_META}
    applied = skipped = 0
    for category, entries in overrides.items():
        for entry in entries:
            policy_id = entry["policyId"]
            if entry.get(SKIP):
                for policies in table.values():
                    policies[:] = [p for p in policies if p["policyId"] != policy_id]
                skipped += 1
                continue
            replaced = False
            for policies in table.values():
                for index, policy in enumerate(policies):
                    if policy["policyId"] == policy_id:
                        policies[index], replaced = dict(entry), True
            if not replaced:
                table.setdefault(category or "Custom", []).append(dict(entry))
            applied += 1
    return table, applied, skipped


def policy_table_digest(text):
    """A short digest of the table's text: the release notes name the bundled table's, the report shows the one in use."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def fetch_best_practices(url=None, timeout=BEST_PRACTICES_FETCH_TIMEOUT_SECONDS, results_bucket=None):
    """
    Reads and parses the policy table the Organization Policies check evaluates.

    v18.1: the table ships with the release (``BUNDLED_POLICY_TABLE``, the default of
    ``BEST_PRACTICES_CSV_URL``), so a scan never depends on GitHub and the rules change only
    with a release; ``BEST_PRACTICES_CSV_URL`` set to a ``gs://`` or ``https://`` source replaces
    it; the operator's overrides at ``gs://<results bucket>/config/best_practices_overrides.csv``
    are merged on top (``apply_policy_overrides``). The result carries its provenance under
    ``POLICY_TABLE_META``.

    Args:
        url (str, optional): The table's source; the setting when omitted.
        timeout (float): Seconds to wait for an HTTPS source.
        results_bucket (str, optional): Where the overrides live; the setting when omitted.

    Returns:
        dict: The policy table by category, plus ``POLICY_TABLE_META``.
        str: An error message if the table could not be read or parsed.
    """
    print("⬇️  Reading the policy table...")
    try:
        settings = get_settings()
        source = url if url is not None else settings.best_practices_csv_url
        text = read_policy_table(source, timeout=timeout)
        table = parse_best_practices_csv(text)
        meta = {"source": BUNDLED_POLICY_TABLE if source in (None, "", BUNDLED_POLICY_TABLE) else source,
                "digest": policy_table_digest(text), "rows": sum(len(v) for v in table.values()), "overrides": None}
        bucket = results_bucket if results_bucket is not None else settings.results_bucket
        overrides_text = read_policy_overrides(bucket)
        if overrides_text is not None:
            table, applied, skipped = apply_policy_overrides(table, parse_best_practices_csv(overrides_text, overrides=True))
            meta["overrides"] = {"source": f"gs://{bucket}/{POLICY_OVERRIDES_OBJECT}", "applied": applied, "skipped": skipped}
            print(f"   -> {applied} override(s) applied, {skipped} row(s) skipped from {meta['overrides']['source']}")
        table[POLICY_TABLE_META] = meta
        return table

    except Exception as e:
        return f"Error reading or parsing the policy table: {e}"


def describe_policy_table(meta):
    """One line for the report: *bundled table (138 rows, 3f2a9c1b0e4d) · 4 overrides, 1 skipped (gs://…)*."""
    if not isinstance(meta, dict):
        return ""
    source = meta.get("source")
    text = f"{'bundled table' if source == BUNDLED_POLICY_TABLE else source} ({meta.get('rows', '?')} rows, {meta.get('digest', '?')})"
    overrides = meta.get("overrides")
    if overrides:
        text += f" · {overrides.get('applied', 0)} override{'' if overrides.get('applied', 0) == 1 else 's'}"
        if overrides.get("skipped"):
            text += f", {overrides['skipped']} skipped"
        text += f" ({overrides.get('source', '')})"
    return text


def get_effective_org_policies(scope, scope_id):
    """
    Calculates the effective organization policies for a resource by manually
    traversing its ancestry and merging policies - top-down, so a folder's policy
    replaces the organization's and a project's replaces both. This avoids the
    low daily quota of the Cloud Asset Policy Analyzer API.

    Args:
        scope (str): The scope ('organization', 'folder', 'project').
        scope_id (str): The ID of the resource.

    Returns:
        dict: A dictionary of effective organization policies, keyed by policy ID.
        str: An error message if fetching fails.
    """
    print(f"🔍 Calculating effective policies for {scope} '{scope_id}' by traversing hierarchy...")
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        # Main client remains v1 for compatibility with listOrgPolicies
        crm_service = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)

        # --- START OF MODIFICATION ---
        # Initialize a separate v3 client specifically to bypass the v1 'get' bug for folder
        crm_v3_service = gcp.api_build('cloudresourcemanager', 'v3', credentials=credentials)
        # --- END OF MODIFICATION ---

        def list_policies_for_resource(resource_str):
            """The policies set on one resource, keyed by constraint ID.

            v18: a level that cannot be listed (a 403, say) stops the calculation with an error — every
            policy would otherwise read as *Not Configured* with nothing in the report to say why.
            """
            policies, errors = {}, []
            api_call = lambda: crm_service.organizations().listOrgPolicies(resource=resource_str, body={}).execute() if resource_str.startswith('organizations/') else \
                             crm_service.folders().listOrgPolicies(resource=resource_str, body={}).execute() if resource_str.startswith('folders/') else \
                             crm_service.projects().listOrgPolicies(resource=resource_str, body={}).execute()
            response = call_api_with_backoff(api_call, context_message=f"listOrgPolicies for {resource_str}", on_error=errors.append)
            if errors:
                raise RuntimeError(f"could not list the policies set on {resource_str}: {errors[0]}")
            for policy in (response or {}).get('policies', []):
                if full_path := policy.get('constraint'):
                    policies[full_path.split('/')[-1]] = policy
            return policies

        # The walk is top-down - organization, folders, then the resource itself - and a
        # nearer resource's policy replaces a farther one's, the way Resource Manager
        # evaluates boolean constraints. (v15.3: project scans applied the ancestry as
        # getAncestry lists it, bottom-up, so the organization's policy overrode a folder's.)
        effective_policies = {}
        resource_hierarchy = []

        if scope == 'organization':
            resource_hierarchy.append(f"organizations/{scope_id}")
        elif scope == 'project':
            # getAncestry lists the project first and the organization last.
            ancestry = crm_service.projects().getAncestry(projectId=scope_id, body={}).execute()
            lineage = [f"{ancestor['resourceId']['type']}s/{ancestor['resourceId']['id']}"
                       for ancestor in ancestry.get('ancestor', [])]
            project = f"projects/{scope_id}"
            resource_hierarchy = [resource for resource in reversed(lineage) if resource != project] + [project]
        elif scope == 'folder':
            ancestors = []
            curr_folder = f"folders/{scope_id}"
            while curr_folder:
                ancestors.append(curr_folder)
                # --- THIS IS CHANGE FOR FOLDER FIX ---
                # Use the new v3 client for the 'get' call, which does not have the bug
                folder_details = crm_v3_service.folders().get(name=curr_folder).execute()
                # --- END OF CHANGE ---
                parent = folder_details.get('parent')
                if parent and parent.startswith('organizations/'):
                    ancestors.append(parent)
                    break
                curr_folder = parent
            resource_hierarchy = list(reversed(ancestors))

        if not resource_hierarchy:
            return f"Could not determine hierarchy for {scope} {scope_id}"

        print(f"   -> Traversing hierarchy: {' -> '.join(resource_hierarchy)}")
        for resource_str in resource_hierarchy:
            policies_at_level = list_policies_for_resource(resource_str)
            effective_policies.update(policies_at_level)

        print(f"✅ Successfully calculated {len(effective_policies)} effective policies.")
        return effective_policies

    except Exception as e:
        traceback.print_exc()
        return f"A critical error occurred in get_effective_org_policies: {e}"
