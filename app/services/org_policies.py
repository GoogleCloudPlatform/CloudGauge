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
import logging
import traceback


from app.config import BEST_PRACTICES_FETCH_TIMEOUT_SECONDS, get_settings, SCOPES
from app.services import gcp
from app.utils import call_api_with_backoff, find_col_index


def parse_best_practices_csv(csv_text):
    """
    Parses the best-practices CSV into boolean organization policies grouped by category.
    This is the parsing half of the legacy ``get_best_practices_from_gcs``; it does no I/O.

    Args:
        csv_text (str): The contents of the CSV file.

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
            elif "wont have" in recommendation_text:
                expected_value = "False"
            
            # We still use "is not None" to correctly include policies that are "False"
            if expected_value is not None:
                if current_category not in best_practices_by_category: 
                    best_practices_by_category[current_category] = []
                
                best_practices_by_category[current_category].append({
                    "policyId": row[id_col].strip(), 
                    "displayName": row[name_col].strip(), 
                    "expectedValue": expected_value
                })
                policies_added += 1
            

    print(f"✅ CSV parsing complete. Loaded {policies_added} boolean policies into the checker.")
    return best_practices_by_category


def fetch_best_practices(url=None, timeout=BEST_PRACTICES_FETCH_TIMEOUT_SECONDS):
    """
    Downloads and parses a CSV file of GCP best practices from a public GCS URL.
    It categorizes boolean organization policies to be used for compliance checking.
    (Legacy name: ``get_best_practices_from_gcs``. The URL now defaults to the
    ``BEST_PRACTICES_CSV_URL`` setting, and the download has a timeout.)

    Args:
        url (str, optional): The public URL to the best practices CSV file.
        timeout (float): Seconds to wait for the server before giving up.

    Returns:
        dict: A dictionary of best practices grouped by category.
        str: An error message if the download or parsing fails.
    """
    print("⬇️  Downloading best practices...")
    try:
        if url is None:
            url = get_settings().best_practices_csv_url
        response = gcp.http_get(url, timeout=timeout)
        response.raise_for_status()
        return parse_best_practices_csv(response.text)

    except Exception as e:
        return f"Error downloading or parsing CSV: {e}"


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
            """Helper to fetch and format policies for a given resource string."""
            policies = {}
            try:
                api_call = lambda: crm_service.organizations().listOrgPolicies(resource=resource_str, body={}).execute() if resource_str.startswith('organizations/') else \
                                 crm_service.folders().listOrgPolicies(resource=resource_str, body={}).execute() if resource_str.startswith('folders/') else \
                                 crm_service.projects().listOrgPolicies(resource=resource_str, body={}).execute()
                response = call_api_with_backoff(api_call, context_message=f"listOrgPolicies for {resource_str}")
                for policy in response.get('policies', []):
                    if full_path := policy.get('constraint'):
                        policies[full_path.split('/')[-1]] = policy
            except Exception as e:
                logging.warning(f"Could not list policies for {resource_str}: {e}")
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
