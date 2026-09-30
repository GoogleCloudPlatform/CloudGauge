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
"""Project, location, and organization discovery.

Moved from ``cloudgauge.py`` (Phase 1); GCP clients now come from
``app.services.gcp``. ``list_resources_for_scope`` is the body of the legacy
``/api/list-resources`` route without the HTTP handling.
"""
import concurrent.futures
import logging
import traceback

from google.cloud import asset_v1

from app.config import SCOPES
from app.services import gcp


def list_projects_for_scope(scope, scope_id):
    """
    Retrieves a list of all ACTIVE projects within a given scope (org, folder, or project)
    using the recursive Cloud Asset Inventory API for complete coverage.
    """
    print(f"📋 Listing projects for {scope} '{scope_id}' using Cloud Asset Inventory...")

    # The single-project case remains the fastest method for that specific scope.
    if scope == 'project':
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            service = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
            project = service.projects().get(projectId=scope_id).execute()
            if project.get('lifecycleState') == 'ACTIVE':
                print(f"✅ Found 1 ACTIVE project.")
                # Return in the same format as the Asset API for consistency
                return [{'projectId': project['projectId'], 'displayName': project.get('name', project['projectId'])}]
            else:
                print("⚠️ Project is not ACTIVE.")
                return []
        except Exception as e:
            print(f"❌ Error fetching single project: {e}")
            return []

    # --- NEW RECURSIVE LOGIC USING CLOUD ASSET API ---
    try:
        asset_client = asset_v1.AssetServiceClient()

        # Define the parent scope for the asset search
        parent_scope_map = {
            'organization': f'organizations/{scope_id}',
            'folder': f'folders/{scope_id}'
        }
        asset_search_scope = parent_scope_map.get(scope)
        if not asset_search_scope:
            print(f"❌ Invalid scope '{scope}' provided for asset search.")
            return []

        # Perform a single, recursive search for all projects
        response = asset_client.search_all_resources(
            request={
                "scope": asset_search_scope,
                "asset_types": ["cloudresourcemanager.googleapis.com/Project"],
                "query": "state:ACTIVE", # Filter for active projects at the API level
            }
        )

        # Process the results into the expected format
        all_projects = []
        for resource in response:
            # The project ID is part of the full resource name
            project_id = resource.name.split('/')[-1]
            all_projects.append({
                'projectId': project_id,
                'displayName': resource.display_name
            })
        
        print(f"✅ Found {len(all_projects)} ACTIVE projects recursively.")
        return all_projects

    except Exception as e:
        logging.error(f"❌ Critical error listing projects with Cloud Asset API: {e}")
        traceback.print_exc()
        return []


def get_active_compute_locations(all_projects):
    """
    Discovers active GCP zones and regions by scanning for various compute resources
    across all projects in the organization. This helps focus subsequent checks
    on relevant locations.

    Args:
        org_id (str): The ID of the organization.
        all_projects (list): A list of project dictionaries.

    Returns:
        tuple: A tuple containing two lists: (active_zones, active_regions).
    """
    print("📍 Discovering active compute zones and regions...")
    active_zones, active_regions = set(), set()

    def scan_project(project):
        project_id = project['projectId']
        try:
            credentials, _ = gcp.auth_default(scopes=SCOPES)
            compute = gcp.api_build('compute', 'v1', credentials=credentials)
            
            # Method 1: Discover zones from VM instances AND infer their regions
            req = compute.instances().aggregatedList(project=project_id)
            while req:
                resp = req.execute()
                for scope, result in resp.get('items', {}).items():
                    if scope.startswith('zones/') and result.get('instances'):
                        zone = scope.split('/')[-1]
                        active_zones.add(zone)
                        # Your suggestion: Infer region from zone (e.g., 'us-central1-a' -> 'us-central1')
                        active_regions.add('-'.join(zone.split('-')[:-1]))
                req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)

            # Method 2: Discover regions from reserved IP Addresses (your suggestion)
            req = compute.addresses().aggregatedList(project=project_id)
            while req:
                resp = req.execute()
                for scope, result in resp.get('items', {}).items():
                    if scope.startswith('regions/') and result.get('addresses'):
                        active_regions.add(scope.split('/')[-1])
                req = compute.addresses().aggregatedList_next(previous_request=req, previous_response=resp)

            # Method 3: Discover regions from Forwarding Rules (Load Balancers)
            req = compute.forwardingRules().aggregatedList(project=project_id)
            while req:
                resp = req.execute()
                for scope, result in resp.get('items', {}).items():
                    if scope.startswith('regions/') and result.get('forwardingRules'):
                        active_regions.add(scope.split('/')[-1])
                req = compute.forwardingRules().aggregatedList_next(previous_request=req, previous_response=resp)

        except Exception as e:
            logging.warning(f"Could not scan locations for project {project_id}: {e}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(scan_project, all_projects)

    # Add 'global' as it's a valid location for some recommenders
    active_regions.add('global')
    
    print(f"✅ Discovered {len(active_zones)} active zones and {len(active_regions)} active regions.")
    return list(active_zones), list(active_regions)


def get_parent_org(project_id):
    """Finds the parent organization of the current project."""
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('cloudresourcemanager', 'v1', credentials=credentials)
        ancestry = service.projects().getAncestry(projectId=project_id, body={}).execute()
        for resource in ancestry.get('ancestor', []):
            if resource.get('resourceId', {}).get('type') == 'organization':
                return resource['resourceId']['id']
    except Exception as e:
        print(f"⚠️ Could not automatically determine organization ID: {e}")
    return None


class InvalidScopeError(ValueError):
    """Raised for a scope other than 'organization', 'folder', or 'project'."""


def list_resources_for_scope(scope, org_id):
    """
    Lists the organization, or the folders or projects under it, for the scope picker.
    This is the body of the legacy ``/api/list-resources`` route; the route keeps
    the HTTP handling (400 for an invalid scope, 500 for other errors).

    Returns:
        list: ``[{"id": ..., "name": ...}]``, sorted by name.

    Raises:
        InvalidScopeError: If ``scope`` is not recognized.
    """
    resources = []
    asset_client = asset_v1.AssetServiceClient()
    parent_scope = f"organizations/{org_id}"

    if scope == 'organization':
        resources.append({"id": org_id, "name": f"Organization {org_id}"})
        return resources

    asset_type_map = {
        'folder': 'cloudresourcemanager.googleapis.com/Folder',
        'project': 'cloudresourcemanager.googleapis.com/Project'
    }

    asset_type = asset_type_map.get(scope)
    if not asset_type:
        raise InvalidScopeError("Invalid scope")

    print(f"🔍 Searching for assets of type '{asset_type}' under organization '{org_id}'...")
    response = asset_client.search_all_resources(
        request={
            "scope": parent_scope,
            "asset_types": [asset_type],
        }
    )

    for resource in response:
        display_name = resource.display_name
        if scope == 'project':
            # For projects, the name is the project ID
            project_id = resource.name.split('/')[-1]
            resources.append({"id": project_id, "name": f"{display_name} ({project_id})"})
        else: # For folders
            folder_id = resource.name.split('/')[-1]
            resources.append({"id": folder_id, "name": f"{display_name}"})

    # Sort resources by name
    resources.sort(key=lambda x: x['name'])
    print(f"✅ Found {len(resources)} resources.")
    return resources
