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


from app.config import SCOPES
from app.services import gcp


def project_number_of(project_resource):
    """The number in Asset Search's ``project`` field (``"projects/123"`` -> ``"123"``); ``""`` when absent."""
    value = str(project_resource or '').strip()
    return value.split('/')[-1] if value.startswith('projects/') else ''


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
                return [{'projectId': project['projectId'], 'displayName': project.get('name', project['projectId']),
                         'projectNumber': str(project.get('projectNumber') or '')}]
            else:
                print("⚠️ Project is not ACTIVE.")
                return []
        except Exception as e:
            print(f"❌ Error fetching single project: {e}")
            return []

    # --- NEW RECURSIVE LOGIC USING CLOUD ASSET API ---
    try:
        asset_client = gcp.asset_client()

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
            # The project ID is part of the full resource name; ``project`` is "projects/<number>"
            project_id = resource.name.split('/')[-1]
            all_projects.append({
                'projectId': project_id,
                'displayName': resource.display_name,
                'projectNumber': project_number_of(getattr(resource, 'project', '')),
                'parent': parent_of(getattr(resource, 'parent_full_resource_name', '')),
            })
        
        print(f"✅ Found {len(all_projects)} ACTIVE projects recursively.")
        if scope == 'folder':
            all_projects = reconcile_folder_projects(scope_id, all_projects)
        return all_projects

    except Exception as e:
        logging.error(f"❌ Critical error listing projects with Cloud Asset API: {e}")
        traceback.print_exc()
        return []


# --- Folder membership (v15.4) ---
#
# A folder scan finds its projects with Cloud Asset Inventory search, which is recursive
# (nested folders included) but eventually consistent: a project moved into the folder,
# or created in it, was missing from the search for an hour in practice, and one moved
# out lingers as long. Resource Manager is authoritative and immediate but lists one
# level at a time. So a folder scan also asks Resource Manager for the folder's direct
# child projects - one call - and reconciles the two lists:
#
# - a project Resource Manager lists in the folder that Asset Inventory did not return is
#   scanned too (``RESOURCE_MANAGER_ONLY``);
# - a project Asset Inventory places directly in the folder that Resource Manager no
#   longer lists there (moved out or deleted) is kept and marked (``ASSET_INVENTORY_ONLY``):
#   Resource Manager only lists what the scanner may read, so dropping it could hide a
#   project for a permission gap rather than a move.
#
# Projects in nested folders are Asset Inventory's word alone; a mismatch there would
# take a folder walk to see. The report says what was reconciled (``folder_membership``);
# when the two agree, which is the normal case, it says nothing.
MEMBERSHIP = 'membership'  # the key on a reconciled project dict; absent when both sources list the project
RESOURCE_MANAGER_ONLY = 'resource-manager-only'
ASSET_INVENTORY_ONLY = 'asset-inventory-only'
RESOURCE_MANAGER_PAGE_SIZE = 300


def parent_of(parent_full_resource_name):
    """Asset Search's parent (``"//cloudresourcemanager.googleapis.com/folders/123"``) as ``"folders/123"``; ``""`` when absent."""
    value = str(parent_full_resource_name or '').strip()
    return value.rsplit('.googleapis.com/', 1)[-1] if value else ''


def list_folder_children(folder_id):
    """The folder's direct child projects per Resource Manager (v3 ``projects.list``), ``{project_id: project dict}``.

    Returns None when they could not be listed; the caller then leaves Asset Inventory's list alone.
    """
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build('cloudresourcemanager', 'v3', credentials=credentials)
        children, page_token = {}, None
        while True:
            response = service.projects().list(parent=f'folders/{folder_id}', pageSize=RESOURCE_MANAGER_PAGE_SIZE,
                                               pageToken=page_token).execute()
            for project in response.get('projects', []):
                if project.get('state', 'ACTIVE') == 'ACTIVE' and project.get('projectId'):
                    children[project['projectId']] = {
                        'projectId': project['projectId'],
                        'displayName': project.get('displayName') or project['projectId'],
                        'projectNumber': project_number_of(project.get('name', '')),
                        'parent': f'folders/{folder_id}',
                    }
            page_token = response.get('nextPageToken')
            if not page_token:
                return children
    except Exception as e:
        logging.warning(f"⚠️ Could not list the folder's projects with Resource Manager; folder membership not checked: {e}")
        return None


def reconcile_folder_projects(folder_id, projects):
    """Reconciles a folder scan's Asset Inventory project list with Resource Manager's direct children.

    Returns the projects to scan: ``projects``, with the ones Asset Inventory places directly in the folder
    but Resource Manager does not list there marked ``ASSET_INVENTORY_ONLY``, followed by the direct children
    Asset Inventory did not return, marked ``RESOURCE_MANAGER_ONLY``. ``projects`` as given when Resource
    Manager could not be asked.
    """
    children = list_folder_children(folder_id)
    if children is None:
        return projects
    parent = f'folders/{folder_id}'
    listed = {project['projectId'] for project in projects}
    reconciled = [dict(project, **{MEMBERSHIP: ASSET_INVENTORY_ONLY})
                  if project.get('parent') == parent and project['projectId'] not in children else project
                  for project in projects]
    added = [dict(child, **{MEMBERSHIP: RESOURCE_MANAGER_ONLY}) for project_id, child in children.items() if project_id not in listed]
    membership = folder_membership(reconciled + added)
    if membership:
        print(f"⚠️ Folder membership: Cloud Asset Inventory and Resource Manager disagree on folder {folder_id}. "
              f"Added from Resource Manager (not yet in Asset Inventory): {', '.join(membership['added']) or 'none'}. "
              f"Listed by Asset Inventory only (no longer in the folder per Resource Manager): {', '.join(membership['unlisted']) or 'none'}.")
    return reconciled + added


def folder_membership(projects):
    """What a folder scan reconciled, for the report: ``{"added": [ids], "unlisted": [ids]}`` (sorted), or None when nothing was.

    ``added``: projects Resource Manager lists in the folder that Asset Inventory did not return (scanned);
    ``unlisted``: projects Asset Inventory places directly in the folder that Resource Manager no longer does (scanned, noted).
    """
    added = sorted(p['projectId'] for p in projects if isinstance(p, dict) and p.get(MEMBERSHIP) == RESOURCE_MANAGER_ONLY)
    unlisted = sorted(p['projectId'] for p in projects if isinstance(p, dict) and p.get(MEMBERSHIP) == ASSET_INVENTORY_ONLY)
    return {'added': added, 'unlisted': unlisted} if added or unlisted else None


def get_active_compute_locations(all_projects, on_error=None):
    """
    Discovers active GCP zones and regions by scanning for various compute resources
    across all projects in the organization. This helps focus subsequent checks
    on relevant locations.

    Args:
        all_projects (list): A list of project dictionaries.
        on_error (callable): Called as ``on_error(project_id, error)`` for a project
            whose resources could not be listed. Such a project adds no locations, so
            the location-based checks query it only at the locations found in other
            projects, or nowhere; given the failures, they report it as not checked
            (see ``app.checks.not_checked``).

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
            if on_error is not None:
                on_error(project_id, e)
    
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


def folder_labels(folders):
    """Folder ID → ``"parent / child (id)"`` for the picker: the folder's path from the organization down, then its ID.

    ``folders`` maps a folder ID to ``(display_name, parent_id)``; ``parent_id`` is a folder ID, or ``None`` for a
    folder whose parent is the organization or unknown (Asset Search did not report one). An ancestor missing
    from ``folders`` (outside the account's view) starts the path lower. Folder display names are unique only
    among siblings, so the path and the ID tell two "Engineering" folders apart.
    """
    labels = {}
    for folder_id, (display_name, parent_id) in folders.items():
        path, seen, ancestor = [display_name], {folder_id}, parent_id
        while ancestor in folders and ancestor not in seen:
            seen.add(ancestor)
            path.append(folders[ancestor][0])
            ancestor = folders[ancestor][1]
        labels[folder_id] = f"{' / '.join(reversed(path))} ({folder_id})"
    return labels


def list_resources_for_scope(scope, org_id):
    """
    Lists the organization, or the active folders or projects under it, for the scope picker.
    This is the body of the legacy ``/api/list-resources`` route; the route keeps
    the HTTP handling (400 for an invalid scope, 500 for other errors).

    One Asset Inventory search per call, restricted to ``state:ACTIVE`` (v15.6; before, a
    folder pending deletion was still offered). A project is named ``"Display name (project-id)"``;
    a folder by its path from the organization down and its ID, ``"Engineering / Platform (4711)"``
    (``folder_labels``), from the parent each search result reports.

    Returns:
        list: ``[{"id": ..., "name": ...}]``, sorted by name.

    Raises:
        InvalidScopeError: If ``scope`` is not recognized.
    """
    resources = []
    asset_client = gcp.asset_client()
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

    print(f"🔍 Searching for active assets of type '{asset_type}' under organization '{org_id}'...")
    response = asset_client.search_all_resources(
        request={
            "scope": parent_scope,
            "asset_types": [asset_type],
            "query": "state:ACTIVE",
        }
    )

    if scope == 'project':
        for resource in response:
            # For projects, the name is the project ID
            project_id = resource.name.split('/')[-1]
            resources.append({"id": project_id, "name": f"{resource.display_name} ({project_id})"})
    else:
        folders = {}
        for resource in response:
            parent = getattr(resource, 'parent_full_resource_name', '') or ''
            parent_id = parent.split('/')[-1] if '/folders/' in parent else None
            folders[resource.name.split('/')[-1]] = (resource.display_name, parent_id)
        resources.extend({"id": folder_id, "name": label} for folder_id, label in folder_labels(folders).items())

    # Sort resources by name
    resources.sort(key=lambda x: x['name'])
    print(f"✅ Found {len(resources)} resources.")
    return resources
