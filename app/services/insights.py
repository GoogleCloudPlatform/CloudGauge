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
"""On-demand cost-optimization insights (the ``/api/get-insights`` scan).

``run_cost_optimization_insights`` was nested inside the legacy route; it is
moved here unchanged.
"""
import logging

from app.services import gcp
from app.services.resource_manager import get_active_compute_locations, list_projects_for_scope


def run_cost_optimization_insights(scope, scope_id):
    print("💡 Performing on-demand detailed INSIGHT scan...")
    all_findings = []
    all_projects = list_projects_for_scope(scope, scope_id)
    if not all_projects:
        return []
    
    active_zones, active_regions = get_active_compute_locations(all_projects)
    recommender_client = gcp.recommender_client()

    
    global_insights = {
        "Idle Images": "google.compute.image.IdleResourceInsight",
    }
    regional_insights = {
        "Unassociated IP Addresses": "google.compute.address.IdleResourceInsight",
        "Idle Cloud SQL Instances": "google.cloudsql.instance.IdleInsight",
    }
    zonal_insights = {
        "Idle Disks": "google.compute.disk.IdleResourceInsight",
        "VM CPU Usage": "google.compute.instance.CpuUsageInsight",
        "VM CPU Prediction": "google.compute.instance.CpuUsagePredictionInsight",
        "VM Memory Usage": "google.compute.instance.MemoryUsageInsight",
        "VM Memory Prediction": "google.compute.instance.MemoryUsagePredictionInsight",
        "VM Bandwidth": "google.compute.instance.NetworkThroughputInsight",
        "MIG CPU Usage": "google.compute.instanceGroupManager.CpuUsageInsight",
        "MIG Memory Usage": "google.compute.instanceGroupManager.MemoryUsageInsight",
    }
    
    for project in all_projects:
        project_id = project['projectId']
        
        # Scan for GLOBAL insights
        for check_name, insight_type_id in global_insights.items():
            parent = f"projects/{project_id}/locations/global/insightTypes/{insight_type_id}"
            try:
                insights = recommender_client.list_insights(parent=parent)
                for insight in insights:
                    resource_name = insight.target_resources[0].split('/')[-1] if insight.target_resources else 'N/A'
                    all_findings.append({"check": check_name, "project": project_id, "resource": resource_name, "details": insight.description})
            except Exception as e: logging.warning(f"Could not check global insight for {project_id}: {e}")

        # Scan for REGIONAL insights
        for loc in active_regions:
            for check_name, insight_type_id in regional_insights.items():
                parent = f"projects/{project_id}/locations/{loc}/insightTypes/{insight_type_id}"
                try:
                    insights = recommender_client.list_insights(parent=parent)
                    for insight in insights:
                        resource_name = insight.target_resources[0].split('/')[-1] if insight.target_resources else 'N/A'
                        all_findings.append({"check": check_name, "project": project_id, "resource": resource_name, "details": insight.description})
                except Exception as e: logging.warning(f"Could not check regional insight for {project_id}: {e}")
        
        # Scan for ZONAL insights
        for loc in active_zones:
            for check_name, insight_type_id in zonal_insights.items():
                parent = f"projects/{project_id}/locations/{loc}/insightTypes/{insight_type_id}"
                try:
                    insights = recommender_client.list_insights(parent=parent)
                    for insight in insights:
                        resource_name = insight.target_resources[0].split('/')[-1] if insight.target_resources else 'N/A'
                        all_findings.append({"check": check_name, "project": project_id, "resource": resource_name, "details": insight.description})
                except Exception as e: logging.warning(f"Could not check zonal isnight for {project_id}: {e}")
    
    return all_findings
