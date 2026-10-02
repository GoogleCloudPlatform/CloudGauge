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
"""The check plan: which checks run, in what order, with which arguments.

A check doesn't know how it is run: this module lists the checks, and
``app.checks.runner`` executes them. To add a check, write it in one of the
``app.checks`` modules, add a ``CheckSpec`` below, and add the names it
reports to ``app.checks.categories.CATEGORY_MAP``.
"""
import functools
from typing import Any, Callable, NamedTuple

from app.checks.cost import run_cost_recommendations
from app.checks.network import run_network_insights
from app.checks.operations import (
    check_audit_logging,
    check_monitoring_coverage,
    check_os_config_coverage,
    check_standalone_vms,
    run_miscellaneous_checks_refactored,
    run_service_limit_checks_refactored,
)
from app.checks.reliability import (
    check_essential_contacts,
    check_gke_hygiene,
    check_resilience_assets,
    check_service_health_status,
    check_storage_versioning,
)
from app.checks.security import (
    check_cloud_sql_security,
    check_open_firewall_rules,
    check_org_iam_policy,
    check_organization_policies,
    check_project_iam_policy,
    check_public_buckets,
    check_sa_key_rotation,
    check_scc_status,
    check_storage_ubla,
    check_vm_external_ips,
    check_vpc_configuration,
)


class CheckSpec(NamedTuple):
    """One planned check: ``(Category, Friendly Name, function_to_run, (tuple_of_arguments,))``."""

    category: str
    name: str
    func: Callable[..., Any]
    args: tuple


def build_check_plan(scope, scope_id, job_id, all_projects, active_zones, active_regions):
    """
    Returns the ordered list of checks to run for a scan, as ``CheckSpec`` entries.
    The 18 common and 6 organization-only checks, their order, and their arguments
    are the same as in upstream beta v1's ``run_all_checks``: the legacy plan plus
    four Security checks at the end of the common list. The runner calls each one as
    ``func(*args, sink=...)``.
    """
    # --- This structured list is the key to accurate progress reporting ---
    # Format: (Category, Friendly Name, function_to_run, (tuple_of_arguments,))
    all_checks_to_run = [
        CheckSpec("Special", "Organization Policies", check_organization_policies, (scope, scope_id, job_id)),
        CheckSpec("Security & Identity", "Project IAM Hygiene", check_project_iam_policy, (scope_id, all_projects, job_id)),
        CheckSpec("Security & Identity", "Service Account Key Rotation", check_sa_key_rotation, (scope_id, all_projects, job_id)),
        CheckSpec("Security & Identity", "Public GCS Buckets", check_public_buckets, (scope_id, all_projects, job_id)),
        CheckSpec("Security & Identity", "Open Firewall Rules", check_open_firewall_rules, (scope_id, all_projects, job_id)),
        CheckSpec("Cost Optimization", "Cost-Saving Recommendations", run_cost_recommendations, (scope_id, all_projects, active_zones, active_regions, job_id)),
        CheckSpec("Reliability & Resilience", "GCS Bucket Versioning", check_storage_versioning, (scope_id, all_projects, job_id)),
        CheckSpec("Reliability & Resilience", "GKE Hygiene", check_gke_hygiene, (scope_id, all_projects, job_id)),
        CheckSpec("Operational Excellence & Observability", "OS Config Agent Coverage", check_os_config_coverage, (scope_id, all_projects, job_id)),
        CheckSpec("Operational Excellence & Observability", "Monitoring Alert Coverage", check_monitoring_coverage, (scope_id, all_projects, job_id)),
        CheckSpec("Operational Excellence & Observability", "Standalone VMs", check_standalone_vms, (scope_id, all_projects, job_id)),
        CheckSpec("Operational Excellence & Observability", "Network Insights", run_network_insights, (scope_id, all_projects, active_zones, active_regions, job_id)),
        CheckSpec("Operational Excellence & Observability", "Miscellaneous Checks", run_miscellaneous_checks_refactored, (scope, scope_id, all_projects, job_id)),
        CheckSpec("Operational Excellence & Observability", "Service Quota Limits", run_service_limit_checks_refactored, (scope_id, all_projects, job_id)),
        CheckSpec("Security & Identity", "Cloud SQL Security", check_cloud_sql_security, (scope_id, all_projects, job_id)),
        CheckSpec("Security & Identity", "VPC Configuration", check_vpc_configuration, (scope_id, all_projects, job_id)),
        CheckSpec("Security & Identity", "GCS Uniform Bucket-Level Access", check_storage_ubla, (scope_id, all_projects, job_id)),
        CheckSpec("Security & Identity", "VM External IPs", check_vm_external_ips, (scope_id, all_projects, job_id)),
    ]

    if scope == 'organization':
        org_only_checks = [
            CheckSpec("Security & Identity", "Organization IAM Policy", check_org_iam_policy, (scope_id, job_id)),
            CheckSpec("Security & Identity", "Security Command Center Status", check_scc_status, (scope_id, job_id)),
            CheckSpec("Operational Excellence & Observability", "Organization Audit Logging", check_audit_logging, (scope_id, job_id)),
            CheckSpec("Reliability & Resilience", "Essential Contacts", check_essential_contacts, (scope_id, job_id)),
            CheckSpec("Reliability & Resilience", "Resilience of Critical Assets", check_resilience_assets, (scope_id, job_id)),
            CheckSpec("Reliability & Resilience", "Personalized Service Health", check_service_health_status, (scope_id, job_id)),
        ]
        all_checks_to_run.extend(org_only_checks)

    return all_checks_to_run


# Checks that look at the scope itself rather than at its projects. A sharded
# scan (app.fanout) runs them once, in the "scope" shard, and the project checks
# once per shard of projects. Rule: a check is scope-level iff its arguments
# don't include the project list (tests/test_fanout.py verifies this agrees).
SCOPE_LEVEL_CHECKS = frozenset({
    "Organization Policies", "Organization IAM Policy", "Security Command Center Status",
    "Organization Audit Logging", "Essential Contacts", "Resilience of Critical Assets", "Personalized Service Health",
})
# The one check that does both: organization-wide insights plus per-project work.
# Shards split it with its keyword flags (see run_miscellaneous_checks_refactored).
MISCELLANEOUS_CHECK = "Miscellaneous Checks"


def scope_check_plan(scope, scope_id, job_id):
    """The scope-level checks of :func:`build_check_plan`: Organization Policies, plus, for an
    organization, the org-only checks and the organization-wide half of the miscellaneous checks."""
    plan = [spec for spec in build_check_plan(scope, scope_id, job_id, [], [], []) if spec.name in SCOPE_LEVEL_CHECKS]
    if scope == 'organization':
        plan.append(CheckSpec("Operational Excellence & Observability", MISCELLANEOUS_CHECK,
                              functools.partial(run_miscellaneous_checks_refactored, project_checks=False),
                              (scope, scope_id, [], job_id)))
    return plan


def project_check_plan(scope, scope_id, job_id, projects, active_zones, active_regions):
    """The project-level checks of :func:`build_check_plan`, over ``projects`` only."""
    plan = []
    for spec in build_check_plan(scope, scope_id, job_id, projects, active_zones, active_regions):
        if spec.name in SCOPE_LEVEL_CHECKS:
            continue
        if spec.name == MISCELLANEOUS_CHECK:
            spec = spec._replace(func=functools.partial(spec.func, org_insights=False))
        plan.append(spec)
    return plan


def shard_check_names(scope, scope_level):
    """The names of the checks a shard owns: the scope shard's (``scope_level``) or a project shard's.

    Pure (no clients, no network), so it works even when the shard itself could
    not run: a sharded scan records one error row per name for such a shard.
    """
    plan = scope_check_plan(scope, "", "") if scope_level else project_check_plan(scope, "", "", [], [], [])
    return [spec.name for spec in plan]
