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
"""Every name a check can write must be in CATEGORY_MAP, or its findings vanish from the report.

This is how B1 (the Security Command Center result was written as "Security
Command Center" but mapped as "... Status") and B2 (error results written under
unmapped names) went unnoticed. The names are collected from the check modules'
source, so a new check or error path with an unmapped name fails here.
"""
import ast
import pathlib
from types import SimpleNamespace

import pytest

from app.checks import categories, cost, network, registry, runner
from app.checks.categories import CATEGORY_MAP, categorize_findings

CHECKS_DIR = pathlib.Path(categories.__file__).parent
# "Check" values that are loop variables over a name table; the tables are checked below.
DYNAMIC_NAMES = {
    ('cost.py', 'check_name'): cost.COST_RECOMMENDERS,
    ('network.py', 'check_name'): network.NETWORK_INSIGHT_TYPES,
    ('runner.py', 'check_name'): None,  # the registry display names (test_registry_names_...)
    ('not_checked.py', 'NOT_CHECKED'): None,  # carries its own "Category" (test_not_checked_record_...)
}
# The registry's "Special" category is the Organization Policies check, shown under Security.
REGISTRY_CATEGORY = {'Special': 'Security & Identity'}


def _check_values(tree):
    """Yields ``(function, value_node)`` for every ``{"Check": value}`` in the module."""
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(func):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and key.value == 'Check':
                        yield func, value


def _string_constants(func):
    """``NAME = "literal"`` assignments inside ``func`` (e.g. ``CHECK_NAME``)."""
    constants = {}
    for node in ast.walk(func):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
    return constants


def _module_constants(tree):
    """``NAME = "literal"`` assignments at the top level of the module (e.g. ``INCIDENTS_CHECK``)."""
    constants = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
    return constants


def emitted_check_names():
    """``{name: [locations]}`` for every "Check" value the check modules can write."""
    names, unresolved = {}, []
    for path in sorted(CHECKS_DIR.glob('*.py')):
        tree = ast.parse(path.read_text(), filename=str(path))
        module_constants = _module_constants(tree)
        for func, value in _check_values(tree):
            where = f'{path.name}:{value.lineno} ({func.name})'
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                names.setdefault(value.value, []).append(where)
            elif isinstance(value, ast.Name) and value.id in _string_constants(func):
                names.setdefault(_string_constants(func)[value.id], []).append(where)
            elif isinstance(value, ast.Name) and (path.name, value.id) in DYNAMIC_NAMES:
                for name in DYNAMIC_NAMES[(path.name, value.id)] or ():
                    names.setdefault(name, []).append(where)
            elif isinstance(value, ast.Name) and value.id in module_constants:
                names.setdefault(module_constants[value.id], []).append(where)
            else:
                unresolved.append(f'{where}: {ast.unparse(value)}')
    assert not unresolved, f'Add these "Check" values to DYNAMIC_NAMES or use a literal/constant: {unresolved}'
    return names


def registry_specs(scope):
    return registry.build_check_plan(scope, 'scope-id', 'job-id', [], [], [])


def test_every_name_a_check_writes_is_mapped():
    names = emitted_check_names()
    assert len(names) > 40  # sanity: the source scan found the checks
    unmapped = {name: where for name, where in names.items() if name not in CATEGORY_MAP}
    assert not unmapped, f'Findings with these names are dropped from the report: {unmapped}'


@pytest.mark.parametrize('scope', ['project', 'folder', 'organization'])
def test_registry_names_map_to_their_category(scope):
    """The runner records a crashed check under its display name, in the check's own category."""
    for spec in registry_specs(scope):
        expected = REGISTRY_CATEGORY.get(spec.category, spec.category)
        assert CATEGORY_MAP.get(spec.name) == expected, spec.name


def test_runner_error_names_come_from_the_registry():
    """Guards DYNAMIC_NAMES['runner.py']: the runner's error "Check" is the spec name."""
    source = pathlib.Path(runner.__file__).read_text()
    assert 'return {"Check": check_name, "Finding": [{"Error": message}], "Status": "Error"}' in source
    assert 'check_name = future_to_info[future]["name"]' in source
    assert 'record_error(sink, job_id, check_name, str(e))' in source


def test_categories_are_the_report_sections():
    assert set(CATEGORY_MAP.values()) == {'Security & Identity', 'Cost Optimization',
                                          'Reliability & Resilience', 'Operational Excellence & Observability'}


# --- B1 / B2 end to end: the findings now reach their report section ---

@pytest.mark.parametrize('check, category', [
    ('Security Command Center Status', 'Security & Identity'),       # B1
    ('Log Sink Check', 'Operational Excellence & Observability'),    # B2: check's own error result
    ('Organization IAM Policy Check', 'Security & Identity'),
    ('Resilience Asset Checks', 'Reliability & Resilience'),
    ('Organization Policies', 'Security & Identity'),
    ('Network Insights', 'Operational Excellence & Observability'),  # B2: runner error, display name
    ('Cost-Saving Recommendations', 'Cost Optimization'),
])
def test_error_and_scc_findings_are_categorized(check, category):
    finding = {'Check': check, 'Finding': [{'Error': 'permission denied'}], 'Status': 'Error'}
    assert categorize_findings([finding])[category] == [finding]


# --- "Projects not checked": one name, the record's own category ---

def test_not_checked_record_is_categorized_by_its_own_category():
    """Guards DYNAMIC_NAMES['not_checked.py']: the record is not in CATEGORY_MAP; its "Category" decides."""
    from app.checks.not_checked import NOT_CHECKED, NotChecked

    assert NOT_CHECKED not in CATEGORY_MAP
    records = []
    for check_name in ('Open Firewall Rules', 'Cost-Saving Recommendations', 'GKE Hygiene', 'Network Insights'):
        skipped = NotChecked(check_name)
        skipped.add('p-1', RuntimeError('403 denied'))
        skipped.write(SimpleNamespace(write_finding=lambda job, name, record: records.append(record)), 'job')
    by_category = categorize_findings(records)
    assert [r['Finding'][0]['Skipped check'] for r in by_category['Security & Identity']] == ['Open Firewall Rules']
    assert [r['Finding'][0]['Skipped check'] for r in by_category['Cost Optimization']] == ['Cost-Saving Recommendations']
    assert [r['Finding'][0]['Skipped check'] for r in by_category['Reliability & Resilience']] == ['GKE Hygiene']
    assert [r['Finding'][0]['Skipped check'] for r in by_category['Operational Excellence & Observability']] == ['Network Insights']
    # A record with a category the report does not have is dropped, like an unmapped name.
    assert all(v == [] for v in categorize_findings([{**records[0], 'Category': 'Nowhere'}]).values())
    with pytest.raises(KeyError):
        NotChecked('Not a check name')
