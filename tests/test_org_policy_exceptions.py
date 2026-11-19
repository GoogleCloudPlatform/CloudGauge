"""
v19.3 — Organization Policy Exceptions: the shapes (v2 spec → v1 policy), Resource Manager's inheritance rules, the verdicts (agreeing with the
report's evaluator), the rows on a fixture hierarchy (folder and project overrides, conditional, reset, tightening, out-of-table, the
scanned resource's own gap), the check end to end at every scope, and the Below column / Scorecard sentence the report derives from it.
"""
from types import SimpleNamespace

from app.checks import org_policy_exceptions as ope
from app.checks.gke_operations import ACTION_REQUIRED as AR, COMPLIANT, INFORMATIONAL as INFO, INVESTIGATION as IR
from app.checks.not_checked import NOT_CHECKED
from app.checks.org_policy_exceptions import (COLUMNS, EXCEPTIONS_CHECK, NOTHING_BELOW_PROJECT, check_org_policy_exceptions, container_facts, describe, effective_below,
                                              exception_rows, exceptions_by_constraint, judge, merge, policies_by_container, v2_to_v1)
from app.reporting.context import PolicyResult, evaluate_org_policies
from app.services.org_policies import POLICY_TABLE_META
from fakes import ORG_ID as ORG

JOB = 'job-193'
ORG_NAME = f'organizations/{ORG}'
F1, F2 = 'folders/1061', 'folders/2062'  # F2 under F1
P1, P2, P3 = ('projects/111', 'web-prod'), ('projects/222', 'data-lake'), ('projects/333', 'sandbox')  # P1, P2 under F2; P3 directly under the organization
OS_LOGIN, EXT_IP, DOMAINS, KEYS = 'compute.requireOsLogin', 'compute.vmExternalIpAccess', 'iam.allowedPolicyMemberDomains', 'iam.disableServiceAccountKeyCreation'

TABLE = {'Compute': [{'policyId': OS_LOGIN, 'displayName': 'Require OS Login', 'expectedValue': 'True', 'type': 'Boolean'},
                     {'policyId': EXT_IP, 'displayName': 'Define allowed external IPs for VM instances', 'expectedValue': 'True', 'type': 'List'}],
         'IAM': [{'policyId': DOMAINS, 'displayName': 'Domain restricted sharing', 'expectedValue': 'True', 'type': 'List'},
                 {'policyId': KEYS, 'displayName': 'Disable service account key creation', 'expectedValue': 'True', 'type': 'Boolean'}],
         POLICY_TABLE_META: {'source': 'bundled'}}
BASELINE = {OS_LOGIN: {'booleanPolicy': {'enforced': True}}, EXT_IP: {'listPolicy': {'allValues': 'DENY'}}, DOMAINS: {'listPolicy': {'allowedValues': ['C0example']}}}  # KEYS not set: the organization's own gap


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_check(self):
        return {record['Check']: record for _, record in self.records if record['Check'] != NOT_CHECKED}


def container(name, ancestors, project_id=None, display=None, state='ACTIVE'):
    data = {'projectId': project_id, 'lifecycleState': state} if project_id else {'displayName': display, 'state': state}
    return SimpleNamespace(name=f'//cloudresourcemanager.googleapis.com/{name}', asset_type=f"cloudresourcemanager.googleapis.com/{'Project' if project_id else 'Folder'}", ancestors=ancestors,
                           resource=SimpleNamespace(data=data))


def policy(container_name, ancestors, constraint, spec):
    return SimpleNamespace(name=f'//orgpolicy.googleapis.com/{container_name}/policies/{constraint}', asset_type='orgpolicy.googleapis.com/Policy', ancestors=ancestors,
                           resource=SimpleNamespace(data={'name': f'{container_name}/policies/{constraint}', 'spec': spec}))


HIERARCHY = [container(F1, [F1, ORG_NAME], display='Platform'), container(F2, [F2, F1, ORG_NAME], display='Dev'),
             container(P1[0], [P1[0], F2, F1, ORG_NAME], project_id=P1[1]), container(P2[0], [P2[0], F2, F1, ORG_NAME], project_id=P2[1]),
             container(P3[0], [P3[0], ORG_NAME], project_id=P3[1]), container('folders/999', ['folders/999', ORG_NAME], display='Gone', state='DELETE_REQUESTED')]
POLICIES = [policy(ORG_NAME, [ORG_NAME], OS_LOGIN, {'rules': [{'enforce': True}]}),  # the organization's own: never "below"
            policy(F2, [F2, F1, ORG_NAME], OS_LOGIN, {'rules': [{'enforce': False}]}),  # a folder switches a held guardrail off → reaches web-prod and data-lake
            policy(P1[0], [P1[0], F2, F1, ORG_NAME], OS_LOGIN, {'rules': [{'enforce': True}]}),  # web-prod re-enforces it: restored there, so the folder's exception reaches data-lake only
            policy(P3[0], [P3[0], ORG_NAME], EXT_IP, {'rules': [{'allowAll': True}]}),  # a project opens a denied list constraint
            policy(F1, [F1, ORG_NAME], DOMAINS, {'inheritFromParent': True, 'rules': [{'values': {'allowedValues': ['C0partner']}}]}),  # merged with the parent's: still configured → tightening/restating
            policy(P2[0], [P2[0], F2, F1, ORG_NAME], KEYS, {'rules': [{'enforce': False}]}),  # the organization does not hold KEYS: its own gap, not an exception
            policy(P2[0], [P2[0], F2, F1, ORG_NAME], 'gcp.resourceLocations', {'rules': [{'denyAll': True}]}),  # outside the table
            policy(P3[0], [P3[0], ORG_NAME], OS_LOGIN, {'rules': [{'enforce': False, 'condition': {'expression': "resource.matchTag('123/env', 'lab')"}}]})]  # conditional only


# --- shapes and rules ---

def test_v2_to_v1_converts_every_rule_shape():
    assert v2_to_v1({'rules': [{'enforce': True}]}) == ({'booleanPolicy': {'enforced': True}}, None)
    assert v2_to_v1({'reset': True}) == ({'restoreDefault': {}}, None)
    assert v2_to_v1({'rules': [{'allowAll': True}]}) == ({'listPolicy': {'allValues': 'ALLOW'}}, None)
    assert v2_to_v1({'rules': [{'denyAll': True}]}) == ({'listPolicy': {'allValues': 'DENY'}}, None)
    assert v2_to_v1({'inheritFromParent': True, 'rules': [{'values': {'allowedValues': ['a'], 'deniedValues': ['b']}}]}) == ({'listPolicy': {'allowedValues': ['a'], 'deniedValues': ['b'], 'inheritFromParent': True}}, None)
    unconditional, tagged = v2_to_v1({'rules': [{'enforce': True}, {'enforce': False, 'condition': {'expression': 'x'}}]})
    assert unconditional == {'booleanPolicy': {'enforced': True}} and tagged == {'booleanPolicy': {'enforced': False}}
    assert v2_to_v1({'rules': [{'enforce': False, 'condition': {'expression': 'x'}}]}) == (None, {'booleanPolicy': {'enforced': False}})
    assert v2_to_v1({}) == (None, None) and v2_to_v1(None) == (None, None)


def test_merge_follows_resource_managers_rules():
    effective = {OS_LOGIN: {'booleanPolicy': {'enforced': True}}, DOMAINS: {'listPolicy': {'allowedValues': ['C0example']}}, EXT_IP: {'listPolicy': {'allValues': 'DENY'}}}
    merge(effective, OS_LOGIN, {'booleanPolicy': {'enforced': False}})
    assert effective[OS_LOGIN] == {'booleanPolicy': {'enforced': False}}  # nearest wins
    merge(effective, OS_LOGIN, {'restoreDefault': {}})
    assert OS_LOGIN not in effective  # reset: back to the default
    merge(effective, DOMAINS, {'listPolicy': {'allowedValues': ['C0partner'], 'inheritFromParent': True}})
    assert effective[DOMAINS] == {'listPolicy': {'allowedValues': ['C0example', 'C0partner']}}  # merged
    merge(effective, DOMAINS, {'listPolicy': {'allowedValues': ['C0other']}})
    assert effective[DOMAINS] == {'listPolicy': {'allowedValues': ['C0other']}}  # replaced
    merge(effective, EXT_IP, {'listPolicy': {'allowedValues': ['projects/p/zones/z/instances/vm'], 'inheritFromParent': True}})
    assert effective[EXT_IP] == {'listPolicy': {'allowedValues': ['projects/p/zones/z/instances/vm'], 'allValues': 'DENY'}}  # the parent's allValues stays
    merge(effective, KEYS, None)
    assert KEYS not in effective


def test_judge_agrees_with_the_reports_evaluator():
    rows = [row for category, rows in TABLE.items() if category != POLICY_TABLE_META for row in rows]
    for policies in (BASELINE, {}, {OS_LOGIN: {'booleanPolicy': {'enforced': False}}, EXT_IP: {'listPolicy': {'allValues': 'ALLOW'}}, DOMAINS: {'restoreDefault': {}}, KEYS: {'booleanPolicy': {'enforced': True}}}):
        reference = {result.policy_id: result.status for _, results in evaluate_org_policies({k: v for k, v in TABLE.items() if k != POLICY_TABLE_META}, policies) for result in results}
        assert {row['policyId']: judge(row, policies.get(row['policyId'])) for row in rows} == reference
    assert isinstance(PolicyResult(OS_LOGIN, 'x', 'True', 'True', COMPLIANT), PolicyResult)


def test_describe_reads_every_shape():
    assert describe(None) == 'not set' and describe({'restoreDefault': {}}) == 'default restored'
    assert describe({'booleanPolicy': {'enforced': True}}) == 'enforced' and describe({'booleanPolicy': {'enforced': False}}) == 'not enforced'
    assert describe({'listPolicy': {'allValues': 'ALLOW'}}) == 'allows all values' and describe({'listPolicy': {'allValues': 'DENY'}}) == 'denies all values'
    assert describe({'listPolicy': {'allowedValues': ['a', 'b', 'c', 'd'], 'inheritFromParent': True}}) == "allows 4 values: a, b, c … (merged with the parent's)"
    assert describe({'listPolicy': {'deniedValues': ['x']}}) == 'denies 1 value: x'


# --- the hierarchy and the rows ---

def test_container_facts_and_policies_by_container():
    containers = container_facts(HIERARCHY)
    assert set(containers) == {F1, F2, P1[0], P2[0], P3[0]}  # the deleted folder is left out
    assert containers[P1[0]] == {'kind': 'project', 'id': 'web-prod', 'label': 'projects/web-prod', 'path': [ORG_NAME, F1, F2, P1[0]]}
    assert containers[F2] == {'kind': 'folder', 'id': 'Dev', 'label': 'folders/2062 (Dev)', 'path': [ORG_NAME, F1, F2]}
    by_container = policies_by_container(POLICIES)
    assert by_container[F2][OS_LOGIN] == ({'booleanPolicy': {'enforced': False}}, None) and by_container[P3[0]][OS_LOGIN] == (None, {'booleanPolicy': {'enforced': False}})
    assert effective_below(BASELINE, [F1, F2, P1[0]], by_container)[OS_LOGIN] == {'booleanPolicy': {'enforced': True}}  # the project restores it
    assert effective_below(BASELINE, [F1, F2, P2[0]], by_container)[OS_LOGIN] == {'booleanPolicy': {'enforced': False}}
    assert effective_below(BASELINE, [F1], by_container)[DOMAINS] == {'listPolicy': {'allowedValues': ['C0example', 'C0partner']}}


def test_exception_rows_name_the_cause_its_reach_and_the_verdict():
    rows = exception_rows(ORG_NAME, TABLE, BASELINE, container_facts(HIERARCHY), policies_by_container(POLICIES))
    assert [(r['Constraint'], r['Set on'], r['Reaches'], r['_status']) for r in rows] == [
        (OS_LOGIN, 'folders/2062 (Dev)', '1 project: data-lake', AR),  # web-prod re-enforced it
        (EXT_IP, 'projects/sandbox', 'the project itself', AR),
        (OS_LOGIN, 'projects/sandbox', 'tagged resources in 1 project', IR),
        ('—', '4 other policies set below', '—', INFO)]  # web-prod's restore, F1's merged domains, data-lake's KEYS (the organization's own gap) and its out-of-table constraint
    folder_row = rows[0]
    assert (folder_row['Above'], folder_row['Below']) == ('enforced', 'not enforced') and folder_row['Issue'] == 'Guardrail weakened below the scanned resource.'
    assert folder_row['Fix'].startswith('gcloud org-policies delete compute.requireOsLogin --folder=2062') and 'Require OS Login: enforced at organizations/' in folder_row['Detail']
    assert rows[1]['Fix'].startswith('gcloud org-policies delete compute.vmExternalIpAccess --project=sandbox') and (rows[1]['Above'], rows[1]['Below']) == ('denies all values', 'allows all values')
    assert rows[2]['Below'] == 'not enforced for tagged resources' and rows[2]['Fix'].startswith('gcloud org-policies describe compute.requireOsLogin --project=sandbox')
    assert all(tuple(k for k in r if k != '_status') == COLUMNS for r in rows)
    # A folder scan: the folder's own effective policies are the baseline; only what is under it counts.
    folder_rows = exception_rows(F2, TABLE, {**BASELINE, OS_LOGIN: {'booleanPolicy': {'enforced': False}}}, container_facts(HIERARCHY), policies_by_container(POLICIES))
    assert [(r['Constraint'], r['Set on']) for r in folder_rows] == [('—', '3 other policies set below')]  # OS Login is the folder's own gap now; web-prod's restore, data-lake's two
    # Nothing set below: no rows (the check writes the all-clear).
    assert exception_rows(ORG_NAME, TABLE, BASELINE, container_facts(HIERARCHY), {}) == []


def test_check_org_policy_exceptions_end_to_end(gcp, monkeypatch):
    monkeypatch.setattr(ope, 'fetch_best_practices', lambda: TABLE)
    monkeypatch.setattr(ope, 'get_effective_org_policies', lambda scope, scope_id: dict(BASELINE))
    gcp.assets.assets += [SimpleNamespace(asset_type=a.asset_type, name=a.name, resource=a.resource, ancestors=a.ancestors, parents={ORG_NAME, 'folders/1061'}) for a in HIERARCHY + POLICIES]
    s = Sink()
    check_org_policy_exceptions('organization', ORG, JOB, sink=s)
    record = s.by_check()[EXCEPTIONS_CHECK]
    assert record['Status'] == AR and [r['Constraint'] for r in record['Finding']] == [OS_LOGIN, EXT_IP, OS_LOGIN, '—'] and all('_status' not in r for r in record['Finding'])
    assert [r['asset_types'] for r in gcp.assets.list_requests] == [['orgpolicy.googleapis.com/Policy'], ['cloudresourcemanager.googleapis.com/Project', 'cloudresourcemanager.googleapis.com/Folder']]
    # The Below column and the count the report derives from the record.
    assert exceptions_by_constraint([record]) == {OS_LOGIN: '2 exceptions (folders/2062 (Dev), projects/sandbox)', EXT_IP: '1 exception (projects/sandbox)'}
    # A project scan has nothing below it.
    s = Sink()
    check_org_policy_exceptions('project', 'web-prod', JOB, sink=s)
    record = s.by_check()[EXCEPTIONS_CHECK]
    assert record['Status'] == INFO and record['Finding'][0]['Issue'] == 'Nothing below a project.' and record['Finding'][0]['Detail'] == NOTHING_BELOW_PROJECT and tuple(record['Finding'][0]) == COLUMNS
    # The listing failing is an Error record.
    gcp.assets.list_errors['orgpolicy.googleapis.com/Policy'] = PermissionError('cloudasset.assets.listResource denied')
    s = Sink()
    check_org_policy_exceptions('organization', ORG, JOB, sink=s)
    assert s.by_check()[EXCEPTIONS_CHECK]['Status'] == 'Error' and 'denied' in s.by_check()[EXCEPTIONS_CHECK]['Finding'][0]['Error']
    gcp.assets.list_errors.clear()
    # Nothing set below: Compliant, with the all-clear.
    gcp.assets.assets = [a for a in gcp.assets.assets if a.asset_type != 'orgpolicy.googleapis.com/Policy']
    s = Sink()
    check_org_policy_exceptions('organization', ORG, JOB, sink=s)
    assert s.by_check()[EXCEPTIONS_CHECK]['Status'] == COMPLIANT and 'weakens a guardrail' in s.by_check()[EXCEPTIONS_CHECK]['Finding'][0]['Status']


def test_the_report_shows_the_below_column_only_when_there_are_exceptions():
    from app.reporting.context import build_org_policy_summary
    data = ({k: v for k, v in TABLE.items()}, BASELINE)
    plain = build_org_policy_summary(data)
    assert plain.exceptions == 0 and all(row.below == '' for category in plain.categories for row in category.rows)
    marked = build_org_policy_summary(data, {OS_LOGIN: '1 exception (folders/2062 (Dev))'})
    rows = {row.display_name: row for category in marked.categories for row in category.rows}
    assert marked.exceptions == 1 and rows['Require OS Login'].below == '1 exception (folders/2062 (Dev))' and rows['Require OS Login'].status == COMPLIANT and rows['Domain restricted sharing'].below == ''
    assert (marked.compliant, marked.total) == (plain.compliant, plain.total)  # the tally is the scanned resource's; the exception is one check elsewhere
