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
"""Cloud SQL Extended Support (v17, ``app.checks.reliability``) and IAM Least Privilege (v17, ``app.checks.security``)."""
from datetime import date, datetime, timezone

import pytest
from google.api_core import exceptions as core_exceptions
from google.cloud import recommender_v1

from app.checks import reliability
from app.checks.not_checked import NOT_CHECKED
from app.checks.reliability import (
    EXTENDED_SUPPORT,
    SQL_VERSIONS_CHECK,
    assess_sql_version,
    check_cloud_sql_versions,
    major_version,
    upgrade_target,
)
from app.checks.security import IAM_CHECK, check_iam_recommendations, iam_fix, iam_operations, iam_rows, recommendation_dict

JOB = 'job-17'
TODAY = date(2026, 10, 22)


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_name(self):
        return {name: record for name, record in self.records}

    def not_checked(self):
        return [row for _, record in self.records if record['Check'] == NOT_CHECKED for row in record['Finding']]


# --- Cloud SQL Extended Support ---

@pytest.mark.parametrize('version, major, target', [
    ('MYSQL_8_0_31', 'MYSQL_8_0', 'MYSQL_8_4'), ('MYSQL_5_7', 'MYSQL_5_7', 'MYSQL_8_4'), ('POSTGRES_15', 'POSTGRES_15', 'POSTGRES_17'),
    ('POSTGRES_9_6', 'POSTGRES_9_6', 'POSTGRES_17'), ('SQLSERVER_2019_STANDARD', 'SQLSERVER_2019', 'SQLSERVER_2022_STANDARD'),
    ('SQLSERVER_2017_EXPRESS', 'SQLSERVER_2017', 'SQLSERVER_2022_EXPRESS'), ('', '', ''), (None, '', ''), ('ORACLE_19', 'ORACLE_19', ''),
])
def test_major_versions_and_upgrade_targets(version, major, target):
    assert (major_version(version), upgrade_target(version)) == (major, target)


def test_postgres_9_6_is_judged_by_its_own_table_entry():
    assert 'POSTGRES_9_6' in EXTENDED_SUPPORT and major_version('POSTGRES_9_6') == 'POSTGRES_9_6'  # the one two-part PostgreSQL major
    assert assess_sql_version('POSTGRES_9_6', TODAY)[0] == 'Action Required'


@pytest.mark.parametrize('version, verdict', [
    ('MYSQL_5_7', ('Action Required', 'In extended support since 2025-02-01 and pays the extended-support fee; deprecated on 2028-02-01.', '2025-02-01', '2028-02-01')),
    ('POSTGRES_12', ('Action Required', 'In extended support since 2025-02-01 and pays the extended-support fee; deprecated on 2028-02-01.', '2025-02-01', '2028-02-01')),
    ('POSTGRES_13', ('Investigation Recommended', 'Enters extended support on 2026-02-01, in 102 days.', '2026-02-01', '2029-02-01')),
    ('MYSQL_8_0_36', None),  # 2027-01-01 is more than 180 days from 2025-10-22
    ('SQLSERVER_2014_STANDARD', ('Action Required', 'Past the end of extended support (2024-07-09): no further fixes or security patches.', '2019-07-09', '2024-07-09')),
    ('SQLSERVER_2019_STANDARD', ('Action Required', 'In extended support since 2025-02-28; deprecated on 2030-01-08.', '2025-02-28', '2030-01-08')),
    ('POSTGRES_14', None),  # 2027-02-01 is more than 180 days away
    ('POSTGRES_17', None), ('MYSQL_8_4', None), ('SQLSERVER_2022_STANDARD', None), ('', None),
])
def test_assess_sql_version(version, verdict):
    assert assess_sql_version(version, date(2025, 10, 22)) == verdict


def test_a_version_within_the_warning_window_is_investigation_recommended():
    assert assess_sql_version('MYSQL_8_0_36', TODAY) == ('Investigation Recommended', 'Enters extended support on 2027-01-01, in 71 days.', '2027-01-01', '2029-07-01')
    assert assess_sql_version('POSTGRES_13', TODAY)[0] == 'Action Required'  # in extended support since 2026-02-01


def sql_asset(gcp, project, name, version):
    gcp.assets.add_asset('sqladmin.googleapis.com/Instance', f'//cloudsql.googleapis.com/projects/{project}/instances/{name}',
                         {'name': name, 'databaseVersion': version, 'settings': {}})


def test_cloud_sql_versions_check_writes_one_row_per_instance_with_the_worst_status(gcp, monkeypatch):
    monkeypatch.setattr(reliability, 'utcnow', lambda: datetime(2025, 10, 22, tzinfo=timezone.utc))
    sql_asset(gcp, 'web-prod', 'orders', 'MYSQL_5_7')
    sql_asset(gcp, 'web-prod', 'sessions', 'POSTGRES_17')
    sql_asset(gcp, 'data-lake', 'warehouse', 'POSTGRES_13')
    sink = Sink()
    check_cloud_sql_versions('organization', '987654321', JOB, sink=sink)
    ((name, record),) = sink.records
    assert (name, record['Check'], record['Status']) == ('Cloud_SQL_Extended_Support', SQL_VERSIONS_CHECK, 'Action Required')
    assert [(r['Project'], r['Instance'], r['Version'], r['Extended Support From'], r['Until']) for r in record['Finding']] == [
        ('web-prod', 'orders', 'MYSQL_5_7', '2025-02-01', '2028-02-01'), ('data-lake', 'warehouse', 'POSTGRES_13', '2026-02-01', '2029-02-01')]
    assert record['Finding'][0]['Fix'] == 'gcloud sql instances patch orders --project=web-prod --database-version=MYSQL_8_4'
    assert all('_status' not in row for row in record['Finding'])
    assert gcp.assets.list_requests[-1]['parent'] == 'organizations/987654321'


def test_cloud_sql_versions_check_investigation_all_clear_and_error(gcp, monkeypatch):
    monkeypatch.setattr(reliability, 'utcnow', lambda: datetime(2025, 10, 22, tzinfo=timezone.utc))
    sql_asset(gcp, 'data-lake', 'warehouse', 'POSTGRES_13')
    sink = Sink()
    check_cloud_sql_versions('project', 'data-lake', JOB, sink=sink)
    assert sink.by_name()['Cloud_SQL_Extended_Support']['Status'] == 'Investigation Recommended'
    sink = Sink()
    check_cloud_sql_versions('project', 'web-prod', JOB, sink=sink)  # no instance there
    assert sink.by_name()['Cloud_SQL_Extended_Support'] == {
        'Check': SQL_VERSIONS_CHECK, 'Status': 'Compliant',
        'Finding': [{'Status': 'No Cloud SQL instance runs a version in or within 180 days of extended support.'}]}
    gcp.assets.list_errors['sqladmin.googleapis.com/Instance'] = core_exceptions.PermissionDenied('no cloudasset.assets.listResource')
    sink = Sink()
    check_cloud_sql_versions('folder', '42', JOB, sink=sink)
    assert sink.by_name()['Cloud_SQL_Extended_Support'] == {'Check': SQL_VERSIONS_CHECK, 'Status': 'Error',
                                                            'Finding': [{'Error': '403 no cloudasset.assets.listResource'}]}


# --- IAM Least Privilege ---

def iam_recommendation(resource, member, role, replacement=None, index=0):
    operations = [{'action': 'remove', 'resource': resource, 'path': '/iamPolicy/bindings/*/members/*',
                   'path_filters': {'/iamPolicy/bindings/*/role': role, '/iamPolicy/bindings/*/members/*': member}}]
    if replacement:
        operations.append({'action': 'add', 'resource': resource, 'path': '/iamPolicy/bindings/*/members/-', 'value': member,
                           'path_filters': {'/iamPolicy/bindings/*/role': replacement}})
    return recommender_v1.Recommendation({
        'name': f'{resource}/recommendations/{index}', 'recommender_subtype': 'REPLACE_ROLE' if replacement else 'REMOVE_ROLE',
        'description': f'Replace {role} with {replacement} for {member}.' if replacement else f'Remove {role} from {member}.',
        'content': {'operation_groups': [{'operations': operations}]}})


def test_iam_recommendations_are_read_from_the_protos_operations():
    reco = recommendation_dict(iam_recommendation('//cloudresourcemanager.googleapis.com/projects/p1', 'user:alice@example.com', 'roles/editor', 'roles/viewer'))
    assert iam_operations(reco) == ([('roles/editor', 'user:alice@example.com')], [('roles/viewer', 'user:alice@example.com')])
    assert iam_fix('projects/p1', *iam_operations(reco)) == ('gcloud projects add-iam-policy-binding p1 --member=user:alice@example.com --role=roles/viewer && '
                                                             'gcloud projects remove-iam-policy-binding p1 --member=user:alice@example.com --role=roles/editor')
    assert iam_fix('folders/42', [('roles/owner', 'group:g@example.com')], []) == 'gcloud resource-manager folders remove-iam-policy-binding 42 --member=group:g@example.com --role=roles/owner'
    assert iam_fix('organizations/9', [('roles/owner', 'user:cto@example.com')], []) == 'gcloud organizations remove-iam-policy-binding 9 --member=user:cto@example.com --role=roles/owner'
    assert recommendation_dict({'description': 'x'}) == {'description': 'x'}
    rows = iam_rows('projects/p1', [iam_recommendation('r', 'user:alice@example.com', 'roles/editor', 'roles/viewer'),
                                    iam_recommendation('r', 'serviceAccount:ci@p1.iam.gserviceaccount.com', 'roles/owner', index=1)])
    assert [(r['Project'], r['Principal'], r['Current Role'], r['Recommended Role']) for r in rows] == [
        ('p1', 'user:alice@example.com', 'roles/editor', 'roles/viewer'),
        ('p1', 'serviceAccount:ci@p1.iam.gserviceaccount.com', 'roles/owner', 'none (remove)')]
    assert rows[1]['Recommendation'] == 'Remove roles/owner from serviceAccount:ci@p1.iam.gserviceaccount.com.'
    assert iam_rows('projects/p1', [recommender_v1.Recommendation({'name': 'odd', 'recommender_subtype': 'REMOVE_ROLE'})]) == [
        {'Project': 'p1', 'Principal': '', 'Current Role': '', 'Recommended Role': 'none (remove)', 'Recommendation': 'Remove role', 'Fix': ''}]
    assert iam_rows('organizations/9', [iam_recommendation('r', 'user:cto@example.com', 'roles/owner')])[0]['Project'] == 'organizations/9'


def test_iam_check_asks_the_scope_and_every_project(gcp):
    gcp.recommender.recommendations['google.iam.policy.Recommender'] = [
        iam_recommendation('//cloudresourcemanager.googleapis.com/x', 'user:alice@example.com', 'roles/editor', 'roles/viewer')]
    gcp.recommender.project_errors['locked'] = core_exceptions.PermissionDenied('denied')
    sink = Sink()
    check_iam_recommendations('organization', '987654321', [{'projectId': 'web-prod'}, {'projectId': 'locked'}], JOB, sink=sink)
    record = sink.by_name()['IAM_Least_Privilege']
    assert (record['Check'], record['Status']) == (IAM_CHECK, 'Action Required')
    assert [r['Project'] for r in record['Finding']] == ['organizations/987654321', 'web-prod']
    assert record['Finding'][0]['Fix'].startswith('gcloud organizations add-iam-policy-binding 987654321 --member=user:alice@example.com --role=roles/viewer')
    assert sink.not_checked() == [{'Project': 'locked', 'Skipped check': IAM_CHECK, 'Reason': '403 denied'}]
    assert gcp.recommender.parents == [f'{r}/locations/global/recommenders/google.iam.policy.Recommender'
                                       for r in ('organizations/987654321', 'projects/web-prod', 'projects/locked')]


def test_iam_check_splits_between_the_scope_and_the_projects_like_the_shards_do(gcp):
    gcp.recommender.recommendations['google.iam.policy.Recommender'] = []
    sink = Sink()
    check_iam_recommendations('folder', '42', [{'projectId': 'p1'}], JOB, sink=sink, project_level=False)
    assert gcp.recommender.parents == ['folders/42/locations/global/recommenders/google.iam.policy.Recommender']
    assert sink.by_name()['IAM_Least_Privilege'] == {'Check': IAM_CHECK, 'Status': 'Compliant',
                                                     'Finding': [{'Status': 'No principal holds a role the IAM recommender would remove or replace.'}]}
    gcp.recommender.parents.clear()
    check_iam_recommendations('folder', '42', [{'projectId': 'p1'}], JOB, sink=Sink(), scope_level=False)
    assert gcp.recommender.parents == ['projects/p1/locations/global/recommenders/google.iam.policy.Recommender']
    gcp.recommender.parents.clear()
    check_iam_recommendations('project', 'p1', [{'projectId': 'p1'}], JOB, sink=Sink())  # a project scan: the project once
    assert gcp.recommender.parents == ['projects/p1/locations/global/recommenders/google.iam.policy.Recommender']


def test_iam_check_is_an_error_when_nothing_could_be_read(gcp):
    gcp.recommender.errors['google.iam.policy.Recommender'] = core_exceptions.PermissionDenied('no recommender.iamPolicyRecommendations.list')
    sink = Sink()
    check_iam_recommendations('organization', '987654321', [{'projectId': 'p1'}], JOB, sink=sink)
    record = sink.by_name()['IAM_Least_Privilege']
    assert record['Status'] == 'Error' and 'Could not read the IAM recommendations of any resource in scope' in record['Finding'][0]['Error']
    assert [row['Project'] for row in sink.not_checked()] == ['organizations/987654321', 'p1']
