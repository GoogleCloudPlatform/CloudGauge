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
"""The GKE Supported Versions check (v15).

The reference is ``projects.locations.getServerConfig``: a cluster on a release
channel is judged against its channel's ``validVersions``, one without against
the static ``validMasterVersions`` / ``validNodeVersions``. A minor that is no
longer in its list is Action Required, the oldest minor in the list is
Investigation Recommended, and every row carries the ``gcloud`` upgrade to the
right target.
"""
import json
from types import SimpleNamespace

import httplib2
import pytest
from googleapiclient.errors import HttpError

from app.checks import gke_versions
from app.checks.gke_versions import (
    CHECK_NAME,
    assess,
    check_gke_supported_versions,
    cluster_rows,
    minor_of,
    more_than_one_minor_apart,
    newest_patch,
    supported_versions,
    upgrade_command,
    version_key,
)
from fakes import _execute

JOB = 'job-15'
# Newest first, as the API lists them: four supported minors, two patches each.
VERSIONS = ['1.33.4-gke.1289000', '1.33.1-gke.1035000', '1.32.4-gke.1289000', '1.32.1-gke.1035000',
            '1.31.4-gke.1289000', '1.31.1-gke.1035000', '1.30.4-gke.1289000', '1.30.1-gke.1035000']
CHANNEL_VERSIONS = VERSIONS[:6]  # the REGULAR channel no longer offers 1.30
SERVER_CONFIG = {'defaultClusterVersion': '1.32.4-gke.1289000', 'validMasterVersions': VERSIONS, 'validNodeVersions': VERSIONS,
                 'channels': [{'channel': 'REGULAR', 'defaultVersion': '1.32.4-gke.1289000', 'validVersions': CHANNEL_VERSIONS}]}


def cluster(name='prod', location='us-central1', master='1.32.4-gke.1289000', pools=(), channel=None):
    entry = {'name': name, 'location': location, 'currentMasterVersion': master,
             'nodePools': [{'name': pool, 'version': version} for pool, version in pools]}
    if channel:
        entry['releaseChannel'] = {'channel': channel}
    return entry


# --- the rules -------------------------------------------------------------------------------------

@pytest.mark.parametrize('version, minor, key', [
    ('1.29.12-gke.1234567', '1.29', (1, 29, 12, 1234567)),
    ('1.30.4-gke.1289000', '1.30', (1, 30, 4, 1289000)),
    ('1.31', '1.31', (1, 31, 0, 0)),
    ('1.31.2', '1.31', (1, 31, 2, 0)),
    ('latest', None, None),
    ('', None, None),
    (None, None, None),
])
def test_versions_parse_to_a_minor_and_a_numeric_sort_key(version, minor, key):
    assert minor_of(version) == minor and version_key(version) == key


def test_versions_sort_numerically_not_textually():
    assert version_key('1.30.10-gke.5') > version_key('1.30.9-gke.900')  # "10" after "9"
    assert newest_patch('1.30', VERSIONS) == '1.30.4-gke.1289000'
    assert newest_patch('1.29', VERSIONS) is None
    assert newest_patch('1.30', ['1.30.9-gke.1', '1.30.10-gke.1']) == '1.30.10-gke.1'


def test_a_channel_cluster_is_judged_against_its_channel_and_the_others_against_the_static_lists():
    assert supported_versions(SERVER_CONFIG, 'REGULAR', 'master') == CHANNEL_VERSIONS
    assert supported_versions(SERVER_CONFIG, 'REGULAR', 'node') == CHANNEL_VERSIONS
    assert supported_versions(SERVER_CONFIG, None, 'master') == VERSIONS
    assert supported_versions(SERVER_CONFIG, 'UNSPECIFIED', 'node') == VERSIONS
    assert supported_versions(SERVER_CONFIG, 'EXTENDED', 'node') == VERSIONS  # a channel the config does not list
    config = {'validMasterVersions': VERSIONS[:2], 'validNodeVersions': VERSIONS[:4]}
    assert (supported_versions(config, None, 'master'), supported_versions(config, None, 'node')) == (VERSIONS[:2], VERSIONS[:4])


@pytest.mark.parametrize('version, verdict', [
    ('1.29.8-gke.1057000', ('Action Required', '1.29 is no longer offered; the oldest supported minor is 1.30.', '1.30.4-gke.1289000')),
    ('1.27.3-gke.100', ('Action Required', '1.27 is no longer offered; the oldest supported minor is 1.30.', '1.30.4-gke.1289000')),
    ('1.30.1-gke.1035000', ('Investigation Recommended', '1.30 is the oldest supported minor: the next to leave support.', '1.31.4-gke.1289000')),
    ('1.30.4-gke.1289000', ('Investigation Recommended', '1.30 is the oldest supported minor: the next to leave support.', '1.31.4-gke.1289000')),
    ('1.31.1-gke.1035000', None),   # supported, not the oldest
    ('1.33.4-gke.1289000', None),   # the newest
    ('1.34.0-gke.1', None),         # newer than anything offered: a preview or a lagging list, not an alarm
    ('2.0.0-gke.1', None),
    ('latest', None),               # unparsable: nothing to judge
    (None, None),
])
def test_assess_flags_minors_that_left_the_list_and_the_oldest_one_still_in_it(version, verdict):
    assert assess(version, VERSIONS) == verdict


def test_assess_has_nothing_to_judge_against_an_empty_list():
    assert assess('1.29.8-gke.1057000', []) is None
    assert assess('1.29.8-gke.1057000', ['latest', '']) is None


def test_assess_names_the_channel_when_the_list_is_a_channels():
    status, issue, target = assess('1.30.4-gke.1289000', CHANNEL_VERSIONS, ' on the Regular channel')
    assert (status, target) == ('Action Required', '1.31.4-gke.1289000')
    assert issue == '1.30 is no longer offered on the Regular channel; the oldest supported minor is 1.31.'
    assert assess('1.31.1-gke.1035000', CHANNEL_VERSIONS, ' on the Regular channel')[1] == \
        '1.31 is the oldest supported minor on the Regular channel: the next to leave support.'


def test_the_oldest_minor_has_no_target_when_it_is_the_only_one_offered():
    assert assess('1.30.1-gke.1', ['1.30.4-gke.2']) == \
        ('Investigation Recommended', '1.30 is the oldest supported minor: the next to leave support.', None)


def test_upgrade_commands_name_the_control_plane_or_the_node_pool():
    assert upgrade_command('p', 'prod', 'us-central1', '1.30.4-gke.1289000') == \
        'gcloud container clusters upgrade prod --location=us-central1 --project=p --master --cluster-version=1.30.4-gke.1289000'
    assert upgrade_command('p', 'prod', 'us-central1-a', '1.30.4-gke.1289000', node_pool='spot') == \
        'gcloud container clusters upgrade prod --location=us-central1-a --project=p --node-pool=spot --cluster-version=1.30.4-gke.1289000'


@pytest.mark.parametrize('version, target, apart', [
    ('1.29.8-gke.1', '1.30.4-gke.1', False), ('1.29.8-gke.1', '1.31.4-gke.1', True),
    ('1.30.1-gke.1', '1.30.4-gke.1', False), ('1.33.4-gke.1', '2.0.0-gke.1', True),
])
def test_more_than_one_minor_apart(version, target, apart):
    assert more_than_one_minor_apart(version, target) is apart


# --- the rows of one cluster -----------------------------------------------------------------------

def rows_of(cluster_entry, project='p', config=SERVER_CONFIG):
    return [dict(row) for row in cluster_rows(project, cluster_entry, config)]


def test_a_healthy_cluster_has_no_rows():
    assert rows_of(cluster(pools=[('default', '1.32.4-gke.1289000'), ('spot', '1.31.4-gke.1289000')])) == []
    assert rows_of(cluster(master='1.33.1-gke.1035000', pools=[('default', '1.32.1-gke.1035000')], channel='REGULAR')) == []


def test_a_control_plane_two_minors_behind_says_it_upgrades_one_minor_at_a_time():
    [row] = rows_of(cluster(master='1.28.3-gke.100'))
    assert row == {
        'Project': 'p', 'Cluster': 'prod', 'Location': 'us-central1', 'Component': 'Control plane', 'Version': '1.28.3-gke.100',
        'Issue': '1.28 is no longer offered; the oldest supported minor is 1.30. Control planes upgrade one minor at a time.',
        'Fix': 'gcloud container clusters upgrade prod --location=us-central1 --project=p --master --cluster-version=1.30.4-gke.1289000',
        '_status': 'Action Required',
    }
    [row] = rows_of(cluster(master='1.29.8-gke.1057000'))  # one minor behind: no note
    assert row['Issue'] == '1.29 is no longer offered; the oldest supported minor is 1.30.'


def test_a_node_pool_never_targets_a_version_newer_than_its_control_plane():
    # Control plane on the oldest minor, a pool on a retired one: the pool can only go as far as the plane.
    [plane, pool] = rows_of(cluster(master='1.30.1-gke.1035000', pools=[('old', '1.29.8-gke.1057000')]))
    assert (plane['Component'], plane['_status'], plane['Fix'].split('--cluster-version=')[1]) == ('Control plane', 'Investigation Recommended', '1.31.4-gke.1289000')
    assert (pool['Component'], pool['_status'], pool['Version']) == ('Node pool old', 'Action Required', '1.29.8-gke.1057000')
    assert pool['Issue'] == '1.29 is no longer offered; the oldest supported minor is 1.30.'
    assert pool['Fix'] == 'gcloud container clusters upgrade prod --location=us-central1 --project=p --node-pool=old --cluster-version=1.30.1-gke.1035000'


def test_a_node_pool_on_its_control_planes_minor_has_to_wait_for_the_plane():
    [plane, pool] = rows_of(cluster(master='1.30.4-gke.1289000', pools=[('default', '1.30.4-gke.1289000')]))
    assert plane['Fix'].endswith('--master --cluster-version=1.31.4-gke.1289000')
    assert pool['Issue'] == '1.30 is the oldest supported minor: the next to leave support. Upgrade the control plane first.'
    assert pool['Fix'] == ''  # no "upgrade to the version you already run"
    [plane, pool] = rows_of(cluster(master='1.29.8-gke.1057000', pools=[('default', '1.29.1-gke.100')]))
    assert pool['Issue'] == '1.29 is no longer offered; the oldest supported minor is 1.30. Upgrade the control plane first.' and pool['Fix'] == ''


def test_a_channel_clusters_rows_name_the_channel():
    rows = rows_of(cluster(master='1.30.4-gke.1289000', pools=[('default', '1.30.4-gke.1289000'), ('spot', '1.31.1-gke.1035000')], channel='REGULAR'))
    assert [(r['Component'], r['_status'], r['Issue']) for r in rows] == [
        ('Control plane', 'Action Required', '1.30 is no longer offered on the Regular channel; the oldest supported minor is 1.31.'),
        ('Node pool default', 'Action Required',
         '1.30 is no longer offered on the Regular channel; the oldest supported minor is 1.31. Upgrade the control plane first.'),
        ('Node pool spot', 'Investigation Recommended',
         '1.31 is the oldest supported minor on the Regular channel: the next to leave support. Upgrade the control plane first.'),
    ]
    assert rows[0]['Fix'].endswith('--master --cluster-version=1.31.4-gke.1289000')
    assert rows[2]['Fix'] == ''  # 1.32 would be newer than the 1.30 control plane


def test_a_cluster_whose_versions_do_not_parse_has_no_rows():
    assert rows_of(cluster(master='', pools=[('default', None)])) == []
    assert rows_of(cluster(master='1.29.8-gke.1057000'), config={}) == []  # no server config lists either


# --- the check -------------------------------------------------------------------------------------

class FakeContainer:
    """``container.projects().locations().clusters().list`` and ``.getServerConfig`` for a few projects."""

    def __init__(self, clusters_by_project, server_config=SERVER_CONFIG):
        self.clusters_by_project = clusters_by_project  # project id -> list of clusters, or an exception
        self.server_config = server_config  # a dict, or an exception
        self.config_names, self.list_parents = [], []

    def projects(self):
        fake = self

        def list_clusters(parent):
            fake.list_parents.append(parent)
            answer = fake.clusters_by_project.get(parent.split('/')[1], [])
            return _execute(answer if isinstance(answer, Exception) else {'clusters': answer})

        def get_server_config(name):
            fake.config_names.append(name)
            return _execute(fake.server_config)
        locations = SimpleNamespace(clusters=lambda: SimpleNamespace(list=list_clusters), getServerConfig=get_server_config)
        return SimpleNamespace(locations=lambda: locations)


def api_disabled(project_id):
    message = (f'Kubernetes Engine API has not been used in project {project_id} before or it is disabled. Enable it by visiting '
               f'https://console.developers.google.com/apis/api/container.googleapis.com/overview?project={project_id} then retry.')
    return HttpError(httplib2.Response({'status': 403, 'reason': message}),
                     json.dumps({'error': {'code': 403, 'message': message, 'status': 'PERMISSION_DENIED'}}).encode(),
                     uri='https://container.googleapis.com/v1/projects/x/locations/-/clusters')


def forbidden():
    message = 'Required "container.clusters.list" permission(s) for "projects/locked".'
    return HttpError(httplib2.Response({'status': 403, 'reason': 'Forbidden'}),
                     json.dumps({'error': {'code': 403, 'message': message, 'status': 'PERMISSION_DENIED'}}).encode(),
                     uri='https://container.googleapis.com/')


def run(gcp, fake, projects):
    gcp.discovery.apis['container'] = fake
    writes = []
    sink = SimpleNamespace(write_finding=lambda job, name, record: writes.append((job, name, record)))
    check_gke_supported_versions('org', [{'projectId': p} for p in projects], JOB, sink=sink)
    assert all(job == JOB for job, _, _ in writes)
    assert ('container', 'v1') in gcp.discovery.calls
    return {name: record for _, name, record in writes}


def test_the_check_writes_one_row_per_component_with_the_worst_status(gcp):
    fake = FakeContainer({
        'web': [cluster('web-1', 'us-central1', master='1.29.8-gke.1057000', pools=[('default', '1.29.8-gke.1057000')])],
        'data': [cluster('data-1', 'europe-west1-b', master='1.30.4-gke.1289000', pools=[('default', '1.30.4-gke.1289000'), ('gpu', '1.30.1-gke.1035000')])],
        'fine': [cluster('fine-1', 'us-central1', pools=[('default', '1.32.4-gke.1289000')])],
    })
    records = run(gcp, fake, ['web', 'data', 'empty', 'fine'])
    assert list(records) == ['GKE_Supported_Versions']
    record = records['GKE_Supported_Versions']
    assert (record['Check'], record['Status']) == (CHECK_NAME, 'Action Required')
    assert [(r['Project'], r['Cluster'], r['Location'], r['Component'], r['Version']) for r in record['Finding']] == [
        ('web', 'web-1', 'us-central1', 'Control plane', '1.29.8-gke.1057000'),
        ('web', 'web-1', 'us-central1', 'Node pool default', '1.29.8-gke.1057000'),
        ('data', 'data-1', 'europe-west1-b', 'Control plane', '1.30.4-gke.1289000'),
        ('data', 'data-1', 'europe-west1-b', 'Node pool default', '1.30.4-gke.1289000'),
        ('data', 'data-1', 'europe-west1-b', 'Node pool gpu', '1.30.1-gke.1035000'),
    ]
    assert all(set(row) == {'Project', 'Cluster', 'Location', 'Component', 'Version', 'Issue', 'Fix'} for row in record['Finding'])
    assert record['Finding'][0]['Fix'] == \
        'gcloud container clusters upgrade web-1 --location=us-central1 --project=web --master --cluster-version=1.30.4-gke.1289000'
    assert record['Finding'][2]['Fix'] == \
        'gcloud container clusters upgrade data-1 --location=europe-west1-b --project=data --master --cluster-version=1.31.4-gke.1289000'
    # The pools of data-1 are on their control plane's minor: taking its patch would not change the finding.
    assert [(r['Fix'], r['Issue'].endswith(' Upgrade the control plane first.')) for r in record['Finding'][3:]] == [('', True), ('', True)]
    assert fake.list_parents == [f'projects/{p}/locations/-' for p in ('web', 'data', 'empty', 'fine')]
    # The server config is read once per location, in whichever project first has a cluster there.
    assert fake.config_names == ['projects/web/locations/us-central1', 'projects/data/locations/europe-west1-b']


def test_the_check_is_investigation_recommended_when_nothing_has_left_support_yet(gcp):
    fake = FakeContainer({'data': [cluster('data-1', master='1.31.4-gke.1289000', pools=[('old', '1.30.4-gke.1289000')])]})
    record = run(gcp, fake, ['data'])['GKE_Supported_Versions']
    assert record['Status'] == 'Investigation Recommended'
    assert [(r['Component'], r['Issue']) for r in record['Finding']] == \
        [('Node pool old', '1.30 is the oldest supported minor: the next to leave support.')]


def test_the_check_is_compliant_with_one_note_whether_or_not_there_are_clusters(gcp):
    compliant = {'Check': CHECK_NAME, 'Finding': [{'Status': 'All GKE clusters and node pools run supported versions.'}], 'Status': 'Compliant'}
    fake = FakeContainer({'fine': [cluster('fine-1', pools=[('default', '1.32.4-gke.1289000')])]})
    assert run(gcp, fake, ['fine'])['GKE_Supported_Versions'] == compliant
    assert run(gcp, FakeContainer({}), ['empty'])['GKE_Supported_Versions'] == compliant  # a sharded scan merges identical notes
    assert run(gcp, FakeContainer({}), [])['GKE_Supported_Versions'] == compliant


def test_a_project_without_the_gke_api_is_left_out_and_other_failures_are_reported(gcp):
    fake = FakeContainer({
        'no-api': api_disabled('no-api'),
        'locked': forbidden(),
        'fine': [cluster('fine-1', pools=[('default', '1.32.4-gke.1289000')])],
    })
    records = run(gcp, fake, ['no-api', 'locked', 'fine'])
    assert list(records) == ['GKE_Supported_Versions', 'NOT_CHECKED_GKE_Supported_Versions']
    assert records['GKE_Supported_Versions']['Status'] == 'Compliant'
    skipped = records['NOT_CHECKED_GKE_Supported_Versions']
    assert (skipped['Check'], skipped['Category'], skipped['Status']) == ('Projects not checked', 'Reliability & Resilience', 'Error')
    assert skipped['Finding'] == [{'Project': 'locked', 'Skipped check': CHECK_NAME,
                                   'Reason': '403 Required "container.clusters.list" permission(s) for "projects/locked".'}]


def test_a_server_config_that_cannot_be_read_skips_that_locations_clusters(gcp):
    fake = FakeContainer({'web': [cluster('web-1', master='1.29.8-gke.1057000')]}, server_config=forbidden())
    records = run(gcp, fake, ['web'])
    assert records['GKE_Supported_Versions']['Status'] == 'Compliant'
    assert records['NOT_CHECKED_GKE_Supported_Versions']['Finding'] == [{
        'Project': 'web', 'Skipped check': f'{CHECK_NAME} (clusters in us-central1)',
        'Reason': '403 Required "container.clusters.list" permission(s) for "projects/locked".'}]


def test_the_check_is_registered_in_the_plan_after_service_health(gcp):
    from app.checks import registry
    from app.checks.categories import CATEGORY_MAP
    names = [spec.name for spec in registry.build_check_plan('project', 'p', JOB, [{'projectId': 'p'}], [], ['global'])]
    assert names.index(CHECK_NAME) == names.index(registry.SERVICE_HEALTH_CHECK) + 1
    assert CATEGORY_MAP[CHECK_NAME] == 'Reliability & Resilience' and CHECK_NAME not in registry.SCOPE_LEVEL_CHECKS
    assert gke_versions.CONTAINER_API == 'container.googleapis.com'
