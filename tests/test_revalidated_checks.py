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
"""The legacy checks revalidated in v18: their rules on fixtures shaped like the real API answers.

Each section states what the legacy rule got wrong and asserts the v18 rule on the case that
exposed it — a deny-all firewall rule, ``ENCRYPTED_ONLY`` TLS, a stopped VM's released address,
the Google APIs service agent's Editor role, an SCC ``organizationSettings`` without a tier, a
Monitoring filter as Cloud Monitoring writes it — and on the ordinary cases around it.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httplib2
import pytest
from google.api_core import exceptions as core_exceptions
from googleapiclient.errors import HttpError

from app.checks import cost, network, operations, reliability, security
from app.checks.categories import CATEGORY_MAP
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS, RULE_CHANGED
from app.reporting.context import evaluate_list_policy, evaluate_org_policies
from app.services.org_policies import parse_best_practices_csv
from fakes import _execute

JOB = 'job-18'
AR, IR, INFO, C = 'Action Required', 'Investigation Recommended', 'Informational', 'Compliant'


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_check(self):
        return {record['Check']: record for _, record in self.records if record['Check'] != NOT_CHECKED}

    def not_checked(self):
        return [row for _, record in self.records if record['Check'] == NOT_CHECKED for row in record['Finding']]


def http_error(status, message='boom'):
    return HttpError(httplib2.Response({'status': status}), message.encode())


# --- Principals ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('member, kind', [
    ('allUsers', security.PUBLIC), ('allAuthenticatedUsers', security.PUBLIC),
    ('deleted:user:gone@example.com?uid=1', security.DELETED),
    ('serviceAccount:123456@cloudservices.gserviceaccount.com', security.GOOGLE_MANAGED),
    ('serviceAccount:service-123456@compute-system.iam.gserviceaccount.com', security.GOOGLE_MANAGED),
    ('serviceAccount:service-123456@gcp-sa-pubsub.iam.gserviceaccount.com', security.GOOGLE_MANAGED),
    ('serviceAccount:automation@system.gserviceaccount.com', security.GOOGLE_MANAGED),
    ('serviceAccount:123456-compute@developer.gserviceaccount.com', security.DEFAULT_SA),
    ('serviceAccount:web-prod@appspot.gserviceaccount.com', security.DEFAULT_SA),
    ('serviceAccount:ci@web-prod.iam.gserviceaccount.com', security.SERVICE_ACCOUNT),
    ('user:alice@example.com', security.USER), ('user:bob@partner.example.net', security.EXTERNAL_USER),
    ('user:someone@gmail.com', security.CONSUMER_ACCOUNT),
    ('group:devs@example.com', security.GROUP), ('domain:example.com', security.DOMAIN),
    ('principalSet://iam.googleapis.com/locations/global/workforcePools/p/*', security.OTHER_PRINCIPAL),
])
def test_principal_kinds(member, kind):
    assert security.principal_kind(member, ('example.com',)) == kind


def test_a_user_is_external_only_when_the_domains_are_known():
    assert security.principal_kind('user:bob@partner.example.net') == security.USER
    assert security.principal_kind('user:bob@partner.example.net', ('example.com',)) == security.EXTERNAL_USER


# --- Primitive Roles (Owner or Editor) ----------------------------------------------------------------------------

PROJECT_POLICY = {'bindings': [
    {'role': 'roles/editor', 'members': ['serviceAccount:123456@cloudservices.gserviceaccount.com',  # the Google APIs agent: by design
                                         'serviceAccount:123456-compute@developer.gserviceaccount.com',
                                         'serviceAccount:ci@web-prod.iam.gserviceaccount.com', 'group:devs@example.com']},
    {'role': 'roles/owner', 'members': ['user:alice@example.com', 'user:someone@gmail.com'],
     'condition': {'title': 'until-2030', 'expression': 'request.time < timestamp("2030-01-01T00:00:00Z")'}},
    {'role': 'roles/viewer', 'members': ['allUsers', 'user:bob@example.com']},  # the public on any role is a row; a viewer is not
    {'role': 'roles/compute.serviceAgent', 'members': ['serviceAccount:service-123456@compute-system.iam.gserviceaccount.com']},
]}


def test_primitive_role_rows_leave_google_agents_out_and_rate_each_kind_of_holder():
    rows = security.primitive_role_rows('web-prod', PROJECT_POLICY, ('example.com',))
    assert [(r['Principal'], r['Type'], r['Role'], r['_status']) for r in rows] == [
        ('serviceAccount:123456-compute@developer.gserviceaccount.com', security.DEFAULT_SA, 'roles/editor', IR),
        ('serviceAccount:ci@web-prod.iam.gserviceaccount.com', security.SERVICE_ACCOUNT, 'roles/editor', AR),
        ('group:devs@example.com', security.GROUP, 'roles/editor', IR),
        ('user:alice@example.com', security.USER, 'roles/owner', IR),
        ('user:someone@gmail.com', security.CONSUMER_ACCOUNT, 'roles/owner', AR),
        ('allUsers', security.PUBLIC, 'roles/viewer', AR),
    ]
    alice = rows[3]
    assert alice['Condition'] == 'until-2030'
    assert alice['Fix'].startswith("gcloud projects remove-iam-policy-binding web-prod --member=user:alice@example.com --role=roles/owner "
                                   "--condition='expression=request.time < timestamp(\"2030-01-01T00:00:00Z\"),title=until-2030'")
    assert rows[0]['Fix'].endswith('# and enforce iam.automaticIamGrantsForDefaultServiceAccounts so new projects stop granting it')
    assert rows[5]['Fix'] == 'gcloud projects remove-iam-policy-binding web-prod --member=allUsers --role=roles/viewer'
    assert security.worst_status(rows) == AR


def test_primitive_roles_check_reads_version_3_and_is_compliant_with_agents_only(gcp):
    calls = []

    class Crm:
        def projects(self):
            def get_iam_policy(resource, body):
                calls.append((resource, body))
                if resource == 'locked':
                    return _execute(RuntimeError('403 The caller does not have permission'))
                return _execute({'bindings': [{'role': 'roles/editor', 'members': ['serviceAccount:123456@cloudservices.gserviceaccount.com']}]})
            return SimpleNamespace(getIamPolicy=get_iam_policy, getAncestry=lambda projectId, body: _execute(
                {'ancestor': [{'resourceId': {'type': 'project', 'id': projectId}}, {'resourceId': {'type': 'organization', 'id': '1'}}]}))

        def organizations(self):
            return SimpleNamespace(get=lambda name: _execute({'name': name, 'displayName': 'example.com'}))

    gcp.discovery.apis['cloudresourcemanager'] = Crm()
    sink = Sink()
    security.check_project_iam_policy('1', [{'projectId': 'web-prod'}, {'projectId': 'locked'}], JOB, sink=sink)
    record = sink.by_check()['Primitive Roles (Owner or Editor)']
    assert record['Status'] == C and record['Finding'] == [{'Status': security.PRIMITIVE_ROLES_ALL_CLEAR}]
    assert calls[0] == ('web-prod', {'options': {'requestedPolicyVersion': 3}})
    assert [r['Project'] for r in sink.not_checked()] == ['locked']


# --- Critical Org-Level Roles -------------------------------------------------------------------------------------

ORG_POLICY = {'bindings': [
    {'role': 'roles/owner', 'members': ['group:cloud-admins@example.com']},
    {'role': 'roles/resourcemanager.organizationAdmin', 'members': ['group:cloud-admins@example.com', 'user:admin@example.com',
                                                                     'serviceAccount:tf@system.gserviceaccount.com']},
    {'role': 'roles/billing.admin', 'members': ['serviceAccount:billing-bot@ops.iam.gserviceaccount.com']},
    {'role': 'roles/browser', 'members': ['allAuthenticatedUsers']},
]}


def test_critical_role_rows_rate_holders_by_kind_and_skip_google_agents():
    rows = security.critical_role_rows('1', ORG_POLICY, ('example.com',))
    assert [(r['Principal'], r['Role'], r['_status']) for r in rows] == [
        ('group:cloud-admins@example.com', 'roles/owner', INFO),
        ('group:cloud-admins@example.com', 'roles/resourcemanager.organizationAdmin', INFO),
        ('user:admin@example.com', 'roles/resourcemanager.organizationAdmin', IR),
        ('serviceAccount:billing-bot@ops.iam.gserviceaccount.com', 'roles/billing.admin', AR),
    ]
    assert rows[2]['Fix'] == ('gcloud organizations remove-iam-policy-binding 1 --member=user:admin@example.com '
                              '--role=roles/resourcemanager.organizationAdmin  # grant the role to a group with few members first')
    assert security.public_org_rows('1', ORG_POLICY) == [{
        'Principal': 'allAuthenticatedUsers', 'Role': 'roles/browser', 'Condition': '',
        'Fix': 'gcloud organizations remove-iam-policy-binding 1 --member=allAuthenticatedUsers --role=roles/browser', '_status': AR}]


def test_org_iam_check_is_compliant_with_groups_only_and_writes_its_errors_under_its_own_names(gcp):
    groups_only = {'bindings': [{'role': 'roles/owner', 'members': ['group:cloud-admins@example.com']}]}

    class Crm:
        def __init__(self, policy):
            self.policy = policy

        def organizations(self):
            return SimpleNamespace(getIamPolicy=lambda resource, body: _execute(self.policy),
                                   get=lambda name: _execute({'name': name, 'displayName': 'example.com'}))

    gcp.discovery.apis['cloudresourcemanager'] = Crm(groups_only)
    sink = Sink()
    security.check_org_iam_policy('1', JOB, sink=sink)
    critical = sink.by_check()['Critical Org-Level Roles']
    assert critical['Status'] == C and [r['Type'] for r in critical['Finding']] == [security.GROUP]  # the inventory, under a pass
    assert sink.by_check()['Public Org-Level Access']['Status'] == C

    gcp.discovery.apis['cloudresourcemanager'] = Crm(RuntimeError('403 denied'))
    sink = Sink()
    security.check_org_iam_policy('1', JOB, sink=sink)
    assert {name: record['Status'] for name, record in sink.by_check().items()} == {'Critical Org-Level Roles': 'Error', 'Public Org-Level Access': 'Error'}
    assert 'Organization IAM Policy Check' not in sink.by_check()


# --- Security Command Center Status -------------------------------------------------------------------------------

@pytest.mark.parametrize('subscription, tier, status', [
    ({'name': 'organizations/1/subscription', 'tier': 'STANDARD', 'details': {'type': 'STANDARD'}}, 'Standard', IR),
    ({'name': 'organizations/1/subscription', 'tier': 'PREMIUM', 'details': {'type': 'SUBSCRIPTION', 'endTime': '2027-03-01T00:00:00Z'}}, 'Premium', C),
    ({'name': 'organizations/1/subscription', 'tier': 'ENTERPRISE', 'details': {'type': 'TRIAL'}}, 'Enterprise', C),
    ({'name': 'organizations/1/organizationSettings', 'enableAssetDiscovery': False}, 'Unknown', IR),  # the v1 resource: no tier
])
def test_scc_tier_row(subscription, tier, status):
    row = security.scc_tier_row(subscription)
    assert (row['Tier'], row['_status']) == (tier, status)
    assert ('Note' in row) == (status == IR)
    if subscription.get('details', {}).get('endTime'):
        assert row['Ends'] == '2027-03-01'


def test_scc_check_reads_the_subscription_and_tells_a_missing_activation_from_the_scanner_api(gcp):
    def run(answer):
        gcp.discovery.apis['securitycenter'] = SimpleNamespace(organizations=lambda: SimpleNamespace(getSubscription=lambda name: _execute(answer)))
        sink = Sink()
        security.check_scc_status('1', JOB, sink=sink)
        return sink.by_check()['Security Command Center Status']

    assert run({'tier': 'ENTERPRISE', 'details': {'type': 'SUBSCRIPTION'}})['Status'] == C
    standard = run({'tier': 'STANDARD', 'details': {'type': 'STANDARD'}})
    assert standard['Status'] == IR and standard['Finding'][0]['Note'] == security.SCC_STANDARD_NOTE
    assert run(http_error(404))['Status'] == AR
    disabled = run(http_error(403, 'Security Command Center API has not been used in project scanner before or it is disabled'))
    assert disabled['Status'] == 'Error' and 'project CloudGauge runs in' in disabled['Finding'][0]['Error']
    assert run(http_error(403, 'The caller does not have permission'))['Status'] == 'Error'
    assert ('securitycenter', 'v1beta2') in gcp.discovery.calls


# --- Service Account Key Rotation ---------------------------------------------------------------------------------

NOW = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)
ACCOUNT = {'name': 'projects/web-prod/serviceAccounts/ci@web-prod.iam.gserviceaccount.com', 'email': 'ci@web-prod.iam.gserviceaccount.com'}


def key(days_old, **extra):
    return {'name': f'{ACCOUNT["name"]}/keys/k{days_old}', 'validAfterTime': (NOW - timedelta(days=days_old)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'validBeforeTime': '9999-12-31T23:59:59Z', 'keyType': 'USER_MANAGED', 'keyOrigin': 'GOOGLE_PROVIDED', **extra}


def test_stale_key_rows_count_keys_that_can_still_authenticate():
    row = security.stale_key_row('web-prod', ACCOUNT, key(100), now=NOW)
    assert (row['Key ID'], row['Age (days)'], row['Expires'], row['Origin'], row['_status']) == ('k100', 100, 'never', 'created in Google Cloud', AR)
    assert row['Fix'].startswith('gcloud iam service-accounts keys disable k100 --iam-account=ci@web-prod.iam.gserviceaccount.com --project=web-prod')
    assert security.stale_key_row('web-prod', ACCOUNT, key(10), now=NOW) is None  # young
    assert security.stale_key_row('web-prod', ACCOUNT, key(100, disabled=True), now=NOW) is None  # cannot authenticate
    expired = key(100, validBeforeTime=(NOW - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))
    assert security.stale_key_row('web-prod', ACCOUNT, expired, now=NOW) is None  # expired
    assert security.stale_key_row('web-prod', {**ACCOUNT, 'disabled': True}, key(100), now=NOW) is None  # account disabled
    uploaded = security.stale_key_row('web-prod', ACCOUNT, key(400, keyOrigin='USER_PROVIDED'), now=NOW)
    assert uploaded['Origin'] == 'uploaded' and uploaded['Fix'].endswith('an uploaded key is rotated at its source')
    expiring = security.stale_key_row('web-prod', ACCOUNT, key(100, validBeforeTime='2027-01-01T00:00:00Z'), now=NOW)
    assert expiring['Expires'] == '2027-01-01'


def test_sa_key_check_puts_a_denied_project_under_projects_not_checked(gcp):
    class Iam:
        def projects(self):
            accounts = SimpleNamespace(
                list=lambda name: _execute(RuntimeError('403 denied') if name == 'projects/locked' else {'accounts': [ACCOUNT]}),
                list_next=lambda previous_request, previous_response: None,
                keys=lambda: SimpleNamespace(list=lambda name, keyTypes: _execute({'keys': [key(100), key(200, disabled=True)]})))
            return SimpleNamespace(serviceAccounts=lambda: accounts)

    gcp.discovery.apis['iam'] = Iam()
    sink = Sink()
    security.check_sa_key_rotation('1', [{'projectId': 'web-prod'}, {'projectId': 'locked'}], JOB, sink=sink)
    record = sink.by_check()['Service Account Key Rotation']
    assert record['Status'] == AR and [r['Key ID'] for r in record['Finding']] == ['k100']
    assert [r['Project'] for r in sink.not_checked()] == ['locked']


# --- Public GCS Buckets -------------------------------------------------------------------------------------------

PUBLIC_BINDINGS = [{'role': 'roles/storage.objectViewer', 'members': {'allUsers', 'user:alice@example.com'}},
                   {'role': 'roles/storage.legacyBucketReader', 'members': {'allUsers'}},
                   {'role': 'roles/storage.objectViewer', 'members': {'allAuthenticatedUsers'}}]


def test_public_bucket_rows_read_public_access_prevention():
    open_rows = security.public_bucket_rows('web-prod', 'assets', PUBLIC_BINDINGS, 'inherited')
    assert [(r['Principal'], r['Role'], r['Public access prevention'], r['_status']) for r in open_rows] == [
        ('allUsers', 'roles/storage.legacyBucketReader, roles/storage.objectViewer', 'not enforced', AR),
        ('allAuthenticatedUsers', 'roles/storage.objectViewer', 'not enforced', AR)]
    assert open_rows[0]['Fix'] == ('gcloud storage buckets remove-iam-policy-binding gs://assets --member=allUsers --role=roles/storage.legacyBucketReader && '
                                   'gcloud storage buckets remove-iam-policy-binding gs://assets --member=allUsers --role=roles/storage.objectViewer && '
                                   'gcloud storage buckets update gs://assets --public-access-prevention')
    enforced = security.public_bucket_rows('web-prod', 'assets', PUBLIC_BINDINGS, 'enforced')
    assert {(r['Public access prevention'], r['_status']) for r in enforced} == {('enforced (bucket)', IR)}
    assert 'update gs://assets --public-access-prevention' not in enforced[0]['Fix']
    by_org = security.public_bucket_rows('web-prod', 'assets', PUBLIC_BINDINGS, 'inherited', org_enforced=True)
    assert {(r['Public access prevention'], r['_status']) for r in by_org} == {('enforced (organization policy)', IR)}
    assert security.public_bucket_rows('web-prod', 'private', [{'role': 'roles/storage.admin', 'members': {'user:alice@example.com'}}], 'inherited') == []


def bucket(name, bindings, pap='inherited'):
    return SimpleNamespace(name=name, iam_configuration=SimpleNamespace(uniform_bucket_level_access_enabled=True, public_access_prevention=pap),
                           get_iam_policy=lambda requested_policy_version: SimpleNamespace(bindings=bindings))


def test_public_buckets_check_reads_the_organization_policy_once_per_project_with_an_open_bucket(gcp):
    reads = []

    class Crm:
        def projects(self):
            def effective(resource, body):
                reads.append((resource, body['constraint']))
                return _execute({'constraint': body['constraint'], 'booleanPolicy': {'enforced': resource == 'projects/web-prod'}})
            return SimpleNamespace(getEffectiveOrgPolicy=effective)

    gcp.discovery.apis['cloudresourcemanager'] = Crm()
    gcp.storage.listings.update({
        'web-prod': [bucket('assets', PUBLIC_BINDINGS), bucket('locked', PUBLIC_BINDINGS, 'enforced'), bucket('private', [])],
        'data-lake': [bucket('lake-public', PUBLIC_BINDINGS)],
        'clean': [bucket('private', [])],
    })
    sink = Sink()
    security.check_public_buckets('1', [{'projectId': 'web-prod'}, {'projectId': 'data-lake'}, {'projectId': 'clean'}], JOB, sink=sink)
    record = sink.by_check()['Public GCS Buckets']
    assert record['Status'] == AR
    assert [(r['Bucket'], r['Public access prevention']) for r in record['Finding']] == [
        ('assets', 'enforced (organization policy)'), ('assets', 'enforced (organization policy)'),
        ('locked', 'enforced (bucket)'), ('locked', 'enforced (bucket)'),
        ('lake-public', 'not enforced'), ('lake-public', 'not enforced')]
    assert reads == [('projects/web-prod', security.PAP_CONSTRAINT), ('projects/data-lake', security.PAP_CONSTRAINT)]  # not for clean, not twice


# --- Open Firewall Rules ------------------------------------------------------------------------------------------

def rule(name, allowed=None, denied=None, ranges=('0.0.0.0/0',), direction='INGRESS', disabled=False, **extra):
    entry = {'name': name, 'network': 'projects/web-prod/global/networks/prod-vpc', 'direction': direction, 'disabled': disabled,
             'sourceRanges': list(ranges), 'priority': 1000, **extra}
    if allowed is not None:
        entry['allowed'] = allowed
    if denied is not None:
        entry['denied'] = denied
    return entry


FIREWALL_RULES = [
    rule('allow-all', [{'IPProtocol': 'all'}]),
    rule('deny-all', denied=[{'IPProtocol': 'all'}], priority=65000),  # the hardening pattern: never a row
    rule('ssh-v6', [{'IPProtocol': 'tcp', 'ports': ['22']}], ranges=('::/0',), targetTags=['bastion']),
    rule('web', [{'IPProtocol': 'tcp', 'ports': ['80', '443']}, {'IPProtocol': 'icmp'}], targetServiceAccounts=['web@web-prod.iam.gserviceaccount.com']),
    rule('rdp-range', [{'IPProtocol': 'tcp', 'ports': ['3389', '8000-8100']}]),
    rule('dns', [{'IPProtocol': 'udp', 'ports': ['53']}]),
    rule('quic', [{'IPProtocol': 'udp', 'ports': ['443']}]),
    rule('egress', [{'IPProtocol': 'all'}], direction='EGRESS'),
    rule('off', [{'IPProtocol': 'all'}], disabled=True),
    rule('internal', [{'IPProtocol': 'all'}], ranges=('10.0.0.0/8',)),
    rule('ssh-iap', [{'IPProtocol': 'tcp', 'ports': ['22']}], ranges=(security.IAP_RANGE,)),
]


def test_open_firewall_rows_flag_allow_rules_from_the_internet_by_what_they_open():
    rows = security.open_firewall_rows('web-prod', FIREWALL_RULES)
    assert [(r['Rule'], r['Protocols/Ports'], r['Targets'], r['_status']) for r in rows] == [
        ('allow-all', 'all', 'all instances in the network', AR),
        ('ssh-v6', 'tcp:22', 'tags: bastion', AR),
        ('web', 'tcp:80,443, icmp', 'service accounts: web@web-prod.iam.gserviceaccount.com', IR),
        ('rdp-range', 'tcp:3389,8000-8100', 'all instances in the network', AR),
        ('dns', 'udp:53', 'all instances in the network', AR),
        ('quic', 'udp:443', 'all instances in the network', IR),
    ]
    by_name = {r['Rule']: r for r in rows}
    assert by_name['ssh-v6']['Fix'] == f'gcloud compute firewall-rules update ssh-v6 --project=web-prod --source-ranges={security.IAP_RANGE}  # Identity-Aware Proxy TCP forwarding instead of the internet'
    assert by_name['web']['Fix'].startswith('gcloud compute firewall-rules update web --project=web-prod --source-ranges=<your CIDRs>  # or front the tier with a load balancer')
    assert by_name['allow-all']['Fix'].endswith('# or: gcloud compute firewall-rules delete allow-all --project=web-prod')
    assert by_name['ssh-v6']['Source Ranges'] == '::/0' and by_name['allow-all']['VPC'] == 'prod-vpc' and by_name['allow-all']['Priority'] == 1000


def test_firewall_check_reads_every_page_and_writes_the_all_clear_row(gcp):
    pages = {'web-prod': [{'items': [FIREWALL_RULES[1]], 'nextPageToken': '2'}, {'items': [FIREWALL_RULES[0]]}], 'clean': [{'items': [FIREWALL_RULES[1]]}]}

    class Compute:
        def firewalls(self):
            def start(project):
                request = _execute(pages[project][0])
                request.project, request.index = project, 0
                return request

            def next_page(previous_request, previous_response):
                if 'nextPageToken' not in previous_response:
                    return None
                request = _execute(pages[previous_request.project][previous_request.index + 1])
                request.project, request.index = previous_request.project, previous_request.index + 1
                return request
            return SimpleNamespace(list=start, list_next=next_page)

    gcp.discovery.apis['compute'] = Compute()
    sink = Sink()
    security.check_open_firewall_rules('1', [{'projectId': 'web-prod'}], JOB, sink=sink)
    assert [r['Rule'] for r in sink.by_check()['Open Firewall Rules']['Finding']] == ['allow-all']  # from the second page
    sink = Sink()
    security.check_open_firewall_rules('1', [{'projectId': 'clean'}], JOB, sink=sink)
    assert sink.by_check()['Open Firewall Rules'] == {'Check': 'Open Firewall Rules', 'Finding': [{'Status': security.FIREWALL_ALL_CLEAR}], 'Status': C}


# --- Cloud SQL Security -------------------------------------------------------------------------------------------

def sql(name, ssl_mode=None, public=False, networks=(), **extra):
    ip = {'ipv4Enabled': public, 'authorizedNetworks': [{'value': n, 'name': n} for n in networks]}
    if ssl_mode:
        ip['sslMode'] = ssl_mode
    return {'name': name, 'databaseVersion': 'POSTGRES_15', 'instanceType': 'CLOUD_SQL_INSTANCE', 'settings': {'ipConfiguration': ip}, **extra}


def test_cloud_sql_rows_read_ssl_mode_authorized_networks_and_the_public_ip():
    rows = security.cloud_sql_rows
    assert rows('p', sql('modern', 'ENCRYPTED_ONLY')) == []  # the recommended mode reads as requireSsl=false: no longer a row
    assert rows('p', sql('mtls', 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED')) == []
    open_tls = rows('p', sql('open', 'ALLOW_UNENCRYPTED_AND_ENCRYPTED'))
    assert [(r['Issue'].split(':')[0], r['Fix'], r['_status']) for r in open_tls] == [
        ('TLS not enforced', 'gcloud sql instances patch open --project=p --ssl-mode=ENCRYPTED_ONLY', AR)]
    internet = rows('p', sql('internet', 'ENCRYPTED_ONLY', public=True, networks=('10.0.0.0/8', '0.0.0.0/0')))
    assert [(r['Issue'], r['_status']) for r in internet] == [('Open to the internet: authorized network 0.0.0.0/0 on a public IP.', AR)]
    assert internet[0]['Fix'].startswith('gcloud sql instances patch internet --project=p --clear-authorized-networks')
    public = rows('p', sql('public', 'ENCRYPTED_ONLY', public=True, networks=('203.0.113.0/24',)))
    assert [(r['Issue'], r['_status']) for r in public] == [('Public IP enabled.', IR)]
    assert public[0]['Fix'].startswith('gcloud sql instances patch public --project=p --no-assign-ip')
    assert public[0] | {'Project': 'p', 'Instance': 'public', 'Kind': 'primary', 'Version': 'POSTGRES_15'} == public[0]
    replica = rows('p', sql('replica', 'ALLOW_UNENCRYPTED_AND_ENCRYPTED', instanceType='READ_REPLICA_INSTANCE', masterInstanceName='p:primary'))
    assert replica[0]['Kind'] == 'replica' and replica[0]['Fix'] == 'gcloud sql instances patch primary --project=p --ssl-mode=ENCRYPTED_ONLY  # a replica\'s settings follow its primary'
    legacy = rows('p', {'name': 'legacy', 'settings': {'ipConfiguration': {'requireSsl': True, 'ipv4Enabled': False}}})
    assert legacy == []  # no sslMode: requireSsl decides
    assert rows('p', {'name': 'mid-operation'}) == []


# --- VM External IPs ----------------------------------------------------------------------------------------------

def vm(name, status='RUNNING', nat=None, ipv6=None, metadata=None, zone='us-central1-a', interfaces=None):
    nic = {'name': 'nic0', 'network': 'prod-vpc'}
    if nat is not None:
        nic['accessConfigs'] = [{'name': 'External NAT', 'type': 'ONE_TO_ONE_NAT', **({'natIP': nat} if nat else {})}]
    if ipv6:
        nic['ipv6AccessConfigs'] = [{'name': 'External IPv6', 'externalIpv6': ipv6}]
    return {'name': name, 'status': status, 'zone': f'https://www.googleapis.com/compute/v1/projects/p/zones/{zone}',
            'networkInterfaces': interfaces or [nic], 'metadata': {'items': [{'key': k, 'value': v} for k, v in (metadata or {}).items()]}}


def test_external_ip_rows_count_addresses_held_and_name_the_kind_of_instance():
    instances = [
        vm('web-1', nat='203.0.113.7'),
        vm('stopped', status='TERMINATED', nat=''),  # the ephemeral address was released with the stop
        vm('stopped-static', status='TERMINATED', nat='203.0.113.9'),
        vm('v6-only', ipv6='2600:1900::1'),
        vm('gke-pool-abcd', nat='203.0.113.11', metadata={'cluster-name': 'prod', 'cluster-location': 'us-central1'}),
        vm('mig-member', nat='203.0.113.12', metadata={'created-by': 'projects/p/zones/us-central1-a/instanceGroupManagers/web-mig'}),
        vm('two-nics', interfaces=[{'name': 'nic0', 'accessConfigs': [{'natIP': '203.0.113.13'}]}, {'name': 'nic1', 'accessConfigs': [{'natIP': '203.0.113.14'}]}]),
        vm('private'),
    ]
    rows = security.external_ip_rows('p', instances)
    assert [(r['VM'], r['Status'], r['External IPs'], r['Kind'], r['_status']) for r in rows] == [
        ('web-1', 'RUNNING', '203.0.113.7', 'standalone', AR),
        ('stopped-static', 'TERMINATED', '203.0.113.9', 'standalone', AR),
        ('v6-only', 'RUNNING', '2600:1900::1', 'standalone', AR),
        ('gke-pool-abcd', 'RUNNING', '203.0.113.11', 'GKE node', IR),
        ('mig-member', 'RUNNING', '203.0.113.12', 'MIG member', AR),
        ('two-nics', 'RUNNING', '203.0.113.13, 203.0.113.14', 'standalone', AR),
    ]
    by_name = {r['VM']: r for r in rows}
    assert by_name['web-1']['Fix'] == 'gcloud compute instances delete-access-config web-1 --zone=us-central1-a --project=p --network-interface=nic0 --access-config-name="External NAT"'
    assert by_name['v6-only']['Fix'] == 'gcloud compute instances network-interfaces update v6-only --zone=us-central1-a --project=p --network-interface=nic0 --stack-type=IPV4_ONLY'
    assert by_name['gke-pool-abcd']['Fix'].startswith('gcloud container node-pools create <pool> --cluster=prod --location=us-central1 --project=p --enable-private-nodes')
    assert 'rolling-action start-update web-mig' in by_name['mig-member']['Fix']
    assert by_name['two-nics']['Fix'].count('delete-access-config') == 2


# --- OS Config Agent Coverage -------------------------------------------------------------------------------------

def instance(name, zone='us-central1-a', vm_id='1', labels=None, metadata=None, status='RUNNING'):
    return {'name': name, 'id': vm_id, 'status': status, 'zone': f'https://www.googleapis.com/compute/v1/projects/p/zones/{zone}', 'labels': labels or {},
            'metadata': {'items': [{'key': k, 'value': v} for k, v in (metadata or {}).items()]}}


def test_managed_fleets_are_excluded_from_os_config_coverage():
    excluded = [instance('gke-pool-1'), instance('gk3-autopilot-1'), instance('dp-m', labels={'goog-dataproc-cluster-name': 'c'}),
                instance('df-worker', labels={'dataflow_job_id': 'j'}), instance('batch-1', labels={'goog-batch-job-id': 'b'}),
                instance('node-by-metadata', metadata={'cluster-name': 'prod'})]
    assert all(operations.is_managed_fleet_vm(i) for i in excluded)
    assert not operations.is_managed_fleet_vm(instance('vm-1', metadata={'created-by': 'projects/p/zones/z/instanceGroupManagers/web'}))


def test_os_config_rows_match_inventories_by_instance_id_or_hostname():
    inventories = [SimpleNamespace(name='projects/123/locations/us-central1-a/instances/42/inventory', os_info=SimpleNamespace(hostname='vm-a')),
                   {'name': 'projects/123/locations/us-central1-a/instances/43/inventory', 'osInfo': {'hostname': 'other'}}]
    covered = operations.inventory_instance_ids(inventories)
    assert covered == {'42', 'vm-a', '43', 'other'}
    rows = operations.os_config_rows('p', [instance('vm-a', vm_id='42'), instance('vm-b', vm_id='99'), instance('vm-c', vm_id='43'), instance('gke-x', vm_id='7')], covered)
    assert [(r['VM'], r['Zone']) for r in rows] == [('vm-b', 'us-central1-a')]
    assert rows[0]['Fix'] == 'gcloud compute instances add-metadata vm-b --zone=us-central1-a --project=p --metadata=enable-osconfig=TRUE'


class FakeOsConfig:
    def __init__(self, answers):
        self.answers = answers  # zone -> inventories, or an exception
        self.parents = []

    def list_inventories(self, request):
        self.parents.append(request['parent'])
        assert request['parent'].endswith('/instances/-'), request['parent']  # the API's parent pattern (the first canary sent the zone alone)
        answer = self.answers.get(request['parent'].split('/locations/')[1].split('/')[0], [])
        if isinstance(answer, Exception):
            raise answer
        return answer


def os_config_run(gcp, monkeypatch, osconfig, instances):
    compute = SimpleNamespace(instances=lambda: SimpleNamespace(
        aggregatedList=lambda project, filter=None: _execute({'items': {'zones/us-central1-a': {'instances': instances}}}),
        aggregatedList_next=lambda previous_request, previous_response: None))
    gcp.discovery.apis['compute'] = compute
    monkeypatch.setattr(operations.gcp, 'osconfig_client', lambda: osconfig)
    sink = Sink()
    operations.check_os_config_coverage('1', [{'projectId': 'p'}], JOB, sink=sink)
    return sink


def test_os_config_check_routes_its_errors(gcp, monkeypatch):
    vms = [instance('vm-a', vm_id='42'), instance('vm-b', vm_id='43'), instance('gke-node', vm_id='44')]
    reporting = FakeOsConfig({'us-central1-a': [SimpleNamespace(name='projects/1/locations/us-central1-a/instances/42/inventory', os_info=None)]})
    record = os_config_run(gcp, monkeypatch, reporting, vms).by_check()['OS Config Agent Coverage']
    assert record['Status'] == AR and [r['VM'] for r in record['Finding']] == ['vm-b']
    assert reporting.parents == ['projects/p/locations/us-central1-a/instances/-']  # one listing per zone (the API's parent pattern), not one call per VM

    disabled = os_config_run(gcp, monkeypatch, FakeOsConfig({'us-central1-a': core_exceptions.FailedPrecondition('OS inventory management has been disabled')}), vms)
    record = disabled.by_check()['OS Config Agent Coverage']
    assert record['Status'] == AR and record['Finding'] == [{'Project': 'p', 'Issue': operations.OS_INVENTORY_DISABLED, 'Fix': operations.os_config_fix('p')}]

    denied = os_config_run(gcp, monkeypatch, FakeOsConfig({'us-central1-a': core_exceptions.PermissionDenied('403 denied')}), vms)
    assert denied.by_check()['OS Config Agent Coverage']['Status'] == C  # nothing found in the projects that could be checked
    assert [r['Project'] for r in denied.not_checked()] == ['p']

    api_off = os_config_run(gcp, monkeypatch, FakeOsConfig({'us-central1-a': core_exceptions.PermissionDenied(
        'OS Config API has not been used in project p before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/osconfig.googleapis.com/overview')}), vms)
    record = api_off.by_check()['OS Config Agent Coverage']
    assert record['Status'] == AR and record['Finding'][0]['Issue'].startswith('The OS Config API is not enabled in this project')

    only_managed = os_config_run(gcp, monkeypatch, FakeOsConfig({}), [instance('gke-node', vm_id='44')])
    assert only_managed.by_check()['OS Config Agent Coverage']['Status'] == C and only_managed.not_checked() == []


# --- Monitoring Alert Coverage ------------------------------------------------------------------------------------

def policy(kind, text, enabled=True):
    return {'displayName': 'p', 'enabled': enabled, 'conditions': [{kind: {'filter' if kind != 'conditionMonitoringQueryLanguage' and kind != 'conditionPrometheusQueryLanguage' else 'query': text}}]}


ALL_ASSETS = set(operations.MONITORED_ASSETS)


def test_missing_alert_rows_match_real_monitoring_filters_across_condition_kinds():
    sql_policy = policy('conditionThreshold', 'metric.type="cloudsql.googleapis.com/database/cpu/utilization" AND resource.type="cloudsql_database"')
    text = operations.alert_policy_text([sql_policy])
    assert [r['Issue'] for r in operations.missing_alert_rows('p', ALL_ASSETS, text)] == [
        'No enabled alert policy for GKE Cluster.', 'No enabled alert policy for Load Balancer.', 'No enabled alert policy for quota.']
    promql = policy('conditionPrometheusQueryLanguage', 'sum(rate(container_cpu_usage_seconds_total[5m])) > 10')
    mql = policy('conditionMonitoringQueryLanguage', "fetch https_lb_rule | metric 'loadbalancing.googleapis.com/https/request_count'")
    absent = policy('conditionAbsent', 'metric.type="serviceruntime.googleapis.com/quota/allocation/usage"')
    text = operations.alert_policy_text([sql_policy, promql, mql, absent])
    assert operations.missing_alert_rows('p', ALL_ASSETS, text) == []
    disabled = operations.alert_policy_text([policy('conditionThreshold', 'resource.type="cloudsql_database"', enabled=False)])
    assert [r['Issue'] for r in operations.missing_alert_rows('p', {'sqladmin.googleapis.com/Instance'}, disabled)] == [
        'No enabled alert policy for Cloud SQL.', 'No enabled alert policy for quota.']
    legacy_needles = operations.alert_policy_text([policy('conditionThreshold', 'metric.type="cloud_sql"')])  # the synthetic world's old filters
    assert len(operations.missing_alert_rows('p', {'sqladmin.googleapis.com/Instance'}, legacy_needles)) == 2
    assert operations.missing_alert_rows('p', set(), '') == []  # a project without the assets owes no alert, not even for quota


def test_monitoring_check_is_investigation_recommended_and_reads_every_page(gcp):
    pages = [{'alertPolicies': [policy('conditionThreshold', 'resource.type="cloudsql_database"')], 'nextPageToken': 't'},
             {'alertPolicies': [policy('conditionThreshold', 'resource.type="https_lb_rule"')]}]

    def start(name):
        request = _execute(pages[0])
        request.index = 0
        return request

    def next_page(previous_request, previous_response):
        if 'nextPageToken' not in previous_response:
            return None
        request = _execute(pages[previous_request.index + 1])
        request.index = previous_request.index + 1
        return request

    gcp.discovery.apis['monitoring'] = SimpleNamespace(projects=lambda: SimpleNamespace(alertPolicies=lambda: SimpleNamespace(list=start, list_next=next_page)))
    for asset_type in operations.MONITORED_ASSETS:
        gcp.assets.add_asset(asset_type, f'//{asset_type.split("/")[0]}/projects/p/locations/x/things/{asset_type.split("/")[1]}', {})
    sink = Sink()
    operations.check_monitoring_coverage('1', [{'projectId': 'p'}], JOB, sink=sink)
    record = sink.by_check()['Monitoring Alert Coverage']
    assert record['Status'] == IR
    assert [r['Issue'] for r in record['Finding']] == ['No enabled alert policy for GKE Cluster.', 'No enabled alert policy for quota.']


# --- Miscellaneous: unattended projects, recent changes, firewall complexity -----------------------------------------

def test_unattended_project_comes_from_the_target_resources_then_the_operation_then_the_description():
    by_target = SimpleNamespace(target_resources=['//cloudresourcemanager.googleapis.com/projects/sandbox-1'], content=None, description='x')
    assert operations.unattended_project(by_target) == 'sandbox-1'
    by_operation = SimpleNamespace(target_resources=[], content=SimpleNamespace(operation_groups=[SimpleNamespace(operations=[SimpleNamespace(resource='//cloudresourcemanager.googleapis.com/projects/123')])]),
                                   description='Project `sandbox-2` has been unattended.')
    assert operations.unattended_project(by_operation) == '123'
    by_text = SimpleNamespace(target_resources=[], content=SimpleNamespace(operation_groups=[]), description='Project `sandbox-3` has been unattended.')
    assert operations.unattended_project(by_text) == 'sandbox-3'
    assert operations.unattended_project(SimpleNamespace(target_resources=[], content=None, description='')) == 'Unknown'


def test_misc_checks_write_errors_under_their_own_names_and_notes_when_there_is_nothing(gcp):
    gcp.discovery.apis['compute'] = SimpleNamespace(firewalls=lambda: SimpleNamespace(
        list=lambda project: _execute({'items': [{'name': f'r{i}'} for i in range(3)]}), list_next=lambda previous_request, previous_response: None))
    gcp.recommender.errors[operations.UNATTENDED_RECOMMENDER] = core_exceptions.PermissionDenied('403 denied')
    sink = Sink()
    operations.run_miscellaneous_checks_refactored('organization', '1', [{'projectId': 'p'}], JOB, sink=sink)
    records = sink.by_check()
    assert 'VPC Firewall Complexity (>150 Rules)' not in records  # v18.1: retired into the FIREWALLS quota
    assert records['Unattended Projects']['Status'] == 'Error' and 'Could not list' in records['Unattended Projects']['Finding'][0]['Error']
    assert records['Recent Changes (Org & Project)'] == {'Check': 'Recent Changes (Org & Project)', 'Status': INFO, 'Finding': [{'Summary': operations.NO_RECENT_CHANGES}]}

    gcp.recommender.errors.clear()
    gcp.recommender.recommendations[operations.UNATTENDED_RECOMMENDER] = [SimpleNamespace(
        target_resources=['//cloudresourcemanager.googleapis.com/projects/sandbox-1'], description='Project `sandbox-1` is unattended.',
        state_info=SimpleNamespace(state=SimpleNamespace(name='ACTIVE')), content=None)]
    gcp.recommender.project_errors['locked'] = core_exceptions.PermissionDenied('403 denied')
    sink = Sink()
    operations.run_miscellaneous_checks_refactored('organization', '1', [{'projectId': 'p'}, {'projectId': 'locked'}], JOB, sink=sink)
    records = sink.by_check()
    assert records['Unattended Projects']['Status'] == IR and records['Unattended Projects']['Finding'] == [{'Project': 'sandbox-1', 'Recommendation': 'Project `sandbox-1` is unattended.'}]
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [('locked', 'Recent Changes (Org & Project)')]


def test_dismissed_recommendations_are_not_findings():
    active = SimpleNamespace(state_info=SimpleNamespace(state=SimpleNamespace(name='ACTIVE')))
    dismissed = SimpleNamespace(state_info=SimpleNamespace(state=SimpleNamespace(name='DISMISSED')))
    assert operations.active_recommendations([active, dismissed, SimpleNamespace()]) == [active, SimpleNamespace()]
    assert cost.is_active(active) and not cost.is_active(dismissed)


# --- Quota --------------------------------------------------------------------------------------------------------

def test_committed_quotas_are_never_rows():
    assert operations.quota_row('p', 'us-central1', {'metric': 'COMMITTED_CPUS', 'usage': 64.0, 'limit': 64.0}) is None
    assert operations.quota_row('p', 'us-central1', {'metric': 'CPUS', 'usage': 64.0, 'limit': 64.0})['_status'] == AR


# --- Cost recommenders --------------------------------------------------------------------------------------------

def test_idle_load_balancers_retired_and_a_cost_increase_is_not_a_saving():
    assert 'Idle Load Balancers' not in cost.COST_RECOMMENDERS and len(cost.COST_RECOMMENDERS) == 14  # v18.1: MIG Rightsizing joined
    assert CATEGORY_MAP['Idle Load Balancers'] == 'Cost Optimization'  # older summaries still name it
    upsize = SimpleNamespace(name='r', description='Upsize for performance.', recommender_subtype='CHANGE_MACHINE_TYPE',
                             content=SimpleNamespace(overview={'resourceName': 'vm-1'}),
                             primary_impact=SimpleNamespace(cost_projection=SimpleNamespace(cost=SimpleNamespace(units=12, nanos=0, currency_code='USD'))))
    assert cost.parse_recommendation(upsize, 'p')['Est. Monthly Saving'] == 'none (costs 12.00 USD more)'


# --- GKE Hygiene --------------------------------------------------------------------------------------------------

def test_gke_hygiene_rows_and_the_attribution_of_recommendations():
    static = {'name': 'legacy', 'location': 'us-central1-a', 'releaseChannel': {'channel': 'UNSPECIFIED'},
              'nodePools': [{'name': 'default-pool', 'management': {'autoUpgrade': False, 'autoRepair': True}}]}
    channel = {'name': 'prod', 'location': 'us-central1-a', 'releaseChannel': {'channel': 'REGULAR'}, 'nodePools': [{'name': 'p', 'management': {'autoUpgrade': True, 'autoRepair': True}}]}
    assert reliability.cluster_channel(static) == '' and reliability.cluster_channel(channel) == 'REGULAR' and reliability.cluster_channel({}) == ''
    rows = reliability.gke_hygiene_rows('p', static)
    assert [(r['Cluster'], r.get('Node Pool'), r['Issue']) for r in rows] == [('legacy', None, 'Not on a release channel.'), ('legacy', 'default-pool', 'Auto-upgrades disabled.')]
    assert rows[0]['Fix'] == 'gcloud container clusters update legacy --location=us-central1-a --project=p --release-channel=regular'
    recos = [{'description': 'Upgrade prod.', 'targetResources': ['//container.googleapis.com/projects/p/locations/us-central1-a/clusters/prod']},
             {'description': 'Location-wide note.'}]
    attributed = reliability.recommendation_rows('p', 'us-central1-a', [static, channel], recos)
    assert [(r['Cluster'], r['Recommendation'], r['_status']) for r in attributed] == [('prod', 'Upgrade prod.', IR), ('(location-wide)', 'Location-wide note.', IR)]


def test_gke_hygiene_check_keeps_cluster_rows_when_the_recommender_fails(gcp):
    clusters = {'clusters': [{'name': 'legacy', 'location': 'us-central1-a', 'nodePools': [{'name': 'default-pool', 'management': {'autoUpgrade': True, 'autoRepair': True}}]}]}
    gcp.discovery.apis['container'] = SimpleNamespace(projects=lambda: SimpleNamespace(locations=lambda: SimpleNamespace(clusters=lambda: SimpleNamespace(list=lambda parent: _execute(clusters)))))
    recommendations = SimpleNamespace(list=lambda parent, filter: _execute(RuntimeError('403 denied')))
    gcp.discovery.apis['recommender'] = SimpleNamespace(projects=lambda: SimpleNamespace(locations=lambda: SimpleNamespace(recommenders=lambda: SimpleNamespace(recommendations=lambda: recommendations))))
    sink = Sink()
    reliability.check_gke_hygiene('1', [{'projectId': 'p'}], JOB, sink=sink)
    record = sink.by_check()['GKE Hygiene']
    assert record['Status'] == AR and [r['Issue'] for r in record['Finding']] == ['Not on a release channel.']
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [('p', 'GKE Hygiene (Active Assist recommendations)')]


# --- Network Insights ---------------------------------------------------------------------------------------------

def test_insights_are_asked_at_global_and_the_regions_and_rated_by_severity(gcp):
    from google.cloud import recommender_v1
    assert network.insight_locations(['us-central1', 'global', 'europe-west1', 'us-central1']) == ['global', 'europe-west1', 'us-central1']
    ip_type, sa_type = network.NETWORK_INSIGHT_TYPES['VPC IP Address Utilization'], network.NETWORK_INSIGHT_TYPES['GKE Service Account']
    gcp.recommender.insights[ip_type] = [recommender_v1.Insight({'name': 'i1', 'description': 'Subnet nearly full.', 'severity': 'LOW', 'state_info': {'state': 'ACTIVE'}})]
    gcp.recommender.insights[sa_type] = [
        recommender_v1.Insight({'name': 'i2', 'description': 'Node account is Editor.', 'severity': 'HIGH', 'state_info': {'state': 'ACTIVE'},
                                'content': {'nodeServiceAccountInsight': {'clusterUri': 'projects/p/locations/us-central1/clusters/prod'}}}),
        recommender_v1.Insight({'name': 'i3', 'description': 'Dismissed.', 'severity': 'HIGH', 'state_info': {'state': 'DISMISSED'}})]
    sink = Sink()
    network.run_network_insights('1', [{'projectId': 'p'}], ['us-central1-a'], ['us-central1'], JOB, sink=sink)
    records = sink.by_check()
    assert records['VPC IP Address Utilization']['Status'] == INFO and records['VPC IP Address Utilization']['Finding'][0]['Severity'] == 'Low'
    assert records['GKE Service Account']['Status'] == AR and {r['Resource'] for r in records['GKE Service Account']['Finding']} == {'Cluster: prod'}  # the fake answers at every location
    assert records['Load Balancer Health'] == {'Check': 'Load Balancer Health', 'Finding': [{'Status': network.NOTHING_FOUND['Load Balancer Health']}], 'Status': C}
    assert not any('us-central1-a' in parent for parent in gcp.recommender.parents)  # zones are never asked
    assert {parent.split('/locations/')[1].split('/')[0] for parent in gcp.recommender.parents} == {'global', 'us-central1'}


# --- Organization Policies ----------------------------------------------------------------------------------------

CSV = """Name,Type,Recommended to set *,ID
Identity,,,
Disable key creation,Boolean,Should have,iam.disableServiceAccountKeyCreation
Use the build account,Boolean,Wont have,cloudbuild.useBuildServiceAccount
Domain restricted sharing,List,Should have,iam.allowedPolicyMemberDomains
Resource locations,List,Should have,gcp.resourceLocations
Legacy services,List,Wont have,serviceuser.services
"""


def test_the_parser_reads_the_type_column():
    policies = parse_best_practices_csv(CSV)['Identity']
    assert [(p['policyId'], p['type'], p['expectedValue']) for p in policies] == [
        ('iam.disableServiceAccountKeyCreation', 'Boolean', 'True'), ('cloudbuild.useBuildServiceAccount', 'Boolean', 'False'),
        ('iam.allowedPolicyMemberDomains', 'List', 'True'), ('gcp.resourceLocations', 'List', 'True'), ('serviceuser.services', 'List', 'False')]
    without_type = parse_best_practices_csv("ID,Policy,Recommended to set *\nx.y,X,Should have\n")['Uncategorized']
    assert without_type[0]['type'] == 'Boolean'


@pytest.mark.parametrize('details, expected_true, outcome', [
    ({'listPolicy': {'allValues': 'DENY'}}, True, ('Compliant', 'Configured (denies all values)')),
    ({'listPolicy': {'allowedValues': ['C0abc', 'C0def']}}, True, ('Compliant', 'Configured (2 allowed, 0 denied)')),
    ({'listPolicy': {'allValues': 'ALLOW'}}, True, ('Non-compliant', 'Allows all values')),
    ({'restoreDefault': {}}, True, ('Not Configured', 'Default restored')),
    ({'listPolicy': {'allValues': 'DENY'}}, False, ('Non-compliant', 'Configured (denies all values)')),
    ({'listPolicy': {'allValues': 'ALLOW'}}, False, ('Compliant', 'Allows all values')),
])
def test_list_constraints_evaluate_as_configured_or_not(details, expected_true, outcome):
    assert evaluate_list_policy(details, expected_true) == outcome


def test_org_policy_evaluation_by_type():
    best = parse_best_practices_csv(CSV)
    current = {'iam.disableServiceAccountKeyCreation': {'booleanPolicy': {'enforced': True}},
               'iam.allowedPolicyMemberDomains': {'listPolicy': {'allowedValues': ['C0abc']}},
               'serviceuser.services': {'listPolicy': {'allValues': 'DENY'}}}
    ((_, results),) = evaluate_org_policies(best, current)
    assert [(r.policy_id, r.status, r.current_value) for r in results] == [
        ('iam.disableServiceAccountKeyCreation', 'Compliant', 'True'),
        ('cloudbuild.useBuildServiceAccount', 'Compliant', 'Not configured'),  # "won't have", and it is not set
        ('iam.allowedPolicyMemberDomains', 'Compliant', 'Configured (1 allowed, 0 denied)'),
        ('gcp.resourceLocations', 'Not Configured', 'N/A'),
        ('serviceuser.services', 'Non-compliant', 'Configured (denies all values)'),
    ]
    assert 'Unsupported' not in {r.status for r in results}


def test_a_policy_level_that_cannot_be_listed_is_an_error_not_a_silent_pass(gcp):
    from app.services.org_policies import get_effective_org_policies
    from fakes import FakeResourceManager

    class Denied(FakeResourceManager):
        def _list_org_policies(self, resource, body):
            if resource.startswith('folders/'):
                return _execute(RuntimeError('403 The caller does not have permission'))
            return super()._list_org_policies(resource, body)

    gcp.discovery.apis['cloudresourcemanager'] = Denied({'organizations/1': {'compute.requireOsLogin': True}}, parents={'folders/2': 'organizations/1'})
    result = get_effective_org_policies('folder', '2')
    assert isinstance(result, str) and 'could not list the policies set on folders/2' in result


# --- The release's rule changes -----------------------------------------------------------------------------------

def test_every_revalidated_check_draws_its_line_at_v18():
    revalidated = ['Organization Policies', 'Security Command Center Status', 'Primitive Roles (Owner or Editor)', 'Critical Org-Level Roles', 'Service Account Key Rotation',
                   'Public GCS Buckets', 'Open Firewall Rules', 'Cloud SQL Security', 'VM External IPs', 'OS Config Agent Coverage',
                   'Monitoring Alert Coverage', *network.NETWORK_INSIGHT_TYPES]
    assert {name: RESHAPED_CHECKS[name] for name in revalidated} == {name: ('18', RULE_CHANGED) for name in revalidated}
    assert RESHAPED_CHECKS['GKE Hygiene'] == RESHAPED_CHECKS['Quota Utilization (>80%)'] == ('18.1', RULE_CHANGED)  # redrawn again in v18.1
    assert RESHAPED_CHECKS['Unattended Projects'] == ('18', 'rows changed')
    for name in revalidated + ['Unattended Projects']:
        assert name in CATEGORY_MAP
