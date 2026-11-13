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
"""v18.1 — the loose rules of the legacy checks, tightened: Cloud Storage Versioning's protection ladder, VPC Configuration's
subnet purposes and default-network fold, the Organization Log Sink's qualification, the new Data Access Audit Logs check
and its hierarchy union, Essential Contacts' validity and every scope, cost priorities and fixes, GKE auto-repair, the
project-global quotas, and the bundled policy table with the operator's overrides."""
from types import SimpleNamespace

from app.checks import cost, operations, reliability, security
from app.checks.categories import CATEGORY_MAP
from app.checks.not_checked import NOT_CHECKED
from app.config import BUNDLED_POLICY_TABLE, POLICY_OVERRIDES_OBJECT
from app.reporting.changes import RESHAPED_CHECKS, RULE_CHANGED
from app.reporting.context import build_org_policy_summary, evaluate_org_policies
from app.services import gcp as gcp_clients
from app.services.org_policies import (POLICY_TABLE_META, apply_policy_overrides, describe_policy_table, fetch_best_practices,
                                       parse_best_practices_csv, read_policy_table)
from fakes import ORG_ID, _execute

JOB = 'job-181'
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


# --- Cloud Storage Versioning -------------------------------------------------------------------------------------

def bucket(name, versioning=False, soft_delete=604800, lifecycle=False, retention=None):
    return SimpleNamespace(name=name, versioning_enabled=versioning, soft_delete_policy=SimpleNamespace(retention_duration_seconds=soft_delete),
                           lifecycle_rules=[{'action': {'type': 'Delete'}, 'condition': {'age': 30}}] if lifecycle else [], retention_period=retention)


def test_versioning_rows_follow_the_protection_ladder():
    sinks = {'audit-logs'}
    row = reliability.versioning_row
    assert row('p', bucket('versioned', versioning=True, soft_delete=0), sinks) is None
    assert row('p', bucket('soft-deleted'), sinks) is None  # the default: 7 days of soft delete protect it
    assert row('p', bucket('lifecycle-only', soft_delete=0, lifecycle=True), sinks) is None
    naked = row('p', bucket('naked', soft_delete=0), sinks)
    assert (naked['Protection'], naked['_status']) == ('none: versioning off, soft delete off, no lifecycle rule, no retention policy', IR)
    assert naked['Fix'] == 'gcloud storage buckets update gs://naked --versioning --soft-delete-duration=7d'
    sink_bucket = row('p', bucket('audit-logs'), sinks)
    assert (sink_bucket['Protection'], sink_bucket['_status'], sink_bucket['Fix']) == ('versioning off on a log-sink destination bucket', AR, 'gcloud storage buckets update gs://audit-logs --versioning')
    # A retention policy protects the objects itself — and excludes versioning (the two cannot be enabled together), so it is never asked for.
    assert row('p', bucket('held', soft_delete=0, retention=86400 * 365), sinks) is None
    assert row('p', SimpleNamespace(name='bare'), sinks)['_status'] == IR  # a client that reports nothing: nothing protects it
    # v18.6: a zonal (Rapid Storage) bucket supports none of the four protections — nothing to fix, no row; a sink bucket there still is one.
    zonal = bucket('rapid', soft_delete=0)
    zonal.location_type = 'zone'
    assert row('p', zonal, sinks) is None and row('p', SimpleNamespace(name='audit-logs', location_type='zone'), sinks)['_status'] == AR


def test_sink_destination_buckets_from_the_asset_listing():
    assets = [SimpleNamespace(resource=SimpleNamespace(data={'destination': 'storage.googleapis.com/audit-logs'})),
              SimpleNamespace(resource=SimpleNamespace(data={'destination': 'bigquery.googleapis.com/projects/p/datasets/d'})),
              SimpleNamespace(resource=SimpleNamespace(data={'destination': 'storage.googleapis.com/exports/sub'})),
              SimpleNamespace(resource=None)]
    assert reliability.sink_destination_buckets(assets) == {'audit-logs', 'exports'}


def test_versioning_check_lists_the_scope_sinks_once_and_reports_the_failed_listing(gcp):
    gcp.assets.add_asset('logging.googleapis.com/LogSink', '//logging.googleapis.com/projects/web-prod/sinks/s1', {'name': 's1', 'destination': 'storage.googleapis.com/web-logs'})
    gcp.storage.listings.update({'web-prod': [bucket('web-logs'), bucket('web-assets'), bucket('web-tmp', soft_delete=0)], 'locked': RuntimeError('403 denied')})
    sink = Sink()
    reliability.check_storage_versioning('organization', ORG_ID, [{'projectId': 'web-prod'}, {'projectId': 'locked'}], JOB, sink=sink)
    record = sink.by_check()['Cloud Storage Versioning']
    assert record['Status'] == AR and [(r['Bucket'], r['Protection'].split(':')[0]) for r in record['Finding']] == [
        ('web-logs', 'versioning off on a log-sink destination bucket'), ('web-tmp', 'none')]
    assert [r['Project'] for r in sink.not_checked()] == ['locked']
    assert [r['parent'] for r in gcp.assets.list_requests if 'logging.googleapis.com/LogSink' in r['asset_types']] == [f'organizations/{ORG_ID}']


# --- VPC Configuration --------------------------------------------------------------------------------------------

def subnet(name, network='prod-vpc', region='us-central1', pga=False, purpose='PRIVATE', **extra):
    return {'name': name, 'network': f'https://www.googleapis.com/compute/v1/projects/p/global/networks/{network}',
            'region': f'https://www.googleapis.com/compute/v1/projects/p/regions/{region}', 'privateIpGoogleAccess': pga, 'purpose': purpose, **extra}


def test_vpc_rows_skip_proxy_subnets_fold_the_default_network_and_rate_pga_a_look():
    networks = [{'name': 'prod-vpc', 'selfLink': 'https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc'},
                {'name': 'default', 'selfLink': 'https://www.googleapis.com/compute/v1/projects/p/global/networks/default', 'autoCreateSubnetworks': True}]
    subnets = [subnet('web-a', pga=True), subnet('web-b'), subnet('proxy', purpose='REGIONAL_MANAGED_PROXY'), subnet('psc', purpose='PRIVATE_SERVICE_CONNECT'),
               subnet('default', network='default'), subnet('default', network='default', region='europe-west1'),
               subnet('v6', stackType='IPV6_ONLY', privateIpv6GoogleAccess='ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE'), subnet('v6-off', stackType='IPV6_ONLY'),
               # GKE's control-plane endpoint subnet (as the v18.1 probe cluster created it): Google's, never a row — by description or by name.
               subnet('gke-prod-a0f6979d-pe-subnet', description='Control Plane Endpoint Subnetwork'), subnet('gke-old-1234abcd-pe-subnet')]
    rows = security.vpc_rows('p', networks, subnets)
    assert [(r['Network / Subnet'], r['Region'], r['_status']) for r in rows] == [
        ('default (network)', 'global', AR), ('prod-vpc / web-b', 'us-central1', IR), ('prod-vpc / v6-off', 'us-central1', IR)]
    assert rows[0]['Issue'] == 'Default VPC network exists. 2 of its auto-mode subnets lack Private Google Access (counted here, not listed).'
    assert rows[1]['Fix'] == 'gcloud compute networks subnets update web-b --region=us-central1 --project=p --enable-private-ip-google-access'
    assert security.vpc_rows('p', [networks[0]], [subnets[0], subnets[2], subnets[8], subnets[9]]) == []
    assert not security.subnet_is_exempt(subnet('gke-nodes-pe-subnet-old'))  # a customer's own naming is judged like any subnet


def test_vpc_check_uses_the_aggregated_listing(gcp):
    calls = []

    class Compute:
        def networks(self):
            return SimpleNamespace(list=lambda project: _execute({'items': [{'name': 'prod-vpc'}]}), list_next=lambda previous_request, previous_response: None)

        def subnetworks(self):
            def aggregated(project):
                calls.append(project)
                return _execute({'items': {'regions/us-central1': {'subnetworks': [subnet('web-b')]}, 'regions/europe-west1': {'warning': {'code': 'NO_RESULTS_ON_PAGE'}}}})
            return SimpleNamespace(aggregatedList=aggregated, aggregatedList_next=lambda previous_request, previous_response: None)

    gcp.discovery.apis['compute'] = Compute()
    sink = Sink()
    security.check_vpc_configuration('1', [{'projectId': 'p'}], JOB, sink=sink)
    record = sink.by_check()['VPC Configuration']
    assert record['Status'] == IR and [r['Network / Subnet'] for r in record['Finding']] == ['prod-vpc / web-b'] and calls == ['p']


# --- Organization Log Sink ----------------------------------------------------------------------------------------

def sink_entry(name, destination='pubsub.googleapis.com/projects/x/topics/t', log_filter='logName:"cloudaudit.googleapis.com"', children=True, disabled=False):
    return {'name': name, 'destination': destination, 'filter': log_filter, 'includeChildren': children, 'disabled': disabled}


def test_log_sink_rows_ignore_the_built_in_sinks_and_qualify_the_customer_ones():
    builtins = [sink_entry('_Required', 'logging.googleapis.com/organizations/1/locations/global/buckets/_Required', children=False),
                sink_entry('_Default', 'logging.googleapis.com/organizations/1/locations/global/buckets/_Default', 'NOT LOG_ID("cloudaudit.googleapis.com/activity")', children=False)]
    rows, status = operations.log_sink_rows('1', builtins)
    assert status == AR and rows[0]['Issue'].startswith('No organization-level log sink besides the built-in') and 'sinks create' in rows[0]['Fix']
    rows, status = operations.log_sink_rows('1', builtins + [sink_entry('export', disabled=True), sink_entry('local', children=False, log_filter='resource.type="gce_instance"')])
    assert status == IR and [r['Assessment'] for r in rows] == ['disabled', 'covers the organization resource only (no --include-children); filter leaves the audit logs out']
    assert all('Fix' in r for r in rows)
    rows, status = operations.log_sink_rows('1', builtins + [sink_entry('export'), sink_entry('everything', log_filter='')])
    assert status == C and [r['Assessment'] for r in rows] == ['qualifies as the organization\'s audit export'] * 2 and rows[1]['Filter'] == '(all logs)'


def test_log_sink_check_reads_every_page(gcp):
    pages = [{'sinks': [sink_entry('_Required', children=False)], 'nextPageToken': 't'}, {'sinks': [sink_entry('export')]}]

    def start(parent):
        request = _execute(pages[0])
        request.index = 0
        return request

    def next_page(previous_request, previous_response):
        if 'nextPageToken' not in previous_response:
            return None
        request = _execute(pages[previous_request.index + 1])
        request.index = previous_request.index + 1
        return request

    gcp.discovery.apis['logging'] = SimpleNamespace(organizations=lambda: SimpleNamespace(sinks=lambda: SimpleNamespace(list=start, list_next=next_page)))
    sink = Sink()
    operations.check_audit_logging('1', JOB, sink=sink)
    record = sink.by_check()['Organization Log Sink']
    assert record['Status'] == C and [r['Sink Name'] for r in record['Finding']] == ['export']


# --- Data Access Audit Logs ---------------------------------------------------------------------------------------

def audit(*types, service='allServices', exempt=()):
    return {'service': service, 'auditLogConfigs': [{'logType': t, **({'exemptedMembers': list(exempt)} if exempt else {})} for t in types]}


def test_audit_config_assessment_unions_the_hierarchy():
    full = operations.audit_config_assessment([('organizations/1', [audit('ADMIN_READ', 'DATA_READ', 'DATA_WRITE')])])
    assert (full['status'], full['missing'], full['configured_at']) == (C, [], ['organizations/1'])
    none = operations.audit_config_assessment([('organizations/1', []), ('projects/p', [])])
    assert (none['status'], none['missing'], none['configured_at']) == (AR, ['ADMIN_READ', 'DATA_READ', 'DATA_WRITE'], [])
    partial = operations.audit_config_assessment([('organizations/1', [audit('ADMIN_READ', 'DATA_WRITE')]), ('projects/p', [audit('DATA_READ', service='storage.googleapis.com')])])
    assert (partial['status'], partial['missing'], partial['services']) == (IR, ['DATA_READ'], {'storage.googleapis.com': ['DATA_READ']})
    union = operations.audit_config_assessment([('organizations/1', [audit('ADMIN_READ', 'DATA_WRITE')]), ('projects/p', [audit('DATA_READ')])])
    assert (union['status'], union['types']) == (C, ['ADMIN_READ', 'DATA_READ', 'DATA_WRITE'])
    exempted = operations.audit_config_assessment([('organizations/1', [audit('ADMIN_READ', 'DATA_READ', 'DATA_WRITE', exempt=('user:a@x.com',))])])
    assert exempted['status'] == IR and exempted['exemptions'] == {'ADMIN_READ': ['user:a@x.com'], 'DATA_READ': ['user:a@x.com'], 'DATA_WRITE': ['user:a@x.com']}
    row = operations.data_access_row('project', 'p', partial)
    assert row['Missing'] == 'DATA_READ' and row['Configured at'] == 'organizations/1, projects/p' and 'gcloud projects set-iam-policy p policy.yaml' in row['Fix']
    assert 'significant log volume' in row['Issue']
    assert 'Fix' not in operations.data_access_row('organization', '1', full)


def test_data_access_check_reads_the_project_and_its_ancestors(gcp):
    policies = {'organizations/1': {'auditConfigs': [audit('ADMIN_READ', 'DATA_WRITE')]}, 'folders/2': {'bindings': []}, 'p': {'auditConfigs': [audit('DATA_READ')]}}

    class Crm:
        def projects(self):
            return SimpleNamespace(getAncestry=lambda projectId, body: _execute({'ancestor': [{'resourceId': {'type': 'project', 'id': 'p'}}, {'resourceId': {'type': 'folder', 'id': '2'}},
                                                                                              {'resourceId': {'type': 'organization', 'id': '1'}}]}),
                                   getIamPolicy=lambda resource, body: _execute(policies[resource]))

        def organizations(self):
            return SimpleNamespace(getIamPolicy=lambda resource, body: _execute(policies[resource]))

        def folders(self):
            return SimpleNamespace(getIamPolicy=lambda resource, body: _execute(policies[resource]), get=lambda name: _execute({'name': name, 'parent': 'organizations/1'}))

    gcp.discovery.apis['cloudresourcemanager'] = Crm()
    sink = Sink()
    operations.check_data_access_audit_logs('project', 'p', JOB, sink=sink)
    record = sink.by_check()['Data Access Audit Logs']
    assert record['Status'] == C and record['Finding'][0]['Configured at'] == 'organizations/1, projects/p'
    sink = Sink()
    operations.check_data_access_audit_logs('folder', '2', JOB, sink=sink)
    record = sink.by_check()['Data Access Audit Logs']
    assert record['Status'] == IR and record['Finding'][0]['Missing'] == 'DATA_READ' and record['Finding'][0]['Resource'] == 'folders/2'
    sink = Sink()
    operations.check_data_access_audit_logs('organization', '1', JOB, sink=sink)
    assert sink.by_check()['Data Access Audit Logs']['Status'] == IR
    assert CATEGORY_MAP['Data Access Audit Logs'] == 'Operational Excellence & Observability'


# --- Essential Contacts -------------------------------------------------------------------------------------------

def contact(email, *categories, state='VALID'):
    return {'email': email, 'notificationCategorySubscriptions': list(categories), 'validationState': state}


def test_invalid_contacts_do_not_count_and_the_compliant_row_names_who_receives_what():
    contacts = [contact('sec@x.com', 'SECURITY', 'TECHNICAL'), contact('legal@x.com', 'LEGAL', 'SUSPENSION', state='INVALID'), contact('all@x.com', 'ALL')]
    assert reliability.missing_contact_categories(reliability.valid_contacts(contacts)) == []  # ALL covers the bounced one's categories
    assert reliability.missing_contact_categories(reliability.valid_contacts(contacts[:2])) == ['LEGAL', 'SUSPENSION']
    assert reliability.contacts_by_category(contacts).startswith('SECURITY: all@x.com, sec@x.com · TECHNICAL: all@x.com, sec@x.com · LEGAL: all@x.com, legal@x.com')


def test_contacts_check_computes_the_effective_contacts_of_a_project(gcp):
    calls = []

    def compute(parent, notificationCategories):
        calls.append((parent, tuple(notificationCategories)))
        return _execute({'contacts': [contact('sec@x.com', 'SECURITY', 'TECHNICAL'), contact('legal@x.com', 'LEGAL', state='INVALID')]})

    gcp.discovery.apis['essentialcontacts'] = SimpleNamespace(
        projects=lambda: SimpleNamespace(contacts=lambda: SimpleNamespace(compute=compute)),
        organizations=lambda: SimpleNamespace(contacts=lambda: SimpleNamespace(list=lambda parent: _execute({'contacts': [contact('all@x.com', 'ALL')]}))))
    sink = Sink()
    reliability.check_essential_contacts('project', 'p', JOB, sink=sink)
    record = sink.by_check()['Essential Contacts']
    assert record['Status'] == AR and record['Finding'][0]['Missing Categories'] == 'LEGAL, SUSPENSION'
    assert '1 contact with a bounced address not counted' in record['Finding'][0]['Issue']
    assert record['Finding'][0]['Fix'] == 'gcloud essential-contacts create --project=p --email=<address> --notification-categories=LEGAL,SUSPENSION'
    assert calls == [('projects/p', tuple(reliability.REQUIRED_CONTACT_CATEGORIES))]
    sink = Sink()
    reliability.check_essential_contacts('organization', '1', JOB, sink=sink)
    record = sink.by_check()['Essential Contacts']
    assert record['Status'] == C and record['Finding'][0]['Contacts'].startswith('SECURITY: all@x.com')


# --- Cost recommendations -----------------------------------------------------------------------------------------

def reco(description, priority='P2', resource='vm-1', usd=10):
    return SimpleNamespace(name='r', description=description, recommender_subtype='X', priority=SimpleNamespace(name=priority),
                           content=SimpleNamespace(overview={'resourceName': resource}),
                           primary_impact=SimpleNamespace(cost_projection=SimpleNamespace(cost=SimpleNamespace(units=-usd, nanos=0, currency_code='USD'))))


def test_cost_rows_carry_priority_and_fix_and_the_priority_decides_the_verdict():
    row = cost.parse_recommendation(reco('Save cost by changing machine type from n1-standard-4 to e2-standard-2.'), 'p', check='VM Rightsizing', location='us-central1-a')
    assert (row['Priority'], row['_status']) == ('P2', AR)
    assert row['Fix'] == ('gcloud compute instances stop vm-1 --zone=us-central1-a --project=p && gcloud compute instances set-machine-type vm-1 --zone=us-central1-a --project=p '
                          '--machine-type=e2-standard-2 && gcloud compute instances start vm-1 --zone=us-central1-a --project=p')
    low = cost.parse_recommendation(reco('Delete the unassociated address.', priority='P4', resource='ip-1'), 'p', check='Unassociated IPs', location='us-central1')
    assert (low['Priority'], low['_status'], low['Fix']) == ('P4', IR, 'gcloud compute addresses delete ip-1 --region=us-central1 --project=p')
    unrated = cost.parse_recommendation(reco('Idle image.', priority='PRIORITY_UNSPECIFIED', resource='img'), 'p', check='Idle Images', location='global')
    assert (unrated['Priority'], unrated['_status'], unrated['Fix']) == ('unrated', AR, 'gcloud compute images delete img --project=p')
    mig = cost.parse_recommendation(reco('Change the machine type to e2-standard-4.', resource='web-mig'), 'p', check='MIG Rightsizing', location='us-central1-a')
    assert 'rolling-action start-update web-mig' in mig['Fix'] and 'e2-standard-4' in mig['Fix']
    assert cost.COST_RECOMMENDERS['MIG Rightsizing'] == ('google.compute.instanceGroupManager.MachineTypeRecommender', 'zone') and len(cost.COST_RECOMMENDERS) == 14
    assert '_status' not in cost.parse_recommendation(reco('x'), 'p')  # the legacy call shape keeps the legacy row


# --- GKE Hygiene: auto-repair -------------------------------------------------------------------------------------

def test_gke_hygiene_flags_auto_repair_off():
    cluster = {'name': 'prod', 'location': 'us-central1', 'releaseChannel': {'channel': 'REGULAR'},
               'nodePools': [{'name': 'a', 'management': {'autoUpgrade': True, 'autoRepair': False}}, {'name': 'b', 'management': {'autoUpgrade': True, 'autoRepair': True}}]}
    rows = reliability.gke_hygiene_rows('p', cluster)
    assert [(r['Node Pool'], r['Issue']) for r in rows] == [('a', 'Auto-repair disabled.')]
    assert rows[0]['Fix'] == 'gcloud container node-pools update a --cluster=prod --location=us-central1 --project=p --enable-autorepair'


# --- Quota: project-global quotas ---------------------------------------------------------------------------------

def test_quota_check_reads_the_project_global_quotas(gcp):
    class Compute:
        def regions(self):
            return SimpleNamespace(list=lambda project: _execute({'items': [{'name': 'us-central1', 'quotas': [{'metric': 'CPUS', 'usage': 10.0, 'limit': 100.0}]}]}),
                                   list_next=lambda previous_request, previous_response: None)

        def projects(self):
            return SimpleNamespace(get=lambda project: _execute({'quotas': [{'metric': 'FIREWALLS', 'usage': 170.0, 'limit': 200.0}, {'metric': 'NETWORKS', 'usage': 2.0, 'limit': 15.0}]}))

    gcp.discovery.apis['compute'] = Compute()
    sink = Sink()
    operations.run_service_limit_checks_refactored('1', [{'projectId': 'p'}], JOB, sink=sink)
    record = sink.by_check()['Quota Utilization (>80%)']
    assert record['Status'] == IR and [(r['Region'], r['Metric'], r['Usage']) for r in record['Finding']] == [('global', 'FIREWALLS', '85.0%')]


def test_firewall_complexity_is_retired():
    assert 'FIREWALL_COMPLEXITY_CHECK' not in dir(operations)
    assert CATEGORY_MAP['VPC Firewall Complexity (>150 Rules)'] == 'Operational Excellence & Observability'  # older summaries still name it


# --- The policy table: bundled, overridable, with provenance --------------------------------------------------------

TABLE = """Name,Type,Recommended to set *,ID
Identity,,,
Disable key creation,Boolean,Should have,iam.disableServiceAccountKeyCreation
Domain restricted sharing,List,Should have,iam.allowedPolicyMemberDomains
Networking,,,
External IPs,List,Should have,compute.vmExternalIpAccess
"""
OVERRIDES = """Name,Type,Recommended to set *,ID
Identity,,,
Disable key creation,Boolean,Wont have,iam.disableServiceAccountKeyCreation
Networking,,,
External IPs,List,Skip,compute.vmExternalIpAccess
Custom,,,
No public buckets (custom),Boolean,Must have,custom.noPublicBuckets
"""


def test_the_bundled_table_is_the_default_and_parses():
    gcp_clients.reset_provider()
    text = read_policy_table(BUNDLED_POLICY_TABLE)
    table = parse_best_practices_csv(text)
    assert sum(len(v) for v in table.values()) >= 130 and all('type' in p for policies in table.values() for p in policies)
    assert read_policy_table(None) == text and read_policy_table('') == text


def test_overrides_merge_by_constraint_id():
    table = parse_best_practices_csv(TABLE)
    merged, applied, skipped = apply_policy_overrides(table, parse_best_practices_csv(OVERRIDES, overrides=True))
    assert (applied, skipped) == (2, 1)
    by_id = {p['policyId']: (category, p) for category, policies in merged.items() for p in policies}
    assert by_id['iam.disableServiceAccountKeyCreation'][0] == 'Identity' and by_id['iam.disableServiceAccountKeyCreation'][1]['expectedValue'] == 'False'  # replaced in place
    assert 'compute.vmExternalIpAccess' not in by_id  # skipped
    assert by_id['custom.noPublicBuckets'] == ('Custom', {'policyId': 'custom.noPublicBuckets', 'displayName': 'No public buckets (custom)', 'expectedValue': 'True', 'type': 'Boolean'})
    assert parse_best_practices_csv(OVERRIDES)['Networking'] == []  # without overrides=True a Skip row is just dropped


def test_fetch_reads_the_source_and_the_overrides_and_records_the_provenance(gcp, monkeypatch):
    monkeypatch.setattr(gcp_clients.current_provider(), 'policy_table', lambda: TABLE, raising=False)
    fetched = fetch_best_practices(results_bucket='')
    meta = fetched[POLICY_TABLE_META]
    assert (meta['source'], meta['rows'], meta['overrides']) == (BUNDLED_POLICY_TABLE, 3, None) and len(meta['digest']) == 12
    assert describe_policy_table(meta) == f"bundled table (3 rows, {meta['digest']})"
    gcp.storage.bucket('results').blob(POLICY_OVERRIDES_OBJECT).upload_from_string(OVERRIDES)
    fetched = fetch_best_practices(results_bucket='results')
    meta = fetched[POLICY_TABLE_META]
    assert meta['overrides'] == {'source': f'gs://results/{POLICY_OVERRIDES_OBJECT}', 'applied': 2, 'skipped': 1}
    assert describe_policy_table(meta) == f"bundled table (3 rows, {meta['digest']}) · 2 overrides, 1 skipped (gs://results/{POLICY_OVERRIDES_OBJECT})"
    # The provenance is not a category: the evaluation and the summary skip it, the summary shows it.
    evaluated = dict(evaluate_org_policies(fetched, {}))
    assert POLICY_TABLE_META not in evaluated and set(evaluated) == {'Custom', 'Identity'}
    summary = build_org_policy_summary((fetched, {}))
    assert summary.total == 3 and summary.source.startswith('bundled table (3 rows')  # Identity 2 (one replaced) + Custom 1; the skipped row is gone
    gcp.storage.bucket('mine').blob('policies.csv').upload_from_string(TABLE)
    fetched = fetch_best_practices(url='gs://mine/policies.csv', results_bucket='')
    assert fetched[POLICY_TABLE_META]['source'] == 'gs://mine/policies.csv' and fetched[POLICY_TABLE_META]['rows'] == 3
    monkeypatch.setattr(gcp_clients, 'http_get', lambda url, **kwargs: SimpleNamespace(status_code=200, text=TABLE, raise_for_status=lambda: None))
    assert fetch_best_practices(url='https://example.com/t.csv', results_bucket='')[POLICY_TABLE_META]['source'] == 'https://example.com/t.csv'
    assert fetch_best_practices(url='gs://missing/policies.csv', results_bucket='').startswith('Error reading or parsing the policy table')


def test_an_overrides_file_that_cannot_be_read_or_parsed_is_the_checks_error_not_a_silent_omission(gcp, monkeypatch):
    monkeypatch.setattr(gcp_clients.current_provider(), 'policy_table', lambda: TABLE, raising=False)
    gcp.storage.bucket('results').blob(POLICY_OVERRIDES_OBJECT).upload_from_string('Name,Type,Recommended to set *\nIdentity,,\n')  # no ID column
    assert fetch_best_practices(results_bucket='results').startswith('Error reading or parsing the policy table')
    gcp.storage.bucket('results').blob(POLICY_OVERRIDES_OBJECT).upload_from_string(OVERRIDES)
    blob_class = type(gcp.storage.bucket('results').blob(POLICY_OVERRIDES_OBJECT))

    def denied(self):
        if self.name == POLICY_OVERRIDES_OBJECT:
            raise PermissionError('403 the scanner may not read this object')
        return (self.bucket.objects[self.name][0])
    monkeypatch.setattr(blob_class, 'download_as_text', denied)
    error = fetch_best_practices(results_bucket='results')
    assert error.startswith('Error reading or parsing the policy table') and f'gs://results/{POLICY_OVERRIDES_OBJECT}' in error and '403' in error
    assert fetch_best_practices(results_bucket='other')[POLICY_TABLE_META]['overrides'] is None  # no file there: the table as it is


# --- The release's rule changes -----------------------------------------------------------------------------------

def test_every_loose_rule_draws_its_line_at_v18_1():
    for name in ['Organization Log Sink', 'Essential Contacts', 'Quota Utilization (>80%)', 'GKE Hygiene',
                 *(name for name in cost.COST_RECOMMENDERS if name != 'MIG Rightsizing')]:
        assert RESHAPED_CHECKS[name] == ('18.1', RULE_CHANGED), name
    assert RESHAPED_CHECKS['VPC Configuration'] == ('18.3', RULE_CHANGED)  # redrawn again in v18.3 (legacy networks)
    assert RESHAPED_CHECKS['Cloud Storage Versioning'] == ('18.6', RULE_CHANGED)  # redrawn again in v18.6 (zonal buckets out)
    for name in ('Data Access Audit Logs', 'MIG Rightsizing'):
        assert name not in RESHAPED_CHECKS, name  # a new check is "new check" on the Changes card by the existing rule
