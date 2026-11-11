"""
v18.4 — Data governance: the rules of ``app.checks.data_governance`` on fixtures of the shapes Asset Inventory and the IAM-policy
search return (a dataset's ACL, a Cloud SQL instance's flag list, an AlloyDB cluster and instance, a KMS key, an API key), the
five checks end to end, and the guard that the five names enter the Changes card as new checks.
"""
from collections import UserDict
from datetime import datetime, timezone
from types import SimpleNamespace

from app.checks import data_governance as dg
from app.checks.not_checked import NOT_CHECKED
from app.reporting.changes import RESHAPED_CHECKS

JOB = 'job-184'
AR, IR, C = 'Action Required', 'Investigation Recommended', 'Compliant'
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
PROJECT = 'stark-data-prod'


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


def asset(service, path, data, project=PROJECT):
    return SimpleNamespace(name=f'//{service}.googleapis.com/projects/{project}/{path}', resource=SimpleNamespace(data=data))


def policy(resource, *bindings):
    """An IAM-policy search result: ``bindings`` are ``(role, [members])``."""
    return SimpleNamespace(resource=resource, policy=SimpleNamespace(bindings=[SimpleNamespace(role=role, members=list(members)) for role, members in bindings]))


# --- the shapes --------------------------------------------------------------------------------------------------------

def dataset(dataset_id, hours=None, public=None, project=PROJECT):
    access = [{'role': 'WRITER', 'specialGroup': 'projectWriters'}, {'role': 'OWNER', 'specialGroup': 'projectOwners'},
              {'role': 'OWNER', 'userByEmail': 'owner@example.test'}, {'role': 'READER', 'specialGroup': 'projectReaders'}]
    if public:
        access.append({'role': 'READER', 'specialGroup': public} if public.startswith('all') else {'role': 'READER', 'iamMember': public})
    data = {'kind': 'bigquery#dataset', 'id': f'{project}:{dataset_id}', 'datasetReference': {'datasetId': dataset_id, 'projectId': project},
            'access': access, 'location': 'asia-south1', 'type': 'DEFAULT',
            'selfLink': f'https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets/{dataset_id}'}
    if hours is not None:
        data['maxTimeTravelHours'] = str(hours)  # the inventory carries it as a string
    return asset('bigquery', f'datasets/{dataset_id}', data, project)


def sql_instance(name, version='POSTGRES_15', flags=None, kind='CLOUD_SQL_INSTANCE', project=PROJECT):
    settings = {'tier': 'db-custom-1-3840', 'availabilityType': 'ZONAL'}
    if flags is not None:
        settings['databaseFlags'] = [{'name': k, 'value': v} for k, v in flags.items()]
    return asset('cloudsql', f'instances/{name}', {'kind': 'sql#instance', 'name': name, 'databaseVersion': version, 'instanceType': kind, 'region': 'asia-south1',
                                                   'settings': settings, 'selfLink': f'https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances/{name}'}, project)


def alloy_cluster(name='alloy-main', backups=True, continuous=True):
    return asset('alloydb', f'locations/asia-south1/clusters/{name}',
                 {'name': f'projects/{PROJECT}/locations/asia-south1/clusters/{name}', 'state': 'READY', 'clusterType': 'PRIMARY',
                  'automatedBackupPolicy': {'enabled': backups, 'weeklySchedule': {}}, 'continuousBackupConfig': {'enabled': continuous, 'recoveryWindowDays': 14}})


def alloy_instance(name='alloy-primary', cluster='alloy-main', kind='PRIMARY', availability='REGIONAL', public=False, ssl='ENCRYPTED_ONLY', flags=None):
    data = {'name': f'projects/{PROJECT}/locations/asia-south1/clusters/{cluster}/instances/{name}', 'instanceType': kind, 'availabilityType': availability,
            'state': 'READY', 'networkConfig': {'enablePublicIp': public}, 'clientConnectionConfig': {'sslConfig': {'sslMode': ssl}}}
    if flags is not None:
        data['databaseFlags'] = flags
    return asset('alloydb', f'locations/asia-south1/clusters/{cluster}/instances/{name}', data)


def kms_key(name, purpose='ENCRYPT_DECRYPT', period=None, next_time=None, state='ENABLED', ring='ring-main'):
    data = {'name': f'projects/{PROJECT}/locations/asia-south1/keyRings/{ring}/cryptoKeys/{name}', 'purpose': purpose,
            'primary': {'name': f'projects/{PROJECT}/locations/asia-south1/keyRings/{ring}/cryptoKeys/{name}/cryptoKeyVersions/1', 'state': state},
            'versionTemplate': {'protectionLevel': 'SOFTWARE', 'algorithm': 'GOOGLE_SYMMETRIC_ENCRYPTION' if purpose == 'ENCRYPT_DECRYPT' else 'EC_SIGN_P256_SHA256'}}
    if period:
        data['rotationPeriod'] = period
    if next_time:
        data['nextRotationTime'] = next_time
    return asset('cloudkms', f'locations/asia-south1/keyRings/{ring}/cryptoKeys/{name}', data)


NUMBER = '385900000001'  # the inventory names API keys by project number


def api_key(uid, display, created, restrictions=None):
    return asset('apikeys', f'locations/global/keys/{uid}', {'name': f'projects/{NUMBER}/locations/global/keys/{uid}', 'uid': uid, 'displayName': display,
                                                          'createTime': created, 'restrictions': restrictions or {}}, project=NUMBER)


def project_result(project_id=PROJECT, number=NUMBER):
    return SimpleNamespace(name=f'//cloudresourcemanager.googleapis.com/projects/{project_id}', project=f'projects/{number}', display_name=project_id)


# --- Cloud SQL Flags --------------------------------------------------------------------------------------------------------

def test_engine_and_flag_values_are_read_from_the_instance():
    assert [dg.engine_of(v) for v in ('MYSQL_8_0', 'POSTGRES_15', 'SQLSERVER_2019_STANDARD', 'POSTGRES_17', None, 'ORACLE')] == ['MYSQL', 'POSTGRES', 'SQLSERVER', 'POSTGRES', '', '']
    assert dg.flag_values({'settings': {'databaseFlags': [{'name': 'log_connections', 'value': 'on'}, {'name': 'max_connections', 'value': '100'}]}}) == {'log_connections': 'on', 'max_connections': '100'}
    assert dg.flag_values({'settings': {}}) == {} and dg.flag_values({}) == {}
    assert dg.flag_values({'databaseFlags': {'log_connections': 'on'}}) == {'log_connections': 'on'}  # AlloyDB: a map
    # The inventory's maps are proto MapComposites — Mappings, not dicts; iterating one as a list yields its keys (the second canary
    # read Error: 'str' object has no attribute 'get').
    assert dg.flag_values({'databaseFlags': UserDict({'password.enforce_complexity': 'on'})}) == {'password.enforce_complexity': 'on'}


def test_the_flag_packs_read_an_unset_flag_as_its_engine_default():
    """Bare instances: what the engine defaults fail. PostgreSQL's defaults already satisfy four of the eight CIS items."""
    assert [(f, c, v) for f, c, _, v, _ in dg.flag_findings('POSTGRES', {})] == [
        ('log_connections', 'off (default)', IR), ('log_disconnections', 'off (default)', IR), ('log_statement', 'none (default)', IR), ('cloudsql.enable_pgaudit', 'off (default)', IR)]
    assert [(f, c, v) for f, c, _, v, _ in dg.flag_findings('MYSQL', {})] == [('local_infile', 'on (default)', AR), ('skip_show_database', 'off (default)', IR)]
    assert [(f, c, v) for f, c, _, v, _ in dg.flag_findings('SQLSERVER', {})] == [('remote access', 'on (default)', AR), ('3625', 'off (default)', IR)]
    assert dg.flag_findings('', {}) == []  # an engine without a pack


def test_the_ordered_postgres_scales_and_the_other_pack_entries():
    full = {'log_connections': 'on', 'log_disconnections': 'on', 'log_statement': 'ddl', 'cloudsql.enable_pgaudit': 'on'}
    assert dg.flag_findings('POSTGRES', full) == []
    assert [(f, c) for f, c, *_ in dg.flag_findings('POSTGRES', {**full, 'log_min_messages': 'error', 'log_min_error_statement': 'panic', 'log_statement': 'all'})] == []
    assert [(f, c) for f, c, *_ in dg.flag_findings('POSTGRES', {**full, 'log_min_messages': 'debug1', 'log_min_error_statement': 'warning', 'log_error_verbosity': 'verbose',
                                                                 'log_min_duration_statement': '0', 'log_statement': 'none'})] == [
        ('log_error_verbosity', 'verbose'), ('log_min_messages', 'debug1'), ('log_min_error_statement', 'warning'), ('log_min_duration_statement', '0'), ('log_statement', 'none')]
    assert [(f, c) for f, c, *_ in dg.flag_findings('POSTGRES', {**full, 'log_min_messages': 'bogus'})] == [('log_min_messages', 'bogus')]  # an unknown level is not "stricter"
    assert dg.flag_findings('MYSQL', {'local_infile': 'off', 'skip_show_database': 'on'}) == []
    assert [(f, c, v) for f, c, _, v, _ in dg.flag_findings('MYSQL', {'local_infile': 'ON'})] == [('local_infile', 'ON', AR), ('skip_show_database', 'off (default)', IR)]
    sqlserver = {'remote access': 'off', '3625': 'on'}
    assert dg.flag_findings('SQLSERVER', sqlserver) == []
    assert [(f, v) for f, _, _, v, _ in dg.flag_findings('SQLSERVER', {**sqlserver, 'external scripts enabled': 'on', 'cross db ownership chaining': 'on', 'user connections': '10',
                                                                       'user options': '123', 'contained database authentication': 'on'})] == [
        ('external scripts enabled', AR), ('cross db ownership chaining', AR), ('user connections', IR), ('user options', IR), ('contained database authentication', AR)]


def test_sql_flag_rows_skip_replicas_and_keep_the_flags_already_set_in_the_fix():
    facts = dg.by_kind([sql_instance('aura-db'), sql_instance('aura-db-replica', kind='READ_REPLICA_INSTANCE'),
                        sql_instance('orders-db', 'MYSQL_8_0', {'local_infile': 'off', 'max_connections': '500'}),
                        sql_instance('erp-db', 'SQLSERVER_2019_STANDARD', {'remote access': 'off', '3625': 'on', 'user options': '123'})])
    rows = dg.sql_flag_rows(facts['instances'])
    assert [(r['Instance'], r['Flag'], r['Current'], r['Expected'], r['_status']) for r in rows] == [
        ('aura-db', 'log_connections', 'off (default)', 'on', IR), ('aura-db', 'log_disconnections', 'off (default)', 'on', IR),
        ('aura-db', 'log_statement', 'none (default)', 'ddl or stricter', IR), ('aura-db', 'cloudsql.enable_pgaudit', 'off (default)', 'on', IR),
        ('orders-db', 'skip_show_database', 'off (default)', 'on', IR), ('erp-db', 'user options', '123', 'not set', IR)]
    assert rows[0] == {'Project': PROJECT, 'Instance': 'aura-db', 'Engine': 'POSTGRES_15', 'Flag': 'log_connections', 'Current': 'off (default)', 'Expected': 'on',
                       'Issue': 'CIS 6.2.1: log_connections is off (default), expected on.',
                       'Fix': f'gcloud sql instances patch aura-db --project={PROJECT} --database-flags=log_connections=on  # patch replaces the whole list: the flags already set are included',
                       '_status': IR}
    assert rows[2]['Fix'].split('--database-flags=')[1].split('  #')[0] == 'log_statement=ddl'  # the first word of "ddl or stricter"
    assert rows[4]['Fix'].split('--database-flags=')[1].split('  #')[0] == 'local_infile=off,max_connections=500,skip_show_database=on'  # patch replaces the list
    assert rows[5]['Fix'].split('--database-flags=')[1].split('  #')[0] == 'remote access=off,3625=on'  # "user options" is removed, not set to ""
    assert all(set(r) == set(rows[0]) for r in rows)


# --- BigQuery Governance -----------------------------------------------------------------------------------------------------

def test_bigquery_rows_public_access_from_the_acl_and_the_policy_search_and_the_time_travel_window():
    grouped = dg.by_kind([dataset('analytics', 168), dataset('scratch', 48), dataset('open_data', public='allAuthenticatedUsers'), dataset('legacy'),
                          dataset('exports', 24, public='allUsers')])
    public = dg.public_policy_rows([
        policy(f'//bigquery.googleapis.com/projects/{PROJECT}/datasets/open_data', ('roles/bigquery.dataViewer', ['allAuthenticatedUsers'])),  # the ACL said so already
        policy(f'//bigquery.googleapis.com/projects/{PROJECT}/datasets/legacy/tables/events', ('roles/bigquery.dataViewer', ['user:a@example.test', 'allUsers'])),
        policy(f'//bigquery.googleapis.com/projects/{PROJECT}/datasets/analytics', ('roles/bigquery.dataEditor', ['group:data@example.test'])),  # not public
        policy(f'//bigquery.googleapis.com/projects/{PROJECT}/datasets/legacy', ('roles/bigquery.dataViewer', ['allUsers'])),  # IAM only, no ACL entry
    ])
    assert sorted(public) == [f'//bigquery.googleapis.com/projects/{PROJECT}/datasets/legacy', f'//bigquery.googleapis.com/projects/{PROJECT}/datasets/legacy/tables/events',
                              f'//bigquery.googleapis.com/projects/{PROJECT}/datasets/open_data']
    rows = dg.bigquery_rows(grouped, public)
    assert [(r['Resource'], r['Issue'], r['_status']) for r in rows] == [
        ('dataset scratch', 'Time travel shortened.', IR), ('dataset open_data', 'Dataset open to the public.', AR),
        ('dataset exports', 'Dataset open to the public.', AR), ('dataset exports', 'Time travel shortened.', IR),
        ('dataset legacy', 'Dataset open to the public.', AR), ('table legacy.events', 'Table open to the public.', AR)]
    assert rows[0]['Detail'].startswith('48 hours instead of 168') and rows[0]['Fix'] == f'bq update --max_time_travel_hours=168 {PROJECT}:scratch'
    assert rows[1]['Detail'] == 'allAuthenticatedUsers as READER: anyone on the internet (or any Google account) reads it.'
    assert 'remove the allAuthenticatedUsers entry from access' in rows[1]['Fix']
    assert rows[4]['Fix'] == f'bq remove-iam-policy-binding --member=allUsers --role=roles/bigquery.dataViewer {PROJECT}:legacy'
    assert rows[5]['Fix'] == f'bq remove-iam-policy-binding --member=allUsers --role=roles/bigquery.dataViewer {PROJECT}:legacy.events'
    assert all(set(r) == {'Project', 'Resource', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    assert dg.bigquery_rows(dg.by_kind([dataset('analytics', 168), dataset('legacy')]), {}) == []


def test_bigquery_resource_parsing():
    assert dg.bigquery_resource('//bigquery.googleapis.com/projects/p/datasets/d') == ('p', 'dataset d', 'd', False)
    assert dg.bigquery_resource('//bigquery.googleapis.com/projects/p/datasets/d/tables/t') == ('p', 'table d.t', 'd', True)
    assert dg.dataset_public_entries({'access': [{'role': 'OWNER', 'iamMember': 'allUsers'}, {'role': 'READER', 'userByEmail': 'x@example.test'}]}) == [('OWNER', 'allUsers')]


# --- AlloyDB Posture ---------------------------------------------------------------------------------------------------------

def test_alloydb_rows_backups_zonal_primary_public_ip_tls_and_log_flags():
    grouped = dg.by_kind([alloy_cluster(backups=False, continuous=False),
                          alloy_instance(availability='ZONAL', public=True, ssl='ALLOW_UNENCRYPTED_AND_ENCRYPTED', flags=UserDict({'log_min_messages': 'debug1', 'log_statement': 'none'})),
                          alloy_instance('alloy-pool', kind='READ_POOL', availability='ZONAL', flags={'log_connections': 'on', 'log_disconnections': 'on'}),  # a zonal read pool is no finding
                          alloy_cluster('alloy-dr'), alloy_instance('alloy-dr-primary', 'alloy-dr', flags={'log_connections': 'on', 'log_disconnections': 'on'})])
    rows = dg.alloydb_rows(grouped)
    assert [(r['Cluster'], r['Instance'], r['Issue'], r['_status']) for r in rows] == [
        ('alloy-main', '(cluster)', 'Automated backups off.', AR), ('alloy-main', '(cluster)', 'Continuous backup off.', IR),
        ('alloy-main', 'alloy-primary', 'Zonal primary.', IR), ('alloy-main', 'alloy-primary', 'Public IP enabled.', IR),
        ('alloy-main', 'alloy-primary', 'TLS not enforced.', IR),
        ('alloy-main', 'alloy-primary', 'log_connections is off (default).', IR), ('alloy-main', 'alloy-primary', 'log_disconnections is off (default).', IR),
        ('alloy-main', 'alloy-primary', 'log_min_messages is debug1.', IR)]  # log_statement and pgAudit are Cloud SQL items, not AlloyDB's
    assert rows[0]['Fix'].startswith(f'gcloud alloydb clusters update alloy-main --region=asia-south1 --project={PROJECT} --automated-backup-start-times')
    assert rows[2]['Fix'] == f'gcloud alloydb instances update alloy-primary --cluster=alloy-main --region=asia-south1 --project={PROJECT} --availability-type=REGIONAL'
    assert rows[7]['Fix'].endswith('--database-flags=log_min_messages=warning  # with the flags already set')
    assert all(set(r) == {'Project', 'Cluster', 'Instance', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)


# --- KMS Keys ----------------------------------------------------------------------------------------------------------------

def test_kms_rows_rotation_public_access_and_separation_of_duties():
    grouped = dg.by_kind([kms_key('data-key'), kms_key('slow-key', period='15552000s', next_time='2026-12-01T00:00:00Z'),
                          kms_key('late-key', period='7776000s', next_time='2026-10-01T00:00:00Z'), kms_key('good-key', period='7776000s', next_time='2026-12-01T00:00:00Z'),
                          kms_key('signing-key', purpose='ASYMMETRIC_SIGN'), kms_key('old-key', state='DESTROYED'), kms_key('mac-key', purpose='MAC')])
    public = dg.public_policy_rows([policy(f'//cloudkms.googleapis.com/projects/{PROJECT}/locations/asia-south1/keyRings/ring-main', ('roles/cloudkms.viewer', ['allAuthenticatedUsers'])),
                                    policy(f'//cloudkms.googleapis.com/projects/{PROJECT}/locations/asia-south1/keyRings/ring-main/cryptoKeys/data-key', ('roles/cloudkms.cryptoKeyDecrypter', ['allUsers']))])
    roles = [policy(f'//cloudresourcemanager.googleapis.com/projects/{PROJECT}', ('roles/cloudkms.admin', ['user:ops@example.test', 'serviceAccount:kms@example.test']),
                    ('roles/cloudkms.cryptoKeyEncrypterDecrypter', ['user:ops@example.test', 'serviceAccount:app@example.test'])),
             policy(f'//cloudkms.googleapis.com/projects/{PROJECT}/locations/asia-south1/keyRings/ring-main', ('roles/cloudkms.admin', ['user:dba@example.test']),
                    ('roles/cloudkms.cryptoKeyEncrypter', ['user:dba@example.test']), ('roles/cloudkms.cryptoKeyDecrypter', ['user:dba@example.test']))]
    rows = dg.kms_rows(grouped, public, roles, NOW)
    assert [(r['Key'], r['Issue'], r['_status']) for r in rows] == [
        ('ring-main/data-key', 'No rotation period.', IR), ('ring-main/slow-key', 'Rotation period above 90 days.', IR), ('ring-main/late-key', 'Rotation overdue.', IR),
        ('ring-main', 'Key ring or key open to the public.', AR), ('ring-main/data-key', 'Key ring or key open to the public.', AR),
        (f'projects/{PROJECT}', 'Admin and user of the same keys.', IR), ('keyRings/ring-main', 'Admin and user of the same keys.', IR)]
    assert rows[0]['Fix'] == f'gcloud kms keys update data-key --keyring=ring-main --location=asia-south1 --project={PROJECT} --rotation-period=90d --next-rotation-time=2026-11-12T00:00:00Z'
    assert rows[1]['Detail'] == '180 days (CIS 1.10: at most 90).' and rows[2]['Detail'] == 'next rotation was due 2026-10-01.'
    assert rows[5]['Detail'].startswith('user:ops@example.test holds roles/cloudkms.admin and roles/cloudkms.cryptoKeyEncrypterDecrypter on')
    assert rows[6]['Detail'].startswith('user:dba@example.test holds roles/cloudkms.admin and roles/cloudkms.cryptoKeyDecrypter, roles/cloudkms.cryptoKeyEncrypter on')
    assert all(set(r) == {'Project', 'Key', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    assert dg.kms_rows(dg.by_kind([kms_key('good-key', period='7776000s', next_time='2026-12-01T00:00:00Z')]), {}, [], NOW) == []
    assert dg.parse_duration_seconds('7776000s') == 7776000 and dg.parse_duration_seconds(None) is None and dg.parse_duration_seconds('soon') is None
    assert dg.parse_time('2026-10-01T00:00:00Z') == datetime(2026, 10, 1, tzinfo=timezone.utc) and dg.parse_time('') is None and dg.parse_time('yesterday') is None
    assert dg.parse_time('2026-10-01T00:00:00.123456Z') == datetime(2026, 10, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)


# --- API Keys ----------------------------------------------------------------------------------------------------------------

def test_api_key_rows_restrictions_and_age():
    grouped = dg.by_kind([api_key('k-1', 'mobile-legacy', '2026-01-15T10:00:00.000000Z'),
                          api_key('k-2', 'maps-web', '2026-10-20T10:00:00Z', {'browserKeyRestrictions': {'allowedReferrers': ['https://www.example.test/*']}}),
                          api_key('k-3', 'backend', '2026-10-20T10:00:00Z', {'serverKeyRestrictions': {'allowedIps': ['203.0.113.0/24']}, 'apiTargets': [{'service': 'storage.googleapis.com'}]}),
                          api_key('k-4', '', '')])
    rows = dg.api_key_rows(grouped, NOW, {NUMBER: PROJECT})
    assert [(r['Key'], r['Created'], r['Issue']) for r in rows] == [
        ('mobile-legacy', '2026-01-15', 'No application restriction.'), ('mobile-legacy', '2026-01-15', 'No API restriction.'), ('mobile-legacy', '2026-01-15', 'Older than 90 days.'),
        ('maps-web', '2026-10-20', 'No API restriction.'), ('k-4', 'unknown', 'No application restriction.'), ('k-4', 'unknown', 'No API restriction.')]
    assert all(r['_status'] == IR and r['Project'] == PROJECT for r in rows)  # the number resolved to the ID
    assert rows[0]['Fix'] == f'gcloud services api-keys update k-1 --project={PROJECT} --allowed-referrers=<sites>  # or --allowed-ips / --allowed-application'
    assert rows[2]['Detail'] == 'created 2026-01-15, 300 days ago (CIS 1.15).'
    assert all(set(r) == {'Project', 'Key', 'Created', 'Issue', 'Detail', 'Fix', '_status'} for r in rows)
    assert {r['Project'] for r in dg.api_key_rows(grouped, NOW)} == {NUMBER}  # without the map the number stands (the row still says which key)


# --- the checks end to end ---------------------------------------------------------------------------------------------------

class Inventory:
    """``list_assets`` answers from ``{asset type: [assets]}``; ``search_all_iam_policies`` from ``{query: results}`` (a query mapped to an
    exception raises it); ``search_all_resources`` answers the project search with ``projects`` (an exception raises it)."""
    def __init__(self, assets=None, searches=None, error=None, projects=None):
        self.assets, self.searches, self.error, self.requests, self.queries = assets or {}, searches or {}, error, [], []
        self.projects, self.resource_searches = [project_result()] if projects is None else projects, []

    def list_assets(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return [a for t in request['asset_types'] for a in self.assets.get(t, [])]

    def search_all_iam_policies(self, request):
        self.queries.append(request)
        answer = self.searches.get(request['query'], [])
        if isinstance(answer, Exception):
            raise answer
        services = {t.split('/')[0] for t in request.get('asset_types', [])}  # the real search honours asset_types; so does the fake
        return iter([r for r in answer if not services or r.resource.split('/')[2] in services])

    def search_all_resources(self, request):
        self.resource_searches.append(request)
        if isinstance(self.projects, Exception):
            raise self.projects
        return iter(self.projects)


def test_the_five_checks_end_to_end(gcp, monkeypatch):
    assets = {'bigquery.googleapis.com/Dataset': [dataset('analytics', 168), dataset('scratch', 48)],
              'sqladmin.googleapis.com/Instance': [sql_instance('orders-db', 'MYSQL_8_0')],
              'alloydb.googleapis.com/Cluster': [alloy_cluster()], 'alloydb.googleapis.com/Instance': [alloy_instance(flags={'log_connections': 'on', 'log_disconnections': 'on'})],
              'cloudkms.googleapis.com/CryptoKey': [kms_key('data-key', period='7776000s', next_time='2999-01-01T00:00:00Z')],
              'apikeys.googleapis.com/Key': [api_key('k-3', 'backend', '2999-01-01T00:00:00Z', {'serverKeyRestrictions': {'allowedIps': ['203.0.113.0/24']}, 'apiTargets': [{'service': 'storage.googleapis.com'}]}),
                                             api_key('k-5', 'legacy', '2999-01-01T00:00:00Z', {'apiTargets': [{'service': 'storage.googleapis.com'}]})]}
    searches = {dg.PUBLIC_QUERY: [policy(f'//bigquery.googleapis.com/projects/{PROJECT}/datasets/analytics/tables/events', ('roles/bigquery.dataViewer', ['allUsers']))],
                dg.KMS_ROLES_QUERY: []}
    inventory = Inventory(assets, searches)
    monkeypatch.setattr(dg.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    for check in (dg.check_bigquery_governance, dg.check_sql_flags, dg.check_alloydb_posture, dg.check_kms_keys, dg.check_api_keys):
        check('organization', '987654321', JOB, sink=sink)
    records = sink.by_check()
    assert {name: record['Status'] for name, record in records.items()} == {'BigQuery Governance': AR, 'Cloud SQL Flags': AR, 'AlloyDB Posture': C, 'KMS Keys': C, 'API Keys': IR}
    assert [(r['Resource'], r['Issue']) for r in records['BigQuery Governance']['Finding']] == [('dataset scratch', 'Time travel shortened.'), ('table analytics.events', 'Table open to the public.')]
    assert [(r['Flag'], r['Current']) for r in records['Cloud SQL Flags']['Finding']] == [('local_infile', 'on (default)'), ('skip_show_database', 'off (default)')]
    assert records['AlloyDB Posture']['Finding'] == [{'Status': dg.ALLOYDB_ALL_CLEAR}] and records['KMS Keys']['Finding'] == [{'Status': dg.KMS_ALL_CLEAR}]
    assert [(r['Project'], r['Key'], r['Issue']) for r in records['API Keys']['Finding']] == [(PROJECT, 'legacy', 'No application restriction.')]  # the number resolved to the ID
    assert inventory.resource_searches == [{'scope': 'organizations/987654321', 'asset_types': ['cloudresourcemanager.googleapis.com/Project']}]
    assert all('_status' not in r for record in records.values() for r in record['Finding']) and sink.not_checked() == []
    assert [(r['parent'], list(r['asset_types'])) for r in inventory.requests] == [('organizations/987654321', dg.BIGQUERY_TYPES), ('organizations/987654321', dg.SQL_TYPES),
                                                                                  ('organizations/987654321', dg.ALLOYDB_TYPES), ('organizations/987654321', dg.KMS_TYPES),
                                                                                  ('organizations/987654321', dg.API_KEY_TYPES)]
    # The two IAM-policy searches: public members on datasets and tables, on key rings and keys; the KMS roles anywhere under the scope.
    assert inventory.queries == [{'scope': 'organizations/987654321', 'query': dg.PUBLIC_QUERY, 'asset_types': dg.BIGQUERY_IAM_TYPES},
                                 {'scope': 'organizations/987654321', 'query': dg.PUBLIC_QUERY, 'asset_types': dg.KMS_IAM_TYPES},
                                 {'scope': 'organizations/987654321', 'query': dg.KMS_ROLES_QUERY}]
    assert dg.KMS_ROLES_QUERY == 'roles:(roles/cloudkms.admin OR roles/cloudkms.cryptoKeyEncrypterDecrypter OR roles/cloudkms.cryptoKeyEncrypter OR roles/cloudkms.cryptoKeyDecrypter)'
    # Nothing in scope: five all-clear rows, and no project search without keys to name.
    empty = Inventory()
    monkeypatch.setattr(dg.gcp, 'asset_client', lambda credentials=None: empty)
    sink = Sink()
    for check in (dg.check_bigquery_governance, dg.check_sql_flags, dg.check_alloydb_posture, dg.check_kms_keys, dg.check_api_keys):
        check('project', 'stark-data-dev', JOB, sink=sink)
    assert {name: (record['Status'], record['Finding']) for name, record in sink.by_check().items()} == {
        'BigQuery Governance': (C, [{'Status': dg.BIGQUERY_ALL_CLEAR}]), 'Cloud SQL Flags': (C, [{'Status': dg.SQL_FLAGS_ALL_CLEAR}]), 'AlloyDB Posture': (C, [{'Status': dg.ALLOYDB_ALL_CLEAR}]),
        'KMS Keys': (C, [{'Status': dg.KMS_ALL_CLEAR}]), 'API Keys': (C, [{'Status': dg.API_KEYS_ALL_CLEAR}])}
    assert empty.resource_searches == []
    # A listing that fails: that check's Error.
    monkeypatch.setattr(dg.gcp, 'asset_client', lambda credentials=None: Inventory(error=RuntimeError('503 inventory unavailable')))
    sink = Sink()
    dg.check_sql_flags('folder', '42', JOB, sink=sink)
    assert sink.by_check()['Cloud SQL Flags'] == {'Check': 'Cloud SQL Flags', 'Finding': [{'Error': '503 inventory unavailable'}], 'Status': 'Error'}


def test_a_failed_policy_search_leaves_the_rule_under_projects_not_checked_and_the_check_standing(gcp, monkeypatch):
    searches = {dg.PUBLIC_QUERY: RuntimeError('403 cloudasset.assets.searchAllIamPolicies denied'), dg.KMS_ROLES_QUERY: [policy(
        f'//cloudresourcemanager.googleapis.com/projects/{PROJECT}', ('roles/cloudkms.admin', ['user:ops@example.test']), ('roles/cloudkms.cryptoKeyEncrypterDecrypter', ['user:ops@example.test']))]}
    inventory = Inventory({'cloudkms.googleapis.com/CryptoKey': [kms_key('data-key')], 'bigquery.googleapis.com/Dataset': [dataset('scratch', 48)]}, searches)
    monkeypatch.setattr(dg.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    dg.check_kms_keys('organization', '987654321', JOB, sink=sink, now=NOW)
    dg.check_bigquery_governance('organization', '987654321', JOB, sink=sink)
    records = sink.by_check()
    assert [(r['Key'], r['Issue']) for r in records['KMS Keys']['Finding']] == [('ring-main/data-key', 'No rotation period.'), (f'projects/{PROJECT}', 'Admin and user of the same keys.')]
    assert [(r['Resource'], r['Issue']) for r in records['BigQuery Governance']['Finding']] == [('dataset scratch', 'Time travel shortened.')]
    assert [(r['Project'], r['Skipped check']) for r in sink.not_checked()] == [
        ('organizations/987654321', 'KMS Keys (public access rule: the IAM policy search failed)'),
        ('organizations/987654321', 'BigQuery Governance (public access rule: the IAM policy search failed)')]
    assert all('403' in r['Reason'] for r in sink.not_checked())
    categories = [record['Category'] for _, record in sink.records if record['Check'] == NOT_CHECKED]
    assert categories == ['Security & Identity', 'Security & Identity']
    # The project search failing: the API-key rows name the project by number and say so under Projects not checked.
    inventory = Inventory({'apikeys.googleapis.com/Key': [api_key('k-5', 'legacy', '2999-01-01T00:00:00Z', {'apiTargets': [{'service': 'storage.googleapis.com'}]})]},
                          projects=RuntimeError('503 search unavailable'))
    monkeypatch.setattr(dg.gcp, 'asset_client', lambda credentials=None: inventory)
    sink = Sink()
    dg.check_api_keys('organization', '987654321', JOB, sink=sink)
    assert [(r['Project'], r['Key']) for r in sink.by_check()['API Keys']['Finding']] == [(NUMBER, 'legacy')]
    assert [(r['Skipped check'], r['Reason']) for r in sink.not_checked()] == [('API Keys (project names: the resource search failed; the rows name projects by number)', '503 search unavailable')]


def test_the_five_names_enter_the_changes_card_as_new_checks():
    assert dg.DATA_GOVERNANCE_CHECKS == ('BigQuery Governance', 'Cloud SQL Flags', 'AlloyDB Posture', 'KMS Keys', 'API Keys')
    assert not any(name in RESHAPED_CHECKS for name in dg.DATA_GOVERNANCE_CHECKS)  # new checks: "new check" by the existing rule
