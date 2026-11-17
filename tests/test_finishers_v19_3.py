"""
v19.3 — Bucket Logging and the databases-and-storage finishers: the two-fact rule (usage logging × Data Access logs) on fixture buckets and
IAM policies, the check end to end at every scope; the new Cloud SQL rows (password policy, server CA expiry, deletion protection, maintenance
window, IAM authentication), the AlloyDB open network, the Public Access Prevention count line, and the SCC oracle's new mappings and label.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.checks import bucket_logging as bl, security
from app.checks.bucket_logging import ALL_CLEAR, BUCKET_LOGGING_CHECK, audit_data_types, bucket_facts, check_bucket_logging, data_access_by_container, logging_rows, project_facts
from app.checks.data_governance import alloydb_rows, sql_flag_rows
from app.checks.gke_operations import ACTION_REQUIRED as AR, COMPLIANT, INFORMATIONAL as INFO, INVESTIGATION as IR
from app.checks.not_checked import NOT_CHECKED
from app.checks.scc import COVERAGE_MAP, finding_rows
from app.checks.security import cloud_sql_rows
from fakes import ORG_ID as ORG

JOB = 'job-194'
ORG_NAME = f'organizations/{ORG}'
P1, N1, P2, N2 = 'web-prod', '111', 'data-lake', '222'
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_check(self):
        return {record['Check']: record for _, record in self.records if record['Check'] != NOT_CHECKED}


def bucket(name, number, logging=False):
    return SimpleNamespace(asset_type='storage.googleapis.com/Bucket', name=f'//storage.googleapis.com/{name}', ancestors=[f'projects/{number}', 'folders/1061', ORG_NAME],
                           resource=SimpleNamespace(data={'name': name, 'projectNumber': number, **({'logging': {'logBucket': f'{name}-logs'}} if logging else {})}), parents={ORG_NAME, 'folders/1061'})


def project(project_id, number):
    return SimpleNamespace(asset_type='cloudresourcemanager.googleapis.com/Project', name=f'//cloudresourcemanager.googleapis.com/projects/{number}', ancestors=[f'projects/{number}', 'folders/1061', ORG_NAME],
                           resource=SimpleNamespace(data={'projectId': project_id, 'lifecycleState': 'ACTIVE'}), parents={ORG_NAME, 'folders/1061'})


def iam_policy(name, kind, configs):
    audit = [SimpleNamespace(service=service, audit_log_configs=[SimpleNamespace(log_type=t) for t in types]) for service, types in configs]
    return SimpleNamespace(asset_type=f'cloudresourcemanager.googleapis.com/{kind}', name=f'//cloudresourcemanager.googleapis.com/{name}', ancestors=[name, ORG_NAME],
                           resource=None, iam_policy=SimpleNamespace(bindings=[], audit_configs=audit), parents={ORG_NAME, 'folders/1061'})


# --- Bucket Logging ---

def test_audit_data_types_read_storage_and_all_services_in_every_shape():
    assert audit_data_types(SimpleNamespace(audit_configs=[SimpleNamespace(service='allServices', audit_log_configs=[SimpleNamespace(log_type='ADMIN_READ'), SimpleNamespace(log_type='DATA_WRITE')])])) == {'DATA_WRITE'}
    assert audit_data_types(SimpleNamespace(audit_configs=[SimpleNamespace(service='storage.googleapis.com', audit_log_configs=[SimpleNamespace(log_type=3), SimpleNamespace(log_type=2)])])) == {'DATA_READ', 'DATA_WRITE'}  # enum numbers
    assert audit_data_types(SimpleNamespace(audit_configs=[SimpleNamespace(service='bigquery.googleapis.com', audit_log_configs=[SimpleNamespace(log_type='DATA_READ')])])) == set()  # another service
    assert audit_data_types({'auditConfigs': [{'service': 'allServices', 'auditLogConfigs': [{'logType': 'DATA_READ'}, {'logType': 'DATA_WRITE'}]}]}) == set()  # a dict has no attributes: read defensively, nothing
    assert audit_data_types(None) == set()


def test_logging_rows_apply_the_two_fact_rule_per_project():
    buckets = bucket_facts([bucket('web-assets', N1), bucket('web-logs', N1, logging=True), bucket('lake-raw', N2), bucket('lake-curated', N2)])
    projects = project_facts([project(P1, N1), project(P2, N2)])
    assert buckets == {N1: [('web-assets', False), ('web-logs', True)], N2: [('lake-raw', False), ('lake-curated', False)]} and projects[N1] == (P1, [ORG_NAME, 'folders/1061', f'projects/{N1}'])
    nothing_on = data_access_by_container([iam_policy(ORG_NAME, 'Organization', [('allServices', ['ADMIN_READ', 'DATA_WRITE'])])])
    rows = logging_rows(buckets, projects, nothing_on)
    assert [(r['Project'], r['Buckets'], r['Data Access logs'], r['_status']) for r in rows] == [(P2, '2 of 2 without usage logging', 'DATA_WRITE', IR), (P1, '1 of 2 without usage logging', 'DATA_WRITE', IR)]
    assert rows[0]['Issue'] == 'Nobody could say who read or wrote these objects.' and 'lake-curated, lake-raw' in rows[0]['Detail'] and rows[0]['Fix'].startswith(f'gcloud projects set-iam-policy {P2} ')
    # Data Access logs on at the project (or a folder, or the organization) cover the buckets: Informational, and the row says what SHA's detector misses.
    covered = data_access_by_container([iam_policy(f'projects/{N2}', 'Project', [('storage.googleapis.com', ['DATA_READ', 'DATA_WRITE'])]), iam_policy('folders/1061', 'Folder', [('allServices', ['DATA_READ', 'DATA_WRITE'])])])
    rows = logging_rows(buckets, projects, covered)
    assert [(r['Project'], r['Data Access logs'], r['_status']) for r in rows] == [(P2, 'on', INFO), (P1, 'on', INFO)] and 'BUCKET_LOGGING_DISABLED reads the legacy path alone' in rows[0]['Detail']
    assert rows[0]['Fix'].startswith('gcloud storage buckets update gs://lake-curated --log-bucket=')
    # Every bucket logged: no row.
    assert logging_rows(bucket_facts([bucket('web-logs', N1, logging=True)]), projects, nothing_on) == []


def test_check_bucket_logging_end_to_end(gcp):
    gcp.assets.assets += [bucket('web-assets', N1), bucket('lake-raw', N2), project(P1, N1), project(P2, N2),
                          iam_policy(ORG_NAME, 'Organization', [('allServices', ['ADMIN_READ'])]), iam_policy(f'projects/{N1}', 'Project', [('allServices', ['DATA_READ', 'DATA_WRITE'])])]
    s = Sink()
    check_bucket_logging('organization', ORG, JOB, sink=s)
    record = s.by_check()[BUCKET_LOGGING_CHECK]
    assert record['Status'] == IR and [(r['Project'], r['Data Access logs']) for r in record['Finding']] == [(P2, 'off'), (P1, 'on')] and all('_status' not in r for r in record['Finding'])
    assert [r.get('content_type') for r in gcp.assets.list_requests][-1] == bl.asset_v1.ContentType.IAM_POLICY and len(gcp.assets.list_requests) == 3  # an organization scan: no listing above it
    # A folder scan reads the containers above it too (one more listing, at the organization).
    gcp.assets.list_requests.clear()
    s = Sink()
    check_bucket_logging('folder', '1061', JOB, sink=s)
    assert len(gcp.assets.list_requests) == 4 and gcp.assets.list_requests[-1]['parent'] == ORG_NAME
    # Everything covered → Compliant; a failed listing → Error.
    gcp.assets.assets = [a for a in gcp.assets.assets if a.asset_type != 'storage.googleapis.com/Bucket'] + [bucket('web-logs', N1, logging=True)]
    s = Sink()
    check_bucket_logging('organization', ORG, JOB, sink=s)
    assert s.by_check()[BUCKET_LOGGING_CHECK] == {'Check': BUCKET_LOGGING_CHECK, 'Finding': [{'Status': ALL_CLEAR}], 'Status': COMPLIANT}
    gcp.assets.list_errors['storage.googleapis.com/Bucket'] = RuntimeError('listing down')
    s = Sink()
    check_bucket_logging('organization', ORG, JOB, sink=s)
    assert s.by_check()[BUCKET_LOGGING_CHECK]['Status'] == 'Error'


# --- the SCC oracle ---

def test_the_oracle_maps_the_two_categories_and_labels_threats():
    assert COVERAGE_MAP['CLUSTER_SECRETS_ENCRYPTION_DISABLED'] == 'GKE Node Hardening' and COVERAGE_MAP['BUCKET_LOGGING_DISABLED'] == BUCKET_LOGGING_CHECK
    def fact(category, cls, source):
        return {'category': category, 'severity': 'LOW', 'class': cls, 'resource': 'p', 'project': '1', 'project_display': 'p', 'event_time': '2026-11-17T00:00:00Z', 'explanation': '', 'recommendation': '',
                'external_uri': '', 'state': 'ACTIVE', 'mute': 'UNDEFINED', 'source': source}
    facts = [fact('Persistence: New API Method', 'THREAT', 'Event Threat Detection'), fact('GEMINI_MODEL_NOT_PROTECTED_BY_MODEL_ARMOR', 'VULNERABILITY', 'Security Health Analytics'),
             fact('Impact: GPU Instance Created', 'OBSERVATION', 'Sensitive Actions Service'), fact('SOME_OBSERVATION', 'OBSERVATION', 'Security Health Analytics')]
    rows = {r['Category']: r for r in finding_rows(facts)}
    assert rows['Persistence: New API Method']['CloudGauge check'] == 'SCC (threat detection)' and rows['GEMINI_MODEL_NOT_PROTECTED_BY_MODEL_ARMOR']['CloudGauge check'] == '—'
    assert rows['Impact: GPU Instance Created']['CloudGauge check'] == 'SCC (threat detection)' and rows['SOME_OBSERVATION']['CloudGauge check'] == '—'  # a detector's observation is SCC's; SHA's is a gap


# --- databases and storage, finished ---

def sql_instance(name='db', policy=True, ca_days=700, protection=True, window=True, flags=None, replica=False):
    return {'name': name, 'databaseVersion': 'POSTGRES_15', 'instanceType': 'READ_REPLICA_INSTANCE' if replica else 'CLOUD_SQL_INSTANCE', 'masterInstanceName': 'p:primary' if replica else '',
            'serverCaCert': {'expirationTime': (NOW + timedelta(days=ca_days)).strftime('%Y-%m-%dT%H:%M:%SZ')},
            'settings': {'ipConfiguration': {'sslMode': 'ENCRYPTED_ONLY', 'ipv4Enabled': False}, 'deletionProtectionEnabled': protection, **({'maintenanceWindow': {'day': 7, 'hour': 2}} if window else {}),
                         **({'passwordValidationPolicy': {'enablePasswordPolicy': True}} if policy else {}), 'databaseFlags': [{'name': k, 'value': v} for k, v in (flags or {}).items()]}}


def test_cloud_sql_security_rows_add_the_password_policy_and_the_ca_expiry(monkeypatch):
    monkeypatch.setattr(security, 'utcnow', lambda: NOW)
    assert cloud_sql_rows(P1, sql_instance()) == []
    rows = cloud_sql_rows(P1, sql_instance(policy=False, ca_days=45))
    assert [(r['Issue'], r['_status']) for r in rows] == [('No password policy: any password is accepted for database users.', IR), ('Server CA certificate expires in 45 days.', IR)]
    assert rows[0]['Fix'].startswith(f'gcloud sql instances patch db --project={P1} --enable-password-policy') and 'server-ca-certs create --instance=db' in rows[1]['Fix']
    assert [(r['Issue'], r['_status']) for r in cloud_sql_rows(P1, sql_instance(ca_days=10))] == [('Server CA certificate expires in 10 days.', AR)]
    assert cloud_sql_rows(P1, sql_instance(ca_days=-3))[0]['Issue'] == 'Server CA certificate expired 3 days ago.'
    assert cloud_sql_rows(P1, sql_instance(policy=False, replica=True)) == []  # a replica follows its primary
    no_cert = sql_instance()
    no_cert.pop('serverCaCert')
    assert cloud_sql_rows(P1, no_cert) == []


def test_cloud_sql_flags_add_iam_authentication_as_a_note():
    rows = sql_flag_rows([{'project_id': P1, 'name': 'db', 'data': sql_instance(flags={'log_connections': 'on', 'log_disconnections': 'on', 'log_statement': 'ddl', 'cloudsql.enable_pgaudit': 'on'})}])
    iam = [r for r in rows if r['Flag'] == 'cloudsql.iam_authentication']
    assert len(iam) == 1 and iam[0]['_status'] == INFO and 'IAM database authentication is Google' in iam[0]['Issue'] and 'CIS' not in iam[0]['Issue']
    assert sql_flag_rows([{'project_id': P1, 'name': 'db', 'data': sql_instance(flags={'log_connections': 'on', 'log_disconnections': 'on', 'log_statement': 'ddl', 'cloudsql.enable_pgaudit': 'on', 'cloudsql.iam_authentication': 'on'})}]) == []


def test_resilience_reads_deletion_protection_and_the_maintenance_window(gcp):
    from app.checks.reliability import check_resilience_assets
    gcp.assets.add_asset('sqladmin.googleapis.com/Instance', f'//cloudsql.googleapis.com/projects/{P1}/instances/db', {'name': 'db', 'settings': {'availabilityType': 'REGIONAL', 'backupConfiguration': {'enabled': True, 'pointInTimeRecoveryEnabled': True, 'retainedBackupsCount': 30},
                                                                                                                       'deletionProtectionEnabled': False}})
    gcp.assets.add_asset('sqladmin.googleapis.com/Instance', f'//cloudsql.googleapis.com/projects/{P1}/instances/replica', {'name': 'replica', 'instanceType': 'READ_REPLICA_INSTANCE', 'settings': {'availabilityType': 'REGIONAL', 'backupConfiguration': {'enabled': True, 'pointInTimeRecoveryEnabled': True, 'retainedBackupsCount': 30}}})
    s = Sink()
    check_resilience_assets('organization', ORG, JOB, sink=s)
    record = s.by_check()['Cloud SQL Deletion Protection']
    assert record['Status'] == IR and [(r['Instance'], r['Issue']) for r in record['Finding']] == [('db', 'Deletion protection off.'), ('db', 'No maintenance window.')] and all('_status' not in r for r in record['Finding'])
    assert record['Finding'][0]['Fix'] == f'gcloud sql instances patch db --project={P1} --deletion-protection' and '--maintenance-window-day=SUN' in record['Finding'][1]['Fix']


def test_alloydb_open_network_is_action_required():
    def instance(public, networks):
        data = {'name': 'projects/p/locations/r/clusters/alloy-main/instances/alloy-primary', 'instanceType': 'PRIMARY', 'availabilityType': 'REGIONAL',
                'networkConfig': {'enablePublicIp': public, 'authorizedExternalNetworks': [{'cidrRange': n} for n in networks]}, 'clientConnectionConfig': {'sslConfig': {'sslMode': 'ENCRYPTED_ONLY'}}, 'databaseFlags': {}}
        return {'clusters': [], 'instances': [{'project_id': P1, 'name': data['name'], 'link': data['name'], 'region': 'r', 'data': data}]}
    assert [(r['Issue'], r['_status']) for r in alloydb_rows(instance(True, ['0.0.0.0/0'])) if 'internet' in r['Issue'] or 'Public IP' in r['Issue']] == [('Open to the internet: authorized network 0.0.0.0/0 on a public IP.', AR)]
    assert [(r['Issue'], r['_status']) for r in alloydb_rows(instance(True, ['203.0.113.0/24'])) if 'Public IP' in r['Issue']] == [('Public IP enabled.', IR)]
    assert [r for r in alloydb_rows(instance(False, ['0.0.0.0/0'])) if 'internet' in r['Issue'] or 'Public IP' in r['Issue']] == []


def test_public_buckets_count_the_buckets_relying_on_iam_alone(gcp, monkeypatch):
    from app.checks.security import PUBLIC_BUCKETS_CHECK, check_public_buckets
    project_bucket = gcp.storage.for_project(P1)
    names = ['plain-a', 'plain-b', 'prevented']
    for name in names:
        project_bucket.create_bucket(name) if hasattr(project_bucket, 'create_bucket') else None
    monkeypatch.setattr(security, 'public_access_prevention', lambda b: 'enforced' if b.name == 'prevented' else 'inherited')
    crm = SimpleNamespace(projects=lambda: SimpleNamespace(getEffectiveOrgPolicy=lambda resource, body: SimpleNamespace(execute=lambda: {'booleanPolicy': {'enforced': False}})))
    gcp.discovery.apis['cloudresourcemanager'] = crm
    s = Sink()
    check_public_buckets(ORG, [{'projectId': P1}], JOB, sink=s)
    record = s.by_check()[PUBLIC_BUCKETS_CHECK]
    listed = [b.name for b in gcp.storage.for_project(P1).list_buckets()]
    if listed:
        assert record['Status'] == INFO and record['Finding'][0]['Bucket'] == f"{len([n for n in listed if n != 'prevented'])} buckets rely on IAM alone" and record['Finding'][0]['Project'] == P1
        assert record['Finding'][0]['Fix'].startswith('gcloud storage buckets update gs://plain-a --public-access-prevention')
    else:
        assert record['Status'] == COMPLIANT  # the storage fake lists no buckets here: the all-clear
