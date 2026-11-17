"""
v19 — Findings and vulnerabilities, Security Command Center: the rules of ``app.checks.scc`` on fixture findings and services, the REST
helpers, and the two checks end to end with their failure paths.
"""
import json
from types import SimpleNamespace

import pytest

from app.checks import scc
from app.checks.scc import (DETECTOR_CHECK, SCC_FINDINGS_CHECK, RestError, check_detector_coverage, check_scc_findings, detector_rows, export_row,
                            finding_facts, finding_rows, first_sentence, get_json, list_pages, not_activated, service_facts)
from app.checks.not_checked import NOT_CHECKED
from fakes import ORG_ID as ORG

JOB = 'job-190'
P, N, P2, N2 = 'stark-sec-prod', '111111111111', 'stark-sec-dev', '222222222222'


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


class Response:
    def __init__(self, status, body):
        self.status_code, self.text = status, json.dumps(body) if not isinstance(body, str) else body

    def json(self):
        return json.loads(self.text)


def error_response(status, message):
    return Response(status, {'error': {'code': status, 'message': message}})


def result(category, severity='MEDIUM', cls='MISCONFIGURATION', resource='aura-db', project=N, project_display=P, mute='UNDEFINED', state='ACTIVE', event='2026-11-10T10:00:00Z',
           recommendation='Go to the console and fix it. Then wait.', explanation='The instance has a public IP. Really.', source='Security Health Analytics'):
    return {'finding': {'name': f'organizations/{ORG}/sources/1/locations/global/findings/{category}-{resource}', 'findingClass': cls, 'category': category, 'severity': severity,
                        'state': state, 'mute': mute, 'eventTime': event, 'resourceName': f'//x.googleapis.com/projects/{project_display}/things/{resource}', 'parentDisplayName': source,
                        'sourceProperties': {'Recommendation': recommendation, 'Explanation': explanation} if recommendation else {}},
            'resource': {'name': f'//x.googleapis.com/projects/{project_display}/things/{resource}', 'displayName': resource, 'gcpMetadata': {'project': f'projects/{project}', 'projectDisplayName': project_display}}}


class FakeHttp:
    """Answers ``gcp.http_get`` by URL substring, in order per key (the last answer repeats); records every request."""

    def __init__(self, answers):
        self.answers = {key: list(value) for key, value in answers.items()}
        self.requests = []

    def __call__(self, url, headers=None, params=None, timeout=None):
        self.requests.append((url, dict(params or {})))
        assert headers == {'Authorization': 'Bearer fake-access-token'} and timeout
        for key, responses in self.answers.items():
            if key in url:
                return responses.pop(0) if len(responses) > 1 else responses[0]
        return error_response(404, f'no fake for {url}')


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(scc.time, 'sleep', lambda s: None)


# --- REST helpers ---

def test_get_json_retries_transient_answers_and_raises_the_rest(monkeypatch, no_sleep):
    fake = FakeHttp({'findings': [error_response(429, 'quota'), error_response(503, 'busy'), Response(200, {'ok': 1})]})
    monkeypatch.setattr(scc.gcp, 'http_get', fake)
    assert get_json('https://x/findings', {'Authorization': 'Bearer fake-access-token'}) == {'ok': 1} and len(fake.requests) == 3
    monkeypatch.setattr(scc.gcp, 'http_get', FakeHttp({'findings': [error_response(403, 'Permission denied on resource')]}))
    with pytest.raises(RestError) as raised:
        get_json('https://x/findings', {'Authorization': 'Bearer fake-access-token'})
    assert (raised.value.status, raised.value.message) == (403, 'Permission denied on resource') and not not_activated(raised.value)
    monkeypatch.setattr(scc.gcp, 'http_get', FakeHttp({'findings': [Response(500, 'not json')] * 5}))
    with pytest.raises(RestError) as raised:
        get_json('https://x/findings', {'Authorization': 'Bearer fake-access-token'})
    assert raised.value.message == 'not json'


def test_list_pages_follows_tokens_and_caps(monkeypatch):
    fake = FakeHttp({'items': [Response(200, {'things': [1, 2], 'nextPageToken': 't2'}), Response(200, {'things': [3], 'nextPageToken': 't3'}), Response(200, {'things': [4]})]})
    monkeypatch.setattr(scc.gcp, 'http_get', fake)
    assert list_pages('https://x/items', 'things', {'Authorization': 'Bearer fake-access-token'}, {'pageSize': 2}) == [1, 2, 3, 4]
    assert [r[1] for r in fake.requests] == [{'pageSize': 2}, {'pageSize': 2, 'pageToken': 't2'}, {'pageSize': 2, 'pageToken': 't3'}]
    fake = FakeHttp({'items': [Response(200, {'things': [1, 2], 'nextPageToken': 't2'}), Response(200, {'things': [3], 'nextPageToken': 't3'})]})
    monkeypatch.setattr(scc.gcp, 'http_get', fake)
    assert list_pages('https://x/items', 'things', {'Authorization': 'Bearer fake-access-token'}, cap=2) == [1, 2]


def test_not_activated_reads_the_legacy_and_activation_messages():
    assert not_activated(RestError(400, "Security Command Center Legacy has been permanently disabled as of June 7, 2021. Migrate to Security Command Center's Standard tier"))
    assert not_activated(RestError(404, 'Security Command Center has not been activated for organizations/1'))
    assert not not_activated(RestError(403, "Permission 'securitycenter.findings.list' denied on resource")) and not not_activated(RestError(500, 'legacy'))
    assert first_sentence('  Go to the console.  Then wait.') == 'Go to the console.' and first_sentence('x' * 300, 20) == 'x' * 19 + '…' and first_sentence('') == ''


# --- findings ---

def test_finding_facts_and_rows_group_rank_and_map():
    results = [result('SQL_PUBLIC_IP'), result('SSL_NOT_ENFORCED', 'HIGH', event='2026-11-12T10:00:00Z'),
               result('GEMINI_MODEL_NOT_PROTECTED_BY_MODEL_ARMOR', 'CRITICAL', 'VULNERABILITY', resource=P, recommendation='', explanation='', source='Model Armor'),
               result('BUCKET_LOGGING_DISABLED', 'LOW', resource='b1'), result('BUCKET_LOGGING_DISABLED', 'LOW', resource='b2'), result('BUCKET_LOGGING_DISABLED', 'LOW', resource='b3'),
               result('BUCKET_LOGGING_DISABLED', 'LOW', resource='b4', event='2026-11-14T10:00:00Z'), result('BUCKET_LOGGING_DISABLED', 'LOW', resource='b1'),
               result('Persistence: New API Method', 'LOW', 'THREAT', resource=P, source='Event Threat Detection'), result('Impact: GPU Instance Created', 'LOW', 'OBSERVATION', resource='vm-1'),
               result('API_DISABLED', 'HIGH', 'SCC_ERROR', resource=P), result('COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED', 'MEDIUM', resource='vm-1'),
               result('COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED', 'MEDIUM', resource='vm-2'), result('MUTED_THING', 'CRITICAL', mute='MUTED'), result('OLD_THING', 'CRITICAL', state='INACTIVE')]
    facts = [finding_facts(r) for r in results]
    assert facts[0] == {'class': 'MISCONFIGURATION', 'category': 'SQL_PUBLIC_IP', 'severity': 'MEDIUM', 'mute': 'UNDEFINED', 'state': 'ACTIVE', 'resource': 'aura-db', 'project': N, 'project_display': P,
                        'event_time': '2026-11-10T10:00:00Z', 'explanation': 'The instance has a public IP. Really.', 'recommendation': 'Go to the console and fix it. Then wait.', 'external_uri': '',
                        'source': 'Security Health Analytics'}
    rows = finding_rows(facts, ORG)
    assert [(r['Severity'], r['Class'], r['Category'], r['Count'], r['_status']) for r in rows] == [
        ('Critical', 'Vulnerability', 'GEMINI_MODEL_NOT_PROTECTED_BY_MODEL_ARMOR', 1, 'Action Required'),
        ('High', 'Scc Error', 'API_DISABLED', 1, 'Investigation Recommended'), ('High', 'Misconfiguration', 'SSL_NOT_ENFORCED', 1, 'Investigation Recommended'),
        ('Medium', 'Misconfiguration', 'COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED', 2, 'Investigation Recommended'), ('Medium', 'Misconfiguration', 'SQL_PUBLIC_IP', 1, 'Investigation Recommended'),
        ('Low', 'Misconfiguration', 'BUCKET_LOGGING_DISABLED', 5, 'Informational'), ('Low', 'Observation', 'Impact: GPU Instance Created', 1, 'Informational'),
        ('Low', 'Threat', 'Persistence: New API Method', 1, 'Informational')]
    buckets = rows[5]
    assert (buckets['Resources'], buckets['Latest'], buckets['CloudGauge check']) == ('b1, b2, b3 +1', '2026-11-14', '—')
    assert buckets['Detail'] == '5 active findings from Security Health Analytics; 4 resources; newest 2026-11-14.'
    assert rows[4]['CloudGauge check'] == 'Cloud SQL Security' and rows[4]['Issue'] == 'The instance has a public IP.'
    assert rows[4]['Fix'] == f"Go to the console and fix it.  gcloud scc findings list --organization={ORG} --location=global --filter='category=\"SQL_PUBLIC_IP\" AND state=\"ACTIVE\"'"
    assert rows[0]['Issue'] == 'Vulnerability finding.' and rows[0]['Fix'].startswith('gcloud scc findings list --organization=')
    assert rows[3]['CloudGauge check'] == 'VM Hardening' and rows[2]['CloudGauge check'] == 'Cloud SQL Security' and rows[7]['CloudGauge check'] == '—'
    assert finding_rows([], ORG) == [] and finding_rows(facts, '')[0]['Fix'].startswith('gcloud scc findings list --project=<project>')
    many = [finding_facts(result(f'CAT_{i}', 'LOW')) for i in range(scc.CATEGORY_CAP + 5)]
    assert len(finding_rows(many)) == scc.CATEGORY_CAP


def test_export_row_by_tier():
    assert export_row(ORG, 'STANDARD', [], [])['_status'] == 'Informational'
    row = export_row(ORG, 'PREMIUM', [], [])
    assert row['_status'] == 'Investigation Recommended' and row['Category'] == 'No findings export' and f'--organization={ORG}' in row['Fix'] and 'Premium tier' in row['Detail']
    assert export_row(ORG, 'STANDARD', [{'name': 'n'}], []) is None and export_row(ORG, 'STANDARD', [], [{'name': 'e'}]) is None


# --- services ---

def service(name, effective, intended='INHERITED', modules_on=0, modules=0):
    return {'name': f'projects/{P}/locations/global/securityCenterServices/{name}', 'effectiveEnablementState': effective, 'intendedEnablementState': intended,
            'modules': {f'M{i}': {'effectiveEnablementState': 'ENABLED' if i < modules_on else 'DISABLED'} for i in range(modules)}}


def test_service_facts_and_detector_rows():
    facts = service_facts([service('security-health-analytics', 'DISABLED', modules=4), service('event-threat-detection', 'DISABLED'), service('container-threat-detection', 'ENABLED', 'ENABLED', 3, 5),
                           service('vm-threat-detection', 'DISABLED'), service('web-security-scanner', 'DISABLED'), service('vm-manager', 'DISABLED'), service('cloud-run-threat-detection', 'DISABLED')])
    assert facts['SECURITY_HEALTH_ANALYTICS'] == {'effective': 'DISABLED', 'intended': 'INHERITED', 'modules_on': 0, 'modules': 4}
    assert facts['CONTAINER_THREAT_DETECTION'] == {'effective': 'ENABLED', 'intended': 'ENABLED', 'modules_on': 3, 'modules': 5}
    rows = detector_rows(P, facts)  # Container Threat Detection is on: the project runs Premium detectors, the others off are Investigation
    assert [(r['Service'], r['State'], r['Issue'], r['_status']) for r in rows] == [
        ('Security Health Analytics', 'disabled', 'Not scanned by Security Health Analytics.', 'Action Required'),
        ('Event Threat Detection', 'disabled', 'Event Threat Detection off.', 'Investigation Recommended'), ('VM Threat Detection', 'disabled', 'VM Threat Detection off.', 'Investigation Recommended'),
        ('Cloud Run Threat Detection', 'disabled', 'Cloud Run Threat Detection off.', 'Investigation Recommended'), ('Web Security Scanner', 'disabled', 'Web Security Scanner off.', 'Investigation Recommended')]
    assert rows[0]['Fix'].startswith(f'gcloud scc manage services update security-health-analytics --project={P} --enablement-state=ENABLED')
    assert rows[1]['Detail'].endswith('the project runs other Premium-tier detectors, so this one was left off.')
    standard = service_facts([service('security-health-analytics', 'DISABLED'), service('event-threat-detection', 'DISABLED'), service('vm-threat-detection', 'DISABLED')])
    rows = detector_rows(P, standard)
    assert [r['_status'] for r in rows] == ['Action Required', 'Informational', 'Informational'] and rows[1]['Detail'].endswith('it needs the Premium or Enterprise tier, which the project is not on.')
    assert detector_rows(P, service_facts([service('security-health-analytics', 'ENABLED', 'ENABLED', 115, 256)])) == []  # a service the list does not name is not judged
    assert detector_rows(P, {}) == []


# --- the checks ---

def findings_response(results, token=None):
    return Response(200, {'listFindingsResults': results, **({'nextPageToken': token} if token else {})})


def test_check_scc_findings_end_to_end(gcp, monkeypatch):
    results = [result('SQL_PUBLIC_IP'), result('GEMINI_MODEL_NOT_PROTECTED_BY_MODEL_ARMOR', 'CRITICAL', 'VULNERABILITY', resource=P, recommendation='', explanation=''), result('BUCKET_LOGGING_DISABLED', 'LOW', resource='b1', project=N2, project_display=P2)]
    fake = FakeHttp({f'organizations/{ORG}/sources/-/locations/global/findings': [findings_response(results[:2], 'next'), findings_response(results[2:])],
                     'notificationConfigs': [Response(200, {})], 'bigQueryExports': [Response(200, {})]})
    monkeypatch.setattr(scc.gcp, 'http_get', fake)
    gcp.discovery.apis['securitycenter'] = SimpleNamespace(organizations=lambda: SimpleNamespace(getSubscription=lambda name: SimpleNamespace(execute=lambda: {'name': name, 'tier': 'STANDARD'})))
    s = Sink()
    check_scc_findings('organization', ORG, JOB, sink=s)
    record = s.by_check()[SCC_FINDINGS_CHECK]
    assert record['Status'] == 'Action Required'
    assert [(r['Category'], r['Count'], r.get('Severity')) for r in record['Finding']] == [('GEMINI_MODEL_NOT_PROTECTED_BY_MODEL_ARMOR', 1, 'Critical'), ('SQL_PUBLIC_IP', 1, 'Medium'),
                                                                                           ('BUCKET_LOGGING_DISABLED', 1, 'Low'), ('No findings export', 0, '—')]
    assert all('_status' not in r for r in record['Finding']) and s.not_checked() == []
    assert fake.requests[0][1] == {'filter': scc.FINDINGS_FILTER, 'pageSize': scc.PAGE_SIZE} and fake.requests[1][1]['pageToken'] == 'next'
    assert [u.rsplit('/', 1)[-1] for u, _ in fake.requests] == ['findings', 'findings', 'notificationConfigs', 'bigQueryExports']
    # A project scan reads the project parent alone, no export row.
    fake = FakeHttp({f'projects/{P}/sources/-/locations/global/findings': [findings_response(results[:1])]})
    monkeypatch.setattr(scc.gcp, 'http_get', fake)
    s = Sink()
    check_scc_findings('project', P, JOB, sink=s)
    record = s.by_check()[SCC_FINDINGS_CHECK]
    assert [(r['Category'], r['Fix'].startswith('Go to the console and fix it.  gcloud scc findings list')) for r in record['Finding']] == [('SQL_PUBLIC_IP', True)] and record['Status'] == 'Investigation Recommended'
    assert 'gcloud scc findings list --project=<project>' in record['Finding'][0]['Fix'] and len(fake.requests) == 1
    # Nothing active: all clear.
    monkeypatch.setattr(scc.gcp, 'http_get', FakeHttp({'findings': [findings_response([])]}))
    s = Sink()
    check_scc_findings('project', P, JOB, sink=s)
    assert s.by_check()[SCC_FINDINGS_CHECK] == {'Check': SCC_FINDINGS_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': scc.FINDINGS_ALL_CLEAR}]}


def test_check_scc_findings_folder_and_fallbacks(gcp, monkeypatch):
    gcp.assets.add('projects', P, 'Prod', parent='folders/1061', project_number=N, organization=ORG)  # the fake search returns the folder's projects: P alone
    results = [result('SQL_PUBLIC_IP'), result('BUCKET_LOGGING_DISABLED', 'LOW', resource='b1', project='333', project_display='other'), result('OPEN_SSH_PORT', 'HIGH', resource='vm', project='999', project_display=P)]
    legacy = error_response(400, "Security Command Center Legacy has been permanently disabled as of June 7, 2021. Migrate to Security Command Center's Standard tier or Premium tier")
    fake = FakeHttp({f'folders/1061/sources': [legacy], f'organizations/{ORG}/sources/-/locations/global/findings': [findings_response(results)]})
    monkeypatch.setattr(scc.gcp, 'http_get', fake)
    s = Sink()
    check_scc_findings('folder', '1061', JOB, sink=s)  # the folder parent is never tried: the organization's findings, the folder's projects kept (by number or by ID)
    assert [r['Category'] for r in s.by_check()[SCC_FINDINGS_CHECK]['Finding']] == ['OPEN_SSH_PORT', 'SQL_PUBLIC_IP']
    assert [u.split('/v2/')[1].split('/sources')[0] for u, _ in fake.requests] == [f'organizations/{ORG}']
    # A project SCC does not serve directly falls back to the organization's findings for that project.
    fake = FakeHttp({f'projects/{P}/sources': [legacy], f'organizations/{ORG}/sources/-/locations/global/findings': [findings_response(results)]})
    monkeypatch.setattr(scc.gcp, 'http_get', fake)
    s = Sink()
    check_scc_findings('project', P, JOB, sink=s)
    assert [r['Category'] for r in s.by_check()[SCC_FINDINGS_CHECK]['Finding']] == ['OPEN_SSH_PORT', 'SQL_PUBLIC_IP']
    # The organization itself not activated: an Informational note; a permission error: Error; the export reads failing: a note, the rows stand.
    monkeypatch.setattr(scc.gcp, 'http_get', FakeHttp({'findings': [error_response(404, f'Security Command Center has not been activated for organizations/{ORG}')]}))
    s = Sink()
    check_scc_findings('organization', ORG, JOB, sink=s)
    record = s.by_check()[SCC_FINDINGS_CHECK]
    assert record['Status'] == 'Informational' and record['Finding'][0]['Summary'].startswith(f'Security Command Center is not activated for organizations/{ORG} (404:')
    monkeypatch.setattr(scc.gcp, 'http_get', FakeHttp({'findings': [error_response(403, "Permission 'securitycenter.findings.list' denied")]}))
    s = Sink()
    check_scc_findings('organization', ORG, JOB, sink=s)
    assert s.by_check()[SCC_FINDINGS_CHECK] == {'Check': SCC_FINDINGS_CHECK, 'Status': 'Error', 'Finding': [{'Error': "403 Permission 'securitycenter.findings.list' denied"}]}
    monkeypatch.setattr(scc.gcp, 'http_get', FakeHttp({'findings': [findings_response(results[:1])], 'notificationConfigs': [error_response(403, 'no')]}))
    gcp.discovery.apis['securitycenter'] = SimpleNamespace(organizations=lambda: SimpleNamespace(getSubscription=lambda name: SimpleNamespace(execute=lambda: {'tier': 'PREMIUM'})))
    s = Sink()
    check_scc_findings('organization', ORG, JOB, sink=s)
    assert [r['Category'] for r in s.by_check()[SCC_FINDINGS_CHECK]['Finding']] == ['SQL_PUBLIC_IP']
    assert [(r['Project'], r['Skipped check']) for r in s.not_checked()] == [(f'organizations/{ORG}', f'{SCC_FINDINGS_CHECK} (the findings-export rule: the notification configs or BigQuery exports could not be read)')]
    gcp.assets.error = RuntimeError('search down')
    s = Sink()
    check_scc_findings('folder', '1061', JOB, sink=s)
    assert s.by_check()[SCC_FINDINGS_CHECK]['Status'] == 'Error'


def test_check_detector_coverage_end_to_end(gcp, monkeypatch):
    prod = [service('security-health-analytics', 'ENABLED', 'ENABLED', 115, 256), service('event-threat-detection', 'ENABLED', 'ENABLED', 147, 171), service('vm-threat-detection', 'ENABLED', 'ENABLED', 5, 5)]
    dev = [service('security-health-analytics', 'DISABLED'), service('event-threat-detection', 'DISABLED'), service('vm-threat-detection', 'DISABLED')]
    fake = FakeHttp({f'projects/{P}/locations/global/securityCenterServices': [Response(200, {'securityCenterServices': prod})],
                     f'projects/{P2}/locations/global/securityCenterServices': [Response(200, {'securityCenterServices': dev})],
                     'projects/locked/locations': [error_response(403, 'Permission denied')]})
    monkeypatch.setattr(scc.gcp, 'http_get', fake)
    s = Sink()
    check_detector_coverage(ORG, [{'projectId': P}, {'projectId': P2}, {'projectId': 'locked'}], JOB, sink=s)
    record = s.by_check()[DETECTOR_CHECK]
    assert record['Status'] == 'Action Required'
    assert [(r['Project'], r['Service']) for r in record['Finding']] == [(P2, 'Security Health Analytics'), (P2, 'Event Threat Detection'), (P2, 'VM Threat Detection')]
    assert record['Finding'][1]['Detail'].endswith('which the project is not on.')  # judged per project: P2 runs no detector, whatever P runs
    assert [(r['Project'], r['Reason']) for r in s.not_checked()] == [('locked', '403 Permission denied')]
    assert [p for p, _ in fake.requests] == [f'{scc.SCM_V1}/projects/{P}/locations/global/securityCenterServices', f'{scc.SCM_V1}/projects/{P2}/locations/global/securityCenterServices',
                                             f'{scc.SCM_V1}/projects/locked/locations/global/securityCenterServices']
    # All on: Compliant.
    monkeypatch.setattr(scc.gcp, 'http_get', FakeHttp({'securityCenterServices': [Response(200, {'securityCenterServices': prod})]}))
    s = Sink()
    check_detector_coverage(ORG, [{'projectId': P}], JOB, sink=s)
    assert s.by_check()[DETECTOR_CHECK] == {'Check': DETECTOR_CHECK, 'Status': 'Compliant', 'Finding': [{'Status': scc.DETECTOR_ALL_CLEAR}]}


def test_the_scc_record_is_one_check_in_the_score_whatever_it_lists():
    """D3: SCC categories CloudGauge also judges are kept, so a fact can appear under two records — the score counts each *check* once, so
    a thirty-row SCC record and Cloud SQL Security failing on the same instance cost the category two checks, not thirty-one."""
    from app.reporting.scoring import tallies_from_checks
    security = 'Security & Identity'
    checks = {SCC_FINDINGS_CHECK: {'category': security, 'status': 'Action Required', 'rows': 31}, 'Cloud SQL Security': {'category': security, 'status': 'Action Required', 'rows': 2},
              'Public GCS Buckets': {'category': security, 'status': 'Compliant', 'rows': 1}, 'VM External IPs': {'category': security, 'status': 'Compliant', 'rows': 1},
              DETECTOR_CHECK: {'category': security, 'status': 'Informational', 'rows': 3}}
    tally = tallies_from_checks(checks)[security]
    assert (tally.compliant, tally.failing, tally.score) == (2, 2, 50.0)
    assert tally.evidence == '2 of 4 checks compliant'
