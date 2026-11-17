"""
v19.2 — Support cases: the facts and the two records of ``app.checks.support`` on fixture cases (the seven lines, the hygiene ladder,
the folder filter, paging and the cap), and the graceful-degradation ladder end to end with the surveyed error shapes — both records
always written with their normal columns, Informational and outside the score whenever nothing can be judged.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from googleapiclient.errors import HttpError

from app.checks import support
from app.checks.gke_operations import COMPLIANT, INFORMATIONAL as INFO, INVESTIGATION as IR
from app.checks.not_checked import NOT_CHECKED
from app.checks.support import (CASE_CAP, CASE_HYGIENE_CHECK, HYGIENE_COLUMNS, LIST_PERMISSION, SUPPORT_BRIEFING, TIER_NOTE, briefing_lines, case_facts, case_issues,
                                check_support_cases, error_kind, has_list_permission, hygiene_rows, search_cases)
from app.reporting.scoring import tallies_from_checks
from fakes import ORG_ID as ORG, _execute

JOB = 'job-192'
P, N = 'stark-web-prod', '111111111111'
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
HOST = 'test-project'  # TEST_ENV['PROJECT_ID'] — what auth_default returns


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_check(self):
        return {record['Check']: record for _, record in self.records if record['Check'] != NOT_CHECKED}


def iso(days_ago):
    return (NOW - timedelta(days=days_ago, hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')


def case(case_id, title, priority='P2', state='IN_PROGRESS_GOOGLE_SUPPORT', age=2, updated=1, escalated=False, product='Compute Engine', project=N):
    return {'name': f'projects/{project}/cases/{case_id}', 'displayName': title, 'priority': priority, 'state': state, 'createTime': iso(age), 'updateTime': iso(updated),
            'escalated': escalated, 'classification': {'id': 'x', 'displayName': f'{product} > Instances :: Boot'}, 'description': 'NEVER SHOWN', 'creator': {'email': 'ops@example.com'}}


FIXTURE = [case('1001', 'Cloud SQL failover took 40 minutes', 'P1', 'IN_PROGRESS_GOOGLE_SUPPORT', age=3, updated=0, product='Cloud SQL'),
           case('1002', 'GKE node pool stuck upgrading', 'P2', 'ACTION_REQUIRED', age=12, updated=5, product='Kubernetes Engine'),
           case('1003', 'BigQuery slot contention', 'P3', 'SOLUTION_PROVIDED', age=20, updated=9, product='BigQuery', project='222222222222'),
           case('1004', 'Quota increase for N2 CPUs', 'P4', 'NEW', age=0, updated=0),
           case('1005', 'Load balancer 502s after certificate rotation', 'P1', 'IN_PROGRESS_GOOGLE_SUPPORT', age=9, updated=1, escalated=True, product='Networking')]


class FakeSupport:
    """``cloudsupport v2`` ``cases().search(parent=..., query=..., pageSize=..., pageToken=...)``: ``data`` maps a parent to its cases (paged) or to an exception."""

    def __init__(self, data):
        self.data = data
        self.calls = []

    def cases(self):
        def search(parent, query, pageSize, pageToken=None):
            self.calls.append({'parent': parent, 'query': query, 'pageSize': pageSize, 'pageToken': pageToken})
            answer = self.data.get(parent, [])
            if isinstance(answer, Exception):
                return _execute(answer)
            start = int(pageToken or 0)
            page = answer[start:start + pageSize]
            return _execute({'cases': page, **({'nextPageToken': str(start + pageSize)} if start + pageSize < len(answer) else {})})
        return SimpleNamespace(search=search)


class FakeCrm:
    """``cloudresourcemanager v3`` ``testIamPermissions`` on organizations, folders and projects: ``held`` are the permissions the caller has; an exception fails the probe."""

    def __init__(self, held=(LIST_PERMISSION,), error=None):
        self.held, self.error, self.asked = set(held), error, []

    def _collection(self):
        def test(resource, body):
            self.asked.append((resource, tuple(body['permissions'])))
            if self.error:
                return _execute(self.error)
            return _execute({'permissions': [p for p in body['permissions'] if p in self.held]})
        return SimpleNamespace(testIamPermissions=test)

    organizations = folders = projects = _collection


def http_error(status, body):
    return HttpError(SimpleNamespace(status=status, reason='x'), body.encode(), uri='https://cloudsupport.googleapis.com/v2/x')


DISABLED = http_error(403, '{"error": {"code": 403, "message": "Google Cloud Support API has not been used in project stark-nw-prod before or it is disabled.", "status": "PERMISSION_DENIED", '
                           '"details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED", "domain": "googleapis.com", "metadata": {"service": "cloudsupport.googleapis.com"}}]}}')
REFUSED = http_error(400, '{"error": {"code": 400, "message": "Invalid query.", "status": "INVALID_ARGUMENT"}}')
DOWN = http_error(503, '{"error": {"code": 503, "message": "unavailable"}}')


def install(gcp, support_api, crm=None):
    gcp.discovery.apis['cloudsupport'] = support_api
    gcp.discovery.apis['cloudresourcemanager'] = crm or FakeCrm()


def columns_of(record):
    return [tuple(row) for row in record['Finding']]


# --- the facts and the lines ---

def test_case_facts_read_the_api_shape_and_never_the_description():
    fact = case_facts(FIXTURE[1], NOW)
    assert (fact['id'], fact['title'], fact['priority'], fact['state'], fact['project'], fact['age'], fact['since_update'], fact['escalated'], fact['product']) == \
        ('1002', 'GKE node pool stuck upgrading', 'P2', 'ACTION_REQUIRED', N, 12, 5, False, 'Kubernetes Engine')
    assert 'NEVER SHOWN' not in str(fact)
    org_case = case_facts({'name': f'organizations/{ORG}/cases/7', 'displayName': 'Org-level billing question'}, NOW)
    assert org_case['project'] == f'organizations/{ORG}' and org_case['priority'] == '—' and org_case['age'] is None and org_case['product'] == '—'
    assert case_facts({}, NOW)['id'] == '?' and case_facts({}, NOW)['title'] == '(untitled)'


def test_briefing_lines_are_the_seven_fixed_lines():
    facts = [case_facts(c, NOW) for c in FIXTURE]
    lines = briefing_lines(f'organizations/{ORG}', facts, HOST)
    assert [line['Line'] for line in lines] == ['Open cases', 'With Google Support', 'Waiting on you', 'Solution provided', 'Escalated', 'By project', 'By product']
    by_line = {line['Line']: line for line in lines}
    assert by_line['Open cases']['Value'] == '5 open' and by_line['Open cases']['Detail'] == 'P1 ×2, P2, P3, P4. Oldest: BigQuery slot contention (1003, P3, 20 d open).'
    assert by_line['With Google Support']['Value'] == '3' and by_line['With Google Support']['Detail'].startswith('Newest: Cloud SQL failover took 40 minutes (1001, P1, 0 d since the last update); Quota increase')
    assert by_line['Waiting on you']['Value'] == '1' and by_line['Waiting on you']['Detail'] == 'State ACTION_REQUIRED — GKE node pool stuck upgrading (1002, P2, 5 d since the last update).'
    assert by_line['Solution provided']['Detail'] == 'Confirm or reopen before they auto-close — BigQuery slot contention (1003, P3, 9 d since the last update).'
    assert by_line['Escalated']['Value'] == '1' and 'Load balancer 502s' in by_line['Escalated']['Detail']
    assert by_line['By project']['Value'] == '2 projects' and by_line['By project']['Detail'] == f'{N} ×4; 222222222222.'
    assert by_line['By product']['Value'] == '5 products' and by_line['By product']['Detail'].startswith('BigQuery; Cloud SQL; ')
    assert all(line['Fix'].startswith(f'curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "x-goog-user-project: {HOST}" "https://cloudsupport.googleapis.com/v2/organizations/{ORG}/cases:search?query=state%3DOPEN"') for line in lines)
    assert by_line['Waiting on you']['Fix'].endswith('# open a case under Support › Cases in the console') and 'NEVER SHOWN' not in str(lines)
    # Nothing open: the same seven lines at zero, the tier caveat on the first; the cap, stated.
    zero = {line['Line']: line for line in briefing_lines(f'projects/{P}', [], HOST)}
    assert [zero[k]['Value'] for k in zero] == ['0 open', '0', '0', '0', '0', '0 projects', '0 products'] and zero['Open cases']['Detail'] == f'No open support case under projects/{P}. {TIER_NOTE}'
    assert all(zero[k]['Detail'] == 'None.' for k in list(zero)[1:])
    capped = briefing_lines(f'organizations/{ORG}', facts, HOST, capped=True)[0]
    assert capped['Value'] == f'5 open (first {CASE_CAP})' and capped['Detail'].endswith(f'The search stopped at {CASE_CAP} cases; the counts are of those.')


# --- Case Hygiene ---

def test_case_issues_ladder_around_each_threshold():
    def issues(**kw):
        return [(i, s) for i, s, _ in case_issues(case_facts(case('1', 't', **kw), NOW))]
    assert issues(state='ACTION_REQUIRED', updated=3) == [] and issues(state='ACTION_REQUIRED', updated=4) == [('Waiting on you.', IR)]
    assert issues(priority='P1', age=7) == [] and issues(priority='P1', age=8) == [("Open beyond its priority's expectation.", IR)]
    assert issues(priority='P0', age=2) == [("Open beyond its priority's expectation.", IR)] and issues(priority='P2', age=30) == [] and issues(priority='P4', age=91) == [("Open beyond its priority's expectation.", IR)]
    assert issues(state='SOLUTION_PROVIDED', updated=7) == [] and issues(state='SOLUTION_PROVIDED', updated=8) == [('Solution provided, not confirmed.', INFO)]
    assert issues(escalated=True) == [('Escalated.', INFO)]
    assert issues(state='ACTION_REQUIRED', updated=10, priority='P1', age=40, escalated=True) == [('Waiting on you.', IR), ("Open beyond its priority's expectation.", IR), ('Escalated.', INFO)]
    assert case_issues(case_facts({'name': 'projects/1/cases/2', 'priority': 'P1', 'state': 'ACTION_REQUIRED'}, NOW)) == []  # no timestamps: nothing to measure


def test_hygiene_rows_one_per_flagged_case_worst_first():
    facts = [case_facts(c, NOW) for c in FIXTURE]
    rows = hygiene_rows(facts, HOST)
    assert [(r['Case'], r['Issue'], r['_status']) for r in rows] == [('1002', 'Waiting on you.', IR), ('1005', "Open beyond its priority's expectation.", IR), ('1003', 'Solution provided, not confirmed.', INFO)]
    assert all(tuple(k for k in r if k != '_status') == HYGIENE_COLUMNS for r in rows)
    waiting = rows[0]
    assert (waiting['Title'], waiting['Priority'], waiting['State'], waiting['Project'], waiting['Age']) == ('GKE node pool stuck upgrading', 'P2', 'ACTION_REQUIRED', N, '12 d')
    assert waiting['Detail'] == 'No update for 5 days in state ACTION_REQUIRED — Google Support waits for your answer.'
    assert waiting['Fix'] == f'curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "x-goog-user-project: {HOST}" "https://cloudsupport.googleapis.com/v2/projects/{N}/cases/1002"  # then reply, escalate or close it under Support › Cases in the console'
    assert rows[1]['Detail'] == 'Open 9 days as P1 (expectation 7 days): escalate it, or lower the priority. Escalated to Google Support management.'
    assert hygiene_rows([], HOST) == [] and hygiene_rows([case_facts(FIXTURE[0], NOW)], HOST) == []


# --- the reads ---

def test_search_cases_pages_and_caps():
    api = FakeSupport({f'organizations/{ORG}': [case(str(i), f't{i}') for i in range(7)]})
    cases, capped = search_cases(api, f'organizations/{ORG}', cap=10, page_size=3)
    assert [c['name'].rsplit('/', 1)[-1] for c in cases] == [str(i) for i in range(7)] and not capped
    assert [(c['pageSize'], c['pageToken']) for c in api.calls] == [(3, None), (3, '3'), (3, '6')] and all(c['query'] == 'state=OPEN' for c in api.calls)
    api = FakeSupport({f'organizations/{ORG}': [case(str(i), f't{i}') for i in range(7)]})
    cases, capped = search_cases(api, f'organizations/{ORG}', cap=4, page_size=3)
    assert len(cases) == 4 and capped and [c['pageSize'] for c in api.calls] == [3, 1]


def test_has_list_permission_and_error_kinds():
    crm = FakeCrm()
    assert has_list_permission(crm, f'organizations/{ORG}') is True and crm.asked == [(f'organizations/{ORG}', (LIST_PERMISSION,))]
    assert has_list_permission(FakeCrm(held=()), 'folders/1061') is False and has_list_permission(FakeCrm(held=()), f'projects/{P}') is False
    assert has_list_permission(FakeCrm(error=RuntimeError('crm down')), f'projects/{P}') is None  # the probe failing never blocks the search
    assert error_kind(DISABLED) == 'disabled' and error_kind(REFUSED) == 'refused' and error_kind(DOWN) == 'error' and error_kind(RuntimeError('x')) == 'error'
    assert error_kind(http_error(403, '{"error": {"message": "The caller does not have permission", "status": "PERMISSION_DENIED"}}')) == 'refused'


# --- the check end to end ---

def test_check_support_cases_writes_both_records(gcp):
    install(gcp, api := FakeSupport({f'organizations/{ORG}': FIXTURE}))
    s = Sink()
    check_support_cases('organization', ORG, JOB, sink=s)
    briefing, hygiene = s.by_check()[SUPPORT_BRIEFING], s.by_check()[CASE_HYGIENE_CHECK]
    assert briefing['Status'] == INFO and [r['Line'] for r in briefing['Finding']][:2] == ['Open cases', 'With Google Support'] and briefing['Finding'][0]['Value'] == '5 open'
    assert hygiene['Status'] == IR and [r['Case'] for r in hygiene['Finding']] == ['1002', '1005', '1003'] and all('_status' not in r for r in hygiene['Finding'])
    assert api.calls[0]['parent'] == f'organizations/{ORG}' and gcp.discovery.apis['cloudresourcemanager'].asked == [(f'organizations/{ORG}', (LIST_PERMISSION,))]
    assert len(s.records) == 2 and 'NEVER SHOWN' not in str(s.records)
    # A project scan searches the project; nothing flagged is Compliant.
    install(gcp, api := FakeSupport({f'projects/{P}': [FIXTURE[0], FIXTURE[3]]}))
    s = Sink()
    check_support_cases('project', P, JOB, sink=s)
    assert api.calls[0]['parent'] == f'projects/{P}' and s.by_check()[CASE_HYGIENE_CHECK] == {'Check': CASE_HYGIENE_CHECK, 'Status': COMPLIANT, 'Finding': [
        {'Status': '2 open cases, each with Google Support within the expectation of its priority; none waits on you beyond 3 days.'}]}
    # A folder scan searches the organization and keeps the folder's projects (by number or ID).
    gcp.assets.add('projects', P, 'Web', parent='folders/1061', project_number=N, organization=ORG)
    install(gcp, api := FakeSupport({f'organizations/{ORG}': FIXTURE}))
    s = Sink()
    check_support_cases('folder', '1061', JOB, sink=s)
    assert api.calls[0]['parent'] == f'organizations/{ORG}' and s.by_check()[SUPPORT_BRIEFING]['Finding'][0]['Value'] == '4 open'  # the 222… project's case is outside the folder
    assert s.by_check()[SUPPORT_BRIEFING]['Finding'][0]['Fix'].endswith(f'/v2/organizations/{ORG}/cases:search?query=state%3DOPEN"  # then keep the folder\'s projects')  # where the search really ran
    assert [r['Case'] for r in s.by_check()[CASE_HYGIENE_CHECK]['Finding']] == ['1002', '1005']


def test_no_open_case_is_informational_not_compliant(gcp):
    install(gcp, FakeSupport({}))
    s = Sink()
    check_support_cases('organization', ORG, JOB, sink=s)
    briefing, hygiene = s.by_check()[SUPPORT_BRIEFING], s.by_check()[CASE_HYGIENE_CHECK]
    assert briefing['Status'] == INFO and [r['Value'] for r in briefing['Finding']] == ['0 open', '0', '0', '0', '0', '0 projects', '0 products'] and TIER_NOTE in briefing['Finding'][0]['Detail']
    assert hygiene['Status'] == INFO and tuple(hygiene['Finding'][0]) == HYGIENE_COLUMNS and hygiene['Finding'][0]['Issue'] == 'No open case.' and TIER_NOTE in hygiene['Finding'][0]['Detail']


def test_graceful_degradation_keeps_both_records_and_their_columns(gcp):
    def run(support_api, crm=None, scope='organization', scope_id=ORG):
        install(gcp, support_api, crm)
        s = Sink()
        check_support_cases(scope, scope_id, JOB, sink=s)
        assert len(s.records) == 2
        return s.by_check()[SUPPORT_BRIEFING], s.by_check()[CASE_HYGIENE_CHECK]

    # The API is not enabled in the host project: the surveyed 403 SERVICE_DISABLED.
    briefing, hygiene = run(FakeSupport({f'organizations/{ORG}': DISABLED}))
    assert briefing['Status'] == hygiene['Status'] == INFO
    assert briefing['Finding'] == [{'Line': 'Support cases', 'Value': 'not configured', 'Detail': f'The Cloud Support API is not enabled in {HOST}; the support records need it.',
                                    'Fix': f'gcloud services enable cloudsupport.googleapis.com --project={HOST}'}]
    assert tuple(hygiene['Finding'][0]) == HYGIENE_COLUMNS and hygiene['Finding'][0]['Issue'] == 'Not configured.' and hygiene['Finding'][0]['Fix'] == f'gcloud services enable cloudsupport.googleapis.com --project={HOST}'
    # The permission is missing: the probe says so before the search (the API itself would answer 200 {}), and the Fix is the grant.
    api = FakeSupport({f'organizations/{ORG}': FIXTURE})
    briefing, hygiene = run(api, FakeCrm(held=()))
    assert api.calls == [] and briefing['Status'] == hygiene['Status'] == INFO and LIST_PERMISSION in briefing['Finding'][0]['Detail']
    assert briefing['Finding'][0]['Fix'].startswith(f'gcloud organizations add-iam-policy-binding {ORG} --member=serviceAccount:') and '--role=roles/cloudsupport.techSupportViewer' in briefing['Finding'][0]['Fix']
    briefing, _ = run(api, FakeCrm(held=()), scope='folder', scope_id='1061')
    assert briefing['Finding'][0]['Fix'].startswith('gcloud resource-manager folders add-iam-policy-binding 1061 ')
    # The probe failing does not block the search.
    briefing, hygiene = run(FakeSupport({f'organizations/{ORG}': FIXTURE}), FakeCrm(error=RuntimeError('crm down')))
    assert briefing['Finding'][0]['Value'] == '5 open' and hygiene['Status'] == IR
    # Another 4xx: Informational with the API's message and both commands.
    briefing, hygiene = run(FakeSupport({f'organizations/{ORG}': REFUSED}))
    assert briefing['Status'] == hygiene['Status'] == INFO and briefing['Finding'][0]['Detail'] == f'The Cloud Support API refused the read under organizations/{ORG}: Invalid query.'
    assert 'gcloud services enable cloudsupport.googleapis.com' in briefing['Finding'][0]['Fix'] and 'add-iam-policy-binding' in briefing['Finding'][0]['Fix']
    # Only a failure the client could not retry is an Error — and the records still exist.
    briefing, hygiene = run(FakeSupport({f'organizations/{ORG}': DOWN}))
    assert briefing['Status'] == hygiene['Status'] == 'Error' and 'Error' in briefing['Finding'][0]
    briefing, hygiene = run(FakeSupport({f'organizations/{ORG}': RuntimeError('socket closed')}))
    assert briefing['Status'] == hygiene['Status'] == 'Error'


def test_case_hygiene_counts_in_the_score_only_when_it_judged_something():
    category = 'Operational Excellence & Observability'

    def tally(status):
        checks = {CASE_HYGIENE_CHECK: {'category': category, 'status': status, 'rows': 1}, SUPPORT_BRIEFING: {'category': category, 'status': INFO, 'rows': 7},
                  'Monitoring Alert Coverage': {'category': category, 'status': COMPLIANT, 'rows': 1}}
        return tallies_from_checks(checks)[category]

    # Not configured, refused and no-cases alike are Informational: outside the score — no penalty for Basic support or a missing API.
    assert (tally(INFO).compliant, tally(INFO).failing, tally(INFO).score) == (1, 0, 100.0)
    assert (tally(IR).compliant, tally(IR).failing, tally(IR).score) == (1, 1, 50.0) and (tally(COMPLIANT).compliant, tally(COMPLIANT).failing) == (2, 0)
    assert support.SUPPORT_CHECKS == (SUPPORT_BRIEFING, CASE_HYGIENE_CHECK)
