"""
v18.8 — Forecasts, budgets and spend: the billing-export read of ``app.checks.spend`` — the table discovery, the two SQL texts, the briefing
lines and the anomaly rows from fixture rows, the Scorecard's spend sentence, and the check end to end (not configured, unreadable, empty,
one table, two tables).
"""
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from googleapiclient.errors import HttpError

from app.checks import spend
from app.checks.spend import (ANOMALIES_CHECK, BRIEFING, SPEND_CHECKS, anomaly_floor, anomaly_parameters, anomaly_query, anomaly_rows, briefing_parameters,
                              briefing_query, briefing_rows, check_spend, discover_tables, parse_briefing, percent_change, run_query, scope_predicate, share_text)
from app.config import Settings
from app.reporting.scorecard import spend_text
from fakes import _execute
from helpers import make_settings

JOB = 'job-188'
TODAY = date(2026, 11, 16)
NOW = datetime(2026, 11, 16, 9, 30, tzinfo=timezone.utc)
ORG, PROJECT, DATASET, TABLE = '880200000000', 'stark-billing-admin', 'billing', 'gcp_billing_export_v1_0AAAAA_BBBBBB_CCCCCC'
SOURCE = f'`{PROJECT}.{DATASET}.{TABLE}`'


class Sink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        assert job_id == JOB
        self.records.append((name, record))

    def by_check(self):
        return {record['Check']: record for _, record in self.records}


def http_error(status, message):
    return HttpError(SimpleNamespace(status=status, reason=message), message.encode(), uri='https://bigquery.googleapis.com/')


class FakeBigQuery:
    """``tables.list`` and ``jobs.query`` / ``jobs.getQueryResults`` of the BigQuery REST API, answering the briefing query with
    ``briefing`` rows and the anomaly query with ``anomalies`` rows (as ``(kind, item, value, value2)`` / ``(project, service, week, mean)``)."""

    def __init__(self, tables=(TABLE,), briefing=(), anomalies=(), list_error=None, query_error=None, pages=1, incomplete=0):
        self.table_ids, self.briefing, self.anomalies = list(tables), list(briefing), list(anomalies)
        self.list_error, self.query_error, self.pages, self.incomplete = list_error, query_error, pages, incomplete
        self.queries = []  # (projectId, body)
        self.result_calls = []  # kwargs of every getQueryResults

    def tables(self):
        def list_(projectId, datasetId, maxResults=None):
            if self.list_error:
                return _execute(self.list_error)
            tables = [{'tableReference': {'projectId': projectId, 'datasetId': datasetId, 'tableId': t}, 'type': 'TABLE', 'timePartitioning': {'type': 'DAY'}}
                      for t in self.table_ids]
            tables += [{'tableReference': {'tableId': 'gcp_billing_export_resource_v1_0AAAAA_BBBBBB_CCCCCC'}, 'type': 'TABLE', 'timePartitioning': {'type': 'DAY'}},
                       {'tableReference': {'tableId': 'cloud_pricing_export'}, 'type': 'TABLE'}, {'tableReference': {'tableId': 'billing_view'}, 'type': 'VIEW'},
                       {'tableReference': {'tableId': 'gcp_billing_export_v1_FIELD'}, 'type': 'TABLE', 'timePartitioning': {'type': 'DAY', 'field': 'export_time'}}]
            return _execute({'tables': tables})
        return SimpleNamespace(list=list_, list_next=lambda previous_request, previous_response: None)

    @staticmethod
    def _response(fields, rows, complete=True, token=None):
        response = {'jobComplete': complete, 'jobReference': {'projectId': 'p', 'jobId': 'j1', 'location': 'asia-south1'}}
        if complete:
            response['schema'] = {'fields': [{'name': f} for f in fields]}
            response['rows'] = [{'f': [{'v': None if v is None else str(v)} for v in row]} for row in rows]
        if token:
            response['pageToken'] = token
        return response

    def _answer(self, body, page=0):
        if '"day" AS kind' in body['query']:
            fields, rows = ('kind', 'item', 'value', 'value2'), self.briefing
        else:
            fields, rows = ('project_id', 'service', 'this_week', 'weekly_mean_before'), self.anomalies
        size = max(1, -(-len(rows) // self.pages))
        chunk = rows[page * size:(page + 1) * size]
        return self._response(fields, chunk, token=f'page{page + 1}' if page + 1 < self.pages and len(rows) > (page + 1) * size else None)

    def jobs(self):
        def query(projectId, body):
            self.queries.append((projectId, body))
            if self.query_error:
                return _execute(self.query_error)
            if self.incomplete:
                return _execute(self._response((), (), complete=False))
            return _execute(self._answer(body))

        def get_query_results(**kwargs):
            self.result_calls.append(kwargs)
            body = self.queries[-1][1]
            if kwargs.get('pageToken'):
                return _execute(self._answer(body, page=int(kwargs['pageToken'][4:])))
            if len([c for c in self.result_calls if not c.get('pageToken')]) < self.incomplete:
                return _execute(self._response((), (), complete=False))
            return _execute(self._answer(body))
        return SimpleNamespace(query=query, getQueryResults=get_query_results)


def day_rows(values_by_offset):
    """``(day, item, value, value2)`` rows for ``{days before TODAY: net}``."""
    return [('day', (TODAY - timedelta(days=offset)).isoformat(), net, 0.0) for offset, net in values_by_offset.items()]


# Steady 60 a day for 95 days: November 1–15 = 900, October = 1,860, September = 1,800.
STEADY = day_rows({offset: 60.0 for offset in range(1, 96)})
BRIEFING_ROWS = STEADY + [('project', 'stark-nw-prod', 960.0, 963.0), ('project', 'stark-argolis', 820.0, 730.0), ('project', 'stark-trial', 0.0, 0.3),
                          ('project', 'syn-tiny', 3.6, 0.01), ('service', 'Networking', 1163.0, 1161.0), ('service', 'Compute Engine', 454.0, 433.0),
                          ('service', 'Cloud SQL', 119.0, 85.0), ('service', 'AlloyDB', 0.8, 0.0), ('service', 'Cloud Build', 0.0, 0.0),
                          ('credit', 'SUSTAINED_USAGE_DISCOUNT', -101.8, 0.0), ('credit', 'DISCOUNT', -23.6, 0.0), ('eligible', 'commitment-eligible', 755.0, 0.0),
                          ('currency', 'USD', 1204, 0.0), ('freshness', '2026-11-16T06:25:01Z', 0.0, 0.0), ('unattributed', '', 12.5, 0.0)]


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr(spend, 'utcnow', lambda: NOW)


# --- SQL ---

def test_scope_predicates_follow_the_project_ancestry():
    assert scope_predicate('project') == 'project.id = @scope_id'
    assert scope_predicate('folder') == 'project.ancestry_numbers LIKE CONCAT("%/", @scope_id, "/%")'
    assert scope_predicate('organization') == 'project.ancestry_numbers LIKE CONCAT("/", @scope_id, "/%")'
    assert scope_predicate('organization', '123') == 'project.ancestry_numbers LIKE CONCAT("/", "123", "/%")'


def test_queries_prune_partitions_filter_the_scope_and_name_their_parameters():
    one = briefing_query(PROJECT, DATASET, [(TABLE, '_PARTITIONTIME')], 'organization')
    assert f'SELECT * FROM {SOURCE} WHERE _PARTITIONTIME >= TIMESTAMP(DATE_SUB(@today, INTERVAL 105 DAY))' in one
    assert 'usage_start_time >= TIMESTAMP(DATE_SUB(@today, INTERVAL 95 DAY)) AND usage_start_time < TIMESTAMP(@today)' in one
    assert 'project.ancestry_numbers LIKE CONCAT("/", @scope_id, "/%")' in one and 'c.type IN UNNEST(@cud_types)' in one and 'service IN UNNEST(@eligible)' in one
    assert all(f'"{kind}"' in one for kind in ('day', 'project', 'service', 'credit', 'eligible', 'currency', 'freshness', 'unattributed'))
    two = briefing_query(PROJECT, DATASET, [(TABLE, '_PARTITIONTIME'), ('gcp_billing_export_v1_X', 'export_time'), ('gcp_billing_export_v1_Y', None)], 'project')
    assert two.count('UNION ALL\n  SELECT * FROM') == 2 and 'export_time >= TIMESTAMP(DATE_SUB(@today, INTERVAL 105 DAY))' in two and 'WHERE TRUE' in two
    assert 'project.id = @scope_id' in two
    anomalies = anomaly_query(PROJECT, DATASET, [(TABLE, '_PARTITIONTIME')], 'folder')
    assert 'INTERVAL 38 DAY' in anomalies and 'INTERVAL 28 DAY' in anomalies and '/ 3 AS weekly_mean_before' in anomalies
    assert 'WHERE this_week >= @floor AND (weekly_mean_before <= 0 OR this_week >= @ratio * weekly_mean_before)' in anomalies and 'LIMIT 200' in anomalies
    params = {p['name']: p for p in briefing_parameters(TODAY, ORG)}
    assert params['today'] == {'name': 'today', 'parameterType': {'type': 'DATE'}, 'parameterValue': {'value': '2026-11-16'}}
    assert params['scope_id']['parameterValue'] == {'value': ORG} and params['eligible']['parameterType'] == {'type': 'ARRAY', 'arrayType': {'type': 'STRING'}}
    assert [v['value'] for v in params['cud_types']['parameterValue']['arrayValues']] == ['COMMITTED_USAGE_DISCOUNT', 'COMMITTED_USAGE_DISCOUNT_DOLLAR_BASE']
    assert [(p['name'], p['parameterValue']['value']) for p in anomaly_parameters(TODAY, ORG, 38.546)] == [('today', '2026-11-16'), ('scope_id', ORG), ('floor', '38.55'), ('ratio', '1.5')]


def test_discovery_keeps_the_standard_export_tables_and_their_partition_columns():
    assert discover_tables(FakeBigQuery(tables=['gcp_billing_export_v1_B', 'gcp_billing_export_v1_A']), PROJECT, DATASET) == [
        ('gcp_billing_export_v1_A', '_PARTITIONTIME'), ('gcp_billing_export_v1_B', '_PARTITIONTIME'), ('gcp_billing_export_v1_FIELD', 'export_time')]
    assert discover_tables(FakeBigQuery(tables=[]), PROJECT, DATASET) == [('gcp_billing_export_v1_FIELD', 'export_time')]


def test_run_query_polls_an_unfinished_job_and_follows_pages():
    bq = FakeBigQuery(briefing=STEADY, pages=3, incomplete=2)
    rows = run_query(bq, PROJECT, briefing_query(PROJECT, DATASET, [(TABLE, '_PARTITIONTIME')], 'organization'), briefing_parameters(TODAY, ORG))
    assert len(rows) == 95 and rows[0] == {'kind': 'day', 'item': '2026-11-15', 'value': '60.0', 'value2': '0.0'}
    polls = [c for c in bq.result_calls if not c.get('pageToken')]
    assert len(polls) == 2 and polls[0]['jobId'] == 'j1' and polls[0]['location'] == 'asia-south1' and polls[0]['timeoutMs'] == 60000
    assert [c['pageToken'] for c in bq.result_calls if c.get('pageToken')] == ['page1', 'page2']
    body = bq.queries[0][1]
    assert body['useLegacySql'] is False and body['parameterMode'] == 'NAMED' and body['timeoutMs'] == 60000 and 'location' not in body  # the location follows the tables
    with pytest.raises(RuntimeError, match='did not finish'):
        run_query(FakeBigQuery(briefing=STEADY, incomplete=99), PROJECT, 'q', [])


# --- the briefing ---

def test_parse_briefing_reads_every_kind():
    facts = parse_briefing([dict(zip(('kind', 'item', 'value', 'value2'), (str(v) for v in row))) for row in BRIEFING_ROWS] + [{'kind': 'day', 'item': 'bad', 'value': '1', 'value2': '0'}])
    assert len(facts['daily']) == 95 and facts['daily'][date(2026, 11, 15)] == 60.0
    assert facts['projects']['stark-argolis'] == (820.0, 730.0) and facts['services']['Cloud SQL'] == (119.0, 85.0)
    assert facts['credits'] == {'SUSTAINED_USAGE_DISCOUNT': -101.8, 'DISCOUNT': -23.6} and facts['eligible'] == (755.0, 0.0)
    assert facts['currency'] == 'USD' and facts['mixed_currencies'] is False and facts['unattributed'] == 12.5
    assert facts['freshness'] == datetime(2026, 11, 16, 6, 25, 1, tzinfo=timezone.utc)
    mixed = parse_briefing([{'kind': 'currency', 'item': 'EUR', 'value': '5', 'value2': '0'}, {'kind': 'currency', 'item': 'USD', 'value': '9', 'value2': '0'}])
    assert mixed['currency'] == 'USD' and mixed['mixed_currencies'] is True and mixed['freshness'] is None


def test_percentages_and_shares_read_well():
    assert percent_change(110, 100) == '+10 %' and percent_change(95, 100) == '\u22125 %' and percent_change(100.2, 100) == '\u00b10 %'
    assert percent_change(3.6, 0.01) == 'new' and percent_change(0.4, 0.3) == '' and percent_change(0, 0) == ''
    assert share_text(52, 100) == '52 %' and share_text(0.2, 100) == '<1 %' and share_text(0, 100) == '0 %' and share_text(1, 0) == '\u2014'


def test_briefing_lines_from_a_steady_series():
    facts = parse_briefing([dict(zip(('kind', 'item', 'value', 'value2'), (str(v) for v in row))) for row in BRIEFING_ROWS])
    rows = briefing_rows(facts, TODAY, 'organization', ORG, SOURCE, [TABLE], f'{PROJECT}.{DATASET}', floor=50.0)
    assert [r['Line'] for r in rows] == ['Month to date', 'Forecast', 'Last month', 'By project (30 days)', 'By service (30 days)', 'Credits (30 days)', 'Freshness']
    by_line = {r['Line']: r for r in rows}
    assert by_line['Month to date']['Value'] == '900.00 USD'
    assert by_line['Month to date']['Detail'] == '1–15 November (15 complete days) vs 900.00 USD for 1–15 October: \u00b10 %.'
    assert by_line['Month to date']['Fix'] == ("bq query --use_legacy_sql=false 'SELECT ROUND(SUM(cost) + SUM((SELECT IFNULL(SUM(c.amount), 0) FROM UNNEST(credits) c)), 2) AS net "
                                               f"FROM {SOURCE} WHERE DATE(usage_start_time) BETWEEN \"2026-11-01\" AND \"2026-11-15\" AND project.ancestry_numbers LIKE CONCAT(\"/\", \"{ORG}\", \"/%\")'")
    assert by_line['Forecast']['Value'] == '\u2248 1,800.00 USD'  # 900 + 60 × 15 remaining days
    assert by_line['Forecast']['Detail'] == 'Month to date plus the mean of the last 7 complete days (60.00 USD/day) over the 15 days remaining in November.'
    assert by_line['Last month']['Value'] == '1,860.00 USD' and by_line['Last month']['Detail'] == 'October; September 1,800.00 USD (+3 %).'
    assert by_line['By project (30 days)']['Value'] == '3 projects, 1,783.60 USD'  # stark-trial's 0.00 is not a project with spend
    assert by_line['By project (30 days)']['Detail'] == ('stark-nw-prod 960.00 (54 %, \u00b10 % vs the 30 days before); stark-argolis 820.00 (46 %, +12 % vs the 30 days before); '
                                                         'syn-tiny 3.60 (<1 %, new vs the 30 days before).')
    assert by_line['By service (30 days)']['Value'] == '4 services, 1,736.80 USD' and 'AlloyDB 0.80 (<1 %)' in by_line['By service (30 days)']['Detail']
    assert by_line['Credits (30 days)']['Value'] == '-125.40 USD'
    assert by_line['Credits (30 days)']['Detail'] == ('sustained-use discounts -101.80; discounts -23.60. Committed-use discounts: none — 0 % of 755.00 USD of commitment-eligible spend '
                                                      '(Compute Engine, Cloud SQL, GKE, Spanner, Cloud Run, Memorystore, AlloyDB, Bigtable, Dataflow) is covered by a commitment.')
    assert by_line['Credits (30 days)']['Fix'].startswith('Review Resource-Based Commitment Recommendations in this report and the Capacity Planner')
    assert by_line['Freshness']['Value'] == '3 h behind'
    assert by_line['Freshness']['Detail'] == (f'Last export 2026-11-16 06:25 UTC; 95 days read from {TABLE} in {PROJECT}.{DATASET}; 12.50 USD of account-level charges without a '
                                              'project in the last 30 days (support, marketplace fees) are not attributed to the organization; the anomaly floor is 50.00 USD.')
    assert all(r['Fix'] for r in rows)
    # A folder scan never attributes account-level charges; a project scan's predicate names the project.
    folder = {r['Line']: r for r in briefing_rows(facts, TODAY, 'folder', '1061', SOURCE, [TABLE], 'p.d')}
    assert 'account-level' not in folder['Freshness']['Detail'] and 'LIKE CONCAT("%/", "1061", "/%")' in folder['Month to date']['Fix']
    project = {r['Line']: r for r in briefing_rows(facts, TODAY, 'project', 'stark-argolis', SOURCE, [TABLE], 'p.d')}
    assert 'project.id = "stark-argolis"' in project['By service (30 days)']['Fix']


def test_briefing_lines_at_month_boundaries_and_with_a_short_export():
    # The first of the month: no complete day yet; the forecast is the 7-day mean over the whole month (31 days of December).
    first = date(2026, 12, 1)
    facts = parse_briefing([dict(zip(('kind', 'item', 'value', 'value2'), ('day', (first - timedelta(days=n)).isoformat(), '40', '0'))) for n in range(1, 50)])
    by_line = {r['Line']: r for r in briefing_rows(facts, first, 'project', 'p', SOURCE, [TABLE], 'p.d')}
    assert by_line['Month to date']['Value'] == '\u2014' and by_line['Month to date']['Detail'].startswith('No complete day of December yet')
    assert by_line['Forecast']['Value'] == '\u2248 1,240.00 USD' and '31 days remaining in December' in by_line['Forecast']['Detail']
    assert by_line['Last month']['Value'] == '1,200.00 USD'  # November: 30 × 40
    assert by_line['Last month']['Detail'] == 'November; October 760.00 USD (export from 2026-10-13) (+58 %).'  # the export starts mid-October
    # March after February: the same days last month stop at February's end.
    march = date(2026, 3, 31)
    facts = parse_briefing([dict(zip(('kind', 'item', 'value', 'value2'), ('day', (march - timedelta(days=n)).isoformat(), '10', '0'))) for n in range(1, 95)])
    by_line = {r['Line']: r for r in briefing_rows(facts, march, 'project', 'p', SOURCE, [TABLE], 'p.d')}
    assert by_line['Month to date']['Value'] == '300.00 USD' and 'vs 280.00 USD for 1–28 February' in by_line['Month to date']['Detail']
    empty = {r['Line']: r for r in briefing_rows(parse_briefing([]), TODAY, 'project', 'p', SOURCE, [TABLE], 'p.d')}
    assert empty['Freshness']['Value'] == 'no rows' and empty['By project (30 days)']['Detail'] == 'no project with spend in the last 30 days.'
    assert empty['Credits (30 days)']['Detail'].startswith('No sustained-use discounts, promotions or negotiated discounts. Committed-use discounts: none — no commitment-eligible spend')


def test_credits_line_shows_committed_use_coverage():
    rows = [('credit', 'COMMITTED_USAGE_DISCOUNT', -150.0, 0.0), ('credit', 'SUSTAINED_USAGE_DISCOUNT', -20.0, 0.0), ('eligible', 'commitment-eligible', 600.0, -150.0),
            ('currency', 'EUR', 10, 0.0)]
    facts = parse_briefing([dict(zip(('kind', 'item', 'value', 'value2'), (str(v) for v in row))) for row in rows])
    credits = {r['Line']: r for r in briefing_rows(facts, TODAY, 'project', 'p', SOURCE, [TABLE], 'p.d')}['Credits (30 days)']
    assert credits['Value'] == '-170.00 EUR'
    assert credits['Detail'] == 'sustained-use discounts -20.00. Committed-use discounts -150.00 — 25 % of 600.00 EUR of commitment-eligible spend (Compute Engine, Cloud SQL, GKE, Spanner, Cloud Run, Memorystore, AlloyDB, Bigtable, Dataflow) is covered by a commitment.'


# --- the anomalies ---

def test_anomaly_floor_is_the_larger_of_the_setting_and_two_percent_of_last_month():
    assert anomaly_floor(50, 1860) == 50 and anomaly_floor(50, 4000) == 80 and anomaly_floor(0, 0) == 0 and anomaly_floor(10, -5) == 10


def test_anomaly_rows_name_the_jump_and_the_sku_query():
    flagged = [{'project_id': 'stark-argolis', 'service': 'Compute Engine', 'this_week': '420.5', 'weekly_mean_before': '150.0'},
               {'project_id': 'stark-nw-prod', 'service': 'BigQuery', 'this_week': '84', 'weekly_mean_before': '0'}]
    rows = anomaly_rows(flagged, TODAY, 'USD', 50.0, SOURCE)
    assert [(r['Project'], r['Service'], r['This Week'], r['Weekly Mean Before'], r['Change'], r['Issue']) for r in rows] == [
        ('stark-argolis', 'Compute Engine', '420.50 USD', '150.00 USD', '+180 %', 'Spend up +180 % week over week.'),
        ('stark-nw-prod', 'BigQuery', '84.00 USD', '\u2014', 'new', 'New spend.')]
    assert rows[0]['Detail'] == '420.50 USD in the 7 days 2026-11-09 to 2026-11-15 against a weekly mean of 150.00 USD over the 3 weeks before (floor 50.00 USD).'
    assert rows[1]['Detail'] == '84.00 USD in the 7 days 2026-11-09 to 2026-11-15, nothing in the 3 weeks before (floor 50.00 USD).'
    assert rows[0]['Fix'] == ("bq query --use_legacy_sql=false 'SELECT sku.description AS sku, ROUND(SUM(cost), 2) AS cost FROM " + SOURCE +
                              " WHERE project.id = \"stark-argolis\" AND service.description = \"Compute Engine\" AND DATE(usage_start_time) BETWEEN \"2026-11-02\" AND \"2026-11-15\" "
                              "GROUP BY 1 ORDER BY 2 DESC LIMIT 10'")
    assert all(r['_status'] == 'Investigation Recommended' for r in rows)


# --- the Scorecard ---

def details(headers, rows):
    return SimpleNamespace(kind='table', headers=tuple(headers), rows=tuple(tuple(r) for r in rows))


def test_scorecard_spend_sentence_reads_the_briefing():
    item = SimpleNamespace(check_name=BRIEFING, status='Informational', details=details(
        ('Line', 'Value', 'Detail', 'Fix'), [('Month to date', '975.81 USD', 'd', 'f'), ('Forecast', '\u2248 1,938.43 USD', 'd', 'f'), ('Last month', '1,927.37 USD', 'd', 'f'),
                                             ('By project (30 days)', '3 projects', 'd', 'f')]))
    section = SimpleNamespace(checks=[SimpleNamespace(check_name='Cloud Run Cost', status='Compliant', details=None), item])
    assert spend_text(section) == 'month to date 975.81 USD, forecast \u2248 1,938.43 USD, last month 1,927.37 USD'
    first_of_month = SimpleNamespace(checks=[SimpleNamespace(check_name=BRIEFING, status='Informational', details=details(('Line', 'Value'), [('Month to date', '\u2014'), ('Forecast', '\u2248 1 USD')]))])
    assert spend_text(first_of_month) == 'forecast \u2248 1 USD'
    not_configured = SimpleNamespace(checks=[SimpleNamespace(check_name=BRIEFING, status='Informational', details=details(('Summary',), [('Not configured: …',)]))])
    assert spend_text(not_configured) is None
    assert spend_text(SimpleNamespace(checks=[])) is None
    assert spend_text(SimpleNamespace(checks=[SimpleNamespace(check_name=BRIEFING, status='Error', details=SimpleNamespace(kind='text', headers=(), rows=()))])) is None


# --- the check ---

def settings_with(export='stark-billing-admin.billing', floor=None):
    env = {'BILLING_EXPORT': export} if export else {}
    if floor is not None:
        env['SPEND_ANOMALY_FLOOR'] = str(floor)
    return make_settings(**env)


def test_billing_export_setting_is_validated():
    assert Settings.from_env({'BILLING_EXPORT': 'stark-billing-admin.billing'}).billing_export == ('stark-billing-admin', 'billing')
    assert Settings.from_env({'BILLING_EXPORT': ' stark-billing-admin:billing_2026 '}).billing_export == ('stark-billing-admin', 'billing_2026')
    assert Settings.from_env({'BILLING_EXPORT': 'example.com:my-project.billing'}).billing_export == ('example.com:my-project', 'billing')
    assert Settings.from_env({}).billing_export is None and Settings.from_env({}).spend_anomaly_floor == 50.0
    assert Settings.from_env({'SPEND_ANOMALY_FLOOR': '120.5'}).spend_anomaly_floor == 120.5
    for bad in ('billing', 'Stark.billing', 'stark-billing-admin.bad-dataset', 'a.b.c.d'):
        with pytest.raises(ValueError, match='BILLING_EXPORT'):
            Settings.from_env({'BILLING_EXPORT': bad})
    with pytest.raises(ValueError, match='SPEND_ANOMALY_FLOOR'):
        Settings.from_env({'SPEND_ANOMALY_FLOOR': '-1'})


def test_check_writes_not_configured_rows_without_the_setting(gcp, monkeypatch):
    monkeypatch.setattr(spend, 'get_settings', lambda: settings_with(export=None))
    sink = Sink()
    check_spend('organization', ORG, JOB, sink=sink)
    records = sink.by_check()
    assert set(records) == set(SPEND_CHECKS) and all(r['Status'] == 'Informational' for r in records.values())
    assert records[BRIEFING]['Finding'][0]['Summary'].startswith('Not configured: set BILLING_EXPORT to the BigQuery dataset the billing account exports to')
    assert gcp.discovery.calls == []


def test_check_reports_an_unreadable_dataset_with_the_grant(gcp, monkeypatch):
    monkeypatch.setattr(spend, 'get_settings', lambda: settings_with())
    gcp.discovery.apis['bigquery'] = FakeBigQuery(list_error=http_error(403, 'Access Denied: Dataset stark-billing-admin:billing'))
    sink = Sink()
    check_spend('organization', ORG, JOB, sink=sink)
    records = sink.by_check()
    assert all(r['Status'] == 'Error' for r in records.values()) and set(records) == set(SPEND_CHECKS)
    error = records[ANOMALIES_CHECK]['Finding'][0]['Error']
    assert 'Access Denied' in error and 'roles/bigquery.dataViewer on the dataset stark-billing-admin.billing' in error and 'bq update --source ds.json stark-billing-admin:billing' in error
    # No standard table in the dataset: both in Error, naming the prefix.
    gcp.discovery.apis['bigquery'] = FakeBigQuery(tables=[])
    gcp.discovery.apis['bigquery'].tables = lambda: SimpleNamespace(list=lambda **kw: _execute({'tables': [{'tableReference': {'tableId': 'cloud_pricing_export'}, 'type': 'TABLE'}]}),
                                                                      list_next=lambda previous_request, previous_response: None)
    sink = Sink()
    check_spend('project', 'stark-argolis', JOB, sink=sink)
    assert sink.by_check()[BRIEFING]['Finding'] == [{'Error': 'No standard billing export table (gcp_billing_export_v1_*) in stark-billing-admin.billing: BILLING_EXPORT must name the '
                                                              'dataset the billing account\'s standard usage cost export writes to.'}]
    # The query itself failing: the same two Error records.
    gcp.discovery.apis['bigquery'] = FakeBigQuery(query_error=RuntimeError('Syntax error at [3:4]'))
    sink = Sink()
    check_spend('folder', '1061', JOB, sink=sink)
    assert [r['Finding'][0]['Error'] for r in sink.by_check().values()] == ['Syntax error at [3:4]'] * 2


def test_check_end_to_end_writes_the_briefing_and_the_anomalies(gcp, monkeypatch):
    monkeypatch.setattr(spend, 'get_settings', lambda: settings_with(floor=30))
    bq = FakeBigQuery(briefing=BRIEFING_ROWS, anomalies=[('stark-argolis', 'Compute Engine', 420.5, 150.0)])
    gcp.discovery.apis['bigquery'] = bq
    sink = Sink()
    check_spend('organization', ORG, JOB, sink=sink)
    records = sink.by_check()
    briefing, anomalies = records[BRIEFING], records[ANOMALIES_CHECK]
    assert briefing['Status'] == 'Informational' and [r['Line'] for r in briefing['Finding']][:3] == ['Month to date', 'Forecast', 'Last month']
    assert anomalies['Status'] == 'Investigation Recommended' and [(r['Project'], r['Change']) for r in anomalies['Finding']] == [('stark-argolis', '+180 %')]
    assert '_status' not in anomalies['Finding'][0]
    # The queries ran in the deployment project, with the floor at 2 % of last month (1,860 → 37.20 beats the configured 30).
    assert [projectId for projectId, _ in bq.queries] == ['test-project'] * 2
    anomaly_params = {p['name']: p['parameterValue']['value'] for p in bq.queries[1][1]['queryParameters']}
    assert anomaly_params == {'today': '2026-11-16', 'scope_id': ORG, 'floor': '37.20', 'ratio': '1.5'}
    assert 'the anomaly floor is 37.20 USD' in {r['Line']: r for r in briefing['Finding']}['Freshness']['Detail']
    # Nothing flagged: the all-clear row. Two export tables: the briefing's bq lines union them.
    gcp.discovery.apis['bigquery'] = FakeBigQuery(tables=['gcp_billing_export_v1_A', 'gcp_billing_export_v1_B'], briefing=BRIEFING_ROWS)
    sink = Sink()
    check_spend('project', 'stark-argolis', JOB, sink=sink)
    records = sink.by_check()
    assert records[ANOMALIES_CHECK] == {'Check': ANOMALIES_CHECK, 'Status': 'Compliant',
                                        'Finding': [{'Status': "No project's spend on a service rose by half or more week over week, and no new service costs more than the floor."}]}
    fix = records[BRIEFING]['Finding'][0]['Fix']
    assert ('FROM (SELECT * FROM `stark-billing-admin.billing.gcp_billing_export_v1_A` UNION ALL SELECT * FROM `stark-billing-admin.billing.gcp_billing_export_v1_B` '
            'UNION ALL SELECT * FROM `stark-billing-admin.billing.gcp_billing_export_v1_FIELD`)') in fix
    assert 'gcp_billing_export_v1_A, gcp_billing_export_v1_B, gcp_billing_export_v1_FIELD' in {r['Line']: r for r in records[BRIEFING]['Finding']}['Freshness']['Detail']

