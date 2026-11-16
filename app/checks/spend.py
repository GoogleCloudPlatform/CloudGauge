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
"""Spend (v18.8): what the organization pays, read from the billing export in BigQuery.

CloudGauge holds nothing on any billing account. The one source it reads is the
**billing export** the account owner already keeps in BigQuery — the standard
usage cost tables (``gcp_billing_export_v1_<account>``) of the dataset named by
``BILLING_EXPORT=<project>.<dataset>`` — with ``roles/bigquery.dataViewer`` on
that dataset, a dataset-level grant, and the ``roles/bigquery.jobUser`` the
deployment project already gives the service account for the scan export. Two
queries per scan, partition-pruned to about a hundred days and summed in SQL,
run in the deployment project: a few MB read, cents a month.

One function, two records, both Cost Optimization:

- **Spend Briefing** — a briefing (*Informational*, never scored, like *Capacity
  Commitments*): month to date against the same days last month, a forecast
  (month to date plus the mean of the last seven complete days over the days
  remaining), last month and the month before, the top projects and services of
  the last 30 days with their share and change, the credits by type with the
  **committed-use coverage** of the commitment-eligible services, and the
  export's freshness. Every line carries the ``bq query`` that reproduces it.
- **Spend Anomalies** — scored: a project's spend on a service over the last
  seven complete days at least ``ANOMALY_RATIO`` (1.5) times the weekly mean of
  the three weeks before and at least the floor (``SPEND_ANOMALY_FLOOR``, or 2 %
  of last month's net when that is higher), or new spend of at least the floor —
  *Investigation Recommended* with the SKU breakdown query as the fix. Drops are
  not rows (a stopped workload is the usual cause; the briefing's deltas show them).

The scope is the scan's: an organization's or a folder's rows by the project's
ancestry (``project.ancestry_numbers``), a project's by its ID — so a project the
export still bills after its deletion is counted where it belonged. ``BILLING_EXPORT``
unset: both records say so (*Informational*, outside the score). The dataset
unreadable: both in Error, the row naming the grant.
"""
import logging
from calendar import monthrange
from datetime import date, timedelta

from googleapiclient.errors import HttpError

from app.config import SCOPES, get_settings
from app.services import gcp
from app.utils import parse_timestamp, utcnow

BRIEFING = "Spend Briefing"
ANOMALIES_CHECK = "Spend Anomalies"
SPEND_CHECKS = (BRIEFING, ANOMALIES_CHECK)
EXPORT_TABLE_PREFIX = "gcp_billing_export_v1_"
INGESTION_PARTITION = "_PARTITIONTIME"
# How far back the briefing reads (this month, last month and the month before fit in 93 days), and how many more
# days of partitions are read: a usage day's rows land in partitions up to a few days later (the export this shipped
# from: 38 hours at the 99th percentile, 89 hours at most).
WINDOW_DAYS = 95
PARTITION_MARGIN_DAYS = 10
COMPARISON_DAYS = 30  # the by-project and by-service lines, the credits
FORECAST_DAYS = 7  # the mean the forecast extends
TOP_ITEMS = 10
ANOMALY_WEEKS_BEFORE = 3
ANOMALY_RATIO = 1.5
ANOMALY_FLOOR_SHARE = 0.02  # of last month's net
MAX_ANOMALY_ROWS = 200
QUERY_TIMEOUT_MS = 60_000
QUERY_PAGE = 10_000
MAX_RESULT_POLLS = 20
CUD_TYPES = ("COMMITTED_USAGE_DISCOUNT", "COMMITTED_USAGE_DISCOUNT_DOLLAR_BASE")
# The services a committed use discount (resource- or spend-based) can cover, as the export names them.
COMMITMENT_ELIGIBLE_SERVICES = ("Compute Engine", "Kubernetes Engine", "Cloud SQL", "Cloud Spanner", "Cloud Run", "Cloud Memorystore for Redis",
                                "Memorystore for Redis", "Memorystore for Memcached", "AlloyDB", "Cloud Bigtable", "Bigtable", "Dataflow", "Cloud Dataflow",
                                "VMware Engine")
CREDIT_NAMES = {"COMMITTED_USAGE_DISCOUNT": "committed-use discounts", "COMMITTED_USAGE_DISCOUNT_DOLLAR_BASE": "spend-based committed-use discounts",
                "SUSTAINED_USAGE_DISCOUNT": "sustained-use discounts", "DISCOUNT": "discounts", "PROMOTION": "promotions", "FREE_TIER": "free tier",
                "RESELLER_MARGIN": "reseller margin", "SUBSCRIPTION_BENEFIT": "subscription benefits", "FEE_UTILIZATION_OFFSET": "fee utilization offsets"}
NO_PROJECT = "(no project)"
NOT_CONFIGURED = ("Not configured: set BILLING_EXPORT to the BigQuery dataset the billing account exports to (<project>.<dataset>) and grant the "
                  "service account roles/bigquery.dataViewer on it; Spend Briefing then reads month to date, forecast, projects, services and credits "
                  "from the standard export tables, and Spend Anomalies lists the week-over-week jumps. Nothing is read from the billing account itself.")
ANOMALIES_ALL_CLEAR = "No project's spend on a service rose by half or more week over week, and no new service costs more than the floor."


# --- SQL ----------------------------------------------------------------------------------------------------------------

def table_reference(project_id, dataset, table_id):
    return f"`{project_id}.{dataset}.{table_id}`"


def scope_predicate(scope, literal=None):
    """The SQL that keeps the rows of the scanned scope: a project by ID, a folder or an organization by the project's ancestry
    (``/<org>/<folder>/…/``). With ``literal`` (the scope ID) the predicate is written out for a ``bq`` line; otherwise it names the
    ``@scope_id`` parameter."""
    value = f'"{literal}"' if literal is not None else "@scope_id"
    if scope == "project":
        return f"project.id = {value}"
    if scope == "folder":
        return f'project.ancestry_numbers LIKE CONCAT("%/", {value}, "/%")'
    return f'project.ancestry_numbers LIKE CONCAT("/", {value}, "/%")'


def partition_predicate(partition_column, days):
    """The predicate that prunes a table to the partitions of the last ``days`` days (``TRUE`` for an unpartitioned table)."""
    if not partition_column:
        return "TRUE"
    return f"{partition_column} >= TIMESTAMP(DATE_SUB(@today, INTERVAL {days} DAY))"


def source_sql(project_id, dataset, tables, days):
    """The ``FROM`` source: the export table pruned to its last ``days`` days of partitions, or the union of several accounts' tables."""
    parts = [f"SELECT * FROM {table_reference(project_id, dataset, table_id)} WHERE {partition_predicate(column, days)}" for table_id, column in tables]
    return parts[0] if len(parts) == 1 else "\n  UNION ALL\n  ".join(parts)


def briefing_query(project_id, dataset, tables, scope):
    """The briefing's one query: ``(kind, item, value, value2)`` rows — the daily net of the last ``WINDOW_DAYS`` days, the projects' and
    services' net over the last 30 days and the 30 before, the credits by type, the commitment-eligible cost and the committed-use credits
    against it, the currency, the freshness, and the account-level charges that name no project (never attributed to a scope)."""
    return f"""WITH source AS (
  {source_sql(project_id, dataset, tables, WINDOW_DAYS + PARTITION_MARGIN_DAYS)}
), usage AS (
  SELECT DATE(usage_start_time) AS day, IFNULL(project.id, "{NO_PROJECT}") AS project_id, IFNULL(service.description, "") AS service, cost,
         (SELECT IFNULL(SUM(c.amount), 0) FROM UNNEST(credits) c) AS credit,
         (SELECT IFNULL(SUM(c.amount), 0) FROM UNNEST(credits) c WHERE c.type IN UNNEST(@cud_types)) AS cud,
         credits, currency, export_time, ({scope_predicate(scope)}) AS in_scope, project.id IS NULL AS unattributed
  FROM source
  WHERE usage_start_time >= TIMESTAMP(DATE_SUB(@today, INTERVAL {WINDOW_DAYS} DAY)) AND usage_start_time < TIMESTAMP(@today)
    AND (({scope_predicate(scope)}) OR project.id IS NULL)
), recent AS (
  SELECT * FROM usage WHERE in_scope AND day >= DATE_SUB(@today, INTERVAL {COMPARISON_DAYS} DAY)
)
SELECT "day" AS kind, CAST(day AS STRING) AS item, SUM(cost + credit) AS value, 0.0 AS value2 FROM usage WHERE in_scope GROUP BY day
UNION ALL
SELECT "project", project_id, SUM(IF(day >= DATE_SUB(@today, INTERVAL {COMPARISON_DAYS} DAY), cost + credit, 0)),
       SUM(IF(day < DATE_SUB(@today, INTERVAL {COMPARISON_DAYS} DAY) AND day >= DATE_SUB(@today, INTERVAL {2 * COMPARISON_DAYS} DAY), cost + credit, 0))
FROM usage WHERE in_scope GROUP BY project_id
UNION ALL
SELECT "service", service, SUM(IF(day >= DATE_SUB(@today, INTERVAL {COMPARISON_DAYS} DAY), cost + credit, 0)),
       SUM(IF(day < DATE_SUB(@today, INTERVAL {COMPARISON_DAYS} DAY) AND day >= DATE_SUB(@today, INTERVAL {2 * COMPARISON_DAYS} DAY), cost + credit, 0))
FROM usage WHERE in_scope GROUP BY service
UNION ALL
SELECT "credit", c.type, SUM(c.amount), 0.0 FROM recent, UNNEST(credits) c GROUP BY c.type
UNION ALL
SELECT "eligible", "commitment-eligible", SUM(IF(service IN UNNEST(@eligible), cost, 0)), SUM(IF(service IN UNNEST(@eligible), cud, 0)) FROM recent
UNION ALL
SELECT "currency", IFNULL(currency, ""), COUNT(*), 0.0 FROM usage WHERE in_scope GROUP BY currency
UNION ALL
SELECT "freshness", IFNULL(FORMAT_TIMESTAMP("%Y-%m-%dT%H:%M:%SZ", MAX(export_time)), ""), 0.0, 0.0 FROM usage
UNION ALL
SELECT "unattributed", "", SUM(IF(unattributed AND day >= DATE_SUB(@today, INTERVAL {COMPARISON_DAYS} DAY), cost + credit, 0)), 0.0 FROM usage"""


def anomaly_query(project_id, dataset, tables, scope):
    """The anomalies' query: per project and service, the net of the last seven complete days and the weekly mean of the three weeks before,
    the rule applied in SQL (ratio and floor as parameters) so only the flagged pairs come back."""
    window = 7 * (ANOMALY_WEEKS_BEFORE + 1)
    return f"""WITH source AS (
  {source_sql(project_id, dataset, tables, window + PARTITION_MARGIN_DAYS)}
), usage AS (
  SELECT DATE(usage_start_time) AS day, IFNULL(project.id, "{NO_PROJECT}") AS project_id, IFNULL(service.description, "") AS service,
         cost + (SELECT IFNULL(SUM(c.amount), 0) FROM UNNEST(credits) c) AS net
  FROM source
  WHERE usage_start_time >= TIMESTAMP(DATE_SUB(@today, INTERVAL {window} DAY)) AND usage_start_time < TIMESTAMP(@today)
    AND ({scope_predicate(scope)})
), weekly AS (
  SELECT project_id, service,
         SUM(IF(day >= DATE_SUB(@today, INTERVAL 7 DAY), net, 0)) AS this_week,
         SUM(IF(day < DATE_SUB(@today, INTERVAL 7 DAY), net, 0)) / {ANOMALY_WEEKS_BEFORE} AS weekly_mean_before
  FROM usage GROUP BY project_id, service
)
SELECT project_id, service, this_week, weekly_mean_before FROM weekly
WHERE this_week >= @floor AND (weekly_mean_before <= 0 OR this_week >= @ratio * weekly_mean_before)
ORDER BY this_week DESC, project_id, service
LIMIT {MAX_ANOMALY_ROWS}"""


def _param(name, kind, value):
    return {"name": name, "parameterType": {"type": kind}, "parameterValue": {"value": str(value)}}


def _array_param(name, values):
    return {"name": name, "parameterType": {"type": "ARRAY", "arrayType": {"type": "STRING"}}, "parameterValue": {"arrayValues": [{"value": v} for v in values]}}


def briefing_parameters(today, scope_id):
    return [_param("today", "DATE", today.isoformat()), _param("scope_id", "STRING", scope_id), _array_param("cud_types", CUD_TYPES),
            _array_param("eligible", COMMITMENT_ELIGIBLE_SERVICES)]


def anomaly_parameters(today, scope_id, floor):
    return [_param("today", "DATE", today.isoformat()), _param("scope_id", "STRING", scope_id), _param("floor", "FLOAT64", f"{floor:.2f}"),
            _param("ratio", "FLOAT64", str(ANOMALY_RATIO))]


# --- BigQuery ------------------------------------------------------------------------------------------------------------

def discover_tables(service, project_id, dataset):
    """``[(table_id, partition column or None)]`` — the standard export tables of the dataset (one per billing account), sorted. The
    partition column is ``_PARTITIONTIME`` for an ingestion-time partitioned table (the export's shape), the field for a column-partitioned
    one, ``None`` for an unpartitioned one."""
    found, collection = [], service.tables()
    request = collection.list(projectId=project_id, datasetId=dataset, maxResults=1000)
    while request:
        response = request.execute() or {}
        for table in response.get("tables") or []:
            table_id = str((table.get("tableReference") or {}).get("tableId") or "")
            if not table_id.startswith(EXPORT_TABLE_PREFIX) or str(table.get("type") or "TABLE") != "TABLE":
                continue
            partitioning = table.get("timePartitioning") or {}
            found.append((table_id, partitioning.get("field") or (INGESTION_PARTITION if partitioning else None)))
        request = collection.list_next(previous_request=request, previous_response=response)
    return sorted(found)


def _rows_of(response):
    fields = [f.get("name") for f in (response.get("schema") or {}).get("fields") or []]
    return [dict(zip(fields, (cell.get("v") for cell in row.get("f") or []))) for row in response.get("rows") or []]


def run_query(service, project_id, query, parameters):
    """Runs ``query`` in ``project_id`` (``jobs.query``; the location follows the tables) and returns its rows as dicts of strings. A
    query that outlives the request's timeout is polled through ``getQueryResults``, as are further pages."""
    body = {"query": query, "useLegacySql": False, "parameterMode": "NAMED", "queryParameters": parameters, "timeoutMs": QUERY_TIMEOUT_MS,
            "maxResults": QUERY_PAGE}
    response = service.jobs().query(projectId=project_id, body=body).execute() or {}
    reference = response.get("jobReference") or {}
    polls = 0
    while not response.get("jobComplete", True):
        polls += 1
        if polls > MAX_RESULT_POLLS:
            raise RuntimeError(f"BigQuery query {reference.get('jobId')} did not finish in time")
        response = service.jobs().getQueryResults(projectId=project_id, jobId=reference.get("jobId"), location=reference.get("location"),
                                                  timeoutMs=QUERY_TIMEOUT_MS, maxResults=QUERY_PAGE).execute() or {}
    rows, token = _rows_of(response), response.get("pageToken")
    while token:
        response = service.jobs().getQueryResults(projectId=project_id, jobId=reference.get("jobId"), location=reference.get("location"),
                                                  pageToken=token, maxResults=QUERY_PAGE).execute() or {}
        rows += _rows_of(response)
        token = response.get("pageToken")
    return rows


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# --- the briefing --------------------------------------------------------------------------------------------------------

def parse_briefing(rows):
    """The query's rows as facts: ``daily`` (date → net), ``projects`` and ``services`` (name → (last 30 days, the 30 before)),
    ``credits`` (type → amount), ``eligible`` (cost, committed-use credits), ``currency``, ``freshness`` (an aware datetime or None),
    ``unattributed`` (account-level charges of the last 30 days that name no project)."""
    facts = {"daily": {}, "projects": {}, "services": {}, "credits": {}, "eligible": (0.0, 0.0), "currency": "", "freshness": None, "unattributed": 0.0}
    currencies = {}
    for row in rows:
        kind, item, value, value2 = row.get("kind"), str(row.get("item") or ""), _float(row.get("value")), _float(row.get("value2"))
        if kind == "day":
            try:
                facts["daily"][date.fromisoformat(item)] = value
            except ValueError:
                continue
        elif kind == "project":
            facts["projects"][item or NO_PROJECT] = (value, value2)
        elif kind == "service":
            facts["services"][item or "(no service)"] = (value, value2)
        elif kind == "credit":
            facts["credits"][item] = facts["credits"].get(item, 0.0) + value
        elif kind == "eligible":
            facts["eligible"] = (value, value2)
        elif kind == "currency" and item:
            currencies[item] = value
        elif kind == "freshness":
            facts["freshness"] = parse_timestamp(item) if item else None
        elif kind == "unattributed":
            facts["unattributed"] = value
    facts["currency"] = max(currencies, key=currencies.get) if currencies else ""
    facts["mixed_currencies"] = len(currencies) > 1
    return facts


def money(amount, currency):
    """``1,931.42 USD``; a negative amount keeps its sign."""
    text = f"{amount:,.2f}"
    return f"{text} {currency}".strip()


def percent_change(now, before, minimum=1.0):
    """``+12 %`` / ``−5 %`` / ``new`` (less than ``minimum`` before: a change from nothing is not a percentage) / ``""`` (nothing either side)."""
    if before < minimum:
        return "new" if now >= minimum else ""
    change = (now - before) / before * 100
    sign = "+" if change >= 0.5 else ("\u2212" if change <= -0.5 else "\u00b1")
    return f"{sign}{abs(change):.0f} %"


def share_text(part, total):
    """``52 %``, ``<1 %`` for a sliver, ``—`` without a total."""
    if total <= 0:
        return "\u2014"
    share = part / total * 100
    return "<1 %" if 0 < share < 0.5 else f"{share:.0f} %"


def month_bounds(day):
    """``(first day, last day)`` of ``day``'s month."""
    return day.replace(day=1), day.replace(day=monthrange(day.year, day.month)[1])


def previous_month(first_day):
    return (first_day - timedelta(days=1)).replace(day=1)


def total_between(daily, start, end):
    """The net over ``[start, end]`` (inclusive) of the daily series."""
    return sum(value for day, value in daily.items() if start <= day <= end)


def bq_line(sql):
    """A runnable ``bq query`` for ``sql`` (double quotes inside the SQL; the line is single-quoted for the shell)."""
    return f"bq query --use_legacy_sql=false '{' '.join(sql.split())}'"


def _net_sql(source, where):
    return f'SELECT ROUND(SUM(cost) + SUM((SELECT IFNULL(SUM(c.amount), 0) FROM UNNEST(credits) c)), 2) AS net FROM {source} WHERE {where}'


def _top(items, total, currency, noun):
    """``name 1,020.00 (52 %, +3 %); …; 2 others 0.40`` over ``{name: (last 30 days, the 30 before)}`` — the items with spend in the last 30
    days, the top ``TOP_ITEMS`` named, the rest counted."""
    ranked = sorted(((name, values) for name, values in items.items() if abs(values[0]) >= 0.005), key=lambda item: (-item[1][0], item[0]))
    parts = []
    for name, (now, before) in ranked[:TOP_ITEMS]:
        change = percent_change(now, before)
        parts.append(f"{name} {now:,.2f} ({share_text(now, total)}" + (f", {change} vs the {COMPARISON_DAYS} days before" if change else "") + ")")
    rest = ranked[TOP_ITEMS:]
    if rest:
        parts.append(f"{len(rest)} other {noun}{'s' if len(rest) != 1 else ''} {sum(now for _, (now, _) in rest):,.2f}")
    return "; ".join(parts) if parts else f"no {noun} with spend in the last {COMPARISON_DAYS} days"


def briefing_rows(facts, today, scope, scope_id, source, table_ids, dataset_ref, floor=None):
    """The briefing's lines — ``Line, Value, Detail, Fix`` — from the facts (:func:`parse_briefing`) as of ``today`` (UTC; the complete
    days are the ones before it). ``source`` is the ``FROM`` expression of the ``bq`` lines, ``dataset_ref`` ``project.dataset``."""
    daily, currency = facts["daily"], facts["currency"] or "USD"
    scope_sql = scope_predicate(scope, scope_id)
    first, last = month_bounds(today)
    yesterday = today - timedelta(days=1)
    elapsed = today.day - 1  # complete days of this month
    last_first = previous_month(first)
    last_last = first - timedelta(days=1)
    before_first = previous_month(last_first)
    before_last = last_first - timedelta(days=1)
    earliest = min(daily) if daily else None
    rows = []

    def from_note(start):
        return f" (export from {earliest.isoformat()})" if earliest and earliest > start else ""

    # Month to date
    mtd = total_between(daily, first, yesterday) if elapsed else 0.0
    same_days_end = min(last_first + timedelta(days=elapsed - 1), last_last) if elapsed else None
    same_days = total_between(daily, last_first, same_days_end) if elapsed else 0.0
    if elapsed:
        detail = (f"{first.day}–{yesterday.day} {first.strftime('%B')} ({elapsed} complete day{'s' if elapsed != 1 else ''}) vs {money(same_days, currency)} for "
                  f"{last_first.day}–{same_days_end.day} {last_first.strftime('%B')}" + (f": {percent_change(mtd, same_days)}." if percent_change(mtd, same_days) else "."))
        fix = bq_line(_net_sql(source, f'DATE(usage_start_time) BETWEEN "{first.isoformat()}" AND "{yesterday.isoformat()}" AND {scope_sql}'))
    else:
        detail = f"No complete day of {first.strftime('%B')} yet (the export runs behind usage); last month stands in below."
        fix = bq_line(_net_sql(source, f'DATE(usage_start_time) BETWEEN "{last_first.isoformat()}" AND "{last_last.isoformat()}" AND {scope_sql}'))
    rows.append({"Line": "Month to date", "Value": money(mtd, currency) if elapsed else "—", "Detail": detail, "Fix": fix})
    # Forecast
    recent_days = [today - timedelta(days=n) for n in range(1, FORECAST_DAYS + 1)]
    mean = sum(daily.get(day, 0.0) for day in recent_days) / FORECAST_DAYS
    remaining = last.day - elapsed
    forecast = mtd + mean * remaining
    rows.append({"Line": "Forecast", "Value": f"\u2248 {money(forecast, currency)}",
                 "Detail": f"Month to date plus the mean of the last {FORECAST_DAYS} complete days ({money(mean, currency)}/day) over the {remaining} day{'s' if remaining != 1 else ''} "
                           f"remaining in {first.strftime('%B')}.",
                 "Fix": bq_line(f'SELECT ROUND((SUM(cost) + SUM((SELECT IFNULL(SUM(c.amount), 0) FROM UNNEST(credits) c))) / {FORECAST_DAYS}, 2) AS daily_mean FROM {source} '
                                f'WHERE DATE(usage_start_time) BETWEEN "{recent_days[-1].isoformat()}" AND "{yesterday.isoformat()}" AND {scope_sql}')})
    # Last month
    last_total = total_between(daily, last_first, last_last)
    before_total = total_between(daily, before_first, before_last)
    rows.append({"Line": "Last month", "Value": money(last_total, currency),
                 "Detail": f"{last_first.strftime('%B')}{from_note(last_first)}; {before_first.strftime('%B')} {money(before_total, currency)}{from_note(before_first)}"
                           + (f" ({percent_change(last_total, before_total)})." if percent_change(last_total, before_total) else "."),
                 "Fix": bq_line(f'SELECT FORMAT_DATE("%Y-%m", DATE(usage_start_time)) AS month, ROUND(SUM(cost) + SUM((SELECT IFNULL(SUM(c.amount), 0) FROM UNNEST(credits) c)), 2) AS net '
                                f'FROM {source} WHERE DATE(usage_start_time) BETWEEN "{before_first.isoformat()}" AND "{last_last.isoformat()}" AND {scope_sql} GROUP BY 1 ORDER BY 1')})
    # By project, by service
    window_start = today - timedelta(days=COMPARISON_DAYS)
    for line, items, noun, column in (("By project", facts["projects"], "project", "project.id"), ("By service", facts["services"], "service", "service.description")):
        total = sum(now for now, _ in items.values())
        active = sum(1 for now, _ in items.values() if abs(now) >= 0.005)
        rows.append({"Line": f"{line} ({COMPARISON_DAYS} days)", "Value": f"{active} {noun}{'s' if active != 1 else ''}, {money(total, currency)}",
                     "Detail": _top(items, total, currency, noun) + ".",
                     "Fix": bq_line(f'SELECT {column} AS {noun}, ROUND(SUM(cost) + SUM((SELECT IFNULL(SUM(c.amount), 0) FROM UNNEST(credits) c)), 2) AS net FROM {source} '
                                    f'WHERE DATE(usage_start_time) BETWEEN "{window_start.isoformat()}" AND "{yesterday.isoformat()}" AND {scope_sql} GROUP BY 1 ORDER BY 2 DESC')})
    # Credits and committed-use coverage
    credits = facts["credits"]
    credit_total = sum(credits.values())
    named = sorted(credits.items(), key=lambda item: item[1])
    parts = [f"{CREDIT_NAMES.get(kind, kind.lower().replace('_', ' '))} {amount:,.2f}" for kind, amount in named if abs(amount) >= 0.005 and kind not in CUD_TYPES]
    eligible_cost, eligible_cud = facts["eligible"]
    cud = -sum(amount for kind, amount in credits.items() if kind in CUD_TYPES)
    if eligible_cost > 0:
        coverage = f"{min(100.0, max(0.0, -eligible_cud / eligible_cost * 100)):.0f} %"
        eligible_text = f"{coverage} of {money(eligible_cost, currency)} of commitment-eligible spend (Compute Engine, Cloud SQL, GKE, Spanner, Cloud Run, Memorystore, AlloyDB, Bigtable, Dataflow) is covered by a commitment"
    else:
        eligible_text = "no commitment-eligible spend in the window"
    cud_text = f"committed-use discounts {-cud:,.2f}" if cud else "committed-use discounts: none"
    rows.append({"Line": f"Credits ({COMPARISON_DAYS} days)", "Value": money(credit_total, currency),
                 "Detail": (("; ".join(parts) + ". ") if parts else "No sustained-use discounts, promotions or negotiated discounts. ") + f"{cud_text[0].upper()}{cud_text[1:]} — {eligible_text}.",
                 "Fix": ("Review Resource-Based Commitment Recommendations in this report and the Capacity Planner (console › Compute Engine › Committed use discounts) "
                         "for the steady part of this spend; a one- or three-year commitment saves 20–55 % on it depending on the service and term. The credits by type: "
                         + bq_line(f'SELECT c.type, ROUND(SUM(c.amount), 2) AS amount FROM {source}, UNNEST(credits) c WHERE DATE(usage_start_time) BETWEEN '
                                   f'"{window_start.isoformat()}" AND "{yesterday.isoformat()}" AND {scope_sql} GROUP BY 1 ORDER BY 2'))})
    # Freshness
    freshness = facts["freshness"]
    if freshness is not None:
        hours = max(0.0, (utcnow() - freshness).total_seconds() / 3600)
        value = f"{hours:.0f} h behind" if hours >= 1 else "under an hour behind"
        detail = f"Last export {freshness.strftime('%Y-%m-%d %H:%M UTC')}"
    else:
        value, detail = "no rows", "No rows in the window"
    tables_text = ", ".join(table_ids)
    detail += f"; {WINDOW_DAYS} days read from {tables_text} in {dataset_ref}"
    if facts.get("mixed_currencies"):
        detail += f"; the rows carry more than one currency, the amounts above are summed as {currency}"
    if scope == "organization" and abs(facts["unattributed"]) >= 0.5:
        detail += (f"; {money(facts['unattributed'], currency)} of account-level charges without a project in the last {COMPARISON_DAYS} days (support, marketplace "
                   f"fees) are not attributed to the organization")
    if floor is not None:
        detail += f"; the anomaly floor is {money(floor, currency)}"
    rows.append({"Line": "Freshness", "Value": value, "Detail": detail + ".",
                 "Fix": bq_line(f"SELECT MAX(export_time) AS last_export, MIN(DATE(usage_start_time)) AS first_day FROM {source}")})
    return rows


def anomaly_floor(configured, last_month_net):
    """The floor a week's spend has to reach: the configured one, or ``ANOMALY_FLOOR_SHARE`` of last month's net when that is higher."""
    return max(float(configured), last_month_net * ANOMALY_FLOOR_SHARE if last_month_net > 0 else 0.0)


def anomaly_rows(rows, today, currency, floor, source):
    """The Spend Anomalies rows from the query's rows (already filtered by the rule): ``Project, Service, This Week, Weekly Mean Before,
    Change, Issue, Detail, Fix``, Investigation Recommended."""
    found = []
    week_end, week_start = today - timedelta(days=1), today - timedelta(days=7)
    for row in rows:
        project_id, service = str(row.get("project_id") or NO_PROJECT), str(row.get("service") or "")
        this_week, before = _float(row.get("this_week")), _float(row.get("weekly_mean_before"))
        change = percent_change(this_week, before)
        new = before <= 0
        found.append({"Project": project_id, "Service": service, "This Week": money(this_week, currency), "Weekly Mean Before": money(before, currency) if not new else "—",
                      "Change": change or "new", "Issue": "New spend." if new else f"Spend up {change} week over week.",
                      "Detail": f"{money(this_week, currency)} in the 7 days {week_start.isoformat()} to {week_end.isoformat()}"
                                + (f" against a weekly mean of {money(before, currency)} over the {ANOMALY_WEEKS_BEFORE} weeks before" if not new else f", nothing in the {ANOMALY_WEEKS_BEFORE} weeks before")
                                + f" (floor {money(floor, currency)}).",
                      "Fix": bq_line(f'SELECT sku.description AS sku, ROUND(SUM(cost), 2) AS cost FROM {source} WHERE project.id = "{project_id}" AND service.description = "{service}" '
                                     f'AND DATE(usage_start_time) BETWEEN "{(today - timedelta(days=14)).isoformat()}" AND "{week_end.isoformat()}" GROUP BY 1 ORDER BY 2 DESC LIMIT 10'),
                      "_status": "Investigation Recommended"})
    return found


# --- the check -----------------------------------------------------------------------------------------------------------

def _write(sink, job_id, check, rows, status):
    sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": rows, "Status": status})


def _write_all(sink, job_id, row, status):
    for check in SPEND_CHECKS:
        _write(sink, job_id, check, [dict(row)], status)


def grant_hint(error, dataset_ref):
    """The Error text: the API's message, plus the dataset grant when the read was refused."""
    text = str(error)
    status = getattr(getattr(error, "resp", None), "status", None) if isinstance(error, HttpError) else None
    if status == 403 or "403" in text or "Access Denied" in text:
        email = get_settings().service_account_email or "the service account"
        text += f" — grant {email} roles/bigquery.dataViewer on the dataset {dataset_ref} (a dataset-level grant: bq show --format=prettyjson {dataset_ref.replace('.', ':', 1)} > ds.json, add " \
                f'{{"role": "READER", "userByEmail": "{email}"}} to "access", bq update --source ds.json {dataset_ref.replace(".", ":", 1)}).'
    return text


def check_spend(scope, scope_id, job_id, *, sink):
    """Writes *Spend Briefing* and *Spend Anomalies* from the billing export (module docstring)."""
    settings = get_settings()
    export = settings.billing_export
    if not export:
        print(f"💳 [{job_id}] {BRIEFING}: BILLING_EXPORT is not set; writing the not-configured rows")
        _write_all(sink, job_id, {"Summary": NOT_CONFIGURED}, "Informational")
        return
    export_project, dataset = export
    dataset_ref = f"{export_project}.{dataset}"
    print(f"💳 [{job_id}] Checking {BRIEFING} and {ANOMALIES_CHECK} under {scope} {scope_id} from {dataset_ref}...")
    run_project = settings.project_id or export_project
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        service = gcp.api_build("bigquery", "v2", credentials=credentials)
        tables = discover_tables(service, export_project, dataset)
    except Exception as e:
        logging.error(f"[{job_id}] {BRIEFING}: could not list the tables of {dataset_ref}: {e}")
        _write_all(sink, job_id, {"Error": grant_hint(e, dataset_ref)}, "Error")
        return
    if not tables:
        _write_all(sink, job_id, {"Error": f"No standard billing export table ({EXPORT_TABLE_PREFIX}*) in {dataset_ref}: BILLING_EXPORT must name the dataset the "
                                           f"billing account's standard usage cost export writes to."}, "Error")
        return
    today = utcnow().date()
    try:
        facts = parse_briefing(run_query(service, run_project, briefing_query(export_project, dataset, tables, scope), briefing_parameters(today, scope_id)))
        last_first = previous_month(today.replace(day=1))
        floor = anomaly_floor(settings.spend_anomaly_floor, total_between(facts["daily"], last_first, today.replace(day=1) - timedelta(days=1)))
        flagged = run_query(service, run_project, anomaly_query(export_project, dataset, tables, scope), anomaly_parameters(today, scope_id, floor))
    except Exception as e:
        logging.error(f"[{job_id}] {BRIEFING}: the query on {dataset_ref} failed: {e}")
        _write_all(sink, job_id, {"Error": grant_hint(e, dataset_ref)}, "Error")
        return
    table_ids = [table_id for table_id, _ in tables]
    source = table_reference(export_project, dataset, table_ids[0]) if len(table_ids) == 1 else \
        "(" + " UNION ALL ".join(f"SELECT * FROM {table_reference(export_project, dataset, t)}" for t in table_ids) + ")"
    _write(sink, job_id, BRIEFING, briefing_rows(facts, today, scope, scope_id, source, table_ids, dataset_ref, floor), "Informational")
    rows = anomaly_rows(flagged, today, facts["currency"] or "USD", floor, source)
    for row in rows:
        row.pop("_status", None)
    if rows:
        _write(sink, job_id, ANOMALIES_CHECK, rows, "Investigation Recommended")
    else:
        _write(sink, job_id, ANOMALIES_CHECK, [{"Status": ANOMALIES_ALL_CLEAR}], "Compliant")
