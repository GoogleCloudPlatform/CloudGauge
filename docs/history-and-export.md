# History and analytics

Scheduled scans, the history page and the BigQuery export of every scan — and the spend records, which read the billing export. The export's schema as a contract: [stability.md › BigQuery export schema](stability.md#bigquery-export-schema).

In this page: [Scheduled scans](#scheduled-scans) · [The history page](#the-history-page) · [The BigQuery export](#the-bigquery-export) · [Spend](#spend)

Every finished scan leaves a summary under `scopes/<scope>/<scope id>/` in the results bucket, which the report's *Changes since last scan* reads. v17 builds three things on top of it: **scheduled scans**, so the history fills in without anyone clicking; the **history page**, the scope's scans over time; and a **BigQuery export** of every scan, for dashboards and questions the pages do not answer.

## Scheduled scans

`SCHEDULES` on `tools/deploy.sh` creates one Cloud Scheduler job per entry (`NAME=SCOPE/SCOPE_ID@CRON`, cron in UTC):

```
PROJECT_ID=my-project SKIP_BUILD=1 TAG=<tag> \
SCHEDULES="weekly-org=organization/123456789012@30 0 * * 1;nightly-prod=project/my-prod@0 2 * * *" \
tools/deploy.sh
```

Each job posts `{"scope", "scope_id", "name"}` to the worker's `/scheduled-scan` with the service account's OIDC token — the same identity Cloud Tasks uses, so the worker needs no new invoker and the web service, behind IAP, is not involved. The endpoint enqueues the same scan task **Start scan** does; the report and the summary read *Requested by* `schedule: <name>`. One rule on top: a scope scans once at a time — while the scope's previous scan (scheduled or started from the page) is still running the endpoint answers **409** and starts nothing (the job's last run shows the failure in Cloud Scheduler), so a weekly schedule on an organization that takes longer than a week never piles scans up. When Cloud Tasks will not take the task after the 30-second retry (v20), the endpoint answers **503** with `Retry-After` and starts nothing; the jobs are created without retries (`--max-retry-attempts=0`, and Terraform the same), so that run is recorded as failed and the next scheduled run, finding the scope free, starts the scan. `gcloud scheduler jobs run NAME --location=REGION` starts one now; the status page of the job it started is `/status/<job id>/<scope>/<scope id>` (the 202 body names it).

## The history page

`/history/<scope>/<scope id>` — from the report header's **History** row, the status page's **View history**, or the setup page once a resource is chosen — shows the newest 52 scans of a scope: the four pillar scores as lines over time and one row per scan with its scores, its four Overview counts, who asked and the checks whose status changed since the scan before, each linking to its report. It reads the summaries, so it covers every scan since v15 and needs nothing configured. Every scan opens its report from the page (v20): the scan's date is the link, the **Report** column next to the counts holds **Open report · CSV**, each dot of the chart opens the scan it stands for, and **Open latest report** in the page head is the newest one in one click.

## The BigQuery export

With `BIGQUERY_DATASET` set (`tools/deploy.sh BIGQUERY_DATASET=cloudgauge` creates the dataset in `REGION` and grants the service account WRITER on it and `roles/bigquery.jobUser` on the project — nothing on the organization), the report build loads each finished scan into two tables before it renders, with BigQuery **load jobs** (free, idempotent: a retried build is told the jobs exist), and the report's header says what became of it — *n finding rows and this scan's summary loaded into cloudgauge.findings and cloudgauge.scans*, *still running*, or *failed: …*. The export never fails a scan. Synthetic scans are not exported.

The columns of both tables, and what a release may change about them: [stability.md › BigQuery export schema](stability.md#bigquery-export-schema).

Both tables are clustered by `scope_id` (and `check_name`). Scans made before the export existed are loaded once from their summaries and CSV reports:

```
python tools/backfill_export.py --project my-project --location asia-south1 --bucket cloudgauge-reports-my-project --dataset cloudgauge [--dry-run]
```

It skips the scans already in `scans`, so it can be run again. **Five queries to start from** (replace the dataset and scope ID):

```sql
-- 1. The four scores over time, one row per scan
SELECT generated_at, security_score, cost_score, reliability_score, operations_score, total_projects
FROM `my-project.cloudgauge.scans` WHERE scope_id = '123456789012' ORDER BY generated_at;

-- 2. Which checks flipped status between the last two scans
WITH last_two AS (
  SELECT job_id, generated_at, c.check_name, c.status, ROW_NUMBER() OVER (ORDER BY generated_at DESC) AS n
  FROM `my-project.cloudgauge.scans`, UNNEST(checks) AS c WHERE scope_id = '123456789012'
  QUALIFY DENSE_RANK() OVER (ORDER BY generated_at DESC) <= 2)
SELECT a.check_name, b.status AS before, a.status AS after
FROM last_two a JOIN last_two b USING (check_name)
WHERE a.generated_at > b.generated_at AND a.status != b.status;

-- 3. Findings that have been open for every one of the last N scans (the ones nobody fixes)
SELECT check_name, identity, COUNT(DISTINCT job_id) AS scans_open, MIN(generated_at) AS first_seen
FROM `my-project.cloudgauge.findings`
WHERE scope_id = '123456789012' AND status IN ('Action Required', 'Investigation Recommended')
GROUP BY check_name, identity HAVING scans_open >= 4 ORDER BY scans_open DESC, first_seen;

-- 4. Identified monthly savings per scan (the Efficiency line, over time)
SELECT generated_at, ROUND(SUM(SAFE_CAST(REPLACE(SPLIT(JSON_VALUE(row_json, '$."Est. Monthly Saving"'), ' ')[OFFSET(0)], ',', '') AS FLOAT64)), 2) AS usd_per_month
FROM `my-project.cloudgauge.findings`
WHERE scope_id = '123456789012' AND category = 'Cost Optimization' AND JSON_VALUE(row_json, '$."Est. Monthly Saving"') LIKE '% USD'
GROUP BY generated_at ORDER BY generated_at;

-- 5. The projects with the most open findings in the latest scan
SELECT project, COUNT(*) AS findings, COUNT(DISTINCT check_name) AS checks
FROM `my-project.cloudgauge.findings`
WHERE job_id = (SELECT job_id FROM `my-project.cloudgauge.scans` WHERE scope_id = '123456789012' ORDER BY generated_at DESC LIMIT 1)
  AND status IN ('Action Required', 'Investigation Recommended') AND project IS NOT NULL
GROUP BY project ORDER BY findings DESC LIMIT 20;
```

**Looker Studio.** Create a report → add a data source → BigQuery → your project → `cloudgauge` → `scans`; a time-series chart with `generated_at` as the dimension and the four scores as metrics (aggregation *Average*, filter `scope_id`) is the history page as a dashboard. A second data source on `findings` gives a table of `check_name`, `project`, `status` filtered to the latest `job_id`, and a scorecard of `COUNT_DISTINCT(identity)` where `status = 'Action Required'`. Both tables are partitioned by `generated_at`: keep a date-range control on it to keep queries small.

**Gemini Enterprise / "talk to your infrastructure".** Point a Gemini Enterprise (Agentspace) data store, or a Conversational Analytics agent in Looker Studio, at the `cloudgauge` dataset: the column names above are what the questions resolve against ("which projects gained findings since last month", "how long has the public bucket in data-lake been open"). `row_json` holds every column a check wrote, so questions about a check's own fields (`$.Bucket`, `$.Principal`, `$.Zone`) are answered with `JSON_VALUE`.

## Spend

*(v18.8)* **Spend Briefing** and **Spend Anomalies** read the organization's **billing export** — the standard usage cost tables (`gcp_billing_export_v1_<account>`) the billing account already writes to a BigQuery dataset — never the billing account itself (CloudGauge holds no billing role; see the decision in the release notes). Two queries per scan, run in `PROJECT_ID` under the `roles/bigquery.jobUser` the export step grants too, pruned to about a hundred days of partitions and summed in SQL: a few MB read, cents a month.

```bash
# 1. Where the billing account exports to (Billing › Billing export › BigQuery export › Standard usage cost): <project>.<dataset>
# 2. Deploy with it; when the dataset is in PROJECT_ID the script grants READER on it, else see step 3
PROJECT_ID=my-project SKIP_BUILD=1 TAG=<tag> BILLING_EXPORT=my-project.billing tools/deploy.sh
# 3. A dataset in another project: its owner grants the service account READER on the dataset once (a dataset-level entry;
#    BigQuery › the dataset › Sharing › Permissions › BigQuery Data Viewer, or:)
bq show --format=prettyjson billing-admin:billing > ds.json   # add {"role": "READER", "userByEmail": "cloudgauge-sa@my-project.iam.gserviceaccount.com"} to "access"
bq update --source ds.json billing-admin:billing
```

What the briefing says, and how the scope is cut: an organization's or a folder's spend is every export row whose project sits under it (`project.ancestry_numbers`), a project's its own — so a project the export still bills after its deletion is counted where it belonged, and account-level charges that name no project (support, marketplace fees) are counted on the organization's **Freshness** line, not attributed. The month-to-date and forecast lines use the **complete** days (through yesterday, UTC); the export runs hours behind usage, and the Freshness line says how many. Each line's `Fix` is the `bq query` that reproduces it, so a number can be checked in a minute. Several billing accounts exporting to the same dataset are summed and named.

**Spend Anomalies** applies its rule in SQL and returns only the flagged pairs: the last seven complete days against the weekly mean of the three weeks before, 1.5 × or more and at least the floor (`SPEND_ANOMALY_FLOOR`, 50 in the export's currency, or 2 % of last month's net when that is higher), or new spend of at least the floor. The fix is the SKU breakdown of the pair over the last two weeks. Unset `BILLING_EXPORT`: both records are *Informational* and say how to configure it; a dataset the account cannot read: both in Error, the row naming the grant.
