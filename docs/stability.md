# The stability surface

What a deployment, a dashboard or a script may depend on, in one place: the environment variables, the Terraform variables and outputs, the roles and APIs, the BigQuery export schema, the CSV columns, the check names and the HTTP routes — and [the rule](#the-rule) a release follows for them. Everything else in this repository may change in any release.

In this page: [Configuration Reference](#configuration-reference) · [Terraform variables and outputs](#terraform-variables-and-outputs) · [Roles and APIs](#roles-and-apis) · [BigQuery export schema](#bigquery-export-schema) · [CSV columns](#csv-columns) · [Check names](#check-names) · [HTTP routes](#http-routes) · [The rule](#the-rule)

## Configuration Reference

CloudGauge is configured entirely through environment variables on the Cloud Run service.

| Variable | Required | Default | Description |
|---|---|---|---|
| `PROJECT_ID` | Yes | – | Project that hosts CloudGauge (Cloud Tasks, GCS, Vertex AI). |
| `LOCATION` | Yes | – | Region of the Cloud Run service and the Cloud Tasks queue. |
| `TASK_QUEUE` | Yes | – | Cloud Tasks queue name. The queue is created automatically at startup if it doesn't exist. |
| `RESULTS_BUCKET` | Yes | – | GCS bucket for status files, intermediate findings, and reports. |
| `SERVICE_ACCOUNT_EMAIL` | Yes | – | Service account whose identity the Cloud Tasks tasks carry (the OIDC token the worker verifies). |
| `CLOUDGAUGE_ROLE` | No | `all` | Which part of the application this service is: `web` (the pages and the API, behind IAP; needs `WORKER_URL`), `worker` (the Cloud Tasks endpoints only), or `all` (everything on one service, as before v16). |
| `PROJECT_NUMBER` | No | the metadata server's | The project's number: the audience of IAP's identity assertions names it, so a `web` service needs it to verify who is signed in. Cloud Run's metadata server provides it; set it to skip that lookup (`tools/deploy.sh` does). |
| `GEMINI_MODEL` | No | `auto` | `auto` uses the newest stable Gemini Flash model available to the project (falls back to `gemini-flash-latest` if models can't be listed). Set a model ID (e.g. `gemini-2.5-flash`) to pin one. |
| `VERTEX_LOCATION` | No | `global` | Vertex AI location used for Gemini calls. |
| `WORKER_URL` | `web`: yes | discovered | URL that Cloud Tasks calls for `/run-scan` and the other worker endpoints. On a `web` service: the worker service's URL (required; the web service never runs scans). On a `worker` or `all` service: its own URL — discovered at startup through the Cloud Run Admin API (from Cloud Run's own `K_SERVICE` variable; needs `roles/run.viewer` on the service) unless set; `tools/deploy.sh` sets it to the deterministic `https://<service>-<project number>.<region>.run.app`. For a canary, the worker's tag URL. |
| `WORKER_AUDIENCE` | No | the task URL | Audience of the OIDC token on the tasks. Leave unset normally. For a canary, set it to the **worker's main** URL: Cloud Run rejects tokens whose audience is a revision tag URL (HTTP 401). |
| `WORKER_TOKEN_CHECK` | No | `on` | Whether the worker endpoints verify the caller's ID token in-process, on top of Cloud Run's IAM check (v18.6.1, [Request hardening](security.md#request-hardening)). `off` is the way back if a front in your path rewrites the token. Enforced in the `production` and `synthetic` profiles only. |
| `CLOUDGAUGE_DISABLE_ATTRIBUTION` | No | – | `true` (also `1`, `yes`, `on`) stops the services from appending the client identifier `cloud-solutions/cloudgauge-v<version>` to the user agent of their Google Cloud API calls (v18.8.1, [Privacy & API Attribution](security.md#privacy--api-attribution)). Unset: the identifier is sent. Nothing is transmitted anywhere but to the Google Cloud APIs the scan calls in either case. |
| `BEST_PRACTICES_CSV_URL` | No | the bundled table | Source of the best-practices table the Organization Policies check scores against: unset, the table shipped inside the image (`assets/gcp_best_practices.csv`); a `gs://bucket/object` the service account can read; or an `https://` URL fetched anonymously (the pre-v18.1 default was the GitHub copy). An overrides file in the results bucket amends whichever is in use — see [Customising the policy table](development.md#customising-the-policy-table). |
| `SERVICE_HEALTH_WINDOW_DAYS` | No | `90` | How far back the **Service Health Incidents** briefing looks (1–366 days). |
| `SERVICE_HEALTH_RELEVANCE` | No | `IMPACTED` | Which Personalized Service Health relevance levels the briefing lists, comma-separated: `IMPACTED`, `RELATED`, `PARTIALLY_RELATED`, `NOT_IMPACTED`, `UNKNOWN`. Whatever the setting, the *Related* incidents confined to specific locations are listed too (Incident Exposure reads them) and the global ones are counted in a note; `IMPACTED,RELATED` (the default until v17.2) lists every Related incident. |
| `SERVICE_HEALTH_INCIDENTS` | No | `on` | `off` removes the **Service Health Incidents** briefing and **Incident Exposure** from the report (v17.3); the Service Health API calls still run for **Personalized Service Health API Coverage**. |
| `ADVISORY_WINDOW_DAYS` | No | `365` | How far back the **Advisory Notifications** briefing looks (1–3660 days). |
| `COST_ALLOCATION_LABELS` | No | – | The label keys every project must carry, comma-separated (`cost-center,environment,owner`); **Cost Allocation Labels** lists the projects missing one. Unset: the check is *Informational* and stays out of the score (v17). |
| `TRUSTED_DOMAINS` | No | – | Domains besides the organization's primary one that **External Principals** counts as the organization's, comma-separated (`partner.example,acquired.example`). Unset: the primary domain alone (v18.5). |
| `SNAPSHOT_MAX_AGE_DAYS` | No | `90` | A disk snapshot older than this is listed by **Snapshot Sprawl** (v17). |
| `RESERVATION_COVERAGE_MIN_VCPUS` | No | `32` | **Reservation Coverage** speaks up from this many running vCPUs in one zone of a project with fewer reserved there (v17). |
| `BILLING_EXPORT` | No | – | The BigQuery dataset the billing account exports to, `<project>.<dataset>` (or `<project>:<dataset>`): **Spend Briefing** and **Spend Anomalies** read its standard usage cost tables (`gcp_billing_export_v1_*`), with `roles/bigquery.dataViewer` on that dataset and `roles/bigquery.jobUser` in `PROJECT_ID` ([Spend](history-and-export.md#spend); v18.8). Unset: both are *Informational* and say how to configure it. |
| `SPEND_ANOMALY_FLOOR` | No | `50` | The least a project's week on a service must cost, in the export's currency, to be a **Spend Anomalies** row; 2 % of last month's net applies when that is higher (v18.8). |
| `BIGQUERY_DATASET` | No | – | The BigQuery dataset, in `PROJECT_ID`, every finished scan is loaded into (`scans` and `findings`; v17). Unset: nothing is exported. `tools/deploy.sh BIGQUERY_DATASET=…` creates it and grants what the load needs ([History and analytics](history-and-export.md#history-and-analytics)). |
| `BIGQUERY_EXPORT_WAIT_SECONDS` | No | `60` | How long the report build waits for the export's load jobs (0–600) before it reports them as still running; they complete on their own either way. |
| `SCAN_SHARD_SIZE` | No | `20` | Projects per shard. A scope with more projects than this runs as a sharded scan (see [Scaling to Large Organizations](architecture.md#scaling-to-large-organizations)); up to this many, in one task as before. |
| `SCAN_MAX_CONCURRENT_SHARDS` | No | `25` | Shards Cloud Tasks runs at a time (the queue's max concurrent dispatches). Lower it if the organization's API quotas are tight, raise it for speed. |
| `SHARD_TIME_BUDGET_SECONDS` | No | `1200` | Time a shard gives its checks (60–1800). Checks still running when it runs out are reported as errors for that shard. |
| `TASK_DISPATCH_DEADLINE_SECONDS` | No | `1800` | Cloud Tasks deadline for one attempt of a task (15–1800, the Cloud Tasks maximum). Keep it above the shard time budget and below the Cloud Run request timeout. |
| `SWEEP_INTERVAL_SECONDS` | No | `1800` | How often the sweeper checks on a sharded job (it checks sooner when the job's time limit is closer than that). |
| `SCAN_TIME_LIMIT_SECONDS` | No | computed per job | After this long a running job is finished with the results it has (the rest become error rows). Unset or `0`: `max(6 h, 2 × ceil(shards / SCAN_MAX_CONCURRENT_SHARDS) × TASK_DISPATCH_DEADLINE_SECONDS)`, so a large organization is never cut off while its shards are queued (see [Sizing for your organization](architecture.md#sizing-for-your-organization)). Set it to cap a scan's wall-clock time regardless of size. |
| `TASK_MAX_ATTEMPTS` | No | `3` | Attempts per task. Must match the queue's `maxAttempts`: a shard that fails on its last attempt records its checks as error rows instead of retrying forever. |
| `CLOUDGAUGE_ENV` | No | `production` | `production` runs the startup checks (required variables, worker URL, queue). `development` and `testing` skip them. `synthetic` is production with a simulated data plane for load tests (see [Load Testing](operations.md#load-testing-with-a-synthetic-organization)). |
| `SYNTHETIC_PROJECTS` | With `synthetic` | – | Number of generated projects. Required by, and only used in, the `synthetic` profile. |
| `SYNTHETIC_SEED` | No | `42` | Seed of the generated organization. Same seed, same organization. |
| `SYNTHETIC_LATENCY_MS` | No | `150` | Median simulated latency per API call, in milliseconds. `0` for CPU-only runs. |
| `SYNTHETIC_ERROR_RATE` | No | `0` | Fraction (0–1) of simulated API calls that fail with HTTP 429 / `RESOURCE_EXHAUSTED`. |
| `SYNTHETIC_DENIED_FRACTION` | No | `0.02` | Fraction (0–1) of generated projects whose APIs all answer 403 (missing permissions). |

The service creates the queue with `SCAN_MAX_CONCURRENT_SHARDS` concurrent dispatches, `TASK_MAX_ATTEMPTS` attempts, and 30 s–10 min back-off. It never modifies a queue that already exists; if the limits differ it logs a warning with the command to apply them, for example:

```
gcloud tasks queues update ${QUEUE_NAME} --location ${REGION} \
  --max-concurrent-dispatches=25 --max-attempts=3 --min-backoff=30s --max-backoff=600s
```

## Terraform variables and outputs

The inputs and outputs of [`terraform/`](../terraform/) as `variables.tf` and `outputs.tf` declare them; the walkthrough is [operations.md › Method 3](operations.md#method-3-deploy-with-terraform), the short form [`terraform/README.md`](../terraform/README.md).

| Variable | Type | Default | Description |
|---|---|---|---|
| `project_id` | `string` | *required* | The project CloudGauge runs in. |
| `region` | `string` | `"asia-south1"` | Region of the services, the queue, the bucket and the export dataset. |
| `service_name` | `string` | `"cloudgauge"` | The web service (the pages, behind Identity-Aware Proxy). |
| `worker_service_name` | `string` | `""` | The worker service (Cloud Tasks only). Empty: <service_name>-worker. |
| `service_account_name` | `string` | `"cloudgauge-sa"` | Account ID of the service account both services run as; it also builds the image. |
| `bucket_name` | `string` | `""` | The results bucket. Empty: cloudgauge-reports-<project_id>. |
| `queue_name` | `string` | `"cloudgauge-scan-queue"` | The Cloud Tasks queue. A deleted queue's name cannot be reused for 3 days; pick a new one in that case. |
| `image` | `string` | `""` | Image repository, without a tag. Empty: gcr.io/<project_id>/<service_name>, what cloudbuild.yaml pushes to by default. |
| `image_tag` | `string` | `""` | Tag of the image to deploy (the short git hash cloudbuild.yaml was given). Empty: deploy nothing yet — only the foundation (APIs, account, roles, bucket, queue, dataset) is created, and the output build_command says how to build the image. |
| `operators` | `list(string)` | `[]` | Who may sign in, as IAM principals: user:alice@example.com, group:cloud-team@example.com, domain:example.com. |
| `extra_env` | `map(string)` | `{}` | More settings for both services (docs/stability.md › Configuration Reference), e.g. { GEMINI_MODEL = "gemini-2.5-flash", SCAN_SHARD_SIZE = "10" }. |
| `cost_allocation_labels` | `list(string)` | `[]` | The label keys every project must carry, e.g. ["cost-center", "environment", "owner"]. Empty: the Cost Allocation Labels check stays Informational. |
| `trusted_domains` | `list(string)` | `[]` | Domains besides the organization's primary one whose users and groups the External Principals check does not list, e.g. ["partner.example"]. Empty: the primary domain alone. |
| `bigquery_dataset` | `string` | `""` | Export every finished scan to this BigQuery dataset in the project (created in the region). Empty: no export. |
| `billing_export` | `string` | `""` | The BigQuery dataset the billing account exports to, <project>.<dataset> (v18.8): Spend Briefing and Spend Anomalies read its standard export tables. Empty: both stay Informational. |
| `spend_anomaly_floor` | `string` | `""` | The least a project's week on a service must cost, in the export's currency, to be a spend anomaly (v18.8). Empty: 50. |
| `schedules` | `map(object({ scope, scope_id, cron }))` | `{}` | Scheduled scans, by job name: { weekly-org = { scope = "organization", scope_id = "123456789012", cron = "30 0 * * 1" } }. Cron in UTC. |
| `organization_id` | `string` | `""` | Set it to grant the service account the organization-level scan roles and create the Advisory Notifications custom role there (needs an account that can grant roles on the organization). Empty: docs/operations.md › Common Prerequisites, step 2, stays the manual step. |
| `advisory_role_id` | `string` | `"CloudGaugeAdvisoryViewer"` | ID of the organization custom role that reads Advisory Notifications and their settings. If the role already exists (created by hand), import it or choose a new ID. |
| `programmatic_access_principals` | `list(string)` | `[]` | Principals allowed to mint tokens for the service account (roles/iam.serviceAccountTokenCreator on it); the account itself is let through IAP. What PROGRAMMATIC_ACCESS=1 does in tools/deploy.sh, for tools/iap_token.py. |
| `scan_max_concurrent_shards` | `number` | `25` | Shards Cloud Tasks runs at a time: the queue's max concurrent dispatches and SCAN_MAX_CONCURRENT_SHARDS on the services. |
| `task_max_attempts` | `number` | `3` | Attempts per task: the queue's max attempts and TASK_MAX_ATTEMPTS on the services. |
| `deletion_protection` | `bool` | `true` | Refuse to destroy the two Cloud Run services. Set it to false before a terraform destroy. |
| `force_destroy` | `bool` | `false` | Let terraform destroy delete the results bucket and the export dataset with everything in them. Keep it false on a deployment whose reports matter. |

| Output | Description |
|---|---|
| `web_url` | The pages, at Cloud Run's deterministic URL (the service also answers at its older <hash> URL). Sign in with an account listed in operators. |
| `worker_url` | The worker (internal ingress: only Cloud Tasks and Cloud Scheduler reach it). |
| `service_account_email` | The identity of both services, and of the image build. |
| `build_command` | Builds the image with Cloud Build as the service account (runs the test suite, pushes only if it passes). Run it from the repository root, then apply again with image_tag. |
| `next_step` | What to do now. |

## Roles and APIs

What [operations.md › Common Prerequisites](operations.md#common-prerequisites-required-for-all-methods) enables and grants — the names only; the commands are there, and `tools/deploy.sh` and Terraform run the project-level part. A check that needs a role or an API not on this list is a change to the stability surface.

**The 27 APIs enabled in the project CloudGauge runs in** (step 1): `run.googleapis.com`, `cloudbuild.googleapis.com`, `artifactregistry.googleapis.com`, `cloudtasks.googleapis.com`, `iap.googleapis.com`, `iam.googleapis.com`, `iamcredentials.googleapis.com`, `cloudresourcemanager.googleapis.com`, `storage.googleapis.com`, `logging.googleapis.com`, `aiplatform.googleapis.com`, `recommender.googleapis.com`, `securitycenter.googleapis.com`, `servicehealth.googleapis.com`, `advisorynotifications.googleapis.com`, `essentialcontacts.googleapis.com`, `compute.googleapis.com`, `container.googleapis.com`, `sqladmin.googleapis.com`, `osconfig.googleapis.com`, `monitoring.googleapis.com`, `cloudasset.googleapis.com`, `cloudscheduler.googleapis.com`, `bigquery.googleapis.com`, `accesscontextmanager.googleapis.com`, `securitycentermanagement.googleapis.com`, `cloudsupport.googleapis.com`.

**The organization-level roles of the service account** (step 2, 1 — all read-only; the one manual step, or Terraform's `organization_id`):

* `roles/browser`
* `roles/cloudasset.viewer`
* `roles/compute.networkViewer`
* `roles/essentialcontacts.viewer`
* `roles/recommender.iamViewer`
* `roles/logging.viewer`
* `roles/monitoring.viewer`
* `roles/orgpolicy.policyViewer`
* `roles/resourcemanager.organizationViewer`
* `roles/servicehealth.viewer`
* `roles/securitycenter.settingsViewer`
* `roles/iam.securityReviewer`

**The custom organization role** (step 2, 1b): `CloudGaugeAdvisoryViewer` — the permissions `advisorynotifications.notifications.list`, `advisorynotifications.notifications.get`, `advisorynotifications.settings.get`.

**The project-level roles of the service account**, in the project CloudGauge runs in (step 2, 2–2d): `roles/aiplatform.user`, `roles/cloudtasks.admin`, `roles/cloudbuild.builds.builder`; `roles/bigquery.jobUser` only with `BIGQUERY_DATASET` or `BILLING_EXPORT`, together with a dataset-level entry — WRITER on the export dataset, READER on the billing export dataset. On the service account itself: `roles/iam.serviceAccountUser` (step 2, 3). On the results bucket: `roles/storage.objectAdmin` (step 3). Method 2 adds `roles/run.admin`, because its trigger deploys the revision.

The deployment then binds `roles/run.invoker` for the service account on the worker service and for IAP's service agent on the web service, and `roles/iap.httpsResourceAccessor` on the web service for each operator ([operations.md › Method 1](operations.md#method-1-deploy-with-toolsdeploysh-recommended); [security.md › Who can use it](security.md#who-can-use-it)). Nothing on any billing account.

## BigQuery export schema

The two tables `BIGQUERY_DATASET` receives ([history-and-export.md › The BigQuery export](history-and-export.md#the-bigquery-export)):

| Table | One row per | Columns |
|---|---|---|
| `scans` | scan | `job_id`, `scope`, `scope_id`, `generated_at` (partition), `release`, `requested_by`, `total_projects`, `projects_scanned`, the four Overview counts (`action_count` …), the four scores (`security_score`, `cost_score`, `reliability_score`, `operations_score`; null when not assessed), `checks` (repeated: `check_name`, `category`, `status`, `rows`), `export_version` |
| `findings` | finding row of every check, plus one per organization policy | `job_id`, `scope`, `scope_id`, `generated_at` (partition), `release`, `category`, `check_name`, `status`, `project`, `identity` (the string the report compares scans by, so a finding can be followed across scans), `new_since_last_scan` (null when the scan compared nothing), `row_json` (the row as JSON: `JSON_VALUE(row_json, '$.Bucket')`) |

The fields as `app/services/bigquery_export.py` declares them. Both tables are partitioned by day on `generated_at`; the schema grows by addition only (`ALLOW_FIELD_ADDITION`).

`scans` (clustered by `scope_id`)

| Field | Type | Mode |
|---|---|---|
| `job_id` | STRING | REQUIRED |
| `scope` | STRING | REQUIRED |
| `scope_id` | STRING | REQUIRED |
| `generated_at` | TIMESTAMP | REQUIRED |
| `release` | STRING | NULLABLE |
| `requested_by` | STRING | NULLABLE |
| `total_projects` | INTEGER | NULLABLE |
| `projects_scanned` | INTEGER | NULLABLE |
| `action_count` | INTEGER | NULLABLE |
| `investigation_count` | INTEGER | NULLABLE |
| `compliant_count` | INTEGER | NULLABLE |
| `error_count` | INTEGER | NULLABLE |
| `security_score` | FLOAT | NULLABLE |
| `cost_score` | FLOAT | NULLABLE |
| `reliability_score` | FLOAT | NULLABLE |
| `operations_score` | FLOAT | NULLABLE |
| `checks` | RECORD | REPEATED |
| `checks.check_name` | STRING | NULLABLE |
| `checks.category` | STRING | NULLABLE |
| `checks.status` | STRING | NULLABLE |
| `checks.rows` | INTEGER | NULLABLE |
| `export_version` | INTEGER | NULLABLE |

`findings` (clustered by `scope_id`, `check_name`)

| Field | Type | Mode |
|---|---|---|
| `job_id` | STRING | REQUIRED |
| `scope` | STRING | REQUIRED |
| `scope_id` | STRING | REQUIRED |
| `generated_at` | TIMESTAMP | REQUIRED |
| `release` | STRING | NULLABLE |
| `category` | STRING | NULLABLE |
| `check_name` | STRING | NULLABLE |
| `status` | STRING | NULLABLE |
| `project` | STRING | NULLABLE |
| `identity` | STRING | NULLABLE |
| `new_since_last_scan` | BOOLEAN | NULLABLE |
| `row_json` | STRING | NULLABLE |

## CSV columns

The CSV report (`/report/<job_id>/<scope_id>/csv`, `app/reporting/csv_report.py`) is one file of sections:

* It opens with the **Organization Policies** section: a title row, the header row `Category, Policy, Expected Value, Current Value, Status` — plus `Below` when the scan found organization policy exceptions (v19.3) — and one row per constraint.
* Then one section per report category, in report order (`Security & Identity`, `Cost Optimization`, `Reliability & Resilience`, `Operational Excellence & Observability`): a blank spacer row, the category's title row, then every check of the category in the order the report page lists it — worst status first, then by name.
  * A check with structured findings writes a header row `Check, Status` followed by **the check's own columns, in the order the check wrote them**, then one row per finding and a blank row. When the scan was compared with a previous one, every structured row ends with `New since last scan` (`yes` or empty). A check that knows its fix carries it in a `Fix` column.
  * A check whose finding is plain text rather than rows (a compliant all-clear sentence, say) writes `Check, Status, Details`, with the details joined by `; `.

A check's columns are its own: under [the rule](#the-rule) a check's rows may gain columns but not lose them, and the leading `Check, Status` pair and the trailing `New since last scan` column stay where they are.

## Check names

The `Check` values a scan can write — the `Check` column of the CSV, `check_name` in the export, the name a report page shows — grouped by report category, from `app/checks/categories.py` (`CATEGORY_MAP`, in its order) and `app/checks/registry.py`. Four names are retired and kept only so that the *Changes since last scan* card can read the summaries older releases stored; eight are the registry's plan names, which the runner writes only as the Error record of a check that raised. Neither kind is counted in the headings.

**Security & Identity** (51 names)

* Critical Org-Level Roles
* Public Org-Level Access
* Organization IAM Policy
* Security Command Center Status
* Project IAM Hygiene
* Service Account Key Rotation
* Public GCS Buckets
* Open Firewall Rules
* Primitive Roles (Owner or Editor)
* Cloud SQL Security
* VPC Configuration
* GCS Uniform Bucket-Level Access
* VM External IPs
* GKE Credential Exposure
* GKE Control Plane Exposure
* GKE Node Hardening
* GKE Threat Detection
* Load Balancer Edge
* DNS Posture
* BigQuery Governance
* Cloud SQL Flags
* KMS Keys
* API Keys
* VM Service Accounts
* VM Hardening
* Service Account Privileges
* External Principals
* Unused Service Accounts
* Serverless Exposure
* Serverless Service Accounts
* Cloud Armor Policy Content
* Container Scanning Enabled
* Folder Primitive Roles
* Privileged Grants
* Secret Access Scope
* Secret Manager Posture
* Custom Roles With IAM Powers
* User-Managed Keys
* Service Account Impersonation
* VPC Service Controls Coverage
* SCC Active Findings
* SCC Detector Coverage
* OS Vulnerabilities
* Exposed Privileged VMs
* GKE Control Plane Activity
* Service Account Activity Signals
* Organization Policy Exceptions
* Organization Policies
* ~~Organization IAM Policy Check~~ — retired; kept so the Changes card can read the summaries older releases stored
* Advisory Notifications
* Advisory Notifications Settings
* IAM Least Privilege

**Cost Optimization** (23 names)

* Idle Cloud SQL Instances
* Low Utilization VMs
* VM Rightsizing
* Unassociated IPs
* ~~Idle Load Balancers~~ — retired; kept so the Changes card can read the summaries older releases stored
* Idle Persistent Disks
* Underutilized Reservations
* Idle Reservations
* MIG Rightsizing
* Resource-Based Commitment Recommendations
* Overprovisioned Cloud SQL Instances
* Cloud Run Cost
* BigQuery Slot Commitments
* Idle Images
* Cloud Storage Soft Delete
* Cost Allocation Labels
* Cloud Storage Lifecycle
* Snapshot Sprawl
* Commitments Expiring
* Spend Briefing
* Spend Anomalies
* Log Cost Levers
* Serverless Cost Hygiene
* Duplicate Log Routing
* Cost-Saving Recommendations *(the registry's plan name: written only when the whole check raises, as an Error record)*

**Reliability & Resilience** (25 names)

* Cloud Storage Versioning
* GKE Hygiene
* Essential Contacts
* Cloud SQL High Availability
* Cloud SQL Automated Backups
* Cloud SQL Backup Retention
* Cloud SQL PITR
* Cloud SQL Deletion Protection
* MIG Resilience (Zonal)
* Disk Snapshot Resilience
* GKE Cluster Resilience
* Incident Exposure
* Cloud SQL Extended Support
* Capacity Commitments
* Reservation Coverage
* Capacity Signals
* GKE Upgrade Readiness
* Hybrid Connectivity
* VPC Peering & Cloud NAT
* AlloyDB Posture
* SSL Certificate Health
* Synthetic and SLO Coverage
* GCS Bucket Versioning *(the registry's plan name: written only when the whole check raises, as an Error record)*
* Resilience of Critical Assets *(the registry's plan name: written only when the whole check raises, as an Error record)*
* Service Health Incidents
* Personalized Service Health API Coverage
* GKE Supported Versions

**Operational Excellence & Observability** (26 names)

* Organization Log Sink
* Data Access Audit Logs
* OS Config Agent Coverage
* Monitoring Alert Coverage
* Standalone VMs (Not in MIGs)
* VPC IP Address Utilization
* VPC Connectivity
* Load Balancer Health
* GKE IP Address Utilization
* GKE Connectivity
* GKE Service Account
* Dynamic Route Health
* Cloud SQL Connectivity
* Recent Changes (Org & Project)
* Unattended Projects
* Quota Utilization (>80%)
* Quota Increase Recommendations
* GKE Observability
* VPC Flow Logs
* Audit Log Pipeline
* Project Log Routing
* Alert Notification Channels
* Platform Footprint
* Support Cases
* Case Hygiene
* Bucket Logging
* ~~Log Sink Check~~ — retired; kept so the Changes card can read the summaries older releases stored
* ~~VPC Firewall Complexity (>150 Rules)~~ — retired; kept so the Changes card can read the summaries older releases stored
* Standalone VMs *(the registry's plan name: written only when the whole check raises, as an Error record)*
* Network Insights *(the registry's plan name: written only when the whole check raises, as an Error record)*
* Miscellaneous Checks *(the registry's plan name: written only when the whole check raises, as an Error record)*
* Service Quota Limits *(the registry's plan name: written only when the whole check raises, as an Error record)*
* Organization Audit Logging *(the registry's plan name: written only when the whole check raises, as an Error record)*

## HTTP routes

The 17 URL rules of the application (`tests/test_routes.py` pins them as `PINNED_URL_MAP`, methods included). The `worker.*` endpoints answer Cloud Tasks and Cloud Scheduler only ([security.md › Request hardening](security.md#request-hardening)); every other rule sits behind Identity-Aware Proxy in the recommended deployment.

| Rule | Methods | Endpoint | What |
|---|---|---|---|
| `/` | GET, HEAD, OPTIONS | `ui.index` | The setup page: the scope and resource picker, **Start scan**. |
| `/api/get-insights` | OPTIONS, POST | `api.get_insights` | The Cost Optimization page's detailed insights (the Recommender's insight types). Same-origin only. |
| `/api/get-suggestions` | OPTIONS, POST | `api.get_suggestions` | **Draft fixes** (Gemini), at most 20 findings per request. Same-origin only. |
| `/api/get-summary` | OPTIONS, POST | `api.get_summary` | The Scorecard's executive summary (Gemini over the CSV in the bucket). Same-origin only. |
| `/api/list-resources` | GET, HEAD, OPTIONS | `api.list_resources` | The active folders or projects of the organization, for the picker. |
| `/api/status/<string:job_id>/<string:scope_id>` | GET, HEAD, OPTIONS | `api.api_check_status` | The status JSON the status page polls. |
| `/history/<string:scope>/<string:scope_id>` | GET, HEAD, OPTIONS | `ui.view_history` | The history page: the scope's scans over time. |
| `/report/<string:job_id>/<string:scope_id>` | GET, HEAD, OPTIONS | `ui.view_report` | The HTML report, served from the results bucket. |
| `/report/<string:job_id>/<string:scope_id>/csv` | GET, HEAD, OPTIONS | `ui.download_report_csv` | The CSV report, every row, streamed from the bucket. |
| `/run-aggregation` | OPTIONS, POST | `worker.run_aggregation_worker` | Cloud Tasks: merges every shard's findings and builds the report. |
| `/run-scan` | OPTIONS, POST | `worker.run_scan_worker` | Cloud Tasks: runs a scan in one request, or dispatches the shards of a large one. |
| `/scan` | OPTIONS, POST | `ui.create_scan_task` | Starts a scan — creates the Cloud Task and redirects to the status page. Same-origin only; **409** while the scope's previous scan runs, **503** when Cloud Tasks will not take the task. |
| `/scan-shard` | OPTIONS, POST | `worker.scan_shard_worker` | Cloud Tasks: one shard of a sharded scan. |
| `/scheduled-scan` | OPTIONS, POST | `worker.scheduled_scan` | Cloud Scheduler: starts a scan as the service account (*Requested by* `schedule: <name>`). |
| `/static/<path:filename>` | GET, HEAD, OPTIONS | `static` | Flask's default static route; the application ships no static files (every page inlines its CSS). |
| `/status/<string:job_id>/<string:scope>/<string:scope_id>` | GET, HEAD, OPTIONS | `ui.get_status` | The status page of a scan. |
| `/sweep` | OPTIONS, POST | `worker.sweep_worker` | Cloud Tasks: finishes a sharded job whose shards died. |

## The rule

These are the things a deployment, a dashboard or a script may depend on. The convention from v20.0.0: removing or renaming any of them is announced in the release notes at least one minor release before it happens and ships only in a major release; additions and new optional variables are free, and a check's rows may gain columns but not lose them. Anything not listed here — HTML structure, log lines, the status file's wording, internal module paths — may change in any release. This is a versioning convention the maintainers follow, not a support commitment: CloudGauge is a free, open-source project and not an officially supported Google product (see the note at the top of the README); there is no service level, and the release notes are the only notice.
