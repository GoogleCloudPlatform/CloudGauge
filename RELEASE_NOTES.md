# CloudGauge Release Notes

Release notes for the `refactor/modular-factory` line of CloudGauge: the modular
rewrite of the original single-file application, the sharded scan architecture
that lets it cover organizations of any size, the report built for that scale,
and the checks added since. Each version was rolled out the same way: build with
the test suite running inside the image, a zero-traffic canary revision scanned
against a real organization, promotion, and a production scan compared fact for
fact with the previous version's report.

Versions are the image tags (`v5` … `v14`); the commit is the one that shipped.

---

## v14 — Service Health incidents, Advisory Notifications, Essential Contacts fix

### New: two briefings and the two checks behind them

CloudGauge now shows what Google has been telling the customer, next to what the
scan found. These two items are **briefings**: always *Informational*, never
counted as compliant or non-compliant, and never a factor in a category's score.
What *is* scored is whether the customer can receive those messages at all.

| Item | Category | Status | What it shows |
|---|---|---|---|
| **Service Health Incidents** | Reliability & Resilience | Informational | The Google Cloud incidents (from Personalized Service Health) that were *Impacted* or *Related* to the scanned projects in the last 90 days, active and resolved. One row per incident — `State`, `Started`, `Ended`, `Incident`, `Products`, `Locations`, `Impacted projects`, `Project IDs`, `Relevance`, `Incident ID` — naming every project it touched; active incidents first, then newest first. |
| **Personalized Service Health API Coverage** | Reliability & Resilience | Action Required / Compliant | Every scanned project in which `servicehealth.googleapis.com` is not enabled, with the `gcloud services enable` fix. Such a project has no personalized incident view, alerts or relevance. |
| **Advisory Notifications** | Security & Identity | Informational | Google's Mandatory Service Announcements, Security & Privacy Advisories, Threat Horizons reports and sensitive-action digests from the last 365 days, in one table with a `Type` column: `Date`, `Type`, `Subject`, `Summary`, `Details` (affected resources from the notification's attachments; for digests, the actions and the actors — "Organization policy updated (x4) · by admin@…"). Read once from the organization in an organization scan, per project (with a `Projects` column) in a folder or project scan. |
| **Advisory Notifications Settings** | Security & Identity | Action Required / Compliant / Error | A scope in which a notification type is turned off (`Type`, `Issue`, `Fix`), or an *Error* naming the missing API or permission when the scanner cannot read the notifications or the settings. |

Design points:

- **Relevance is computed per project.** Personalized Service Health only
  computes relevance at the project level (organization-level events show
  every incident, relevant or not), so the briefing reads each scanned
  project's events and folds them into one row per incident. The API rejects a
  server-side relevance filter, so relevance is filtered client-side after a
  time-window filter. Defaults: `IMPACTED` and `RELATED`, 90 days
  (`SERVICE_HEALTH_RELEVANCE`, `SERVICE_HEALTH_WINDOW_DAYS`).
- **One row per incident or notification, never one per project.** The same
  incident seen from 400 projects is one row saying "400 projects" and listing
  them, so the report stays readable at enterprise scale; the row folds across
  the shards of a sharded scan too (projects, products, locations, highest
  relevance, "active if any part was active").
- **Scanner-side problems are reported once, not per project.** If the Service
  Health or Advisory Notifications API is disabled in the project CloudGauge
  runs in, or the service account lacks the Advisory Notifications permissions,
  both items of that pair say so as a single *Error* with the exact
  `gcloud services enable …` command or the permission to grant, instead of
  listing every project as "not checked".
- The organization-level "Personalized Service Health" probe (an HTTP GET to see
  whether the API answered) is **retired**; the per-project coverage check
  replaces it with something actionable.

### Fixed

- **Essential Contacts** looked only at the *first* category of each contact and
  ignored the `ALL` subscription, so an organization whose one contact was
  subscribed to `[TECHNICAL, SECURITY, LEGAL]` (or to `ALL`) was reported as
  missing categories. Every subscription of every contact now counts, `ALL`
  covers everything, and `SUSPENSION` is required alongside `SECURITY`,
  `TECHNICAL` and `LEGAL`. The finding names the missing categories and the
  `gcloud essential-contacts create` fix.

### Upgrade notes

1. **Enable the API** in the CloudGauge project:
   `gcloud services enable advisorynotifications.googleapis.com`
   (`servicehealth.googleapis.com` was already required).
2. **Grant the custom role.** No predefined read-only role can read the
   Advisory Notifications *settings*, so the README's prerequisites now create
   a custom organization role, `CloudGaugeAdvisoryViewer`
   (`advisorynotifications.notifications.list`, `.notifications.get`,
   `.settings.get`), and bind it to the service account. Without it the
   Advisory Notifications items report an *Error* that says exactly this; the
   rest of the scan is unaffected. The cleanup script removes the role.
3. New optional settings: `SERVICE_HEALTH_WINDOW_DAYS` (90),
   `SERVICE_HEALTH_RELEVANCE` (`IMPACTED,RELATED`), `ADVISORY_WINDOW_DAYS` (365).
4. Project lists now carry `projectNumber` (the Advisory Notifications API
   addresses projects by number).

Tests: 436 (new `tests/test_service_health.py`, `tests/test_advisories.py`,
`tests/test_essential_contacts.py`; the synthetic organization simulates both
APIs, including disabled-API and denied projects).

---

## v13 — "Projects not checked" instead of silent passes

A per-project check skips a project whose API call fails (missing role,
disabled API, quota, transient 5xx) rather than stop the scan. Until v13 that
skip was invisible: the check still came out *Compliant*, and an empty category
even said "all checks were compliant" (user question that triggered it: *"If any
check failed due to error, are we still saying the result is compliant?"*).

- Every per-project check collects its skips in `NotChecked`
  (`app/checks/not_checked.py`) and writes one **Projects not checked** record
  (status *Error*, in the check's own category). Each category page shows at
  most one such item: a `Project | Skipped check | Reason` table, filterable by
  project ID, summarized as "N skipped checks across M of T projects"; the CSV
  has the same rows.
- Not reported, to keep the table meaningful: a project in which the API that
  *owns* the resources is disabled (no Compute Engine API → no VMs or firewall
  rules to check) and errors about the request itself (an invalid argument, a
  recommender not offered in a location). A disabled *analysis* API
  (Recommender, Monitoring) is reported: the project may well have the resources.
- Two mechanical gaps closed on the way: `call_api_with_backoff` swallowed every
  non-429 error (the cost and network checks' permission-denied branches were
  dead code) — it now takes an `on_error` callback; and location discovery runs
  per shard, so a shard of unreadable projects found no zones or regions and the
  cost check queried nothing and reported nothing — discovery failures now flow
  to the two location-based checks ("all 8 recommenders: no zones or regions
  were discovered to query" / "queried only in zones and regions found in other
  projects").

## v12 — Every category has a page

A category with no check rows (Cost Optimization on a small organization) used
to have a sidebar link and a 100% score but no page body. Every category now
gets a page; one with nothing to list says "No findings in this category — all
Cost Optimization checks were compliant", and a page whose checks are all hidden
by the filter says so and how many matching checks are on other pages.

## v11 — Filter box only where there is something to filter

The row filter and its status line are hidden on the Overview (which has no
findings) and shown on the category pages; the toolbar keeps the CSV link
everywhere.

## v10 — Job time limit sized from the scan

A sharded job's time limit is no longer a fixed 6 hours:
`max(6 h, 2 × ceil(shards / SCAN_MAX_CONCURRENT_SHARDS) × TASK_DISPATCH_DEADLINE_SECONDS)`,
so a large organization is never cut off while its shards are still queued
(`SCAN_TIME_LIMIT_SECONDS` caps it explicitly). The README gained a "Sizing for
your organization" section. Synthetic sizing runs: 1k, 5k, 10k and 50k projects
all at 100% coverage with no retries; 50k projects = 2,501 shards, aggregation
in 3.7 s, a 6.1 MB HTML report (bounded by the row cap) and a 57 MB CSV.

## v9 — Speak of projects, not shards

Everything a user reads — status page, coverage line, error rows — speaks of
projects and organization-level checks; "shard" is an implementation word that
appears only in code and logs. The report's coverage line reads, for example,
`3 of 3 projects scanned (100%) · organization-level checks: completed`.

## v8 — A report built for large organizations

A 1,000-project report can hold tens of thousands of rows. The HTML report keeps
one page per category (no grouping by project, which would make hundreds of
groups) and makes that page usable at scale:

- **Worst first**: checks ordered Action Required → Investigation Recommended →
  Error → Informational → Compliant, with a count strip per category.
- **A summary line per check**: "1,204 findings across 312 of 1,000 projects (31%)".
- **Paged, sortable, filterable tables**: 50 rows at a time, any column sorts,
  one filter box per page matching project IDs, bucket names or any text. All
  inline vanilla JavaScript; the report stays a single self-contained file.
- **Bounded page size and prompts**: at most 2,000 rows per table in the page
  (the CSV always has every row and is downloadable at any time from
  `/report/<job>/<scope>/csv`); the Gemini summary and remediation prompts read
  a bounded number of rows per check.

## v7 — Sharded scans: fan-out with automatic fan-in

The scan of an organization with thousands of projects no longer has to fit in
one Cloud Run request. The user flow is unchanged (submit, status page, report).

- **Dispatcher.** `/run-scan` lists the projects in scope; up to
  `SCAN_SHARD_SIZE` (20) it runs the whole scan inline as before. Beyond that it
  writes a job *manifest*, enqueues one `/scan-shard` task per shard of projects
  plus one **scope shard** for the checks that look at the organization itself
  (Organization Policies, org IAM, SCC, audit logging, Essential Contacts, …),
  schedules a sweeper, and returns within seconds.
- **Bounded, retried work.** Each shard runs the project-level checks for its
  projects under a time budget (`SHARD_TIME_BUDGET_SECONDS`); Cloud Tasks runs up
  to `SCAN_MAX_CONCURRENT_SHARDS` at a time and retries a failed shard; a shard
  that fails on its last attempt records its checks as error rows, so one bad
  shard never costs the whole report.
- **Fan-in without a database.** A finished shard writes a marker; the shard
  that sees a marker for every shard enqueues `/run-aggregation` under a
  deterministic task name, so two shards finishing together cannot aggregate
  twice. The `/sweep` task is the safety net: it gives vanished shards error rows
  and finishes the job, so a scan always terminates.
- **Aggregation** merges the shards' findings into the same report an inline
  scan produces (one item per check, a coverage line), builds HTML and CSV,
  uploads them, and deletes the intermediate files (in parallel).
- **Synthetic load mode** (`CLOUDGAUGE_ENV=synthetic`, `tools/synthetic_scan.py`):
  the whole pipeline against a generated organization of any size, with
  configurable latency, error rate and denied projects, without touching Google
  Cloud. Used for every sizing claim above.

New settings: `SCAN_SHARD_SIZE`, `SCAN_MAX_CONCURRENT_SHARDS`,
`SHARD_TIME_BUDGET_SECONDS`, `TASK_DISPATCH_DEADLINE_SECONDS`,
`SWEEP_INTERVAL_SECONDS`, `SCAN_TIME_LIMIT_SECONDS`, `TASK_MAX_ATTEMPTS`,
`SYNTHETIC_*`. The Cloud Run request timeout must be at least the task dispatch
deadline (the instructions use 3600 s).

## v5 — The modular application (foundation of this line)

- **App factory.** The single `cloudgauge.py` became a Flask package built by
  `create_app()`: `app/routes` (UI, API, worker blueprints), `app/checks` (one
  module per pillar, a registry that defines the check plan and a runner that
  executes it concurrently with progress reporting), `app/services` (GCP
  clients, Cloud Tasks, the GCS results store, Gemini, org policies),
  `app/reporting` (HTML and CSV), `app/config.py` (settings read once from the
  environment, with `production` / `development` / `testing` profiles and
  startup checks). `cloudgauge.py` stays as a thin entrypoint, so the container
  command is unchanged; `run.py` is a local dev server.
- **Checks unchanged in substance.** The plan, order and arguments of every
  check match the previous release line for line, and a parity suite proves the
  new report states the same facts as the old one (same overview counts, scores
  and items).
- **Gemini via the `google-genai` SDK** with automatic model selection
  (`GEMINI_MODEL=auto` picks the newest stable Flash model available to the
  project, so the summary keeps working when a model is retired).
- **Build and test.** Pinned production requirements (dev tools separate), a
  non-root Dockerfile that copies only what runs, a `cloudbuild.yaml` that
  builds, runs the suite inside the image and pushes only on success, and a
  test suite (289 tests at v5, 436 at v14) with GCP faked behind one seam.
- **Canary-safe.** `WORKER_AUDIENCE` lets a zero-traffic canary revision run its
  own scans (Cloud Run rejects OIDC tokens whose audience is a tag URL).
- **Fixed B1/B2.** The Security Command Center result was written under one
  name and mapped under another, so it never reached the report; a check's own
  error records were written under unmapped names and dropped. Both fixed, and
  `tests/test_category_consistency.py` reads the check modules' source so an
  unmapped name fails the build.

---

## Roadmap

Driven by the Quarterly Technical Review agenda (executive stoplight summary;
operational excellence — incident retrospective and security posture; product
performance; modernization; enablement; roadmap and roadblocks).

| Release | Theme | Contents |
|---|---|---|
| **v15** | The QTR brief | A scan index per scope and a **"Changes since last scan"** view (new, fixed and persisting findings); a **QTR brief page** (stoplight scorecard per pillar, top actions, action-plan export); **GKE end-of-support** rows (cluster and node-pool versions against the release schedule). |
| **v16** | History and analytics | **BigQuery export** of every scan's findings; **scheduled scans**; a history page (scores over time); a guide for Gemini Enterprise / Looker over the export ("talk to your infrastructure"). |
| **v17** | Footprint and support | A **Platform Footprint** page (what runs where: services, regions, versions); **modernization indicators** (legacy runtimes, unmanaged VMs, missing release channels); a **Support cases** briefing. |
| Later | | VM Manager vulnerability summary, Security Command Center findings summary, SLO coverage, PDF export. |

Not in scope of the core QTR brief: financial governance beyond the existing
cost checks.
