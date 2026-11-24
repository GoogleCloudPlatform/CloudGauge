# CloudGauge Release Notes

Release notes for the `refactor/modular-factory` line of CloudGauge: the modular
rewrite of the original single-file application, the sharded scan architecture
that lets it cover organizations of any size, the report built for that scale,
and the checks added since. Each version was rolled out the same way: build with
the test suite running inside the image, a zero-traffic canary revision scanned
against a real organization, promotion, and a production scan compared fact for
fact with the previous version's report.

Versions are the image tags (`v5` … `v20.0.0`); the commit is the one that shipped. From v20 the
versions are also git tags, and a tag publishes the GitHub Release (docs/development.md › Cut a release).

## v20.0.0 — General availability

The release that moves the modular CloudGauge onto `main`: the application that
has been the shipped one since v5 replaces the 2025 single-file original as the
repository's default branch. Two release candidates went before it — `rc.1`
(19 November, the cutover itself) and `rc.2` (20 November, with the
Organization Policy Exceptions note naming its policies) — and the candidate
ran unattended on the daily scheduled scans of a real organization and a
sandbox project for five days, ten scheduled scans and four end-to-end scans
without an Error record, before this tag. No new check — the check plan is the
v19.3 plan, pinned by the tests at 77 functions for an organization and 74 for
a folder or a project — no new role, no new API. What changed is around the
application: how a scan that Cloud Tasks will not take is reported, how the
report prints, how the history page reaches a report, how the repository is
built, tested, released and documented, what a deployer may rely on, and what
the sharded scan was measured to do at 500 and 1,000 projects.

### Added

- **Scan not queued (503).** Every `create_task` retries a transient Cloud
  Tasks answer — `UNAVAILABLE` (a `Stream removed` reached a person as a 500
  once), `DEADLINE_EXCEEDED`, `INTERNAL` — with exponential backoff for up to
  30 seconds; the scan task is named `scan-<job id>`, so the retry after a lost
  answer meets *already exists* and never starts a scan twice. What still fails
  is a 503 page in the 409 page's shape — the queue, the answer, a **Try again**
  button, `Retry-After: 60`, JSON for a client that asks — and nothing is
  started or noted. `/scheduled-scan` answers the same 503; the job records a
  failed run and its next scheduled run is the next attempt (the deployments
  create the jobs without retries).
- **Print or save as PDF** on the report header: the whole report through the
  browser's print dialog — the Scorecard first, then the Overview and each
  category on its own sheet, every accordion open with its title kept with its
  first rows, rows never split, a table's header row repeated when it breaks.
  The Scorecard's own **Print** keeps printing that page alone. A 12-project
  synthetic report prints on 79 sheets.
- **Every scan on the history page opens its report**: the scan's date is the
  link, a **Report · CSV** column sits before the wide *Changes* column, each
  dot of the chart opens the scan it stands for, and **Open latest report** is
  in the page head. The link was there since v17 — as the last of eight
  columns behind a horizontal scrollbar; the page is 1,200 px wide now and all
  eight fit a laptop.
- **CI** (`.github/workflows/ci.yml`): the lint and the suite on Python 3.11
  (the image) and 3.13, `terraform fmt`/`init`/`validate`, the application and
  test images built with the suite run inside and the container served, on
  every pull request and push — the four jobs are the required status checks
  of `main`. **Release** (`.github/workflows/release.yml`): a tag `vX` on a
  merged commit of `main` publishes the GitHub Release with that version's
  section of these notes as the body (`tools/release_notes.py`), a pre-release
  when the tag carries a suffix. `SECURITY.md`, Dependabot, CODEOWNERS, issue
  and pull-request templates, the rulesets of `main` and of the `v*` tags as
  files under `.github/rulesets/`.
- **`VERSION`**: the release number lives in one file at the repository root;
  `app/config.py` reads it, the image copies it, `terraform/versions.tf`
  carries the same number (a `provider_meta` block takes constants only) and
  the tests hold the two to the newest section of these notes.
- **`docs/`**: the README is a 100-line landing page; the depth moved,
  verbatim, into eight pages — the catalogue, the architecture, the operations
  guide, security, history and export, development, the roadmap, and
  **`docs/stability.md`**: the stability surface (configuration, Terraform
  variables and outputs, roles and APIs, the export schema, the CSV columns,
  every check name, the routes) and the rule a release follows from v20.0.0 —
  removing or renaming any of them is announced a minor release ahead and
  ships only in a major; additions are free.

### Changed

- **rc.2** (20 Nov, after a day of rc.1 on the scheduled scans): the *Organization Policy Exceptions*
  note about the policies set below that weaken no guardrail names them — the constraint (or how
  many), the resource (or how many), *set — weakens nothing*, each policy on its resource in the
  Detail — where rc.1 showed an empty constraint and a bare count, which read like a finding with a
  hole in it; the Organization Policies table's Below column leaves the note out.
- **The documentation was scrubbed claim by claim against the code** (~515
  claims, 45 corrected): the Troubleshooting entries name the worker
  (`cloudgauge-worker`, 2 GiB; `SCAN_SHARD_SIZE` is the lever that survives a
  redeploy) instead of a service that never existed in this line; the VPC-SC
  build recipe builds through `cloudbuild.yaml`; the prerequisites create the
  bucket with `gcloud storage`; the load-test example sets `WORKER_URL`; the
  public-deployment snippet sets it before the start that needs it; Method 3's
  build command runs through `eval` from the repository root; 27 APIs; Python
  3.11 or 3.13. **The cleanup script undoes the v20 deployment** — scheduled
  scans, both services, the queue, the bucket, the export dataset as an opt-in
  step, every image, the twelve organization roles and the custom one, all four
  project roles, the account — and a test holds it to `tools/deploy.sh`.
- The Advisory Notifications row that pointed at "the README" points at
  `docs/operations.md › Common Prerequisites`; the Terraform outputs and the
  deploy script's notes point at the pages that hold their sections.

### Removed

- **`tests/legacy/`** — the frozen pre-refactor application and its beta branch
  (7,000 lines) and the fixtures built on them. Of the 48 tests that compared
  the two applications, the ones that encode a contract now state it: the HTTP
  contract of the web routes (`tests/test_api_contract.py`), the pinned URL
  map, view resolution and `url_for`, the production startup, the worker's
  writes, and the pinned check plan. A guard test forbids a reference to the
  frozen modules from growing back.

### Fixed

- **`tools/deploy.sh` updates an existing scheduled scan.** The second run of a
  deployment with `SCHEDULES` — the documented upgrade, the same command again —
  stopped at step 7 with `unrecognized arguments: --headers`: `gcloud scheduler
  jobs update http` spells that flag `--update-headers`, and the script used
  the `create` spelling for both verbs. Present since the schedules of v17; met
  on the second deployment that carried `SCHEDULES`. The services were already
  deployed when it stopped, so nothing was half-done — the jobs simply kept
  their earlier definition. Fixed after rc.2 was cut; a test holds the verb
  and the flag together.

### Verified at scale

- **500 and 1,000 synthetic projects through the deployed sharded path** (the
  release image as a separate Cloud Run service with the worker's settings, a
  Cloud Tasks queue at 25 concurrent dispatches, 150 ms simulated latency, 2% of
  projects denying every API): **500 projects in 11 min 11 s** (26 tasks in two
  waves, project shards 5.0–5.8 min, the scope shard 8.2 min, merge 18 s) and
  **1,000 projects in 17 min 30 s** (51 tasks in three waves, the scope shard
  16.7 min, merge 35 s); every project covered, no shard error, memory under
  17% of 2 GiB. One shard of the 1,000-project run was delivered twice by Cloud
  Tasks while its first attempt still ran; the second attempt cleaned up and
  rewrote the shard, and the report came out identical, row for row (57,451),
  to the in-process run of the same organization. The in-process harness at
  the same sizes: 178 API calls per project, at most ~385 in flight, the merge
  of 10,000 projects' shards in a minute. The reports are about ten times
  the size the first synthetic runs measured (22 MB HTML and 22 MB CSV for
  1,000 projects) — the v17–v19.3 checks — and the sizing table says so now,
  as it says that the scope shard, the one task that holds the
  organization-level checks, grows with the organization (8 minutes at 500
  projects, 17 at 1,000) and is the first thing to size past a couple of
  thousand projects.

### Tests

- 1,347 tests. New: the enqueue retry and the 503 (14), the release tooling and
  the workflows (14), the pinned check plan, URL map and startup, the print
  path, the history links, the cleanup script against the deploy script, the
  frozen-module guard. The synthetic quota test's intermittent failure is
  gone: a project named by number is the same project.

### Upgrade notes

Nothing to enable or grant. The scan task is named now, which changes nothing
a deployment can see. A deployment made from this tag runs the v19.3 checks;
the Changes card has nothing new to flag. The image tag is the git tag from
here on (`TAG=v20.0.0 tools/deploy.sh`, `?ref=v20.0.0` for Terraform) and the
short hash still works. A deployment that carries `SCHEDULES` upgrades with the
same command (the `--update-headers` fix above); one that runs the
pre-v18.1 image fetched its policy table from the `beta` branch, which this
release retires — upgrade it. The `beta` and `dev` branches are archived as
tags (`archive/beta`, `archive/dev`); every earlier release, `v17.0.0` to
`v19.3.0`, is a tag and a GitHub pre-release on its commit.

## v19.3 — Finish what the report points at

The last feature release before the GA cut: three themes that close gaps the
report itself named, no new role, no new API. The first is the one the owner
put his finger on — *Organization Policies* judges the policies as effective
at the scanned resource and could not see a folder or project that overrides a
guardrail; an organization scan said Compliant while our own organization has
`compute.requireOsLogin` enforced at the top and switched off on a folder. The
second is the SCC oracle's "—" column on the categories our organization
actually shows. The third finishes the Cloud SQL, AlloyDB and bucket facts the
report had left half-read.

What our own organization reads after it: **Organization Policy Exceptions —
Action Required**: OS Login enforced at the organization, off on folder
`1061012327179`, reaching its project; the Organization Policies row for OS
Login *Compliant — 1 exception below*. **Bucket Logging — Investigation**: no
bucket has usage logging and no Data Access logs are on for storage anywhere.
`aura-db` without deletion protection, a maintenance window or a password
policy. The oracle column no longer says "—" for bucket logging, GKE secrets
encryption or the threat-class findings.

### Added

- **Organization Policy Exceptions** (Security & Identity, every scope;
  scope-level): one `assets.list` of `orgpolicy.googleapis.com/Policy` under
  the scope — every policy set at the organization, the folders and the
  projects, each with its `ancestors` — and one of the folders and projects
  under it; the **effective policy of every container computed in memory**
  with Resource Manager's rules (boolean nearest-wins and `reset`; list
  `inheritFromParent` merge against replace, `allowAll`/`denyAll`; a rule with
  a tag condition for tagged resources only; managed and custom constraints by
  the same shapes). One row per policy set below the scanned resource that
  **weakens** a best-practice constraint it holds, attributed to the **nearest
  container that sets it** (a project that re-enforces a folder's exception is
  not reached by it): `Constraint, Set on, Above, Below, Reaches, Issue,
  Detail, Fix` (`gcloud org-policies delete … --folder|--project`, back to
  inheritance). Unconditional → **Action Required**; tag-conditional →
  *Investigation*; the rest — tightening, restating, out-of-table, the scanned
  resource's own gaps (counted once in its table), reaching no project — one
  Informational count line. A project scan: Informational, nothing below it.
  The verdict function is the report's own (`evaluate_org_policies`, with a
  parity test). **One check in the score whatever it lists**; the Organization
  Policies tally is unchanged. Policy Analyzer is not used (Premium-only,
  quota-bound — dropped by decision). No per-project call: thousands of
  projects are a few pages.
- The **Organization Policies** table gains a **Below** column — "*2
  exceptions (folders/…, projects/…)*" — shown (HTML and CSV) when the scan
  found any; its summary line and the Scorecard's sentence say how many
  guardrails have exceptions below.
- **Bucket Logging** (Operational Excellence & Observability, every scope;
  scope-level): per project with buckets — no usage logging **and** no Data
  Access logs (`DATA_READ`, `DATA_WRITE`) for `storage.googleapis.com` or
  `allServices` effective at the project (set on it, a folder or the
  organization — the IAM policies read as one `IAM_POLICY` listing) →
  *Investigation*; usage logging off but Data Access logs on → Informational
  (SHA's `BUCKET_LOGGING_DISABLED` reads the legacy path alone); every bucket
  logged → no row. Rows `Project, Buckets, Usage logging, Data Access logs,
  Issue, Detail, Fix`.
- **Cloud SQL Deletion Protection** (Reliability, from Resilience of Critical
  Assets' listing): deletion protection off (*Investigation*: one `delete` or
  a Terraform destroy removes the instance and its backups), no maintenance
  window (Informational); replicas follow their primary.
- *Cloud SQL Security*: no instance-level **password policy** →
  *Investigation*; the **server CA certificate** expiring within 90 days →
  *Investigation*, within 30 → **Action Required** (create + rotate lines).
  *Cloud SQL Flags*: `cloudsql.iam_authentication` off → an Informational
  note (Google's recommendation, not CIS's). *AlloyDB Posture*: a public
  instance with `0.0.0.0/0` or `::/0` among its authorized external networks
  → **Action Required**. *Public GCS Buckets*: one Informational line per
  project counting the buckets that rely on IAM alone (Public Access
  Prevention enforced neither on the bucket nor by the organization policy).

### Changed

- The SCC oracle (`COVERAGE_MAP`): `CLUSTER_SECRETS_ENCRYPTION_DISABLED` →
  *GKE Node Hardening* (a mapping gap: the rule existed), `BUCKET_LOGGING_DISABLED`
  → *Bucket Logging*; THREAT-class findings read **"SCC (threat detection)"**
  instead of "—" — a detected event is SCC's own domain, not a gap of this
  report. `GEMINI_MODEL_NOT_PROTECTED_BY_MODEL_ARMOR` keeps its "—": Model
  Armor is a new API, a post-GA minor.
- The synthetic organization: the inventory answers the organization-policy
  listing (the same draws `listOrgPolicies` answers, in the v2 shape with
  ancestors — folders and projects override a constraint 30 % of the time),
  the Project and Folder assets with their ancestors, the buckets with usage
  logging derived from their existing draws, the IAM-policy listing with the
  audit configurations; the Cloud SQL assets carry deletion protection, the
  window, the password policy and a CA expiry derived from their existing
  draws (no new draw — nothing shifts).
- README: the two catalogue entries, a sentence on each finished record, the
  scope note, the project structure. `VERSION = "19.3"`; the Terraform module
  name carries it. The roadmap: v19.3 shipped; next, the GA work (v20).

### Tests

- `tests/test_org_policy_exceptions.py` (8): the v2 → v1 shapes, Resource
  Manager's merge rules, the verdicts' parity with the report's evaluator, the
  descriptions, the hierarchy (inactive containers out), the rows on a fixture
  hierarchy — a folder's exception reaching the project that did not restore it,
  a project's, a conditional one, the organization's own gap and an
  out-of-table policy counted, a folder scan's baseline, nothing below — the
  check end to end (organization, project, Error, all-clear), the Below
  column and the unchanged tally.
- `tests/test_finishers_v19_3.py` (9): the audit-configuration shapes, the
  two-fact rule per project, the check end to end (the organization's three
  listings, a folder's fourth, Compliant, Error), the oracle's new mappings
  and label, the Cloud SQL password-policy and CA rows around their
  thresholds, the IAM-authentication note, deletion protection and the window,
  the AlloyDB open network, the Public Access Prevention count line.
- `tests/test_worker.py`: 77 checks for an organization, 74 otherwise;
  `tests/test_synthetic.py`: 31 organization-wide listings and the IAM-policy
  listing; the Cloud SQL and flag fixtures carry a password policy and the
  IAM-authentication flag so the earlier expectations stay about what they
  tested. `tests/fakes.py`: `list_assets` honours the content type.
- 1,330 tests.

### Upgrade notes

Nothing to enable or grant. The Organization Policies table shows its Below
column from the first scan that finds an exception; the Changes card treats
the two new records as new checks until the scan after the upgrade.

## v19.2 — Support cases

The small release the roadmap promised, and a different one from the row it
replaced: the survey found that `roles/iam.securityReviewer` — on the
organization since v17 — already carries `cloudsupport.techCases.list`, and
that `cases.search` returns the full case objects. So: **no new role**, one API
enabled in the host project, and two records that are always present. The
owner's requirement shaped the second half — an upgraded deployment that has
not enabled the API, or one on a custom role set without the permission, must
lose nothing but these two records' content: both are written with their
normal columns, *Informational*, with the exact command that configures them;
never an Error, never a layout shift.

What our own organization reads after it: an honest zero — seven lines at 0
and *Case Hygiene* Informational, "nothing to judge". Our organization is on
Basic support, which has no cases; the tier is not readable through any API, so
the text says that an organization with no open case reads the same.

### Added

- **Support Cases** (Operational Excellence & Observability, every scope;
  scope-level; a briefing): one `cases.search` under the scope (`state=OPEN`,
  pages of 100, 500 at most — stated when hit) — the organization's search
  returns its own and its projects' cases, a project's its own, a folder scan
  searches the organization and keeps the folder's projects by number or ID
  (`scc.scope_projects`). Seven fixed lines, zero where nothing: **Open
  cases** (by priority; the oldest), **With Google Support** (`NEW`,
  `IN_PROGRESS_GOOGLE_SUPPORT`; the newest), **Waiting on you**
  (`ACTION_REQUIRED`, days since the last update), **Solution provided**,
  **Escalated**, **By project**, **By product** (the classification's root).
  Titles and metadata only — `description` is never read into the report.
  Every Fix the authenticated `curl` that reproduces the line (gcloud 593 has
  no `support cases` command). Rows `Line, Value, Detail, Fix`.
- **Case Hygiene** (Operational Excellence & Observability, from the same
  search): one row per open case that needs the customer — `ACTION_REQUIRED`
  with no update for more than **3 days** (*Investigation*), open beyond the
  expectation of its priority — **P0 1 / P1 7 / P2 30 / P3 60 / P4 90 days**
  (*Investigation*), `SOLUTION_PROVIDED` for more than **7 days**
  (Informational), escalated (Informational); worst issue first, every issue in
  the Detail. Cases with nothing flagged → **Compliant**. **No open case at
  all → Informational**, "nothing to judge" with the tier caveat: the score is
  never moved by Basic support or by a missing API. Rows `Case, Title,
  Priority, State, Project, Age, Issue, Detail, Fix`.
- **Graceful degradation** (both records, always): `testIamPermissions` on the
  scope *before* the search — without `cloudsupport.techCases.list` the API
  does not refuse, it answers `200 {}`, indistinguishable from "no case"
  (surveyed) — → Informational with the `add-iam-policy-binding` line
  (`roles/cloudsupport.techSupportViewer`, or `roles/iam.securityReviewer` as
  the README prescribes); the API not enabled in the host project (the
  surveyed `403` with `ErrorInfo.reason = SERVICE_DISABLED`) → Informational
  with `gcloud services enable cloudsupport.googleapis.com --project=…`; any
  other 4xx → Informational with the API's message and both commands; a
  failed probe never blocks the search; only a 5xx or a network failure after
  the client's retries is an Error — and the records still exist.

### Changed

- `cloudsupport.googleapis.com` joins the APIs `tools/deploy.sh`, the Terraform
  module and README › Common Prerequisites enable (27). No role.
- The synthetic organization draws a project's open support cases (drawn
  last: none for most, a few for some — waiting on the customer, escalated,
  long open); the provider answers `cases.search` for the organization and a
  project, paged, and `testIamPermissions` on every scope.
- README: the two catalogue entries, the scope note, the project structure,
  the prerequisites paragraph. `VERSION = "19.2"`; the Terraform module name
  carries it. The roadmap row rewritten: no new role, no opt-in flag.

### Tests

- `tests/test_support.py`: the facts (the API's shape, the organization's own
  case, never the description), the seven lines and their zero form and the
  cap, the hygiene ladder around every threshold, the rows worst first, paging
  and the cap, the permission probe and the error kinds, the check end to end
  (organization, project, folder filter), no-cases Informational, the
  degradation ladder with the surveyed error shapes (both records, their
  columns, their status), the score guarantee (Informational outside the
  score; one check when scored).
- `tests/test_worker.py`: 75 checks for an organization, 72 otherwise;
  `tests/test_terraform.py`: 27 APIs.
- 1,313 tests.

### Upgrade notes

Enable `cloudsupport.googleapis.com` in the host project (`tools/deploy.sh`
does when run without `SKIP_SETUP`; `terraform apply` does). Until then the two
records read *Informational* with that very command. No role to grant: the
organization's `roles/iam.securityReviewer` already carries the permission.

## v19.1 — Footprint and detection

The second half of the roadmap's v19 line, split off in the v19 plan. One
briefing and two detective records, no new API, no new organization-level
role: the Asset Inventory search under `roles/cloudasset.viewer` and the Admin
Activity audit logs under `roles/logging.viewer`, both of which the scanner
already holds. Until now the report judged *configuration*; these two records
read what was *done* in the last seven days — the half of the SSRF chain that
posture cannot see.

What our own organization reads after it: the footprint on one page — three
projects, 1,908 indexed assets of 113 types, 112 distinct APIs enabled, one GKE
cluster on 1.32 in the extended channel, one Cloud SQL instance on
PostgreSQL 15, seven Cloud Run services, six VMs — and two all-clears: every
control-plane write of the month and every IAM change of the week was Google's
own (`system:addon-manager`, the KTD agent, the organization's own IAM
automation). The sandbox probes confirm the rows exist when the actions do.

### Added

- **Platform Footprint** (Operational Excellence & Observability, every scope;
  scope-level; a briefing): one all-types `searchAllResources` under the scope
  (`read_mask` names, types, locations, projects — 1,908 assets in 2 s on the
  reference organization), one content search for the resources whose version
  matters (`versionedResources`: GKE clusters — version, channel, Autopilot or
  Standard, node count; Cloud SQL — engine and tier; VMs — machine family and
  state; AlloyDB, Spanner, Memorystore, Bigtable), and the enabled-service
  assets. The lines, in the Spend Briefing's shape (`Line, Value, Detail,
  Fix`): **Projects** (by ID), **Regions** (count and leading families per
  location), **Enabled APIs** (per project; on in every project; on in one
  project only), one line per product family (`FAMILIES`: Compute Engine, GKE,
  Cloud Run, Databases, Storage, BigQuery, data processing and messaging,
  Vertex AI, Networking, identity and secrets, registries and build,
  Operations — 14 families, about a hundred types; each counted by its own
  kind first — *7 services, 232 resources*, *6 VMs, 77 resources* with the
  VMs' states and machine families), one for the **Kubernetes objects** GKE
  indexes (every `*.k8s.io` type, by rule — 461 ClusterRoles, bindings,
  workloads and namespaces on the reference organization, which would
  otherwise have swamped *Other*) and **Other** for the rest, every Fix the
  `gcloud asset search-all-resources` that lists the line.
  *Informational*; the inventory search failing is an Error, the content and
  service searches failing cost the versions or the API line, not the briefing.
- **GKE Control Plane Activity** (Security & Identity, every scope; per
  project): one `entries.list` per project (`resourceNames` the project — the
  `k8s_cluster` audit log is a project's, and a read of the organization
  returns the organization's *own* entries only, which the sandbox probe
  proved: the first cut read the organization and saw nothing; ten projects
  read at a time, a failed read under *Projects not checked*), the Admin
  Activity log of the last 7 days, newest first, 2,000 entries per project at
  most (a capped read says so in every row):
  `pods.exec|attach|portforward.create|get` (SPDY is a POST, the WebSocket
  exec of kubectl ≥ 1.31 a GET — the sandbox probe's shape), `daemonsets.create` and
  `cronjobs.create` in `kube-system`, `clusterrolebindings.create|patch|update`
  to `cluster-admin`, `mutating|validatingwebhookconfigurations.create|update|
  patch`. Google's own principals are left out — `system:*` (except a workload's
  Kubernetes service account outside the GKE-managed namespaces, which is the
  very caller the exec rule is for), `*@gcp-sa-*`,
  `*@system.gserviceaccount.com`, the GKE robot, `cloudservices`; the default
  compute account stays, it is the customer's. Caller addresses are classed
  internal (`private`, `gce-internal-ip`, RFC 1918, shared address space,
  loopback, link-local, ULA — spelled out, not Python's `is_private`, whose
  meaning moved between releases) or external. Grouped by project, cluster,
  action, principal and address class; a user's exec *Informational*, a
  service account's *Investigation*, **Action Required** from outside;
  `cluster-admin` granted *Investigation* by a user, **Action Required** by a
  service account; `kube-system` workloads and webhook changes
  *Investigation*, **Action Required** by a service account from outside — an
  external address escalates service accounts only, people work from laptops
  (the plan had "or from outside" on the binding; the sandbox probe's admin,
  granting `cluster-admin` from a workstation, showed what that would flag). A
  refused call (a non-zero status — RBAC, IAM, an organization policy) counts
  and is said (*2 of them were denied*): an attempt is a signal. The
  all-clear says that secrets reads are Data Access logs and are not read.
  Rows `Project, Cluster, Action, Principal, From, Count, Latest, Issue,
  Detail, Fix` (`gcloud logging read … --project|--organization|--folder`,
  then the RBAC or the access to remove).
- **Service Account Activity Signals** (Security & Identity, every scope; a
  split check — the organization's or folder's own entries in the scope shard,
  an IAM change on the organization being written there, and every project's
  in the project shards): the same read for principals ending in `gserviceaccount.com`
  — `CreateServiceAccountKey`, `SetIamPolicy`, `setCommonInstanceMetadata`,
  `compute.instances.setMetadata`, `CreateServiceAccount` — Google's own
  excluded (on the reference organization the whole week's 43 entries were the
  organization's IAM automation). Keys, IAM changes and metadata writes
  *Investigation*, **Action Required** from an external address; service
  accounts created *Informational*; refused calls counted and said, as above
  (the sandbox probe's first key attempt, refused by
  `iam.disableServiceAccountKeyCreation`, reads *1 of them was denied*). The
  key's target is the account's email from the resource labels; an organization- or folder-level entry keeps its
  parent in the Project column and the fix line names it. The all-clear says
  that token minting is a Data Access log and is not read. Rows `Project,
  Principal, Action, Target, From, Count, Latest, Issue, Detail, Fix`.

### Changed

- The synthetic organization draws a detection profile (drawn last): a user's
  exec, a service account's exec from outside, a `cluster-admin` binding, a
  Google DaemonSet (which the rules must leave out), a service account key, a
  project factory's IAM change, the organization's own IAM churn. The provider
  answers `entries.list` for the two filters at every scope, the all-types and
  content searches (`versionedResources` for clusters, Cloud SQL instances and
  VMs) and the enabled services per project.
- README: the three catalogue entries, the scope note, the project structure.
  `VERSION = "19.1"`; the Terraform module name carries it. The roadmap: v19.1
  shipped; **v19.2 Support cases** added as a small release of its own (the
  first new organization-level role, by decision).

### Tests

- `tests/test_footprint.py`: the family map (no type in two families, every
  versioned type placed), the facts and the versions (dict and proto shapes,
  Autopilot, Redis, Spanner), the lines from a two-project fixture (projects by
  ID, regions, the APIs on everywhere and in one project only, the Compute
  Engine states and families, the GKE and Cloud SQL versions, Other), the
  empty scope and the counts-only briefing, the check end to end (three
  searches with their read masks; the inventory search failing → Error; the
  content and service searches failing → no versions, no API line).
- `tests/test_detection.py`: the filter texts, paging and the cap, Google's
  principals against the customer's and workload identities, the address
  classes, the judged shapes and the two ladders, the grouping with Google's
  churn left out, the cap note, both checks end to end (the scope's parent in
  `resourceNames`, the window from the pinned clock, the all-clear, the Error).
- `tests/test_worker.py`: the plan is 74 checks for an organization and 71
  otherwise; the three new names in their places, Platform Footprint in the
  scope-level list, the Service Account Activity Signals scope half beside the
  other split halves. `tests/test_fanout.py`: 35 project-level names.
- `tests/fakes.py`: a search without asset types returns every resource, as
  the API does.
- 1,303 tests.

### Upgrade notes

No new API, no new role: `tools/deploy.sh` and the Terraform module are
unchanged but for the version. The three records appear from the first scan
after the upgrade; the scan after that compares them.

## v19 — Findings and vulnerabilities

Theme H of the google/skills mining, the first release that reads **Security
Command Center** as a source rather than a tier flag. Until now the report said
whether SCC was activated; it said nothing about what SCC had found, whether SCC
looked at every project, which CVEs sit on the VMs, or which VM combines the
three facts a break-in needs. Four records, no new API, no new organization-level
role: SCC v2 findings, the Security Center Management services and VM Manager's
vulnerability reports answer under `roles/iam.securityReviewer`, the exposure
join reads the inventory and the IAM-policy search the report already makes.
The two SCC endpoints go through plain authorized REST, the way Service Health
does — the image's static discovery documents have no SCC v2, and the Security
Center Management API serves no discovery document at all.

What our own organization reads after it: Security Command Center covers **one
project in three** — the detector services are inherited-off at the organization
and switched on in `stark-argolis` alone — and in that one project SCC holds 51
active findings, among them a CRITICAL (a Gemini model without Model Armor),
three open GKE security bulletins and ten buckets without logging, none of which
the report said before. Findings leave SCC nowhere. VM Manager is not fully
enabled anywhere, so no CVE is known. No VM combines the three exposure legs.

### Added

- **SCC Active Findings** (Security & Identity, every scope; scope-level): the
  active, unmuted findings under the scope — `findings.list` at the
  organization or the project (`state="ACTIVE" AND mute!="MUTED"`); a folder
  scan reads the organization's and keeps the findings whose resource belongs
  to one of the folder's projects, by number or by ID (the folder parent is
  refused at the Standard tier with the legacy-disabled message; a project SCC
  does not serve directly falls back the same way). One row per class ×
  category × severity, the worst severity first: the count, the first three
  resources, the newest event time, SHA's explanation as the issue and its
  recommendation as the fix (plus the `gcloud scc findings list --filter` that
  lists them), and a **CloudGauge check** column — the record of this report
  that judges the same fact (`COVERAGE_MAP`, 134 categories), or "—" where the
  report has none: the oracle the sourcing plan asked for, inside the report.
  SCC's severity is the verdict: CRITICAL **Action Required**, HIGH and MEDIUM
  *Investigation*, LOW and the OBSERVATION class Informational, an `SCC_ERROR`
  finding *Investigation*. An organization scan adds a row when findings are
  exported nowhere (`notificationConfigs` and `bigQueryExports` both empty):
  Informational at the Standard tier (the v1beta2 subscription says which),
  *Investigation* at Premium or Enterprise. An organization SCC was never
  activated for is one Informational note (*Security Command Center Status*
  says what to do); a permission error is the scanner's and an Error. Capped at
  200 categories. **One check in the score** whatever it lists (D3, with a
  test): a fact failing here and in its own record costs the category two
  checks, never two plus the rows. Rows `Severity, Class, Category, Count,
  Resources, Latest, CloudGauge check, Issue, Detail, Fix`.
- **SCC Detector Coverage** (Security & Identity, per project): the *effective*
  enablement of each detector service at the project
  (`securityCenterServices.list` — the organization's own list says
  *inherited → disabled* for every service here while `stark-argolis` has five
  on; the project is the level that tells the truth). Security Health
  Analytics off → **Action Required** ("the project is never scanned"); Event,
  Container, VM and Cloud Run Threat Detection and Web Security Scanner off →
  *Investigation* where the project runs another threat detector (its
  Premium-tier services are on, this one was left off), Informational where it
  runs none ("needs the Premium or Enterprise tier") — judged per project, so a
  sharded scan reads exactly as a single one (the first cut judged against the
  whole scope, and the shard harness caught the difference). Module states
  counted, not judged (141 names
  here, most of them other clouds'). Rows `Project, Service, State, Issue,
  Detail, Fix` (`gcloud scc manage services update … --enablement-state=ENABLED`,
  effective once Security Command Center is activated at the project or the
  organization — the sandbox probe switched the intended state and the
  effective one stayed off, which the check reads). *Security Command Center
  Status* is unchanged beside it.
- **OS Vulnerabilities** (Security & Identity, per project): the zones with
  RUNNING VMs outside the managed fleets (from `instances.aggregatedList`),
  then VM Manager's `vulnerabilityReports.list` per zone; an instance with
  **critical CVEs that have a fix available** (`availableInventoryItemIds`)
  → **Action Required**, with **high** ones → *Investigation*, the three worst
  CVEs named with their CVSS, the fix an OS Config patch job on the instance;
  CVEs without a fix and MEDIUM and below counted in the Detail. A project where
  the API answers *vulnerability reports are disabled* → one Informational row
  (full VM Manager off: the CVEs on its N VMs are unknown), the other zones not
  asked. Rows `Project, Instance, Zone, Critical, High, Fixable, Issue, Detail,
  Fix`.
- **Exposed Privileged VMs** (Security & Identity, every scope; scope-level):
  one inventory listing of the scope's instances, VPC firewall rules and
  firewall policies, plus the project IAM policies from one search. A RUNNING
  instance outside the managed fleets with an **external address** (IPv4 NAT
  or external IPv6), a **privileged identity** (the default compute account
  with the `cloud-platform` scope; or any service account on it holding
  Owner, Editor, an `*.admin` or an `iam.*` role on the project) and an **open
  ingress rule that reaches it** (enabled, allow, `0.0.0.0/0` or `::/0` among
  the sources, in its network — a hierarchical policy applies to every
  network — targeting it by no target, a tag or a service account; a firewall
  policy rule in the shape of a VPC rule, as *Open Firewall Rules* reads them)
  → **Action Required**, the row naming the three facts, the fix removing the
  address (`delete-access-config`), the rule and the identity named as the
  alternatives. Two legs are not a row. The IAM search is made only when a
  running VM has an external address; failing, the default account alone
  counts, said under *Projects not checked*. Rows `Project, Instance, Zone,
  External IP, Identity, Open rule, Issue, Detail, Fix`.

### Changed

- The synthetic organization draws the findings profile (drawn last): a
  project's SCC findings in one of four shapes (misconfigurations of mixed
  severity; plus a CRITICAL vulnerability; threats; everything including an
  `SCC_ERROR` and an observation), muted ones the filter must leave out, the
  detector services inherited-off / Standard / Premium, full VM Manager on or
  off with CVE counts per VM. The provider answers the two REST endpoints
  (`http_get`: the organization's and a project's findings, a folder's 400,
  the services by profile, no exports), `vulnerabilityReports.list` (or the
  precondition error), and lists the firewall rules and the instances'
  interfaces in the inventory.
- README: the four catalogue entries, the scope note, the project structure.
  `VERSION = "19"`; the Terraform module name carries it. The roadmap: v19
  shipped; **v19.1 Footprint and detection** added with the survey's numbers;
  the *deprecations recommender* line removed (the Recommender catalogue —
  76 recommenders — has none); *Support cases* marked as needing a role.

### Tests

- `tests/test_scc.py`: the REST helpers (retries, pages, the cap, the
  not-activated reading); finding facts and rows (the ladder over every class
  and severity, muted and inactive left out, the resources and latest, the
  coverage column, the fixes, the cap); the export row by tier; service facts
  and the detector rows with and without Premium available; both checks end
  to end — the organization with pages and the export row, a project scan,
  the all-clear, the folder fallback, the project fallback, not activated, a
  permission error, the export reads failing, the search failing; the score
  guarantee (one check whatever the rows).
- `tests/test_vulnerabilities.py`: the running zones, report facts and rows
  (fixable critical and high, the worst CVEs, the patch-job fix), the
  precondition row and its reading; instance facts, the identity rule, the
  open rules (VPC and policy, disabled, egress, deny, tags, other networks,
  hierarchical), the reaching rule, the three-leg join; both checks end to end
  with the precondition, the Compute API disabled, a zone failing, the IAM
  search failing, no external VM, the inventory failing.
- `tests/test_worker.py`, `tests/test_fanout.py`, `tests/test_synthetic.py`:
  the plan (71 / 68), the scope-level list, the project shards (33), one more
  organization listing.
- 1,284 tests.

### Upgrade notes

- Nothing to do: redeploy as usual. The first scan after the upgrade shows the
  four records as *new check* on the Changes card; *Security Command Center
  Status* is unchanged. The `securitycenter`, `securitycentermanagement` and
  `osconfig` APIs must be enabled in the project CloudGauge runs in (they are
  in a deployment made by `tools/deploy.sh` or Terraform since v17.1 / v18);
  `tools/deploy.sh` and the Terraform configuration enable
  `securitycentermanagement.googleapis.com` from this release.

---

## v18.9 — Logging pipeline and alerting hygiene

The fourth themed release of the re-cut programme (theme C of the google/skills
mining): where the logs go, whether they arrive, what is stored twice, and
whether an alert reaches anybody. Until now the report said *an aggregated
audit sink exists* (CIS 2.2) and *this project has an alert policy about its
databases*; it said nothing about the sink exporting one audit type out of
four to a topic nobody can verify, the policy that fires to nobody, the
external load balancer nothing probes. Five records from reads the scanner's
roles already allow — the Logging API's sinks, exclusions, buckets and views,
the Monitoring API's policies, channels, uptime checks, services and SLOs, the
inventory and the IAM-policy search for the destinations, the topics and the
writers — fresh, so a fix shows on the next scan. No new API, no new
organization-level role.

What our own organization reads after it: the one aggregated sink exports
`activity` alone, to a Pub/Sub topic outside the organization; no project
keeps an audit trail beyond `_Required`'s 400 days; no alert policy, channel,
uptime check or SLO exists anywhere, while an external load balancer and four
public Cloud Run services run — nobody would be told.

### Added

- **Audit Log Pipeline** (Operational Excellence, every scope; scope-level):
  the scanned resource's own customer sinks — the organization's in an
  organization scan, a folder's or a project's otherwise; `_Required` and
  `_Default` left out, as *Organization Log Sink* leaves them. That check
  stays the CIS yes/no on whether an aggregated audit export exists; this one
  asks whether it is complete and durable. Per sink: a filter that names audit
  logs but admits only some of `activity`, `system_event`, `data_access`,
  `policy` (log-ID and `logName` forms, `%2F` and `/`; a generic
  `cloudaudit.googleapis.com` or `google.cloud.audit.AuditLog` match admits
  all four; a filter whose every audit mention is negated — the `_Default`
  shape — names none), or an enabled exclusion that drops audit entries, or a
  folder sink without `includeChildren` (*Investigation*); a **log-bucket
  destination** read from the API: not `ACTIVE` or gone (**Action Required**),
  kept **under 365 days** (*Investigation*), **unlocked** (Informational — a
  lock is irreversible, the row says so); a BigQuery dataset or Pub/Sub topic
  **absent from the scope's inventory** (**Action Required** — every exported
  entry is lost; a Cloud Storage bucket absent is Informational, its project
  not being in its name); the sink's **writer identity without the destination
  role** by the IAM-policy search — on the destination, its project by ID or
  number, or a folder or organization above (**Action Required**; a project's
  sink into a bucket of its own project needs no grant, and the pre-2019
  shared identity is never judged); **export errors** over the last seven days
  (`logging.googleapis.com/exports/error_count`, summed per sink — a project
  sink's in the project's Monitoring, an organization's or folder's tried in
  the project CloudGauge runs in and skipped quietly when the metric is not
  there) (**Action Required**); a destination **in a project outside the
  scanned scope** — our organization's own case — Informational, nothing else
  judged. A scope without a customer sink writes one Informational note (a
  folder or project: the organization's aggregated sink covers it, judged in an
  organization scan). Rows `Resource, Sink, Destination, Issue, Detail, Fix`
  (`gcloud logging sinks update … --log-filter=…`, `… buckets update …
  --retention-days=365`, `… --locked`, the `add-iam-policy-binding` per
  destination kind, `gcloud logging read` of the sink's error log).
- **Duplicate Log Routing** (Cost Optimization, every scope; scope-level): an
  **aggregated sink** of the organization or a folder in scope (`includeChildren`,
  enabled) into a **log bucket** whose filter admits what `_Default` stores,
  while projects below it keep their `_Default` sinks enabled (not disabled, no
  catch-all exclusion) — every entry stored twice, ingestion billed twice:
  *Investigation*, one row per aggregated sink counting the projects and naming
  the first five (the projects' `_Default` sinks are read only when such a
  sink exists; one that cannot be read counts as storing, and says so under
  *Projects not checked*); a customer sink into a log bucket whose filter
  admits the **`_Required` streams** (`activity`, `system_event`,
  `access_transparency` — kept 400 days in `_Required` at no charge):
  Informational, with the `AND NOT LOG_ID(…)` fix — a longer or locked
  archive stores them again on purpose. Sinks into BigQuery, Cloud Storage or
  Pub/Sub are not rows. Rows `Resource, Sink, Destination, Projects, Issue,
  Detail, Fix`.
- **Project Log Routing** (Operational Excellence, per project): the
  `_Default` sink **disabled or excluding everything** with no other enabled
  sink into a log bucket whose filter admits what `_Default` stores — an
  audit-only sink keeps the audit trail, not the project's logs (the sandbox
  probe: an activity-only sink beside a disabled `_Default`, and the logs were
  discarded all the same) — the project's logs are discarded as they arrive,
  the `_Required` streams excepted (**Action Required**, `--no-disabled` /
  `--clear-exclusions`); **Data Access audit logs effective** for the project
  (its own `auditConfigs` or the organization's — read once — for all services
  or for named ones) while the `_Default` view of the `_Default` bucket no
  longer excludes them, so every `roles/logging.viewer` reads who accessed
  what (Informational, with the view's filter as Logging creates it); the
  `_Default` bucket **without Log Analytics** (Informational — free and
  irreversible). The IAM policy or the views unreadable leaves the view rule
  out, noted. Rows `Project, Resource, Issue, Detail, Fix`.
- **Alert Notification Channels** (Operational Excellence, per project):
  *Monitoring Alert Coverage* says whether a project has alert policies; this
  record judges the ones it has. An enabled policy with **no notification
  channel** ("fires to nobody"), or whose channels are all **disabled**,
  **unverified** (`verificationStatus` `UNVERIFIED` — the API's one word for a
  channel that does not deliver; a channel of a type that needs no
  verification reports neither) or **gone** (*Investigation*); a **Pub/Sub
  channel** an enabled policy uses whose topic is **not in the inventory** of
  its project (**Action Required**) or on which the project's Monitoring
  notification agent (`service-<number>@gcp-sa-monitoring-notification.iam.gserviceaccount.com`)
  holds **no publisher role** by the IAM-policy search in the topic's project
  (*Investigation* — undeliverable); a policy with an **MQL condition**
  (Informational — deprecated in favour of PromQL; it keeps working). Channels
  are listed only in projects whose enabled policies name one; the topics and
  the grants once per topic project; a topic project the scanner cannot read is
  noted. Rows `Project, Policy, Channels, Issue, Detail, Fix`
  (`gcloud alpha monitoring policies update … --add-notification-channels`,
  `… channels update … --enabled`, `gcloud pubsub topics add-iam-policy-binding`
  for the agent).
- **Synthetic and SLO Coverage** (Reliability, every scope; scope-level with
  per-project reads): one listing of the scope's forwarding rules (regional
  and global), Cloud Run services and GKE clusters, then — in each project
  that runs one of them — the Monitoring API's uptime checks, services and
  their SLOs, and the alert policies where a check or an SLO needs them. An
  **external load balancer** (external or external-managed scheme; no scheme
  counts as external) with **no uptime check** targeting its address (a check
  on a hostname, which the scanner does not resolve, is taken as covering) —
  *Investigation*, with the `gcloud monitoring uptime create` line; an
  **uptime check with no enabled alert policy** naming its check ID in a
  `check_passed` condition, or watching every check (*Investigation*); an
  **SLO with no burn-rate alert** (no enabled policy with `select_slo_*` on
  its name) (*Investigation*); a project running any of the three with **no
  SLO** (Informational). Uptime checks and SLOs kept in a metrics scoping
  project are not seen (the *Monitoring Alert Coverage* caveat). Projects the
  inventory names by number are renamed by the project search. Rows
  `Project, Resource, Kind, Issue, Detail, Fix`.

### Changed

- The synthetic organization draws the observability facts (drawn last): a
  customer sink in one of four shapes (activity alone into a 30-day unlocked
  bucket; every audit log into the locked 400-day audit bucket; into a Pub/Sub
  topic its writer cannot publish to; into a dataset that is gone), a
  disabled `_Default` sink, Log Analytics, an open default view; channels of
  every state and which policies reach them, an MQL condition; an uptime check
  on the external load balancer and an SLO on the first Cloud Run service,
  each with or without its policy; the first folder has an aggregated sink of
  every log into a bucket of its first project. The provider fakes the folder
  sinks, `buckets.get`, the views, the notification channels, uptime checks,
  services and SLOs, the topics in the inventory and the IAM searches for the
  sink writers and the notification agent; the external forwarding rule now
  carries an address.
- README: the five catalogue entries, the scope note, the project structure.
  `VERSION = "18.9"`; the Terraform module name carries it.

### Tests

- `tests/test_log_pipeline.py`: the filter reading (log IDs, `logName` forms,
  the generic and `AuditLog` matches, negations, the `_Default` shape), the
  `_Required` and `_Default` stream rules, the exclusions; destination facts of
  every kind, the in-scope test by ID, number, folder and scope, the writer's
  grant per destination kind and by inherited folder, the export-error series;
  the pipeline rows (filter, exclusions, children, bucket retention and lock,
  errors; bucket gone, unreadable, inactive; outside the scope; dataset gone,
  topic with the grant, Cloud Storage bucket not in scope, project destination;
  the shared writer and the same-project bucket never judged); the duplicate
  rows over an organization and a folder sink with `_Default` sinks on, off and
  excluding everything; the `_Required` stream rows; the view filter; the
  project rows; the three checks end to end — the organization with every
  shape, a project scan, the no-sink notes, the listing failing, the search
  failing, the Monitoring read failing, the folder listing and the project's
  `_Default` failing, the IAM policy failing.
- `tests/test_alerting.py`: channel states and labels; the channel rows
  (nobody, dead ends, MQL, the topic gone and the agent without the grant,
  unknown facts, policies off); the topic and grant matching; the workload
  facts; uptime targets and matching by address, hostname and check ID; SLO
  matching; the synthetic rows and their all-clear; both checks end to end with
  the Monitoring, listing and search failures.
- `tests/test_worker.py`, `tests/test_fanout.py`, `tests/test_synthetic.py`:
  the plan (67 / 64), the scope-level list, the project shards (31), one more
  organization listing.
- 1,268 tests.

### Upgrade notes

- Nothing to do: redeploy as usual. The first scan after the upgrade shows the
  five records as *new check* on the Changes card; *Organization Log Sink* and
  *Monitoring Alert Coverage* are unchanged.

---

## v18.8.1 — API attribution

A point release with no check in it. CloudGauge now identifies itself on the
Google Cloud API calls a scan makes — a static token, `cloud-solutions/cloudgauge-v<release>`,
appended to the SDK user agent — so that aggregate adoption of the open-source
solution can be measured on Google's side from API usage alone, with nothing
added to what leaves a deployment: no finding, no resource configuration, no
organization metadata, no phone-home. The README says so in one place, and the
opt-out is one variable.

### Added

- **`app/services/user_agent.py`**: the identifier (`app.config.VERSION`
  behind the solution token: one release, not two) and one helper per SDK
  family — `client_info` for the `google-cloud-*` clients, `authorized_http`
  for the Discovery services (`discovery.build` takes `http` *or*
  `credentials`, never both: the credentials become an authorized `httplib2`
  transport with the agent set), `genai_http_options` for the Vertex AI client
  (under the lower-case `user-agent` key the `google-genai` SDK merges its own
  label into — an upper-case key would travel beside it), `request_headers`
  for the one plain `requests` call to a Google API (Service Health).
- **Every client the real provider builds carries it** (`app.services.gcp`):
  the eighteen Discovery APIs, both `storage.Client`s, Cloud Tasks, Asset
  Inventory, Recommender, OS Config, the Service Health REST call; and the
  Gemini client (`app.services.gemini`). The four gRPC clients get a
  transport whose channel carries the token as its primary user agent
  (`grpc_transport`): on a gRPC call `client_info` reaches the
  `x-goog-api-client` metadata only, and the `user-agent` the API front end
  records — the canary's audit logs showed `grpc-python/…` alone — is the
  channel's. Discovery, Storage, gRPC and `requests` calls send the token
  first; Vertex AI calls carry it after the SDK's label. The
  policy table's GitHub fetch (when configured) and the IAP / certificate /
  metadata fetches are not Google Cloud APIs and are left as they were. The
  synthetic provider calls no Google API and is unchanged.
- **`CLOUDGAUGE_DISABLE_ATTRIBUTION`** (`app.config`, read like
  `WORKER_TOKEN_CHECK`: `true`/`1`/`yes`/`on` turns the identifier off, any
  case; unset or `false` keeps it; anything else fails at startup). Set it
  through `EXTRA_ENV` (`tools/deploy.sh`) or `extra_env` (Terraform); no new
  script variable.
- **Terraform** carries the deploy-time counterpart: `provider_meta "google"
  { module_name = "cloud-solutions/cloudgauge-deploy-v18.8.1" }` in
  `versions.tf`, which the Google provider appends to its user agent while it
  creates the deployment; the test suite keeps its release equal to
  `app.config.VERSION`.
- README: **Privacy & API Attribution** (under *Deployment Instructions*), the
  Configuration Reference row, one clause in the Architecture introduction.
- **A public-repository guardrail** (`tests/test_packaging.py`): the suite
  fails if any tracked text file carries a Google-internal shortlink, hostname
  or analytics system name. It found one on its first run — a note in the
  bundled policy table (`iam.disableWorkloadIdentityClusterCreation`) pointed
  at an internal shortlink; the note now points at the public documentation,
  and the bundled table's digest is `922e3257c491` (138 rows, as before: the
  report's *Policy table* line shows the new digest, and no constraint,
  expectation or category changed).

### Changed

- `VERSION = "18.8.1"`; the identifier and the Terraform module name carry it.
- The bundled policy table's digest (above). No check, rule or row changed.

### Tests

- `tests/test_attribution.py`: the identifier's shape (a product token, the
  release inside, no space); the opt-out in every spelling and the startup
  error; the helpers on and off; the authorized transport setting the agent in
  front of the Discovery client's on every request; the gRPC transport factory
  (the channel's primary user agent, the client's own resolution kept); the real provider handing
  the identifier to every SDK (`http` without `credentials`, the other
  arguments passed through, `client_info` on the six clients, the header on
  the Google `requests` call and not on the GitHub one) and falling back
  cleanly when it is off; the Gemini client's options under the lower-case key.
- `tests/test_terraform.py`: the `provider_meta` module name and its release;
  `tests/test_packaging.py`: the guardrail; `tests/helpers.py`: the variable.
- 1,240 tests.

### Upgrade notes

- Nothing to do: redeploy as usual and the identifier is on. To keep it off,
  add `CLOUDGAUGE_DISABLE_ATTRIBUTION=true` to the services' variables.
- Verified on the canary by reading the audit logs' `callerSuppliedUserAgent`
  of the scan's own calls (Data Access logs turned on for the deployment
  project for the minutes of one scan, then off again): the token arrives as
  sent, and the report is unchanged fact for fact.

---

## v18.8 — Forecasts, budgets and spend

The FinOps release held since v17.4, with the configuration-level cost rows
the google/skills mining found riding along. Until now the report said what
could be saved and nothing about what is spent; the one reader of spend
Google Cloud offers without a billing-account role is the **billing export**
the account owner already keeps in BigQuery, and that is what this release
reads — a dataset-level grant, two partition-pruned queries per scan, cents a
month, nothing on any billing account (the 2026-10-23 decision stands). The
log, serverless and lifecycle levers come from reads the scanner's roles
already allow — the Logging, Compute, Monitoring, Cloud Run v2 and VPC
Access APIs, the inventory for the connectors — fresh, so a fix shows on the
next scan. No new API, no new organization-level role.

### Added

- **Spend Briefing** (Cost Optimization, every scope; a briefing —
  *Informational*, never scored, like *Capacity Commitments*): from the
  standard usage cost tables (`gcp_billing_export_v1_<account>`, discovered
  by prefix; several accounts summed and named) of
  `BILLING_EXPORT=<project>.<dataset>`: **month to date** against the same
  days last month, a **forecast** (month to date plus the mean of the last
  seven complete days over the days remaining), **last month** and the month
  before, the top ten **projects** and **services** of the last 30 days with
  share and change against the 30 before, the **credits** by type with the
  **committed-use coverage** of the commitment-eligible services (Compute
  Engine, GKE, Cloud SQL, Spanner, Cloud Run, Memorystore, AlloyDB, Bigtable,
  Dataflow; 0 % = nothing committed), and the export's **freshness** (hours
  behind, the tables read, the account-level charges without a project that
  an organization scan does not attribute). The scope is the scan's — an
  organization's or a folder's rows by `project.ancestry_numbers`, a
  project's by ID — so a project the export still bills after its deletion
  counts where it belonged. The complete days are the ones before today (UTC);
  on the first of a month the line says so and the forecast is the 7-day mean
  over the whole month. Rows `Line, Value, Detail, Fix` — every line's Fix is
  the exact `bq query` that reproduces it; the credits line's names
  Resource-Based Commitment Recommendations and the Capacity Planner. Unset:
  one *Informational* row saying how to configure it (the Cost Allocation
  Labels pattern). The dataset unreadable or without an export table: Error,
  the row naming the grant. The scan's queries run in the deployment project
  (`jobs.query`, the location following the tables; a long job is polled, pages
  followed).
- **Spend Anomalies** (Cost Optimization, every scope; the same function):
  a project's spend on a service over the last seven complete days at least
  **1.5 ×** the weekly mean of the three weeks before and at least the
  **floor** — `SPEND_ANOMALY_FLOOR` (50 in the export's currency) or 2 % of
  last month's net when that is higher — or **new spend** of at least the
  floor: *Investigation Recommended*, rows `Project, Service, This Week,
  Weekly Mean Before, Change, Issue, Detail, Fix` with the SKU breakdown of
  the pair as the fix. The rule runs in SQL (parameters, not interpolation):
  only the flagged pairs come back, two hundred at most. Drops are not rows.
  Not configured: the briefing's Informational row.
- **Log Cost Levers** (Cost Optimization, per project): a log bucket other
  than `_Required` **kept beyond the 30 days** included with ingestion
  (Informational — compliance may want the history; the row counts the paid
  days and says when the bucket is locked and cannot be shortened); a subnet
  with VPC flow logs **sampled above 0.5** (*Investigation*; all metadata and
  the 5-second interval named in the fix when set); **DEBUG entries at 10 %
  or more** of a project's 30-day log volume above the 50 GiB free tier with
  no enabled exclusion on the `_Default` sink (or any sink into the `_Default`
  bucket) that drops them (*Investigation*). Buckets and sinks from the
  Logging API, subnets from `subnetworks.aggregatedList`, the volume from
  Cloud Monitoring (`logging.googleapis.com/byte_count` summed by severity
  over 30 days). `_Required` streams, Data Access logs and the severities
  above DEBUG are never proposed for exclusion. Each failing read is its own
  line under *Projects not checked* (a project without the Compute Engine
  API has no subnets to read). Rows `Project, Resource, Issue, Detail, Fix`
  (`gcloud logging buckets update … --retention-days=30`; `gcloud compute
  networks subnets update … --logging-flow-sampling=0.5`; `gcloud logging
  sinks update _Default … --add-exclusion=…`).
- **Serverless Cost Hygiene** (Cost Optimization, every scope): a Cloud Run
  service, job or gen-2 function whose egress goes through a **Serverless
  VPC Access connector** (its instances bill around the clock; Direct VPC
  egress scales to zero — the fix moves it, naming the connector's network
  and subnet), a connector **no workload uses**, and a workload whose Cloud
  SQL instance is **in another region** — all *Investigation*. One listing of
  the scope's services, jobs, gen-2 functions and connectors (the connector's
  content from the search index, which names it by project *number* — mapped
  to IDs by the project search, as API keys and secrets are; the workloads' connector, Direct VPC
  interfaces and Cloud SQL instances read from every `annotations` mapping of
  the Knative copy or from the v2 templates), then the Cloud Run v2 and VPC
  Access APIs per project that has any, the inventory's copy standing where a
  read is refused (said under *Projects not checked*). Rows `Project,
  Workload, Location, Kind, Issue, Detail, Fix`.
- **Cloud Storage Lifecycle** gains a row: a bucket with **versioning on and
  no lifecycle rule that deletes noncurrent versions** (`Delete` on
  `numNewerVersions`, `daysSinceNoncurrentTime` or `isLive: false`) keeps
  every overwritten or deleted object for ever, billed — *Investigation*; the
  fix writes the bucket's existing rules plus one that keeps the three newest
  noncurrent versions, in one line — the merged configuration to a file, then
  `--lifecycle-file` (the file replaces the whole configuration; `gcloud`
  cannot read it from `/dev/stdin`: the closed loop found the here-string form
  fails with *Unable to read file [/proc/…/fd/pipe]*). A bucket with no rule
  at all and versioning on gets both rows. The all-clear text says both.
- The Scorecard's **Efficiency** line opens with the spend when the briefing
  has it — "month to date 975.81 USD, forecast ≈ 1,938.43 USD, last month
  1,927.37 USD" — beside the savings tally; the score is unchanged (the
  briefing is Informational, Spend Anomalies counts like any check). The
  executive summary, generated from the Scorecard, sees the sentence.
- `BILLING_EXPORT` and `SPEND_ANOMALY_FLOOR` (`app.config`, validated);
  `tools/deploy.sh` takes both, grants the service account READER on the
  export dataset when it is in `PROJECT_ID` (the access-list edit the export
  step makes; a note with the `bq` lines when the dataset is elsewhere) and
  `roles/bigquery.jobUser` on the project; `terraform/` takes
  `billing_export` and `spend_anomaly_floor`, grants the same READER
  (`google_bigquery_dataset_access`, non-authoritative) and the Job User role.

### Changed

- Shard merging (`app.checks.categories.merge_shard_findings`): an
  *Informational* record of a check joins the verdict records of the same
  check under the worst status, as a single scan writes it — a per-project
  check whose rows are Informational in one shard and Investigation in
  another (Log Cost Levers' retention rows beside a sampling row) is one
  record in both shapes. Nothing else changes: Informational records of a
  check with no verdict record are joined as before.
- The synthetic organization draws the cost levers (log retention and a
  locked audit bucket, flow-log sampling and verbosity, log volume and DEBUG
  share, a DEBUG exclusion, a connector idle or used, a cross-region Cloud SQL
  instance, the versioned buckets that prune, a spend scale; drawn last) and
  answers the two spend queries from a deterministic daily series — steady
  per-service costs with a Compute Engine spike in every seventh project, a
  new BigQuery line in every eleventh, Cloud SQL stopped in every thirteenth,
  sustained-use and committed-use credits — the way BigQuery would; the
  provider fakes `bigquery.tables.list`, `bigquery.jobs.query`, the log
  buckets, the project sinks, the `byte_count` series, the connectors (search,
  listing and API) and the subnets' flow-log configuration.
- README: the four catalogue entries and the lifecycle sentence, the
  Efficiency line, a **Spend** section under History and analytics, the
  prerequisites step 2d, the `deploy.sh` and Configuration Reference rows,
  the scope note, the project structure, the roadmap row. `VERSION = "18.8"`.

### Tests

- `tests/test_spend.py`: the scope predicates; the two SQL texts (partition
  pruning per table shape, the union of several accounts, the parameters);
  the table discovery; `run_query` polling an unfinished job and following
  pages; the facts from the query's rows; percentages and shares; the
  briefing's lines from a steady series (every line, the `bq` fixes, the
  organization's unattributed charges, folder and project predicates), at the
  first of a month, across February, with a short export, empty; the credits
  line with committed-use coverage; the floor; the anomaly rows; the
  Scorecard sentence; the setting's validation; the check end to end — not
  configured, a refused dataset with the grant, no export table, a failing
  query, the floor from last month, two tables.
- `tests/test_log_cost.py`: the retention rows (locked, `_Required`,
  deleted, odd shapes), the sampling rows and the verbose fix, the DEBUG
  exclusions, the volume and the DEBUG row's three conditions, the Monitoring
  request; the check end to end under the worst status, Informational alone,
  all clear, and with each read failing on its own.
- `tests/test_serverless.py`: cost facts from the Knative copy, the v2
  service and job templates and a gen-2 function; gen-2 functions merged into
  their services; the connector facts; the rows (a job on an unlisted
  connector, a service on a connector with its subnet, a cross-region
  instance, an idle connector, Direct VPC and same-region instances passing);
  the check end to end with the APIs as the copy of record, refused reads,
  nothing serverless, the listing failing; the catalogue entry.
- `tests/test_finops.py`: the pruning rule, the merged lifecycle fix, the
  versioned-bucket rows; `tests/test_worker.py`, `tests/test_fanout.py`,
  `tests/test_synthetic.py`, `tests/test_category_consistency.py`,
  `tests/test_terraform.py`: the plan, the scope shard, the names, the
  variables, the roles.
- 1,217 tests.

### Upgrade notes

- No new role and no new API on the organization: `logging.buckets.list`,
  `logging.sinks.list`, `monitoring.timeSeries.list`, `compute.subnetworks.list`,
  `vpcaccess.connectors.list` and `bigquery.tables.list` are in
  `roles/iam.securityReviewer`, `roles/logging.viewer`, `roles/monitoring.viewer`
  and `roles/compute.networkViewer`; the connector search under
  `roles/cloudasset.viewer` — verified as the service account before the
  release. **One setup step** for the spend records: `roles/bigquery.dataViewer`
  on the billing export dataset (a dataset-level entry: `tools/deploy.sh
  BILLING_EXPORT=…` adds it when the dataset is in the deployment project, the
  dataset's owner otherwise) and `BILLING_EXPORT` on both services. Without
  it the two records are Informational and the rest of the release works.
- The first scan after the upgrade shows **Spend Anomalies**, **Log Cost
  Levers** and **Serverless Cost Hygiene** as *new check* on the Changes card
  (the briefing is Informational and not compared); Cloud Storage Lifecycle's
  new rows are *new* findings, not a rule change.

---

## v18.7 — Folders, keys and privileged grants

The seventh themed release, the second deduced from the google/skills mining
and the Workload Manager catalogue diff: the IAM the report never read.
Nothing judged folder-level Owner and Editor; nothing read who may create
projects or reach billing at the organization, who can read every secret
under a resource, which custom roles re-acquire the power to grant, or
whether a just-in-time elevation path exists and is respected; and the key
check saw only keys older than 90 days. Everything comes from reads the
scanner's roles already allow — **fresh** where a fix should show on the next
scan (folder and organization policies from Resource Manager, custom roles
from the IAM API, entitlements from Privileged Access Manager, deny policies
from IAM v2, keys from the IAM API), the inventory search for the folders,
projects, secrets and versions, the IAM-policy search for the secret roles
and the holders of custom roles. No new API, no new role.

### Added

- **Folder Primitive Roles** (Security & Identity, every scope): Owner or
  Editor on a **folder**, by kind of holder — the project table of Primitive
  Roles: a user-managed service account, a consumer account or a whole domain
  **Action Required**; a person, a group, a default service account or a
  deleted principal *Investigation* — and **Project Creator on a folder** (a
  whole domain **Action Required**, a person *Investigation*, a group or a
  service account the project-factory practice, listed). Every project below
  the folder inherits the grant: the row counts them (`Projects below`). A
  folder scan includes the scope folder itself; a project scan has none and
  says so. Fresh `folders.getIamPolicy` (policy version 3) per folder; when a
  read is refused the IAM-policy search's copy stands in and a line under
  *Projects not checked* says so. Google-managed agents are never rows; a
  public principal on a folder stays External Principals' Action Required
  row. Rows `Folder, Principal, Type, Role, Projects below, Condition, Fix`
  (`gcloud resource-manager folders remove-iam-policy-binding`).
- **Privileged Grants** (Security & Identity, a split check): in an
  organization scan, from the organization's policy — **Project Creator**
  held by a whole domain or the public (**Action Required**: every account can
  create projects), by a person (*Investigation*), by a group or an automation
  account (the project-factory practice, listed); the **billing roles**
  `billing.creator`, `billing.user`, `billing.viewer`, `billing.costsManager`
  granted at the organization (they belong on the billing account:
  *Investigation*; a domain or the public **Action Required**; `billing.admin`
  stays Critical Org-Level Roles' row); **Organization Administrator
  redundancy** — fewer than two principals holding the role without a
  condition: **Action Required** (lockout), Informational when the one holder
  is a group (its membership is not visible to the scanner); and one
  Informational row when **no IAM deny policy** is attached to the
  organization (metadata only — the rules would need `iam.denypolicies.get`).
  Under every scope, the **Privileged Access Manager** entitlements of the
  organization, its folders (scope shard) and its projects (project shards): an
  entitlement that hands out an administrative role — the organization's
  critical roles, the escalation roles, any `*.admin` — with **no approval
  workflow** (*Investigation*, "self-approved elevation"), one that lasts over
  24 hours or needs no justification (Informational), and a **standing grant
  that duplicates an entitlement** — the same principal and role bound
  unconditionally on the organization or the project where PAM would grant
  them on request (**Action Required**; PAM's own grants are conditional and
  never standing). A project without the PAM API is not a row and not a line.
  Rows `Resource, Principal, Type, Role, Condition, Issue, Detail, Fix`
  (`remove-iam-policy-binding` with the billing-account alternative;
  `add-iam-policy-binding` for a second administrator; `gcloud pam
  entitlements export … update`; `gcloud iam policies create … --kind=denypolicies`).
- **Secret Access Scope** (Security & Identity, every scope):
  `secretmanager.admin`, `secretmanager.secretAccessor` or
  `secretmanager.secretVersionManager` granted **resource-wide** — on a
  project, a folder or the organization — rather than on a secret: to the
  public or a whole domain **Action Required**; to a service account
  *Investigation* (every workload and key of the account can read every secret
  under the resource); to a person or a group *Investigation* with at least one
  secret in reach, Informational with none. One IAM-policy search for the
  three roles on organizations, folders and projects; the secrets in reach
  counted from the inventory (a project's by number, a folder's descendants',
  the organization's all). `secretmanager.viewer` (metadata only) is not
  judged; Owner is Primitive Roles' row. Rows `Resource, Principal, Type,
  Role, Secrets in reach, Condition, Fix` — the removal plus the per-secret
  `gcloud secrets add-iam-policy-binding`.
- **Secret Manager Posture** (Security & Identity, every scope, the same
  function): from the inventory's copy of the secrets and their versions (the
  Secret Manager API itself would need `roles/secretmanager.viewer`, which the
  account does not hold; the inventory never carries payloads, and the rows say
  *from the inventory*): a secret whose **newest enabled version is older than
  90 days with no rotation schedule** (*Investigation* — a static credential
  whose exposure nobody would notice; the version's age is the fact, not the
  secret's, so adding a version is the fix); **user-managed replication in one
  location** (Informational — often a residency choice, immutable in place) and
  a secret with **no enabled version** (Informational, housekeeping). Rows
  `Project, Secret, Issue, Detail, Fix` (`gcloud secrets versions add … &&
  versions disable OLD`, or `gcloud secrets update --rotation-period`).
- **Custom Roles With IAM Powers** (Security & Identity, a split check): the
  organization's custom roles (organization scans) and every project's, read
  fresh with `view=FULL`, deleted ones included; a role carrying a permission
  that changes who may do what — any `*.setIamPolicy`,
  `iam.serviceAccountKeys.create`, `iam.serviceAccounts.actAs` /
  `getAccessToken` / `signBlob` / `signJwt` / `implicitDelegation`,
  `iam.roles.create` / `update`, `orgpolicy.policy.set` — is *Investigation*
  when a principal that is not a Google-managed agent holds it on an
  organization, folder or project under the scope (one IAM-policy search per
  twenty roles names the holders), Informational when dormant; a **retired**
  role (disabled, deprecated or soft-deleted) still bound, Informational. An
  unset stage reads as ALPHA, as the API documents. Rows `Role, Defined at,
  Stage, Powers, Holders, Issue, Detail, Fix` (`gcloud iam roles update
  --remove-permissions`, `roles delete`, the removal per holder). Predefined
  roles are Service Account Privileges' and Critical Org-Level Roles' ground.
- **User-Managed Keys** (Security & Identity, per project): the second record
  of the key listing Service Account Key Rotation already pages — one row per
  service account with **any user-managed key that can still authenticate**
  (not disabled, not expired, the account enabled): `Keys`, `Oldest (days)`,
  `Expiry` (`never` ×N and the earliest dated one), `Origin` (created in
  Google Cloud / uploaded) — *Investigation* (CIS 1.4; Security Health
  Analytics' `USER_MANAGED_SERVICE_ACCOUNT_KEY`): a long-lived credential that
  works from anywhere for whoever holds the file. The Fix disables the oldest
  key once the caller uses an attached service account, impersonation or
  Workload Identity Federation, then names `iam.disableServiceAccountKeyCreation`
  and `iam.serviceAccountKeyExpiryHours` so none come back. The rotation rows
  (keys older than 90 days, **Action Required**) are unchanged.

### Changed

- **Service Account Key Rotation** writes two records from one listing (its
  own rows unchanged); its all-clear text is unchanged.
- The synthetic organization draws folder bindings (a person as Owner and a
  project-factory group on the first folder, an Editor service account on the
  second), domain-wide project creation, a billing role and an organization
  custom role with IAM powers at the organization, and per project
  resource-wide secret roles, secrets in five shapes, a custom role held,
  dormant or retired, and a PAM entitlement approved, unapproved or duplicated
  by a standing grant (drawn last, so earlier releases' worlds are unchanged);
  the provider fakes the folder policies, the IAM roles listings, Privileged
  Access Manager (the API disabled where the world draws no entitlement, as the
  real API answers), the IAM v2 deny-policy listing, the secret and version
  searches, the two IAM-policy queries.
- README: the six catalogue entries and the SA Key Rotation line, the
  scope-shard list, the scope note, the fixes paragraph, the project
  structure, the roadmap row. `VERSION = "18.7"`.

### Tests

- `tests/test_privileges.py`: policy bindings and the folder label; the
  folder and project searches from the index; folder rows by kind and role
  (incl. an unknown organization domain); the folder check end to end — fresh
  policies, the inventory's copy for a refused read with its line, a folder
  scan, a project scan, a listing that fails; project creation, billing and
  the redundancy row by kind (two administrators, one group, one person with
  PAM's conditional grant excluded, none); the deny row; entitlement facts and
  rows (approval, duration, justification, state, the admin tier, organization
  and project fixes); standing grants against conditional and unrelated
  bindings; Privileged Grants end to end — organization, folder and project
  entitlements, the disabled API, a failing project, the project policy read
  only where entitlements exist — and its two halves, a folder scan, the
  organization read refused, the deny listing failing; role facts and powers
  (`setIamPolicy` suffixes, the unset stage); custom-role rows by holder and
  stage; Custom Roles end to end — the quoted holders query, the halves, a
  folder scan, nothing flagged, the holders search failing, the organization's
  roles refused; the split checks' halves in the scope and project plans.
- `tests/test_secrets.py`: secrets and versions from the search; reach per
  level; scope rows by kind, reach and condition with the per-secret fix;
  posture rows (the newest *enabled* version, a schedule, single-location
  replication, no enabled version, the 90-day edge, numbers without project
  names); the check end to end with the side reads failing, nothing in scope,
  a search that fails.
- `tests/test_revalidated_checks.py`: the User-Managed Keys roll-up (count,
  oldest, expiry, origin, the disabled/expired/account-disabled exclusions)
  and the two records from one listing; `tests/test_worker.py`,
  `tests/test_fanout.py`, `tests/test_synthetic.py`,
  `tests/test_category_consistency.py`: the plan, the scope shard, the split
  halves, the names.
- 1,186 tests.

### Upgrade notes

- No new role and no new API: `resourcemanager.folders.getIamPolicy`,
  `iam.roles.list`, `privilegedaccessmanager.entitlements.list`,
  `iam.denypolicies.list` and the key listing are in
  `roles/iam.securityReviewer`, the searches under `roles/cloudasset.viewer` —
  verified by impersonating the service account before the release. The
  Privileged Access Manager client library has no bundled discovery document:
  the client fetches it at first use (`static_discovery=False`); a project
  without the PAM API answers `SERVICE_DISABLED`, which the check reads as
  "not used there". Redeploy with `tools/deploy.sh` or `terraform apply` as
  usual.
- The first scan after the upgrade shows the five new checks and the new
  record as *new check* on the Changes card; nothing is *rule changed*.

---

## v18.6.1 — Request hardening

A point release with no check changes, answering a security review of the
application's request handling (three findings filed against the original
single-file version: object keys built from unvalidated identifiers, no
cross-site protection or rate limit on scan submission, and worker endpoints
that trusted their caller). The two-service deployment this line documents
already closes the unauthenticated path — the pages behind Identity-Aware
Proxy, the worker a separate `--ingress internal` service the service account
alone may invoke — and this release adds the application-level controls the
findings name, so they hold whatever the deployment, including the single
public service the README still describes (discouraged). No new role, no new
API, no new report name.

### Added

- **Request validation** (`app/validation.py`): one definition of what the
  identifiers may be — `scope` one of three words; `scope_id` an organization
  or folder number, or a project ID (6–30 characters, a letter first, letters,
  digits and hyphens, optionally behind the domain of a domain-scoped project);
  `job_id` the lower-case UUID `POST /scan` mints; a shard name as the fan-out
  plans them; a sweep number; `requested_by` a short printable name — applied
  at every entry: `POST /scan`, `/status/…`, `/report/…` (+ `/csv`),
  `/history/…`, `/api/status/…`, `/api/get-summary`, `/api/get-insights`, and
  the five worker bodies (`/run-scan`, `/scan-shard`, `/run-aggregation`,
  `/sweep`, `/scheduled-scan`). A malformed value is a **400** with the reason,
  before anything is read, written or called — on the worker routes too, where
  a malformed task used to fail inside the job with a 500 (Cloud Tasks retries
  either status the same bounded number of times; the log now says why).
- **Key-part guard in the results store**: `job_id`, `scope_id`, `scope` and
  `shard_id` pass through `key_part` wherever an object key is built (status,
  reports, intermediate files, the scope summaries, the scope's job note) —
  letters, digits, `.`, `_`, `:` and `-` only, never a slash or `..`, 128
  characters at most — so no caller, present or future, can steer an object
  under another prefix.
- **Same-origin enforcement** (`app/routes/guards.py`) on the four POST
  routes — `POST /scan`, `/api/get-summary`, `/api/get-suggestions`,
  `/api/get-insights`: `Sec-Fetch-Site` must be `same-origin` or `none`; without
  it the `Origin`, then the `Referer`, must name this service; a request with
  none of the three (`curl`, a script) is allowed, having no victim's browser
  behind it. A cross-site request gets **403**. IAP authenticates the person,
  not the page: without this a form on another site could start a scan as
  the signed-in operator.
- **One scan per scope at a time, whoever asks**: `POST /scan` now writes and
  consults the scope's job note (`schedules/<scope>/<scope_id>.json`, the one
  scheduled scans have kept since v17) and, while the noted job is still
  running, answers **409** with a page in the status page's design naming the
  running scan — when it started, who asked, the job — with a button to its
  status page and a link back to the form (JSON with `job_id` and
  `status_path` for a client that asks for it); nothing new is started. A
  noted job whose status file never appeared counts as running for 10 minutes
  only, so a task that never dispatched cannot block its scope for the note's
  36-hour life (this refinement applies to scheduled scans too).
- **A bounded suggestions batch**: `/api/get-suggestions` takes at most 20
  findings per request (the report's script sends 5), each with a numeric
  `index`, at most 20,000 characters of `finding_text` and a printable
  `project_id` of at most 128 characters; a body that is not a JSON object is
  a 400 on every API route; no request body may exceed 1 MiB (**413**).
- **The worker verifies its caller** (`app.identity.CallerVerifier`, a
  `before_request` on the worker blueprint): the bearer ID token Cloud Tasks
  and Cloud Scheduler send — Google's signature (certificates cached an hour,
  refetched once on an unknown key, the IAP pattern), issuer
  `accounts.google.com`, an audience among `WORKER_AUDIENCE`, the worker's own
  URL (what scheduler jobs carry) and the request's URL with and without its
  path (what Cloud Tasks carries), a current expiry, and `email` equal to
  `SERVICE_ACCOUNT_EMAIL` — answering **401** otherwise. Cloud Run's IAM check
  remains the guard that keeps everyone else out of the worker service in the
  two-service deployment; Cloud Run hands the `Authorization` header on to the
  container, so this is defence in depth there and the only guard in the
  single-service public mode. Enforced in the `production` and `synthetic`
  profiles (both receive real tasks); `testing` and `development` skip it; the
  offline harness (`tools/synthetic_scan.py`) never goes through HTTP.
- `WORKER_TOKEN_CHECK` (default `on`): `off` disables the worker's token check
  — the way back if a front in your path rewrites the token, instead of a
  rollback.

### Changed

- `POST /scan` applies the scope allow-list it had always declared
  (`SCOPES`) and refuses a scope ID that is not one; the status, report, CSV
  and history routes refuse a job ID that is not a UUID (every job the
  application ever minted is one) — before, such values were only escaped into
  the page or sanitised in the download's filename.
- The API's error answers are uniform: a 400 JSON `{"error": …}` naming the
  field, where legacy handlers answered 400, 415 or 500 with JSON or an HTML
  error page depending on how the body was malformed.
- `app/services/schedules.py` is now the one place a scan starts
  (`start_scan`, raising `ScanInProgress`); `/scheduled-scan` keeps its
  202/400/409 contract and its note shape.
- README: a **Request hardening** section under the deployment chapter; the
  public-deployment section says the worker endpoints now require the service
  account's token; the configuration reference gains `WORKER_TOKEN_CHECK`.
  `VERSION = "18.6.1"`.

### Tests

- `tests/test_request_hardening.py`: the validator table (accepted and refused
  values per field, domain-scoped project IDs, slashes, `..`, whitespace, the
  UUID shape); the key-part guard; every page and API route's 400; the
  same-origin matrix (`Sec-Fetch-Site`, `Origin`, `Referer`, none) on each POST
  route and the GET routes untouched; `POST /scan` writing the note, the 409
  page and its JSON form, the pending allowance, a note that cannot be read or
  written; the suggestions caps; the worker's 401 matrix with signed tokens (no
  header, another key, another issuer, another audience, another account,
  expired, `WORKER_TOKEN_CHECK=off`, the testing profile) and the 400 for each
  malformed task body; the request-size limit.
- The parity suites keep their happy paths on real identifier shapes and
  assert the new 400s where legacy answered otherwise (`tests/test_api_parity.py`,
  `tests/test_worker.py`); the test environment runs the worker's token check
  off (`tests/helpers.py`) except where the new suite turns it on.
- 1,162 tests.

### Upgrade notes

- Redeploy with `tools/deploy.sh` or `terraform apply` as usual; nothing to
  grant or enable. The first scan after the upgrade shows nothing on the
  Changes card (no check changed).
- A public single-service deployment keeps working — its worker endpoints now
  answer 401 to anything but the service account's token, which is what Cloud
  Tasks sends; scripts that posted to `/run-scan` directly must send one too.
- Scripts that submit scans by posting the form must send a real scope ID and
  no `Origin` header of another site; a second submission for a scope whose
  scan is still running now gets 409 instead of a second scan.

---

---

## v18.6 — Serverless and edge exposure

The sixth themed release, and the first deduced from the google/skills
mining (61 Google Cloud skills read against the check code; Google's Workload
Manager best-practice catalogue of 486 rules diffed against v18.5): the one
compute family the tool had never judged for exposure or identity — Cloud Run
and Cloud Functions — and the first look *inside* the edge it already listed:
Cloud Armor policy content, certificates, and whether the images serverless
runs are ever scanned. Two Cloud Asset Inventory listings under the scope
(serverless workloads with their load balancers; edge policies and
certificates), two searches (repositories; the Artifact Analysis service),
the public-principal IAM search the data checks already run, and **fresh
reads** from the Cloud Run v2, Cloud Functions v2 and Compute APIs per project
that has the resources, so a fix shows on the next scan. No new API, no new
role; three refinements to existing rules ride along.

### Added

- **Serverless Exposure** (Security & Identity, every scope): a Cloud Run
  service or Cloud Function **behind an external load balancer** (a serverless
  NEG in an external backend service) whose ingress is still `all` — callers
  reach the `run.app` URL and bypass the load balancer and whatever Cloud Armor
  policy it carries — **Action Required** (*Investigation* when IAP on the
  service still authenticates them: the WAF is what is skipped); a **public**
  one — `allUsers` / `allAuthenticatedUsers` on the invoker role **or the
  invoker IAM check disabled**, the newer setting no IAM search sees (in the
  organization this shipped from, all four public services used it) — with
  ingress `all` and no IAP, *Investigation*, the row naming what makes it public
  and IAP or an authenticated caller as the alternatives. IAP-fronted and
  internal services are never rows; second-generation functions are judged
  through their Cloud Run service; event-triggered gen-1 functions have no
  endpoint and no row. Rows `Project, Workload, Location, Kind, Ingress,
  Invoker, Issue, Detail, Fix` (`--ingress=internal-and-cloud-load-balancing`,
  `--invoker-iam-check`, `remove-iam-policy-binding`, `--iap`).
- **Serverless Service Accounts** (Security & Identity, every scope): a Cloud
  Run service or job, or a function, running as the Compute Engine or App
  Engine **default service account** (or none, which is the Compute default) —
  **Action Required** when the account holds a privileged role (the v17.1
  list, read with the IAM search VM Service Accounts runs), *Investigation*
  otherwise: a Cloud Run token has no scope limit, every role of the account is
  reachable from the container. The Fix creates a dedicated account and points
  the workload at it. Rows `Project, Workload, Location, Kind, Service
  Account, Issue, Detail, Fix`.
- **Cloud Armor Policy Content** (Security & Identity, every scope): inside
  the **attached L7 policies** (`type` `CLOUD_ARMOR`; network and edge
  policies carry no WAF rules by design, Google's advanced-DDoS policies are
  its own) — a rule on an **older ruleset generation** (`sqli-stable`,
  `xss-v33-stable`, `nodejs-v33-*`, …) or on the legacy
  `evaluatePreconfiguredExpr` syntax, *Investigation*, the Detail naming the
  current ruleset, the signature gap (RCE 15 → 44, SQLi 49 → 60), the retired
  signature IDs to drop from the opt-out list and the method-enforcement
  caveat (PUT/PATCH/DELETE), the Fix the current rule in preview beside the old
  one; a policy that **protects nothing** (only the default rule, or allow
  rules over a default allow: no WAF rule, no deny or throttle, Layer-7 DDoS
  defense off — an allowlist over a default deny is protective and passes); a
  policy whose deny and throttle rules are **all in preview** ("WAF not
  enforcing"); *Informational*: preview rules left behind, 180 of the 200-rule
  quota. The ruleset generations, retired IDs and signature counts ship in
  `assets/cloud_armor_rulesets.json` (from the google/skills Cloud Armor upgrade
  reference; a newer generation is one table change). Unattached policies get
  no row. Rows `Project, Policy, Attached to, Rule, Issue, Detail, Fix`.
- **SSL Certificate Health** (Reliability & Resilience, every scope): the
  certificates the target HTTPS and SSL proxies serve — a **self-managed**
  certificate expiring within 30 days (*Investigation*; **Action Required**
  within 7 days or expired; the Fix a replacement certificate on the proxy,
  Google-managed renews itself), a **Google-managed** certificate in
  `PROVISIONING_FAILED`, `PROVISIONING_FAILED_PERMANENTLY` or `RENEWAL_FAILED`
  or with a `FAILED_*` domain (**Action Required**: it will not issue until
  the domain's records point at the load balancer; the old certificate serves
  until it expires, then nothing) or `PROVISIONING` for more than a day
  (*Investigation*), an unattached expired certificate (*Informational*,
  housekeeping). Regional certificates and proxies carry `--region`. Rows
  `Project, Certificate, Type, Attached to, Expires / Status, Issue, Detail,
  Fix`.
- **Container Scanning Enabled** (Security & Identity, every scope),
  *Investigation Recommended*: a project with standard **Docker repositories**
  in Artifact Registry (gcr.io redirect repositories included; remote and
  virtual repositories not counted) and Artifact Analysis
  (`containerscanning.googleapis.com`) not enabled — no image pushed to it has
  ever been scanned for known CVEs. One row per project with the repository
  count and names; `gcloud services enable` as the Fix (billed per image
  scanned). Two searches of the index — the repositories, and the projects
  where the service is enabled (an enabled service is an asset, a disabled one
  is absent) — then the service's state from the Service Usage API per project
  with such repositories. Rows `Project, Repositories, Issue, Detail, Fix`.
- **Load Balancer Edge** gains **IAP over HTTP**: a backend service with
  Identity-Aware Proxy on that an HTTP-only load balancer serves (its session
  cookie and identity headers cross the internet in clear), *Investigation*;
  the listing adds `compute.googleapis.com/UrlMap` to tell which backend
  services an HTTP-only map routes to.

### Changed

- **BigQuery Governance** — the time-travel row is graded by the dataset's
  **storage billing model**: *Investigation* under logical billing (time-travel
  bytes are not billed there, so a shorter window saves nothing — the dataset
  merely lost recoverability), *Informational* under physical billing (a
  deliberate trade-off; the Detail says what it trades). *Rule changed* on the
  Changes card of the first scan after the upgrade.
- **Cloud SQL Flags** — a `Note` column on every row; it says where Google's
  Workload Manager best-practice rule points the other way
  (`log_min_duration_statement`, trace flag `3625`, `user connections`) and
  that the row follows CIS. *Rows changed* on the Changes card.
- **Cloud Storage Versioning** — zonal (Rapid Storage) buckets, which support
  none of versioning, soft delete, lifecycle rules or retention, are no longer
  the "nothing protects the objects" row (its Fix was impossible there); a
  log-sink destination among them still is. *Rule changed*.
- **Fresh reads**: Cloud Run services, jobs and their invoker policies (v2
  API), Cloud Functions (v2 API), the backend services in front of them,
  Cloud Armor policies and certificates (Compute API), and Artifact
  Analysis's state (Service Usage API) are re-read per project that has the
  resources; the inventory says which projects those
  are and stands in when a read is refused (a line under *Projects not
  checked* says so, as for the v18.5 VM reads). The first canary showed why
  the load balancers need it: the index kept a backend service's creation
  snapshot — an empty backend list — minutes after its NEG was added. The Cloud
  Functions and API Gateway APIs are read only where the inventory shows the
  resources — a project without the API has none.
- **The search-first inventory read, repaired**: two of the edge types —
  `compute.googleapis.com/RegionBackendService` and `GlobalForwardingRule` —
  are not searchable (the index files regional backend services and global
  forwarding rules under the plain types), and naming them made the whole
  search fail, so every type of *Load Balancer Edge* had been falling back to
  the hours-stale listing since v18.5 without a sign. `search_assets` now drops
  a type the index refuses and retries; the listing serves that type alone,
  and what it repeats is dropped by name. Found by the v18.6 canary, whose
  bypass row needed the fresh backend services.
- The synthetic organization draws serverless workloads in every exposure
  shape, a job and a function, Cloud Armor policy content, certificates and
  repositories (drawn last, so earlier releases' worlds are unchanged); the
  synthetic provider fakes Cloud Run **v2** (v1 stays passed through for the
  worker-URL lookup), Cloud Functions v2, the Compute policy and certificate
  listings, the repository and service searches, and the public invokers in
  the IAM-policy search.
- README: the five catalogue entries and the Load Balancer Edge line, the
  scope-shard list, the scope note, the data-freshness paragraph, the project
  structure, the roadmap table re-cut as decided (below). `VERSION = "18.6"`.

### Tests

- `tests/test_serverless.py`: service, job and function facts from the
  inventory's and the v2 API's shapes (the three ingress spellings, the two
  public settings, IAP, gen-2 labelling, an unset account); the NEG → backend
  service → workload join (URL-mask NEGs and internal backend services
  excluded); exposure rows by binding, setting, IAP, ingress and load balancer,
  for services and gen-1 functions; service-account rows by account, roles and
  kind, including unreadable roles and an unknown project number; the checks
  end to end — the inventory's copy against the API's, each failure path
  (services, functions, one invoker policy, the public search, the roles
  search) with its *Projects not checked* line, nothing in scope, a listing
  that fails; repository facts from search results and listed assets, scanning
  rows per project, the scanning check end to end; the catalogue, categories
  and scope-shard lists.
- `tests/test_edge_security.py`: the bundled ruleset table's consistency;
  legacy rulesets in expressions and exclusions, standalone rulesets, the
  legacy syntax on a current name, retired IDs, the signature notes; Armor rows
  for legacy, empty, allowlist, blocklist, preview-only, modern, oversized,
  unattached, network and DDoS policies, regional policies, adaptive
  protection alone; certificate rows by type, expiry, managed status,
  attachment and region, the Compute timestamp with an offset; the check end
  to end with the inventory's copy against the API's and the failure paths;
  the IAP-over-HTTP row of Load Balancer Edge and `url_map_services`.
- `tests/test_data_governance.py`, `tests/test_loose_rules.py`,
  `tests/test_changes.py`: the three refinements and their `RESHAPED_CHECKS`
  lines; `tests/test_worker.py`, `tests/test_synthetic.py`,
  `tests/test_category_consistency.py`: the plan, the scope shard, the two
  listings, the names.
- 1,098 tests.

### Upgrade notes

- No new role and no new API: the Cloud Run, Cloud Functions and Compute
  reads are under the roles the service account holds (`run.services.list`,
  `run.services.getIamPolicy`, `cloudfunctions.functions.list`,
  `compute.securityPolicies.list`, `compute.sslCertificates.list` are in
  `roles/iam.securityReviewer`; the inventory and the searches under
  `roles/cloudasset.viewer`), verified by impersonating the service account
  before the release. Redeploy with `tools/deploy.sh` or `terraform apply`
  as usual.
- The first scan after the upgrade shows the five checks as *new check* on
  the Changes card, and *rule changed* / *rows changed* for the three refined
  checks.

---

## v18.5 — VM hardening & identities

The fourth themed release. CIS §4 (Compute) and §1 (IAM) Level-1 items and the
matching Security Health Analytics detectors that the identity checks of v17.1
and v18 do not cover: who VMs run as and how they are reachable, which service
accounts hold administrative power, who in the IAM policies is not of the
organization, and which service accounts nobody uses. Two Cloud Asset Inventory
listings under the scope (instances with compute projects; the IAM policies of
organization, folders and projects), one IAM-policy search (public images), the
account-roles search GKE Credential Exposure already runs, and the IAM
recommender's service-account insights per project. No new API, no new role;
one optional setting (`TRUSTED_DOMAINS`).

### Added

- **VM Service Accounts** (Security & Identity, every scope): a VM that runs
  as the Compute Engine or App Engine **default service account** —
  **Action Required** when the account holds a privileged role (the v17.1 list:
  owner, editor, the IAM and service-account admin roles, container and compute
  admin, storage and Secret Manager admin) or the VM has the `cloud-platform`
  scope (`FULL_API_ACCESS`, CIS 4.2); *Investigation* otherwise
  (`DEFAULT_SERVICE_ACCOUNT_USED`, CIS 4.1). The Detail names the privileged
  role and what the scopes let a stolen token call; stopped instances are
  judged and say so. A dedicated account is never a row. Fix:
  `set-service-account` on the stopped instance, or the instance template for
  an instance a managed instance group created. Rows `Project, Instance, Zone,
  Status, Service Account, Scopes, Issue, Detail, Fix`.
- **VM Hardening** (Security & Identity, every scope), *Investigation
  Recommended*: per **project** (one row each, the metadata from the Compute
  API) OS Login off
  (`OS_LOGIN_DISABLED`, CIS 4.4, with how many instances rely on metadata
  keys), project-wide SSH keys in use while OS Login is off
  (`COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED`, CIS 4.3, with how many instances
  they reach), the serial console enabled project-wide (CIS 4.5); per
  **instance** an OS Login opt-out, the serial console
  (`COMPUTE_SERIAL_PORTS_ENABLED`), IP forwarding (`IP_FORWARDING_ENABLED`,
  CIS 4.6 — legitimate for a router or NAT appliance, the row says so),
  Shielded VM off (`SHIELDED_VM_DISABLED`, CIS 4.8: vTPM or integrity
  monitoring, or an image that is not Shielded-capable), Secure Boot off
  (`COMPUTE_SECURE_BOOT_DISABLED`). Rows `Project, Instance ("(project)" for
  project rows), Zone, Status, Issue, Detail, Fix`.
- **Service Account Privileges** (Security & Identity, every scope): a service
  account holding a predefined **administrative role** (`roles/*.admin`,
  `roles/*Admin`) at project, folder or organization level — except what
  Primitive Roles and Critical Org-Level Roles report already — *Investigation*;
  **Action Required** when the role grants the power to change who may do what
  (`iam.securityAdmin`, `resourcemanager.projectIamAdmin`,
  `iam.serviceAccountAdmin`, `iam.serviceAccountKeyAdmin`,
  `orgpolicy.policyAdmin`, `iam.denyAdmin`, `iam.organizationRoleAdmin`,
  `resourcemanager.folderAdmin`, `resourcemanager.organizationAdmin`,
  `billing.admin`) or the holder is a **default service account**
  (`ADMIN_SERVICE_ACCOUNT`, CIS 1.5); one principal holding
  `iam.serviceAccountAdmin` **and** `iam.serviceAccountUser` or Token Creator
  on one resource (`SERVICE_ACCOUNT_ROLE_SEPARATION`, CIS 1.8). Custom roles
  are not judged by name; Google-managed service agents are never rows. Rows
  `Resource, Principal, Type, Role, Issue, Detail, Fix`, projects named by ID
  (one resource search).
- **External Principals** (Security & Identity, every scope): users and groups
  outside the organization's primary domain and `TRUSTED_DOMAINS`
  (*Investigation*: an acquired company's domain as often as a stranger),
  consumer accounts and external `domain:` grants (**Action Required**;
  `NON_ORG_IAM_MEMBER`, CIS 1.1), deleted principals still bound, a folder open
  to the public (**Action Required**; projects are Primitive Roles' subject,
  the organization Public Org-Level Access'), a custom image open to the public
  (**Action Required**; `PUBLIC_COMPUTE_IMAGE`). One row per (resource,
  principal) with the roles joined. The organization's domain comes from
  `organizations.get` (the organization of the scope, read from the policies'
  ancestors); when it cannot be read the rule is noted under *Projects not
  checked* and the rest of the check stands.
- **Unused Service Accounts** (Security & Identity, per project): the IAM
  recommender's `SERVICE_ACCOUNT_USAGE` insights — accounts without an
  authentication in Google's 90-day window — one *Investigation* row each with
  the last authentication date (or *never*), default accounts included (disable,
  never delete), `gcloud iam service-accounts disable` as the fix.
- **`TRUSTED_DOMAINS`** (optional): domains besides the organization's primary
  one that External Principals counts as the organization's
  (`tools/deploy.sh`, `terraform/` `trusted_domains`, README configuration
  reference).
- **Fresh reads.** The first canary showed Cloud Asset Inventory's two read
  paths apart: the search index had the probe VMs within minutes (its
  `createTime` is the real one), the listing every inventory check used
  showed them 95 minutes later and the project's metadata change only the next
  morning — refreshed by periodic snapshots, not by events. `list_assets`
  (shared by the network-edge, data-governance and VM checks) now reads the
  **search index first** (`searchAllResources` with the versioned resource
  content, which the index carries for every type these checks read) and
  falls back to the listing for a type the index returns no content for, a
  type it has nothing of, or a failed search; the identity checks read the IAM
  policies from `searchAllIamPolicies` (which also names projects by ID, so
  the number lookup went away). The index is prompt about a resource's
  *existence*; a *change* to an existing resource reached neither path for a
  long time in the same measurements, so the VM checks read each project's
  instances and common instance metadata from the **Compute API**
  (`instances.aggregatedList`, `projects.get`; the inventory says which
  projects have VMs and stands in when a read is refused, noted under
  *Projects not checked*) — the inventory also **omits the `ssh-keys` item on
  both read paths** (measured against the API). A finding fixed minutes before
  a scan is gone from the scan. README › *Data freshness*.

### Changed

- README: the five catalogue entries, the scope-shard list, the scope note,
  the fixes paragraph, the configuration rows; the roadmap row below.
  `VERSION = "18.5"`.

### Tests

- `tests/test_vm_hardening.py` (new): the instance facts (accounts and scopes,
  metadata, Shielded settings, the fleets by label and by name, the
  instance-group origin); default-account rows by scopes and privileged roles
  (v17.1's order), roles not read, dedicated accounts and fleets left out,
  stopped instances, the template fix; project rows for OS Login, project-wide
  keys and the serial console with their counts, no project row where OS Login
  is on, the instance opt-out; instance rows for the serial console, IP
  forwarding, a non-Shielded image, vTPM off, Secure Boot off; the check end to
  end with the roles search and the Compute API as the copy of record (a VM
  moved to a dedicated account, one deleted, one new, the project's key the
  inventory never shows), each read's failure under *Projects not checked*,
  the all-clear rows and the Errors.
- `tests/test_identity_hygiene.py` (new): policy facts, resource labels, the
  organization from the ancestors, the admin-role name test, the removal lines
  with conditions; administrative roles by holder and level with every
  exclusion (primitive, critical at the organization, not admin-named, custom,
  agents); role separation at project and folder level; external principals by
  kind, domain and trust, with and without the organization's domain; public
  images; the insights as protos and dicts, dismissed and other subtypes
  skipped, the default-account fix; both checks end to end with the side reads
  failing one by one.
- `tests/test_network_edge.py`: `list_assets` from the search index with the
  listing for the rest, a failed search, a client without a search.
- Synthetic world (drawn last): per VM the account (dedicated, default, default
  with `cloud-platform`) and the loose settings, per project OS Login and
  project-wide keys, administrative roles on accounts, a role-separation
  principal, external, consumer and deleted principals, unused-account insights;
  the provider answers the IAM-policy search (projects by ID, with their
  number, folders and organization) and the service-account insight type.
  1,080 tests.

### Upgrade notes

- Expect, on the first scan: the five names as *new check*. Where VMs run as
  the default compute account, VM Service Accounts will list them — and Service
  Account Privileges will show what that account has been granted; where the
  IAM policies carry partner or consultant identities, External Principals will
  list them until `TRUSTED_DOMAINS` names their domains.
- Nothing to grant and no new API: inventory listings and searches under
  `roles/cloudasset.viewer`, `organizations.get` under
  `roles/resourcemanager.organizationViewer`, the insights under
  `roles/recommender.iamViewer`.

---

## v18.4 — Data governance

The third themed release. The Security Health Analytics Standard detectors
and the CIS Level-1 items for the data plane — public datasets, Cloud SQL
flags, KMS rotation, API keys — were the largest block of the benchmark the
tool did not read, and a leaked key or an open dataset is the shortest path
from a misconfiguration to an incident. Every item is a setting in Cloud Asset
Inventory — one listing per check under the scanned scope — plus one
IAM-policy search where the question is *who* may reach the data. No new API,
no new role.

### Added

- **BigQuery Governance** (Security & Identity, every scope): a dataset whose
  ACL admits `allUsers` or `allAuthenticatedUsers`, and a dataset or **table**
  whose IAM policy does (one `searchAllIamPolicies` under the scope, the
  dataset's own ACL not repeated) — **Action Required**
  (`PUBLIC_DATASET`, CIS 7.1); a dataset whose **time-travel window** is
  below the seven-day default (*Investigation*: a dropped table or a bad
  `DELETE` is recoverable for that long only). Rows `Project, Resource,
  Issue, Detail, Fix`.
- **Cloud SQL Flags** (Security & Identity, every scope): the CIS §6 flag
  pack of each engine, an unset flag read as its **engine default** — MySQL
  `local_infile` (**Action Required**) and `skip_show_database`; PostgreSQL
  `log_connections`, `log_disconnections`, `log_error_verbosity`,
  `log_min_messages`, `log_min_error_statement`,
  `log_min_duration_statement`, `log_statement`, `cloudsql.enable_pgaudit`
  (the level flags judged on their ordered scales: *warning or stricter*,
  *ddl or stricter*); SQL Server `external scripts enabled`, `cross db
  ownership chaining`, `remote access`, `contained database authentication`
  (**Action Required**), `user connections`, `user options`, trace flag
  `3625`. One row per failing flag with the CIS item; the fix is the
  `gcloud sql instances patch --database-flags=` line with **the flags
  already set included** (patch replaces the whole list). Read replicas
  inherit their primary's flags and are not repeated.
- **AlloyDB Posture** (Reliability & Resilience, every scope): a cluster
  without **automated backups** (**Action Required**) or without
  **continuous backup** (*Investigation*: no point-in-time recovery); a
  **zonal primary**; an instance with a **public IP**; an instance whose
  `sslMode` is not `ENCRYPTED_ONLY`; the PostgreSQL log flags
  (`log_connections`, `log_disconnections`, `log_error_verbosity`,
  `log_min_messages`, `log_min_error_statement`) — *Investigation
  Recommended*, each with its `gcloud alloydb … update` line.
- **KMS Keys** (Security & Identity, every scope): a **symmetric** key with
  no rotation period, with one above 90 days, or whose next rotation is
  overdue (CIS 1.10, *Investigation*; asymmetric, MAC, disabled and destroyed
  keys have no rotation and are not judged); a key ring or key whose IAM
  policy admits the public (**Action Required**, `KMS_PUBLIC_KEY`); a
  principal holding `roles/cloudkms.admin` **and** an encrypter or decrypter
  role on the same resource (CIS 1.11, separation of duties, *Investigation*)
  — from one `searchAllIamPolicies` on the KMS roles under the scope.
- **API Keys** (Security & Identity, every scope): a key **without an
  application restriction** (CIS 1.13), **without an API restriction** (CIS
  1.14), or **older than 90 days** (CIS 1.15) — *Investigation Recommended*,
  with the `gcloud services api-keys update` line. That a project has API
  keys at all is not a row. The inventory names API keys by project
  *number*; the rows name the project by ID (one resource search under the
  scope; if it fails the rows keep the number and *Projects not checked*
  says so).

### Changed

- README: the five catalogue entries, the scope-shard list, the scope note,
  the fixes paragraph; the roadmap row below. `VERSION = "18.4"`.

### Tests

- `tests/test_data_governance.py` (new): the engine and flag readers; the
  three flag packs on bare instances (what the engine defaults fail) and on
  set flags, the ordered PostgreSQL scales and an unknown level; replicas
  skipped and the patch line keeping the flags already set; public datasets
  by ACL and by policy search (deduplicated), public tables, the time-travel
  window; AlloyDB backups, zonal primary, public IP, TLS and log flags, a
  read pool not judged as a primary; KMS rotation (none, above 90 days,
  overdue, in time), asymmetric, MAC and destroyed keys skipped, public rings
  and keys, separation of duties at project and ring level; API keys by
  restriction and age, a key without a creation time, project numbers
  resolved to IDs; the five checks end to
  end with the inventory and both searches, the all-clear rows, the Error,
  and a failed policy search left under *Projects not checked* with the rest
  of the check standing; the five names as new checks.
- Synthetic world (drawn last): per project BigQuery datasets (a short
  time-travel window, a public one), Cloud SQL flags bare or the CIS pack, an
  AlloyDB cluster of two shapes, a KMS ring with an unrotated or a rotated
  key beside a signing key, a user holding both KMS roles, API keys
  restricted or not; the provider answers the public-member and KMS-role
  policy searches. 1,064 tests.

### Upgrade notes

- Expect, on the first scan: the five names as *new check*. Where a
  PostgreSQL instance runs on its default flags, the Cloud SQL Flags check
  will list the four items the defaults fail; where API keys were created
  without restrictions, API Keys will list them — those are the cases behind
  the release.
- Nothing to grant and no new API: inventory reads and IAM-policy searches
  under `roles/cloudasset.viewer`.

---

## v18.3 — Network edge & reachability

The second themed release. Interconnect and VPN outages and VM-to-VM
connectivity are the widest networking clusters in the support-case evidence,
and CIS §3 was the largest block of the benchmark the tool did not read. Every
item is a setting in Cloud Asset Inventory — one listing per check under the
scanned scope — except the *state* of a VPN tunnel, re-read from the Compute
API per project that has tunnels (the inventory's copy of state can lag). No
new API, no new role.

### Added

- **Hybrid Connectivity** (Reliability & Resilience, every scope): a VPN
  tunnel that is not `ESTABLISHED` (**Action Required**, with the API's
  detailed status); an HA VPN gateway whose tunnels all sit on one interface,
  or that has none (**Action Required** — no redundancy, no SLA); a Classic
  VPN gateway (*Investigation*: deprecated); Dedicated/Partner Interconnect
  with fewer than two attachments per Cloud Router or all in one edge
  availability domain, or an attachment that is not `OS_ACTIVE` (**Action
  Required**); a Cloud Router with one BGP peer for two links
  (*Investigation*). Rows `Project, Network, Region, Resource, Issue, Detail,
  Fix`. Tunnel state comes from `vpnTunnels.aggregatedList` per project with
  tunnels; a failed read keeps the inventory copy and says so.
- **Load Balancer Edge** (Security & Identity, every scope): an **HTTP-only**
  external load balancer (a forwarding rule to a target HTTP proxy whose URL
  map has no HTTPS rule; `HTTP_LOAD_BALANCER`); **weak TLS** — a target HTTPS
  or SSL proxy without an SSL policy, or with one below TLS 1.2 or on the
  `COMPATIBLE` profile (CIS 3.9; `WEAK_SSL_POLICY`); an external backend
  service, global or regional, **without Cloud Armor** or **without logging**
  (`LOAD_BALANCER_LOGGING_DISABLED`) — all *Investigation Recommended*, each
  with its `gcloud` line. Internal load balancers are not judged.
- **DNS Posture** (Security & Identity, every scope): a public zone with
  DNSSEC off (CIS 3.3, *Investigation*); a zone signing with `RSASHA1` (CIS
  3.4/3.5, **Action Required**); a VPC network without a Cloud DNS server
  policy that enables logging (CIS 2.12, *Investigation*).
- **VPC Flow Logs** (Operational Excellence & Observability, every scope): a
  VM subnet (`PRIVATE` purpose; proxy-only, PSC, NAT and GKE endpoint subnets
  exempt) without flow logs (CIS 3.8, *Investigation*), with the sampled
  (`0.5`, 5-second aggregation) fix.
- **VPC Peering & Cloud NAT** (Reliability & Resilience, every scope): a
  peering that is not `ACTIVE` (the other side has not peered back); peered
  networks with different MTUs (absent = 1460; reported once per pair; private
  services access and other Google-managed peers not judged); a Cloud NAT
  with logging off; a Cloud NAT with static port allocation at the default 64
  ports per VM — all *Investigation Recommended*. Secure Web Proxy's
  auto-generated NATs are Google's and are not judged.

### Changed

- **Open Firewall Rules**: hierarchical and network **firewall policies**
  under the scope (one inventory listing of
  `compute.googleapis.com/FirewallPolicy`) are judged like VPC rules — enabled
  *ingress allow* rules from `0.0.0.0/0` or `::/0`, the verdict by port family,
  the policy named with where it is attached, the `firewall-policies rules
  update` fix; a folder or project scan sees the policies under it, not the
  ones inherited from above. In a sharded scan the scope shard reads the
  policies and the project shards the VPC rules (`registry.SPLIT_CHECKS`).
  `RESHAPED_CHECKS["Open Firewall Rules"] = ("18.3", RULE_CHANGED)`.
- **VPC Configuration**: a **legacy network** (`IPv4Range`, no subnets) is
  **Action Required** (CIS 3.2) — no subnets, no peering, no Private Google
  Access; the fix is a new VPC network and migration.
  `RESHAPED_CHECKS["VPC Configuration"] = ("18.3", RULE_CHANGED)`.
- README: the five catalogue entries, the two extensions, the scope-shard
  list; the roadmap row below. `VERSION = "18.3"`.

### Tests

- `tests/test_network_edge.py` (new): asset facts and link keys across API
  versions; the production gateway (one tunnel, interface 0, down) and a
  redundant one; one BGP peer for two links; a gateway without a tunnel; a
  Classic gateway; Interconnect single, same-domain, redundant and
  non-active; the fresh tunnel read and its failure; HTTP-only, weak TLS
  (none / COMPATIBLE / TLS 1.1 / MODERN / RESTRICTED), Cloud Armor and
  logging, internal schemes ignored, regional backend services; DNSSEC off,
  RSASHA1, private zones, logging policies with and without logging; flow logs
  by purpose and the legacy field; peerings (inactive, MTU mismatch once per
  pair, peers outside the listing), NAT defaults and the `swg-autogen-`
  exemption; the five checks end to end, the all-clear rows and the Error;
  firewall-policy rules by port family, association and kind (network,
  hierarchical, regional); legacy networks; the 18.3 lines.
- Synthetic world (drawn last): per project an MTU, a peering (active or
  not), flow logs per subnet, a NAT (default or tuned) beside a Secure Web
  Proxy one, HA VPN with one or two tunnels, a Classic gateway, Interconnect
  single or redundant, an external load balancer of three shapes, public zones
  of three shapes, a DNS logging policy, a network firewall policy with an open
  rule, a legacy network; the provider answers `vpnTunnels.aggregatedList`.
  A listing the inventory refuses for one asset type is retried type by type
  (the first canary named `RegionTargetHttpProxy`, which is no asset type, and
  the whole check read Error). 1,052 tests.

### Upgrade notes

- Expect, on the first scan: the five names as *new check*; *Open Firewall
  Rules* and *VPC Configuration* as *rule changed*. Where an HA VPN runs on
  one tunnel, where a public zone is unsigned, where subnets have no flow logs
  and a NAT runs on its defaults, the new checks will say so — those are the
  cases behind the release.
- Nothing to grant and no new API: inventory reads under
  `roles/cloudasset.viewer`, the tunnel state under
  `roles/compute.networkViewer`.

---

## v18.2 — GKE upgrade readiness & hygiene

The first themed release of the check-sourcing programme. The widest GKE
cluster in the support-case evidence is *upgrades* — node pools upgraded in
business hours because nobody set a maintenance window, freezes that nobody
declared as an exclusion, upgrades that stall on a PodDisruptionBudget no
drain can satisfy, security bulletins nobody was told about — and none of its
causes was checked. Every one is a setting, not an event: readable from the
cluster resource the v17.1 checks already list in Cloud Asset Inventory, and
from the Kubernetes `PodDisruptionBudget` objects the inventory indexes for
every GKE cluster. So v18.2 adds two checks and four hardening rows from two
inventory listings, with no cluster credentials, no Kubernetes API call and no
new role.

### Added

- **GKE Upgrade Readiness** (Reliability & Resilience, every scope): from the
  cluster listing — **no maintenance window** (GKE chooses the time) and
  **upgrade notifications off** or filtered without the upgrade events and
  security bulletins, *Investigation Recommended* with the `clusters update`
  lines; an **active maintenance exclusion** as a calendar row (*Informational*:
  scope and the date upgrades resume); a Standard node pool whose surge
  settings **lose capacity** during an upgrade (`maxUnavailable ≥ 1`) or that
  sits **two minors behind** its control plane (*Investigation* when auto-upgrade
  is off — the control plane cannot take its next minor until the pool moves;
  *Informational* when GKE will move it). From one listing of
  `policy.k8s.io/PodDisruptionBudget` — a budget that **can never be
  satisfied** (`maxUnavailable: 0`, `minAvailable: 100%`, or an absolute minimum
  not below the pods it expects) is **Action Required**: no node running that
  workload can ever be drained, upgrades stall (GKE waits an hour per node,
  then proceeds) and scale-down never happens; a budget **allowing no
  disruption right now** (`disruptionsAllowed: 0` with pods expected) is
  *Investigation Recommended* — a snapshot, since the inventory lags the
  cluster by minutes. Budgets in `kube-*`, `gke-*`, `gmp-*` and
  `config-management-*` are Google's and are not judged; Autopilot clusters
  get the cluster-level rows only. One shape for every row — `Project,
  Cluster, Location, Node Pool, Issue, Detail, Fix` — a budget named
  `namespace/name` in `Node Pool` with its spec and status in `Detail` (the
  first canary wrote wider budget rows that the table and the CSV header
  could not show); the record's status is the worst row. A budget
  listing that fails leaves the drain rule under *Projects not checked* and
  the rest of the check standing. The clusters themselves are re-read from
  the GKE API (`clusters.list` per project, the call GKE Hygiene already
  makes): the inventory's copy of a cluster can lag a maintenance-policy
  change by hours — the probe cluster's exclusion was still absent from it
  half an hour later — and a window set today must clear the row today; a
  project whose listing fails keeps the inventory copy and says so.
- **GKE Observability** (Operational Excellence & Observability, every scope):
  **system metrics off** (`SYSTEM_COMPONENTS` not among the monitoring
  components; CIS GKE 5.7.1 / `MONITORING_DISABLED`) is **Action Required**;
  **control-plane metrics** (API server, scheduler, controller manager) off,
  **Managed Service for Prometheus** off and, on Standard clusters, **NodeLocal
  DNSCache** off are *Investigation Recommended* — each with the
  `--monitoring=` value that keeps what is already on, `--enable-managed-prometheus`
  or `--update-addons=NodeLocalDNS=ENABLED`. The legacy `monitoringService`
  field is read when a cluster predates the component configuration.

### Changed

- **GKE Node Hardening**: four more rows, all *Investigation Recommended* —
  **integrity monitoring off** on a node pool (`INTEGRITY_MONITORING_DISABLED`,
  `--shielded-integrity-monitoring`), **intra-node visibility off**
  (`INTRANODE_VISIBILITY_DISABLED`, `--enable-intra-node-visibility`), a
  **routes-based** cluster (`IP_ALIAS_DISABLED`) and an **alpha** cluster
  (`ALPHA_CLUSTER_ENABLED`), the last two with the sentence that says nothing
  can be changed in place. The all-clear row names the new items.
  `RESHAPED_CHECKS["GKE Node Hardening"] = ("18.2", RULE_CHANGED)`: the first
  scan after the upgrade says *rule changed*, not *new rows*.
- `gke_security.list_cluster_facts` is the one cluster listing both modules
  share; `hardening_fix` renders a pool line, a cluster line or a sentence.
- README: the two catalogue entries, the hardening additions, the scope-shard
  list; the roadmap table below (v18.6 numbered). `VERSION = "18.2"`.

### Tests

- `tests/test_gke_operations.py` (new): GKE timestamps; the window and the
  exclusions with a fixed clock (in force, over, default scope, unreadable);
  the notification gap (off, no filter, a filter without bulletins); surge
  settings and version skew; the production cluster's rows and a ready
  cluster's none; pools, exclusions and Autopilot; budget assets (regional and
  zonal names, every spec form, the status snapshot, the system namespaces,
  the fix); the observability rules, the `--monitoring=` value that keeps
  what is on, the legacy field, Autopilot; the status ladder with
  Informational; both checks end to end from two listings, with no cluster,
  with a failed budget listing and with a failed cluster listing; the
  hardening additions and the 18.2 line.
- `tests/test_gke_security.py`: the hardened fixture is VPC-native with
  intra-node visibility; the weak cluster's new row; integrity monitoring,
  routes-based and alpha as sentences; the new all-clear text.
- Synthetic world (drawn last; Kubernetes numbers as the inventory delivers
  them, protobuf floats — the first canary read none of the budgets until the
  parser accepted `0.0`): per cluster a window, an exclusion, the
  notification state, `maxUnavailable`, a lagging pool, integrity monitoring,
  intra-node visibility, the metric components, Managed Prometheus, the DNS
  cache, and PodDisruptionBudget assets (blocking, exhausted, healthy, a
  `kube-system` one that must not be judged). 1,040 tests.

### Upgrade notes

- Expect, on the first scan: *GKE Upgrade Readiness* and *GKE Observability*
  as *new check*; *GKE Node Hardening* as *rule changed*, typically gaining an
  intra-node-visibility row per Standard cluster.
- Nothing to grant and no new API: both listings are Cloud Asset Inventory
  reads under `roles/cloudasset.viewer`.

---

## v18.1 — Legacy checks revalidated: what is loose

v18 corrected the inherited checks that said something false. v18.1 is the
second half of that review: the checks that were true but loose — rules that
could not fail on any real organization, rules that asked for more than the
practice they cite, rules that asked for less. **Organization Log Sink**
counted the `_Required` and `_Default` sinks every organization is born with,
so it never failed, while the thing CIS 2.2 asks for — an aggregated export of
the audit logs — went unexamined; **Cloud Storage Versioning** flagged every
bucket without versioning, soft delete (on by default since 2024) and lifecycle
rules notwithstanding, and so on a real organization every row was noise and
the one bucket that must have versioning, a log-sink destination, was
indistinguishable from the rest; **VPC Configuration** flagged proxy-only and
Private Service Connect subnets, which cannot have Private Google Access, and
listed each auto-mode subnet of a `default` network as its own finding;
**Essential Contacts** counted contacts whose address had bounced and ran in an
organization scan only; the **cost recommendations** carried no priority and no
fix; **GKE Hygiene** did not read auto-repair; **Quota Utilization** never saw a
project-global quota; nothing read the Data Access audit configuration at all.
This release tightens each rule to what the practice actually asks, adds the
**Data Access Audit Logs** check, and — the request behind the policy table —
makes the Organization Policies best-practices table something an operator can
change without a redeploy: the table ships inside the image, a `gs://` or
`https://` URL replaces it, and an overrides file in the results bucket amends
it row by row. The Changes card says *rule changed* for every rule touched.

### Changed

- **Cloud Storage Versioning** (Reliability): the rule asks for versioning
  where CIS 2.3 and Security Health Analytics ask for it — on a bucket a log
  sink writes to (one Asset Inventory `logging.googleapis.com/LogSink` listing
  of the scope, shared by every project) — *Action Required* with the
  `--versioning` line; any other bucket without versioning is a row only when
  nothing protects its objects at all (soft delete off, no lifecycle rule, no
  retention policy) — *Investigation Recommended* with the `--versioning
  --soft-delete-duration=7d` line; a bucket with soft delete of seven days or
  more, a lifecycle rule or a retention policy is no row (a retention policy
  and versioning exclude each other, so a retention bucket is never asked for
  versioning). `Project`, `Bucket`, `Protection`, `Fix`. When the sink
  listing fails, the sink-destination rule is reported under *Projects not
  checked* and the rest of the check still runs. Signature `(scope, scope_id,
  all_projects, job_id)`.
- **VPC Configuration** (Security): one `subnetworks.aggregatedList` per
  project instead of one listing per region; proxy-only, PSC, private NAT and
  peer-migration subnets are not judged (they cannot have Private Google
  Access), nor is the subnet GKE creates for a cluster's private control-plane
  endpoint (`gke-…-pe-subnet`, Google's, no VM in it — the probe cluster
  showed it); IPv6-only access counts as access; the `default` network is one
  *Action Required* row with its auto-mode subnets lacking PGA counted into it
  rather than listed; any other subnet without PGA is *Investigation
  Recommended* with `Region` and the `subnets update
  --enable-private-ip-google-access` line.
- **Uniform Bucket-Level Access**: the `--uniform-bucket-level-access` fix on
  every row.
- **Organization Log Sink** (Operations): the built-in `_Required` and
  `_Default` sinks no longer count; a customer sink qualifies when it is
  enabled, includes children and its filter admits the audit logs — one row per
  customer sink (`Sink Name`, `Destination`, `Filter`, `Children`, `State`,
  `Assessment`); a qualifying sink is Compliant, customer sinks that all fall
  short *Investigation Recommended* (each with the fix), none *Action
  Required*; every page of the listing.
- **Data Access Audit Logs** (Operations, **new**, every scope): the
  `auditConfigs` of the scanned resource's IAM policy — the organization's in
  an organization scan; the project's or folder's and its ancestors' otherwise,
  the effective configuration being their union — judged against CIS 2.1 /
  `AUDIT_LOGGING_DISABLED`: `ADMIN_READ`, `DATA_READ` and `DATA_WRITE` on for
  `allServices` with nobody exempted is Compliant; nothing configured anywhere
  *Action Required*; a partial configuration or an exemption *Investigation
  Recommended*. One row: `Resource`, `Log types on for all services`,
  `Missing`, `Exemptions`, `Configured at`, `Services configured
  individually`, the cost caveat on `DATA_READ`, and the `set-iam-policy`
  recipe. Scope-level (one shard runs it).
- **Essential Contacts** (Reliability): runs in every scope — the
  organization's own contacts, a folder's or a project's *effective* contacts
  (`contacts.compute`, inherited ones included); a contact whose address
  bounced (`validationState: INVALID`) does not count and the row says how many
  were left out; the Compliant row names who receives each required category
  (`Contacts`). Leaves the organization-only list.
- **Cost-Saving Recommendations** (Cost): every row carries the
  recommendation's `Priority` (`P1` … `P4`, or *unrated*) and a `Fix` — the
  `gcloud` line that applies it, or the console path where the action is a
  purchase; the verdict follows the priority (`P1`/`P2` *Action Required*,
  `P3`/`P4` *Investigation Recommended*, unrated *Action Required* as before);
  a record's status is the worst of its rows. **MIG Rightsizing**
  (`google.compute.instanceGroupManager.MachineTypeRecommender`, zonal) joins
  the recommenders — fourteen in all.
- **GKE Hygiene** (Reliability): a node pool with auto-repair off is an
  *Action Required* row with the `--enable-autorepair` line
  (`AUTO_REPAIR_DISABLED`); the all-clear row says so.
- **Quota Utilization (>80%)** (Operations): the project-global Compute quotas
  (`FIREWALLS`, `NETWORKS`, `ROUTES`, `IMAGES`, `SNAPSHOTS`, …) from
  `projects.get`, `Region` *global*, next to the regional ones.
- **VPC Firewall Complexity (>150 Rules)** retired: a rule count is not a
  posture signal (firewall policies and rule quality are the network release's
  subject); the Changes card reads *No longer checked*.
- **Organization Policies — the policy table**: the best-practices table ships
  inside the image (`assets/gcp_best_practices.csv`, 138 policies in 21
  categories, digest `348c39eaaf95`) and is the default;
  `BEST_PRACTICES_CSV_URL` takes an `https://` URL as before or a `gs://`
  object the service account can read; and an **overrides file** at
  `gs://<results bucket>/config/best_practices_overrides.csv` — the same
  columns as the table — is merged into whichever table is in use by
  constraint ID: a row with an ID the table has replaces that row in place, a
  new ID is appended under the file's category, and `Skip` in the *Recommended
  to set* column removes the constraint from the evaluation. The report's
  Organization Policies table carries a provenance line — *Policy table:
  bundled table (138 rows, 348c39eaaf95) · 2 overrides, 1 skipped (gs://…)* —
  so two reports are never compared without knowing what each was scored
  against. An overrides file that cannot be read or parsed is the check's
  *Error*, not a table quietly scored without it. No redeploy for any of it.
- `changes.RESHAPED_CHECKS`: *rule changed* at 18.1 for Cloud Storage
  Versioning, VPC Configuration, Organization Log Sink, Essential Contacts,
  Quota Utilization, GKE Hygiene and the thirteen pre-existing cost
  recommenders; Data Access Audit Logs and MIG Rightsizing are *new check* by
  the existing rule.
- README: the catalogue lines above, `BEST_PRACTICES_CSV_URL` in the
  configuration reference, and a *Customising the policy table* section.
  `VERSION = "18.1"`.

### Tests

- `tests/test_loose_rules.py` (new): the versioning protection ladder
  (versioned, soft-deleted, lifecycle, naked, sink destination, retention
  policy, a client that reports nothing), sink destinations from the asset
  listing,
  the one sink listing per scan and the failed listing; VPC rows (proxy-only
  skipped, the default network folded, PGA rows) and the aggregated listing;
  log-sink rows (built-ins ignored, disabled, no children, a narrowing filter,
  a qualifying sink) and paging; the audit-config union, exemptions and the
  hierarchy read; invalid contacts and the effective contacts of a project;
  cost priorities, fixes and the fourteen recommenders; GKE auto-repair; the
  project-global quotas; the retired firewall-complexity check; the bundled
  table, overrides merging (replace, append, skip), provenance through
  `fetch_best_practices`, the summary and a `gs://` or `https://` source; the
  18.1 lines of `RESHAPED_CHECKS`.
- `tests/test_beta_checks.py`: no check remains at parity with beta v1; the
  four it covered are held to their own expectations instead.
- Synthetic world (drawn last): unprotected, sink-destination and retention
  buckets, a proxy-only subnet, auto-repair off, project audit configs, a
  project contact and an invalid organization contact; the provider answers
  `subnetworks.aggregatedList`, `projects.get` quotas, `LogSink` assets,
  `contacts.compute`, folder IAM policies, recommendation priorities, and
  serves the synthetic policy table. The sharded-versus-inline end-to-end test
  freezes the synthetic world's clock (two scans a minute apart differed in
  the rows that show a time — the flake noted since v17.3). 1,024 tests.

### Upgrade notes

- The first scan after the upgrade shows *rule changed* for the checks above.
  Expect: Cloud Storage Versioning to lose every soft-delete-protected bucket
  and keep (or gain) the log-sink destinations; VPC Configuration to lose its
  proxy-only rows; Organization Log Sink to stay Compliant where a real
  aggregated export exists and to turn *Action Required* where only the
  built-in sinks did; **Data Access Audit Logs** to read *Action Required* on
  most organizations (few turn it on at the top); Essential Contacts to appear
  in folder and project scans; cost rows to gain `Priority` and `Fix`.
- Nothing to grant and no new API: the LogSink asset type, `contacts.compute`,
  `folders.getIamPolicy`, `projects.get` and `subnetworks.aggregatedList` are
  covered by the roles the README already lists.
- `BEST_PRACTICES_CSV_URL` unset now means the bundled table (before, the
  GitHub copy at `GITHUB_POLICY_TABLE_URL`); set it to that URL to keep reading
  from GitHub.

---

## v18 — Legacy checks revalidated

The refactor kept the behaviour of the twenty-two checks it inherited and froze
it in parity tests; it never asked whether the behaviour was right. v18 asked,
check by check, against today's APIs and against Security Health Analytics on
a real organization, and found that several of them could not be passed, could
not be failed, or said something false: **Security Command Center Status** read
`tier` from a resource that has no such field, so every organization — Premium
and Enterprise included — read *Action Required: STANDARD*; **Monitoring Alert
Coverage** looked for `cloud_sql`, `gke_cluster` and `load_balancer` in filters
that never contain those words, so every project with those assets failed on
every scan; **Organization Policies** scored 62 list constraints that it could
only ever read as *Unsupported*; **Cloud SQL Security** read the deprecated
`requireSsl` and flagged the recommended `ENCRYPTED_ONLY` mode while missing
`0.0.0.0/0` in the authorized networks; **Open Firewall Rules** counted deny
rules — the hardening pattern — as findings; **Primitive Roles** listed the
Google APIs service agent, Editor by design in every project, so no real
organization could pass; **OS Config Agent Coverage** turned a disabled API, a
missing permission or OS inventory management being off into "every VM is not
reporting"; **VM External IPs** flagged stopped instances whose address had
long been released. This release is the correction: rows that disappear were
never true, rows that appear were always there, and the Changes card says *rule
changed* rather than *resolved* or *new*. The next release, v18.1, is for what
is merely loose (the rules that should ask for more).

### Changed

Every revalidated check now has a pure rule over the API's own JSON, unit-tested
on fixtures of the real shapes, a verdict that distinguishes what is wrong
(*Action Required*) from what deserves a look (*Investigation Recommended*), and
a `Fix` line on every row where one exists.

- **Security Command Center Status**: reads `securitycenter v1beta2
  organizations.getSubscription`, the resource that carries the tier. Premium
  and Enterprise are Compliant; Standard is *Investigation Recommended* with a
  neutral note on what the paid tiers add; a 404 (never activated) is *Action
  Required*; the API being disabled in the scanner's own project is an *Error*,
  not the organization's fault.
- **Organization Policies**: the best-practices table's `Type` column is read.
  A list constraint is compliant when a policy configures it (denies all
  values, or names allowed or denied values); `allValues: ALLOW` and
  `restoreDefault` are not configurations; a "won't have" constraint passes
  when unset. *Unsupported* is gone. A hierarchy level that cannot be listed is
  an *Error* instead of every policy silently reading *Not Configured*. (The
  reader stays on Resource Manager v1: the probe showed it does return managed
  constraints.)
- **Primitive Roles (Owner or Editor)**: policy version 3 (conditions shown),
  Google-managed service agents excluded, and the verdict by kind of holder — a
  user-managed service account, a consumer account, a whole domain or the
  public (on any role) *Action Required*; a person, a group or a default
  service account *Investigation Recommended*. `Type`, `Condition` and `Fix`
  columns. The empty-project-list Error writes under the check's own name.
- **Critical Org-Level Roles**: Editor, Billing Administrator, Security
  Administrator, Organization Role Administrator and Folder Administrator join
  Owner and Organization Administrator; groups are the practice (a Compliant
  inventory), a person *Investigation Recommended*, a service account, consumer
  account, domain or public principal *Action Required*; Google-managed agents
  excluded; `Fix` lines. **Public Org-Level Access** is unchanged in rule; both
  write their errors under their own names (`Organization IAM Policy Check`
  retired).
- **Service Account Key Rotation**: disabled keys, expired keys and the keys
  of disabled accounts are not rows; rows carry `Key ID`, `Created`, `Age
  (days)`, `Expires`, `Origin` and the `keys disable` line; a project whose
  keys could not be listed is under *Projects not checked* instead of turning
  the check *Action Required* with an error row.
- **Public GCS Buckets**: Public Access Prevention is read — on the bucket, and
  the effective `storage.publicAccessPrevention` organization policy, once per
  project with an open bucket; a blocked binding is *Investigation Recommended*
  (dormant: remove it), an unblocked one *Action Required*; one row per public
  principal with its roles and the `remove-iam-policy-binding` /
  `--public-access-prevention` lines.
- **Open Firewall Rules**: enabled *ingress allow* rules from `0.0.0.0/0` or
  `::/0`, every page; `Protocols/Ports`, `Source Ranges`, `Targets`,
  `Priority`; *Action Required* for everything, ranges and the sensitive ports
  (the Security Health Analytics `OPEN_*_PORT` family), *Investigation
  Recommended* for web ports and ICMP only; the fix is the IAP TCP-forwarding
  range for SSH/RDP rules. Deny rules are never findings; firewall policies are
  a later release.
- **Cloud SQL Security**: `sqladmin v1`, every page; `sslMode` decides TLS
  (`requireSsl` only when `sslMode` is absent); three rules — *TLS not
  enforced* and *Open to the internet* (an authorized network of `0.0.0.0/0`
  or `::/0` on a public IP) *Action Required*, *Public IP* alone *Investigation
  Recommended*; `Kind` (primary/replica) and `Version` columns; the patch line
  (a replica's names its primary).
- **VM External IPs**: an instance is a row when it holds an address (`natIP`
  or `externalIpv6`), one row per instance with `Zone`, `Status`, `External
  IPs`, `Kind` (GKE node / MIG member / standalone) and the fix for that kind;
  GKE nodes *Investigation Recommended*.
- **OS Config Agent Coverage**: one `list_inventories` per zone (the
  permission `roles/iam.securityReviewer` actually grants) instead of one
  `get_inventory` per VM; `FailedPrecondition` → the project's one *OS
  inventory management is disabled* row, a disabled OS Config API → likewise,
  a 403 or 429 → *Projects not checked*; Autopilot (`gk3-`) nodes, Dataflow
  and Batch workers excluded with GKE and Dataproc; one row per VM with `Zone`
  and the `enable-osconfig` line.
- **Monitoring Alert Coverage**: enabled policies, every page, every kind of
  condition (threshold, absence, log match, MQL, PromQL, SQL), matched on
  `cloudsql_database`/`cloudsql.googleapis.com`, `k8s_`/`kubernetes.io/`/
  PromQL, `loadbalancing.googleapis.com`/`_lb_rule`,
  `serviceruntime.googleapis.com/quota`; *Investigation Recommended*; the
  quota row only for projects running one of the three asset families.
- **GKE Hygiene**: the diagnosis recommender is asked once per location with
  the ACTIVE filter and every page, and its recommendations are attributed by
  `targetResources` (before, each was listed under every cluster of the
  location); recommendations are *Investigation Recommended*; a Recommender
  failure costs the project its recommendation rows, not its cluster rows;
  `UNSPECIFIED` is no channel; fix lines.
- **Network Insights** (eight names): asked at `global` and the active regions
  (VPC insights live at `global`, GKE insights at the cluster's region; zones
  answer nothing); ACTIVE insights only; a `Severity` column and the verdict by
  it — Critical/High *Action Required*, Medium *Investigation Recommended*,
  Low *Informational*; an insight type that answered with nothing writes its
  all-clear row instead of nothing.
- **Cost-Saving Recommendations**: every listing asks for
  `stateInfo.state = ACTIVE` (applied and dismissed recommendations stop
  persisting); a recommendation that costs more (an upsize) shows *none (costs
  N more)* instead of a negative saving the Scorecard subtracted; **Idle Load
  Balancers** retired — `google.compute.loadBalancer.IdleResourceRecommender`
  is not a recommender (76 exist; none for load balancers), so it never
  reached a verdict.
- **Miscellaneous**: firewall complexity reads every page and writes its
  all-clear row; the organization-level listings' failures are *Error* rows
  under *Recent Changes* and *Unattended Projects* (before, one error row was
  appended to both as a finding); a project whose recent changes cannot be
  read is under *Projects not checked*; *Unattended Projects* is
  *Investigation Recommended*, names the project by its target resource and
  writes a Compliant row when Active Assist flags none; *Recent Changes*
  writes a note when there were none.
- **Standalone VMs (Not in MIGs)**: *Informational*.
- **Quota Utilization (>80%)**: one `regions.list` per project (it already
  carries every region's quotas) instead of one `regions.get` per region;
  `COMMITTED_*` quotas excluded.
- **Organization Log Sink**: its error writes under its own name (`Log Sink
  Check` retired); the Action Required row carries the `sinks create` line.
- **Sharded scans**: a check whose rows split between *Action Required* and
  *Investigation Recommended* across shards is merged into one record under
  the worst, as a single scan writes it (`categories.merge_shard_findings`).
- `changes.RESHAPED_CHECKS`: *rule changed* at 18 for Organization Policies,
  Security Command Center Status, Primitive Roles, Critical Org-Level Roles,
  Service Account Key Rotation,
  Public GCS Buckets, Open Firewall Rules, Cloud SQL Security, VM External IPs,
  OS Config Agent Coverage, Monitoring Alert Coverage, GKE Hygiene, Quota
  Utilization and the eight Network Insights names; *rows changed* for
  Unattended Projects.
- README: the Security, Reliability and Operations catalogues rewritten for
  the fourteen checks; the two kinds of fixes paragraph; the roadmap
  reconciled (below). `VERSION = "18"`.

### Tests

- `tests/test_revalidated_checks.py` (new, 40-odd): principal kinds; primitive
  and critical role rows and both checks end to end (version 3, agents only →
  Compliant, errors under their own names); the SCC tier row and the four
  outcomes of the check; stale-key rows with a fixed clock and the
  *Projects not checked* path; public-bucket rows under the three PAP states
  and the one-read-per-project rule; firewall rows (allow-all, deny-all,
  `::/0`, web, RDP+range, DNS, QUIC, egress, disabled, internal, IAP) and
  paging; Cloud SQL rows for every `sslMode`, the open network, the public IP,
  a replica, the legacy field and an instance without settings; external-IP
  rows (running, stopped, static on stopped, IPv6, GKE node, MIG member, two
  interfaces); OS Config exclusions, inventory matching and the four error
  routes; real Monitoring filters across condition kinds; unattended-project
  resolution and the miscellaneous records; committed quotas; the retired
  recommender and the upsize; GKE Hygiene rows, attribution and the
  recommender failure; Network Insights locations, severities and the
  all-clear row; the parser's `Type` column, list-policy evaluation, the
  evaluation by type and the unreadable level; the v18 lines of
  `RESHAPED_CHECKS`.
- `tests/test_beta_checks.py`: VPC Configuration and UBLA stay at parity with
  beta v1; Cloud SQL Security and VM External IPs leave it by design (the
  parity pinned the defects) and keep the skipped-project contract.
- Synthetic world (drawn last): stopped VMs, disabled keys, Cloud SQL
  authorized networks, PAP-enforced buckets; the provider answers the
  subscription, `getEffectiveOrgPolicy`, inventories per zone, real
  Monitoring filters, `allowed`/`denied`/`direction` on firewall rules,
  `sslMode`, instance IDs, insight severities, `targetResources`; the
  best-practices table carries `Type` and two list constraints. 996 tests.

### Upgrade notes

- The first scan after the upgrade shows *rule changed* for the checks above
  instead of listing their old rows as resolved. Expect: Security Command
  Center Status to read *Standard* (Investigation) where it read *Action
  Required*, the Primitive Roles and Critical Org-Level Roles rows to lose the
  Google-managed agents, Cloud SQL rows to disappear for `ENCRYPTED_ONLY`
  instances, Open Firewall Rules to lose deny rules, Monitoring Alert Coverage
  to clear where real alert policies exist, OS Config Agent Coverage to turn
  into one row per project where VM Manager is off (or into *Projects not
  checked* where the scanner may not read inventories), and *Idle Load
  Balancers* to read *No longer checked*.
- Nothing to grant and no new API: `securitycenter v1beta2`,
  `getEffectiveOrgPolicy` and `osconfig.inventories.list` are covered by the
  roles the README already lists.

---

## v17.3 — Incidents as evidence

A release that began with a question from the field: should a posture report
hand a customer a list of Google's incidents? The production report answered
it — 42 incidents in 90 days for a three-project organization, 40 of them
*Related* rather than *Impacted*, most of them global and niche, and the
Scorecard's Stability line reading *42 incidents impacted you in 90 days*: our
word *impacted* for rows Personalized Service Health calls *Related*. So two
things at once. The briefing steps back: nothing about Google's incidents on
the Scorecard, in its Markdown copy or in the executive summary; by default it
lists what PSH classed *Impacted* plus the *Related* incidents confined to
specific locations, counts the global ones in a note, and can be switched off.
And the incidents become the customer's finding: **Incident Exposure** joins
each location-specific incident with the customer's own zonal assets in the
locations and the product it concerned — *what you ran, without failover, where
the product you ran had an incident* — one row per asset, with the incidents as
evidence and the fix. It needs the footprint to carry its locations, so **GKE
Cluster Resilience** arrives with it (zonal control planes and single-zone
node pools, a gap the tool never flagged), the Cloud SQL HA rows gain their
Region and the MIG rows their Zone. Also in this release: five v17.1 columns
rendered Python lists (`['a', 'b']`, `[]`) in the page and the CSV — fixed at
the source, with a guard — and the Fix block says what it is.

### Added

- **Incident Exposure** (Reliability & Resilience; `app/checks/exposure.py`):
  derived at categorization — the one place a sharded and an inline scan both
  pass through — from the Service Health briefing's rows and the resilience
  checks' rows; no API call. Matching: the incident is location-specific
  (fewer than 30 regions; PSH enumerates every region for a product-wide
  event), its product maps to the asset's kind (Compute Engine and Persistent
  Disk → zonal MIGs and single-region snapshots; GKE → zonal control planes and
  single-zone node pools; Cloud SQL → zonal instances), the asset's project is
  one the incident touched and its location one the incident named (a zone
  counts for its region on both sides). Rows are asset-centric (snapshots
  grouped per project and location), `Project · Asset · Location · Incidents ·
  Fix`; *Action Required* with rows, *Compliant* when incidents met footprints
  that all had failover, *Informational* when no location-specific incident in
  a mapped product touched the scanned projects. A note under the table counts
  the location-specific incidents in products the tool has no footprint for.
  The briefing's Error is this check's Error; with the briefing off, the check
  does not exist. An asset's identity is the asset, not its incidents
  (`changes.EXCLUDED_COLUMNS`): the window slides, the finding stays.
- **GKE Cluster Resilience** (Reliability & Resilience): the fifth record of
  the v17.1 cluster listing — a zonal control plane (the location is a zone),
  each node pool whose nodes are all in one zone; Autopilot skipped. The fix
  for a pool is the `--node-locations` line; for a control plane, the truth:
  create a regional cluster and migrate.
- The Scorecard's Stability line, when Incident Exposure has rows: *N assets
  without failover in locations that had incidents*.
- `SERVICE_HEALTH_INCIDENTS` (`on`/`off`): `off` removes the briefing and
  Incident Exposure; the API calls still run for the coverage check.
- A record may carry a `Note`, rendered under its table (the briefing's global
  count, Incident Exposure's unmapped products); the shards' omitted incident
  IDs are unioned like their rows, so the count is one count.
- The briefing's rows carry `Scope` (*Global* / *Location-specific*); the
  incident's second line reads *Global · 46 regions* or names its regions.

### Changed

- **Service Health Incidents**: `SERVICE_HEALTH_RELEVANCE` defaults to
  `IMPACTED`; whatever the setting, the *Related* incidents confined to
  specific locations are listed and the global ones are counted in the note
  (`IMPACTED,RELATED` lists them all, as before). A project's copy with any
  other relevance never puts that project on the row. The *impacted you* tally
  is gone from the Scorecard and its Markdown copy; the executive summary's
  prompt never contains the briefing (`gemini.SUMMARY_EXCLUDED_CHECKS`).
- **Cloud SQL High Availability** rows gain `Region`, **MIG Resilience
  (Zonal)** rows gain `Zone` (as a name, whatever the API's URL form): the
  footprint Incident Exposure reads. Both are *not compared (rows changed)*
  against a scan by a release before 17.3 (`changes.RESHAPED_CHECKS`).
- **Lists in cells** (v17.1 bug): GKE Credential Exposure's Roles and Scopes,
  Service Account Impersonation's Targets and Target Roles and VPC Service
  Controls Coverage's Projects were Python lists, shown as `['a', 'b']` chips
  and written to the CSV as such. Joined at the source; the synthetic
  organization's CSV is now checked for any repr.
- The **Fix** block's title row says *exact, from the check — Draft fixes
  covers the findings without one*; README › How to Use explains the two kinds
  of fixes in one paragraph.
- README: the Reliability catalogue (the briefing rewritten, the two checks),
  the *Briefings* design note, the Configuration Reference. `VERSION = "17.3"`.
  Roadmap: *Forecasts, budgets and spend* becomes v17.4.

### Tests

- `tests/test_exposure.py` (14): product mapping, zone↔region matching, global
  never matched, the label, asset-centric rows and evidence, Cloud SQL
  incidents meet instances only, fixes (the owning check's or the mechanical
  one), five incidents listed then *and N more*, the three statuses and the
  note, no briefing → no record and Error → Error, idempotence, the derivation
  through `categorize_findings` for the inline and the sharded path, the
  footprint columns are the reliability checks' own.
- `tests/test_gke_security.py`: zones and regions, pool zones, resilience
  issues (zonal, single-zone pool, regional multi-zone, Autopilot), the
  listing now writes five findings. `tests/test_service_health.py`: the
  inclusion rule, the global note across shards, the switch, `Scope`.
  `tests/test_scorecard.py`: no tally; the exposure sentence with rows only.
  `tests/test_gemini.py`: the prompt never sees the briefing.
  `tests/test_synthetic.py`: the two names in the report, no list repr in the
  CSV. Synthetic world: node pool zones (drawn last), the SQL instance's
  region. 948 tests.

### Upgrade notes

- Expect the Service Health briefing to shrink (ours: 42 rows → 4) and the
  Stability line to lose its incident tally; the new sentence appears only when
  Incident Exposure has rows. `SERVICE_HEALTH_RELEVANCE=IMPACTED,RELATED`
  restores the full list if a team wants it.
- The first scan after the upgrade says *rows changed* for Cloud SQL High
  Availability and MIG Resilience (Zonal), and *new check* for the two new
  names. Expect Stability to drop where clusters are zonal — that is the point.
- Nothing to grant and no new API: both new checks read what the scan already
  reads.

---

## v17.2 — Deploy with Terraform

The deployment, declared. `terraform/` creates what `tools/deploy.sh` creates —
the 25 APIs, the service account with its project roles and its self-binding,
the results bucket, the Cloud Tasks queue, the worker behind internal ingress
and invoked by the account alone, the web service behind Identity-Aware Proxy
with IAP's agent as its invoker and each operator let in, and on request the
BigQuery export dataset, the Cloud Scheduler jobs and the organization-level
roles of the prerequisites, custom role included — for teams whose
infrastructure lives in Terraform. Terraform builds no image, and the build
runs as the account Terraform creates, so a first deployment is two applies
around one Cloud Build: the foundation, the image, the services; the outputs
say what comes next at each point. A second description of a deployment rots
unless something ties it to the first, so the test suite now reads both: the
APIs, roles, variables, limits and scheduler job in `terraform/` must be the
script's, the README's and the app's own.

### Added

- `terraform/`: `versions.tf` (Terraform ≥ 1.5, `hashicorp/google` ≥ 7 < 9,
  locked at 8.10), `variables.tf` (the script's knobs with its defaults:
  `project_id`, `region`, the names, `image` and `image_tag`, `operators`,
  `extra_env`, `cost_allocation_labels`, `bigquery_dataset`, `schedules`,
  `organization_id` and `advisory_role_id`, `programmatic_access_principals`,
  `scan_max_concurrent_shards`, `task_max_attempts`, `deletion_protection`,
  `force_destroy`; validated where the script validates), `main.tf` (the
  foundation), `services.tf` (the services, IAP, access, schedules),
  `outputs.tf` (`web_url`, `worker_url`, `service_account_email`,
  `build_command`, `next_step`), `terraform.tfvars.example`, a short
  `README.md`, the provider lock file.
- Nothing is deployed without an image: with `image_tag` empty the first apply
  creates the foundation and `build_command` prints the Cloud Build line (as
  the new account, with the test suite); the second apply, with the tag,
  creates the services.
- The ownership contract: Terraform owns the services' image, variables,
  resources, identity, ingress and IAP; `lifecycle.ignore_changes` leaves
  traffic splits and tags to the operator, so the canary runbook of *Updating
  an Existing Deployment* works on a Terraform-managed deployment and its
  finalize step is `terraform apply` with the tested tag.
- The Cloud Tasks queue is declared, with the limits the services expect
  (`scan_max_concurrent_shards`, `task_max_attempts`, 30 s–10 min back-off),
  and the services are told the same two numbers; the script still leaves the
  queue to the services.
- Safety by default: `deletion_protection` on the services, `force_destroy`
  off for the bucket and the dataset, APIs never disabled on destroy, public
  access prevention on the bucket, never `invoker_iam_disabled`.
- With `organization_id`: the twelve read-only roles and the
  `CloudGaugeAdvisoryViewer` custom role (importable if it already exists),
  bound to the account — the prerequisites' manual step, done.

### Changed

- README: *Method 3: Deploy with Terraform* (the three commands, the variables,
  the contract), the Project Structure, the prerequisites (Terraform can do the
  organization step), *Updating an Existing Deployment* (step 7 on a
  Terraform-managed deployment). `tools/deploy.sh`'s header names the
  alternative.
- `.gcloudignore` and both build contexts leave `terraform/` out; `.gitignore`
  keeps providers, state and the real variables local.
- `VERSION = "17.2"`; the report's footer names it. No check changed. Roadmap:
  *Forecasts, budgets and spend* becomes v17.3.

### Tests

- `tests/test_terraform.py` (19 tests, no Terraform binary needed): the APIs
  equal the script's and the README's; the organization roles and the custom
  role (ID, title, description, permissions) equal README step 2; the project
  roles equal the script's loop; every role Terraform grants is one the script
  or the README grants, never Owner or Editor; the self-binding is Service
  Account User only; the services get the required variables and only known
  ones (`config.REQUIRED_ENV_VARS`, `helpers.APP_ENV_VARS`, the script's
  `COMMON_ENV`); worker and web timeout, concurrency, memory, ingress and IAP
  equal the script's flags; the deterministic worker URL; the lifecycle rule
  and the image reference; nothing deployed without an image; the queue limits
  equal `app.config`; the export's description and WRITER; the scheduler job's
  URI, audience, time zone, deadline, retries and body; the folder as root and
  as module (no provider block, every resource names its project); every
  variable described, the example consistent with the declarations; the folder
  documented and out of the build; `terraform fmt -check` when terraform is
  installed. 926 tests.

### Upgrade notes

- Nothing changes for a deployment made with `tools/deploy.sh`: the image is
  the same application. A new deployment can be made with Terraform; moving an
  existing one under Terraform means importing its resources and is not
  described.
- Verified as a customer would do it: in a project that had never run
  CloudGauge or Cloud Build, the folder called as a module with its own names
  — first apply (51 resources: APIs, account, roles on the project and the
  organization, custom role, bucket, queue, dataset), the `build_command`
  output run as printed (the image built and tested as the new account),
  second apply (7 resources: the two services, IAP's invoker, the operator,
  programmatic access, one schedule). An organization scan through the new
  web URL, its report, CSV, history page and BigQuery rows; the schedule run
  once by hand and accepted by the worker (*Requested by schedule: …*). Then
  the runbook's canary deploy on the Terraform-managed worker: the plan showed
  the two variables and nothing about traffic, the apply put them back, the
  plan after it was empty; `--to-latest` moved the traffic — the apply's
  revision serves nothing until it does, which the README now says. Then
  `terraform destroy`: 58 resources gone, and a listing of the project and the
  organization afterwards found nothing (the custom role in its seven-day
  deleted state, as Google keeps them). Two things changed on the way: the
  web URL output names Cloud Run's deterministic URL rather than the service's
  older hash URL, and the scheduler job declares no retry block — the API
  returns none for the no-retries default, so a declared one was a diff on
  every plan.

---

## v17.1 — The SSRF chain: GKE and identity hardening

A release shaped by an intrusion pattern seen in the wild: a server-side
request forgery in an internet-facing pod reaches the node's metadata server,
steals the token of a Compute Engine default service account that holds
Editor, replays it from outside Google Cloud, chains through broad Token
Creator grants into most of the project's service accounts and the
neighbouring projects, and drives a publicly reachable GKE control plane —
with no perimeter to stop the replay and no runtime detection to raise an
alarm. No platform vulnerability; five stacked posture gaps, each of them a
setting this release now reads. **GKE Credential Exposure** names, per node
pool, whether pods reach the GCE or the GKE metadata server, the node account,
its roles and scopes, and the verdict in one sentence — *one SSRF from
roles/editor on project X*. **Service Account Impersonation** answers *who can
become which service account*: token minting granted on a project, folder or
organization, account-to-account chains, principals from outside the
organization, Workload Identity for the `default` Kubernetes account — with the
reach of each grant (*every service account under projects/x (27)*, *3 of 27
service accounts in projects/x*). **GKE Control Plane Exposure** (public
endpoint without authorized networks or with `0.0.0.0/0` in them, legacy ABAC,
client certificates), **GKE Node Hardening** (public nodes, no network policy
enforcement, Shielded nodes and Secure Boot, COS, Binary Authorization,
posture scanning, secrets encryption), **GKE Threat Detection** (Container and
Event Threat Detection per cluster and project, logging components,
data-access audit logs) and **VPC Service Controls Coverage** (projects outside
every enforced perimeter, perimeters that leave the token-replay services
unrestricted, dry-run perimeters) complete the chain. The Organization Policies
check now evaluates the nine `container.managed.*` guardrails. Six new report
names, one listing of the scope's clusters, one IAM search, one read of the
access policies; **no new role**, one API enabled for read-only use.

### Changed

- **GKE security posture** (`app/checks/gke_security.py`, scope-level): one
  Cloud Asset Inventory listing of `container.googleapis.com/Cluster` under the
  scope feeds four findings. Pure evaluators over the cluster JSON:
  `pool_metadata_mode` (`GKE_METADATA` or the deprecated
  `GKE_METADATA_SERVER` count as GKE; metadata concealment does not),
  `node_service_account` (the API writes `"default"`; the project number from
  the asset's parent spells it out), `exposure` (GCE metadata and a privileged
  role — `PRIVILEGED_ROLES`, primitive roles first — is *Action Required*
  whatever the scopes; the row says when the pool's OAuth scopes limit what a
  stolen token can call), `control_plane_issues` (the classic
  `privateClusterConfig`/`masterAuthorizedNetworksConfig` fields and the newer
  `controlPlaneEndpointsConfig`; anonymous authentication and system-group
  bindings as one Investigation row), `hardening_issues`, `logging_gaps`,
  `data_access_logging`. The roles of each node account come from one IAM
  search per account (`policy:"<email>"`, project/folder/organization
  bindings only). Threat detection reads the Security Command Center settings
  API's effective state: `containerThreatDetectionSettings:calculate` per
  cluster, `eventThreatDetectionSettings:calculate` per project. Autopilot
  clusters skip the node-pool rows. A failed listing is the four findings'
  Error; a node account or SCC setting that could not be read is on *Projects
  not checked*.
- **Service Account Impersonation** (`app/checks/impersonation.py`,
  scope-level): `searchAllIamPolicies` with a permission-based query
  (`iam.serviceAccounts.getAccessToken`, `implicitDelegation`, `signBlob`,
  `iam.serviceAccountKeys.create`, plus the predefined roles), so custom roles
  count — their permissions are read once each through `iam.roles.get`. One
  `searchAllResources` of `iam.googleapis.com/ServiceAccount` gives the reach
  denominators (per project, folder, organization) and tells a foreign
  principal from one in scope. `member_kind` sorts principals (public, domain,
  human, service account, Google-managed service agent, Kubernetes, federated,
  federated pool); `severity` holds the rules (Google-managed agents and
  `*.serviceAgent` roles are never listed, nor is an account bound on itself
  — Cloud Build deploying as the account it runs as; primitive roles stay with
  Project IAM Hygiene; a person's grant on one account is Investigation —
  CloudGauge's own operator grant shows there). Rows: *Resource · Level · Principal · Path ·
  Reach · Targets · Target Roles · Fix*; target roles are looked up for up to
  200 accounts.
- **VPC Service Controls Coverage** (`app/checks/perimeters.py`,
  scope-level): the access policies of the scanned projects' organization
  (`accessPolicies.list`, scoped policies included; a folder or project scan
  finds the organization in the project search results) and each policy's
  `servicePerimeters.list`, both permissions in `roles/iam.securityReviewer`.
  Asset Inventory's `ACCESS_POLICY` content type was the first design and was
  dropped: it lagged a newly created policy by longer than a scan can wait.
  Rows for no perimeter at all, projects outside every enforced regular perimeter,
  perimeters that leave `iamcredentials`, `storage`, `secretmanager`,
  `container`, `sqladmin` or `compute` unrestricted, and dry-run-only
  perimeters; *Investigation Recommended* throughout.
- **Registry** (`app/checks/registry.py`): three scope-level specs after IAM
  Least Privilege (37 checks in an organization scan, 33 otherwise; the GKE
  spec writes four findings). `categories.py`: six names under Security &
  Identity. `layouts.py`: `Metadata`, `Path`, `Level` as states; `Exposure`,
  `Reach` as prose; `Scopes`, `Roles`, `Targets`, `Target Roles` as resource
  lists; `Perimeter` as a resource.
- **Organization Policies**: `assets/gcp_best_practices.csv` now recommends
  the nine `container.managed.*` constraints (Workload Identity Federation and
  no default Compute account as *Must have*; private nodes, network policy,
  no RBAC system bindings, security bulletins, Binary Authorization as
  *Should have*; DNS-only control plane access, secrets encryption, Google
  Groups RBAC as *Could have*), so the check evaluates them instead of
  skipping rows without a recommendation. The deployed check fetches the CSV
  from `BEST_PRACTICES_CSV_URL`; the file must be on that branch too.
- **Synthetic world** (`app/synthetic`): every cluster gets a `GkeHardening`
  profile, projects an impersonation table (a project-level Token Creator for
  an account, a person on one account, an account-to-account chain, Workload
  Identity for `default`, a principal from outside, act-as for a deployer
  group, a custom token-minting role), threat-detection and audit-log flags;
  the organization two perimeters (one enforced with two replay services
  missing, one dry-run) — every draw after the v17 ones, fictional names only.
  The provider serves cluster and perimeter assets, `searchAllIamPolicies`,
  the service-account inventory, the SCC `calculate` calls and `iam.roles.get`.
- README: the six checks in the Security catalogue with the chain they break,
  the project structure, prerequisites (*no new role*). `VERSION = "17.1"`.
- **History page** (follow-up): the chart's right margin holds its end labels
  (they were clipped), gridlines at 0/25/50/75/100, up to five date labels
  with repeats and crowding removed, one dot per scan with a native tooltip
  (`<title>`, no script). The footer says where scans are kept — summaries
  under `scopes/` in the results bucket, reports under the job's folder, and
  BigQuery when the export is configured — and, when the 52-scan window
  leaves older scans out, how many (`list_summaries(with_total=True)`).

### Tests

- `tests/test_gke_security.py`: metadata modes (including concealment and the
  deprecated field), the default account by name and by number, scopes, legacy
  endpoints; the exposure verdicts and their wording; credential rows with the
  three fixes and the Autopilot skip; control-plane issues on classic and new
  fields (`0.0.0.0/0`, Google public IPs, ABAC, certificates, basic auth, the
  anonymous/system-group row); hardening issues for Standard and Autopilot;
  logging gaps and audit configs; the check against the fakes (one listing,
  one search per account, the four findings, a failed listing, partial
  failures on *Projects not checked*, all-clear rows).
- `tests/test_impersonation.py`: member kinds, the path of predefined and
  custom roles, the severity table, rows with reach, targets, order and fixes
  (an organization scan and a folder scan), the check against the fakes
  (custom roles read once, counts, an unreadable role, a failed search), the
  perimeter facts and coverage rows, the perimeter check (organization and
  folder scans, the no-access-policy answer, an Error).
- `tests/fakes.py`: assets with parents and ancestors, perimeters, IAM policy
  search, service-account resources. Updated: `test_worker` (37/33 checks; the
  scope-level plan), `test_category_consistency` (the GKE writer's names),
  `test_synthetic` (eight organization listings, the perimeters read at the
  organization in folder and project scans). 907 tests.

### Upgrade notes

- Nothing to grant: the checks read through `roles/cloudasset.viewer`
  (clusters, the IAM and resource searches), `roles/iam.securityReviewer`
  (access policies, perimeters, custom roles) and
  `roles/securitycenter.settingsViewer` (threat-detection settings), all of
  which the service account already holds. `tools/deploy.sh` enables
  `accesscontextmanager.googleapis.com` in the project CloudGauge runs in
  (read-only calls); without it *VPC Service Controls Coverage* reports an
  Error and nothing else changes.
- The six new names are *not compared (new check)* on the first scan after the
  upgrade, as every new check is. No existing check changed shape.
- Expect the Security pillar to drop on the first scan of an organization with
  Standard clusters on the default node account or project-level Token Creator
  grants: that is the point.

## v17 — History, analytics and FinOps

The release that turns single reports into a record. Every finished scan can
now be **loaded into BigQuery** (two tables, `scans` and `findings`, by free
load jobs the report build starts and the header accounts for), **scheduled
scans** fill that record in without anyone clicking (Cloud Scheduler posting to
the worker as the service account; a scope scans once at a time), and a
**history page** shows a scope's scans over time — the four pillar scores as
lines, one row per scan with what flipped since the one before. On the
findings side, **FinOps** joins the cost checks: six more recommenders
(resource-based commitments, overprovisioned Cloud SQL, Cloud Run cost,
BigQuery slots, idle images, Cloud Storage soft delete), **cost-allocation
labels**, **storage lifecycle**, **snapshot sprawl**, **commitments
expiring**, and a
savings total on the Scorecard's Efficiency line. Capacity gets its own pair of
checks — what is reserved and committed, what runs without a reservation, and
where Compute Engine has been short of capacity or quota in the last 30 days —
the quota check learns accelerator families, two thresholds and headroom, Cloud
SQL versions in extended support are flagged, and the IAM recommender's unused
roles land in Security. Sixteen new report names, no new organization-level
role: every new check reads through roles the service account already holds.

### Changed

- **BigQuery export** (`app/services/bigquery_export.py`): with
  `BIGQUERY_DATASET` set, `generate_reports` calls the exporter between the
  context and the page — `scans` (one row per scan: who, how many projects,
  the four scores and counts, every check's status as a repeated record) and
  `findings` (one row per finding row of every check and per organization
  policy, with the row's *identity* from `app.reporting.changes`, whether it
  was new, and the raw row as `row_json`) staged as NDJSON under
  `exports/<job>/` and loaded by two jobs named after the scan's job ID
  (`cloudgauge-<job>-<table>`; a 409 is a retry, polled not re-inserted),
  `WRITE_APPEND`, created on first use, partitioned by day on `generated_at`,
  clustered by `scope_id` (and `check_name`), `ALLOW_FIELD_ADDITION`. The build
  waits `BIGQUERY_EXPORT_WAIT_SECONDS` (60) and the header's new **BigQuery
  export** row says *loaded*, *still running* or *failed: …*; nothing here can
  fail a scan, and synthetic scans are never exported. The REST API through
  `app.services.gcp`: no new dependency. `Services.get_exporter()` builds it
  once; `scan_job` and `FanOut.aggregate` pass it through.
  `tools/backfill_export.py` loads the scans made before the export existed
  from their summaries and CSV reports (the CSV's *New since last scan* column
  becomes the flag; text details are split back on `"; "`), skipping the job
  IDs already in `scans`.
- **Scheduled scans** (`app/services/schedules.py`, `/scheduled-scan` on the
  worker blueprint): Cloud Scheduler posts `{scope, scope_id, name}`; the
  endpoint validates it (400), notes the job under
  `schedules/<scope>/<scope id>.json` and enqueues the usual `/run-scan` task
  with `requested_by="schedule: <name>"` (202 with the status path), or
  answers 409 while the noted job's status file is missing or not finished
  (a note older than 36 hours is stale). `tools/deploy.sh SCHEDULES=…` parses
  `NAME=SCOPE/SCOPE_ID@CRON` entries before it changes anything and creates or
  updates one job each (`--oidc-service-account-email`, audience the worker's
  URL, `Etc/UTC`, no retries).
- **History page** (`app/reporting/history.py`, `history.html`,
  `/history/<scope>/<scope_id>`): `GcsResultsStore.list_summaries` (newest
  first, `HISTORY_PAGE_SCANS` = 52) → one `HistoryEntry` per scan with scores
  recomputed under the current rule (`scores_from_checks`), the Overview
  counts, and `status_flips` against the scan before (briefings excluded,
  regressions first); the chart is inline SVG — one polyline per pillar in
  ink with a dash pattern each, 0/50/100 hairlines, the oldest and newest
  dates — so the page is a document with no script. Linked from the report
  header's new **History** row, the status page's **View history** and the
  setup page's *Scan history* line once a resource is chosen. Empty state and
  a 404 for an unknown scope.
- **Cost recommenders** (`app/checks/cost.py`): `COST_RECOMMENDERS` grows to
  14 with location types `global` and `bigquery` (US, EU and the active
  regions); `recommender_locations` replaces the inline loop. A global or
  BigQuery recommender is asked whatever locations were discovered, so the
  *Projects not checked* row of a project without locations now names the 11
  location-bound recommenders instead of "all 8".
- Spend-based commitments are **not** read from billing accounts: that access
  is centralised in most organizations and a per-deployment billing-account
  grant would stall scans. v17.1 reads them from the organization's Recommender
  export to BigQuery (a dataset-level read) instead; CloudGauge holds nothing on
  any billing account and does not enable the Cloud Billing API.
- **Cost Allocation Labels** (`COST_ALLOCATION_LABELS`, validated label keys):
  *Informational* with a how-to note until configured; then Resource Manager
  per project, rows `Project · Missing Labels · Fix`. **Cloud Storage
  Lifecycle**: a bucket with no lifecycle rule and Autoclass off, with
  `--enable-autoclass`, *Investigation Recommended*. **Snapshot Sprawl**
  (scope-level, two Asset Inventory listings): older than
  `SNAPSHOT_MAX_AGE_DAYS` (90) or whose source disk is gone, oldest first, with
  age, size and the delete line. All three with all-clear rows.
- **Capacity** (`app/checks/capacity.py`): `check_capacity_commitments` reads
  reservations, future reservations, commitments and running instances per
  project and writes the **Capacity Commitments** briefing (Informational, a
  note when there is nothing; shards' notes folded by `fold_note_rows`),
  **Reservation Coverage** (`RESERVATION_COVERAGE_MIN_VCPUS` = 32 running
  vCPUs in one zone with fewer reserved; the fix names the zone's most common
  machine type; vCPUs from `machine_type_vcpus`) and **Commitments Expiring**
  (active, not auto-renewing, within 90 days; the `--auto-renew` line).
  `check_capacity_signals` asks Cloud Logging per project for 30 days of
  `ZONE_RESOURCE_POOL_EXHAUSTED` / `QUOTA_EXCEEDED` operations and groups them
  by zone, resource and kind — *Action Required* under 7 days old.
- **Quota Utilization (>80%)** (`app/checks/operations.py`): rows gain
  `Family` (*Accelerator* for GPU/TPU metrics) and `Headroom`; 80–95 % is
  *Investigation Recommended*, 95 %+ *Action Required*. In
  `RESHAPED_CHECKS` as `("17", "rows changed")`: against a scan before v17 the
  rows are not compared. **Quota Increase Recommendations**: the quota
  recommender at `global`, per project; each row names the service, the quota
  and its current limit from the recommendation's `overview`.
- **Cloud SQL Extended Support** (`app/checks/reliability.py`, scope-level):
  `EXTENDED_SUPPORT`, a static table of the published dates (MySQL 5.6/5.7/8.0,
  PostgreSQL 9.6–15, SQL Server 2014–2022); in extended support or past its end
  *Action Required*, within 180 days *Investigation Recommended*; the fix is
  the in-place `gcloud sql instances patch --database-version` to the newest
  major of the engine (SQL Server keeps its edition).
- **IAM Least Privilege** (`app/checks/security.py`): the IAM recommender for
  the scanned organization or folder and every project, rows `Project ·
  Principal · Current Role · Recommended Role · Recommendation · Fix` (the
  organization or folder by its resource name) from the
  recommendation's operation groups. A **split check** like the miscellaneous
  one: `registry.SPLIT_CHECKS` now drives both — the scope shard runs the
  scope half (`project_level=False`), project shards the rest
  (`scope_level=False`), with identical all-clear rows so the merge keeps one.
- **Scorecard** (`app/reporting/scorecard.py`): `savings_text` sums the
  failing cost checks' *Est. Monthly Saving* per currency onto the Efficiency
  evidence line. **Layouts**: roles for the new columns (resources, lists,
  numbers, times, states). **Config**: `VERSION = "17"`,
  `COST_ALLOCATION_LABELS`, `SNAPSHOT_MAX_AGE_DAYS`,
  `RESERVATION_COVERAGE_MIN_VCPUS`, `BIGQUERY_DATASET`,
  `BIGQUERY_EXPORT_WAIT_SECONDS`; `app/utils.py` gains `utcnow`,
  `parse_timestamp`, `days_between`.
- **Synthetic world** (`app/synthetic/world.py`, `provider.py`): labels,
  machine types, Cloud SQL versions, old and orphaned snapshots and the disks
  behind them, reservations, future reservations, commitments, capacity
  events, IAM recommendations, a GPU quota, a quota recommendation and the six
  recommenders' findings — every draw after the existing ones, the dataclass
  fields added with `replace`, so every synthetic fact of v16.1 is where it
  was. The provider answers the reservation and commitment listings, Cloud
  Logging entries, the IAM and quota recommenders, and gives buckets lifecycle
  rules and Autoclass.
- **`tools/deploy.sh`**: enables `cloudscheduler` and `bigquery` (v17) and `accesscontextmanager` (v17.1); steps 6 (dataset, WRITER through the dataset's access list,
  `roles/bigquery.jobUser`) and 7 (schedules); `BIGQUERY_DATASET` and
  `COST_ALLOCATION_LABELS` on both services — the latter its own variable, and
  the services' variables now passed behind gcloud's `^|^` delimiter, because
  `--update-env-vars` splits on commas and the label keys contain them.
  README: the catalogue, the pages, the structure, prerequisites
  (APIs; *no new organization-level role*), the script's variables, the
  configuration table, and a **History and analytics** section with the
  tables, the backfill, five queries, Looker Studio and Gemini Enterprise.

### Tests

- `tests/test_finops.py`: the settings; `recommender_locations`; labels
  (unconfigured, missing keys, all present); lifecycle (rules, Autoclass,
  neither, a generator of rules); snapshot sprawl (ages, orphans, order, a
  failed listing); the Efficiency savings line.
- `tests/test_capacity.py`: `machine_type_vcpus` (standard, custom, shared-core,
  accelerator-optimized), descriptions, `expiring_row`, `coverage_rows`,
  signal classification; the commitments check against a fake Compute API
  (briefing rows, coverage at 50 of 32 reserved, one expiring, a denied project
  on both scored names' rows); the signals check against a fake Logging API
  (grouping, a full page as `N+`, 7-day urgency); the quota rows, thresholds
  and the quota recommender (the service, quota and limit of each row).
- `tests/test_versions_and_iam.py`: `major_version` (PostgreSQL 9.6 keeps its
  minor), targets, `assess_sql_version` across the table; the check against
  Asset Inventory; IAM operations, fixes per resource kind, rows, the scope and
  projects asked, the split flags, an Error when nothing could be read.
- `tests/test_export.py`: the `scans` and `findings` rows (schema-complete,
  identities, policies, text details, *new* flags); the loader against a fake
  BigQuery API (NDJSON staging, the two job bodies, 409 as a retry, a failed
  job, a slow job, an API that is down, a bucket that is down); the worker
  exporting a scan and saying so in the header; a failed export leaving the
  scan completed; no export without a dataset; synthetic scans skipped; the
  backfill rebuilding the live rows from a CSV, and its command line.
- `tests/test_history.py`: flips, entries, the chart's points and labels,
  the model; the page (newest first, links, empty state, 404, 500, the 52
  limit, an unreadable summary skipped); the links from the report, status
  and setup pages; the scheduler body, `scan_in_progress`, the endpoint
  (202 with the task and the note, 409, another scope, after completion,
  400s) and its absence from the web service.
- Updated: `test_category_consistency` (the writers' name tables),
  `test_fanout` (25 project-level checks; `SPLIT_CHECKS`), `test_worker`
  (34/30 checks in the plan; the scope plans; the best-practices CSV served
  in-process so the suite needs no network), `test_not_checked` (14
  recommenders, 11 location-bound), `test_synthetic` (six Asset listings,
  the v17 names, the savings line, an empty folder's Efficiency verdict),
  `test_changes` (`RESHAPED_CHECKS`), `test_routes`, `test_roles`,
  `test_packaging` (17 rules, `history.html`), `test_design` (the history
  page under the same rules). 847 tests.

### Upgrade notes

- Nothing to grant on the organization, and nothing on any billing account. In
  the project CloudGauge runs in, `tools/deploy.sh` enables
  `cloudscheduler.googleapis.com` and `bigquery.googleapis.com`.
- The export is opt-in: `BIGQUERY_DATASET=cloudgauge tools/deploy.sh` creates
  the dataset and the two grants; then `tools/backfill_export.py` loads the
  earlier scans. Schedules are opt-in too (`SCHEDULES=…`).
- The first scan after the upgrade compares as usual except **Quota
  Utilization (>80%)**, whose rows are *not compared (rows changed)* once;
  the sixteen new names are *not compared (new check)*, as every new check
  is. **Cost Allocation Labels** stays *Informational* (outside the score)
  until `COST_ALLOCATION_LABELS` names the keys.
- Reports stored by earlier releases are unchanged; the history page reads
  every summary filed since v15.

## v16.1 — Multi-region snapshots pass, downloads behind the sign-in

Two things the v15.6 and v16 rollouts left on the list. **Disk Snapshot
Resilience** flagged every snapshot it saw: a Compute Engine snapshot has
exactly one storage location, so "fewer than two locations" was true of all of
them — every one of the 56 an organization scan found was kept in the `asia`
multi-region, which is geo-redundant by construction. The check now reads the
kind of the location: a multi-region (`asia`, `eu`, `us`) passes, a single
region (`asia-south1`) is flagged with its name, as before. And the status
page's **Download CSV**, the one link v16 left outside Identity-Aware Proxy — a
Cloud Storage URL signed by the service account, good for an hour for whoever
held it — is now the web service's own `/report/<job>/<scope>/csv` route, the
one the report's toolbar already used: the CSV is streamed from the bucket by
the service, behind the same sign-in as every page, and nothing in the results
bucket is addressed by a browser any more. The service account signs nothing
now, so it no longer needs Token Creator on itself.

### Changed

- **Disk Snapshot Resilience** (`app/checks/reliability.py`): `MULTI_REGIONS`
  names the three Compute Engine multi-regions; `is_single_region(locations)`
  is true when none of a snapshot's storage locations is one of them (compared
  lower-cased; an empty or missing list still counts as single-region, with
  Location *unknown* — the conservative reading). The row, `Project · Snapshot
  · Location`, and the all-clear text (*No single-region disk snapshots
  found.*) are unchanged, so a snapshot still flagged is the same finding it
  was.
- **The first scan after the upgrade says so** (`app/reporting/changes.py`).
  Under the new rule a snapshot in `asia` leaves the table without anyone
  touching it; compared row by row that would read as 56 resolved.
  `RESHAPED_CHECKS` now carries the release that drew the line *and why* —
  `("16.1", "rule changed")` for this check, in place of v15.6's *rows changed*
  line — and against a previous scan by any older release (15.5, 15.6, 16) the
  check's rows are *not compared (rule changed)*: no resolved list, no `−56` on
  the card. Its status change still shows (*Action Required → Compliant*) and
  the Reliability delta with it: that is the posture under the new rule, and
  the chip beside it says it is a rule change, not work done. From the next
  scan on, rows compare as usual. `SUMMARY_VERSION` unchanged.
- **The status page's CSV link** (`app/routes/ui.py`, `status.html`,
  `app/services/results_store.py`): `csv_url` is built next to `report_url`
  and the button uses it; `get_status` renders the page and nothing else. The
  route serves the object **streamed** — `open_report` returns the blob's
  reader and size, read in 1 MiB chunks, with `Content-Length` and the
  attachment `Content-Disposition` — so an organization-sized CSV never sits
  whole in the web service's 1 GiB; 404 until the CSV exists, as before.
  `generate_signed_csv_url` and its imports are gone. Behind IAP a click after
  the session expired is a navigation, not a fetch: IAP signs in, returns to
  the CSV URL, and the download proceeds.
- **`tools/deploy.sh`** grants the service account one binding on itself,
  `roles/iam.serviceAccountUser` — what a Cloud Tasks task carrying its
  identity needs (`iam.serviceAccounts.actAs`), which the README's step 3 had
  labelled "for signed URLs" — and no longer
  `roles/iam.serviceAccountTokenCreator`. The grant `PROGRAMMATIC_ACCESS=1`
  makes to a person (minting IAP tokens with `tools/iap_token.py`) is a
  different binding and stays.
- **Synthetic world** (`app/synthetic/world.py`, `provider.py`): a project
  profile draws `multi_region_snapshots` (0–2, after every existing draw, so
  every other synthetic fact is as it was) and the provider lists them in
  `asia`, `us` and `eu` beside the `us-central1` ones, so a synthetic scan
  exercises both sides of the rule.
- The README: the catalogue line; the status-page and *Reports for Large
  Organizations* passages (no link expires); the *Changes* paragraph (*rule
  changed*); prerequisites step 3; `SERVICE_ACCOUNT_EMAIL`; Cleanup (the Token
  Creator self-binding as a leftover of releases before v16.1, with its
  removal line).

### Tests

- `tests/test_resilience.py`: the rule, parametrised — `['asia']`, `['us']`,
  `['eu']`, `['ASIA']`, `['us', 'eu']` leave no row; `['asia-south1']`,
  `['us-central1']`, `['europe-west1']` a row with that location, `[]` and a
  missing key one with *unknown*; `MULTI_REGIONS` is exactly the three offers.
- `tests/test_changes.py`: `rows_reshaped_since` returns the reason against
  `None`, `''`, `15.5`, `15.6`, `16`, `16.0` and nothing against `16.1`,
  `16.2`, `17`; a check whose rule changed reports its status change but
  nothing resolved, with the chip title *Was Action Required in the previous
  scan; Rows not compared: rule changed*; the gate applies across releases
  only.
- `tests/test_routes.py`: the CSV route streams — body (non-ASCII, so the
  length is in bytes), `text/csv`, `Content-Disposition`, `Content-Length`,
  the blob opened with the route's chunk size; an 800-byte object in 8-byte
  chunks arrives whole in 100 reads and the file is closed; a bucket failure
  is the same 500 as before. `tests/fakes.py`'s `FakeBlob` gains `size`,
  `reload` and `open`.
- `tests/test_smoke.py`: the status page links `/report/<job>/<scope>/csv` and
  signs nothing. `tests/test_api_parity.py`: parity with the legacy page on
  everything but the link it signs (`status_page_facts` in `tests/helpers.py`
  leaves the CSV URL out), the new page's own facts asserted beside it;
  `test_status_page_without_a_signed_url` retired with the signing.

### Upgrade notes

- The first scan of each scope after the upgrade shows **Disk Snapshot
  Resilience** on the Changes card as a status change (*Action Required →
  Compliant* where every snapshot was in a multi-region) with a *not compared
  (rule changed)* chip, and lists nothing as resolved for it; Stability moves
  accordingly (the first organization: 27 % → about 36 %). A snapshot in a
  single region stays flagged and keeps its identity.
- Reports stored by earlier releases are not affected: their toolbar link was
  this route already. Status pages are rendered on request, so every job's
  **Download CSV** is the route from the moment the new revision serves.
- The `roles/iam.serviceAccountTokenCreator` binding the service account held
  on itself signed the old link and nothing else; `tools/deploy.sh` no longer
  grants it, and on an existing deployment it can go once no earlier revision
  is a rollback target: `gcloud iam service-accounts remove-iam-policy-binding
  $SA --member=serviceAccount:$SA --role=roles/iam.serviceAccountTokenCreator`.
  The `roles/iam.serviceAccountUser` self-binding stays: Cloud Tasks needs it.
- The public single service (`CLOUDGAUGE_ROLE=all`) behaves as before; its
  CSV is as public as its pages are.

---

## v16 — Authenticated by default

Every deployment so far was public: `--allow-unauthenticated`, or the invoker
check disabled where an organization policy forbids `allUsers`, and nothing in
front of the pages. v16 puts **Identity-Aware Proxy** in front of them and keeps
Cloud Tasks away from it. One image, two Cloud Run services told apart by
`CLOUDGAUGE_ROLE`: the **web** service serves the pages and the API behind IAP —
a Google sign-in on the service's own `run.app` URL, and only accounts holding
`roles/iap.httpsResourceAccessor` get through — and the **worker** service runs
the scans and accepts Cloud Tasks only (`--ingress internal`, invoked by the
service account). No load balancer, domain, certificate or OAuth client to
create: `gcloud run deploy --iap`. The pages say who is signed in; a scan
records who asked for it and the report says *Requested by*. `tools/deploy.sh`
is the whole deployment, and the update. The single service of every earlier
release (`CLOUDGAUGE_ROLE=all`, the default) keeps working unchanged.

### Added

- **`CLOUDGAUGE_ROLE`** (`app/config.py`, `app/routes/__init__.py`,
  `app/__init__.py`): `web` registers the `ui` and `api` blueprints, `worker`
  the `worker` blueprint, `all` (default) everything — the single service of
  every earlier release. A `web` service must be told `WORKER_URL` (startup
  fails naming the variable if not: self-discovery would hand it its own URL,
  which has no `/run-scan`); a `worker` or `all` service discovers its own, as
  before, unless `WORKER_URL` says it. Both create the queue if it is missing.
  Nothing that passes IAP can post to `/run-aggregation`: the web service has
  no such route, and the worker has no pages to sign in to.
- **Who is signed in** (`app/identity.py`, new). Behind IAP every request
  carries `X-Goog-IAP-JWT-Assertion`; the service **verifies** it — ES256
  signature against IAP's published keys (cached an hour, refetched once on an
  unknown key ID), issuer `https://cloud.google.com/iap`, audience
  `/projects/NUMBER/locations/REGION/services/SERVICE`, expiry — and takes the
  email from the verified claims. The plain `X-Goog-Authenticated-User-Email`
  header is never read, so a service reachable without IAP cannot be told a
  name. The project number comes from `PROJECT_NUMBER` or the metadata server
  (read once); without it identities count as absent, with one warning. The
  pages' header reads *Signed in as alice@example.com*; `/scan` adds
  `requested_by` to the task body (only then — the legacy body is otherwise
  unchanged); the worker hands it to the report, through the manifest for a
  sharded scan, and the report's header gains a *Requested by* row after the
  Report ID. The scan summary carries `requested_by` too (`null` when unknown;
  `SUMMARY_VERSION` unchanged, comparisons with older scans unaffected).
- **Sessions that expire** (`status.html`, `report/_script.js`): an IAP
  session lasts about an hour, after which a `fetch` from the status page or
  a report would get a sign-in redirect it cannot follow. The pages' calls send
  `X-Requested-With: XMLHttpRequest` (IAP answers 401 instead) and reload the
  page on 401, which signs in again and comes back. The report's three API
  calls go through one `apiFetch`.
- **`tools/deploy.sh`** — the deployment, in one idempotent command: the APIs,
  the service account with its project roles, the bucket; build and test with
  `cloudbuild.yaml` **as the service account** (not as the Compute Engine
  default account, which organizations commonly leave without roles); the worker (`CLOUDGAUGE_ROLE=worker`, `--ingress
  internal`, `--no-allow-unauthenticated`, the service account its only
  invoker); the web service (`CLOUDGAUGE_ROLE=web`, `WORKER_URL`, `--iap`,
  IAP's service agent its invoker, `PROJECT_NUMBER` set); `OPERATORS` granted
  `roles/iap.httpsResourceAccessor`. It uses Cloud Run's deterministic URLs,
  so the worker is told its own URL before it exists and needs no
  `roles/run.viewer`. `PROGRAMMATIC_ACCESS=1` lets the service account through
  IAP and lets the gcloud account sign tokens for it; `SKIP_SETUP`,
  `SKIP_BUILD`, `EXTRA_ENV` and `DRY_RUN` cover updates and reviews. The
  organization-level scan roles stay the one manual step.
- **`tools/iap_token.py`** — a token that passes IAP, for `curl`, scripts and
  the demo recorder: a JWT signed by the service account through the IAM
  Credentials API (`signJwt`), audience `BASE_URL/*`, up to an hour, minted
  with the signed-in gcloud identity (which needs
  `roles/iam.serviceAccountTokenCreator` on the account). Google-issued ID
  tokens — `gcloud auth print-identity-token`, Cloud Tasks OIDC tokens — do
  not pass IAP on Cloud Run with its Google-managed OAuth client, whatever
  their audience: the finding of the v16 spike, and the reason for the two
  services. `tools/demo_gif.py --iap-service-account` records through it.

### Changed

- `WORKER_URL` on a web service names the worker service; on a worker it is
  optional (its own URL). `WORKER_AUDIENCE` keeps its canary meaning, now on
  the worker: the web canary's `WORKER_URL` is the worker canary's tag URL and
  `WORKER_AUDIENCE` the worker's main URL.
- The web service runs small — `--concurrency 80`, `--memory 1Gi`, `--timeout
  600` (pages and the three on-demand Gemini / Recommender calls); the worker
  keeps `--timeout 3600 --concurrency 4 --memory 2Gi`.
- The README's deployment is written around the two services and IAP: Method 1
  (console) is two services with *Require authentication → Identity-Aware
  Proxy* on the web one, Method 2 is the script; a *Who can use it* section;
  the single public service is a discouraged appendix with the Domain
  Restricted Sharing caveat; the zero-downtime recipe runs two canaries.
- `tests/test_packaging.py` counts `app.identity` among the web modules (it
  imports Flask); the scan modules still import no Flask and open no socket.

### Tests

- New `tests/test_identity.py`, on a stand-in IAP that signs with real P-256
  keys: a valid assertion names the person; no assertion, the raw email
  header alone, another service's or project's audience, a URL-form audience,
  another issuer, expiry, a missing email, garbage, a rogue key under IAP's
  key ID or a new one (one refetch, then rejected), key rotation followed
  with one refetch, the hour-long key cache, a failed key fetch, the project
  number from the metadata server once or missing with one warning, the
  assertion never logged. In the app: one verification per request, the two
  pages showing and escaping the name, `/scan` with and without IAP, and the
  *Requested by* row and summary field from an inline and from a sharded scan,
  absent without a person.
- New `tests/test_roles.py`: the blueprints per role, the web service
  answering 404 on every worker path and the worker on every page, the
  production startup per role (web without `WORKER_URL` fails before any GCP
  call; web with it never discovers; worker discovers or is told), the role
  read case-insensitively, an unknown role rejected, the default unchanged.
- `tests/test_reporting.py`: the stored report's calls go through `apiFetch`
  with the XHR header and the 401 reload; the three paths are unchanged.

### Upgrade notes

- Nothing changes for an existing single-service deployment: `CLOUDGAUGE_ROLE`
  defaults to `all`, no new variable is required, and without IAP the pages
  show no name and scans record none.
- To move to the authenticated shape run `tools/deploy.sh` with the names you
  deployed with (`SERVICE`, `REGION`, `QUEUE`, `BUCKET`, `SERVICE_ACCOUNT`)
  and `OPERATORS`: it adds the worker, turns the service into the web service
  (IAP on, `allUsers` and the disabled invoker check gone) and grants access.
  Do it between scans: the shard and sweep tasks of a sharded scan in flight
  are addressed to the old service's URL, which has no worker routes once it
  is the web service. IAM grants take up to a minute; a 403 right after the
  switch goes away on reload. Access to the pages is then the
  `roles/iap.httpsResourceAccessor` binding, per person, group or domain.
- Reports stored by earlier releases keep their frozen script: after an IAP
  session expires, their *Draft fixes*, *executive summary* and *detailed
  insights* buttons do nothing until the page is reloaded.
- `curl`, scripts and `tools/demo_gif.py` need a token from
  `tools/iap_token.py` (`PROGRAMMATIC_ACCESS=1` in the deploy script sets up
  the two grants it needs); `gcloud auth print-identity-token` no longer
  opens the service.

---

## v15.6 — Resilience at every scope

A folder scan could not see a single-region disk snapshot in one of its own
projects: **Resilience of Critical Assets** (Cloud SQL high availability,
automated backups, backup retention and point-in-time recovery; zonal managed
instance groups; single-region disk snapshots) ran in organization scans only,
with its three Asset Inventory listings under the organization. It now runs in
every scope, under the scanned folder or project, and each of its six checks
ends the scan with a verdict, so Stability counts it. The scope picker offers
active folders and projects only and names folders by their path and ID. No new
settings or permissions: the per-project checks already read Asset Inventory
under a project, and the organization-level `cloudasset.viewer` inherits down.

### Added

- **Resilience of Critical Assets in folder and project scans**
  (`app/checks/reliability.py`, `app/checks/registry.py`). The check takes the
  scope and lists Cloud SQL instances, managed instance groups and snapshots
  under `organizations/`, `folders/` or `projects/<scope id>`. It joins the
  common check plan after GKE Supported Versions — 22 checks in a folder or
  project scan (21 before), 26 in an organization scan as before — and stays a
  scope-level check: a sharded scan runs it once, in the scope shard, and a
  folder with no project runs it with Organization Policies. The
  organization-only block is now exactly the checks that describe the
  organization itself: Organization IAM Policy, Security Command Center Status,
  Organization Audit Logging, Essential Contacts (and Advisory Notifications
  read from the organization).
- **An all-clear row per check** (v15.2's rule for the cost checks): a listing
  that answered and flagged nothing writes a Compliant row — "No zonal (non-HA)
  Cloud SQL instances found.", "No Cloud SQL instances without automated
  backups found.", "No Cloud SQL instances retaining fewer than 30 backups
  found.", "No Cloud SQL instances with backups but without point-in-time
  recovery found.", "No zonal managed instance groups found.", "No single-region
  disk snapshots found." — so each of the six names reaches a verdict in every
  scan. A folder without a project reads "6 of 6 checks compliant" under
  Stability: its listings answered and every statement is true.
- **The scope picker** (`app/services/resource_manager.py`) asks Asset
  Inventory for `state:ACTIVE` folders and projects (a folder pending deletion
  was still offered) and names each folder by its path from the organization
  down and its ID — `stark-folder (1061012327179)`, `Engineering / Platform
  (4711)` — built from the parent the one search already returns, since folder
  names are unique only among siblings. A parent outside the account's view
  starts the path lower. Projects keep `Display name (project-id)`.

### Changed

- **Disk Snapshot Resilience names each snapshot.** One row per single-region
  snapshot — `Project · Snapshot · Location` — instead of "Found N snapshots
  stored in only one region.", so the report and the action-plan CSV say which
  snapshot, as the Cloud SQL and MIG rows already did. The first organization
  scan after the upgrade reads *not compared (rows changed)* for this check
  (`RESHAPED_CHECKS` in `app/reporting/changes.py`: a check whose rows changed
  shape in a release is not row-compared against a scan by an older release —
  the status still is); the next scan compares as usual.
- **A failed listing is an Error under the checks it served.** The Cloud SQL
  listing failing writes Error rows under the four Cloud SQL checks, the MIG or
  snapshot listing under its one; a credentials failure under all six. Before,
  one row named *Resilience Asset Checks* — a seventh name that was none of the
  six — stood for whichever listing had failed. The report counts these as
  "could not be checked" next to the score, never inside it.
- **Stability scores shift once.** Six verdicts join every scope's Stability
  arithmetic. On the stark organization five of the six already flagged
  something, so only Cloud SQL PITR's all-clear is new: 20% (2 of 10) → 27%
  (3 of 11); its folder went from 3 of 4 to 9 of 10. The Changes card shows
  the delta, as it did for the Cost rows in v15.2; the six rows themselves read
  *not compared (new check)* in the first folder or project scan after the
  upgrade (v15.5's rule).

### Tests

- New `tests/test_resilience.py` (the check's first unit tests, on a
  `list_assets` fake that answers by parent): the parent per scope, the six
  all-clear rows and their wording, the row shapes with one row per snapshot,
  a folder or project scan seeing only its own assets, a failed listing as
  Error rows under the names it served while the other listings reach a
  verdict, a credentials failure under every name, every name mapped to
  Stability. `tests/test_changes.py`: release ordering, which previous
  releases trigger the reshape rule, the status-only change, and `compare`
  across and within a release. `tests/test_api_parity.py`: the picker's
  `state:ACTIVE` request and the folder labels (nested, same-named under
  different parents, a parent outside the view, sorted) — the route is no
  longer compared with legacy, which searched without a state filter and
  named folders by display name alone; the organization and error cases still
  are. `tests/test_worker.py`, `tests/test_synthetic.py`,
  `tests/test_category_consistency.py`: the plan (22 / 26), the no-project
  plan, the synthetic folder and project scans listing the six checks with
  their listings under the scope, the empty folder with a Stability verdict.

### Upgrade notes

- Every scope's Stability score moves at its first v15.6 scan (see above);
  nothing to migrate. Reports and summaries by older releases are unchanged.
- Folder labels in the picker changed; the `id` the form submits did not.

---

## v15.5 — Release-aware comparison

The first folder scans with a project in the folder (v15.3, v15.4) compared
themselves with the scans of the folder while it was empty. Security went 13%
→ 81% and three failing checks appeared, but the since line said "0 new
findings · 0 resolved · no status changes", seventeen chips read *not compared
(new check)* and no row was marked **New**: a check absent from the previous
summary was treated as new to the release — the safe reading when the previous
scan may have been run by an older version — when in fact the previous scan
had nothing to check. The two cases are now told apart by the release that
wrote each summary. Nothing changes for a check present in both scans; no new
settings or permissions.

### Added

- **Every scan summary and the report name their release.** `app.config.VERSION`
  (`"15.5"`, the image tag without the `v`) is recorded in each summary as
  `release` (summary format 3) and shown in the report's sidebar footer under
  the generation time ("CloudGauge v15.5"), so a stored report can be matched
  to its release notes. A test pins the constant to the newest entry of this
  file, so a release cannot ship without bumping it.

### Changed: a check only in this scan (`app/reporting/changes.py`)

- **Both scans by the same release:** the release could have run the check
  then and did not, so there was nothing to check — an empty folder that has
  its first project now, a project with its first bucket. The check is
  compared with an empty previous result: every Action Required or
  Investigation Recommended row is **new**, counted in the since line and the
  card ("+3 new", chip tooltip "No result in the previous scan (nothing to
  check then), so every finding is new"), marked **New** in the table and
  flagged `yes` in the CSV; the Changes card lists it as "no result → Action
  Required" and the Scorecard's *Since last scan* cell says "+3 new · first
  result". A first result that is Compliant counts nothing and says nothing;
  an Error now is still *not compared (could not be checked now)*.
- **The previous scan by another release, or by one before v15.5 (its
  summary names no release):** *not compared (new check)*, as before. The
  rule is conservative across releases and self-corrects at the next scan.
- **The reverse — a check with a result then and none now:** within a
  release the card's footer says "No result in this scan: VM Rightsizing."
  instead of "No longer checked: …"; nothing is counted as resolved by it,
  as before.
- The Scorecard's since line now states a change from **0 projects** ("0 → 1
  projects"); a previous count of zero was dropped as if unknown.

### Tests

- `tests/test_changes.py`: the first-result rule on its own (rows, chip and
  tooltip; Compliant nothing; Error not compared) and what makes two
  summaries the same release; the card built within a release (Fresh's row
  new, Backups' first Compliant result silent, Retired "No result in this
  scan") next to the card built across releases and from a summary that
  names none; two rendered scans by this release (chip, New row, card entry,
  CSV flag, footer) and the same pair with the previous summary by v15.4 or
  unnamed (unchanged reading). `tests/test_scorecard.py`: the per-action
  since text; an empty scope's scan followed by its first project (10 new
  findings, 0 → 1 projects, "no result → Action Required" ranked first) and
  the reverse move (nothing resolved, 1 → 0 projects). `tests/test_reporting.py`:
  the footer. `tests/test_packaging.py`: `VERSION` is the newest entry here
  (`Dockerfile.test` now copies this file into the test image, which keeps
  every other Markdown file out, so the gate runs inside the build).
  `tests/test_scoring.py`, `tests/test_worker.py`: summary format 3 with the
  release; a version-1 summary (no release) still reads the old way.

### Upgrade notes

- The first scan of each scope after this upgrade compares itself with a
  summary that names no release, so it reads as before (*not compared (new
  check)* for a check the previous summary lacked); from the second scan on,
  the new rule applies. Nothing to migrate.
- Summaries written by v15.5 carry `release`; older releases ignore the field.

---

## v15.4 — Folder membership from Resource Manager

A folder scan finds its projects with Cloud Asset Inventory search, which is
recursive but eventually consistent. After the v15.3 rollout a project moved
into the scanned folder was missing from the folder-scoped search for 58
minutes (Resource Manager listed it in the folder at once), so a folder scan
started in that hour would have reported the folder without it — and the
header would have said "0 of 0 projects", true to the search and wrong about
the folder. One Resource Manager call per folder scan now closes the gap.
Organization and project scans are unchanged; no new settings or permissions.

### Added

- **A folder scan compares Asset Inventory with Resource Manager.** After the
  Asset Inventory search, the scan lists the folder's direct child projects
  with Resource Manager (v3 `projects.list(parent=folders/…)`, one paged call)
  and reconciles the two lists. A project Resource Manager lists in the folder
  that Asset Inventory did not return is **scanned too**. A project Asset
  Inventory still places directly in the folder that Resource Manager no
  longer lists there — moved out, deleted, or not readable by the scanner,
  which is why it is not dropped — is **kept and noted**. The report's header
  gains a **Folder membership** row ("1 project added from Resource Manager ·
  1 project no longer in this folder per Resource Manager", amber), the
  Overview a note under the count cards naming the projects, saying why and
  that they were scanned, and the Scorecard's Markdown copy carries the line
  in its meta; the worker log has a warning with the same project IDs. When
  the two sources agree — the normal case — nothing is shown and nothing is
  logged.
- If Resource Manager cannot be asked (a permission, an outage), the Asset
  Inventory list stands, the scan goes on, and the log says the membership
  was not checked. Projects under a subfolder are Asset Inventory's word
  alone: Resource Manager lists one level, and a walk of the folder tree was
  deliberately not added. The check costs one API call in a folder scan and
  nothing in the others. `app/services/resource_manager.py`
  (`reconcile_folder_projects`, `folder_membership`),
  `app/reporting/context.py` (`FolderMembership`).

### Tests

- New `tests/test_folder_membership.py`: the two sources agreeing (one
  Resource Manager call, nothing marked, nothing logged); a project only
  Resource Manager lists appended and marked, a project only Asset Inventory
  places in the folder kept and marked, each with its log line; a project
  under a subfolder left alone; inactive children not added; every page of
  Resource Manager's answer read; Resource Manager failing (the list stands,
  the warning logged); an organization scan never asking; the header row,
  the Overview note and the Scorecard meta for one project, for several
  ("a, b and 2 more") and for none; and a folder scan through `/run-scan`
  with the real listing over the fakes, where the added project reaches the
  checks, the coverage and the report.
- `tests/test_fanout.py`: a sharded folder scan carries the listing's marks
  through the manifest and the aggregated report states them.
  `tests/test_synthetic.py`: the per-scope synthetic scan asserts the one
  `projects.list` call in a folder scan, none otherwise, and no membership
  row when the two agree. `tests/fakes.py`: `FakeResourceManager` serves v3
  `projects.list` (children per folder, paging, errors), `FakeAssets.add`
  takes a `parent`; the synthetic provider answers `projects.list` from its
  world.

### Upgrade notes

- No new permission: `resourcemanager.projects.list` is in `roles/browser`,
  which the service account already holds on the organization.
- A folder scan run within an hour or so of moving a project into the folder
  now includes it, with the Folder membership row and note; the next scan,
  once Asset Inventory has caught up, shows neither. A scan run in the hour
  after a project is moved *out* of the folder still includes it (Asset
  Inventory still places it there) and says so.

---

## v15.3 — Folder and project scans

Three fixes from the first folder and project scans run against a real
organization (every earlier rollout had scanned at organization scope). None
changes an organization scan's report. No new settings.

### Fixed

- **A project scan applies its folders' policies before the organization's.**
  `get_effective_org_policies` walked `getAncestry` as the API lists it —
  project, folder, organization — then the project again, and applied the
  policies in that order, so the organization's policy replaced a folder's.
  A project under a folder that overrides a constraint reported the
  organization's value, while a folder scan of the same folder reported the
  folder's. The walk is now top-down for every scope (organization, folders
  from the farthest, then the resource itself, listed once), the nearest
  policy winning, as Resource Manager evaluates boolean constraints.
  Inherited from upstream beta v1; invisible in an organization whose
  projects sit directly under it.
- **An empty folder is still checked as a folder.** With no project to list
  the scan stopped before any check ran and uploaded an empty report — every
  category *Not assessed* under a header that said "0 of 0 projects ·
  folder-level checks completed". The runner now runs the scope-level checks
  (`registry.scope_check_plan`: Organization Policies for a folder or project;
  for an organization the org-only checks too) and skips location discovery,
  so the folder's effective policies are evaluated and the header is true.
  The same applies when the project listing failed: the scope's own checks
  run, and the listing error is in the logs as before.
- **The executive summary speaks of what was scanned.** Its prompt always
  asked for "the overall state of the organization's cloud environment"; it
  now says the folder's or the project's for those scans, and adds a
  **Scope** paragraph saying the report covers one folder or one project and
  that its Organization Policies rows are the policies in effect there. The
  paragraph is needed: with the subject alone, the first real folder scan's
  summary (an empty folder, whose report is only Organization Policies rows)
  still opened on "The organization's cloud environment"; with it, four runs
  out of four against the real model opened on "The folder" and "The project".
  The Scorecard sends the scope with the `/api/get-summary` request; a request
  without one (a report page rendered before v15.3) keeps the organization
  wording, so the legacy request shape produces the legacy prompt byte for
  byte.

### Tests

- New `tests/test_org_policies.py` with a `FakeResourceManager`
  (`tests/fakes.py`: `getAncestry`, `listOrgPolicies` on the three resource
  kinds, v3 `folders.get`): the listing order and the effective policies for
  an organization, a folder under a folder, a project under both and a
  project directly under the organization; the folder/project agreement that
  was broken; and the same agreement in the synthetic organization (the probe
  that found the bug). Four of the six failed before the fix.
- The per-scope synthetic scan (`tests/test_synthetic.py`) now pins what the
  scope changes: the title, the coverage line ("2 of 2 projects ·
  folder-level checks completed", "1 project"), the organization-only checks
  absent from folder and project reports, Organization Policies and Advisory
  Notifications present in all three. A new test scans an empty folder end
  to end: "0 of 0 projects · folder-level checks completed", a Security
  verdict from the policies, the other three categories *Not assessed*.
- `tests/test_worker.py`: the runner with no project runs exactly the
  scope-level plan for each scope and never calls location discovery; the
  no-projects scan test now states the difference from legacy (which uploaded
  an empty report) instead of parity.
- `tests/test_gemini.py` and `tests/test_api_parity.py`: the prompt's subject
  and Scope paragraph for each scope, and neither for no scope or an unknown
  one; the route forwarding the page's scope; `test_summary` still proves the
  legacy request's prompt unchanged.

### Upgrade notes

- A project scan of a project that sits in a folder with its own policies
  will show different Organization Policies rows than before — the folder's
  values, which are the effective ones. Scans of projects directly under the
  organization are unchanged.
- An empty folder's report gains its Organization Policies result and a
  Security score (the policies' share as recommended); Cost, Reliability and
  Operations stay *Not assessed*, as nothing in them can be checked without a
  project.

---

## v15.2 — Scores count verdicts

A change to how a category's score is computed, prompted by a question the
v15.1 Scorecard made visible: one production scan showed Operations at 25%
(▼ −4) and the next 29% with "no status changes". The first scan had a
*Projects not checked* item (one API call had failed for one project), and
an Error counted against the score — 2 of 8 instead of 2 of 7. Scores should
move when the estate moves, not when an API hiccups. No new settings; the
scan summary gains one field.

### Changed: the rule (`app/reporting/scoring.py`)

- **A score is the share of a category's checks that reached a verdict and
  were compliant**: `compliant / (compliant + Action Required + Investigation
  Recommended)`. The bands are unchanged (above 90 high, above 70 medium,
  otherwise low).
- **An Error is coverage, not a verdict.** A check in Error — the *Projects
  not checked* item included — is stated next to the score and never inside
  it. The Review scores table and the Scorecard's evidence line say "7 of 12
  checks compliant · 1 could not be checked"; the Scorecard's *Could not
  check* footer and the category pages list which. A transient failure no
  longer moves a score.
- **Organization Policies is one check with partial credit**, worth
  `compliant policies / total policies` of a pass. Before, every policy
  counted as a check, so 128 policies outweighed the 12 real checks in
  Security: the stark organization's Security score was 18% with 7 of 12
  checks compliant. It now reads **55%** — "7 of 12 checks compliant · 18 of
  128 policies as recommended". The Overview's count cards count it once as
  well (Action Required 127 → 18 on that organization), as the sidebar and
  the Scorecard already did.
- **A category without a verdict is *Not assessed***, not 100%: no number,
  no band, a fourth state on every surface — the Review scores row says *Not
  assessed* in words over an empty bar, the section pill says it, the
  Scorecard stoplight lights no lamp and shows a dash, the Markdown copy a
  dash and the state. A category page with nothing to list says "Not
  assessed — no Cost Optimization check reported a result in this scan."
- **The cost recommenders reach a verdict.** Each of the eight recommenders
  is a check: it now writes a Compliant row when it answered in at least one
  project and had nothing to recommend ("No idle persistent disks found."),
  as every other check does; Action Required anywhere still wins, and a
  recommender nobody could ask (no zones or regions to query, every call
  failed, or not offered in the queried locations) writes nothing. Cost
  Optimization therefore scores 100% "8 of 8 checks compliant" on a tidy
  estate instead of reading *Not assessed*.
- **Changes since last scan recomputes the previous scan under the current
  rule.** The previous scan's scores and counts are derived from the check
  statuses in its summary rather than read from the summary's stored
  numbers, so the first v15.2 scan does not show the rule change as a move
  of −109 Action Required or +37 points: the deltas are the estate's. A
  category not assessed on either side shows "—". The summary is now
  `version 2`: the Organization Policies entry carries `policies:
  {compliant, total}`; a version 1 summary is read the same way (its `rows`
  is the total and its identities are the differing policies).
- **Rounding is unchanged**: whole-point deltas are the difference of the
  rounded scores the reader sees.

### Tests

- The rule has its own module, `tests/test_scoring.py`: the tally
  (7 Compliant + 3 Error → 100% "3 could not be checked"; all Error → Not
  assessed; the briefings outside; (7 + 18⁄128) ⁄ 13 → 55), the bands, the
  evidence wording for every shape, and every surface that shows a score —
  ending with the 25%/29% case run end to end: a version 1 summary with a
  *Projects not checked* Error compared with a scan without it reads 29% →
  29%, "—", "no status changes", and lists the item as no longer checked.
- `tests/test_changes.py` fixes the invariant the recompute rests on
  (`scores_from_checks(summary["checks"]) == summary["scores"]`, the same
  for the Overview counts) and the version 1 fallback;
  `tests/test_not_checked.py` the cost verdicts against the fake recommender.
- The legacy parity tests compare everything but the scores, the section
  pills and the count cards (`helpers.SCORED_FACTS`): those diverged by
  design, and the legacy generator keeps the old rule untouched.

### Upgrade notes

- Expect scores to move once, on the first v15.2 scan, without a delta: on
  the stark organization Security 18% → 55%, Cost 100% → 100% "7 of 7"
  (it was 100% with no check; the eighth recommender, Idle Load Balancers,
  is not offered in that organization's region and reaches no verdict),
  Reliability and Operations unchanged; the count cards Action Required
  127 → 18, Compliant 29 → 18. The Changes card
  shows "—" against the previous scan where the previous scan's recomputed
  score equals the new one, and the estate's real deltas otherwise.
- A category that was 100% because nothing was found in it now reads *Not
  assessed* until a check reaches a verdict there; with the cost
  recommenders' all-clear rows this should only happen when a whole
  category could not be checked.

## v15.1 — The Scorecard

The QTR-brief page promised in v15's roadmap, and a fix to the CSV's table
order. No new settings and nothing new in the results bucket: a v15 scan's
summary is read as before, so the first v15.1 scan of a scope already shows its
deltas.

### New: the Scorecard, a report's one-pager

- **Who it is for.** The Overview is the operator's working page; the
  **Scorecard**, the next entry in the sidebar, is the page for the people who
  will not open the category pages — a quarterly technical review, a leadership
  update. It states only what the rest of the report can back: every number on
  it is read from the same context that renders the category pages
  (`app/reporting/scorecard.py`); nothing is recomputed.
- **Four stoplights**, one per pillar of the review playbook, each over one
  report category: Stability (Reliability & Resilience), Security (Security &
  Identity), Operations (Operational Excellence & Observability), Efficiency
  (Cost Optimization). Each is a three-lamp light that reads in monochrome, the
  category's score with its delta since the previous scan, a state in the bands
  the score bars already use — above 90 **Healthy**, above 70 **Needs
  attention**, else **At risk** — and the evidence behind it: compliant checks
  out of the scored ones, projects with findings and, for Stability, the Service
  Health briefing's tally ("1 incident impacted you in 90 days, 0 active").
  Velocity & Innovation has no checks yet, so it has no stoplight.
- **The since line.** Under the stoplights, one sentence: new and resolved
  findings since the previous scan (linked), the scope's size when it changed,
  the first three status changes — regressions first — and "N more" linking to
  the Overview's Changes card. A first scan says so: "First scan of this
  organization — changes appear from the next scan".
- **Top actions.** The ten failing checks (Action Required, then Investigation
  Recommended), ranked by status, then projects affected, then findings, then
  name — the card's note says so in those words, and the table shows all three
  keys, so the order is never a mystery; each links to its finding and shows,
  after a previous scan, what changed ("+3 new · was Compliant"). *Findings* is
  the count the category pages already use ("1,204 findings across 312 of
  1,000 projects"); the page, the Markdown copy and the action-plan CSV all
  call it that. A check that ships its own command (Essential Contacts,
  Personalized Service Health API Coverage, Advisory Notifications Settings,
  GKE Supported Versions) carries a quiet *fix in report* tag; the others get
  theirs from **Draft fixes**. Footers: the Organization Policies tally ("4 of
  30 organization policies differ from the recommendation", linked), the checks
  that could not run and how many more failing checks the category pages hold.
  A scan with nothing failing says "No failing checks — nothing to take away
  from this scan."
- **The executive summary lives here.** Gemini's executive summary is generated
  and read on the Scorecard, in an **Executive summary · Powered by Gemini**
  card that says what it will do until it is generated ("Not generated yet.
  Gemini reads this report's findings and writes a short summary of what stands
  out and what to do first.") and then holds the summary with its
  *AI-generated* pill and **Copy** button. **Generate executive summary** stays
  the report's one primary button; it is no longer on the Overview.
- **Three exports, one model.** **Print** prints the Scorecard alone, on one A4
  page (the report header above it included; the buttons and an empty summary
  card hidden). **Download action plan (CSV)** writes the ranked actions —
  `Priority, Check, Category, Status, Projects affected, Findings, Fix in
  report, Owner, Target date`, the last two blank for the owner to fill in — as
  `cloudgauge-action-plan-<scope id>-<date>.csv`. **Copy as Markdown** puts the
  stoplights, the since line and the actions on the clipboard as Markdown
  tables, with the executive summary appended once it has been generated. The
  exports are built in Python from the same model as the page and embedded in
  the report, so a stored report exports exactly what it shows.

### Changed: the Overview's Gemini card

- The card is now **Suggested fixes · Powered by Gemini**, with one outline
  button, **Draft fixes**, and copy that says where the drafts land ("Draft a
  gcloud fix for every failing finding that does not already show one; each
  appears under its finding on the category pages."). The executive summary and
  its primary button moved to the Scorecard; the Overview keeps the counts, the
  review scores, the Changes card and the drafts — the operator's tools — so
  the two pages do not repeat each other.
- Two decisions from the review of the preview, recorded here. The Top actions
  table has **no Fix column**: its only two values would have been "built in"
  and "AI-drafted", and the latter promised a draft that exists only after
  **Draft fixes** is pressed in the browser; so the rare checks that ship a
  command carry the *fix in report* tag and the action-plan CSV keeps a
  yes/blank `Fix in report` column. And the executive summary is generated
  **only on the Scorecard**, where it is read, rather than on both pages.
- The cards of a section are now 16px apart on every page; the Overview's sat
  flush against each other.

### Fixed: the CSV lists a category's tables as the page does

- The CSV wrote each category's check tables in the order the results
  **arrived** — which, under the sharded scan, is whichever shard finished
  first. Two scans of an unchanged estate could therefore differ in the file
  (the v15 production scan placed *Advisory Notifications Settings* after
  *Advisory Notifications*; the canary scan had placed it before) although
  the page, which sorts, was identical. The tables now come in the page's order:
  by the check's most severe status (Action Required, Investigation
  Recommended, Error, Informational, Compliant), then by name; a check with
  several records keeps them together and in order. Columns, rows and the
  `New since last scan` column are unchanged, and *Changes since last scan* was
  never affected (it matches rows by identity, not position).
- Tests: the same results fed in two arrival orders produce byte-identical
  CSV, and each category's table order equals the page's; the legacy parity
  tests for the CSV compare tables as a set rather than byte for byte, since
  the legacy writer kept arrival order.

## v15 — Changes since last scan, and GKE Supported Versions

The first release of the QTR-brief line: a scan of a scope now knows about the
scan before it, and the report says what changed. It also folds in the review
feedback on v14.2's Overview (the coverage line, the Gemini card's name and
copy, a Copy button on every fix) and adds one check, **GKE Supported
Versions**. No new settings; one new kind of object in the results bucket (see
*Upgrade notes*).

### New: the report compares itself with the previous scan of the scope

- **A summary per scan.** A finished scan files a small JSON document under
  `scopes/<scope>/<scope id>/<time>_<job id>.json`: its scores, its four
  counts, each check's status and, for the Action Required and Investigation
  Recommended checks, the identity of every row (Organization Policies counts
  as one check whose rows are the policies that differ). The next scan of the
  same scope lists that prefix once, takes the newest summary that is not its
  own (a retried render compares with the scan before, never with itself), and
  renders against it. Synthetic scans neither compare nor enter the history.
- **What the reader sees.** The header gains a **Previous scan** line (the
  time, linked to that report; or "none — first scan of this organization").
  Each count card says how it moved ("+2 since last scan", "unchanged since
  last scan"). A **Changes since last scan** card on the Overview, under the
  review scores, gives per category the score with its delta (▲ +6, ▼ −11, —),
  the rows resolved and new, and the status changes ("Public GCS Buckets
  Compliant → Action Required"; three inline, the rest behind "N more"), with
  the previous scan's time and the scope's size in its corner ("3 projects then
  · 4 now" when it changed) and a line for checks the previous scan had and
  this one does not. On the category pages a check whose rows changed carries a
  chip after its status pill ("+3 new · −5 resolved", or "not compared" with
  the reason in its tooltip), the rows the previous scan did not have carry a
  **New** marker, and the rows it had and this scan does not are listed under
  the table ("Resolved since last scan (5)", capped at 100 with "… and N
  more"). The CSV ends every structured row with a `New since last scan`
  column (`yes` or empty) so an action plan can be filtered on it; the
  existing columns do not move.
- **What makes two rows the same finding.** The row's cells minus the columns
  that only measure (numbers, dates) and the `Fix` and `Version` columns, with
  the digits in prose cells normalised, so a recommender that re-estimates a
  saving or rewords "taken 4 times" does not produce a new finding, and a GKE
  node pool that takes a patch while it stays on a retired minor is still the
  same one; the second identical row is "… #2", so two identical rows stay two
  findings. A check's text details are one line per finding, compared the same
  way.
- **The rules per check**, written so the numbers never flatter or alarm: a
  check in both scans with neither an Error is compared by identity (Compliant
  → Action Required lists every row as new, the reverse every previous row as
  resolved); a check that is an Error in either scan is *not compared* — an
  Error scan did not look, so nothing was resolved and nothing is new — and
  shows the status change only; a check only in this scan is *not compared
  (new check)*, never "all new"; a check only in the previous scan is listed
  once on the card; the briefings (Informational) are events, not findings, and
  are never compared.
- **Deltas are not statuses.** The deltas, chips and markers are muted
  monochrome, never rose or emerald: a score that fell is a number, not an
  alarm. The **New** marker is generated by CSS from the row's class, so it is
  not part of the row's text for sorting, filtering, the CSV or the Gemini
  prompts, and the parity suite still compares each report fact for fact with
  the legacy generator.

### New: GKE Supported Versions (Reliability & Resilience)

- **What it finds.** For every GKE cluster in the scanned projects, the control
  plane and each node pool whose minor version GKE **no longer offers** in that
  location (*Action Required*: "1.29 is no longer offered; the oldest supported
  minor is 1.30."), and those on the **oldest minor still offered** — the next
  to leave support (*Investigation Recommended*). The reference is GKE's own
  `projects.locations.getServerConfig`, read once per location: a cluster on a
  release channel is judged against its channel's `validVersions` (the row
  says so: "… no longer offered on the Regular channel"), a cluster without one
  against the static `validMasterVersions` / `validNodeVersions`. A minor newer
  than anything in the list (a preview, a list that lags) is never flagged; the
  check does not invent alarms, and it does not guess dates — the end-of-support
  date is on the release schedule, not in the API.
- **One row per component**, `Project · Cluster · Location · Component ·
  Version · Issue`, with a `Fix` per row: the `gcloud container clusters
  upgrade … --master|--node-pool=… --cluster-version=…` command to the newest
  patch of the oldest supported minor (the next minor for the Investigation
  rows), shown once per distinct command in the Fix block under the table and
  in full in the CSV. A control plane more than one minor behind says
  "Control planes upgrade one minor at a time"; a node pool never targets a
  version beyond its control plane, and one that cannot move until the plane
  does says "Upgrade the control plane first" instead of carrying a command.
- **Where it sits.** After *Service Health Incidents* in the plan, under
  Reliability & Resilience, in every scope; a sharded scan runs it per shard
  like the other project checks. A project in which the Kubernetes Engine API
  is disabled has no clusters and is left out; any other failure (a denied
  `clusters.list`, an unreadable server config) is reported under *Projects not
  checked*. It complements **GKE Hygiene** (release channel, auto-upgrade),
  which stays as it is. The synthetic organization gives its clusters versions
  (one project in ten runs a retired minor, two in ten the oldest supported
  one), so load tests and the demo report exercise the check.

### Changed: the Overview, after the v14.2 review

- **Coverage is back, on every scan.** v14.2 showed the coverage line only for
  sharded scans; it now sits in the report header for every scan ("312 of 312
  projects · organization-level checks completed"), with an amber dot and the
  detailed note under the count cards only when a sharded scan did not finish
  everything. Single-task scans list the scope's projects before the checks
  run, so they can state it too.
- **AI analysis, powered by Gemini.** The Gemini card is now titled **AI
  analysis** with a quiet *Powered by Gemini* attribution, says what it does
  ("Generate an executive summary, or draft fixes for failing findings."), and
  its buttons read **Generate executive summary** (the page's one primary
  action) and **Draft fixes**.
- **Copy on every fix.** Each **Fix** block and each *Suggested fix
  (AI-generated)* block has the same **Copy** control as the executive summary,
  in a title row above the commands; the three share one clipboard helper.

### Unchanged, deliberately

- **What a report says about a scan.** Every check, finding, count, score,
  summary line and "Projects not checked" item is what v14.2 produced; the
  comparison only adds to it, and a first scan (or a scan whose previous
  summary cannot be read) renders exactly as before, with "Previous scan:
  none".
- **The CSV's existing columns, the API and the URLs.** The `New since last
  scan` column is appended, and only when there is a previous scan.
- **IAM.** The new check reads the Kubernetes Engine API with the permissions
  GKE Hygiene already needs (`container.clusters.list`); `getServerConfig`
  needs no more than that.
- **Sharded scans.** The dispatcher, the shards, the markers and the
  aggregation are untouched; the aggregator reads the previous summary and
  files the new one exactly as a single-task scan does, after the reports are
  uploaded.

### Upgrade notes

- **One new object per scan in the results bucket**, under `scopes/`. Nothing
  reads or writes it but the scan job (and a missing or unreadable summary
  costs only the comparison, which is logged), so no IAM change is needed. The
  summaries are small (about 80 bytes per finding row: 150 KB for a scan
  with 2,000 rows that need work, under 10 MB for 100,000) and are never
  deleted by the application; a lifecycle rule on `scopes/` is the place to
  bound them if you want to.
- The first scan after the upgrade is a first scan: it writes its summary and
  shows "Previous scan: none". The comparison starts with the second. Its
  *GKE Supported Versions* item reads "not compared (new check)" on that
  second scan's Changes card, as every new check does.

Tests: 557 (new `tests/test_changes.py`: identities, the rules per check, the
card, and two-scan renders read through the report's markup and the CSV; a
two-scan worker test in `tests/test_worker.py` that also retries a render; the
fan-out suite asserts that sharded scans compare and that synthetic ones do
not; new `tests/test_gke_versions.py`: the version rules, the rows of a
cluster, and the check against a fake Kubernetes Engine API).

---

## v14.2 — The redesign: one design system for the three pages

A release about how the application looks and reads, prompted by a review of
the v14.1 pages: they relied on framework defaults — primary red, green and
blue, drop shadows, boxy cards, one type size for everything — and did not
read as a product built for enterprise review. No new checks, no new settings,
no upgrade steps; the data on every page is unchanged.

### Changed: the three screens

- **Setup and status** are one centred card (448px) on a dot-grid canvas. The
  setup card is the two selects and one black **Start scan** button, with a
  help line under the resource select that says what happened ("3 projects
  available", "No folders are visible to the service account.", or, in rose,
  "Couldn't load the projects. Check the service account's permissions and
  the application logs."). The status card shows a thin progress bar, the
  current task and the job ID; then **Scan complete** with **View interactive
  report** and **Download CSV**, or **Scan failed** with the last message in
  a code block and a link to start another scan. The card names the scope
  ("organization 880241551927").
- **The report's Overview** has a fixed sidebar — each category with a dot in
  the colour of its worst status and the number of items that need a human,
  and a "Generated" time at the foot — four count cards with the numbers set
  large and light, the coverage line with its own dot, the review scores as
  bars (bar, percentage, "3 of 11"), and the Gemini card.
- **Category pages** show the checks as accordions. Each row is a dot, the
  name with the one-line summary under it, and a status pill; the items that
  need a human (Action Required, Investigation Recommended, Error) are open
  on load, Compliant and Informational ones collapsed. **Expand all** /
  **Collapse all** sit on the toolbar next to the filter box; the filter opens
  what it matches and restores the default when cleared; printing opens
  everything; a `#<section>-<check>` link opens that one check. The category
  heading carries a "27% compliant" pill and a strip of per-status counts.
- **The Gemini flows** were restyled with the rest. *Get AI summary* writes
  the summary into its own card under the actions — rendered from Gemini's
  Markdown (headings, lists, bold, code), labelled *AI-generated*, with a
  **Copy** button and a footnote — and the button reads *Retry summary* after
  an error. *Get remediation suggestions* shows "Gemini is drafting a fix…"
  under each finding it asked about, and a status line under the actions
  says where the answers landed ("Suggested fixes added to 12 findings:
  Security & Identity (5) · Cost Optimization (7)", with links to the pages),
  how many Gemini declined, and after an error how many were added before it
  and that **Try again** asks only for the rest. Error notices are the same
  rose notice everywhere.

### The design system

Everything shared lives in `app/templates/_design.css` — tokens (Tailwind's
zinc / rose / amber / emerald / sky palette, Inter and a monospace stack) and
primitives (card, notice, buttons, dot, pill, chip, table, form controls,
spinner) — and is inlined into every page, so a stored report still depends on
nothing served later. The rules, which the new `tests/test_design.py` holds
the templates to:

| Rule | In practice |
|---|---|
| Separation is a 1px border, never a shadow | zinc-200 borders on cards, the sidebar and each accordion row; no `box-shadow` anywhere |
| A quiet canvas, white content | zinc-50 page, white cards and rows |
| One high-contrast primary action per page | the zinc-900 button; everything else outlined or a text link |
| Status is a dot and a soft pill in a semantic colour | rose / amber / emerald / zinc / sky for the five statuses, each pill a pale fill, a one-shade-darker border and dark text of its hue; never raw red or green |
| Inter for text, monospace for anything a machine would read | IDs, principals, instances, dates, counts, scores, the report and job IDs; the KPI numbers are the one exception (light Inter, tabular figures) |
| Dense, quiet tables | no vertical rules; uppercase letter-spaced zinc-500 headers; a hairline under each row; a hover; 6px cell padding |
| Sentence-case copy | "Review your cloud environment", "Scan complete", "Get AI summary"; status and category names keep their capitals |

### Unchanged, deliberately

- **What the pages say.** Every check, finding, count, score, summary line,
  coverage sentence and "Projects not checked" item is the same; the parity
  suite still compares each report fact for fact with the legacy generator.
- **The CSV, the API and the URLs.** `/api/*` requests and responses, the
  form the setup page posts, the values the status page embeds and polls,
  and the report's three Gemini calls are byte-for-byte what they were.
- **The scale rules of v14.1** (sorting, paging, filtering, clamping, chips
  and disclosures) now sit on the new table primitive. One layout change: an
  incident's ID moved from its own column to a monospace line under the
  incident's title, so the incident table is six columns.

Tests: 459 (new `tests/test_design.py`; the index and status pages are
compared with the legacy module on what they tell the browser — form target,
field names, scope values, embedded constants, polled URLs — rather than
line by line).

---

## v14.1 — One remediation convention, readable briefing tables

A patch release prompted by a review of v14's report: the two briefings were
unreadable at normal page widths, and the report had two ways of offering a
fix. No new checks, no new settings, no upgrade steps.

### Changed: where a fix is shown

Until v14 the report offered remediation one way: the **Get Remediation
Suggestions** button asked Gemini for every Action Required or Investigation
Recommended finding. v14 then gave its two new scored checks and Essential
Contacts a `Fix` column — the exact `gcloud` command — without reconciling the
two, so a reader saw a fix up front for three checks and had to ask Gemini for
the rest (user question: *"I want to understand the reasoning for this being
different from the rest of the flow"*). There was no good reason; the
deterministic fix is simply more reliable than a generated one wherever a check
can compute it. v14.1 makes it one convention:

- **Every failing finding has one remediation block, under its table.** A check
  that knows its fix shows a **Fix** block with the distinct commands (one line
  per distinct value, the CSV keeps every row's). The `Fix` column is gone from
  the page; it stays in the CSV.
- **Gemini fills the gaps.** *Get Remediation Suggestions* asks only for the
  findings without a fix block and renders its answer in the same place,
  labelled *Suggested fix (AI-generated)*. When every finding already shows its
  fix, the button says so instead of calling Gemini.
- Any check can opt in by writing a `Fix` key in its rows (README, *Adding a
  check*).

### Fixed: the briefing tables

The v14 incident table had ten columns and the notification table five, two of
them long texts; at normal widths the browser squeezed them until the legacy
stylesheet's `word-break: break-all` split words anywhere ("Resolve / d",
"JZBYGF / V", "Sensitiv / e Action / s"), and three caps in the checks had
already cut the data before it reached the page or the CSV (ten locations, 400
characters of message, three attachment rows). Three changes:

- **Cells wrap at word boundaries**, short columns (dates, states, IDs, counts)
  stay on one line, a table wider than the page scrolls sideways instead of
  squeezing, and a plain cell longer than a few lines is clamped to three with
  a *Show more* toggle. These rules apply to every table in the report.
- **The briefings have their own layouts** (`app/reporting/layouts.py`, a
  presentation layer over the raw rows). An incident is
  `State | When (UTC) | Incident | Products | Projects | Relevance | ID`: start
  and end stacked, the locations as a muted line under the title (a long list
  as "14 locations", opening on click), the projects as "37 projects" that
  opens to the list, Products its own sortable column. A notification is
  `Date | Type | Notification | Details` (+ `Projects` in folder and project
  scans): the message under its subject, clamped to three lines from its first
  line with *Show full message*; attachments and digest actions as a list with
  the first three items shown and the rest behind "N more".
- **Nothing is shortened at the source.** Every location, every attachment row
  (up to 25 quoted, then a count) and the whole message (one line per
  paragraph) are in the page and in the CSV, whose columns are unchanged and
  raw. Everything behind a disclosure is in the page as text, so the filter box
  and column sorting see it, and the print stylesheet unclamps it.
- **Informational and Error badges are visible.** The legacy stylesheet gave
  them no background, so their white text was invisible — a gap every briefing
  (always *Informational*) and every *Projects not checked* item (*Error*) fell
  into. They now use the same grey as their icons.

Tests: 445 (new `tests/test_layouts.py`; the parity suite still compares the
legacy checks' tables byte for byte, which the new rules leave unchanged).

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

## Roadmap: see [docs/roadmap.md](docs/roadmap.md)
