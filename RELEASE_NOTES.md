# CloudGauge Release Notes

Release notes for the `refactor/modular-factory` line of CloudGauge: the modular
rewrite of the original single-file application, the sharded scan architecture
that lets it cover organizations of any size, the report built for that scale,
and the checks added since. Each version was rolled out the same way: build with
the test suite running inside the image, a zero-traffic canary revision scanned
against a real organization, promotion, and a production scan compared fact for
fact with the previous version's report.

Versions are the image tags (`v5` … `v18.6`); the commit is the one that shipped.

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

## Roadmap

Driven by the Quarterly Technical Review agenda (executive stoplight summary;
operational excellence — incident retrospective and security posture; product
performance; modernization; enablement; roadmap and roadblocks).

| Release | Theme | Contents |
|---|---|---|
| **v15.1** | The QTR brief | *Shipped.* The **Scorecard** page (a stoplight per pillar with its evidence, the since line, top actions, action-plan CSV, Markdown copy, one-page print) on top of v15's scan summaries and *Changes since last scan*; the executive summary is generated there. |
| **v15.2** | Scores count verdicts | *Shipped.* A category's score is the share of its checks that reached a verdict and were compliant: Errors are stated next to the score, not inside it; Organization Policies is one check with partial credit; a category without a verdict is *Not assessed*; the cost recommenders write all-clear rows; the previous scan is recomputed under the current rule. |
| **v15.3** | Folder and project scans | *Shipped.* From the first real folder and project scans: a project scan applies its folders' policies before the organization's; an empty folder still gets its scope-level checks; the executive summary speaks of the folder or project that was scanned. |
| **v15.4** | Folder membership | *Shipped.* A folder scan compares Cloud Asset Inventory's project list with Resource Manager's direct children (one call): a project Asset Inventory has not caught up with is scanned too, one it still places in the folder is kept and noted, and the report says so only when the two disagree. |
| **v15.5** | Release-aware comparison | *Shipped.* Every scan summary and the report's footer name the release; between two scans of one release a check with no earlier result is compared with nothing — its rows are new, counted and marked — instead of *not compared (new check)*, which stays for a previous scan by another release. |
| **v15.6** | Resilience at every scope | *Shipped.* Resilience of Critical Assets (Cloud SQL HA, backups, retention and PITR; zonal MIGs; single-region snapshots, now named one by one) runs in folder and project scans under the scanned scope, and each of its six checks reaches a verdict so Stability counts it; the scope picker offers active folders and projects only and names folders by their path and ID. |
| **v16** | Authenticated by default | *Shipped.* Deployed **without `--allow-unauthenticated`**: people sign in through Identity-Aware Proxy on the web service's own `run.app` URL — no load balancer, domain, certificate or OAuth client — and a separate worker service is reachable by Cloud Tasks alone (`--ingress internal`, IAM); the pages say who is signed in and the report who requested the scan; `tools/deploy.sh` is the deployment; the public single service becomes an explicit, discouraged option. |
| **v16.1** | Multi-region snapshots pass, downloads behind the sign-in | *Shipped.* *Disk Snapshot Resilience* reads the kind of a snapshot's storage location: a multi-region (`asia`, `eu`, `us`) is geo-redundant and compliant, a single region is flagged — the first scan after the upgrade says *rule changed* instead of listing the snapshots as resolved. The status page's **Download CSV** is the web service's own route, streamed, so a report's downloads — like its pages — exist only for someone IAP let in; the service account no longer needs Token Creator on itself. |
| **v17** | History, analytics and FinOps | *Shipped.* **BigQuery export** of every scan (`scans`, `findings`; free load jobs the header accounts for; a backfill for earlier scans), **scheduled scans** (Cloud Scheduler → the worker, as the service account, one scan per scope at a time), the **history page** (pillar scores over time, status flips per scan), the analytics guide (five queries, Looker Studio, Gemini Enterprise); **FinOps** — six more recommenders, cost-allocation labels, storage lifecycle, snapshot sprawl, commitments expiring, a savings total on the Scorecard; **capacity** — reservations and commitments, reservation coverage, stockout and quota signals, accelerator quotas with headroom; Cloud SQL extended support; IAM least privilege. No new organization-level role, nothing on billing accounts. |
| **v17.1** | The SSRF chain: GKE and identity hardening | *Shipped.* **GKE Credential Exposure** (metadata server, node account, roles, scopes, *one SSRF from roles/editor*), **Service Account Impersonation** (who can become which service account, with reach), **GKE Control Plane Exposure**, **GKE Node Hardening**, **GKE Threat Detection**, **VPC Service Controls Coverage**; the nine `container.managed.*` guardrails in Organization Policies. No new role, no new API. |
| **v17.2** | Deploy with Terraform | *Shipped.* `terraform/` declares the deployment of `tools/deploy.sh` — the APIs, the account and its roles, the bucket, the queue, the worker and the web service behind IAP, the export, the schedules, and on request the organization-level roles — in two applies around one Cloud Build; the test suite holds it to the script, the README and the app. |
| **v17.3** | Incidents as evidence | *Shipped.* The Service Health briefing off the Scorecard and the executive summary, *Impacted* plus location-specific *Related* by default, switchable; **Incident Exposure** (the customer's zonal assets in the locations and product of each location-specific incident, one row per asset with the incidents as evidence) and **GKE Cluster Resilience** (zonal control planes, single-zone node pools); list cells fixed. No new role, no new API. |
| **v18** | Legacy checks revalidated | *Shipped.* The twenty-two inherited checks re-read against today's APIs and Security Health Analytics: what was wrong corrected (a constant SCC tier, Monitoring needles no filter contains, list constraints scored as failures, `requireSsl`, deny rules as findings, the Google APIs agent as a finding, OS Config's swallowed errors, stopped VMs' released addresses), verdicts split between *Action Required* and *Investigation Recommended*, a `Fix` on every row that has one, *rule changed* on the Changes card. |
| **v18.1** | Legacy checks revalidated — what is loose | *Shipped.* Cloud Storage Versioning scoped to log-sink destination buckets (soft delete, lifecycle rules and retention policies as protection); VPC Configuration without proxy-only subnets and with the default network's auto-subnets collapsed; Organization Log Sink's filter, state and `includeChildren`, and a **Data Access Audit Logs** check from the `auditConfigs` of the scanned resource and its ancestors; Essential Contacts without invalid contacts and in every scope; cost recommendations by priority with fix lines, **MIG Rightsizing**; GKE auto-repair; project-global quotas; firewall complexity retired; the best-practices table bundled in the image, replaceable by a `gs://` or `https://` URL and amended by an overrides file in the results bucket, with a provenance line in the report. No new role, no new API. |
| **v18.2** | GKE upgrade readiness & hygiene | *Shipped.* **GKE Upgrade Readiness** — maintenance windows, active exclusions, upgrade notifications and security bulletins, surge settings, version skew, and the **PodDisruptionBudgets** that block drains, read from Cloud Asset Inventory; **GKE Observability** — system and control-plane metrics, Managed Prometheus, NodeLocal DNSCache; GKE Node Hardening gains integrity monitoring, intra-node visibility, routes-based and alpha clusters. No new role, no new API. |
| **v18.3** | Network edge & reachability | *Shipped.* **Hybrid Connectivity** (tunnels down, HA VPN on one interface, Classic VPN, Interconnect without a redundant attachment, one BGP peer for two links), **Load Balancer Edge** (HTTP-only, weak TLS, no Cloud Armor, logging off), **DNS Posture** (DNSSEC, RSASHA1, Cloud DNS logging), **VPC Flow Logs**, **VPC Peering & Cloud NAT** (inactive peerings, MTU mismatch, NAT logging and port allocation); Open Firewall Rules reads firewall policies; VPC Configuration flags legacy networks. No new role, no new API. |
| **v18.4** | Data governance | *Shipped.* **BigQuery Governance** (public datasets and tables, the time-travel window), **Cloud SQL Flags** (the CIS flag pack of each engine, unset flags read as their defaults, the patch line keeping the flags already set), **AlloyDB Posture** (backups, zonal primaries, public IP, TLS, log flags), **KMS Keys** (90-day rotation of symmetric keys, public rings and keys, separation of duties), **API Keys** (application and API restrictions, age). No new role, no new API. |
| **v18.5** | VM hardening & identities | *Shipped.* **VM Service Accounts** (the default account, by its roles and scopes), **VM Hardening** (OS Login and project-wide keys per project; serial console, IP forwarding, Shielded VM and Secure Boot per instance), **Service Account Privileges** (administrative roles on service accounts, separation of duties), **External Principals** (users, groups and domains outside the organization and `TRUSTED_DOMAINS`, consumer accounts, deleted principals, public folders and images), **Unused Service Accounts** (the IAM recommender's 90-day insights). No new role, no new API. |
| **v18.6** | Serverless and edge exposure | *Shipped.* **Serverless Exposure** (public Cloud Run services and functions — by binding or by the disabled invoker check — and services reachable around their load balancer), **Serverless Service Accounts** (the default account on Cloud Run and Cloud Functions, by its roles), **Cloud Armor Policy Content** (legacy rulesets, policies that protect nothing, preview-only WAFs, the rule quota), **SSL Certificate Health** (expiring self-managed and failed Google-managed certificates), **Container Scanning Enabled** (Artifact Analysis off beside Docker repositories); IAP over HTTP in Load Balancer Edge; the time-travel row graded by billing model, a Note on the contested Cloud SQL flags, zonal buckets out of Cloud Storage Versioning. The first release deduced from the google/skills mining and the Workload Manager catalogue diff. No new role, no new API. |
| **v18.7** | Folders, keys and privileged grants | **Folder Primitive Roles** (Owner/Editor on folders — nothing reads them today), **Privileged Grant Inventory** (project creators and billing roles at the organization, `domain:` grants, fewer than two Organization Admins), **Secret Access Scope** (secret-accessor and admin roles granted resource-wide, with the secrets in reach; Secret Manager replication and rotation), **Service Account Key Lifecycle** (any active user-managed key, never-expiring keys, validity above 90 days), **Custom Roles With IAM Powers**, **Data Admin Role Sprawl**. No new role, no new API. |
| **v18.8** | Forecasts, budgets and spend | A **spend briefing** from the organization's **billing export to BigQuery** (`BILLING_EXPORT=<project>.<dataset>`, a dataset-level read, no billing-account IAM; *Informational — not configured* when unset): spend by project and service, month-to-date against last month, a trend forecast, week-over-week anomaly flags, the Scorecard's Efficiency line grounded in real spend; **commitment coverage** from the export's credits; the spend-based commitment recommendations from the Recommender export once that export carries billing-account rows; plus the config-level cost rows the skills mining found — log retention, DEBUG volume and flow-log sampling, serverless VPC connectors, versioning without pruning, uncovered BigQuery baseline slots, staging datasets without expiry, non-production Cloud SQL HA, backend buckets without CDN, resource labels beyond projects, GKE cost allocation. Budget coverage (billing-account IAM) and Capacity Planner forecasts stay optional-later. |
| **v18.9** | Logging pipeline and alerting hygiene | **Audit Log Pipeline** (sink filters missing audit log types, destination retention and lock, the writer's grant, export errors), **Duplicate Log Routing** (central sink plus untouched `_Default` sinks; free audit streams re-stored), **Project Log Routing** (`_Default` disabled, Data Access logs in the default view, Log Analytics), **Alert Notification Channels** (policies routed to nobody, unverified or disabled channels, undeliverable Pub/Sub channels), **Synthetic and SLO Coverage**. No new role, no new API. |
| **v19** | Footprint and detection | A **Platform Footprint** page (what runs where: services, regions, versions); the detective half of the SSRF chain over Cloud Logging — **GKE control-plane activity** (exec, webhooks, RBAC and DaemonSet changes by service accounts or external IPs), **service-account activity signals**; **Findings and vulnerabilities** — Security Command Center active findings by category (the v2 API answers under the roles already held), detector services and modules off, findings export, VM Manager OS vulnerabilities with a fix available, exposed privileged VMs (the join of three existing checks); a **Support cases** briefing (its own API and role, its own decision); the deprecations recommender, once confirmed to exist. |
| Later | | In this order: GKE health, backup and support (cluster conditions and CA expiry, Backup for GKE, end of support, workload disruption readiness); Compute reliability (disk backup coverage, VM availability policy, MIG and load-balancer resilience, reservations); managed databases and storage finished (Cloud SQL deletion protection, maintenance windows, password policy, CA expiry, IAM authentication; AlloyDB open networks; Public Access Prevention, versioning without cleanup; BigQuery unpartitioned tables); the data plane never read (Pub/Sub, Memorystore, Filestore, Spanner, Bigtable, Firestore, NetApp); org-policy depth and residency (exceptions below the root, domain-restriction values, location and service-usage drift); SLO coverage, PDF export. The Workload Manager results import does not ship (a new role, a per-project API, a dedupe layer). |
