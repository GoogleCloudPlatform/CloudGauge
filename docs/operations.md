# Deployment and operations

What a deployer runs: the prerequisites and the three deployment methods, the zero-downtime upgrade, how to use the pages, the synthetic load test, troubleshooting and the cleanup script. Who may sign in and what every request is checked for: [security.md](security.md); every variable, role and name as a contract: [stability.md](stability.md).

In this page: [Deployment Instructions](#deployment-instructions) — [Common Prerequisites](#common-prerequisites-required-for-all-methods), [Method 1: `tools/deploy.sh`](#method-1-deploy-with-toolsdeploysh-recommended), [Method 2: the Console](#method-2-deploy-from-the-console), [Method 3: Terraform](#method-3-deploy-with-terraform) · [Updating an Existing Deployment (Zero-Downtime)](#updating-an-existing-deployment-zero-downtime) · [How to Use](#how-to-use) · [Load Testing with a Synthetic Organization](#load-testing-with-a-synthetic-organization) · [Troubleshooting](#troubleshooting) · [Cleanup Script](#cleanup-script)

## Deployment Instructions

CloudGauge runs as **two Cloud Run services from one image**, in a project of your choice:

| Service | `CLOUDGAUGE_ROLE` | Who reaches it | How it is deployed |
|---|---|---|---|
| **Web** — `cloudgauge` | `web` | People, through **Identity-Aware Proxy**: a Google sign-in on the service's own `run.app` URL, open to the accounts, groups or domains granted `roles/iap.httpsResourceAccessor`. | `--iap --no-allow-unauthenticated`; `WORKER_URL` names the worker. Small: concurrency 80, 1 GiB, 600 s. |
| **Worker** — `cloudgauge-worker` | `worker` | Cloud Tasks only, as the service account (`roles/run.invoker`); `--ingress internal` keeps the internet out even with a token. | `--no-allow-unauthenticated --ingress internal`; 3600 s, concurrency 4, 2 GiB. |

No load balancer, domain, certificate or OAuth client is involved: IAP on Cloud Run needs the `iap.googleapis.com` API and the `--iap` flag. A project that belongs to an organization needs no console step; gcloud warns that a project without one may need a one-time setup in the console the first time IAP is enabled.

These two are the two halves of the application, not two copies of it, and that is all a deployment is: **two services, one revision each**, whichever method below you use — and two idle services cost what one idle service does, nothing, since no minimum instances are set. A *canary* is never a service: it is a zero-traffic revision tag on one of these two, which only [Updating an Existing Deployment](#updating-an-existing-deployment-zero-downtime) creates and whose last step removes it. A fresh deployment has none.

Do the **Common Prerequisites** once, then deploy with **Method 1** (the script; recommended, and also the way to update), **Method 2** (the console) or **Method 3** (Terraform, for teams that keep their infrastructure declared; it can do the organization step of the prerequisites too), and grant access: [Who can use it](security.md#who-can-use-it). The single public service that releases before v16 deployed is still possible: [A public deployment (discouraged)](security.md#a-public-deployment-discouraged).

### Common Prerequisites (Required for all methods)

1. **Enable APIs**:  
   * A Google Cloud Project with billing enabled.  
   * [gcloud CLI](https://cloud.google.com/sdk/install) installed, current (`gcloud components update` — `--iap` is a recent flag) and authenticated (`gcloud auth login`).  
   * An account that is **Owner** of that project: the setup enables APIs, creates the service account and grants its project roles, creates the bucket, runs Cloud Build, deploys to Cloud Run and sets the IAP policy (`roles/iap.admin`, part of Owner). The organization-level roles in step 2 additionally need someone who can grant roles on the organization.
   * Run the following two commands to enable all necessary APIs (`tools/deploy.sh` does this too). Two, because gcloud enables at most 20 APIs per command — first what CloudGauge runs on, then what it reads:

   ```
   gcloud services enable \
       run.googleapis.com \
       cloudbuild.googleapis.com \
       artifactregistry.googleapis.com \
       cloudtasks.googleapis.com \
       iap.googleapis.com \
       iam.googleapis.com \
       iamcredentials.googleapis.com \
       cloudresourcemanager.googleapis.com \
       storage.googleapis.com \
       logging.googleapis.com \
       aiplatform.googleapis.com

   gcloud services enable \
       recommender.googleapis.com \
       securitycenter.googleapis.com \
       servicehealth.googleapis.com \
       advisorynotifications.googleapis.com \
       essentialcontacts.googleapis.com \
       compute.googleapis.com \
       container.googleapis.com \
       sqladmin.googleapis.com \
       osconfig.googleapis.com \
       monitoring.googleapis.com \
       cloudasset.googleapis.com

   # v17: scheduled scans, the BigQuery export; v17.1: the perimeters (Access Context Manager, read-only); v19: the SCC detector services (read-only)
   # v19.2: the open support cases (Cloud Support API, read-only; the two support records read Informational without it)
   gcloud services enable cloudscheduler.googleapis.com bigquery.googleapis.com accesscontextmanager.googleapis.com securitycentermanagement.googleapis.com cloudsupport.googleapis.com
   ```

   > The Service Health and Advisory Notifications APIs must be enabled in the project CloudGauge runs in: the scanner calls them on behalf of every scanned project, and the report says so (as an *Error* on the two Service Health / Advisory Notifications items) if either is missing. The **Personalized Service Health API Coverage** check additionally lists the *scanned* projects in which `servicehealth.googleapis.com` is not enabled.
   

2. **Create Service Account & Grant Permissions**:  
   * This SA is the identity of both services: it scans the organization, creates the tasks and invokes the worker.
   * `tools/deploy.sh` creates it and grants the **project-level** roles (2 and 3 below) if they are missing. The **organization-level** roles (1 and 1b) are the one manual step, for an account that can grant roles on the organization — unless you deploy with Terraform and set `organization_id` ([Method 3](#method-3-deploy-with-terraform)), which grants them. **v17 adds no organization-level role**: the new checks read through roles the account already holds — `roles/iam.securityReviewer` lists every Recommender (the commitment, IAM and quota recommenders included), `roles/compute.networkViewer` the reservations, commitments and quotas, `roles/logging.viewer` the capacity signals, `roles/cloudasset.viewer` the snapshots, disks and Cloud SQL versions. The BigQuery export, when configured, adds two **project-level** grants in the project CloudGauge runs in (step 2c), nothing on the organization. Nothing on any **billing account** either: billing access is centralised in most organizations, so CloudGauge does not read billing accounts; spend-based commitments arrive, when the *Forecasts, budgets and spend* release is taken up, through the organization's Recommender export to BigQuery. **v17.1 adds no role either**: the cluster listing and the IAM searches go through `roles/cloudasset.viewer`, the access policies and perimeters and the custom roles through `roles/iam.securityReviewer`, the threat-detection settings through `roles/securitycenter.settingsViewer`. It enables one API in the project CloudGauge runs in, `accesscontextmanager.googleapis.com`, for read-only calls. **v19.2 adds no role either**: the two support records read the open cases through `cloudsupport.techCases.list`, which `roles/iam.securityReviewer` carries (a deployment on a custom role set can add `roles/cloudsupport.techSupportViewer`); it enables `cloudsupport.googleapis.com` in the project CloudGauge runs in, and without the API or the permission the two records read *Informational* with the command that configures them — never an error, never a layout change.
```
   # Set your Organization ID
   export ORG_ID="<your-org-id>"

   

   # Set Project and SA variables

   export PROJECT_ID=$(gcloud config get-value project)
   export SA_NAME="cloudgauge-sa"
   export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

   

   # Create the Service Account

   gcloud iam service-accounts create ${SA_NAME} --display-name="CloudGauge Service Account"

   

   #  Grant Permissions 

   

   # 1. Grant ORG-level roles to read assets and policies

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/browser"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudasset.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/compute.networkViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/essentialcontacts.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/recommender.iamViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/logging.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/monitoring.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/orgpolicy.policyViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/resourcemanager.organizationViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/servicehealth.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/securitycenter.settingsViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.securityReviewer"

   

   # 1b. Advisory Notifications (v14): a custom org role that can list the notifications AND read the
   #     notification settings. The predefined roles/advisorynotifications.viewer cannot read the settings,
   #     and the admin role can change them; this role is read-only. The same role covers the per-project
   #     reads of a folder or project scan (roles granted on the organization are inherited).

   gcloud iam roles create CloudGaugeAdvisoryViewer --organization=${ORG_ID} \
       --title="CloudGauge Advisory Notifications Viewer" \
       --description="Read-only access to Advisory Notifications and their settings for CloudGauge scans" \
       --permissions=advisorynotifications.notifications.list,advisorynotifications.notifications.get,advisorynotifications.settings.get \
       --stage=GA

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="organizations/${ORG_ID}/roles/CloudGaugeAdvisoryViewer"

   

   

   # 2. Grant PROJECT-level roles (on the project where Cloud Run is deployed)

   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/aiplatform.user"

   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudtasks.admin"

   # 2b. Cloud Build runs as this account too (see step 4): read the uploaded source, push the image, write the build log

   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudbuild.builds.builder"

   # 2c. (v17, only with BIGQUERY_DATASET) the export: load jobs in the project, and WRITER on the dataset alone
   #     (tools/deploy.sh creates the dataset in REGION and grants both; see History and analytics)

   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/bigquery.jobUser"

   # 2d. (v18.8, only with BILLING_EXPORT) the spend records: the same Job User role for the two queries per scan, and
   #     READER on the billing export dataset alone — a dataset-level entry the dataset's owner adds once (tools/deploy.sh
   #     adds it when the dataset is in PROJECT_ID; see Spend under History and analytics). Nothing on the billing account.

   

   # 3. Service Account User on the SA itself: the web service hands its own identity to Cloud Tasks
   #    (the task's OIDC token for the worker), which needs iam.serviceAccounts.actAs on that account

   gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} --member="serviceAccount:${SA_EMAIL}"  --role="roles/iam.serviceAccountUser"
```
3. **Create GCS Bucket** (`tools/deploy.sh` creates it in the services' region, with uniform bucket-level access, if it is missing):
```
export BUCKET_NAME="cloudgauge-reports-${PROJECT_ID}"

gsutil mb -p ${PROJECT_ID} gs://${BUCKET_NAME}

gcloud storage buckets add-iam-policy-binding gs://${BUCKET_NAME} --member="serviceAccount:${SA_EMAIL}" --role="roles/storage.objectAdmin"
```
4. **The image is built as `cloudgauge-sa`.** Left to itself, Cloud Build runs as the project's Compute Engine default service account; organizations commonly withhold that account's roles, and the build then fails before it starts (`…-compute@developer.gserviceaccount.com does not have storage.objects.get access` to the uploaded source). Rather than widening that account, CloudGauge builds as its own service account, which step 2b equips for it: `tools/deploy.sh` passes `--service-account` to Cloud Build (Method 1); a console trigger is told the same (Method 2, Step 2).
---

### Method 1: Deploy with `tools/deploy.sh` (Recommended)

One command deploys everything; run again, it updates the deployment.

```
git clone https://github.com/GoogleCloudPlatform/CloudGauge
cd CloudGauge

PROJECT_ID="my-project" REGION="asia-south1" \
OPERATORS="group:cloud-team@example.com,user:alice@example.com" \
tools/deploy.sh
```

The script, in order (every step is idempotent):

1. **Setup** — enables the APIs, creates `cloudgauge-sa` with its project roles (Cloud Build's among them) and its self-binding (Service Account User, for Cloud Tasks), creates the bucket `cloudgauge-reports-<project>` (the organization-level roles stay the manual step above).
2. **Build** — `gcloud builds submit` with `cloudbuild.yaml`, as `cloudgauge-sa`: builds the image, runs the test suite inside it and pushes it only if every test passes. The tag is the short git hash.
3. **Worker** — deploys `cloudgauge-worker` with `CLOUDGAUGE_ROLE=worker`, `--no-allow-unauthenticated --ingress internal --timeout 3600 --concurrency 4 --memory 2Gi`, and makes the service account its only invoker.
4. **Web** — deploys `cloudgauge` with `CLOUDGAUGE_ROLE=web`, `WORKER_URL` (the worker), `PROJECT_NUMBER`, `--iap --no-allow-unauthenticated --concurrency 80 --memory 1Gi --timeout 600`, and grants IAP's service agent `roles/run.invoker` on it.
5. **Access** — grants each `OPERATORS` entry `roles/iap.httpsResourceAccessor` on the web service.
6. **Export** *(v17, with `BIGQUERY_DATASET`)* — creates the dataset in `REGION` if missing and lets the service account load into it (WRITER on the dataset, `roles/bigquery.jobUser` on the project).
   **Spend** *(v18.8, with `BILLING_EXPORT`)* — lets the service account read the billing export dataset (READER on it when it is in `PROJECT_ID`, `roles/bigquery.jobUser` on the project).
7. **Schedules** *(v17, with `SCHEDULES`)* — creates or updates one Cloud Scheduler job per entry, posting to the worker's `/scheduled-scan` with the service account's OIDC token.

It ends with the URL to open. Both services are told `WORKER_URL` = Cloud Run's deterministic URL of the worker, `https://cloudgauge-worker-<project number>.<region>.run.app`, which is known before the worker exists, so nothing is discovered at startup and no `roles/run.viewer` is needed.

| Variable | Default | Meaning |
|---|---|---|
| `PROJECT_ID` | *required* | The project CloudGauge runs in. |
| `REGION` | `asia-south1` | Region of the services, the queue and the bucket. |
| `SERVICE`, `WORKER_SERVICE` | `cloudgauge`, `${SERVICE}-worker` | The two service names. |
| `QUEUE`, `BUCKET`, `SERVICE_ACCOUNT` | `cloudgauge-scan-queue`, `cloudgauge-reports-${PROJECT_ID}`, `cloudgauge-sa` | The names from the prerequisites (an email works for the service account). |
| `IMAGE`, `TAG` | `gcr.io/${PROJECT_ID}/${SERVICE}`, the short git hash | What to build and deploy. |
| `OPERATORS` | – | Comma-separated principals allowed to sign in: `user:`, `group:`, `domain:` (a bare email counts as a user). |
| `EXTRA_ENV` | – | More settings for both services, `KEY=VALUE,KEY=VALUE` (see [Configuration Reference](stability.md#configuration-reference)); values cannot contain commas. |
| `COST_ALLOCATION_LABELS` | – | The label keys every project must carry, `cost-center,environment,owner` (v17, [Cost Allocation Labels](checks.md#cost-optimization)); its own variable because the value has commas. |
| `TRUSTED_DOMAINS` | – | Domains besides the organization's primary one whose users and groups **External Principals** does not list, `partner.example,acquired.example` (v18.5); its own variable for the same reason. |
| `BIGQUERY_DATASET` | – | Export every finished scan to this BigQuery dataset (v17): the script creates it in `REGION` if missing, grants the service account WRITER on it and `roles/bigquery.jobUser` on the project, and sets the variable on both services ([History and analytics](history-and-export.md#history-and-analytics)). |
| `BILLING_EXPORT` | – | The BigQuery dataset the billing account exports to, `<project>.<dataset>` (v18.8, [Spend](history-and-export.md#spend)): the script grants the service account READER on it when it is in `PROJECT_ID` (the dataset's owner does otherwise) and `roles/bigquery.jobUser` on the project, and sets the variable on both services. `SPEND_ANOMALY_FLOOR` (a number) rides along. |
| `SCHEDULES` | – | Scheduled scans (v17), semicolon-separated `NAME=SCOPE/SCOPE_ID@CRON` with the cron in UTC: `"weekly-org=organization/123456789012@30 0 * * 1"`. One Cloud Scheduler job per entry, created or updated, posting to the worker's `/scheduled-scan` as the service account. |
| `SKIP_SETUP=1`, `SKIP_BUILD=1` | – | Skip step 1 (updating a deployment that works); skip step 2 and deploy `IMAGE:TAG` as it is. |
| `PROGRAMMATIC_ACCESS=1` | – | Also lets the service account through IAP and lets your gcloud account sign tokens for it, so `tools/iap_token.py` works ([Who can use it](security.md#who-can-use-it)). |
| `DRY_RUN=1` | – | Prints the gcloud commands instead of running them. |

To update, run the same command (`SKIP_SETUP=1` saves a minute); for a canary first, see [Updating an Existing Deployment](#updating-an-existing-deployment-zero-downtime). If a step fails right after the first setup, the IAM grants may still be propagating: run the command again a minute later. The script needs a shell with bash and gcloud (Cloud Shell works).

---

### Method 2: Deploy from the Console

Two Cloud Run services created from your fork of the repository with Cloud Build (the console builds the `Dockerfile`), the worker first.

**Step 1: Fork the GitHub repository**

1. Navigate to the [CloudGauge GitHub repository](https://github.com/GoogleCloudPlatform/CloudGauge/).  
2. Click the **Fork** button in the top-right corner of the page.  
3. Choose your GitHub account as the destination for the fork. This will create a copy of the repository under your account (e.g., `https://github.com/your-username/CloudGauge`).

**Step 2: Create the worker service**

1. In the Google Cloud Console, go to **Cloud Run** → **Create Service** → **Continuously deploy new revisions from a source repository** → **Set up with Cloud Build**. Connect your fork (install the Google Cloud Build app on GitHub if asked), choose the `main` branch, **Build Type** `Dockerfile`, source location `/Dockerfile`. The trigger this creates builds *and deploys* as the Compute Engine default account; make it `cloudgauge-sa` instead (prerequisites step 4): **Cloud Build** → **Triggers** → the new trigger → **Service account** `cloudgauge-sa`, and in its advanced options **Logging: Cloud Logging only** (a build with a chosen service account must say where its log goes). Because the trigger also deploys the revision, this method needs one more project role for `cloudgauge-sa`: `gcloud projects add-iam-policy-binding <project> --member="serviceAccount:cloudgauge-sa@<project>.iam.gserviceaccount.com" --role="roles/run.admin"`.  
2. **Service name**: `cloudgauge-worker`. **Region**: for example `asia-south1`.  
3. **Authentication**: **Require authentication**. **Ingress**: **Internal**.  
4. Expand *Container(s), Volumes, Networking, Security*:  
   * **Identity & Security**: the `cloudgauge-sa` service account.  
   * **General**: request timeout `3600`, maximum concurrent requests per instance `4`, memory `2 GiB` (a shard of a large scan may run for 30 minutes; see [Scaling to Large Organizations](architecture.md#scaling-to-large-organizations)).  
   * **Variables & Secrets**:  
     * `PROJECT_ID`, `LOCATION` (the region), `TASK_QUEUE` (`cloudgauge-scan-queue`), `RESULTS_BUCKET`, `SERVICE_ACCOUNT_EMAIL`  
     * `CLOUDGAUGE_ROLE`: `worker`  
     * `WORKER_URL`: `https://cloudgauge-worker-<project number>.<region>.run.app` — the URL Cloud Run will give the service (the project number is on the console's dashboard). Or leave it out and, after the first deployment, grant the service account `roles/run.viewer` on the service so that it discovers its own URL.  
     * Optional settings such as `GEMINI_MODEL` are listed in the [Configuration Reference](stability.md#configuration-reference).  
5. **Create**. Once it is up, let Cloud Tasks — which calls as the service account — invoke it: on the **Cloud Run** service list tick `cloudgauge-worker`, open the info panel's **Permissions** tab, **Add principal** `cloudgauge-sa@<project>.iam.gserviceaccount.com` with the role **Cloud Run Invoker**. The same with gcloud:

```
gcloud run services add-iam-policy-binding cloudgauge-worker --region=<region> \
  --member="serviceAccount:cloudgauge-sa@<project>.iam.gserviceaccount.com" --role="roles/run.invoker"
```

**Step 3: Create the web service**

As in Step 2, with these differences: **Service name** `cloudgauge`; **Authentication**: **Require authentication**, and turn on **Identity-Aware Proxy (IAP)**; **Ingress**: **All**; **General**: timeout `600`, concurrency `80`, memory `1 GiB`; variables: the same five, plus `CLOUDGAUGE_ROLE`: `web`, `WORKER_URL`: the worker's URL, `PROJECT_NUMBER`: your project number. Enabling IAP from Cloud Run grants IAP's service agent the invoker role by itself; should the service answer 403 to everyone afterwards, grant it by hand — the same **Permissions** panel, principal `service-<project number>@gcp-sa-iap.iam.gserviceaccount.com`, role **Cloud Run Invoker** — or:

```
gcloud run services add-iam-policy-binding cloudgauge --region=<region> \
  --member="serviceAccount:service-<project number>@gcp-sa-iap.iam.gserviceaccount.com" --role="roles/run.invoker"
```

Then grant access ([Who can use it](security.md#who-can-use-it); in the console, **Security** → **Identity-Aware Proxy**). From now on each push to `main` builds and deploys both services.

---

### Method 3: Deploy with Terraform

The deployment of Method 1, declared in [`terraform/`](../terraform/) *(v17.2)*: the 25 APIs, `cloudgauge-sa` with its project roles and its self-binding, the bucket, the Cloud Tasks queue (with the limits the services expect), the worker (internal ingress, invoked by the account only), the web service (IAP enabled, IAP's service agent as invoker, each operator granted `roles/iap.httpsResourceAccessor`), and — when asked — the BigQuery export dataset, the Cloud Scheduler jobs and the organization-level roles of the prerequisites, custom role included. Terraform builds no image, and the build runs as the account Terraform creates, so a first deployment is two applies around one build:

```
git clone https://github.com/GoogleCloudPlatform/CloudGauge
cd CloudGauge/terraform
cp terraform.tfvars.example terraform.tfvars        # project_id, operators, …
terraform init
terraform apply                                      # 1. the foundation: APIs, account, roles, bucket, queue, dataset
cd .. && $(terraform -chdir=terraform output -raw build_command)   # 2. the image, built and tested by Cloud Build as the account
terraform -chdir=terraform apply -var image_tag=$(git rev-parse --short HEAD)   # 3. the services, IAP, access, schedules
```

`terraform output next_step` says what comes next at each point, and `web_url` is the page to open. Credentials are Application Default Credentials (`gcloud auth application-default login`) of an account that can create the resources in the project — and grant roles on the organization if `organization_id` is set. Put `image_tag` in `terraform.tfvars` once it is known; a release is the same build command followed by `terraform apply` with the new tag.

| Variable | Default | Meaning |
|---|---|---|
| `project_id` | *required* | The project CloudGauge runs in. |
| `region`, `service_name`, `worker_service_name`, `service_account_name`, `bucket_name`, `queue_name`, `image` | as in Method 1 | The names. `image` is the repository without a tag. |
| `image_tag` | – | The tag to deploy. Empty: the foundation only (first apply). |
| `operators` | `[]` | Who may sign in: `user:`, `group:`, `domain:` principals. |
| `organization_id` | – | Set it to grant the organization-level roles (prerequisites step 2, 1 and 1b) and create the `CloudGaugeAdvisoryViewer` role (`advisory_role_id`). If that role already exists, `terraform import` it or choose another ID. |
| `bigquery_dataset`, `cost_allocation_labels`, `trusted_domains`, `schedules`, `extra_env` | – | As in Method 1; `schedules` is a map of name → `{ scope, scope_id, cron }`, cron in UTC. |
| `scan_max_concurrent_shards`, `task_max_attempts` | `25`, `3` | The queue's limits and the services' `SCAN_MAX_CONCURRENT_SHARDS` / `TASK_MAX_ATTEMPTS`, kept equal. |
| `programmatic_access_principals` | `[]` | What `PROGRAMMATIC_ACCESS=1` does: the account through IAP, and these principals allowed to mint its tokens (`tools/iap_token.py`). |
| `deletion_protection`, `force_destroy` | `true`, `false` | A `terraform destroy` refuses the services and keeps the bucket and dataset until both are flipped. |

**Terraform and the runbook.** Terraform owns the services' shape — image, variables, resources, identity, ingress, IAP — and ignores traffic splits and tags, so [Updating an Existing Deployment](#updating-an-existing-deployment-zero-downtime) works on a Terraform-managed deployment too: its finalize step is `terraform apply` with the tested tag (which also puts `WORKER_URL` / `WORKER_AUDIENCE` back), then `update-traffic --to-latest --remove-tags canary` — not optional: a `--no-traffic` deploy pins the traffic to the revision that was serving, and since Terraform never touches traffic, the revision its apply creates serves nothing until `--to-latest`. A `terraform plan` after a canary deploy shows those two variables (and the image, if it changed), never the traffic. Use `tools/deploy.sh` or Terraform for a deployment, not both. Cloud Tasks reserves a deleted queue's name for 3 days: a redeploy within that time needs another `queue_name`. The folder has no provider block and names its project everywhere, so it can also be called as a module from your own configuration (`source = "github.com/GoogleCloudPlatform/CloudGauge//terraform?ref=<commit>"`). More in [`terraform/README.md`](../terraform/README.md).

## Updating an Existing Deployment (Zero-Downtime)

To roll out a new version safely, deploy it to both services as tagged revisions that receive **no traffic**, test it at the web canary's URL, then shift traffic.

```
export PROJECT_ID="my-project" REGION="asia-south1"
export SERVICE="cloudgauge" WORKER_SERVICE="${SERVICE}-worker"
export IMAGE="gcr.io/${PROJECT_ID}/${SERVICE}" TAG=$(git rev-parse --short HEAD)
export SA_EMAIL="cloudgauge-sa@${PROJECT_ID}.iam.gserviceaccount.com"
export PROJECT_NUMBER=$(gcloud projects describe ${PROJECT_ID} --format='value(projectNumber)')
export WORKER_MAIN="https://${WORKER_SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"
export WORKER_CANARY="https://canary---${WORKER_SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"
export WEB_CANARY="https://canary---${SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"

# 1. Note the revisions currently serving traffic (your rollback targets)
for S in ${WORKER_SERVICE} ${SERVICE}; do gcloud run services describe $S --region ${REGION} --format='value(status.traffic[0].revisionName)'; done

# 2. Build, test, and push
gcloud builds submit . --config cloudbuild.yaml --substitutions=_IMAGE=${IMAGE},_TAG=${TAG} \
  --service-account=projects/${PROJECT_ID}/serviceAccounts/${SA_EMAIL}

# 3. The worker canary: 0% traffic, reachable at its tag URL; its own tasks (shards, aggregation, sweeps) go there too
gcloud run deploy ${WORKER_SERVICE} --region ${REGION} --image ${IMAGE}:${TAG} --no-traffic --tag canary \
  --update-env-vars WORKER_URL=${WORKER_CANARY},WORKER_AUDIENCE=${WORKER_MAIN}

# 4. The web canary: its scans go to the worker canary
gcloud run deploy ${SERVICE} --region ${REGION} --image ${IMAGE}:${TAG} --no-traffic --tag canary \
  --update-env-vars WORKER_URL=${WORKER_CANARY},WORKER_AUDIENCE=${WORKER_MAIN}

# 5. Test at ${WEB_CANARY}: IAP protects the tag URL like the main one (sign in, or tools/iap_token.py with the tag URL)

# 6. Shift traffic, the worker first
gcloud run services update-traffic ${WORKER_SERVICE} --region ${REGION} --to-tags canary=100
gcloud run services update-traffic ${SERVICE} --region ${REGION} --to-tags canary=10
gcloud run services update-traffic ${SERVICE} --region ${REGION} --to-tags canary=100

# 7. Finalize: deploy the tested tag as the latest revision of both services with the normal settings
#    (WORKER_URL back to the worker's main URL, WORKER_AUDIENCE removed), then drop the tags
SKIP_SETUP=1 SKIP_BUILD=1 TAG=${TAG} tools/deploy.sh
for S in ${WORKER_SERVICE} ${SERVICE}; do
  gcloud run services update-traffic $S --region ${REGION} --to-latest
  gcloud run services update-traffic $S --region ${REGION} --remove-tags canary
done

# Rollback at any time (both services)
gcloud run services update-traffic ${WORKER_SERVICE} --region ${REGION} --to-revisions <OLD_WORKER_REVISION>=100
gcloud run services update-traffic ${SERVICE} --region ${REGION} --to-revisions <OLD_WEB_REVISION>=100
```

**Why the canaries need two overrides:**
* `WORKER_URL`: the web canary must send its scans to the worker *canary*, and the worker canary must send its own shard, aggregation and sweep tasks to itself, not to the revision serving the worker's main URL.
* `WORKER_AUDIENCE`: by default a task's OIDC token is issued for the task URL, which is now the tag URL. Cloud Run rejects that with HTTP 401, and the scan never starts. A token issued for the worker's main URL is accepted on any of its tag URLs.

A canary does not touch the pages' access: the IAP bindings belong to the service, so the same people can open the tag URL. On a deployment made with Terraform ([Method 3](#method-3-deploy-with-terraform)), step 7 is `terraform apply -var image_tag=${TAG}` instead of `tools/deploy.sh`, and the `--to-latest` / `--remove-tags` loop that follows it is what moves the traffic to the revision Terraform created; the rest is the same.

## How to Use

1. Open the web service's URL and sign in with a Google account that was granted access ([Who can use it](security.md#who-can-use-it)); the header says who is signed in.  
2. Choose your scope: Organization, Folder or Project.
3. Choose the resource from the list (the organization the service runs in, or one of its folders or projects).
4. Click **Start scan**.  
5. You will be redirected to a status page. A project or a small organization takes a few minutes; a large organization runs in parallel shards and the page counts the projects scanned (see [Sizing for your organization](architecture.md#sizing-for-your-organization) for what to expect).  
6. Once finished, **View interactive report** and **Download CSV** appear. The report itself also has a **Download CSV** button (the same route, every row), a filter box, and sortable, paged tables (see [Reports for Large Organizations](architecture.md#reports-for-large-organizations) and [The Pages](architecture.md#the-pages)). Three things run on demand from the report, so they cost nothing until asked for: the Scorecard's **executive summary**, the Overview's **Draft fixes**, and the Cost Optimization page's **Get detailed insights**.

   **Two kinds of fixes, one place.** Some findings show a **Fix** block under their table as soon as the report opens, before anyone presses anything: those are the checks that *know* their fix — they hold the resource names, so the `gcloud` line is exact (the GKE and identity checks of v17.1, the Service Health coverage check, Essential Contacts, GKE versions, and since v18 the legacy Security checks — Primitive Roles, the organization's critical roles, SA keys, public buckets, firewall rules, Cloud SQL, VM external IPs — and OS Config, GKE Hygiene and the Monitoring and Unattended rows; since v18.1 the cost recommendations, Cloud Storage Versioning, VPC Configuration, UBLA, the log sink and the Data Access audit configuration; since v18.2 GKE Upgrade Readiness and GKE Observability; since v18.3 the five network-edge checks; since v18.4 the five data-governance checks; since v18.5 the VM and identity checks; since v18.6 the serverless and edge checks; since v18.7 the folder, grant, secret, custom-role and key checks). The block says so: *exact, from the check*. **Draft fixes** is for the rest: it asks Gemini only about the failing findings that have no fix block, writes its answers in the same place marked *AI-generated*, and never rewrites an exact one; when every failing finding already shows its fix, the button says so instead of calling Gemini. The CSV has `Fix` as a column on every row that has one; the Scorecard's top actions tag such a check *fix in report*.

> **Checks that can't run are reported, not hidden.** If a check fails (for example, a missing permission or a disabled API), the report shows it with status **Error** and the reason, in the check's own section. Errors do not count against that section's score — they are stated next to it ("1 could not be checked") and a section with nothing but errors is *Not assessed* — so fix the cause (see [Permission Denied on Google Cloud APIs](#permission-denied-on-google-cloud-apis)) for a complete score.

> **Data freshness.** Cloud Asset Inventory has two read paths and they are not equally fresh. Its **search index** reflects a change within minutes and, for most asset types, carries the resource's content; its **listing** (`listAssets`) is refreshed by periodic snapshots and was measured hours behind (a new VM listed 95 minutes after creation, a project's metadata change the next morning). Since v18.5 the checks that read the scope's inventory in one pass — the network edge, data governance, the VM checks — read the search index first and fall back to the listing only for the types the index returns no content for or when the search fails; the identity checks read the IAM policies from the IAM-policy search. The index is prompt about a resource's *existence*; a *change* to an existing resource reached neither path for a long time in the same measurements, so the checks whose rules turn on such changes read the product API: GKE clusters (v18.2), VPN tunnel state (v18.3), since v18.5 every project's instances and common instance metadata — the inventory also **omits the `ssh-keys` metadata item** on both paths, so project-wide keys are only visible to the API — and since v18.6 Cloud Run services, jobs and their invoker policies, Cloud Functions, the backend services in front of them, Cloud Armor policies and certificates, and Artifact Analysis's state. A finding fixed minutes before a scan is therefore gone from the scan, and the Changes card says *resolved*. The older per-project checks call the product APIs directly and were always fresh.

> **What differs by scope.** Every scope runs the same project checks over the projects in scope, Organization Policies as they are *effective* at the scanned resource, and **Resilience of Critical Assets** (Cloud SQL HA, backups, retention and PITR; zonal MIGs; single-region snapshots) over the Asset Inventory of the scanned organization, folder or project (since v15.6; organization scans only before), **Essential Contacts** as they are *effective* at the scanned resource and **Data Access Audit Logs** from its IAM policy and its ancestors' (since v18.1), **GKE Upgrade Readiness** and **GKE Observability** over the clusters and PodDisruptionBudgets under the scope (since v18.2), and the network edge — **Hybrid Connectivity**, **Load Balancer Edge**, **DNS Posture**, **VPC Flow Logs**, **VPC Peering & Cloud NAT** — over the scope's inventory (since v18.3), and data governance — **BigQuery Governance**, **Cloud SQL Flags**, **AlloyDB Posture**, **KMS Keys**, **API Keys** — over the scope's inventory and IAM-policy search (since v18.4), and **VM Service Accounts**, **VM Hardening**, **Service Account Privileges** and **External Principals** over the scope's instances, compute projects and IAM policies (since v18.5), and **Serverless Exposure**, **Serverless Service Accounts**, **Cloud Armor Policy Content**, **SSL Certificate Health** and **Container Scanning Enabled** over the scope's serverless workloads, edge and registries (since v18.6), and **Folder Primitive Roles**, **Secret Access Scope**, **Secret Manager Posture** over the folders and secrets under the scope and the entitlements and custom roles of **Privileged Grants** and **Custom Roles With IAM Powers** (since v18.7; the organization-level rules of those two — project creation, billing roles, administrator redundancy, deny policies, the organization's custom roles — are judged in an organization scan), and **Spend Briefing** and **Spend Anomalies** over the export rows of the projects under the scope and **Serverless Cost Hygiene** over the scope's workloads and connectors (since v18.8), and **Audit Log Pipeline** over the scanned resource's own log sinks, **Duplicate Log Routing** over the aggregated sinks of the organization and the folders in scope against the projects' `_Default` sinks, and **Synthetic and SLO Coverage** over the scope's external load balancers, Cloud Run services and GKE clusters (since v18.9), and **SCC Active Findings** over Security Command Center's findings under the scope and **Exposed Privileged VMs** over the scope's instances, firewall rules and policies (since v19), and **Platform Footprint** over the scope's inventory, **GKE Control Plane Activity** over each project's Admin Activity log and **Service Account Activity Signals** over the scanned resource's own Admin Activity entries and each project's (since v19.1), and **Support Cases** and **Case Hygiene** over the open support cases under the scope (since v19.2), and **Organization Policy Exceptions** over every organization policy set under the scope and **Bucket Logging** over the buckets, projects and IAM policies under it (since v19.3). An organization scan adds the checks that describe the organization itself: **Organization IAM**, **Security Command Center Status**, **Organization Audit Logging**, **Unattended Projects**, and the organization's own Advisory Notifications and Recent Changes.

> **Folder scans and recently moved projects.** A folder scan finds the folder's projects with Cloud Asset Inventory, which can lag a project move or creation by an hour or more, so it also asks Resource Manager for the folder's direct child projects (one call) and compares the two. A project Resource Manager lists in the folder that Asset Inventory does not yet is scanned too; one Asset Inventory still places there that Resource Manager no longer does (moved out, deleted, or not readable by the scanner) is scanned anyway. When the two disagree the header shows a **Folder membership** row and the Overview a note naming the projects; when they agree — the usual case — nothing appears. Projects under a subfolder of the scanned folder come from Asset Inventory alone.

## Load Testing with a Synthetic Organization

Few teams have a spare organization with a thousand projects, but that is the size at which a scan is most likely to hang, exhaust API quota, or run out of memory. The **synthetic load mode** scans a *generated* organization instead of Google Cloud: every data-plane API the checks call (Resource Manager, Compute, IAM, Storage, Asset Inventory, Recommender, Cloud SQL, GKE, Monitoring, Logging, OS Config, ...) is answered from a deterministic in-process model (`app/synthetic/`), with simulated latency, optional quota errors (429) and projects whose APIs are denied (403). The checks, the reports, Cloud Tasks and the results bucket are the real code paths: nothing in the scan pipeline knows it is being fed synthetic data.

The organization is derived from `(seed, project index)`, so the same settings always produce the same projects, VMs, buckets, IAM bindings, findings, and so on. Project IDs look like `syn-42-00017`.

**1. Offline, in-process (no Google Cloud needed).** `tools/synthetic_scan.py` runs one scan job the way the worker does, against an in-memory results bucket, and prints what matters for capacity planning: API calls per API and per method, wall-clock time versus simulated API wait, peak concurrent calls, peak memory, objects written to the bucket, and report sizes.

```
python tools/synthetic_scan.py --projects 100                     # 150 ms median API latency (realistic)
python tools/synthetic_scan.py --projects 1000 --latency-ms 0     # CPU and call counts only, in seconds
python tools/synthetic_scan.py --projects 50 --error-rate 0.02 --denied-fraction 0.1 --scope folder
python tools/synthetic_scan.py --projects 200 --quiet --json run.json   # machine-readable, for comparing runs
python tools/synthetic_scan.py --projects 1000 --shard-size 20 --concurrency 25   # the sharded path, in-process
```

Reports are written to `synthetic-reports/` (or `--output-dir`). Add `--quiet` to hide the scan's own log lines.

With `--shard-size`, the harness runs the job the way the deployed service runs a large scope: the dispatcher plans the shards, an in-process queue plays Cloud Tasks (named tasks created once, `--concurrency` deliveries at a time, retries up to `--max-attempts`), every shard runs its checks under `--shard-budget-seconds`, the last one triggers the aggregation, and the sweeper finds the job complete. The summary adds the dispatch time, the median and longest shard, retries, the aggregation time, and the report's coverage line. The reports of a sharded and a single-task run of the same organization contain the same checks, statuses and rows.

**2. Deployed, end to end.** Deploy the normal image as a *separate* Cloud Run service (or a no-traffic tagged revision) with `CLOUDGAUGE_ENV=synthetic` and `SYNTHETIC_PROJECTS=<n>`, plus the usual required variables. Cloud Run, Cloud Tasks and the results bucket are real, so request timeouts, task deadlines and retries, memory limits and status polling behave exactly as they would for a real organization of that size, while no Google Cloud API other than the Cloud Run Admin API (worker URL discovery) is called. The scope picker lists the generated organization, folders and projects. Every page and report carries a **SYNTHETIC LOAD TEST** banner, and the mode cannot be switched on by accident: it needs both the profile *and* `SYNTHETIC_PROJECTS`, and the production profile ignores all `SYNTHETIC_*` variables.

```
gcloud run deploy cloudgauge-loadtest --region ${REGION} --image ${IMAGE}:${TAG} \
  --service-account ${SERVICE_ACCOUNT_EMAIL} --memory 2Gi --timeout 3600 --concurrency 4 \
  --set-env-vars PROJECT_ID=${PROJECT_ID},LOCATION=${REGION},TASK_QUEUE=cloudgauge-loadtest-queue,\
RESULTS_BUCKET=${RESULTS_BUCKET},SERVICE_ACCOUNT_EMAIL=${SERVICE_ACCOUNT_EMAIL},\
CLOUDGAUGE_ENV=synthetic,SYNTHETIC_PROJECTS=1000
```

> **What the runs show.** With the default 150 ms latency, 20 projects take about 8 minutes and ~3,600 API calls (≈180 per project, three quarters of them Recommender `insights.list` / `recommendations.list`), while only ~2 calls are in flight on average: most checks walk the projects one at a time, so a single task's scan time grows linearly with the number of projects (≈40 minutes for 100, hours for 1,000). Sharded (`--shard-size 20 --concurrency 25`), the same 1,000-project organization completes in **16 minutes**: 51 shards, median shard 7.8 minutes and longest 8.1 (well inside the 20-minute budget), ~490 API calls in flight at the peak, no retries, 100% coverage, and the aggregation of 1,260 intermediate objects into a 1.1 MB HTML / 11,000-line CSV report takes under a second. The peak in-flight calls is the number to compare with the organization's API quotas when choosing `SCAN_MAX_CONCURRENT_SHARDS`.

## Troubleshooting

If the status page is stuck for a long time, the background worker is likely failing.

### Step 1: Check the Cloud Run Logs

1. Go to the **Cloud Run** page in the Google Cloud Console.  
2. Click on the **worker** service (`cloudgauge-worker`; in a public single-service deployment, the one service) — every scan runs there. The web service's logs cover the pages and the API only.  
3. Go to the **LOGS** tab.  
4. Look for log entries for requests made to the worker URLs: `/run-scan` (every scan starts there), and for a large scope `/scan-shard`, `/run-aggregation` and `/sweep`.  
5. Every line the worker logs starts with the job ID in brackets — the status page shows it as *Job …* — so filtering the logs on `[<job-id>]` shows one scan's whole story across its shards. Look for any errors in red.

### Step 2: Check the Cloud Tasks Logs

1. Go to the **Cloud Tasks** page in the Google Cloud Console.  
2. Click on your queue (`cloudgauge-scan-queue`).  
3. Go to the **LOGS** tab.  
4. Look at the status of the task attempts. `PERMISSION_DENIED` (HTTP 403) means the service account is not `roles/run.invoker` on the worker service (the script's step 3; Method 2's Step 2). `NOT_FOUND` (HTTP 404) means the task reached a service that has no worker endpoints: the web service's `WORKER_URL` names the web service itself instead of the worker. Requests that Identity-Aware Proxy rejects never appear in Cloud Run's logs, only here.

### Step 3: Resolve Common Errors

#### A Google sign-in, then "You don't have access"

* **Symptom**: The web service's URL asks for a Google sign-in and then shows Google's *You don't have access* page.  
* **Cause**: The account is not `roles/iap.httpsResourceAccessor` on the web service, or was granted it less than a minute ago.  
* **Solution**: Grant it (see [Who can use it](security.md#who-can-use-it)) and reload after a minute. A `tools/iap_token.py` token answers the same way when its service account lacks the role.

---

#### The web service answers 403 to everyone

* **Symptom**: `gcloud run deploy --iap` warned that setting the IAP service agent failed, or every signed-in person gets 403.  
* **Cause**: IAP forwards requests as its service agent, `service-<project number>@gcp-sa-iap.iam.gserviceaccount.com`, which must be `roles/run.invoker` on the web service.  
* **Solution**: `gcloud run services add-iam-policy-binding cloudgauge --region=<region> --member="serviceAccount:service-<project number>@gcp-sa-iap.iam.gserviceaccount.com" --role="roles/run.invoker"` (`tools/deploy.sh` does this).

---

#### A report's buttons stop working after an hour

* **Symptom**: In an open report, **Draft fixes**, **Generate executive summary** or **Get detailed insights** do nothing, or the status page stops updating.  
* **Cause**: The Identity-Aware Proxy session expired (after about an hour). Pages rendered by v16 or later notice the 401 and reload themselves, which signs in again; reports stored by earlier releases keep their older script and do not.  
* **Solution**: Reload the page.

---

#### Memory Limit Exceeded

* **Error Message**: You might see an error in the Cloud Run logs that says: “`Memory limit of 512 MiB exceeded …”`  
* **Cause**: The scan process is using more memory than the default amount allocated to the Cloud Run service.  
* **Solution**: You need to increase the memory allocated to your service.  
  * **Via Console**:  
    1. Click **"Edit & Deploy New Revision"** on your Cloud Run service page.  
    2. Under the "General" tab, find **"Memory allocation"** and increase it (e.g., to `2 GiB`).  
    3. Click **Deploy**.  
  * **Via gcloud CLI**:

```
gcloud run services update cloudgauge-service \
  --memory=2Gi \
  --region=<your-region>
```
    
---

#### Permission Denied on Google Cloud APIs

* **Error Message**: The logs show a `PERMISSION_DENIED` error related to a specific Google Cloud service, such as `storage.googleapis.com` or `iam.googleapis.com`.  
* **Cause**: The service account (`cloudgauge-sa@...`) is missing an IAM role needed to access a specific API.  
* **Solution**: The error message will usually state which permission is missing. Go back to the **"Common Prerequisites"** section of the deployment instructions and verify that all `gcloud ... add-iam-policy-binding` commands were run successfully against the correct service account. You may need to re-run the command for the missing role.

---

#### Container Failed to Start

* **Error Message**: The Cloud Run revision is not becoming healthy, and the logs show an error right at startup, such as `ModuleNotFoundError` in Python or an error about a missing environment variable.  
* **Cause**: This typically happens for one of two reasons:  
  1. An environment variable was not set correctly.  
  2. There is a bug in the application code or a missing dependency in `requirements.txt`.  
* **Solution**:  
  1. Check the **LOGS** tab for the specific error message that occurs when the container tries to start.  
  2. If the error is related to a variable, click **"Edit & Deploy New Revision,"** go to the **"Variables & Secrets"** tab, and ensure all required variables (`PROJECT_ID`, `LOCATION`, `TASK_QUEUE`, `RESULTS_BUCKET`, `SERVICE_ACCOUNT_EMAIL`) are present and have the correct values. The startup log line `FATAL: Missing required environment variables: ...` names the missing ones.  
  3. If the log shows `FATAL: CLOUDGAUGE_ROLE=web needs WORKER_URL`, the web service was deployed without the worker's URL: set `WORKER_URL` to it. If it shows `FATAL: Could not discover WORKER_URL via API`, a `worker` or `all` service tried to look up its own URL without `roles/run.viewer` on itself: grant the role, or set `WORKER_URL` to the service's URL (what `tools/deploy.sh` does).  
  4. If it is a code error, you will need to fix the source code and deploy a new revision.

---

#### AI Summary or Suggestions Fail

* **Symptom**: The report loads, but the Gemini executive summary or remediation suggestions return an error.  
* **Cause**: The service account lacks `roles/aiplatform.user`, the Vertex AI API (`aiplatform.googleapis.com`) is not enabled, or the selected model isn't available to your project or location.  
* **Solution**: Verify the role and API from the **Common Prerequisites**. If a specific model is the problem, pin one that is available with `GEMINI_MODEL` (and, if needed, `VERTEX_LOCATION`):

```
gcloud run services update cloudgauge-service \
  --update-env-vars GEMINI_MODEL=<model-id> \
  --region=<your-region>
```

---

#### Request Timeout

* **Error Message**: The logs show an HTTP `504` status code or a message like "The request has been terminated because it has reached its deadline."  
* **Cause**: A request is taking longer than the configured request timeout on the Cloud Run service. A scope of up to `SCAN_SHARD_SIZE` projects runs in one `/run-scan` request, so that request is as long as the whole scan; a larger scope runs as shards, and each `/scan-shard` request is bounded by the task's dispatch deadline (`TASK_DISPATCH_DEADLINE_SECONDS`, 30 minutes at most) and stops starting new checks after `SHARD_TIME_BUDGET_SECONDS` (default 20 minutes), so it should never reach a 1-hour request timeout — if a shard does time out, see [A Large Scan Reports "Partially Scanned" or Error Rows](#a-large-scan-reports-partially-scanned-or-error-rows).  
* **Solution**: The deployment instructions recommend a timeout of `3600` seconds (1 hour). Verify this was set correctly.  
  * **Via Console**: Go to **"Edit & Deploy New Revision"** and check the **"Request timeout"** value under the "General" tab.  
  * **Via gcloud CLI**: You can update the service with the correct timeout using:

```
gcloud run services update cloudgauge-service \
  --timeout=3600 \
  --region=<your-region>
```
---

#### A Large Scan Reports "Partially Scanned" or Error Rows

* **Symptom**: The status page of a scan with more than `SCAN_SHARD_SIZE` projects shows *"Scanned X of Y projects · organization-level checks: in progress · some checks could not run (listed as errors in the report)"*, and the report's **Coverage** line is amber: some projects are *partially scanned* or *not scanned*, and checks list rows such as *"Not checked for 20 projects (proj-a, proj-b, ...): the scan failed after 3 attempts. Last error: ..."*, *"Check did not finish within the time budget of 1200 seconds for 20 projects (...)"*, or *"... the scan did not finish; the results are missing from this report."*.
* **Cause**: The scan ran as a sharded scan (see [Scaling to Large Organizations](architecture.md#scaling-to-large-organizations)) and a shard hit an error on every attempt, ran out of its time budget, or its task vanished (for example the instance ran out of memory, or the Cloud Run request timeout is below the 30-minute task deadline). *"Did not finish"* rows mean the job reached its time limit with shards still queued or running (the log says `Sweep N: K shards still not finished after X h, the job's time limit of Y h`): the queue was slower than planned, paused, or `SCAN_TIME_LIMIT_SECONDS` is set too low for the organization. The report is delivered anyway, with the affected checks as error rows, instead of failing the whole scan.
* **Solution**: The row's text names the affected projects and the error. In the Cloud Run logs, filter on `[<job-id>]` to find the shard those projects belonged to (`Dispatched ... in N shards`, `Shard shard-012 failed on attempt 3: ...`). Typical fixes: raise the Cloud Run request timeout to `3600` and memory to `2Gi`, set `--concurrency=4`, lower `SCAN_MAX_CONCURRENT_SHARDS` if the errors are API quota errors (`429`), raise `SHARD_TIME_BUDGET_SECONDS` (up to `1800`) if checks time out, or, for *did not finish* rows, raise `SCAN_MAX_CONCURRENT_SHARDS` so the scan fits its time limit (see [Sizing for your organization](architecture.md#sizing-for-your-organization)). Re-run the scan afterwards.
---

#### Builds Fail in a VPC Service Controls Environment

* **Symptom:** When running a Cloud Build, the process fails during steps that require fetching external packages (e.g., `pip install`, `apt-get update`, or `npm install`). You may see timeout errors or messages related to network connectivity and egress being blocked.  
* **Cause:** By default, Cloud Build runs on workers in a Google-managed project that is outside your organization's VPC Service Controls (VPC SC) perimeter. Your perimeter is correctly blocking egress traffic from these external workers, preventing them from accessing public repositories to download dependencies.  
* **Solution:** Use **Cloud Build private pools**. This provisions dedicated build workers that run *inside* your own VPC network, making all build traffic internal and compliant with your security perimeter.  
    
  **1\. Create a Private Pool in Your VPC:** First, create a private worker pool connected to your VPC network. This ensures all build steps are executed within your perimeter.
```
gcloud builds worker-pools create [POOL_NAME] \
    --project=[PROJECT_ID] \
    --region=[REGION] \
    --peered-network=projects/[PROJECT_ID]/global/networks/[VPC_NETWORK]
```
  *Replace `[POOL_NAME]`, `[PROJECT_ID]`, `[REGION]`, and `[VPC_NETWORK]` with your specific values.*  

  
    
  **2\. Configure a Secure Egress Route for the Private Pool**

A private pool inside a VPC SC perimeter cannot access public package repositories by default. You need to provide a route to the internet.

**Note:** **Cloud NAT will not work for this use case.** Private pools reside in a separate, Google-managed VPC peered to yours. Cloud NAT does not provide service across a VPC peering connection.

The recommended solution is to use a **dedicated Compute Engine VM as a secure NAT Gateway**.

1. **Create a NAT Gateway VM:** Provision a small Compute Engine VM within your VPC. This VM should have an external IP address and be configured to perform network address translation (masquerading). You can use a startup script to enable IP forwarding and set the necessary iptables rules.  
2. **Create Custom Routes:** You must create custom routes to direct traffic from your private pool's IP range to the NAT gateway VM. This ensures only the build workers' traffic is routed for external access, leaving other resources unaffected.  
3. **Configure Firewall Rules:** Create VPC firewall rules to:  
   * Allow **ingress** traffic from the private pool's IP range to the NAT gateway VM.  
   * Allow **egress** traffic from the NAT gateway VM to the internet (0.0.0.0/0).
    
  **3\. Run Your Build Using the Private Pool:** Modify your `gcloud builds submit` command to include the `--worker-pool` flag, pointing it to your newly created private pool.

```
gcloud builds submit . \
  --tag "gcr.io/[PROJECT_ID]/[SERVICE_NAME]" \
  --region=[REGION] \
  --worker-pool=projects/[PROJECT_ID]/locations/[REGION]/workerPools/[POOL_NAME]
```

This command now directs Cloud Build to use a worker from your internal pool. The worker's traffic is routed through your secure NAT Gateway VM, allowing it to fetch external dependencies while remaining fully compliant with your VPC SC perimeter.

---

### Forcing Image Storage to a Specific Region

**Symptom:** You need to store your container images in a specific Google Cloud region (e.g., asia-south1 for organization policy resource location constraints), but by default, gcr.io hosts images in multi-regional locations (us, eu, asia) and does not offer specific regional control.

**Cause:** Google Container Registry (gcr.io) is a multi-regional service. To gain fine-grained control over the storage location of your images, you should use **Artifact Registry**, which is Google Cloud's recommended service for managing container images and language packages.

**Solution:** Create a Docker repository in Artifact Registry in your desired region and update your build commands to point to the new regional endpoint.


**Step 1: Create a Regional Artifact Registry Repository**

First, create a new Docker-format repository in your chosen region. This example uses asia-south1 (Mumbai).

```
gcloud artifacts repositories create cloudgauge-repo \ 
    --repository-format=docker \
    --location=asia-south1 \
    --description="CloudGauge Docker repository in Mumbai"
```

*You only need to run this command once to set up the repository.*


**Step 2: Update Your Build and Push Commands**

Next, you must change the image path in your build and push commands from gcr.io/... to the new Artifact Registry path. The new format is \[REGION\]-docker.pkg.dev/\[PROJECT\_ID\]/\[REPO\_NAME\]/\[IMAGE\_NAME\].

#### Option A: Using Cloud Build

If you're using Cloud Build, update the \--tag flag in your gcloud builds submit command:

```
gcloud builds submit . --tag "asia-south1-docker.pkg.dev/[PROJECT_ID]/cloudgauge-repo/[SERVICE_NAME]"
```

#### Option B: Pushing a Local Image

If you are building your image locally, update your docker tag and docker push commands:

\# 1\. Build the image 
```
docker build -t cloudgauge-image .
```
\# 2\. Tag the image for your new Artifact Registry repo 
```
docker tag cloudgauge-image asia-south1-docker.pkg.dev/[PROJECT_ID]/cloudgauge-repo/cloudgauge-image
```
\# 3\. Push the image  
```
docker push asia-south1-docker.pkg.dev/[PROJECT_ID]/cloudgauge-repo/cloudgauge-image
```
By following these steps, you can ensure your container images are stored and managed in the specific Google Cloud region that meets your requirements.

---

## Cleanup Script

This gCloud script will remove all the resources created by the tool. 

### Configure Your Variables

Before running the script, replace the placeholder values in the first few lines with the ones you used during deployment.

```
#!/bin/bash

# --- CONFIGURE THESE VARIABLES ---
export ORG_ID="123456789012"              # The Organization ID you granted the roles on
export PROJECT_ID="your-gcp-project-id"   # The project CloudGauge was deployed in
export REGION="asia-south1"               # The region you deployed to
# --- END CONFIGURATION ---


# Set derived variables (the names the deployment instructions use; change them if you chose others)
export SERVICE_NAME="cloudgauge"
export WORKER_SERVICE="${SERVICE_NAME}-worker"   # a public single-service deployment has no worker
export QUEUE_NAME="cloudgauge-scan-queue"
export BUCKET_NAME="cloudgauge-reports-${PROJECT_ID}"
export SA_NAME="cloudgauge-sa"
export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# --- DELETION SCRIPT STARTS HERE ---

echo "--- Starting Cleanup for CloudGauge in project ${PROJECT_ID} ---"

# 1. Delete the two Cloud Run services (their IAM bindings go with them: the operators' IAP access,
#    the IAP service agent's and the service account's roles/run.invoker)
echo "Deleting Cloud Run services: ${SERVICE_NAME}, ${WORKER_SERVICE}..."
gcloud run services delete ${SERVICE_NAME} --region=${REGION} --platform=managed --quiet
gcloud run services delete ${WORKER_SERVICE} --region=${REGION} --platform=managed --quiet

# 2. Delete the Cloud Tasks queue (the service created it at startup)
echo "Deleting Cloud Tasks queue: ${QUEUE_NAME}..."
gcloud tasks queues delete ${QUEUE_NAME} --location=${REGION} --quiet

# 3. Delete the results bucket and everything in it: reports, status files and the per-scope
#    scan history (the bucket's roles/storage.objectAdmin binding goes with it)
echo "Deleting GCS bucket: gs://${BUCKET_NAME}..."
gsutil -m rm -r "gs://${BUCKET_NAME}"

# 4. Delete the container image (Method 2 pushes it to gcr.io; see the explanation below for Method 1)
echo "Deleting container image..."
gcloud container images delete "gcr.io/${PROJECT_ID}/${SERVICE_NAME}" --force-delete-tags --quiet

# 5. Remove the IAM bindings the prerequisites granted: the same roles, in the same order
echo "Removing IAM bindings for ${SA_EMAIL}..."

# Organization-level roles, including the custom Advisory Notifications role (v14)
for ROLE in \
    roles/browser \
    roles/cloudasset.viewer \
    roles/compute.networkViewer \
    roles/essentialcontacts.viewer \
    roles/recommender.iamViewer \
    roles/logging.viewer \
    roles/monitoring.viewer \
    roles/orgpolicy.policyViewer \
    roles/resourcemanager.organizationViewer \
    roles/servicehealth.viewer \
    roles/securitycenter.settingsViewer \
    roles/iam.securityReviewer \
    "organizations/${ORG_ID}/roles/CloudGaugeAdvisoryViewer"; do
  gcloud organizations remove-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="${ROLE}" --quiet
done

# The custom role itself, now that nothing is bound to it
gcloud iam roles delete CloudGaugeAdvisoryViewer --organization=${ORG_ID} --quiet

# Project-level roles (on the project CloudGauge was deployed in)
for ROLE in roles/aiplatform.user roles/cloudtasks.admin; do
  gcloud projects remove-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="${ROLE}" --quiet
done

# 6. Delete the Service Account (its own Token Creator and Service Account User bindings go with it)
echo "Deleting service account: ${SA_EMAIL}..."
gcloud iam service-accounts delete ${SA_EMAIL} --quiet

echo "✅ Cleanup complete!"
```
---

### Step-by-Step Explanation

Here's a breakdown of what each command in the script does:

1. **Delete Cloud Run Services**: `gcloud run services delete`  
   * This removes the web service and the worker, stopping them from running and incurring costs. Everything granted on them disappears with them: the `roles/iap.httpsResourceAccessor` bindings of the people who could sign in, the IAP service agent's and the service account's `roles/run.invoker`. IAP itself leaves nothing behind. A public single-service deployment has no worker; the second command then reports it as not found.  
2. **Delete Cloud Tasks Queue**: `gcloud tasks queues delete`  
   * The service creates the Cloud Tasks queue named in `TASK_QUEUE` (`cloudgauge-scan-queue`) when it starts, if it does not exist. This command deletes that queue, and with it any scan still queued.  
3. **Delete GCS Bucket**: `gsutil -m rm -r`  
   * This command deletes the `cloudgauge-reports-...` bucket and everything stored inside it: the HTML/CSV reports, the status files, and the per-scope scan summaries under `scopes/` that the report's *since* line compares against. The `-m` flag helps it run faster if there are many files. The `roles/storage.objectAdmin` binding was granted on the bucket, so it goes with it.  
4. **Delete Container Image**: `gcloud container images delete`  
   * Method 2 builds the image with Cloud Build and stores it in Google Container Registry (`gcr.io`); this command deletes it. Method 1 (deploy from source) stores its images in the Artifact Registry repository `cloud-run-source-deploy` and creates a Cloud Build trigger for your fork; delete both from the console (**Artifact Registry** and **Cloud Build › Triggers**), as their names depend on your repository. If you followed [Forcing Image Storage to a Specific Region](#forcing-image-storage-to-a-specific-region), delete the `cloudgauge-repo` repository as well.  
5. **Remove IAM Bindings**: `gcloud ... remove-iam-policy-binding`  
   * This is a critical step. Before deleting the service account, remove the roles the prerequisites granted it at the **Organization** level (the twelve predefined roles and the custom `CloudGaugeAdvisoryViewer` role, which is then deleted) and at the **Project** level (`roles/aiplatform.user`, `roles/cloudtasks.admin`). This prevents "ghost" principals from showing up in your IAM policies.  
6. **Delete Service Account**: `gcloud iam service-accounts delete`  
   * This is the final step. After removing its permissions, you can safely delete the `cloudgauge-sa` service account itself; the Service Account User binding it held on itself (for Cloud Tasks), and any `roles/iam.serviceAccountTokenCreator` granted to a person for `tools/iap_token.py`, are deleted with it. A deployment first made by a release before v16.1 also holds a Token Creator binding on the account itself, which signed the status page's CSV link; since v16.1 the link is a route of the service and nothing is signed, so on a deployment you keep the binding can go: `gcloud iam service-accounts remove-iam-policy-binding ${SA_EMAIL} --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.serviceAccountTokenCreator"`.
