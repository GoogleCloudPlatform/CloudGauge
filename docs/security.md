# Security

Who can reach the pages and the worker, the single public service a deployment can still be (and why not), the checks every request goes through whatever the deployment, and what the services read — and never send anywhere. The roles and APIs by name: [stability.md › Roles and APIs](stability.md#roles-and-apis).

In this page: [Who can use it](#who-can-use-it) · [A public deployment (discouraged)](#a-public-deployment-discouraged) · [Request hardening](#request-hardening) · [Privacy & API Attribution](#privacy--api-attribution) · [Reporting a vulnerability](#reporting-a-vulnerability)

## Who can use it

Access to the pages is the `roles/iap.httpsResourceAccessor` binding on the web service — for a person, a Google group or a whole domain:

```
gcloud iap web add-iam-policy-binding --project=<project> --region=<region> \
  --resource-type=cloud-run --service=cloudgauge \
  --member="group:cloud-team@example.com" --role="roles/iap.httpsResourceAccessor"
```

`remove-iam-policy-binding` with the same arguments revokes it; `tools/deploy.sh OPERATORS=…` grants it. In the console: **Security** → **Identity-Aware Proxy**, tick the `cloudgauge` row (Cloud Run services are listed with their region), **Add principal**, role **IAP-secured Web App User**. A change takes up to a minute to apply; until then the person sees Google's *You don't have access* page. Everyone who gets through sees the same thing — every scan, every report; the page header says who is signed in, and a scan's report who requested it.

**Programmatic access** (`curl`, scripts, `tools/demo_gif.py`). IAP on Cloud Run does not accept Google-issued ID tokens (`gcloud auth print-identity-token`); it accepts a JWT signed by a service account that holds the accessor role. `tools/iap_token.py` mints one through the IAM Credentials API, with the signed-in gcloud account:

```
# Once: let the service account through IAP, and let yourself sign tokens for it
# (PROGRAMMATIC_ACCESS=1 tools/deploy.sh does both)
gcloud iap web add-iam-policy-binding --project=<project> --region=<region> --resource-type=cloud-run --service=cloudgauge \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/iap.httpsResourceAccessor"
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} \
  --member="user:you@example.com" --role="roles/iam.serviceAccountTokenCreator"

# Then
BASE="https://cloudgauge-<project number>.<region>.run.app"
TOKEN=$(python tools/iap_token.py ${SA_EMAIL} ${BASE})
curl -H "Authorization: Bearer ${TOKEN}" ${BASE}/api/status/<job id>/<scope id>
```

The token is good for an hour and for that URL only (a canary tag URL needs its own). The pages then read *Signed in as* the service account.

## A public deployment (discouraged)

Releases before v16 ran one public service, and that still works: `CLOUDGAUGE_ROLE=all` (the default) serves the pages, the API and the worker endpoints together, and the service discovers its own URL. Anyone with the URL can start scans against your organization and read every report, so prefer the two services above. If you need it anyway:

```
export REGION="asia-south1" SERVICE_NAME="cloudgauge" QUEUE_NAME="cloudgauge-scan-queue" BUCKET_NAME="cloudgauge-reports-${PROJECT_ID}"

# Build, test and push the image
gcloud builds submit . --config cloudbuild.yaml --substitutions=_IMAGE=gcr.io/${PROJECT_ID}/${SERVICE_NAME},_TAG=latest \
  --service-account=projects/${PROJECT_ID}/serviceAccounts/${SA_EMAIL}

# One service, public
gcloud run deploy ${SERVICE_NAME} --region ${REGION} --image gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest \
  --service-account ${SA_EMAIL} --allow-unauthenticated \
  --timeout=3600 --concurrency=4 --memory=2Gi \
  --set-env-vars=PROJECT_ID=${PROJECT_ID},LOCATION=${REGION},TASK_QUEUE=${QUEUE_NAME},RESULTS_BUCKET=${BUCKET_NAME},SERVICE_ACCOUNT_EMAIL=${SA_EMAIL}

# Cloud Tasks invokes it, and it looks up its own URL at startup
gcloud run services add-iam-policy-binding ${SERVICE_NAME} --region ${REGION} --member="serviceAccount:${SA_EMAIL}" --role="roles/run.invoker"
gcloud run services add-iam-policy-binding ${SERVICE_NAME} --region ${REGION} --member="serviceAccount:${SA_EMAIL}" --role="roles/run.viewer"
```

Where the **Domain Restricted Sharing** organization policy (`iam.allowedPolicyMemberDomains`) forbids `allUsers`, `--allow-unauthenticated` fails; `--no-invoker-iam-check` in its place makes the service public by skipping the invoker check altogether. Behind neither IAP nor IAM the pages show no name and scans record none. To move such a deployment to the two services later, run `tools/deploy.sh` with its names: it adds the worker and turns the service into the web service.

Since v18.6.1 the worker endpoints of such a service (`/run-scan` and the rest) still answer only Cloud Tasks and Cloud Scheduler: they verify the service account's ID token in-process (see [Request hardening](#request-hardening)), so an anonymous `POST /run-scan` gets 401 even though the service is public. What stays open on a public service is what the pages offer anyone with the URL — starting scans and reading every report — which is why the two services are the recommendation.

## Request hardening

Whatever the deployment, the application checks its own requests (v18.6.1):

* **Every identifier is validated** before it reaches a bucket key, a task body or an API call: `scope` is `organization`, `folder` or `project`; `scope_id` an organization or folder number, or a project ID; `job_id` the UUID `POST /scan` minted. A malformed one is a **400** — on the pages, the API and the worker endpoints alike — and the results store refuses to build an object key from anything but a plain key segment, so a value can never steer an object under another job's prefix.
* **The POST routes are same-origin only** (`POST /scan`, `/api/get-summary`, `/api/get-suggestions`, `/api/get-insights`): Identity-Aware Proxy says who is in the browser, not which page sent the request, so a form on another site could otherwise start a scan as the operator. Browsers label every request with `Sec-Fetch-Site`; it must read `same-origin` or `none`, else the `Origin` (then the `Referer`) must name this service — a cross-site request gets **403**. A request with none of those headers (`curl`, a script) has no victim's browser behind it and is allowed.
* **A scope scans once at a time**, whoever asks: `POST /scan` while the scope's previous scan is still running answers **409** with a page naming that scan and linking its status page (JSON for a client that asks for it); nothing new is started. Scheduled scans have followed the same rule since v17. A scan counts as running while its status file says so; one that has not started within 10 minutes no longer blocks its scope.
* **A scan that Cloud Tasks will not take is said so, not a 500** (v20): every `create_task` retries a transient answer — `UNAVAILABLE` (a `Stream removed` reached a person once), `DEADLINE_EXCEEDED`, `INTERNAL` — with exponential backoff for up to 30 seconds; the scan task is named after its job (`scan-<job id>`), so the retry after a lost answer meets *already exists* and never starts a scan twice. What still fails is a **503** page — *Scan not queued*, naming the queue and the answer, with a **Try again** button and `Retry-After: 60` (JSON for a client that asks for it); nothing was started and nothing was noted, so the next attempt is a fresh start. `/scheduled-scan` answers the same 503 and Cloud Scheduler retries the job as configured.
* **The suggestions batch is bounded**: `/api/get-suggestions` takes at most 20 findings per request (the report sends 5), each with at most 20,000 characters of text; no request body may exceed 1 MiB (**413**).
* **The worker endpoints verify their caller**: Cloud Run's IAM check is what keeps everyone but the service account out of the worker service, and Cloud Run hands the `Authorization` header on to the container, so the worker verifies the token too — Google's signature, the service account's `email`, an audience among `WORKER_AUDIENCE`, the worker's URL and the request's URL, the expiry — and answers **401** otherwise. This is defence in depth behind IAM in the two-service deployment and the only guard in the public one. `WORKER_TOKEN_CHECK=off` switches it off (if a front in your path rewrites the token); it runs in the `production` and `synthetic` profiles only.

## Privacy & API Attribution

CloudGauge runs entirely within your own Google Cloud project — the results bucket, the Cloud Tasks queue, the BigQuery export and the Vertex AI calls all stay inside your environment — and **never** transmits scan findings, resource configurations or organization metadata to the maintainers or to any external server. There is no phone-home.

On the standard Google Cloud API calls a scan makes, CloudGauge appends a static client identifier, `cloud-solutions/cloudgauge-v<version>`, to the SDK `User-Agent` header *(v18.8.1)*. It names the solution and its release and nothing else; Google uses it to measure aggregate adoption of the open-source solution from API usage alone. To turn it off, set `CLOUDGAUGE_DISABLE_ATTRIBUTION=true` on both services (`tools/deploy.sh … EXTRA_ENV=CLOUDGAUGE_DISABLE_ATTRIBUTION=true`, or `extra_env` in Terraform); nothing else about a scan changes. The Terraform configuration carries the deploy-time counterpart (`provider_meta` in `terraform/versions.tf`), which the Google provider appends to its own user agent while it creates the deployment.

## Reporting a vulnerability

A security problem goes through [SECURITY.md](../SECURITY.md) — g.co/vulnz or the repository's private vulnerability reporting — never through an issue. That file also says what the deployment relies on and which versions receive fixes.
