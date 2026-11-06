# Deploying CloudGauge with Terraform

The same deployment as `tools/deploy.sh` — two Cloud Run services from one image, the web service behind Identity-Aware Proxy, the worker reachable by Cloud Tasks only — declared in Terraform. The full walkthrough is in the main README under *Deployment Instructions › Method 3: Deploy with Terraform*; this file is the short form.

## The three commands

Terraform builds no image, and the build runs as the service account Terraform creates, so a first deployment is two applies around one build:

```
cd terraform
cp terraform.tfvars.example terraform.tfvars   # project_id, operators, …
terraform init
terraform apply                                 # 1. the foundation: APIs, account, roles, bucket, queue, dataset
$(terraform output -raw build_command)          # 2. the image, built and tested by Cloud Build as the account (run from the repository root)
terraform apply -var image_tag=$(git rev-parse --short HEAD)   # 3. the two services, IAP, access, schedules
```

`terraform output next_step` says what comes next at each point. Put `image_tag` in `terraform.tfvars` once it is known, and a release is `terraform apply` with the new tag after the same build command.

Credentials: Application Default Credentials (`gcloud auth application-default login`) of an account that can create the resources in the project — and grant roles on the organization if `organization_id` is set. For shared state add a backend, e.g. in `backend.tf`:

```hcl
terraform {
  backend "gcs" {
    bucket = "my-terraform-state"
    prefix = "cloudgauge"
  }
}
```

## What it creates

| | |
|---|---|
| APIs | the 25 APIs `tools/deploy.sh` enables (never disabled on destroy) |
| Service account | `cloudgauge-sa` with `roles/aiplatform.user`, `roles/cloudtasks.admin`, `roles/cloudbuild.builds.builder` (and `roles/bigquery.jobUser` with the export) on the project, Service Account User on itself |
| Bucket | `cloudgauge-reports-<project>` in the region, uniform access, public access prevented; the account is Object Admin |
| Queue | the Cloud Tasks queue, with the limits the services expect (`scan_max_concurrent_shards`, `task_max_attempts`, 30 s–10 min back-off) |
| Worker | `cloudgauge-worker`: internal ingress, 3600 s, concurrency 4, 2 GiB; invoked by the account only |
| Web | `cloudgauge`: IAP enabled, 600 s, concurrency 80, 1 GiB; IAP's service agent is its invoker; each `operators` entry gets `roles/iap.httpsResourceAccessor` |
| Export | with `bigquery_dataset`: the dataset in the region, the account WRITER on it |
| Schedules | with `schedules`: one Cloud Scheduler job each, posting to the worker's `/scheduled-scan` with the account's OIDC token |
| Organization | with `organization_id`: the twelve read-only scan roles and the `CloudGaugeAdvisoryViewer` custom role, bound to the account |

Variables and defaults: `variables.tf`. Outputs: `web_url`, `worker_url`, `service_account_email`, `build_command`, `next_step`.

## Terraform and the gcloud runbook

Terraform owns the services' shape — image, variables, resources, identity, ingress, IAP — and ignores traffic splits and tags (`lifecycle.ignore_changes`), so the canary runbook of README › *Updating an Existing Deployment* still works on a Terraform-managed deployment; its "finalize" step is `terraform apply` with the tested tag (which also puts `WORKER_URL` / `WORKER_AUDIENCE` back), followed by `update-traffic --to-latest --remove-tags canary` — **that last command matters**: a `--no-traffic` deploy pins the traffic to the revision that was serving, and because Terraform never touches traffic, the revision its apply creates serves nothing until `--to-latest` says so. A fresh deployment, never canaried, has no such pin: each apply's revision serves at once. Rollback is as in the runbook (`--to-revisions`); a `terraform plan` after a canary deploy shows the two variables (and the image, if it changed), never the traffic. Use either `tools/deploy.sh` or Terraform for a deployment, not both.

## Good to know

- **Destroying.** The services are protected (`deletion_protection = true`), and the bucket and dataset keep their contents (`force_destroy = false`); set both before a `terraform destroy` you mean. Cloud Tasks reserves a deleted queue's name for 3 days: choose another `queue_name` to redeploy sooner.
- **A custom role that already exists.** If `CloudGaugeAdvisoryViewer` was created by hand (README step 2, 1b), import it — `terraform import 'google_organization_iam_custom_role.advisory_viewer[0]' organizations/123456789012/roles/CloudGaugeAdvisoryViewer` — or set `advisory_role_id` to a new ID.
- **IAM propagation.** A 403 right after the first apply goes away within a minute; apply again if a step failed on one.
- **As a module.** Every resource names its project and location and there is no provider block, so the folder can also be called from your own configuration, pinned to a commit: `module "cloudgauge" { source = "github.com/GoogleCloudPlatform/CloudGauge//terraform?ref=<commit>"  project_id = "my-project"  operators = [...] }`.
