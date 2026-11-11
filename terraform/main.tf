# terraform/main.tf — the foundation: what tools/deploy.sh's setup and export steps create, plus the
# organization-level roles of README › Common Prerequisites when organization_id is set.
#
# The image is not built here (Terraform builds nothing): apply once without image_tag to create the
# foundation, build with the command in the build_command output, then apply again with image_tag to
# deploy the two services (services.tf).

locals {
  worker_service_name = var.worker_service_name != "" ? var.worker_service_name : "${var.service_name}-worker"
  bucket_name         = var.bucket_name != "" ? var.bucket_name : "cloudgauge-reports-${var.project_id}"
  image               = var.image != "" ? var.image : "gcr.io/${var.project_id}/${var.service_name}"
  deploy_services     = var.image_tag != ""
  export              = var.bigquery_dataset != ""
  on_organization     = var.organization_id != ""

  project_number        = data.google_project.this.number
  service_account_email = google_service_account.cloudgauge.email
  # Cloud Run's deterministic URLs: known before the services exist, so the worker can be told its own URL
  # and nothing has to discover anything at startup.
  worker_url = "https://${local.worker_service_name}-${local.project_number}.${var.region}.run.app"
  web_url    = "https://${var.service_name}-${local.project_number}.${var.region}.run.app"

  # The APIs, as tools/deploy.sh enables them: what CloudGauge runs on, then what it reads, then what v17
  # (scheduled scans, the BigQuery export) and v17.1 (the perimeters, read-only) added.
  apis = [
    "run.googleapis.com", "cloudbuild.googleapis.com", "artifactregistry.googleapis.com", "cloudtasks.googleapis.com",
    "iap.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com", "cloudresourcemanager.googleapis.com",
    "storage.googleapis.com", "logging.googleapis.com", "aiplatform.googleapis.com",
    "recommender.googleapis.com", "securitycenter.googleapis.com", "servicehealth.googleapis.com",
    "advisorynotifications.googleapis.com", "essentialcontacts.googleapis.com", "compute.googleapis.com",
    "container.googleapis.com", "sqladmin.googleapis.com", "osconfig.googleapis.com", "monitoring.googleapis.com",
    "cloudasset.googleapis.com",
    "cloudscheduler.googleapis.com", "bigquery.googleapis.com", "accesscontextmanager.googleapis.com",
  ]

  # Project roles: Gemini calls, the Cloud Tasks queue, and Cloud Build — the image is built as this account
  # (it reads the uploaded source, pushes the image, writes the build log) rather than as the Compute Engine
  # default account, which organizations commonly leave without roles. With the export: load jobs in the project.
  project_roles = concat(
    ["roles/aiplatform.user", "roles/cloudtasks.admin", "roles/cloudbuild.builds.builder"],
    local.export ? ["roles/bigquery.jobUser"] : [],
  )

  # Organization roles: README › Common Prerequisites, step 2 (1), all read-only. The Advisory Notifications
  # custom role (1b) is created below; roles granted on the organization are inherited by every folder and project.
  organization_roles = [
    "roles/browser",
    "roles/cloudasset.viewer",
    "roles/compute.networkViewer",
    "roles/essentialcontacts.viewer",
    "roles/recommender.iamViewer",
    "roles/logging.viewer",
    "roles/monitoring.viewer",
    "roles/orgpolicy.policyViewer",
    "roles/resourcemanager.organizationViewer",
    "roles/servicehealth.viewer",
    "roles/securitycenter.settingsViewer",
    "roles/iam.securityReviewer",
  ]

  # The variables both services get (tools/deploy.sh's COMMON_ENV), plus the two queue limits so that the
  # services and the queue below can never disagree.
  common_env = merge(
    {
      PROJECT_ID                 = var.project_id
      LOCATION                   = var.region
      TASK_QUEUE                 = var.queue_name
      RESULTS_BUCKET             = local.bucket_name
      SERVICE_ACCOUNT_EMAIL      = local.service_account_email
      SCAN_MAX_CONCURRENT_SHARDS = tostring(var.scan_max_concurrent_shards)
      TASK_MAX_ATTEMPTS          = tostring(var.task_max_attempts)
    },
    var.extra_env,
    local.export ? { BIGQUERY_DATASET = var.bigquery_dataset } : {},
    length(var.cost_allocation_labels) > 0 ? { COST_ALLOCATION_LABELS = join(",", var.cost_allocation_labels) } : {},
    length(var.trusted_domains) > 0 ? { TRUSTED_DOMAINS = join(",", var.trusted_domains) } : {},
  )
}

data "google_project" "this" {
  project_id = var.project_id
}

# --- 1. APIs ------------------------------------------------------------------------------------

resource "google_project_service" "apis" {
  for_each = toset(local.apis)

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false # other things in the project may use them
}

# --- 1. The service account ---------------------------------------------------------------------

resource "google_service_account" "cloudgauge" {
  project      = var.project_id
  account_id   = var.service_account_name
  display_name = "CloudGauge Service Account"

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "project_roles" {
  for_each = toset(local.project_roles)

  project = var.project_id
  role    = each.value
  member  = google_service_account.cloudgauge.member
}

# On itself: Service Account User, so the services can create Cloud Tasks that carry its OIDC token
# (iam.serviceAccounts.actAs). Token Creator on itself is not needed.
resource "google_service_account_iam_member" "self_user" {
  service_account_id = google_service_account.cloudgauge.name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.cloudgauge.member
}

# --- 1. The results bucket ----------------------------------------------------------------------

resource "google_storage_bucket" "reports" {
  project                     = var.project_id
  name                        = local.bucket_name
  location                    = var.region # same region as the services
  uniform_bucket_level_access = true       # what organization policies usually require
  public_access_prevention    = "enforced"
  force_destroy               = var.force_destroy

  depends_on = [google_project_service.apis]
}

resource "google_storage_bucket_iam_member" "reports_admin" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectAdmin"
  member = google_service_account.cloudgauge.member
}

# --- The Cloud Tasks queue ----------------------------------------------------------------------
# tools/deploy.sh leaves the queue to the services, which create it at startup with these same limits and
# never modify one that exists; declaring it here keeps the limits and the services' variables together.

resource "google_cloud_tasks_queue" "scans" {
  project  = var.project_id
  name     = var.queue_name
  location = var.region

  rate_limits {
    max_concurrent_dispatches = var.scan_max_concurrent_shards
  }

  retry_config {
    max_attempts = var.task_max_attempts
    min_backoff  = "30s"
    max_backoff  = "600s"
  }

  depends_on = [google_project_service.apis]
}

# --- 6. The BigQuery export (v17) ---------------------------------------------------------------

resource "google_bigquery_dataset" "export" {
  count = local.export ? 1 : 0

  project                    = var.project_id
  dataset_id                 = var.bigquery_dataset
  location                   = var.region
  description                = "CloudGauge scan history: one row per scan (scans) and per finding (findings)"
  delete_contents_on_destroy = var.force_destroy

  depends_on = [google_project_service.apis]
}

# WRITER on the dataset alone (what roles/bigquery.dataEditor would grant project-wide).
resource "google_bigquery_dataset_access" "writer" {
  count = local.export ? 1 : 0

  project       = var.project_id
  dataset_id    = google_bigquery_dataset.export[0].dataset_id
  role          = "WRITER"
  user_by_email = google_service_account.cloudgauge.email
}

# --- The organization (README › Common Prerequisites, step 2) -----------------------------------

resource "google_organization_iam_member" "organization_roles" {
  for_each = local.on_organization ? toset(local.organization_roles) : toset([])

  org_id = var.organization_id
  role   = each.value
  member = google_service_account.cloudgauge.member
}

# 1b. Advisory Notifications: a custom role that can list the notifications AND read the notification settings.
# The predefined viewer role cannot read the settings, and the admin role can change them; this one is read-only.
resource "google_organization_iam_custom_role" "advisory_viewer" {
  count = local.on_organization ? 1 : 0

  org_id      = var.organization_id
  role_id     = var.advisory_role_id
  title       = "CloudGauge Advisory Notifications Viewer"
  description = "Read-only access to Advisory Notifications and their settings for CloudGauge scans"
  permissions = [
    "advisorynotifications.notifications.list",
    "advisorynotifications.notifications.get",
    "advisorynotifications.settings.get",
  ]
  stage = "GA"
}

resource "google_organization_iam_member" "advisory_viewer" {
  count = local.on_organization ? 1 : 0

  org_id = var.organization_id
  role   = google_organization_iam_custom_role.advisory_viewer[0].id
  member = google_service_account.cloudgauge.member
}
