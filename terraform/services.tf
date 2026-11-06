# terraform/services.tf — the two Cloud Run services and what hangs off them (tools/deploy.sh steps 3–5
# and 7), created once image_tag names an image that exists.
#
# Ownership: Terraform owns the services' shape — image, variables, resources, identity, ingress, IAP.
# Traffic splits and tags (the canary runbook of README › Updating an Existing Deployment) belong to the
# operator, so lifecycle.ignore_changes leaves them alone; a release is `terraform apply -var image_tag=<new>`.

locals {
  # IAP's service agent, which forwards the signed-in person's request; Google provisions it for the project.
  iap_agent = "serviceAccount:service-${local.project_number}@gcp-sa-iap.iam.gserviceaccount.com"
}

# --- 3. The worker (Cloud Tasks only) -----------------------------------------------------------
# Long requests, few per instance: a shard can run for 30 minutes. Internal ingress: nothing from the
# internet reaches it, Cloud Tasks does.

resource "google_cloud_run_v2_service" "worker" {
  count = local.deploy_services ? 1 : 0

  project             = var.project_id
  name                = local.worker_service_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = var.deletion_protection

  template {
    service_account                  = google_service_account.cloudgauge.email
    timeout                          = "3600s"
    max_instance_request_concurrency = 4

    containers {
      image = "${local.image}:${var.image_tag}"

      resources {
        limits = { cpu = "1", memory = "2Gi" }
      }

      dynamic "env" {
        for_each = merge(local.common_env, { CLOUDGAUGE_ROLE = "worker", WORKER_URL = local.worker_url })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [client, client_version, traffic]
  }

  depends_on = [
    google_project_iam_member.project_roles,
    google_service_account_iam_member.self_user,
    google_storage_bucket_iam_member.reports_admin,
    google_cloud_tasks_queue.scans,
  ]
}

# The service account is the identity on every Cloud Tasks request; nobody else may invoke the worker.
resource "google_cloud_run_v2_service_iam_member" "worker_invoker" {
  count = local.deploy_services ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.worker[0].name
  role     = "roles/run.invoker"
  member   = google_service_account.cloudgauge.member
}

# --- 4. The web service, behind Identity-Aware Proxy --------------------------------------------
# Pages and the on-demand Gemini / Recommender calls: small instances, many requests each. PROJECT_NUMBER
# lets the service verify IAP's signed identity assertions.

resource "google_cloud_run_v2_service" "web" {
  count = local.deploy_services ? 1 : 0

  project             = var.project_id
  name                = var.service_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  iap_enabled         = true
  deletion_protection = var.deletion_protection

  template {
    service_account                  = google_service_account.cloudgauge.email
    timeout                          = "600s"
    max_instance_request_concurrency = 80

    containers {
      image = "${local.image}:${var.image_tag}"

      resources {
        limits = { cpu = "1", memory = "1Gi" }
      }

      dynamic "env" {
        for_each = merge(local.common_env, { CLOUDGAUGE_ROLE = "web", WORKER_URL = local.worker_url, PROJECT_NUMBER = local.project_number })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [client, client_version, traffic]
  }

  depends_on = [
    google_project_iam_member.project_roles,
    google_service_account_iam_member.self_user,
    google_storage_bucket_iam_member.reports_admin,
    google_cloud_tasks_queue.scans,
  ]
}

# IAP forwards the signed-in person's request as its service agent.
resource "google_cloud_run_v2_service_iam_member" "web_iap_invoker" {
  count = local.deploy_services ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.web[0].name
  role     = "roles/run.invoker"
  member   = local.iap_agent
}

# --- 5. Access: roles/iap.httpsResourceAccessor on the web service is what lets a Google account sign in

resource "google_iap_web_cloud_run_service_iam_member" "operators" {
  for_each = local.deploy_services ? toset(var.operators) : toset([])

  project                = var.project_id
  location               = var.region
  cloud_run_service_name = google_cloud_run_v2_service.web[0].name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = each.value
}

# Programmatic access (tools/iap_token.py): the service account through IAP, and the named principals
# allowed to mint tokens for it.
resource "google_iap_web_cloud_run_service_iam_member" "programmatic" {
  count = local.deploy_services && length(var.programmatic_access_principals) > 0 ? 1 : 0

  project                = var.project_id
  location               = var.region
  cloud_run_service_name = google_cloud_run_v2_service.web[0].name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = google_service_account.cloudgauge.member
}

resource "google_service_account_iam_member" "token_creators" {
  for_each = toset(var.programmatic_access_principals)

  service_account_id = google_service_account.cloudgauge.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = each.value
}

# --- 7. Scheduled scans (v17) -------------------------------------------------------------------
# Each job calls the worker as the service account (its OIDC token, audience the worker's URL), like Cloud Tasks does.

resource "google_cloud_scheduler_job" "schedules" {
  for_each = local.deploy_services ? var.schedules : {}

  project          = var.project_id
  region           = var.region
  name             = each.key
  description      = "CloudGauge scheduled scan of ${each.value.scope} ${each.value.scope_id}"
  schedule         = each.value.cron
  time_zone        = "Etc/UTC"
  attempt_deadline = "120s"
  # No retry_config block: the default is no retries (what the script's --max-retry-attempts=0 asks for), and
  # the API returns no block for an all-default configuration, so declaring one would be a diff on every plan.

  http_target {
    uri         = "${local.worker_url}/scheduled-scan"
    http_method = "POST"
    headers     = { "Content-Type" = "application/json" }
    body        = base64encode(jsonencode({ scope = each.value.scope, scope_id = each.value.scope_id, name = each.key }))

    oidc_token {
      service_account_email = google_service_account.cloudgauge.email
      audience              = local.worker_url
    }
  }

  depends_on = [google_cloud_run_v2_service_iam_member.worker_invoker]
}
