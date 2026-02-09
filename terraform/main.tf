# main.tf

locals {
  build_sa_id = "build-pipeline-sa"
}
# --- 1. API Enablement ---
# Enables all the APIs listed in the install script.
resource "google_project_service" "apis" {
  for_each                   = toset(var.apis_to_enable)
  project                    = var.project_id
  service                    = each.key
  disable_on_destroy         = false # Set to true to disable APIs on terraform destroy
  disable_dependent_services = true
}
resource "google_project_iam_member" "storage_reader" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.build_sa.email}"
}

# Grant the build SA permission to push to Artifact Registry
resource "google_project_iam_member" "build_sa_artifact_registry_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.build_sa.email}"
}

# Grant the build SA permission to write logs
resource "google_project_iam_member" "build_sa_logwriter" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.build_sa.email}"
}

# --- 5. Cloud Build Trigger ---
# This trigger will build the container image from the specified GitHub repo
# and push it to Google Container Registry (gcr.io).
resource "google_cloudbuild_trigger" "build_from_github" {
  project  = var.project_id
  name     = "${var.service_name}-source-trigger"
  location = var.gcp_region

  # This connects to the 2nd Gen GitHub repository.
  repository_event_config {
    repository = var.github_repository_connection
    push {
      branch = var.github_branch
    }
  }

  # Defines the build steps
  build {
    step {
      name = "gcr.io/cloud-builders/docker"
      args = ["build", "-t", "gcr.io/${var.project_id}/${var.service_name}:latest", "."]
    }
    images = ["gcr.io/${var.project_id}/${var.service_name}:latest"]
    options {
      logging = "CLOUD_LOGGING_ONLY"
    }
  }

  # The service account for the build itself.
  # We grant this SA permissions to act as our app's SA.
  service_account = google_service_account.build_sa.id

  depends_on = [
    google_project_service.apis
  ]
}

# Grant the Cloud Build SA permission to act as the CloudGauge SA
resource "google_service_account_iam_member" "build_sa_user" {
  service_account_id = google_service_account.cloudgauge_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_project.project.number}@cloudbuild.gserviceaccount.com"
}

# --- 6. Cloud Run Service ---
# Deploys the container image built by Cloud Build.
resource "google_cloud_run_v2_service" "cloudgauge_service" {
  project              = var.project_id
  name                 = var.service_name
  location             = var.gcp_region
  deletion_protection  = false
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = true
  template {
    service_account = google_service_account.cloudgauge_sa.email
    timeout         = "3600s"

    containers {
      image = "gcr.io/${var.project_id}/${var.service_name}:latest"
      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "TASK_QUEUE"
        value = var.task_queue
      }
      env {
        name  = "RESULTS_BUCKET"
        value = google_storage_bucket.reports_bucket.name
      }
      env {
        name  = "SERVICE_ACCOUNT_EMAIL"
        value = google_service_account.cloudgauge_sa.email
      }
      env {
        name  = "LOCATION"
        value = var.gcp_region
      }
    }
  }

  # This depends on the trigger to ensure an image exists before deploying.
  # For the first run, you must manually trigger the build.
  depends_on = [
    google_cloudbuild_trigger.build_from_github,
    google_service_account_iam_member.build_sa_user
  ]
}

# --- 7. Cloud Run IAM ---
# Allow the service account to invoke its own service (for async tasks)
resource "google_cloud_run_v2_service_iam_member" "sa_viewer" {
  project  = google_cloud_run_v2_service.cloudgauge_service.project
  location = google_cloud_run_v2_service.cloudgauge_service.location
  name     = google_cloud_run_v2_service.cloudgauge_service.name
  role     = "roles/run.viewer"
  member   = "serviceAccount:${google_service_account.cloudgauge_sa.email}"
}

# --- Data Sources ---
data "google_project" "project" {
  project_id = var.project_id
  depends_on = [
    google_project_service.apis
  ]
}
