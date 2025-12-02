# variables section

variable "project_id" {
  type        = string
  description = "The GCP project ID to deploy the resources into."
}

variable "org_id" {
  type        = string
  description = "The GCP organization ID where organization-level roles will be applied."
}

variable "gcp_region" {
  type        = string
  description = "The GCP region for deployment."
  default     = "us-central1"
}

variable "service_name" {
  type        = string
  description = "The name of the Cloud Run service."
  default     = "cloudgauge-service"
}

variable "sa_name" {
  type        = string
  description = "The name of the service account to create."
  default     = "cloudgauge-sa"
}

variable "task_queue" {
  type        = string
  description = "The name of the Cloud Task queue."
  default     = "cloudgauge-scan-queue"
}

variable "apis_to_enable" {
  type        = list(string)
  description = "A list of Google Cloud APIs to enable on the project."
  default = [
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudtasks.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "logging.googleapis.com",
    "recommender.googleapis.com",
    "securitycenter.googleapis.com",
    "servicehealth.googleapis.com",
    "essentialcontacts.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "osconfig.googleapis.com",
    "monitoring.googleapis.com",
    "storage.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudasset.googleapis.com",
    "secretmanager.googleapis.com"
  ]
}

variable "org_roles" {
  type        = list(string)
  description = "A list of IAM roles to grant at the organization level."
  default = [
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
    "roles/iam.securityReviewer"
  ]
}

variable "project_roles" {
  type        = list(string)
  description = "A list of IAM roles to grant at the project level."
  default = [
    "roles/aiplatform.user",
    "roles/cloudtasks.admin",
    "roles/run.viewer"
  ]
}

variable "allow_unauthenticated" {
  type        = bool
  description = "Whether to allow unauthenticated access to the Cloud Run service."
  default     = true
}

variable "github_repository_connection" {
  type        = string
  description = "The full resource name of the GitHub repository connection (e.g., projects/PROJECT_ID/locations/REGION/connections/CONNECTION_ID/repositories/REPO_ID)."
}

variable "github_branch" {
  type        = string
  description = "The regex for the branch to trigger the build."
  default     = "^main$"
}
