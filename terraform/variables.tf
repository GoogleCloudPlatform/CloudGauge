# terraform/variables.tf — the same knobs as tools/deploy.sh, with its defaults.

variable "project_id" {
  description = "The project CloudGauge runs in."
  type        = string
}

variable "region" {
  description = "Region of the services, the queue, the bucket and the export dataset."
  type        = string
  default     = "asia-south1"
}

variable "service_name" {
  description = "The web service (the pages, behind Identity-Aware Proxy)."
  type        = string
  default     = "cloudgauge"
}

variable "worker_service_name" {
  description = "The worker service (Cloud Tasks only). Empty: <service_name>-worker."
  type        = string
  default     = ""
}

variable "service_account_name" {
  description = "Account ID of the service account both services run as; it also builds the image."
  type        = string
  default     = "cloudgauge-sa"
}

variable "bucket_name" {
  description = "The results bucket. Empty: cloudgauge-reports-<project_id>."
  type        = string
  default     = ""
}

variable "queue_name" {
  description = "The Cloud Tasks queue. A deleted queue's name cannot be reused for 3 days; pick a new one in that case."
  type        = string
  default     = "cloudgauge-scan-queue"
}

variable "image" {
  description = "Image repository, without a tag. Empty: gcr.io/<project_id>/<service_name>, what cloudbuild.yaml pushes to by default."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Tag of the image to deploy (the short git hash cloudbuild.yaml was given). Empty: deploy nothing yet — only the foundation (APIs, account, roles, bucket, queue, dataset) is created, and the output build_command says how to build the image."
  type        = string
  default     = ""
}

variable "operators" {
  description = "Who may sign in, as IAM principals: user:alice@example.com, group:cloud-team@example.com, domain:example.com."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for member in var.operators : can(regex("^(user|group|domain|serviceAccount|principal|principalSet):.+", member))])
    error_message = "Each operator needs a type: user:, group: or domain: (serviceAccount:, principal: and principalSet: also work)."
  }
}

variable "extra_env" {
  description = "More settings for both services (README › Configuration Reference), e.g. { GEMINI_MODEL = \"gemini-2.5-flash\", SCAN_SHARD_SIZE = \"10\" }."
  type        = map(string)
  default     = {}
}

variable "cost_allocation_labels" {
  description = "The label keys every project must carry, e.g. [\"cost-center\", \"environment\", \"owner\"]. Empty: the Cost Allocation Labels check stays Informational."
  type        = list(string)
  default     = []
}

variable "bigquery_dataset" {
  description = "Export every finished scan to this BigQuery dataset in the project (created in the region). Empty: no export."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[A-Za-z0-9_]*$", var.bigquery_dataset))
    error_message = "bigquery_dataset must be a dataset ID: letters, digits and underscores."
  }
}

variable "schedules" {
  description = "Scheduled scans, by job name: { weekly-org = { scope = \"organization\", scope_id = \"123456789012\", cron = \"30 0 * * 1\" } }. Cron in UTC."
  type = map(object({
    scope    = string
    scope_id = string
    cron     = string
  }))
  default = {}

  validation {
    condition     = alltrue([for name, s in var.schedules : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", name)) && contains(["organization", "folder", "project"], s.scope)])
    error_message = "A schedule's name is letters, digits, - and _ (64 at most); its scope is organization, folder or project."
  }
}

variable "organization_id" {
  description = "Set it to grant the service account the organization-level scan roles and create the Advisory Notifications custom role there (needs an account that can grant roles on the organization). Empty: README › Common Prerequisites, step 2, stays the manual step."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[0-9]*$", var.organization_id))
    error_message = "organization_id is the numeric organization ID."
  }
}

variable "advisory_role_id" {
  description = "ID of the organization custom role that reads Advisory Notifications and their settings. If the role already exists (created by hand), import it or choose a new ID."
  type        = string
  default     = "CloudGaugeAdvisoryViewer"
}

variable "programmatic_access_principals" {
  description = "Principals allowed to mint tokens for the service account (roles/iam.serviceAccountTokenCreator on it); the account itself is let through IAP. What PROGRAMMATIC_ACCESS=1 does in tools/deploy.sh, for tools/iap_token.py."
  type        = list(string)
  default     = []
}

variable "scan_max_concurrent_shards" {
  description = "Shards Cloud Tasks runs at a time: the queue's max concurrent dispatches and SCAN_MAX_CONCURRENT_SHARDS on the services."
  type        = number
  default     = 25
}

variable "task_max_attempts" {
  description = "Attempts per task: the queue's max attempts and TASK_MAX_ATTEMPTS on the services."
  type        = number
  default     = 3

  validation {
    condition     = var.task_max_attempts >= 1 && var.task_max_attempts <= 100
    error_message = "task_max_attempts is between 1 and 100."
  }
}

variable "deletion_protection" {
  description = "Refuse to destroy the two Cloud Run services. Set it to false before a terraform destroy."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Let terraform destroy delete the results bucket and the export dataset with everything in them. Keep it false on a deployment whose reports matter."
  type        = bool
  default     = false
}
