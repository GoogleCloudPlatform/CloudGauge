# --- 3. IAM Bindings ---
# Grant roles at the Organization level
resource "google_organization_iam_member" "org_roles" {
  for_each = toset(var.org_roles)
  org_id   = var.org_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.cloudgauge_sa.email}"
}

# Grant roles at the Project level
resource "google_project_iam_member" "project_roles" {
  for_each = toset(var.project_roles)
  project  = var.project_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.cloudgauge_sa.email}"
}

# Grant self-impersonation roles to the Service Account
resource "google_service_account_iam_member" "sa_self_iam" {
  for_each           = toset(["roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"])
  service_account_id = google_service_account.cloudgauge_sa.name
  role               = each.key
  member             = "serviceAccount:${google_service_account.cloudgauge_sa.email}"
}

# Grant the SA admin access to the bucket
resource "google_storage_bucket_iam_member" "bucket_admin" {
  bucket = google_storage_bucket.reports_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.cloudgauge_sa.email}"
}

# --- 7. Cloud Run IAM ---
# Allow the service account to invoke its own service (for async tasks)
resource "google_cloud_run_v2_service_iam_member" "sa_invoker" {
  project  = google_cloud_run_v2_service.cloudgauge_service.project
  location = google_cloud_run_v2_service.cloudgauge_service.location
  name     = google_cloud_run_v2_service.cloudgauge_service.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.cloudgauge_sa.email}"
}