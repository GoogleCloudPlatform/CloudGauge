# --- 4. Storage Bucket ---
resource "google_storage_bucket" "reports_bucket" {
  project                     = var.project_id
  name                        = "cloudgauge-reports-${var.project_id}"
  location                    = var.gcp_region
  force_destroy               = true # Allows deletion of non-empty buckets
  uniform_bucket_level_access = true
  depends_on = [
    google_project_service.apis
  ]
}
