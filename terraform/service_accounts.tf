# --- 2. Service Account ---
resource "google_service_account" "cloudgauge_sa" {
  project      = var.project_id
  account_id   = var.sa_name
  display_name = "CloudGauge Service Account"
  depends_on = [
    google_project_service.apis
  ]
}

# 1. Create the User-Managed Service Account (SA)
# This is the dedicated identity for your build process.
resource "google_service_account" "build_sa" {
  project      = var.project_id
  account_id   = local.build_sa_id
  display_name = "SA for CI/CD Build Pipeline - Least Privilege"
}