# terraform/outputs.tf

output "web_url" {
  description = "The pages, at Cloud Run's deterministic URL (the service also answers at its older <hash> URL). Sign in with an account listed in operators."
  value       = local.web_url
}

output "worker_url" {
  description = "The worker (internal ingress: only Cloud Tasks and Cloud Scheduler reach it)."
  value       = local.worker_url
}

output "service_account_email" {
  description = "The identity of both services, and of the image build."
  value       = google_service_account.cloudgauge.email
}

output "build_command" {
  description = "Builds the image with Cloud Build as the service account (runs the test suite, pushes only if it passes). Run it from the repository root, then apply again with image_tag."
  value       = "gcloud builds submit . --project ${var.project_id} --config cloudbuild.yaml --substitutions=_IMAGE=${local.image},_TAG=$(git rev-parse --short HEAD) --service-account=projects/${var.project_id}/serviceAccounts/${google_service_account.cloudgauge.email}"
}

output "next_step" {
  description = "What to do now."
  value = local.deploy_services ? (
    length(var.operators) > 0 ? "Open ${local.web_url} (IAM changes take up to a minute). Scans need the organization-level roles of README › Common Prerequisites${local.on_organization ? " — granted here" : ", granted once to ${google_service_account.cloudgauge.email}"}." :
    "Nobody can sign in yet: add principals to operators and apply again, or grant roles/iap.httpsResourceAccessor on ${var.service_name} in the console (Security › Identity-Aware Proxy)."
    ) : (
    "Foundation created. Build the image with the build_command output (from the repository root), then: terraform apply -var image_tag=$(git rev-parse --short HEAD)"
  )
}
