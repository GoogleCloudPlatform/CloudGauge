# --- Outputs ---
# outputs.tf

output "cloud_run_service_url" {
  description = "The URL of the deployed CloudGauge service."
  value       = google_cloud_run_v2_service.cloudgauge_service.uri
}

output "trigger_build_command" {
  description = "Command to manually trigger the Cloud Build."
  value       = "gcloud builds triggers run ${google_cloudbuild_trigger.build_from_github.name} --region=${google_cloudbuild_trigger.build_from_github.location} --project=${var.project_id} --branch=main"
}