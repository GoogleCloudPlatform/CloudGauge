# terraform/versions.tf — what this configuration needs.
#
# No provider block on purpose: every resource names its project and location, so the folder works
# both as a root configuration (cd terraform && terraform apply) and as a module. Credentials come
# from Application Default Credentials (gcloud auth application-default login) or GOOGLE_APPLICATION_CREDENTIALS.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.0.0, < 9.0.0"
    }
  }
}
