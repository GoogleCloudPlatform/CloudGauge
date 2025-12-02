# main.tf

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.3.0"
    }
  }
  required_version = ">= 1.0" # Or the minimum Terraform version you require
}

provider "google" {
  project = var.project_id
  region  = var.gcp_region
}
