# CloudGauge Terraform Infrastructure

This directory contains the Terraform configuration for deploying the CloudGauge infrastructure on Google Cloud Platform.

## Overview

The Terraform code provisions the following resources:
- **Cloud Run Service**: Hosts the CloudGauge application.
- **Cloud Build Trigger**: Automates builds from the GitHub repository.
- **Cloud Storage Bucket**: Stores reports and other artifacts.
- **Service Accounts**: Dedicated service accounts for the application and build process.
- **IAM Roles**: Necessary permissions for the service accounts.
- **API Enablement**: Enables required Google Cloud APIs.

## Prerequisites

- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed and authenticated.
- [Terraform](https://developer.hashicorp.com/terraform/install) installed (version >= 1.0).
- A Google Cloud Project.
- A GitHub Repository Connection (2nd Gen) set up in Cloud Build.

## Configuration

1.  **Copy the example variables file:**
    ```bash
    cp terraform.tfvars.example terraform.tfvars
    ```

2.  **Edit `terraform.tfvars`** and provide values for the following required variables:
    - `project_id`: Your Google Cloud Project ID.
    - `org_id`: Your Google Cloud Organization ID.
    - `github_repository_connection`: The full resource name of your GitHub repository connection.
      - Format: `projects/PROJECT_ID/locations/REGION/connections/CONNECTION_ID/repositories/REPO_ID`

3.  **Review optional variables** in `variables.tf` and override them in `terraform.tfvars` if needed (e.g., `gcp_region`, `service_name`).

## State Management

The `backend.tf` file is used to configure the GCS backend for remote state storage.

1.  **Create a GCS bucket** to store the state (if you don't have one).
2.  **Edit `backend.tf`** and replace `ADD_YOUR_BUCKET_NAME` with your actual GCS bucket name.
    ```hcl
    terraform {
      backend "gcs" {
        bucket = "ADD_YOUR_BUCKET_NAME" # Replace with your GCS bucket name
        prefix = "terraform/state"
      }
    }
    ```
3.  **Initialize Terraform** to configure the backend:
    ```bash
    terraform init
    ```

## Deployment

1.  **Initialize Terraform:**
    ```bash
    terraform init
    ```

2.  **Plan the deployment:**
    ```bash
    terraform plan
    ```

3.  **Apply the changes:**
    ```bash
    terraform apply
    ```

## Outputs

After a successful apply, Terraform will output:
- `cloud_run_service_url`: The URL of the deployed CloudGauge service.
- `trigger_build_command`: A command to manually trigger the initial Cloud Build.

## Notes

- **Initial Build**: After the first deployment, you may need to manually trigger the Cloud Build to deploy the container image to Cloud Run. Use the command provided in the `trigger_build_command` output.
