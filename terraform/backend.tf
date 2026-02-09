terraform {
  backend "gcs" {
    bucket = "ADD_YOUR_BUCKET_NAME" # Replace with your GCS bucket name
    prefix = "terraform/state"      # Optional: Change prefix if needed
  }

}
