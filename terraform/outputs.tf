output "service_url" {
  description = "The URL of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.proof_verifier.uri
}

output "workload_identity_provider" {
  description = "The full resource name of the WIF provider (use as WIF_PROVIDER GitHub secret)"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "service_account_email" {
  description = "The deployer service account email (use as WIF_SERVICE_ACCOUNT GitHub secret)"
  value       = google_service_account.github_actions_deployer.email
}
