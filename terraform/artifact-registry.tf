resource "google_artifact_registry_repository" "proof_verifier" {
  location      = var.region
  repository_id = "proof-verifier"
  format        = "DOCKER"
  description   = "Docker images for zkpassport proof verifier"

  depends_on = [google_project_service.artifactregistry]
}

resource "google_artifact_registry_repository_iam_member" "public_reader" {
  repository = google_artifact_registry_repository.proof_verifier.name
  location   = var.region
  role       = "roles/artifactregistry.reader"
  member     = "allUsers"
}
