provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  type    = string
  default = "proof-verifier"
}

variable "region" {
  type    = string
  default = "europe-west2"
}

variable "image" {
  description = "Full Docker image URI including tag"
  type        = string
}

resource "google_cloud_run_v2_service" "proof_verifier" {
  name     = "proof-verifier"
  location = var.region

  template {
    scaling {
      min_instance_count = 3
      max_instance_count = 10
    }

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          memory = "512Mi"
          cpu    = "1"
        }
      }

      startup_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        initial_delay_seconds = 5
        period_seconds        = 10
        failure_threshold     = 3
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        period_seconds = 30
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.proof_verifier.name
  location = google_cloud_run_v2_service.proof_verifier.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "service_url" {
  value = google_cloud_run_v2_service.proof_verifier.uri
}
