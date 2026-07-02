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
      min_instance_count = 1
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
        cpu_idle = true
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

resource "google_compute_region_network_endpoint_group" "serverless_neg" {
  name                  = "proof-verifier-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.proof_verifier.name
  }
}

resource "google_compute_backend_service" "default" {
  name                  = "proof-verifier-backend"
  protocol              = "HTTP"
  load_balancing_scheme = "EXTERNAL_MANAGED"

  backend {
    group = google_compute_region_network_endpoint_group.serverless_neg.id
  }
}

resource "google_compute_url_map" "default" {
  name            = "proof-verifier-url-map"
  default_service = google_compute_backend_service.default.id
}

resource "google_compute_managed_ssl_certificate" "default" {
  name = "proof-verifier-cert"

  managed {
    domains = ["verifier.zkpassport.id"]
  }
}

resource "google_compute_target_https_proxy" "default" {
  name             = "proof-verifier-https-proxy"
  url_map          = google_compute_url_map.default.id
  ssl_certificates = [google_compute_managed_ssl_certificate.default.id]
}

resource "google_compute_global_forwarding_rule" "default" {
  name                  = "proof-verifier-forwarding-rule"
  target                = google_compute_target_https_proxy.default.id
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

resource "google_compute_url_map" "http_redirect" {
  name = "proof-verifier-http-redirect"

  default_url_redirect {
    https_redirect = true
    strip_query    = false
  }
}

resource "google_compute_target_http_proxy" "http_redirect" {
  name    = "proof-verifier-http-proxy"
  url_map = google_compute_url_map.http_redirect.id
}

resource "google_compute_global_forwarding_rule" "http_redirect" {
  name                  = "proof-verifier-http-forwarding-rule"
  target                = google_compute_target_http_proxy.http_redirect.id
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

output "service_url" {
  value = google_cloud_run_v2_service.proof_verifier.uri
}

output "load_balancer_ip" {
  value = google_compute_global_forwarding_rule.default.ip_address
}
