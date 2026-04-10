variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "proof-verifier"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "europe-west2"
}

variable "image" {
  description = "Full Docker image URI including tag"
  type        = string
}
