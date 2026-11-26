variable "gcp_project_id" {
  type        = string
  description = "GCP Project ID for Confidential VM Anchors"
  default     = "pog-anchor-grid"
}

variable "azure_subscription_id" {
  type        = string
  description = "Azure Subscription ID for Confidential VM Anchors"
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "enable_gcp" {
  type    = bool
  default = true
}

variable "enable_aws" {
  type    = bool
  default = true
}

variable "enable_azure" {
  type    = bool
  default = true
}

variable "pog_image_tag" {
  type    = string
  default = "v0.1.0"
}

variable "anchor_tcp_port" {
  type    = number
  default = 7443
}

variable "anchor_udp_port" {
  type    = number
  default = 7444
}
