variable "enable_aws_hnl" {
  description = "Deploy the operator-run AWS Honolulu Local Zone (us-west-2-hnl-1a) diagnostic anchor (requires Local Zone opt-in first)."
  type        = bool
  default     = true
}

variable "enable_vultr_hnl" {
  description = "Deploy the operator-run Vultr Honolulu (hnl / DRFortress) diagnostic anchor (requires existing VULTR_API_KEY)."
  type        = bool
  default     = true
}

variable "aws_parent_region" {
  description = "Parent AWS region for Honolulu Local Zone."
  type        = string
  default     = "us-west-2"
}

variable "aws_local_zone" {
  description = "AWS Honolulu Local Zone AZ name."
  type        = string
  default     = "us-west-2-hnl-1a"
}

variable "aws_network_border_group" {
  description = "AWS Network Border Group for Honolulu Local Zone Elastic IP."
  type        = string
  default     = "us-west-2-hnl-1"
}

variable "aws_instance_type" {
  description = "AWS Honolulu Local Zone EC2 SKU (smallest available: t3.medium at $0.0645/hr = $47.09/mo; Nitro Enclaves NOT supported in Local Zones)."
  type        = string
  default     = "t3.medium"
}

variable "aws_root_volume_gb" {
  description = "Root EBS volume size (GB). Honolulu Local Zone supports gp2 only ($0.26/GB-mo)."
  type        = number
  default     = 10
}

variable "vultr_region" {
  description = "Vultr Honolulu region code."
  type        = string
  default     = "hnl"
}

variable "vultr_plan" {
  description = "Vultr Honolulu SKU (default vhp-1c-1gb-intel $6/mo -> $59.34/mo combined fixed <= $62/mo approved baseline; optional vhp-1c-2gb-intel $12/mo)."
  type        = string
  default     = "vhp-1c-1gb-intel"
}

variable "ssh_public_key" {
  description = "Operator Ed25519 SSH public key (bootstrap only; keep allow_ssh = false in public mode)."
  type        = string
}

variable "release_tarball_url" {
  description = "Pinned static musl Linux x86_64 pog-anchor release tarball URL."
  type        = string
  default     = "https://github.com/jperla/proof-of-geography/releases/download/v0.1.4/pog-linux-x86_64.tar.gz"
}

variable "release_tarball_sha256" {
  description = "Expected SHA-256 hex digest of release_tarball_url (verified by sha256sum before extraction)."
  type        = string
  default     = "53f29a28f7814c8e86062413fa41bc7fcd41282b7a5884cf92954eca7b38a489"
}

variable "allow_ssh" {
  description = "Temporarily open TCP/22 during initial bootstrap/TLS setup only; keep false in normal operation."
  type        = bool
  default     = false
}

variable "allow_https_443" {
  description = "Open TCP/443 only after DNS + TLS reverse proxy is explicitly configured; default false (no unnecessary public ports)."
  type        = bool
  default     = false
}

variable "lockdown_egress" {
  description = "Lock down AWS egress (UDP 1024-65535 + NTP 123 only) and disable IMDS after bootstrap (set false only for initial cloud-init HTTPS tarball pull, then true)."
  type        = bool
  default     = true
}
