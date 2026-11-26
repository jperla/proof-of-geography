# Tencent Cloud Confidential CVM Anchor Module (AMD SEV-SNP / Intel TDX)
# Regions: ap-hongkong, ap-singapore, ap-tokyo, ap-seoul, eu-frankfurt
#
# Provides deep Asia-Pacific IXP peering (HKIX, SGIX, Equinix HK/SG) and independent
# cloud-provider diversity alongside GCP, AWS, Azure, OVH, and ByteDance.

terraform {
  required_providers {
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "~> 1.81"
    }
  }
}

variable "anchor_id" { type = string }
variable "availability_zone" {
  type    = string
  default = "ap-hongkong-2"
}
variable "instance_type" {
  type        = string
  default     = "S6.MEDIUM4"
  description = "AMD EPYC SEV-SNP Confidential CVM instance type on Tencent Cloud"
}
variable "image_id" {
  type        = string
  description = "Ubuntu 24.04 Confidential Computing compatible image ID"
}
variable "vpc_id" { type = string }
variable "subnet_id" { type = string }
variable "tcp_port" {
  type    = number
  default = 7443
}
variable "udp_port" {
  type    = number
  default = 7444
}
variable "user_data_b64" { type = string }

resource "tencentcloud_security_group" "sg" {
  name        = "${var.anchor_id}-sg"
  description = "Proof of Geography Anchor TCP/UDP distance-bounding"
}

resource "tencentcloud_security_group_lite_rule" "rules" {
  security_group_id = tencentcloud_security_group.sg.id
  ingress = [
    "ACCEPT#0.0.0.0/0#${var.tcp_port}#TCP",
    "ACCEPT#0.0.0.0/0#${var.udp_port}-65535#UDP",
  ]
  egress = ["ACCEPT#0.0.0.0/0#ALL#ALL"]
}

resource "tencentcloud_instance" "anchor" {
  instance_name              = var.anchor_id
  availability_zone          = var.availability_zone
  image_id                   = var.image_id
  instance_type              = var.instance_type
  vpc_id                     = var.vpc_id
  subnet_id                  = var.subnet_id
  orderly_security_groups    = [tencentcloud_security_group.sg.id]
  allocate_public_ip         = true
  internet_max_bandwidth_out = 100
  user_data                  = var.user_data_b64

  tags = {
    project = "proof-of-geography"
    tee     = "amd-sev-snp"
  }
}

output "public_ip" {
  value = tencentcloud_instance.anchor.public_ip
}
