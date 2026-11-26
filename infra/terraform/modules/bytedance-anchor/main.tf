# ByteDance (BytePlus / Volcengine) Confidential ECS Anchor Module (Intel TDX / AMD SEV-SNP)
# Regions: ap-southeast-1 (Johor/Singapore), ap-southeast-3 (Jakarta), cn-hongkong, cn-beijing
#
# Adds independent Asian network peering & multi-jurisdiction Anchor diversity so that
# East/SE Asia GPU localization does not rely solely on US cloud providers.

terraform {
  required_providers {
    volcengine = {
      source  = "volcengine/volcengine"
      version = "~> 0.0.150"
    }
  }
}

variable "anchor_id" { type = string }
variable "zone_id" {
  type    = string
  default = "ap-southeast-1a"
}
variable "instance_type" {
  type        = string
  default     = "ecs.c3t.large"
  description = "Confidential Intel TDX / AMD SEV-SNP ECS instance type on BytePlus/Volcengine"
}
variable "image_id" { type = string }
variable "subnet_id" { type = string }
variable "security_group_id" { type = string }
variable "user_data_b64" { type = string }

resource "volcengine_ecs_instance" "anchor" {
  instance_name        = var.anchor_id
  zone_id              = var.zone_id
  instance_type        = var.instance_type
  image_id             = var.image_id
  subnet_id            = var.subnet_id
  security_group_ids   = [var.security_group_id]
  instance_charge_type = "PostPaid"
  user_data            = var.user_data_b64

  system_volume_type = "ESSD_PL0"
  system_volume_size = 40

  tags {
    key   = "project"
    value = "proof-of-geography"
  }
}

resource "volcengine_eip_address" "eip" {
  billing_type = "PostPaidByTraffic"
  bandwidth    = 100
}

resource "volcengine_eip_associate" "assoc" {
  allocation_id = volcengine_eip_address.eip.id
  instance_id   = volcengine_ecs_instance.anchor.id
  instance_type = "EcsInstance"
}

output "public_ip" {
  value = volcengine_eip_address.eip.eip_address
}
