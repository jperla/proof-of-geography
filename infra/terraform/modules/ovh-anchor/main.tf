# OVHcloud Sovereign European Anchor Module (OpenStack Public Cloud / Bare-Metal AMD SEV-SNP)
# Regions: GRA11 (Gravelines, France), WAW1 (Warsaw, Poland), SBG5 (Strasbourg), SGP1 (Singapore)
#
# Provides independent EU-jurisdiction hardware diversity outside US hyperscalers.

terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 2.1"
    }
  }
}

variable "anchor_id" { type = string }
variable "region" {
  type    = string
  default = "GRA11"
}
variable "flavor_name" {
  type    = string
  default = "b3-8"
}
variable "image_name" {
  type    = string
  default = "Ubuntu 24.04"
}
variable "tcp_port" {
  type    = number
  default = 7443
}
variable "udp_port" {
  type    = number
  default = 7444
}
variable "user_data" { type = string }

resource "openstack_networking_secgroup_v2" "anchor_sg" {
  name        = "${var.anchor_id}-sg"
  region      = var.region
  description = "Proof of Geography Anchor TCP/UDP ingress"
}

resource "openstack_networking_secgroup_rule_v2" "tcp_rule" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = var.tcp_port
  port_range_max    = var.tcp_port
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.anchor_sg.id
  region            = var.region
}

resource "openstack_networking_secgroup_rule_v2" "udp_rule" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = var.udp_port
  port_range_max    = 65535
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.anchor_sg.id
  region            = var.region
}

resource "openstack_compute_instance_v2" "anchor" {
  name            = var.anchor_id
  region          = var.region
  flavor_name     = var.flavor_name
  image_name      = var.image_name
  security_groups = [openstack_networking_secgroup_v2.anchor_sg.name]
  user_data       = var.user_data

  network {
    name = "Ext-Net"
  }
}

output "public_ip" {
  value = openstack_compute_instance_v2.anchor.access_ip_v4
}
