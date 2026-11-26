output "gcp_anchor_endpoints" {
  description = "Public IPs and TEE metadata for deployed GCP Confidential VM Anchors"
  value = {
    for k, m in module.gcp_anchors : k => {
      public_ip = m.public_ip
      tee_type  = m.tee_type
      tcp       = "${m.public_ip}:${var.anchor_tcp_port}"
      udp       = "${m.public_ip}:${var.anchor_udp_port}"
    }
  }
}

output "azure_anchor_endpoints" {
  description = "Public IPs and TEE metadata for deployed Azure Confidential VM Anchors"
  value = {
    for k, m in module.azure_anchors : k => {
      public_ip = m.public_ip
      tee_type  = m.tee_type
      tcp       = "${m.public_ip}:${var.anchor_tcp_port}"
      udp       = "${m.public_ip}:${var.anchor_udp_port}"
    }
  }
}
