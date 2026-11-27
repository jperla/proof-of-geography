output "aws_hnl_anchor" {
  description = "AWS Honolulu Local Zone diagnostic anchor outputs (distinct network AS16509)."
  value = var.enable_aws_hnl ? {
    anchor_id       = "aws-us-west-2-hnl-honolulu"
    cloud_provider  = "aws"
    region          = var.aws_local_zone
    failure_domain  = "aws-us-west-2-hnl-1a/AS16509"
    asn             = 16509
    diagnostic_only = true
    tee_vendor      = "SoftwareDev"
    instance_id     = aws_instance.hnl[0].id
    instance_type   = aws_instance.hnl[0].instance_type
    public_ip       = aws_eip.hnl[0].public_ip
    endpoint_tcp    = "${aws_eip.hnl[0].public_ip}:7443"
    endpoint_udp    = "${aws_eip.hnl[0].public_ip}:7444"
    http_info_url   = "http://${aws_eip.hnl[0].public_ip}:7445"
  } : null
}

output "vultr_hnl_anchor" {
  description = "Vultr Honolulu (DRFortress) diagnostic anchor outputs (distinct network AS20473)."
  value = var.enable_vultr_hnl ? {
    anchor_id       = "vultr-hnl-honolulu"
    cloud_provider  = "vultr"
    region          = var.vultr_region
    failure_domain  = "vultr-hnl-drfortress/AS20473"
    asn             = 20473
    diagnostic_only = true
    tee_vendor      = "SoftwareDev"
    instance_id     = vultr_instance.hnl[0].id
    instance_type   = vultr_instance.hnl[0].plan
    public_ip       = vultr_instance.hnl[0].main_ip
    endpoint_tcp    = "${vultr_instance.hnl[0].main_ip}:7443"
    endpoint_udp    = "${vultr_instance.hnl[0].main_ip}:7444"
    http_info_url   = "http://${vultr_instance.hnl[0].main_ip}:7445"
  } : null
}
