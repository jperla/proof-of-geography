variable "anchor_id" { type = string }
variable "instance_type" {
  type        = string
  default     = "c6a.large"
  description = "c6a.large for AMD SEV-SNP (lowest latency/cost) or c6i.xlarge for AWS Nitro Enclaves"
}
variable "tee_mode" {
  type        = string
  default     = "sev_snp"
  description = "sev_snp (direct ENA NIC, ~30us) or nitro (all AWS regions, ~300us vsock)"
}
variable "ami_id" { type = string }
variable "tcp_port" {
  type    = number
  default = 7443
}
variable "udp_port" {
  type    = number
  default = 7444
}
variable "user_data" { type = string }

resource "aws_security_group" "anchor_sg" {
  name        = "${var.anchor_id}-sg"
  description = "Proof of Geography Anchor TCP/UDP distance-bounding ingress"

  ingress {
    from_port   = var.tcp_port
    to_port     = var.tcp_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = var.udp_port
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "anchor" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  vpc_security_group_ids      = [aws_security_group.anchor_sg.id]
  associate_public_ip_address = true
  user_data                   = var.user_data

  # AMD SEV-SNP and Nitro Enclaves are mutually exclusive on EC2.
  dynamic "cpu_options" {
    for_each = var.tee_mode == "sev_snp" ? [1] : []
    content {
      amd_sev_snp = "enabled"
    }
  }

  dynamic "enclave_options" {
    for_each = var.tee_mode == "nitro" ? [1] : []
    content {
      enabled = true
    }
  }

  tags = {
    Name    = var.anchor_id
    Project = "proof-of-geography"
    TeeMode = var.tee_mode
  }
}

output "public_ip" {
  value = aws_instance.anchor.public_ip
}
