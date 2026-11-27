# Reversible Operator-Run AWS Honolulu Local Zone (us-west-2-hnl-1a) Diagnostic Anchor
#
# Governance & Security Invariants:
# - Completely isolated from infra/terraform/pilot/ (zero touch on Frankfurt or 42-node pilot state).
# - Diagnostic / SoftwareDev ONLY (AWS Local Zones do NOT support Nitro Enclaves or AMD SEV-SNP).
# - Explicitly tagged DiagnosticOnly=true and FailureDomain=aws-us-west-2-hnl-1a/AS16509 so it can
#   NEVER be silently promoted into the production hardware proof quorum.
# - Reversible via `terraform destroy` (plus optional `modify-availability-zone-group --opt-in-status not-opted-in`).

data "aws_ami" "rocky_9_hnl" {
  count       = var.enable_aws_hnl ? 1 : 0
  most_recent = true
  owners      = ["792107900819"] # Official Rocky Enterprise Software Foundation (RESF)

  filter {
    name   = "name"
    values = ["Rocky-9-EC2-Base-9.*x86_64*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_vpc" "hnl" {
  count                = var.enable_aws_hnl ? 1 : 0
  cidr_block           = "10.209.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name           = "pog-isolated-vpc-aws-us-west-2-hnl-honolulu"
    Project        = "proof-of-geography-honolulu-diagnostic"
    DiagnosticOnly = "true"
    FailureDomain  = "aws-us-west-2-hnl-1a-as16509"
  }
}

resource "aws_internet_gateway" "hnl" {
  count  = var.enable_aws_hnl ? 1 : 0
  vpc_id = aws_vpc.hnl[0].id
  tags = {
    Name    = "pog-isolated-igw-aws-us-west-2-hnl-honolulu"
    Project = "proof-of-geography-honolulu-diagnostic"
  }
}

resource "aws_subnet" "hnl" {
  count                   = var.enable_aws_hnl ? 1 : 0
  vpc_id                  = aws_vpc.hnl[0].id
  cidr_block              = "10.209.1.0/24"
  availability_zone       = var.aws_local_zone
  map_public_ip_on_launch = false
  tags = {
    Name           = "pog-isolated-snet-aws-us-west-2-hnl-honolulu"
    Project        = "proof-of-geography-honolulu-diagnostic"
    DiagnosticOnly = "true"
  }
}

resource "aws_route_table" "hnl" {
  count  = var.enable_aws_hnl ? 1 : 0
  vpc_id = aws_vpc.hnl[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.hnl[0].id
  }
  tags = {
    Name    = "pog-isolated-rt-aws-us-west-2-hnl-honolulu"
    Project = "proof-of-geography-honolulu-diagnostic"
  }
}

resource "aws_route_table_association" "hnl" {
  count          = var.enable_aws_hnl ? 1 : 0
  subnet_id      = aws_subnet.hnl[0].id
  route_table_id = aws_route_table.hnl[0].id
}

resource "aws_security_group" "hnl" {
  count       = var.enable_aws_hnl ? 1 : 0
  name        = "pog-isolated-sg-aws-us-west-2-hnl-honolulu"
  description = "Scoped diagnostic ingress/egress for AWS Honolulu Local Zone anchor"
  vpc_id      = aws_vpc.hnl[0].id

  dynamic "ingress" {
    for_each = var.allow_ssh ? [1] : []
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 7443
    to_port     = 7443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 7445
    to_port     = 7445
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 40000
    to_port     = 40999
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "egress" {
    for_each = var.lockdown_egress ? [1] : []
    content {
      from_port   = 1024
      to_port     = 65535
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  dynamic "egress" {
    for_each = var.lockdown_egress ? [1] : []
    content {
      from_port   = 123
      to_port     = 123
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  dynamic "egress" {
    for_each = var.lockdown_egress ? [] : [1]
    content {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    Name           = "pog-isolated-sg-aws-us-west-2-hnl-honolulu"
    Project        = "proof-of-geography-honolulu-diagnostic"
    DiagnosticOnly = "true"
  }
}

resource "aws_key_pair" "hnl" {
  count      = var.enable_aws_hnl ? 1 : 0
  key_name   = "pog-diag-aws-us-west-2-hnl-honolulu"
  public_key = var.ssh_public_key
  tags = {
    Project        = "proof-of-geography-honolulu-diagnostic"
    DiagnosticOnly = "true"
  }
}

resource "aws_eip" "hnl" {
  count                = var.enable_aws_hnl ? 1 : 0
  domain               = "vpc"
  network_border_group = var.aws_network_border_group
  tags = {
    Name           = "pog-eip-aws-us-west-2-hnl-honolulu"
    Project        = "proof-of-geography-honolulu-diagnostic"
    DiagnosticOnly = "true"
  }
}

resource "aws_instance" "hnl" {
  count                  = var.enable_aws_hnl ? 1 : 0
  ami                    = data.aws_ami.rocky_9_hnl[0].id
  instance_type          = var.aws_instance_type
  availability_zone      = var.aws_local_zone
  subnet_id              = aws_subnet.hnl[0].id
  vpc_security_group_ids = [aws_security_group.hnl[0].id]
  key_name               = aws_key_pair.hnl[0].key_name

  # Honolulu Local Zone supports gp2 EBS only ($0.26/GB-mo)
  root_block_device {
    volume_type           = "gp2"
    volume_size           = var.aws_root_volume_gb
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = var.lockdown_egress ? "disabled" : "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = templatefile("${path.module}/cloud-init-honolulu.yaml", {
    anchor_id           = "aws-us-west-2-hnl-honolulu"
    cloud_provider      = "aws"
    failure_domain      = "aws-us-west-2-hnl-1a/AS16509"
    release_tarball_url = var.release_tarball_url
    ssh_public_key      = var.ssh_public_key
    extra_flags         = "--allow-dev-tee --allow-dev-prover"
  })

  tags = {
    Name           = "aws-us-west-2-hnl-honolulu"
    Project        = "proof-of-geography-honolulu-diagnostic"
    OS             = "rocky-linux-9"
    DiagnosticOnly = "true"
    TeeMode        = "software-dev-diagnostic"
    FailureDomain  = "aws-us-west-2-hnl-1a/AS16509"
    ASN            = "16509"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_eip_association" "hnl" {
  count         = var.enable_aws_hnl ? 1 : 0
  instance_id   = aws_instance.hnl[0].id
  allocation_id = aws_eip.hnl[0].id
}
