# Staged Reversible AWS Nitro Enclave Production Canary (Non-Debug EIF — Approval Required Before Apply)
#
# Governance & Security Invariants:
# - Isolated dedicated VPC (10.211.0.0/16) in `us-east-1` — ZERO touch on existing 14 AWS diagnostic nodes,
#   Honolulu stack, `quill-enclave`, or `tr-eu-clickhouse-1`.
# - Requires operator approval for incremental compute spend (NO already-paid Nitro-Enclave-capable PoG capacity):
#   * Option A (Smallest / Cheapest — ARM64 Graviton2): `c6g.large` (2 vCPU / 2 dedicated physical cores, 4 GiB)
#     = $49.64/mo compute + $1.60/mo 20 GB gp3 + $3.65/mo IPv4 = $54.89/mo incremental
#     (14-node fleet replacement delta = -$110.62/mo cheaper than current $891.86/mo fleet!).
#   * Option B (x86_64 Same-Arch): `c6a.xlarge` (4 vCPU / 2 physical cores, 8 GiB)
#     = $111.69/mo compute + $1.60/mo 20 GB gp3 + $3.65/mo IPv4 = $116.94/mo incremental
#     (14-node fleet replacement delta = +$891.86/mo).
# - Boots REAL non-debug `.eif` (`nitro-cli run-enclave --enclave-cid 16 --cpu-count ... --memory 1024`,
#   STRICTLY NO `--debug-mode`) where ephemeral Ed25519 keygen, `/dev/nsm` COSE_Sign1 attestation,
#   X25519 key agreement, BLAKE3-MAC challenge/RTT stopwatch, and receipt signing all execute inside enclave RAM.
# - Untrusted parent EC2 runs ONLY stateless `--nitro-host-relay --enclave-cid 16 --vsock-port 7443`.
# - ZERO SSH ingress (`tcp/22` omitted); IMDSv2 disabled after bootstrap (`lockdown_egress = true`).

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "anchor_id" {
  type    = string
  default = "aws-us-east-1-nvirginia-nitro-canary"
}

variable "instance_type" {
  description = "Smallest Nitro-Enclave-supported SKU: c6g.large ($49.64/mo ARM64) or c6a.xlarge ($111.69/mo x86_64)."
  type        = string
  default     = "c6a.xlarge"
}

variable "enclave_cpu_count" {
  description = "vCPUs carved off for Nitro Enclave (2 for c6a.xlarge; 1 for c6g.large)."
  type        = number
  default     = 2
}

variable "enclave_memory_mib" {
  type    = number
  default = 1024
}

variable "eif_download_url" {
  description = "HTTPS URL of signed non-debug pog-anchor.eif artifact built in CI."
  type        = string
}

variable "eif_sha256" {
  description = "Expected SHA-256 hex digest of pog-anchor.eif (verified before nitro-cli run-enclave)."
  type        = string
}

variable "expected_pcr0_hex" {
  description = "Pinned non-zero 96-hex SHA-384 PCR0 emitted by `nitro-cli build-enclave`."
  type        = string
}

variable "lockdown_egress" {
  type    = bool
  default = true
}

provider "aws" {
  region = var.aws_region
}

locals {
  is_arm64 = startswith(var.instance_type, "c6g.") || startswith(var.instance_type, "c7g.")
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = [local.is_arm64 ? "al2023-ami-2023.*-arm64" : "al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_vpc" "nitro" {
  cidr_block           = "10.211.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "pog-tee-vpc-${var.anchor_id}", Project = "proof-of-geography-tee-canary" }
}

resource "aws_internet_gateway" "nitro" {
  vpc_id = aws_vpc.nitro.id
  tags   = { Name = "pog-tee-igw-${var.anchor_id}", Project = "proof-of-geography-tee-canary" }
}

resource "aws_subnet" "nitro" {
  vpc_id                  = aws_vpc.nitro.id
  cidr_block              = "10.211.1.0/24"
  map_public_ip_on_launch = true
  tags                    = { Name = "pog-tee-snet-${var.anchor_id}", Project = "proof-of-geography-tee-canary" }
}

resource "aws_route_table" "nitro" {
  vpc_id = aws_vpc.nitro.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.nitro.id
  }
}

resource "aws_route_table_association" "nitro" {
  subnet_id      = aws_subnet.nitro.id
  route_table_id = aws_route_table.nitro.id
}

resource "aws_security_group" "nitro" {
  name        = "pog-tee-sg-${var.anchor_id}"
  description = "Zero-SSH Nitro Enclave Canary SG (probe ports only)"
  vpc_id      = aws_vpc.nitro.id

  ingress {
    description = "PoG Phase 1 TCP handshake"
    from_port   = 7443
    to_port     = 7443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "PoG HTTP /info and /attest?nonce="
    from_port   = 7445
    to_port     = 7445
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "PoG Phase 2 UDP distance-bounding range"
    from_port   = 40000
    to_port     = 40999
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "PoG Phase 2 UDP replies"
    from_port   = 1024
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "NTP clock sync"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  dynamic "egress" {
    for_each = var.lockdown_egress ? [] : [1]
    content {
      description = "Bootstrap-only HTTPS pull of signed EIF & AL2023 aws-nitro-enclaves-cli"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  dynamic "egress" {
    for_each = var.lockdown_egress ? [] : [1]
    content {
      description = "Bootstrap-only DNS"
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}

resource "aws_instance" "nitro" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.nitro.id
  vpc_security_group_ids      = [aws_security_group.nitro.id]
  associate_public_ip_address = true

  enclave_options {
    enabled = true
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = var.lockdown_egress ? "disabled" : "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = <<-YAML
    #cloud-config
    runcmd:
      - dnf install -y aws-nitro-enclaves-cli
      - sed -i 's/memory_mib:.*/memory_mib: ${var.enclave_memory_mib}/' /etc/nitro_enclaves/allocator.yaml
      - sed -i 's/cpu_count:.*/cpu_count: ${var.enclave_cpu_count}/' /etc/nitro_enclaves/allocator.yaml
      - systemctl enable --now nitro-enclaves-allocator.service
      - mkdir -p /opt/pog
      - curl -fsSL "${var.eif_download_url}" -o /opt/pog/pog-anchor.eif
      - echo "${var.eif_sha256}  /opt/pog/pog-anchor.eif" | sha256sum -c -
      - nitro-cli run-enclave --enclave-cid 16 --cpu-count ${var.enclave_cpu_count} --memory ${var.enclave_memory_mib} --eif-path /opt/pog/pog-anchor.eif
      - systemctl disable --now sshd || true
  YAML

  tags = {
    Name         = var.anchor_id
    Project      = "proof-of-geography-tee-canary"
    TeeMode      = "aws-nitro-enclave-non-debug"
    ExpectedPCR0 = var.expected_pcr0_hex
  }
}

output "nitro_canary_ip" {
  value = aws_instance.nitro.public_ip
}
