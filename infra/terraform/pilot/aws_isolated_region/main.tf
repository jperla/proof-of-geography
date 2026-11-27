terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "anchor_id" { type = string }
variable "ssh_public_key" { type = string }
variable "release_tarball_url" { type = string }
variable "instance_type" {
  type    = string
  default = "c6a.large"
}
variable "enable_nitro_enclave" {
  type    = bool
  default = false
}
variable "arm64_tarball_url" {
  type    = string
  default = "https://github.com/jperla/proof-of-geography/releases/download/v0.1.7/pog-linux-aarch64.tar.gz"
}
variable "nitro_eif_url" {
  type    = string
  default = "https://github.com/jperla/proof-of-geography/releases/download/v0.1.7/pog-anchor-arm64.eif"
}
variable "enclave_cpu_count" {
  type    = number
  default = 1
}
variable "enclave_memory_mib" {
  type    = number
  default = 1024
}
variable "allow_ssh" {
  type    = bool
  default = false
}
variable "lockdown_egress" {
  type    = bool
  default = true
}

data "aws_ami" "rocky_9" {
  most_recent = true
  owners      = ["792107900819"] # Rocky Enterprise Software Foundation (official RESF Rocky Linux 9)

  filter {
    name   = "name"
    values = ["Rocky-9-EC2-Base-9.*x86_64*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_ami" "al2023_arm64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-6.12-arm64"]
  }
  filter {
    name   = "architecture"
    values = ["arm64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Strictly isolated dedicated VPC (zero touch on default VPC or any existing AWS resources!)
resource "aws_vpc" "isolated" {
  cidr_block           = "10.199.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "pog-isolated-vpc-${var.anchor_id}", Project = "proof-of-geography-pilot" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.isolated.id
  tags   = { Name = "pog-isolated-igw-${var.anchor_id}", Project = "proof-of-geography-pilot" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.isolated.id
  cidr_block              = "10.199.1.0/24"
  map_public_ip_on_launch = true
  tags                    = { Name = "pog-isolated-snet-${var.anchor_id}", Project = "proof-of-geography-pilot" }
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.isolated.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "pog-isolated-rt-${var.anchor_id}", Project = "proof-of-geography-pilot" }
}

resource "aws_route_table_association" "rta" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.rt.id
}

resource "aws_security_group" "sg" {
  name        = "pog-isolated-sg-${var.anchor_id}"
  description = "Isolated Proof of Geography Anchor SG"
  vpc_id      = aws_vpc.isolated.id

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
  # Stateful SG automatically allows return TCP replies on 443/7443/7445; block all outbound TCP in public mode!
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
  tags = { Project = "proof-of-geography-pilot" }
}

resource "aws_key_pair" "pilot" {
  key_name   = "pog-pilot-${var.anchor_id}"
  public_key = var.ssh_public_key
  tags       = { Project = "proof-of-geography-pilot" }
}

resource "aws_instance" "anchor" {
  ami                         = var.enable_nitro_enclave ? data.aws_ami.al2023_arm64.id : data.aws_ami.rocky_9.id
  instance_type               = var.enable_nitro_enclave ? "c6g.large" : var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.sg.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.pilot.key_name

  enclave_options {
    enabled = var.enable_nitro_enclave
  }

  # Enable IMDSv2 ONLY during initial cloud-init bootstrap; disable IMDS completely in public lockdown mode!
  metadata_options {
    http_endpoint               = var.lockdown_egress ? "disabled" : "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = var.enable_nitro_enclave ? templatefile("${path.module}/../cloud-init-aws-nitro.yaml", {
    anchor_id          = var.anchor_id
    ssh_public_key     = var.ssh_public_key
    arm64_tarball_url  = var.arm64_tarball_url
    eif_url            = var.nitro_eif_url
    enclave_cpu_count  = var.enclave_cpu_count
    enclave_memory_mib = var.enclave_memory_mib
  }) : templatefile("${path.module}/../cloud-init-pilot.yaml", {
    anchor_id           = var.anchor_id
    cloud_provider      = "aws"
    release_tarball_url = var.release_tarball_url
    ssh_public_key      = var.ssh_public_key
    extra_flags         = "--allow-dev-tee --allow-dev-prover"
  })

  tags = {
    Name    = var.anchor_id
    Project = "proof-of-geography-pilot"
    OS      = var.enable_nitro_enclave ? "amazon-linux-2023-arm64" : "rocky-linux-9"
    TeeMode = var.enable_nitro_enclave ? "aws-nitro-enclave-non-debug" : "aws-isolated-pilot"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

output "public_ip" {
  value = aws_instance.anchor.public_ip
}

output "instance_id" {
  value = aws_instance.anchor.id
}

output "security_group_id" {
  value = aws_security_group.sg.id
}
