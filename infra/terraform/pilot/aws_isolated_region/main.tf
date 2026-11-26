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

data "aws_ami" "ubuntu_2404" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
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

  ingress {
    from_port   = 22
    to_port     = 22
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
    from_port   = 1024
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
  tags = { Project = "proof-of-geography-pilot" }
}

resource "aws_key_pair" "pilot" {
  key_name   = "pog-pilot-${var.anchor_id}"
  public_key = var.ssh_public_key
  tags       = { Project = "proof-of-geography-pilot" }
}

resource "aws_instance" "anchor" {
  ami                         = data.aws_ami.ubuntu_2404.id
  instance_type               = "c6a.large"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.sg.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.pilot.key_name

  user_data = templatefile("${path.module}/../cloud-init-pilot.yaml", {
    anchor_id           = var.anchor_id
    cloud_provider      = "aws"
    release_tarball_url = var.release_tarball_url
    ssh_public_key      = var.ssh_public_key
    extra_flags         = "--allow-dev-tee --allow-dev-prover"
  })

  tags = {
    Name    = var.anchor_id
    Project = "proof-of-geography-pilot"
    TeeMode = "aws-isolated-pilot"
  }
}

output "public_ip" {
  value = aws_instance.anchor.public_ip
}
