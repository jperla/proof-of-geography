# =============================================================================
# ISOLATED AWS PILOT MODULE (4 Regions — Dedicated VPC 10.199.0.0/16 per region)
# Zero touch on default VPC or any existing AWS resources!
# =============================================================================

provider "aws" {
  alias  = "us_west_1"
  region = "us-west-1"
}
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
provider "aws" {
  alias  = "eu_central_1"
  region = "eu-central-1"
}
provider "aws" {
  alias  = "ap_northeast_1"
  region = "ap-northeast-1"
}

module "aws_isolated_us_west_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.us_west_1 }
  anchor_id           = "aws-us-west-1-sanjose"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
}

module "aws_isolated_us_east_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.us_east_1 }
  anchor_id           = "aws-us-east-1-nvirginia"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
}

module "aws_isolated_eu_central_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.eu_central_1 }
  anchor_id           = "aws-eu-central-1-frankfurt"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
}

module "aws_isolated_ap_northeast_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.ap_northeast_1 }
  anchor_id           = "aws-ap-northeast-1-tokyo"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
}

locals {
  aws_pilot_outputs = {
    "aws-us-west-1-sanjose" = {
      ip             = module.aws_isolated_us_west_1.public_ip
      cloud_provider = "aws"
      region         = "us-west-1"
      city           = "San Jose, CA, USA"
      lat            = 37.3382
      lon            = -121.8863
    }
    "aws-us-east-1-nvirginia" = {
      ip             = module.aws_isolated_us_east_1.public_ip
      cloud_provider = "aws"
      region         = "us-east-1"
      city           = "Ashburn, VA, USA"
      lat            = 39.0180
      lon            = -77.4590
    }
    "aws-eu-central-1-frankfurt" = {
      ip             = module.aws_isolated_eu_central_1.public_ip
      cloud_provider = "aws"
      region         = "eu-central-1"
      city           = "Frankfurt, Germany"
      lat            = 50.1167
      lon            = 8.6833
    }
    "aws-ap-northeast-1-tokyo" = {
      ip             = module.aws_isolated_ap_northeast_1.public_ip
      cloud_provider = "aws"
      region         = "ap-northeast-1"
      city           = "Tokyo, Japan"
      lat            = 35.6895
      lon            = 139.6917
    }
  }
}
