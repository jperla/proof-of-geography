# =============================================================================
# ISOLATED AWS ANCHOR FLEET (14 Regions — Dedicated VPC 10.199.0.0/16 per region)
# Uniform Rocky Linux 9.9 (official RESF AMI), IMDS disabled, ZERO touch on default VPC!
# =============================================================================

provider "aws" {
  alias  = "us_west_1"
  region = "us-west-1"
}
provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
}
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
provider "aws" {
  alias  = "us_east_2"
  region = "us-east-2"
}
provider "aws" {
  alias  = "ca_central_1"
  region = "ca-central-1"
}
provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}
provider "aws" {
  alias  = "eu_west_2"
  region = "eu-west-2"
}
provider "aws" {
  alias  = "eu_central_1"
  region = "eu-central-1"
}
provider "aws" {
  alias  = "eu_north_1"
  region = "eu-north-1"
}
provider "aws" {
  alias  = "eu_south_1"
  region = "eu-south-1"
}
provider "aws" {
  alias  = "ap_south_1"
  region = "ap-south-1"
}
provider "aws" {
  alias  = "ap_northeast_1"
  region = "ap-northeast-1"
}
provider "aws" {
  alias  = "ap_southeast_2"
  region = "ap-southeast-2"
}
provider "aws" {
  alias  = "sa_east_1"
  region = "sa-east-1"
}

module "aws_isolated_us_west_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.us_west_1 }
  anchor_id           = "aws-us-west-1-sanjose"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_us_west_2" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.us_west_2 }
  anchor_id           = "aws-us-west-2-oregon"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_us_east_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.us_east_1 }
  anchor_id           = "aws-us-east-1-nvirginia"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_us_east_2" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.us_east_2 }
  anchor_id           = "aws-us-east-2-ohio"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_ca_central_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.ca_central_1 }
  anchor_id           = "aws-ca-central-1-montreal"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_eu_west_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.eu_west_1 }
  anchor_id           = "aws-eu-west-1-dublin"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_eu_west_2" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.eu_west_2 }
  anchor_id           = "aws-eu-west-2-london"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_eu_central_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.eu_central_1 }
  anchor_id           = "aws-eu-central-1-frankfurt"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_eu_north_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.eu_north_1 }
  anchor_id           = "aws-eu-north-1-stockholm"
  instance_type       = "c6i.large"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_eu_south_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.eu_south_1 }
  anchor_id           = "aws-eu-south-1-milan"
  instance_type       = "c6i.large"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_ap_south_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.ap_south_1 }
  anchor_id           = "aws-ap-south-1-mumbai"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_ap_northeast_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.ap_northeast_1 }
  anchor_id           = "aws-ap-northeast-1-tokyo"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_ap_southeast_2" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.ap_southeast_2 }
  anchor_id           = "aws-ap-southeast-2-sydney"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
}

module "aws_isolated_sa_east_1" {
  source              = "./aws_isolated_region"
  providers           = { aws = aws.sa_east_1 }
  anchor_id           = "aws-sa-east-1-saopaulo"
  ssh_public_key      = var.ssh_public_key
  release_tarball_url = var.release_tarball_url
  allow_ssh           = var.allow_ssh
  lockdown_egress     = var.lockdown_egress
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
      slug           = "sjc-aws"
    }
    "aws-us-west-2-oregon" = {
      ip             = module.aws_isolated_us_west_2.public_ip
      cloud_provider = "aws"
      region         = "us-west-2"
      city           = "Boardman, OR, USA"
      lat            = 45.8399
      lon            = -119.7006
      slug           = "bdo-aws"
    }
    "aws-us-east-1-nvirginia" = {
      ip             = module.aws_isolated_us_east_1.public_ip
      cloud_provider = "aws"
      region         = "us-east-1"
      city           = "Ashburn, VA, USA"
      lat            = 39.0180
      lon            = -77.4590
      slug           = "iad-aws"
    }
    "aws-us-east-2-ohio" = {
      ip             = module.aws_isolated_us_east_2.public_ip
      cloud_provider = "aws"
      region         = "us-east-2"
      city           = "Columbus, OH, USA"
      lat            = 39.9612
      lon            = -82.9988
      slug           = "cmh-aws"
    }
    "aws-ca-central-1-montreal" = {
      ip             = module.aws_isolated_ca_central_1.public_ip
      cloud_provider = "aws"
      region         = "ca-central-1"
      city           = "Montreal, QC, Canada"
      lat            = 45.5017
      lon            = -73.5673
      slug           = "yul-aws"
    }
    "aws-eu-west-1-dublin" = {
      ip             = module.aws_isolated_eu_west_1.public_ip
      cloud_provider = "aws"
      region         = "eu-west-1"
      city           = "Dublin, Ireland"
      lat            = 53.3498
      lon            = -6.2603
      slug           = "dub-aws"
    }
    "aws-eu-west-2-london" = {
      ip             = module.aws_isolated_eu_west_2.public_ip
      cloud_provider = "aws"
      region         = "eu-west-2"
      city           = "London, UK"
      lat            = 51.5074
      lon            = -0.1278
      slug           = "lhr-aws"
    }
    "aws-eu-central-1-frankfurt" = {
      ip             = module.aws_isolated_eu_central_1.public_ip
      cloud_provider = "aws"
      region         = "eu-central-1"
      city           = "Frankfurt, Germany"
      lat            = 50.1167
      lon            = 8.6833
      slug           = "fra-aws"
    }
    "aws-eu-north-1-stockholm" = {
      ip             = module.aws_isolated_eu_north_1.public_ip
      cloud_provider = "aws"
      region         = "eu-north-1"
      city           = "Stockholm, Sweden"
      lat            = 59.3293
      lon            = 18.0686
      slug           = "arn-aws"
    }
    "aws-eu-south-1-milan" = {
      ip             = module.aws_isolated_eu_south_1.public_ip
      cloud_provider = "aws"
      region         = "eu-south-1"
      city           = "Milan, Italy"
      lat            = 45.4642
      lon            = 9.1900
      slug           = "mxp-aws"
    }
    "aws-ap-south-1-mumbai" = {
      ip             = module.aws_isolated_ap_south_1.public_ip
      cloud_provider = "aws"
      region         = "ap-south-1"
      city           = "Mumbai, India"
      lat            = 19.0760
      lon            = 72.8777
      slug           = "bom-aws"
    }
    "aws-ap-northeast-1-tokyo" = {
      ip             = module.aws_isolated_ap_northeast_1.public_ip
      cloud_provider = "aws"
      region         = "ap-northeast-1"
      city           = "Tokyo, Japan"
      lat            = 35.6895
      lon            = 139.6917
      slug           = "nrt-aws"
    }
    "aws-ap-southeast-2-sydney" = {
      ip             = module.aws_isolated_ap_southeast_2.public_ip
      cloud_provider = "aws"
      region         = "ap-southeast-2"
      city           = "Sydney, Australia"
      lat            = -33.8688
      lon            = 151.2093
      slug           = "syd-aws"
    }
    "aws-sa-east-1-saopaulo" = {
      ip             = module.aws_isolated_sa_east_1.public_ip
      cloud_provider = "aws"
      region         = "sa-east-1"
      city           = "São Paulo, Brazil"
      lat            = -23.5505
      lon            = -46.6333
      slug           = "gru-aws"
    }
  }
}
