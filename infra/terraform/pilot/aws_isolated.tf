# =============================================================================
# ISOLATED AWS NITRO ENCLAVE FLEET (27 Regions — Dedicated VPC 10.199.0.0/16 per region)
# Non-debug ARM64 AWS Nitro Enclaves (c6g.large, AL2023 kernel 6.12 + FROM scratch EIF),
# IMDS disabled in lockdown mode, ZERO touch on default VPC!
# Note: AWS me-central-1 / me-south-1 omitted due to AWS RunInstances regional restriction;
# Middle East is covered by aws-il-central-1-telaviv + gcp-me-central1-doha + azure-uaenorth-dubai.
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
# --- 14 Additional Global Perimeter & Standard AWS Regions ---
provider "aws" {
  alias  = "ca_west_1"
  region = "ca-west-1"
}
provider "aws" {
  alias  = "mx_central_1"
  region = "mx-central-1"
}
provider "aws" {
  alias  = "eu_west_3"
  region = "eu-west-3"
}
provider "aws" {
  alias  = "eu_south_2"
  region = "eu-south-2"
}
provider "aws" {
  alias  = "eu_central_2"
  region = "eu-central-2"
}
provider "aws" {
  alias  = "il_central_1"
  region = "il-central-1"
}
provider "aws" {
  alias  = "af_south_1"
  region = "af-south-1"
}
provider "aws" {
  alias  = "ap_east_1"
  region = "ap-east-1"
}
provider "aws" {
  alias  = "ap_northeast_2"
  region = "ap-northeast-2"
}
provider "aws" {
  alias  = "ap_northeast_3"
  region = "ap-northeast-3"
}
provider "aws" {
  alias  = "ap_southeast_1"
  region = "ap-southeast-1"
}
provider "aws" {
  alias  = "ap_southeast_3"
  region = "ap-southeast-3"
}
provider "aws" {
  alias                  = "ap_southeast_6"
  region                 = "ap-southeast-6"
  skip_region_validation = true
}

module "aws_isolated_us_west_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.us_west_1 }
  anchor_id            = "aws-us-west-1-sanjose"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_us_west_2" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.us_west_2 }
  anchor_id            = "aws-us-west-2-oregon"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_us_east_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.us_east_1 }
  anchor_id            = "aws-us-east-1-nvirginia"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_us_east_2" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.us_east_2 }
  anchor_id            = "aws-us-east-2-ohio"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ca_central_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ca_central_1 }
  anchor_id            = "aws-ca-central-1-montreal"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_eu_west_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.eu_west_1 }
  anchor_id            = "aws-eu-west-1-dublin"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_eu_west_2" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.eu_west_2 }
  anchor_id            = "aws-eu-west-2-london"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_eu_central_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.eu_central_1 }
  anchor_id            = "aws-eu-central-1-frankfurt"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_eu_north_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.eu_north_1 }
  anchor_id            = "aws-eu-north-1-stockholm"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_eu_south_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.eu_south_1 }
  anchor_id            = "aws-eu-south-1-milan"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_south_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_south_1 }
  anchor_id            = "aws-ap-south-1-mumbai"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_northeast_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_northeast_1 }
  anchor_id            = "aws-ap-northeast-1-tokyo"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_southeast_2" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_southeast_2 }
  anchor_id            = "aws-ap-southeast-2-sydney"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_sa_east_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.sa_east_1 }
  anchor_id            = "aws-sa-east-1-saopaulo"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

# --- 13 Additional Global Perimeter & Standard AWS Nitro Enclave Regions ---
module "aws_isolated_ca_west_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ca_west_1 }
  anchor_id            = "aws-ca-west-1-calgary"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_mx_central_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.mx_central_1 }
  anchor_id            = "aws-mx-central-1-queretaro"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_eu_west_3" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.eu_west_3 }
  anchor_id            = "aws-eu-west-3-paris"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_eu_south_2" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.eu_south_2 }
  anchor_id            = "aws-eu-south-2-spain"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_eu_central_2" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.eu_central_2 }
  anchor_id            = "aws-eu-central-2-zurich"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_il_central_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.il_central_1 }
  anchor_id            = "aws-il-central-1-telaviv"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_af_south_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.af_south_1 }
  anchor_id            = "aws-af-south-1-capetown"
  enable_nitro_enclave = true
  availability_zone    = "af-south-1b"
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_east_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_east_1 }
  anchor_id            = "aws-ap-east-1-hongkong"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_northeast_2" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_northeast_2 }
  anchor_id            = "aws-ap-northeast-2-seoul"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_northeast_3" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_northeast_3 }
  anchor_id            = "aws-ap-northeast-3-osaka"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_southeast_1" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_southeast_1 }
  anchor_id            = "aws-ap-southeast-1-singapore"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_southeast_3" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_southeast_3 }
  anchor_id            = "aws-ap-southeast-3-jakarta"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

module "aws_isolated_ap_southeast_6" {
  source               = "./aws_isolated_region"
  providers            = { aws = aws.ap_southeast_6 }
  anchor_id            = "aws-ap-southeast-6-auckland"
  enable_nitro_enclave = true
  ssh_public_key       = var.ssh_public_key
  release_tarball_url  = var.release_tarball_url
  allow_ssh            = var.allow_ssh
  lockdown_egress      = var.lockdown_egress
}

locals {
  aws_pilot_outputs = {
    "aws-us-west-1-sanjose" = {
      ip                = module.aws_isolated_us_west_1.public_ip
      instance_id       = module.aws_isolated_us_west_1.instance_id
      security_group_id = module.aws_isolated_us_west_1.security_group_id
      cloud_provider    = "aws"
      region            = "us-west-1"
      city              = "San Jose, CA, USA"
      lat               = 37.3382
      lon               = -121.8863
      slug              = "sjc-aws"
    }
    "aws-us-west-2-oregon" = {
      ip                = module.aws_isolated_us_west_2.public_ip
      instance_id       = module.aws_isolated_us_west_2.instance_id
      security_group_id = module.aws_isolated_us_west_2.security_group_id
      cloud_provider    = "aws"
      region            = "us-west-2"
      city              = "Boardman, OR, USA"
      lat               = 45.8399
      lon               = -119.7006
      slug              = "bdo-aws"
    }
    "aws-us-east-1-nvirginia" = {
      ip                = module.aws_isolated_us_east_1.public_ip
      instance_id       = module.aws_isolated_us_east_1.instance_id
      security_group_id = module.aws_isolated_us_east_1.security_group_id
      cloud_provider    = "aws"
      region            = "us-east-1"
      city              = "Ashburn, VA, USA"
      lat               = 39.0180
      lon               = -77.4590
      slug              = "iad-aws"
    }
    "aws-us-east-2-ohio" = {
      ip                = module.aws_isolated_us_east_2.public_ip
      instance_id       = module.aws_isolated_us_east_2.instance_id
      security_group_id = module.aws_isolated_us_east_2.security_group_id
      cloud_provider    = "aws"
      region            = "us-east-2"
      city              = "Columbus, OH, USA"
      lat               = 39.9612
      lon               = -82.9988
      slug              = "cmh-aws"
    }
    "aws-ca-central-1-montreal" = {
      ip                = module.aws_isolated_ca_central_1.public_ip
      instance_id       = module.aws_isolated_ca_central_1.instance_id
      security_group_id = module.aws_isolated_ca_central_1.security_group_id
      cloud_provider    = "aws"
      region            = "ca-central-1"
      city              = "Montreal, QC, Canada"
      lat               = 45.5017
      lon               = -73.5673
      slug              = "yul-aws"
    }
    "aws-eu-west-1-dublin" = {
      ip                = module.aws_isolated_eu_west_1.public_ip
      instance_id       = module.aws_isolated_eu_west_1.instance_id
      security_group_id = module.aws_isolated_eu_west_1.security_group_id
      cloud_provider    = "aws"
      region            = "eu-west-1"
      city              = "Dublin, Ireland"
      lat               = 53.3498
      lon               = -6.2603
      slug              = "dub-aws"
    }
    "aws-eu-west-2-london" = {
      ip                = module.aws_isolated_eu_west_2.public_ip
      instance_id       = module.aws_isolated_eu_west_2.instance_id
      security_group_id = module.aws_isolated_eu_west_2.security_group_id
      cloud_provider    = "aws"
      region            = "eu-west-2"
      city              = "London, UK"
      lat               = 51.5074
      lon               = -0.1278
      slug              = "lhr-aws"
    }
    "aws-eu-central-1-frankfurt" = {
      ip                = module.aws_isolated_eu_central_1.public_ip
      instance_id       = module.aws_isolated_eu_central_1.instance_id
      security_group_id = module.aws_isolated_eu_central_1.security_group_id
      cloud_provider    = "aws"
      region            = "eu-central-1"
      city              = "Frankfurt, Germany"
      lat               = 50.1167
      lon               = 8.6833
      slug              = "fra-aws"
    }
    "aws-eu-north-1-stockholm" = {
      ip                = module.aws_isolated_eu_north_1.public_ip
      instance_id       = module.aws_isolated_eu_north_1.instance_id
      security_group_id = module.aws_isolated_eu_north_1.security_group_id
      cloud_provider    = "aws"
      region            = "eu-north-1"
      city              = "Stockholm, Sweden"
      lat               = 59.3293
      lon               = 18.0686
      slug              = "arn-aws"
    }
    "aws-eu-south-1-milan" = {
      ip                = module.aws_isolated_eu_south_1.public_ip
      instance_id       = module.aws_isolated_eu_south_1.instance_id
      security_group_id = module.aws_isolated_eu_south_1.security_group_id
      cloud_provider    = "aws"
      region            = "eu-south-1"
      city              = "Milan, Italy"
      lat               = 45.4642
      lon               = 9.1900
      slug              = "mxp-aws"
    }
    "aws-ap-south-1-mumbai" = {
      ip                = module.aws_isolated_ap_south_1.public_ip
      instance_id       = module.aws_isolated_ap_south_1.instance_id
      security_group_id = module.aws_isolated_ap_south_1.security_group_id
      cloud_provider    = "aws"
      region            = "ap-south-1"
      city              = "Mumbai, India"
      lat               = 19.0760
      lon               = 72.8777
      slug              = "bom-aws"
    }
    "aws-ap-northeast-1-tokyo" = {
      ip                = module.aws_isolated_ap_northeast_1.public_ip
      instance_id       = module.aws_isolated_ap_northeast_1.instance_id
      security_group_id = module.aws_isolated_ap_northeast_1.security_group_id
      cloud_provider    = "aws"
      region            = "ap-northeast-1"
      city              = "Tokyo, Japan"
      lat               = 35.6895
      lon               = 139.6917
      slug              = "nrt-aws"
    }
    "aws-ap-southeast-2-sydney" = {
      ip                = module.aws_isolated_ap_southeast_2.public_ip
      instance_id       = module.aws_isolated_ap_southeast_2.instance_id
      security_group_id = module.aws_isolated_ap_southeast_2.security_group_id
      cloud_provider    = "aws"
      region            = "ap-southeast-2"
      city              = "Sydney, Australia"
      lat               = -33.8688
      lon               = 151.2093
      slug              = "syd-aws"
    }
    "aws-sa-east-1-saopaulo" = {
      ip                = module.aws_isolated_sa_east_1.public_ip
      instance_id       = module.aws_isolated_sa_east_1.instance_id
      security_group_id = module.aws_isolated_sa_east_1.security_group_id
      cloud_provider    = "aws"
      region            = "sa-east-1"
      city              = "São Paulo, Brazil"
      lat               = -23.5505
      lon               = -46.6333
      slug              = "gru-aws"
    }
    "aws-ca-west-1-calgary" = {
      ip                = module.aws_isolated_ca_west_1.public_ip
      instance_id       = module.aws_isolated_ca_west_1.instance_id
      security_group_id = module.aws_isolated_ca_west_1.security_group_id
      cloud_provider    = "aws"
      region            = "ca-west-1"
      city              = "Calgary, AB, Canada"
      lat               = 51.0447
      lon               = -114.0719
      slug              = "yyc-aws"
    }
    "aws-mx-central-1-queretaro" = {
      ip                = module.aws_isolated_mx_central_1.public_ip
      instance_id       = module.aws_isolated_mx_central_1.instance_id
      security_group_id = module.aws_isolated_mx_central_1.security_group_id
      cloud_provider    = "aws"
      region            = "mx-central-1"
      city              = "Querétaro, Mexico"
      lat               = 20.5888
      lon               = -100.3899
      slug              = "qro-aws"
    }
    "aws-eu-west-3-paris" = {
      ip                = module.aws_isolated_eu_west_3.public_ip
      instance_id       = module.aws_isolated_eu_west_3.instance_id
      security_group_id = module.aws_isolated_eu_west_3.security_group_id
      cloud_provider    = "aws"
      region            = "eu-west-3"
      city              = "Paris, France"
      lat               = 48.8566
      lon               = 2.3522
      slug              = "cdg-aws"
    }
    "aws-eu-south-2-spain" = {
      ip                = module.aws_isolated_eu_south_2.public_ip
      instance_id       = module.aws_isolated_eu_south_2.instance_id
      security_group_id = module.aws_isolated_eu_south_2.security_group_id
      cloud_provider    = "aws"
      region            = "eu-south-2"
      city              = "Zaragoza, Spain"
      lat               = 41.6488
      lon               = -0.8891
      slug              = "zaz-aws"
    }
    "aws-eu-central-2-zurich" = {
      ip                = module.aws_isolated_eu_central_2.public_ip
      instance_id       = module.aws_isolated_eu_central_2.instance_id
      security_group_id = module.aws_isolated_eu_central_2.security_group_id
      cloud_provider    = "aws"
      region            = "eu-central-2"
      city              = "Zurich, Switzerland"
      lat               = 47.3769
      lon               = 8.5417
      slug              = "zrh-aws"
    }
    "aws-il-central-1-telaviv" = {
      ip                = module.aws_isolated_il_central_1.public_ip
      instance_id       = module.aws_isolated_il_central_1.instance_id
      security_group_id = module.aws_isolated_il_central_1.security_group_id
      cloud_provider    = "aws"
      region            = "il-central-1"
      city              = "Tel Aviv, Israel"
      lat               = 32.0853
      lon               = 34.7818
      slug              = "tlv-aws"
    }
    "aws-af-south-1-capetown" = {
      ip                = module.aws_isolated_af_south_1.public_ip
      instance_id       = module.aws_isolated_af_south_1.instance_id
      security_group_id = module.aws_isolated_af_south_1.security_group_id
      cloud_provider    = "aws"
      region            = "af-south-1"
      city              = "Cape Town, South Africa"
      lat               = -33.9249
      lon               = 18.4241
      slug              = "cpt-aws"
    }
    "aws-ap-east-1-hongkong" = {
      ip                = module.aws_isolated_ap_east_1.public_ip
      instance_id       = module.aws_isolated_ap_east_1.instance_id
      security_group_id = module.aws_isolated_ap_east_1.security_group_id
      cloud_provider    = "aws"
      region            = "ap-east-1"
      city              = "Hong Kong"
      lat               = 22.3193
      lon               = 114.1694
      slug              = "hkg-aws"
    }
    "aws-ap-northeast-2-seoul" = {
      ip                = module.aws_isolated_ap_northeast_2.public_ip
      instance_id       = module.aws_isolated_ap_northeast_2.instance_id
      security_group_id = module.aws_isolated_ap_northeast_2.security_group_id
      cloud_provider    = "aws"
      region            = "ap-northeast-2"
      city              = "Seoul, South Korea"
      lat               = 37.5665
      lon               = 126.9780
      slug              = "icn-aws"
    }
    "aws-ap-northeast-3-osaka" = {
      ip                = module.aws_isolated_ap_northeast_3.public_ip
      instance_id       = module.aws_isolated_ap_northeast_3.instance_id
      security_group_id = module.aws_isolated_ap_northeast_3.security_group_id
      cloud_provider    = "aws"
      region            = "ap-northeast-3"
      city              = "Osaka, Japan"
      lat               = 34.6937
      lon               = 135.5023
      slug              = "kix-aws"
    }
    "aws-ap-southeast-1-singapore" = {
      ip                = module.aws_isolated_ap_southeast_1.public_ip
      instance_id       = module.aws_isolated_ap_southeast_1.instance_id
      security_group_id = module.aws_isolated_ap_southeast_1.security_group_id
      cloud_provider    = "aws"
      region            = "ap-southeast-1"
      city              = "Singapore"
      lat               = 1.3521
      lon               = 103.8198
      slug              = "sin-aws"
    }
    "aws-ap-southeast-3-jakarta" = {
      ip                = module.aws_isolated_ap_southeast_3.public_ip
      instance_id       = module.aws_isolated_ap_southeast_3.instance_id
      security_group_id = module.aws_isolated_ap_southeast_3.security_group_id
      cloud_provider    = "aws"
      region            = "ap-southeast-3"
      city              = "Jakarta, Indonesia"
      lat               = -6.2088
      lon               = 106.8456
      slug              = "cgk-aws"
    }
    "aws-ap-southeast-6-auckland" = {
      ip                = module.aws_isolated_ap_southeast_6.public_ip
      instance_id       = module.aws_isolated_ap_southeast_6.instance_id
      security_group_id = module.aws_isolated_ap_southeast_6.security_group_id
      cloud_provider    = "aws"
      region            = "ap-southeast-6"
      city              = "Auckland, New Zealand"
      lat               = -36.8485
      lon               = 174.7633
      slug              = "akl-aws"
    }
  }
}
