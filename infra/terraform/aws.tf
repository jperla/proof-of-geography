# =============================================================================
# Multi-Region AWS Anchor Deployment (8 Regions — EC2 AMD SEV-SNP + Nitro)
# =============================================================================

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
}
provider "aws" {
  alias  = "us_west_1"
  region = "us-west-1"
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
  alias  = "ap_northeast_1"
  region = "ap-northeast-1"
}
provider "aws" {
  alias  = "ap_northeast_2"
  region = "ap-northeast-2"
}
provider "aws" {
  alias  = "ap_southeast_2"
  region = "ap-southeast-2"
}

module "aws_us_east_1" {
  source        = "./modules/aws-anchor"
  count         = var.enable_aws ? 1 : 0
  providers     = { aws = aws.us_east_1 }
  anchor_id     = "aws-us-east-1-nvirginia"
  instance_type = "c6a.large"
  tee_mode      = "sev_snp"
  tcp_port      = var.anchor_tcp_port
  udp_port      = var.anchor_udp_port
  user_data     = local.cloud_init_rendered
}

module "aws_us_west_2" {
  source        = "./modules/aws-anchor"
  count         = var.enable_aws ? 1 : 0
  providers     = { aws = aws.us_west_2 }
  anchor_id     = "aws-us-west-2-oregon"
  instance_type = "c6a.large"
  tee_mode      = "sev_snp"
  tcp_port      = var.anchor_tcp_port
  udp_port      = var.anchor_udp_port
  user_data     = local.cloud_init_rendered
}

module "aws_us_west_1" {
  source        = "./modules/aws-anchor"
  count         = var.enable_aws ? 1 : 0
  providers     = { aws = aws.us_west_1 }
  anchor_id     = "aws-us-west-1-sanjose"
  instance_type = "c6i.xlarge"
  tee_mode      = "nitro"
  tcp_port      = var.anchor_tcp_port
  udp_port      = var.anchor_udp_port
  user_data     = local.cloud_init_rendered
}

module "aws_eu_central_1" {
  source        = "./modules/aws-anchor"
  count         = var.enable_aws ? 1 : 0
  providers     = { aws = aws.eu_central_1 }
  anchor_id     = "aws-eu-central-1-frankfurt"
  instance_type = "c6a.large"
  tee_mode      = "sev_snp"
  tcp_port      = var.anchor_tcp_port
  udp_port      = var.anchor_udp_port
  user_data     = local.cloud_init_rendered
}

module "aws_eu_north_1" {
  source        = "./modules/aws-anchor"
  count         = var.enable_aws ? 1 : 0
  providers     = { aws = aws.eu_north_1 }
  anchor_id     = "aws-eu-north-1-stockholm"
  instance_type = "c6a.large"
  tee_mode      = "sev_snp"
  tcp_port      = var.anchor_tcp_port
  udp_port      = var.anchor_udp_port
  user_data     = local.cloud_init_rendered
}

module "aws_ap_northeast_1" {
  source        = "./modules/aws-anchor"
  count         = var.enable_aws ? 1 : 0
  providers     = { aws = aws.ap_northeast_1 }
  anchor_id     = "aws-ap-northeast-1-tokyo"
  instance_type = "c6a.large"
  tee_mode      = "sev_snp"
  tcp_port      = var.anchor_tcp_port
  udp_port      = var.anchor_udp_port
  user_data     = local.cloud_init_rendered
}

module "aws_ap_northeast_2" {
  source        = "./modules/aws-anchor"
  count         = var.enable_aws ? 1 : 0
  providers     = { aws = aws.ap_northeast_2 }
  anchor_id     = "aws-ap-northeast-2-seoul"
  instance_type = "c6i.xlarge"
  tee_mode      = "nitro"
  tcp_port      = var.anchor_tcp_port
  udp_port      = var.anchor_udp_port
  user_data     = local.cloud_init_rendered
}

module "aws_ap_southeast_2" {
  source        = "./modules/aws-anchor"
  count         = var.enable_aws ? 1 : 0
  providers     = { aws = aws.ap_southeast_2 }
  anchor_id     = "aws-ap-southeast-2-sydney"
  instance_type = "c6a.large"
  tee_mode      = "sev_snp"
  tcp_port      = var.anchor_tcp_port
  udp_port      = var.anchor_udp_port
  user_data     = local.cloud_init_rendered
}

output "aws_anchor_endpoints" {
  description = "Public IPs for all deployed AWS Anchor nodes"
  value = var.enable_aws ? {
    "aws-us-east-1-nvirginia"    = module.aws_us_east_1[0].public_ip
    "aws-us-west-2-oregon"       = module.aws_us_west_2[0].public_ip
    "aws-us-west-1-sanjose"      = module.aws_us_west_1[0].public_ip
    "aws-eu-central-1-frankfurt" = module.aws_eu_central_1[0].public_ip
    "aws-eu-north-1-stockholm"   = module.aws_eu_north_1[0].public_ip
    "aws-ap-northeast-1-tokyo"   = module.aws_ap_northeast_1[0].public_ip
    "aws-ap-northeast-2-seoul"   = module.aws_ap_northeast_2[0].public_ip
    "aws-ap-southeast-2-sydney"  = module.aws_ap_southeast_2[0].public_ip
  } : {}
}
