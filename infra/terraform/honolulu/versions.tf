terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.21"
    }
  }
}

provider "aws" {
  region = var.aws_parent_region
}

# Set VULTR_API_KEY in environment (existing operator account only — never commit secrets!).
# When enable_vultr_hnl = false, zero Vultr data sources or resources are created; the sentinel avoids an interactive prompt.
provider "vultr" {
  api_key = var.enable_vultr_hnl ? null : "disabled-when-enable-vultr-hnl-is-false"
}
