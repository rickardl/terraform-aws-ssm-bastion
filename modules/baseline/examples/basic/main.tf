terraform {
  required_version = ">= 0.12"
}

provider "aws" {
  version             = ">= 2.70"
  region              = var.region
  allowed_account_ids = ["641157627364"]
}

module "baseline" {
  source      = "../../"
  name_prefix = var.name_prefix

  tags = {
    environment = "dev"
    terraform   = "True"
  }
}
