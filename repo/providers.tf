terraform {
  required_providers {
    github = {
      source = "integrations/github"
      version = ">=5.18.3"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=2.46.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "integrations-infra"
    storage_account_name = "tfprovidertests"
    container_name       = "terraform-provider-keyfactor-tfstate"
    key                  = "terraform.tfstate"
  }
  required_version = ">= 1.0"
}

provider "github" {
  # Configuration options
}

provider "azurerm" {
  features {}
}