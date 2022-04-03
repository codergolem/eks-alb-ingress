terraform {
  required_version = "1.1.5"
  required_providers {
    aws = {
      version = "~> 2.0"
    }
    kubernetes = {
      version = "~> 1.10"
    }
    external = {
      version = "~> 1.2"
    }
  }
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
}

provider "aws" {
  region = "us-east-1"
}

provider "external" {}

data "aws_eks_cluster" "cluster" {
  name = aws_eks_cluster.mario-sample.id
}

data "aws_eks_cluster_auth" "cluster" {
  name = aws_eks_cluster.mario-sample.id
}