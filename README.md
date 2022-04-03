# EKS-Fargate Cluster with ALB-Ingress controller

This code creates an EKS cluster from scratch including a brand new VPC and subnets. It also installs the ALB-Ingress controller.

## Requirements

- Terraform 1.15

## Running the code

To deploy the infrastructure run the following:
```bash
cd infra
terraform init
terraform apply
```