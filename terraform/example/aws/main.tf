# Minimal AWS example for the policies in this repository.
#
# Resources suffixed `_good` are meant to PASS every policy; resources suffixed
# `_bad` are meant to FAIL on purpose. Never apply this configuration as-is —
# it deliberately creates insecure resources. It exists to be scanned:
#
#   checkov -d terraform/example --external-checks-dir policies/checkov --soft-fail
#   terraform plan -out tfplan && terraform show -json tfplan > plan.json
#   opa eval -d policies/opa -i plan.json "data.terraform"
#
# All names, ranges and identifiers are fictional (Northwind Logistics).

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

locals {
  common_tags = {
    owner       = "platform-team"
    environment = "prod"
  }
}

# --- Object storage ----------------------------------------------------------

# PASS: bucket with a full public access block and an owner tag.
resource "aws_s3_bucket" "invoices_good" {
  bucket = "northwind-invoices-prod"
  tags   = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "invoices_good" {
  bucket = aws_s3_bucket.invoices_good.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FAIL (OPA: block_public_policy must be true; Checkov: no owner tag).
resource "aws_s3_bucket" "logs_bad" {
  bucket = "northwind-logs-dev"
}

resource "aws_s3_bucket_public_access_block" "logs_bad" {
  bucket = aws_s3_bucket.logs_bad.id

  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FAIL (OPA: no public access block, public-read ACL; Checkov: CKV2_CUSTOM_1 and CKV2_CUSTOM_2).
resource "aws_s3_bucket" "exports_bad" {
  bucket        = "northwind-exports-dev"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "exports_bad" {
  bucket = aws_s3_bucket.exports_bad.id
  acl    = "public-read"
}

# --- Block storage and databases ----------------------------------------------

# PASS
resource "aws_ebs_volume" "data_good" {
  availability_zone = "eu-west-1a"
  size              = 100
  type              = "gp3"
  encrypted         = true
  tags              = { owner = "orders-team" }
}

# FAIL (OPA: encrypted = false; Checkov: no owner tag).
resource "aws_ebs_volume" "data_bad" {
  availability_zone = "eu-west-1a"
  size              = 100
  type              = "gp3"
  encrypted         = false
}

# PASS
resource "aws_db_instance" "orders_good" {
  identifier                  = "northwind-orders-prod"
  engine                      = "postgres"
  instance_class              = "db.t4g.medium"
  allocated_storage           = 50
  username                    = "orders_app"
  manage_master_user_password = true
  storage_encrypted           = true
  publicly_accessible         = false
  skip_final_snapshot         = true
  tags                        = { owner = "orders-team" }
}

# FAIL (OPA: storage_encrypted = false; Checkov: no owner tag).
resource "aws_db_instance" "orders_bad" {
  identifier                  = "northwind-orders-dev"
  engine                      = "postgres"
  instance_class              = "db.t4g.micro"
  allocated_storage           = 20
  username                    = "orders_app"
  manage_master_user_password = true
  storage_encrypted           = false
  publicly_accessible         = true
  skip_final_snapshot         = true
}

# --- Network -------------------------------------------------------------------

# PASS: HTTPS from anywhere, SSH only from the corporate range.
resource "aws_security_group" "web_good" {
  name        = "northwind-web-prod"
  description = "HTTPS from anywhere, SSH from the corporate range only"
  tags        = local.common_tags

  ingress {
    description      = "HTTPS"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "SSH from corporate"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FAIL (OPA: SSH from 0.0.0.0/0; Checkov: no owner tag).
resource "aws_security_group" "web_bad" {
  name        = "northwind-web-dev"
  description = "SSH open to the world"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FAIL (OPA: RDP from ::/0).
resource "aws_security_group_rule" "rdp_bad" {
  type              = "ingress"
  security_group_id = aws_security_group.web_bad.id
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"]
  description       = "RDP from anywhere over IPv6"
}

# PASS: HTTPS only.
resource "aws_vpc_security_group_ingress_rule" "https_good" {
  security_group_id = aws_security_group.web_good.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "HTTPS"
}

# FAIL (OPA: every port from everywhere).
resource "aws_vpc_security_group_ingress_rule" "any_bad" {
  security_group_id = aws_security_group.web_bad.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Everything from everywhere"
}
