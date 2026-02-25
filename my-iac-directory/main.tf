# =============================================================
# INTENTIONALLY INSECURE TERRAFORM — FOR TESTING ONLY
# DO NOT USE IN PRODUCTION
# =============================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# --------------------------------------------------------------
# CRITICAL: S3 Bucket with NO encryption and PUBLIC access
# --------------------------------------------------------------
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-totally-insecure-bucket-test-lab"

  tags = {
    Environment = "test-lab"
    Purpose     = "fcs-scan-testing"
  }
}

# Explicitly DISABLE all public access protection
resource "aws_s3_bucket_public_access_block" "vulnerable_bucket_public_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Make the bucket publicly readable via ACL
resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read"
}

# NO server-side encryption configured — data at rest is unencrypted
# NO versioning — no protection against accidental deletion
# NO logging — no audit trail

# --------------------------------------------------------------
# CRITICAL: Security Group allowing ALL inbound traffic
# --------------------------------------------------------------
resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg"
  description = "Intentionally insecure - allows all traffic"

  ingress {
    description = "Allow ALL inbound traffic from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "wide-open-sg"
  }
}

# --------------------------------------------------------------
# CRITICAL: RDS instance with no encryption and public access
# --------------------------------------------------------------
resource "aws_db_instance" "insecure_db" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name              = "insecuredb"
  username             = "admin"
  password             = "SuperSecret123!"  # Hardcoded password!
  skip_final_snapshot  = true

  publicly_accessible    = true   # Database exposed to the internet
  storage_encrypted      = false  # No encryption at rest

  vpc_security_group_ids = [aws_security_group.wide_open.id]

  tags = {
    Environment = "test-lab"
  }
}

# --------------------------------------------------------------
# CRITICAL: EC2 instance with no monitoring and public IP
# --------------------------------------------------------------
resource "aws_instance" "insecure_instance" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
  monitoring                  = false

  vpc_security_group_ids = [aws_security_group.wide_open.id]

  # No encryption on root volume
  root_block_device {
    encrypted = false
  }

  metadata_options {
    http_tokens = "optional"  # IMDSv1 allowed — SSRF risk
  }

  tags = {
    Name = "insecure-instance"
  }
}
