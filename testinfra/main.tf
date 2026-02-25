# ============================================================
# PROVIDER
# ============================================================
provider "aws" {
  region = "us-east-1"
}

# ============================================================
# VARIABLES
# ============================================================
variable "environment" {
  default = "production"
}

variable "db_password" {
  default = "SuperSecret123!"
}

variable "api_key" {
  default = "AKIAIOSFODNN7EXAMPLE"
}

variable "private_key" {
  default = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\naFDrBz9vFqU4yqlSMnDhJYYP9GN+J2TfEBPcMnmF6JvdFGOj2iBKEAQakMr3VfB\n-----END RSA PRIVATE KEY-----"
}

# ============================================================
# S3 BUCKETS (50 insecure buckets)
# ============================================================
resource "aws_s3_bucket" "insecure" {
  count  = 50
  bucket = "insecure-bucket-${count.index}-${var.environment}"

  tags = {
    Environment = var.environment
    Password    = var.db_password
  }
}

resource "aws_s3_bucket_public_access_block" "insecure" {
  count  = 50
  bucket = aws_s3_bucket.insecure[count.index].id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_versioning" "insecure" {
  count  = 50
  bucket = aws_s3_bucket.insecure[count.index].id

  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "none" {
  count  = 25
  bucket = aws_s3_bucket.insecure[count.index].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "disabled" {
  count         = 50
  bucket        = aws_s3_bucket.insecure[count.index].id
  target_bucket = aws_s3_bucket.insecure[0].id
  target_prefix = ""
}

resource "aws_s3_bucket_policy" "public_read" {
  count  = 50
  bucket = aws_s3_bucket.insecure[count.index].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:*"
        Resource  = "${aws_s3_bucket.insecure[count.index].arn}/*"
      }
    ]
  })
}

# ============================================================
# SECURITY GROUPS (40 wide-open groups)
# ============================================================
resource "aws_security_group" "wide_open" {
  count       = 40
  name        = "wide-open-sg-${count.index}"
  description = "Intentionally insecure SG ${count.index}"

  ingress {
    description = "All traffic from anywhere"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "All traffic IPv6"
    from_port        = 0
    to_port          = 65535
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MySQL from anywhere"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "PostgreSQL from anywhere"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MongoDB from anywhere"
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Redis from anywhere"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Elasticsearch from anywhere"
    from_port   = 9200
    to_port     = 9300
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "All UDP"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ============================================================
# VPC & NETWORKING (no flow logs, public subnets)
# ============================================================
resource "aws_vpc" "insecure" {
  count                = 5
  cidr_block           = "10.${count.index}.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "insecure-vpc-${count.index}"
  }
}

resource "aws_subnet" "public" {
  count                   = 20
  vpc_id                  = aws_vpc.insecure[count.index % 5].id
  cidr_block              = "10.${count.index % 5}.${count.index}.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"

  tags = {
    Name = "public-subnet-${count.index}"
  }
}

resource "aws_internet_gateway" "open" {
  count  = 5
  vpc_id = aws_vpc.insecure[count.index].id
}

resource "aws_route_table" "public" {
  count  = 5
  vpc_id = aws_vpc.insecure[count.index].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.open[count.index].id
  }
}

resource "aws_default_security_group" "open" {
  count  = 5
  vpc_id = aws_vpc.insecure[count.index].id

  ingress {
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
}

# ============================================================
# EC2 INSTANCES (30 insecure instances)
# ============================================================
resource "aws_instance" "insecure" {
  count                       = 30
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.public[count.index % 20].id
  vpc_security_group_ids      = [aws_security_group.wide_open[count.index % 40].id]
  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    encrypted   = false
    volume_size = 20
    volume_type = "gp2"
  }

  ebs_block_device {
    device_name = "/dev/sdb"
    encrypted   = false
    volume_size = 100
  }

  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="${var.db_password}"
    export API_KEY="${var.api_key}"
    echo "password=SuperSecret123!" > /etc/app.conf
    curl -H "Authorization: Bearer ${var.api_key}" https://api.example.com
  EOF

  tags = {
    Name     = "insecure-instance-${count.index}"
    Password = var.db_password
  }
}

# ============================================================
# EBS VOLUMES (unencrypted)
# ============================================================
resource "aws_ebs_volume" "unencrypted" {
  count             = 30
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = false

  tags = {
    Name = "unencrypted-vol-${count.index}"
  }
}

# ============================================================
# RDS INSTANCES (20 insecure databases)
# ============================================================
resource "aws_db_instance" "insecure" {
  count                  = 20
  allocated_storage      = 20
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t2.micro"
  identifier             = "insecure-db-${count.index}"
  username               = "admin"
  password               = "password123"
  publicly_accessible    = true
  skip_final_snapshot    = true
  storage_encrypted      = false
  backup_retention_period = 0
  multi_az               = false
  deletion_protection    = false
  auto_minor_version_upgrade = false
  iam_database_authentication_enabled = false

  vpc_security_group_ids = [aws_security_group.wide_open[count.index % 40].id]

  tags = {
    Name = "insecure-db-${count.index}"
  }
}

resource "aws_db_instance" "postgres_insecure" {
  count                  = 10
  allocated_storage      = 20
  engine                 = "postgres"
  engine_version         = "13.4"
  instance_class         = "db.t2.micro"
  identifier             = "insecure-pg-${count.index}"
  username               = "admin"
  password               = "admin123456"
  publicly_accessible    = true
  skip_final_snapshot    = true
  storage_encrypted      = false
  backup_retention_period = 0
  multi_az               = false
  deletion_protection    = false

  vpc_security_group_ids = [aws_security_group.wide_open[count.index % 40].id]
}

# ============================================================
# ELASTICACHE (unencrypted, no auth)
# ============================================================
resource "aws_elasticache_cluster" "insecure" {
  count                = 10
  cluster_id           = "insecure-cache-${count.index}"
  engine               = "redis"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  port                 = 6379
  security_group_ids   = [aws_security_group.wide_open[count.index % 40].id]

  tags = {
    Name = "insecure-cache-${count.index}"
  }
}

resource "aws_elasticache_replication_group" "insecure" {
  count                         = 5
  replication_group_id          = "insecure-rep-${count.index}"
  description                   = "Insecure replication group"
  node_type                     = "cache.t2.micro"
  num_cache_clusters            = 2
  at_rest_encryption_enabled    = false
  transit_encryption_enabled    = false
  automatic_failover_enabled    = false
  security_group_ids            = [aws_security_group.wide_open[count.index % 40].id]
}

# ============================================================
# IAM (overly permissive roles and policies)
# ============================================================
resource "aws_iam_role" "overprivileged" {
  count = 20
  name  = "overprivileged-role-${count.index}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { AWS = "*" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "admin_access" {
  count = 20
  name  = "admin-access-${count.index}"
  role  = aws_iam_role.overprivileged[count.index].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "insecure" {
  count = 15
  name  = "insecure-user-${count.index}"
}

resource "aws_iam_user_policy" "admin" {
  count = 15
  name  = "admin-policy-${count.index}"
  user  = aws_iam_user.insecure[count.index].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_access_key" "insecure" {
  count = 15
  user  = aws_iam_user.insecure[count.index].name
}

resource "aws_iam_group" "admins" {
  name = "everyone-is-admin"
}

resource "aws_iam_group_policy" "admin" {
  name  = "full-admin"
  group = aws_iam_group.admins.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6
  require_lowercase_characters   = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0
  password_reuse_prevention      = 0
}

# ============================================================
# LAMBDA FUNCTIONS (insecure configs)
# ============================================================
resource "aws_lambda_function" "insecure" {
  count         = 20
  filename      = "lambda.zip"
  function_name = "insecure-lambda-${count.index}"
  role          = aws_iam_role.overprivileged[count.index % 20].arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
  timeout       = 900

  environment {
    variables = {
      DB_PASSWORD = "password123"
      API_KEY     = "AKIAIOSFODNN7EXAMPLE"
      SECRET_KEY  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      DB_HOST     = "production-db.example.com"
    }
  }

  tracing_config {
    mode = "PassThrough"
  }
}

resource "aws_lambda_permission" "public" {
  count         = 20
  statement_id  = "AllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.insecure[count.index].function_name
  principal     = "*"
}

# ============================================================
# CLOUDWATCH (missing alarms and log retention)
# ============================================================
resource "aws_cloudwatch_log_group" "no_retention" {
  count             = 20
  name              = "/aws/lambda/insecure-${count.index}"
  retention_in_days = 0
}

# ============================================================
# SNS TOPICS (public access)
# ============================================================
resource "aws_sns_topic" "public" {
  count = 10
  name  = "public-topic-${count.index}"
}

resource "aws_sns_topic_policy" "public" {
  count  = 10
  arn    = aws_sns_topic.public[count.index].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "SNS:*"
        Resource  = aws_sns_topic.public[count.index].arn
      }
    ]
  })
}

# ============================================================
# SQS QUEUES (public access, no encryption)
# ============================================================
resource "aws_sqs_queue" "insecure" {
  count                     = 15
  name                      = "insecure-queue-${count.index}"
  sqs_managed_sse_enabled   = false
  message_retention_seconds = 345600
}

resource "aws_sqs_queue_policy" "public" {
  count     = 15
  queue_url = aws_sqs_queue.insecure[count.index].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "SQS:*"
        Resource  = aws_sqs_queue.insecure[count.index].arn
      }
    ]
  })
}

# ============================================================
# KMS KEYS (overly permissive)
# ============================================================
resource "aws_kms_key" "insecure" {
  count                   = 10
  description             = "Insecure KMS key ${count.index}"
  deletion_window_in_days = 7
  enable_key_rotation     = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

# ============================================================
# ELASTICSEARCH / OPENSEARCH (public, unencrypted)
# ============================================================
resource "aws_elasticsearch_domain" "insecure" {
  count       = 5
  domain_name = "insecure-es-${count.index}"

  cluster_config {
    instance_type  = "t2.small.elasticsearch"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = false
  }

  node_to_node_encryption {
    enabled = false
  }

  domain_endpoint_options {
    enforce_https = false
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "es:*"
        Resource  = "*"
      }
    ]
  })
}

# ============================================================
# DYNAMODB (no encryption, no backups)
# ============================================================
resource "aws_dynamodb_table" "insecure" {
  count        = 15
  name         = "insecure-table-${count.index}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = false
  }
}

# ============================================================
# ELB / ALB (insecure listeners, no access logs)
# ============================================================
resource "aws_lb" "insecure" {
  count              = 10
  name               = "insecure-lb-${count.index}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.wide_open[count.index % 40].id]
  subnets            = [aws_subnet.public[count.index % 20].id, aws_subnet.public[(count.index + 1) % 20].id]

  enable_deletion_protection = false
  drop_invalid_header_fields = false
}

resource "aws_lb_listener" "http" {
  count             = 10
  load_balancer_arn = aws_lb.insecure[count.index].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.insecure[count.index].arn
  }
}

resource "aws_lb_target_group" "insecure" {
  count    = 10
  name     = "insecure-tg-${count.index}"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.insecure[count.index % 5].id
}

# ============================================================
# ECR (mutable tags, no scanning)
# ============================================================
resource "aws_ecr_repository" "insecure" {
  count                = 10
  name                 = "insecure-repo-${count.index}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_ecr_repository_policy" "public" {
  count      = 10
  repository = aws_ecr_repository.insecure[count.index].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "ecr:*"
      }
    ]
  })
}

# ============================================================
# CLOUDTRAIL (disabled or misconfigured)
# ============================================================
resource "aws_cloudtrail" "insecure" {
  count                         = 3
  name                          = "insecure-trail-${count.index}"
  s3_bucket_name                = aws_s3_bucket.insecure[count.index].id
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_logging                = false
  enable_log_file_validation    = false
}

# ============================================================
# SECRETS MANAGER (hardcoded values)
# ============================================================
resource "aws_secretsmanager_secret" "bad" {
  count       = 10
  name        = "hardcoded-secret-${count.index}"
  description = "Secret with password: SuperSecret123!"
}

resource "aws_secretsmanager_secret_version" "bad" {
  count     = 10
  secret_id = aws_secretsmanager_secret.bad[count.index].id
  secret_string = jsonencode({
    username = "admin"
    password = "SuperSecret123!"
    api_key  = "AKIAIOSFODNN7EXAMPLE"
  })
}

# ============================================================
# REDSHIFT (public, unencrypted)
# ============================================================
resource "aws_redshift_cluster" "insecure" {
  count                    = 5
  cluster_identifier       = "insecure-redshift-${count.index}"
  database_name            = "mydb"
  master_username          = "admin"
  master_password          = "Password123!"
  node_type                = "dc2.large"
  cluster_type             = "single-node"
  publicly_accessible      = true
  encrypted                = false
  skip_final_snapshot      = true
  allow_version_upgrade    = false
  automated_snapshot_retention_period = 0

  vpc_security_group_ids = [aws_security_group.wide_open[count.index % 40].id]
}

# ============================================================
# ECS (privileged containers, host networking)
# ============================================================
resource "aws_ecs_task_definition" "insecure" {
  count  = 10
  family = "insecure-task-${count.index}"

  container_definitions = jsonencode([
    {
      name       = "insecure-container-${count.index}"
      image      = "nginx:latest"
      cpu        = 256
      memory     = 512
      essential  = true
      privileged = true
      readonlyRootFilesystem = false

      environment = [
        { name = "DB_PASSWORD", value = "password123" },
        { name = "API_KEY", value = "AKIAIOSFODNN7EXAMPLE" },
        { name = "SECRET", value = "wJalrXUtnFEMI/K7MDENG" }
      ]

      portMappings = [
        {
          containerPort = 80
          hostPort      = 0
          protocol      = "tcp"
        }
      ]

      logConfiguration = null
    }
  ])

  network_mode = "host"
}

# ============================================================
# API GATEWAY (no auth, no logging)
# ============================================================
resource "aws_api_gateway_rest_api" "insecure" {
  count       = 10
  name        = "insecure-api-${count.index}"
  description = "No auth API"

  endpoint_configuration {
    types = ["EDGE"]
  }
}

resource "aws_api_gateway_method" "open" {
  count         = 10
  rest_api_id   = aws_api_gateway_rest_api.insecure[count.index].id
  resource_id   = aws_api_gateway_rest_api.insecure[count.index].root_resource_id
  http_method   = "ANY"
  authorization = "NONE"
}

# ============================================================
# KINESIS (unencrypted streams)
# ============================================================
resource "aws_kinesis_stream" "insecure" {
  count            = 10
  name             = "insecure-stream-${count.index}"
  shard_count      = 1
  retention_period = 24
  encryption_type  = "NONE"
}

# ============================================================
# GLUE (no encryption)
# ============================================================
resource "aws_glue_data_catalog_encryption_settings" "insecure" {
  data_catalog_encryption_settings {
    connection_password_encryption {
      return_connection_password_encrypted = false
    }

    encryption_at_rest {
      catalog_encryption_mode = "DISABLED"
    }
  }
}

resource "aws_glue_security_configuration" "insecure" {
  count = 5
  name  = "insecure-glue-${count.index}"

  encryption_configuration {
    cloudwatch_encryption {
      cloudwatch_encryption_mode = "DISABLED"
    }

    job_bookmarks_encryption {
      job_bookmarks_encryption_mode = "DISABLED"
    }

    s3_encryption {
      s3_encryption_mode = "DISABLED"
    }
  }
}

# ============================================================
# CLOUDFRONT (HTTP only, no WAF)
# ============================================================
resource "aws_cloudfront_distribution" "insecure" {
  count   = 5
  enabled = true

  origin {
    domain_name = aws_s3_bucket.insecure[count.index].bucket_regional_domain_name
    origin_id   = "insecure-origin-${count.index}"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1", "TLSv1.1"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "insecure-origin-${count.index}"
    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = true
      cookies {
        forward = "all"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1"
  }

  logging_config {
    bucket = aws_s3_bucket.insecure[count.index].bucket_domain_name
  }
}

# ============================================================
# ATHENA (unencrypted workgroups)
# ============================================================
resource "aws_athena_workgroup" "insecure" {
  count = 5
  name  = "insecure-workgroup-${count.index}"

  configuration {
    enforce_workgroup_configuration = false
    publish_cloudwatch_metrics_enabled = false

    result_configuration {
      output_location = "s3://${aws_s3_bucket.insecure[count.index].id}/athena-results/"
    }
  }
}

# ============================================================
# DAX (no encryption)
# ============================================================
resource "aws_dax_cluster" "insecure" {
  count                = 3
  cluster_name         = "insecure-dax-${count.index}"
  iam_role_arn         = aws_iam_role.overprivileged[count.index].arn
  node_type            = "dax.t2.small"
  replication_factor   = 1

  server_side_encryption {
    enabled = false
  }
}

# ============================================================
# NEPTUNE (no encryption, public)
# ============================================================
resource "aws_neptune_cluster" "insecure" {
  count                       = 3
  cluster_identifier          = "insecure-neptune-${count.index}"
  engine                      = "neptune"
  storage_encrypted           = false
  skip_final_snapshot         = true
  iam_database_authentication_enabled = false
  deletion_protection         = false

  vpc_security_group_ids = [aws_security_group.wide_open[count.index % 40].id]
}

# ============================================================
# DOCDB (no encryption, weak auth)
# ============================================================
resource "aws_docdb_cluster" "insecure" {
  count                   = 3
  cluster_identifier      = "insecure-docdb-${count.index}"
  master_username         = "admin"
  master_password         = "password123"
  storage_encrypted       = false
  skip_final_snapshot     = true
  deletion_protection     = false
  backup_retention_period = 1

  vpc_security_group_ids = [aws_security_group.wide_open[count.index % 40].id]
}

# ============================================================
# MSK (no encryption)
# ============================================================
resource "aws_msk_cluster" "insecure" {
  count         = 3
  cluster_name  = "insecure-msk-${count.index}"
  kafka_version = "2.8.1"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = [aws_subnet.public[0].id, aws_subnet.public[1].id, aws_subnet.public[2].id]
    security_groups = [aws_security_group.wide_open[count.index % 40].id]

    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS_PLAINTEXT"
      in_cluster    = false
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled = false
      }
      s3_logs {
        enabled = false
      }
    }
  }
}

# ============================================================
# OUTPUTS (leaking sensitive data)
# ============================================================
output "db_password" {
  value = var.db_password
}

output "api_key" {
  value = var.api_key
}

output "private_key" {
  value = var.private_key
}

output "iam_access_keys" {
  value = aws_iam_access_key.insecure[*].secret
}

output "rds_endpoints" {
  value = aws_db_instance.insecure[*].endpoint
}

output "redshift_endpoints" {
  value = aws_redshift_cluster.insecure[*].endpoint
}
