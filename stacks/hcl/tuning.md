# HCL/Terraform Security Tuning Guide

## Overview

Infrastructure-as-Code (IaC) with Terraform introduces unique security challenges. Misconfigurations can expose entire cloud environments to attack. This guide covers advanced security hardening for HCL/Terraform.

## Critical Security Vectors

### 1. State File Compromise (CWE-311, CWE-922)

**Attack Surface:**
- Plaintext secrets in state files
- Unencrypted remote state storage
- State file exposure via version control
- State file access via S3 bucket compromise
- Lock table compromise (DynamoDB)

**Hardening:**

```hcl
# Backend with maximum security
terraform {
  required_version = ">= 1.5"

  backend "s3" {
    # State storage
    bucket         = "terraform-state-${var.org}-${var.env}"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"

    # Encryption at rest
    encrypt    = true
    kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/uuid"

    # Access control
    acl                 = "private"
    workspace_key_prefix = "workspaces"

    # State locking
    dynamodb_table = "terraform-state-locks"

    # Additional security
    skip_credentials_validation = false
    skip_metadata_api_check     = false
    force_path_style            = false
  }
}

# S3 bucket security
resource "aws_s3_bucket" "terraform_state" {
  bucket = "terraform-state-${var.org}-${var.env}"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny unencrypted uploads
resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.terraform_state.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# DynamoDB lock table with encryption
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-state-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform_state.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

# KMS key with rotation
resource "aws_kms_key" "terraform_state" {
  description             = "Terraform state encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Terraform to use the key"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.terraform.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}
```

**Detection Tuning:**
- Gitleaks: Scan for `.tfstate` in commits
- Manual audit: Check S3 bucket encryption, versioning, access logs
- CI check: Fail if backend not configured or uses local state

### 2. Credential Exposure (CWE-798)

**Attack Surface:**
- Hardcoded provider credentials
- Secrets in variable files (`.tfvars`)
- Credentials in outputs
- Environment variable leakage in CI/CD

**Hardening:**

```hcl
# Provider authentication via IAM role (best practice)
provider "aws" {
  region = var.aws_region

  # No credentials here - use:
  # - EC2 instance profile
  # - ECS task role
  # - GitHub OIDC
  # - AWS SSO

  assume_role {
    role_arn     = var.terraform_role_arn
    session_name = "terraform-${var.environment}"
    external_id  = var.external_id
  }

  default_tags {
    tags = local.common_tags
  }
}

# Secrets management pattern
# NEVER: password = "hardcoded"
# ALWAYS: Generate + store in secret manager

resource "random_password" "db_master_password" {
  length  = 40
  special = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "db_master_password" {
  name_prefix             = "${var.project}-db-master-password-"
  recovery_window_in_days = 30
  kms_key_id              = aws_kms_key.secrets.id
}

resource "aws_secretsmanager_secret_version" "db_master_password" {
  secret_id     = aws_secretsmanager_secret.db_master_password.id
  secret_string = random_password.db_master_password.result
}

# Reference secret in RDS
resource "aws_db_instance" "main" {
  username = "admin"
  password = random_password.db_master_password.result

  # Store connection string in Secrets Manager
  depends_on = [aws_secretsmanager_secret_version.db_master_password]
}

# Sensitive outputs
output "db_password_secret_arn" {
  description = "ARN of the secret containing the database password"
  value       = aws_secretsmanager_secret.db_master_password.arn
}

# NEVER output the actual password
# ❌ output "db_password" { value = aws_db_instance.main.password }
```

**CI/CD Integration:**

```yaml
# GitHub Actions with OIDC (no long-lived credentials)
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
    role-session-name: github-actions-terraform
    aws-region: us-east-1

- name: Terraform Apply
  run: terraform apply -auto-approve
  env:
    # No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY
    TF_VAR_environment: production
```

**Detection Tuning:**
- Gitleaks: Detect AWS keys, passwords, tokens in HCL files
- Semgrep rule: `terraform-hardcoded-aws-credentials`
- Pre-commit hook: Block `.tfvars` with credential patterns

### 3. IAM Privilege Escalation (CWE-269, CWE-732)

**Attack Surface:**
- Wildcard resource permissions (`Resource: "*"`)
- Overly permissive actions (`Action: "*"`)
- Trust policies allowing `sts:AssumeRole` from any principal
- Missing condition constraints

**Hardening:**

```hcl
# BAD: Overly permissive policy
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# GOOD: Least privilege with conditions
resource "aws_iam_policy" "s3_readonly" {
  name        = "S3ReadOnlySpecificBucket"
  description = "Read-only access to specific S3 bucket with MFA and IP restrictions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = aws_s3_bucket.data.arn
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      },
      {
        Sid    = "ReadObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringEquals = {
            "s3:ExistingObjectTag/Sensitivity" = "public"
          }
        }
      }
    ]
  })
}

# Trust policy with constraints
resource "aws_iam_role" "cross_account" {
  name = "CrossAccountRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.trusted_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
          IpAddress = {
            "aws:SourceIp" = var.trusted_ip_ranges
          }
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}

# Permission boundary to limit maximum permissions
resource "aws_iam_role" "constrained" {
  name                 = "ConstrainedRole"
  permissions_boundary = aws_iam_policy.permission_boundary.arn

  assume_role_policy = "..."
}

resource "aws_iam_policy" "permission_boundary" {
  name = "PermissionBoundary"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyPrivilegeEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateRole",
          "iam:PutRolePolicy",
          "iam:PutUserPolicy",
          "iam:AttachRolePolicy",
          "iam:AttachUserPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}
```

**Detection Tuning:**
- Semgrep rules: `terraform-iam-wildcard-resource`, `terraform-iam-admin-policy`
- tfsec: `aws-iam-no-policy-wildcards`
- Custom policy: Deny IAM policy attachments for `AdministratorAccess`, `PowerUserAccess`

### 4. Network Misconfiguration (CWE-284, CWE-668)

**Attack Surface:**
- Security groups allowing 0.0.0.0/0 ingress
- Publicly accessible databases (RDS, Redshift, DynamoDB)
- S3 buckets with public ACLs
- Missing VPC endpoints (data exfiltration via public internet)

**Hardening:**

```hcl
# Defense in depth for RDS
resource "aws_db_instance" "secure" {
  identifier     = "secure-db"
  engine         = "postgres"
  engine_version = "15.4"

  # Network isolation
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.db.id]

  # Encryption
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  # Backup and recovery
  backup_retention_period = 30
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  # Deletion protection
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "secure-db-final-snapshot"

  # Logging
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  # Automatic version upgrades
  auto_minor_version_upgrade = true
}

# Security group with minimal ingress
resource "aws_security_group" "db" {
  name        = "db-sg"
  description = "Database security group"
  vpc_id      = aws_vpc.main.id

  # Only allow from application tier
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
    description     = "PostgreSQL from app tier"
  }

  # No outbound rules needed (managed service)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound (managed service updates)"
  }

  tags = {
    Name = "db-security-group"
  }
}

# VPC endpoint to avoid internet egress
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.region}.s3"
  route_table_ids = [
    aws_route_table.private.id
  ]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })
}
```

**Detection Tuning:**
- tfsec: `aws-ec2-no-public-ingress-sgr`, `aws-rds-no-public-db-access`
- Semgrep: `terraform-security-group-open-ingress`, `terraform-s3-public-read`
- Custom check: Alert on any `0.0.0.0/0` in security groups

### 5. Encryption Misconfiguration (CWE-311)

**Attack Surface:**
- Unencrypted data at rest (S3, EBS, RDS, DynamoDB)
- Unencrypted data in transit (ALB, CloudFront, API Gateway)
- Weak encryption algorithms (SSE-S3 vs SSE-KMS)
- Missing key rotation

**Hardening:**

```hcl
# S3 with mandatory encryption and versioning
resource "aws_s3_bucket" "data" {
  bucket = "sensitive-data-${var.environment}"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true  # Reduce KMS API calls
  }
}

# Deny unencrypted uploads
resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# KMS key with automatic rotation
resource "aws_kms_key" "s3" {
  description             = "S3 encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Purpose = "S3 data encryption"
  }
}

# ALB with TLS 1.2+ only
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Redirect HTTP to HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
```

**Detection Tuning:**
- tfsec: `aws-s3-enable-bucket-encryption`, `aws-rds-encrypt-instance-storage-data`
- Trivy: Check for unencrypted resources
- Compliance: CIS AWS Foundations Benchmark 2.1.1 (S3 encryption)

## Scanner Configuration

### tfsec Severity Tuning

```yaml
pass_threshold:
  critical: 0  # Zero tolerance for critical issues
  high: 0      # Zero tolerance for high issues
  medium: 5    # Allow up to 5 medium issues (with justification)
  low: 10      # Allow up to 10 low issues

severity_overrides:
  aws-s3-enable-versioning: MEDIUM  # Versioning required for stateful data
  aws-ec2-no-public-ip-subnet: HIGH  # Public subnets are dangerous
  aws-iam-no-policy-wildcards: CRITICAL  # Wildcard permissions = privilege escalation
```

### Trivy Custom Policies

```rego
# custom-checks/deny-public-rds.rego
package user.terraform.deny_public_rds

deny[msg] {
  resource := input.resource.aws_db_instance[name]
  resource.publicly_accessible == true
  msg := sprintf("RDS instance '%s' is publicly accessible", [name])
}
```

## Continuous Monitoring

1. **Pre-commit:** `terraform fmt`, `terraform validate`, tfsec (fast checks)
2. **PR:** Full scan suite with SARIF upload to GitHub Security
3. **Drift Detection:** Daily `terraform plan` to detect out-of-band changes
4. **Compliance Scan:** Weekly CIS benchmark check via Prowler or AWS Security Hub
5. **State Audit:** Monthly review of state file access logs

## References

- [Terraform Security Best Practices](https://developer.hashicorp.com/terraform/tutorials/security)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [NIST SP 800-53 Cloud Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
