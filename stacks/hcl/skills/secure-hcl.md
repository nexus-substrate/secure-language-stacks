# Secure HCL/Terraform Development - nexus-agents Skill

**Skill ID:** `secure-hcl`
**Category:** Security Engineering
**Language Stack:** HCL (Terraform, OpenTofu, Terragrunt)

## Purpose

Guide secure infrastructure-as-code development with Terraform/HCL, prevent cloud misconfigurations, enforce encryption at rest and in transit, implement least privilege IAM policies, and protect state files and secrets.

## Core Security Principles

### 1. State File Protection (CWE-311)

**ALWAYS secure Terraform state files - they contain sensitive data:**

```hcl
# ❌ DANGEROUS - Local state file (unencrypted, in git)
# Default behavior without backend configuration

# ✅ SECURE - Remote backend with encryption
terraform {
  backend "s3" {
    bucket         = "terraform-state-prod"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true              # Encrypt at rest with AWS-managed keys
    kms_key_id     = "arn:aws:kms:..."  # Or use customer-managed KMS key
    dynamodb_table = "terraform-locks"  # State locking
    versioning     = true               # State versioning for rollback
  }
}

# ✅ SECURE - Terraform Cloud with encrypted state
terraform {
  cloud {
    organization = "my-org"
    workspaces {
      name = "production"
    }
  }
}
```

**Why:** State files contain plaintext secrets, resource IDs, IP addresses, and complete infrastructure topology. Local or S3-stored state without encryption exposes this data.

**Additional measures:**
- Never commit `.tfstate` files to version control (add to `.gitignore`)
- Restrict S3 bucket access with IAM policies (least privilege)
- Enable S3 versioning for state history and rollback
- Use DynamoDB state locking to prevent concurrent modifications
- Rotate KMS keys periodically

### 2. Credential Management (CWE-798)

**NEVER hardcode credentials in Terraform configurations:**

```hcl
# ❌ CRITICAL - Hardcoded AWS credentials
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ✅ SECURE - Use AWS credential chain (environment, IAM role, SSO)
provider "aws" {
  region = "us-east-1"
  # Credentials automatically sourced from:
  # 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  # 2. Shared credentials file (~/.aws/credentials)
  # 3. IAM role (EC2 instance profile, ECS task role)
  # 4. AWS SSO
}

# ✅ SECURE - Use assume_role for cross-account access
provider "aws" {
  region = "us-east-1"
  assume_role {
    role_arn     = "arn:aws:iam::123456789012:role/TerraformRole"
    session_name = "terraform-session"
  }
}

# ❌ DANGEROUS - Hardcoded database password
resource "aws_db_instance" "main" {
  password = "SuperSecret123!"
}

# ✅ SECURE - Use random_password + AWS Secrets Manager
resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "db_password" {
  name = "prod/db/password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

resource "aws_db_instance" "main" {
  password = random_password.db_password.result
}
```

**Why:** Hardcoded credentials in HCL files are exposed in version control, state files, logs, and CI/CD pipelines.

### 3. Encryption at Rest (CWE-311)

**ALWAYS enable encryption for data at rest:**

```hcl
# ❌ DANGEROUS - Unencrypted RDS instance
resource "aws_db_instance" "main" {
  allocated_storage = 100
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  # storage_encrypted = false (default)
}

# ✅ SECURE - Encrypted RDS instance with KMS
resource "aws_db_instance" "main" {
  allocated_storage   = 100
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds.arn
}

# ❌ DANGEROUS - Unencrypted S3 bucket
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

# ✅ SECURE - Encrypted S3 bucket with default encryption
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# ❌ DANGEROUS - Unencrypted EBS volume
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
}

# ✅ SECURE - Encrypted EBS volume
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}
```

**Why:** Unencrypted storage exposes data to unauthorized access via snapshots, backups, or physical disk compromise.

### 4. Network Exposure (CWE-668, CWE-732)

**Minimize network exposure with security groups and network ACLs:**

```hcl
# ❌ CRITICAL - Security group open to internet
resource "aws_security_group" "app" {
  name = "app-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Wide open!
  }
}

# ✅ SECURE - Restricted security group
resource "aws_security_group" "app" {
  name = "app-sg"

  # Only allow HTTPS from specific IP ranges
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal VPC only
    description = "HTTPS from internal VPC"
  }
}

# ❌ DANGEROUS - Publicly accessible RDS instance
resource "aws_db_instance" "main" {
  publicly_accessible = true
}

# ✅ SECURE - Private RDS instance
resource "aws_db_instance" "main" {
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.db.id]
}

# ❌ DANGEROUS - Public S3 bucket
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# ✅ SECURE - Private S3 bucket with explicit block
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**Why:** Overly permissive network rules expose resources to unauthorized access, data exfiltration, and attack.

### 5. IAM Least Privilege (CWE-732)

**Grant minimal required permissions:**

```hcl
# ❌ CRITICAL - AdministratorAccess policy
resource "aws_iam_role_policy_attachment" "app" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ❌ DANGEROUS - Wildcard resource permissions
resource "aws_iam_policy" "app" {
  name = "app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"  # All S3 buckets!
      }
    ]
  })
}

# ✅ SECURE - Specific resource permissions
resource "aws_iam_policy" "app" {
  name = "app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.data.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.data.arn
      }
    ]
  })
}

# ✅ SECURE - Condition-based permissions
resource "aws_iam_policy" "app" {
  name = "app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceVpce" = aws_vpc_endpoint.s3.id
          }
        }
      }
    ]
  })
}
```

**Why:** Overly permissive IAM policies enable privilege escalation and lateral movement in case of compromise.

### 6. Logging and Monitoring (CWE-778)

**Enable comprehensive logging:**

```hcl
# ❌ MISSING - No CloudTrail logging
# No audit trail for API calls

# ✅ SECURE - CloudTrail with encryption and log validation
resource "aws_cloudtrail" "main" {
  name                          = "organization-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }
  }
}

# ✅ SECURE - VPC Flow Logs
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
}

# ✅ SECURE - S3 bucket logging
resource "aws_s3_bucket_logging" "data" {
  bucket = aws_s3_bucket.data.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}
```

### 7. Resource Tagging and Organization

**Tag all resources for security and compliance:**

```hcl
# Define standard tags
locals {
  common_tags = {
    Environment  = var.environment
    Project      = var.project_name
    ManagedBy    = "Terraform"
    Owner        = var.owner_email
    CostCenter   = var.cost_center
    Compliance   = "PCI-DSS"  # If applicable
    DataClass    = "Sensitive"
  }
}

# Apply to all resources
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t3.medium"

  tags = merge(
    local.common_tags,
    {
      Name = "app-server-${var.environment}"
      Role = "application"
    }
  )
}
```

### 8. Input Validation

**Validate all variable inputs:**

```hcl
# ✅ SECURE - Constrained variable with validation
variable "environment" {
  type        = string
  description = "Deployment environment"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type"

  validation {
    condition     = can(regex("^[tm][0-9]+\\.[a-z]+$", var.instance_type))
    error_message = "Instance type must be valid AWS format (e.g., t3.medium)."
  }
}

variable "cidr_block" {
  type        = string
  description = "VPC CIDR block"

  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "Must be valid IPv4 CIDR notation."
  }
}
```

### 9. Module Security

**Use trusted, verified modules:**

```hcl
# ❌ RISKY - Unverified external module
module "vpc" {
  source = "git::https://github.com/random-user/terraform-vpc.git"
}

# ✅ SECURE - Official Terraform Registry module with version pinning
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"  # Pin to major version

  # Module configuration
}

# ✅ SECURE - Internal module with controlled source
module "security_group" {
  source = "git::https://github.com/my-org/terraform-modules.git//modules/security-group?ref=v1.2.3"
}
```

### 10. Sensitive Output Protection

**Mark sensitive outputs to prevent exposure:**

```hcl
# ❌ DANGEROUS - Sensitive value in output
output "database_password" {
  value = aws_db_instance.main.password
}

# ✅ SECURE - Sensitive output marked
output "database_password" {
  value     = aws_db_instance.main.password
  sensitive = true  # Redacted in logs and console
}

# ✅ BEST - Don't output secrets at all
# Store in AWS Secrets Manager and reference ARN
output "database_password_secret_arn" {
  value = aws_secretsmanager_secret.db_password.arn
}
```

## Security Scanning Integration

### tfsec

Run tfsec for Terraform-specific security checks:

```bash
tfsec . --config-file=stacks/hcl/configs/tfsec.yml --minimum-severity=MEDIUM
```

**Detects:**
- Unencrypted storage (RDS, S3, EBS, EFS)
- Publicly accessible resources
- Overly permissive security groups
- Missing logging configurations
- Weak encryption settings

### Trivy

Run Trivy for IaC misconfiguration scanning:

```bash
trivy config . --config=stacks/hcl/configs/trivy.yaml --severity=CRITICAL,HIGH
```

**Detects:**
- AWS, Azure, GCP misconfigurations
- Kubernetes security issues
- Compliance violations (CIS benchmarks)
- Secrets in configuration

### Semgrep

Run Semgrep for pattern-based security analysis:

```bash
semgrep --config=stacks/hcl/configs/.semgrep.yml --config=p/terraform .
```

**Detects:**
- Hardcoded credentials
- Insecure resource configurations
- IAM policy issues
- Network exposure

### Checkov

Run Checkov for policy-as-code scanning:

```bash
checkov -d . --framework terraform --output sarif
```

**Detects:**
- 1000+ built-in policies
- Custom policy support
- Compliance frameworks (PCI-DSS, HIPAA, SOC2)

## Workflow Integration

1. **Pre-commit:** `terraform fmt`, `terraform validate`, tfsec
2. **CI Pipeline:** Full scan suite (tfsec, Trivy, Semgrep, Checkov) on every PR
3. **Security Gate:** Block merge if CRITICAL/HIGH findings
4. **Scheduled Scan:** Weekly drift detection and security scan
5. **Plan Review:** Automated PR comments with Terraform plan and security findings

## Common Pitfalls

| Pitfall | Impact | Fix |
|---------|--------|-----|
| Local state file | State exposure | Use remote backend with encryption |
| Hardcoded credentials | Credential leakage | Use provider credential chain |
| Unencrypted storage | Data exposure | Enable encryption at rest |
| Public resources | Unauthorized access | Restrict with security groups and ACLs |
| Wildcard IAM | Privilege escalation | Use least privilege policies |
| No logging | No audit trail | Enable CloudTrail, VPC Flow Logs |
| Missing tags | Poor governance | Enforce tagging policy |
| Unvalidated inputs | Misconfigurations | Add variable validation |

## References

- [Terraform Security Best Practices](https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables)
- [AWS Security Best Practices](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [tfsec Documentation](https://aquasecurity.github.io/tfsec/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
