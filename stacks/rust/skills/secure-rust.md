---
name: secure-rust
description: Security scanning and hardening workflow for Rust projects
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
context: fork
---

# Secure Rust Skill

Security scanning and hardening workflow for Rust codebases.

## Workflow Steps

### 1. Repository Context

Gather project context:

```bash
# Check for Cargo.toml
ls -la Cargo.toml

# Identify Rust project structure
find . -name "*.rs" -type f | head -20

# Check for existing security tooling
cat .github/workflows/*.yml 2>/dev/null | grep -E "(semgrep|cargo-audit|clippy)"
```

### 2. Unsafe Code Audit

Identify and review `unsafe` blocks:

```bash
# Find all unsafe blocks
rg "unsafe\s*\{" --type rust -A 5

# Count unsafe occurrences
rg "unsafe" --type rust --stats

# Check for raw pointer usage
rg "\*const|\*mut" --type rust -C 3
```

**Critical areas:**
- FFI boundaries
- Raw pointer dereferences
- Memory transmutation
- Uninitialized memory

### 3. Dependency Security

Run cargo-audit to check for known vulnerabilities:

```bash
# Install cargo-audit if not present
cargo install cargo-audit

# Run audit
cargo audit --json > cargo-audit-results.json

# Display vulnerabilities
jq '.vulnerabilities.list[] | {id, package, title, severity}' cargo-audit-results.json

# Check for yanked crates
cargo audit --deny warnings
```

### 4. SAST with Semgrep

Run Semgrep with Rust-specific rules:

```bash
# Using stack config
semgrep --config stacks/rust/configs/.semgrep.yml \
  --config p/rust \
  --json --output semgrep-results.json \
  .

# Filter critical findings
jq '[.results[] | select(.extra.severity == "ERROR")] |
  group_by(.check_id) |
  map({rule: .[0].check_id, count: length, files: [.[].path]})' \
  semgrep-results.json

# Common vulnerabilities to check:
# - SQL injection via format!()
# - Command injection
# - Path traversal
# - Hardcoded secrets
# - Weak cryptography (MD5, SHA1)
# - Unchecked unwrap() calls
```

### 5. Clippy Security Lints

Run Clippy with security-focused lints:

```bash
# Run clippy with all warnings as errors
cargo clippy --all-targets -- -D warnings

# Specific security lints
cargo clippy -- \
  -W clippy::unwrap_used \
  -W clippy::expect_used \
  -W clippy::panic \
  -W clippy::integer_arithmetic \
  -W clippy::cast_possible_truncation \
  -W clippy::cast_sign_loss

# Check for integer overflow risks
rg "checked_add|checked_sub|checked_mul|saturating" --type rust --stats
```

### 6. SCA with Trivy

Scan dependencies for vulnerabilities:

```bash
# Scan Cargo.lock
trivy fs --config stacks/rust/configs/trivy.yaml \
  --format json --output trivy-results.json \
  Cargo.lock

# Filter high/critical
jq '[.Results[]?.Vulnerabilities[]? |
  select(.Severity == "CRITICAL" or .Severity == "HIGH")] |
  group_by(.PkgName) |
  map({package: .[0].PkgName, count: length, cves: [.[].VulnerabilityID]})' \
  trivy-results.json
```

### 7. Secret Detection

Scan for hardcoded secrets:

```bash
# Run gitleaks
gitleaks detect --source . \
  --report-format json \
  --report-path gitleaks-results.json \
  --no-git

# Check for common patterns
rg -i "password|secret|token|api_key" --type rust -C 2

# Environment variable usage audit
rg "env::var|std::env" --type rust
```

### 8. Supply Chain Analysis

Review dependency tree for risks:

```bash
# Generate dependency tree
cargo tree --depth 3

# Check for duplicate dependencies
cargo tree --duplicates

# Audit build dependencies
cargo tree --edges build

# Review dependency sources
grep -E "git|path" Cargo.toml
```

### 9. Generate Security Report

Aggregate findings:

```bash
# Create consolidated report
jq -n \
  --slurpfile semgrep semgrep-results.json \
  --slurpfile cargo_audit cargo-audit-results.json \
  --slurpfile trivy trivy-results.json \
  '{
    timestamp: now | todate,
    stack: "rust",
    summary: {
      sast_findings: ($semgrep[0].results | length),
      vulnerabilities: $cargo_audit[0].vulnerabilities.count,
      sca_findings: ([$trivy[0].Results[]?.Vulnerabilities[]?] | length)
    },
    scans: {
      semgrep: $semgrep[0],
      cargo_audit: $cargo_audit[0],
      trivy: $trivy[0]
    }
  }' > security-report.json

# Display summary
jq '.summary' security-report.json
```

## Remediation Guidance

### High Priority

1. **Unsafe code**: Minimize unsafe blocks, document safety invariants
2. **Known CVEs**: Update vulnerable dependencies immediately
3. **Secrets**: Move to environment variables or secret management
4. **SQL injection**: Use parameterized queries with sqlx or diesel

### Medium Priority

1. **Unchecked unwrap()**: Replace with proper error handling
2. **Integer overflow**: Use checked/saturating arithmetic
3. **Path traversal**: Canonicalize and validate paths
4. **Weak crypto**: Migrate to modern algorithms (SHA-256+)

### Security Best Practices

- Enable `overflow-checks = true` in release profile
- Use `#[deny(unsafe_code)]` where possible
- Pin dependency versions for reproducible builds
- Regular `cargo update` + `cargo audit` cycles
- Review all FFI boundaries for memory safety
- Use `cargo-geiger` to measure unsafe usage

## Integration

To integrate into CI/CD:

```bash
# Copy pipeline templates
cp stacks/rust/pipelines/github-actions/security.yml .github/workflows/
# OR
cp stacks/rust/pipelines/concourse/pipeline.yml ci/

# Install pre-commit hooks
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/bash
cargo clippy -- -D warnings
cargo audit
EOF
chmod +x .git/hooks/pre-commit
```

## References

- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [RustSec Advisory Database](https://rustsec.org/)
- [Cargo Audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
- [OWASP Top 10](https://owasp.org/Top10/)
