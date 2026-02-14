---
name: secure-go
description: Configure security scanning for Go applications with Semgrep, Gosec, Trivy, and Govulncheck
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
context: fork
---

# Secure Go Scanning Setup

Configure comprehensive security scanning for Go applications using the secure-language-stacks Go stack.

## Pre-Flight Checks

1. Verify Go application structure:
   - Check for `go.mod` and `go.sum` files
   - Identify Go version in `go.mod`
   - Verify build configuration

2. Detect frameworks:
   - Gin, Echo, Fiber, Chi, net/http
   - Database drivers (database/sql, gorm, sqlx)
   - HTTP clients and server implementations

3. Identify existing security tooling:
   - Check for existing gosec configuration
   - Look for Trivy or other SCA tools
   - Review CI/CD pipeline for security steps

## Configuration Steps

1. **Copy Stack Configuration:**
   ```bash
   cp /path/to/secure-language-stacks/stacks/go/configs/.semgrep.yml .semgrep.yml
   cp /path/to/secure-language-stacks/stacks/go/configs/gosec.json gosec.json
   cp /path/to/secure-language-stacks/stacks/go/configs/trivy.yaml trivy.yaml
   ```

2. **Install Security Tools:**
   ```bash
   # Install Gosec
   go install github.com/securego/gosec/v2/cmd/gosec@latest

   # Install Govulncheck
   go install golang.org/x/vuln/cmd/govulncheck@latest

   # Install Semgrep (requires Python)
   pip install semgrep

   # Install Trivy
   wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
   echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
   sudo apt-get update && sudo apt-get install trivy
   ```

3. **Run Initial Scans:**
   ```bash
   # Semgrep SAST
   semgrep --config .semgrep.yml --config p/golang --json --output semgrep-results.json .

   # Gosec SAST
   gosec -conf gosec.json -fmt json -out gosec-results.json ./...

   # Trivy SCA
   trivy fs --config trivy.yaml --format json --output trivy-results.json .

   # Govulncheck
   govulncheck -json ./... > govulncheck-results.json
   ```

4. **Review Results:**
   - Check for critical and high-severity findings
   - Identify false positives
   - Plan remediation for true positives

5. **Integrate into CI/CD:**
   - For GitHub Actions: Copy `pipelines/github-actions/security.yml` to `.github/workflows/`
   - For Concourse: Copy `pipelines/concourse/pipeline.yml` and configure with your repository details
   - Configure required secrets and permissions

## Go-Specific Security Considerations

1. **Race Conditions:**
   - Run `go vet -race` during development
   - Use `sync.Mutex`, `sync.RWMutex`, or channels for synchronization
   - Avoid shared mutable state when possible

2. **SQL Injection:**
   - Always use parameterized queries with `database/sql`
   - Prefer `db.Query("SELECT * FROM users WHERE id = ?", userID)` over string concatenation
   - Use ORM query builders with proper escaping

3. **Command Injection:**
   - Avoid `exec.Command("sh", "-c", userInput)`
   - Use direct command execution: `exec.Command("ls", "-la", safePath)`
   - Validate and sanitize all user input

4. **Unsafe Package:**
   - Minimize use of `unsafe` package
   - Document all `unsafe` usage with safety justification
   - Consider safer alternatives

5. **Cryptography:**
   - Use `crypto/rand` not `math/rand` for security-sensitive operations
   - Prefer SHA-256 or SHA-3 over MD5/SHA-1
   - Use established libraries like `golang.org/x/crypto`

6. **HTTP Security:**
   - Set `ReadTimeout` and `WriteTimeout` on `http.Server`
   - Implement rate limiting and request size limits
   - Use HTTPS with proper TLS configuration

7. **Error Handling:**
   - Never ignore error return values
   - Log errors with sufficient context
   - Avoid exposing sensitive information in error messages

## Tuning Recommendations

1. **Reduce False Positives:**
   - Review and customize Semgrep rules in `.semgrep.yml`
   - Adjust Gosec severity thresholds in `gosec.json`
   - Configure Trivy to ignore unfixed vulnerabilities if needed

2. **Framework-Specific Rules:**
   - Add custom Semgrep rules for Gin/Echo/Fiber patterns
   - Configure gosec to understand framework-specific security controls

3. **Performance Optimization:**
   - Exclude test files and vendor directories from scans
   - Run scans in parallel in CI/CD
   - Cache Trivy database between runs

## Expected Outcomes

- Comprehensive SAST coverage with Semgrep and Gosec
- Dependency vulnerability scanning with Trivy and Govulncheck
- Secret detection with Gitleaks
- Automated CI/CD integration
- Actionable security reports in JSON format

## Troubleshooting

- **High false positive rate:** Tune Semgrep and Gosec rules, add exclusions for test code
- **Slow scans:** Exclude vendor directories, increase concurrency settings
- **Govulncheck failures:** Ensure Go version compatibility, check network access for vulnerability database
- **Missing vulnerabilities:** Update Trivy database, verify scanner coverage
