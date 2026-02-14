# Go Security Scanner Tuning Guide

## Overview

This document provides guidance for tuning security scanners for Go applications, reducing false positives, and improving detection accuracy.

## Common Go Security Risks

### 1. Race Conditions

**Risk:** Concurrent access to shared memory without synchronization.

**Detection:**
```bash
# Enable race detector during tests
go test -race ./...

# Build with race detector for local testing
go build -race
```

**Mitigation:**
- Use `sync.Mutex` or `sync.RWMutex` for shared state
- Prefer channels for communication between goroutines
- Use `sync.Once` for initialization
- Avoid sharing memory; communicate by passing data

### 2. Unsafe Package Usage

**Risk:** Memory corruption, type safety violations, undefined behavior.

**Detection:** Semgrep and Gosec both flag `unsafe` package usage.

**Mitigation:**
- Avoid `unsafe` unless absolutely necessary
- Document all `unsafe` usage with safety proofs
- Consider alternatives: reflection, code generation, or accepting performance trade-off
- Review all `unsafe` usage in security audits

### 3. SQL Injection

**Risk:** Arbitrary SQL execution via unsanitized user input.

**Detection:**
```go
// Bad: String concatenation
query := "SELECT * FROM users WHERE id = " + userID
db.Query(query)

// Good: Parameterized query
db.Query("SELECT * FROM users WHERE id = ?", userID)
```

**Mitigation:**
- Always use parameterized queries with `database/sql`
- Use prepared statements for repeated queries
- Validate input types before query construction
- Consider using an ORM with built-in escaping

### 4. Command Injection

**Risk:** Arbitrary command execution via shell metacharacters.

**Detection:**
```go
// Bad: Shell execution with user input
exec.Command("sh", "-c", "ls " + userPath)

// Good: Direct command execution with arguments
exec.Command("ls", "-la", userPath)
```

**Mitigation:**
- Never pass user input to shell (`sh -c`, `bash -c`)
- Use direct command execution with separate arguments
- Validate and sanitize all user input
- Use allowlists for permitted commands and arguments

### 5. Cryptographic Misuse

**Risk:** Weak hashing, insecure random number generation, broken encryption.

**Detection:** Gosec rules G401-G505 cover cryptographic issues.

**Common Issues:**
```go
// Bad: Weak hashing algorithms
md5.Sum(data)
sha1.Sum(data)

// Good: Strong hashing
sha256.Sum256(data)
sha3.Sum256(data)

// Bad: Insecure random
rand.Intn(100)  // math/rand

// Good: Cryptographically secure random
randInt, _ := rand.Int(rand.Reader, big.NewInt(100))  // crypto/rand
```

**Mitigation:**
- Use `crypto/rand` not `math/rand` for security
- Use SHA-256, SHA-3, or stronger hashing
- Use established crypto libraries (`golang.org/x/crypto`)
- Avoid implementing custom crypto primitives

### 6. Integer Overflow

**Risk:** Arithmetic overflow leading to incorrect calculations or buffer overruns.

**Detection:**
```go
// Risky: No overflow check
size := userCount * itemSize
buffer := make([]byte, size)

// Safe: Check for overflow
if userCount > 0 && itemSize > math.MaxInt64/userCount {
    return errors.New("overflow")
}
size := userCount * itemSize
```

**Mitigation:**
- Check for overflow before multiplication
- Use `math.MaxInt64`, `math.MaxUint64` constants
- Consider using `math/big` for arbitrary precision
- Validate input ranges

### 7. HTTP Handler Security

**Risk:** Slowloris attacks, request smuggling, header injection.

**Detection:** Gosec and custom Semgrep rules.

**Mitigation:**
```go
// Configure timeouts
server := &http.Server{
    Addr:           ":8080",
    ReadTimeout:    10 * time.Second,
    WriteTimeout:   10 * time.Second,
    MaxHeaderBytes: 1 << 20,  // 1 MB
}

// Implement rate limiting
// Use middleware for request size limits
// Validate and sanitize headers
```

### 8. Path Traversal

**Risk:** Unauthorized file access via relative paths (`../../../etc/passwd`).

**Detection:**
```go
// Risky: Direct file access with user input
file, _ := os.Open(userPath)

// Safe: Validate path
cleanPath := filepath.Clean(userPath)
if !strings.HasPrefix(cleanPath, "/allowed/dir/") {
    return errors.New("invalid path")
}
file, _ := os.Open(cleanPath)
```

**Mitigation:**
- Use `filepath.Clean()` to normalize paths
- Validate paths against allowlist
- Use `filepath.Join()` for path construction
- Never trust user-provided paths

### 9. Error Handling

**Risk:** Ignored errors leading to incorrect program state.

**Detection:** Gosec G104, custom Semgrep rules.

**Mitigation:**
```go
// Bad: Ignored error
file, _ := os.Open(path)

// Good: Handle error
file, err := os.Open(path)
if err != nil {
    return fmt.Errorf("failed to open file: %w", err)
}
defer file.Close()
```

## Scanner-Specific Tuning

### Semgrep

**Reduce False Positives:**
1. Add `pattern-not` clauses for safe patterns
2. Use `metavariable-regex` for stricter matching
3. Exclude test files: `paths.exclude: ["**/*_test.go"]`

**Custom Rules:**
```yaml
rules:
  - id: custom-sql-injection
    pattern: db.Query($FMT, ...)
    pattern-not: db.Query("...", ...)  # Literal string is safe
    message: Use parameterized queries
    severity: ERROR
```

### Gosec

**Configuration:**
```json
{
  "exclude": ["G304"],  // Exclude specific rules
  "severity": "medium",
  "confidence": "medium",
  "exclude-generated": true,
  "tests": false  // Skip test files
}
```

**Common False Positives:**
- G304: File path from user input (validate before use)
- G104: Unhandled errors (add explicit ignore with comment)
- G601: Implicit memory aliasing (fixed in Go 1.22+)

### Trivy

**Configuration:**
```yaml
vulnerability:
  ignore-unfixed: false
  severity: [CRITICAL, HIGH]

golang:
  include-dev: false
  include-test: false
```

**Tuning:**
- Ignore unfixed vulnerabilities if no patch available
- Focus on CRITICAL and HIGH severity
- Exclude dev dependencies if not deployed

### Govulncheck

**Usage:**
```bash
# Scan for vulnerabilities in dependencies
govulncheck ./...

# JSON output for CI/CD
govulncheck -json ./... > results.json
```

**Tuning:**
- Update regularly as new vulnerabilities are published
- Cross-reference with Trivy for comprehensive coverage
- Prioritize vulnerabilities in reachable code paths

## Framework-Specific Tuning

### Gin Framework

```yaml
# Semgrep rule for Gin input validation
- id: gin-missing-input-validation
  pattern: |
    c.ShouldBind($VAR)
    ...
    $X = $VAR.$FIELD
  message: Validate input after binding
  severity: WARNING
```

### Echo Framework

```yaml
# Semgrep rule for Echo parameter validation
- id: echo-param-validation
  pattern: |
    $PARAM := c.Param($NAME)
  message: Validate and sanitize parameters
  severity: WARNING
```

### Database Drivers

```yaml
# Rule for unsafe gorm usage
- id: gorm-raw-sql
  pattern: db.Raw($SQL, ...)
  message: Prefer GORM query builder over raw SQL
  severity: WARNING
```

## CI/CD Integration Best Practices

1. **Fail Fast:** Set critical thresholds to fail builds
2. **Parallel Execution:** Run scanners in parallel
3. **Caching:** Cache Trivy database, Go modules
4. **Incremental Scanning:** Focus on changed files for PRs
5. **Reporting:** Upload results as artifacts, generate badges

## Baseline and Remediation

1. **Establish Baseline:**
   ```bash
   # Run all scanners, save results
   ./scan-all.sh > baseline.json
   ```

2. **Triage Findings:**
   - Categorize: True Positive, False Positive, Won't Fix
   - Document exceptions with justification
   - Create exclusion rules for accepted findings

3. **Remediation Plan:**
   - Fix critical and high-severity issues first
   - Group similar issues for batch fixes
   - Track progress with metrics

4. **Continuous Improvement:**
   - Review scanner output weekly
   - Update rules for new vulnerability patterns
   - Adjust thresholds as baseline improves

## Performance Optimization

1. **Exclude Unnecessary Files:**
   - Vendor directories
   - Test files (if not security-relevant)
   - Generated code

2. **Parallel Execution:**
   - Run SAST, SCA, and secret scanning in parallel
   - Use multiple CPU cores for Trivy

3. **Incremental Scanning:**
   - For PRs, scan only changed files
   - Use git diff to identify scope

4. **Caching:**
   - Cache Go module downloads
   - Cache Trivy vulnerability database
   - Cache Semgrep rules

## References

- [Go Security Best Practices](https://go.dev/doc/security/best-practices)
- [Gosec Rules](https://github.com/securego/gosec#available-rules)
- [Semgrep Go Registry](https://semgrep.dev/p/golang)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Go Vulnerability Database](https://pkg.go.dev/vuln/)
