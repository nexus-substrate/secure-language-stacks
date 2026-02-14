---
name: secure-javascript
description: |
  JavaScript/Node.js security scanning setup and configuration.
  Covers SAST (Semgrep, ESLint), SCA (Trivy, npm audit), secret detection,
  and common JavaScript vulnerabilities (XSS, prototype pollution, injection).
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
context: fork
---

# Secure JavaScript Development

## Overview

This skill provides comprehensive security scanning setup for JavaScript and Node.js applications, covering static analysis, dependency scanning, and common vulnerability detection.

## Security Scanners

### SAST - Semgrep

**Installation:**
```bash
pip install semgrep
# or
brew install semgrep
```

**Configuration:**
- Location: `stacks/javascript/configs/.semgrep.yml`
- Rulesets: `p/javascript`, `p/nodejs`
- Custom rules for eval(), innerHTML, SQL injection, XSS

**Run scan:**
```bash
semgrep --config=p/javascript \
        --config=p/nodejs \
        --config=stacks/javascript/configs/.semgrep.yml \
        --json \
        --output=semgrep-results.json \
        .
```

### SAST - ESLint Security Plugin

**Installation:**
```bash
npm install -g eslint eslint-plugin-security
# or project-local
npm install --save-dev eslint eslint-plugin-security
```

**Configuration:**
- Location: `stacks/javascript/configs/eslint-security.json`
- Detects: eval usage, unsafe regex, timing attacks, object injection

**Run scan:**
```bash
eslint --config stacks/javascript/configs/eslint-security.json \
       --format json \
       --output-file eslint-results.json \
       .
```

### SCA - Trivy

**Installation:**
```bash
# macOS
brew install aquasecurity/trivy/trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

**Configuration:**
- Location: `stacks/javascript/configs/trivy.yaml`
- Scans: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
- Severity: HIGH, CRITICAL

**Run scan:**
```bash
trivy fs --config stacks/javascript/configs/trivy.yaml \
         --format json \
         --output trivy-results.json \
         .
```

### SCA - npm audit

**Built into npm** (no installation needed)

**Run scan:**
```bash
npm audit --json > npm-audit-results.json
npm audit --audit-level=moderate
```

**Fix vulnerabilities:**
```bash
npm audit fix
npm audit fix --force  # may introduce breaking changes
```

### Secret Detection - Gitleaks

**Installation:**
```bash
brew install gitleaks
# or
docker pull zricethezav/gitleaks:latest
```

**Run scan:**
```bash
gitleaks detect --config shared/gitleaks.toml \
                --report-format json \
                --report-path gitleaks-results.json \
                --verbose
```

## Common JavaScript Vulnerabilities

### 1. Cross-Site Scripting (XSS)

**Risk:** User input rendered without sanitization

**Detection patterns:**
- `innerHTML`, `outerHTML` assignments
- `document.write()` usage
- Unescaped template rendering

**Prevention:**
```javascript
// BAD
element.innerHTML = userInput;

// GOOD
element.textContent = userInput;
// or use DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 2. Prototype Pollution

**Risk:** Attacker modifies Object.prototype

**Detection patterns:**
- Unchecked object key access: `obj[key] = value`
- Unsafe `Object.assign()`, merge operations
- JSON parsing without validation

**Prevention:**
```javascript
// BAD
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];
  }
}

// GOOD
function merge(target, source) {
  for (let key in source) {
    if (Object.hasOwnProperty.call(source, key) &&
        !['__proto__', 'constructor', 'prototype'].includes(key)) {
      target[key] = source[key];
    }
  }
}

// BEST - use Object.freeze() on prototypes
Object.freeze(Object.prototype);
```

### 3. Code Injection

**Risk:** eval() and Function() execute arbitrary code

**Detection patterns:**
- `eval()`, `Function()` constructor
- `setTimeout(string)`, `setInterval(string)`

**Prevention:**
```javascript
// BAD
eval(userInput);
new Function(userInput)();

// GOOD
// Use JSON.parse() for data
const data = JSON.parse(userInput);
// Use proper function calls
const allowedFunctions = { add, subtract };
allowedFunctions[userInput]();
```

### 4. SQL Injection

**Risk:** Unsanitized input in SQL queries

**Detection patterns:**
- String concatenation in queries
- Template literals with user input

**Prevention:**
```javascript
// BAD
const query = `SELECT * FROM users WHERE id = ${userId}`;

// GOOD - parameterized queries
const query = 'SELECT * FROM users WHERE id = ?';
db.execute(query, [userId]);
```

### 5. Insecure Randomness

**Risk:** Math.random() predictable for security contexts

**Detection patterns:**
- `Math.random()` for tokens, IDs, crypto

**Prevention:**
```javascript
// BAD
const token = Math.random().toString(36);

// GOOD
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

### 6. Client-Side Storage Risks

**Risk:** Sensitive data in localStorage/sessionStorage

**Prevention:**
- Never store tokens, passwords, PII in localStorage
- Use httpOnly cookies for session tokens
- Encrypt sensitive data before storing
- Clear storage on logout

### 7. CORS Misconfiguration

**Risk:** Overly permissive cross-origin access

**Detection patterns:**
- `Access-Control-Allow-Origin: *`
- Reflected origin without validation

**Prevention:**
```javascript
// BAD
res.header('Access-Control-Allow-Origin', '*');

// GOOD
const allowedOrigins = ['https://example.com'];
if (allowedOrigins.includes(req.headers.origin)) {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
}
```

### 8. Dependency Supply Chain Attacks

**Risks:**
- Malicious npm packages
- Compromised maintainer accounts
- Typosquatting

**Prevention:**
- Run `npm audit` regularly
- Use lock files (package-lock.json, yarn.lock)
- Verify package integrity with `npm ci`
- Review dependencies before adding
- Use Snyk, Dependabot for monitoring
- Pin versions in production

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
      - run: npm audit
      - uses: aquasecurity/trivy-action@master
```

### Concourse

Reference: `stacks/javascript/pipelines/concourse/pipeline.yml`

## Reporting

All scan results are output in JSON format:
- `semgrep-results.json`
- `eslint-results.json`
- `trivy-results.json`
- `npm-audit-results.json`
- `gitleaks-results.json`

## Compliance Mapping

- **OWASP Top 10:** A03 (Injection), A05 (Security Misconfiguration), A06 (Vulnerable Components)
- **CWE Top 25:** CWE-79 (XSS), CWE-89 (SQL Injection), CWE-798 (Hardcoded Credentials)

## References

- [Semgrep JavaScript rules](https://semgrep.dev/p/javascript)
- [ESLint security plugin](https://github.com/eslint-community/eslint-plugin-security)
- [npm audit docs](https://docs.npmjs.com/cli/v9/commands/npm-audit)
- [OWASP NodeGoat](https://github.com/OWASP/NodeGoat)
