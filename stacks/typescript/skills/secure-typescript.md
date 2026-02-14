---
name: secure-typescript
description: |
  Security scanning guidance for TypeScript/Node.js projects.
  Triggers on "secure typescript", "typescript security", "scan typescript".
allowed-tools: Read, Grep, Glob, Bash
context: fork
---

# Secure TypeScript Skill

This skill provides comprehensive security scanning guidance for TypeScript and Node.js projects.

## Trigger Phrases

- "secure typescript"
- "typescript security"
- "scan typescript"
- "typescript security scan"
- "node.js security"

## Security Scanning Workflow

### 1. Initial Assessment

First, identify the project structure:

```bash
# Check for package manager
ls -la | grep -E "package-lock.json|pnpm-lock.yaml|yarn.lock"

# Identify framework
cat package.json | grep -E "express|nestjs|next|fastify|hono"

# Check existing security tooling
cat package.json | grep -E "eslint-plugin-security|semgrep|trivy"
```

### 2. Install Security Scanners

#### Semgrep (SAST)

```bash
# Install Semgrep (via pip or Docker)
pip install semgrep
# OR use Docker
docker pull returntocorp/semgrep
```

Configure Semgrep with TypeScript-specific rules:

```bash
# Create .semgrep.yml in project root
cp stacks/typescript/configs/.semgrep.yml .semgrep.yml

# Run Semgrep scan
semgrep scan \
  --config p/typescript \
  --config p/nodejs \
  --config .semgrep.yml \
  --sarif \
  --output semgrep-results.sarif \
  .
```

#### ESLint Security Plugin

```bash
# Install ESLint with security plugin
npm install --save-dev eslint eslint-plugin-security

# Create or update .eslintrc.json
cat > .eslintrc.json <<'EOF'
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"],
  "rules": {
    "security/detect-eval-with-expression": "error",
    "security/detect-non-literal-fs-filename": "warn",
    "security/detect-non-literal-regexp": "warn",
    "security/detect-unsafe-regex": "error",
    "security/detect-pseudoRandomBytes": "error"
  }
}
EOF

# Run ESLint security scan
npx eslint --ext .ts,.js .
```

#### Trivy (SCA - Software Composition Analysis)

```bash
# Install Trivy
# macOS: brew install trivy
# Linux: see https://aquasecurity.github.io/trivy/latest/getting-started/installation/

# Create trivy config
cp stacks/typescript/configs/trivy.yaml trivy.yaml

# Scan dependencies
trivy fs \
  --config trivy.yaml \
  --format sarif \
  --output trivy-results.sarif \
  .
```

#### NPM Audit

```bash
# Run npm audit (built-in)
npm audit --json > npm-audit-results.json

# Check for high/critical vulnerabilities
npm audit --audit-level=high

# Auto-fix where possible
npm audit fix
```

#### Gitleaks (Secret Scanning)

```bash
# Install Gitleaks
# macOS: brew install gitleaks
# Linux: see https://github.com/gitleaks/gitleaks

# Scan for secrets
gitleaks detect \
  --config ../shared/configs/gitleaks.toml \
  --report-format sarif \
  --report-path gitleaks-results.sarif \
  --verbose \
  .
```

### 3. Common TypeScript Vulnerabilities to Check

#### Prototype Pollution

Search for vulnerable patterns:

```bash
# Find potential prototype pollution
grep -rn "__proto__" src/
grep -rn "\.prototype" src/
grep -rn "Object.assign" src/
```

**Mitigation:**
- Use `Object.create(null)` for dictionaries
- Validate object keys before assignment
- Use Map/Set instead of plain objects
- Enable `--frozen-intrinsics` in production

#### Regular Expression Denial of Service (ReDoS)

```bash
# Find complex regex patterns
grep -rn "new RegExp" src/
grep -rn "/.*\*.*\*" src/
```

**Mitigation:**
- Test regex with tools like https://devina.io/redos-checker
- Set regex execution timeouts
- Avoid nested quantifiers: `(a+)+`, `(a*)*`
- Use possessive quantifiers where supported

#### Command Injection

```bash
# Find shell execution
grep -rn "exec\|spawn\|execSync\|spawnSync" src/
```

**Mitigation:**
- Use `execFile` or `spawnFile` instead of `exec`/`spawn`
- Pass arguments as array, not concatenated strings
- Validate and sanitize all user input
- Use allowlists for permitted commands

#### Path Traversal

```bash
# Find file system operations
grep -rn "fs.readFile\|fs.writeFile\|fs.createReadStream" src/
```

**Mitigation:**
- Validate file paths against allowlist
- Use `path.resolve()` and check result is within allowed directory
- Never trust user-supplied file paths
- Use `path.normalize()` to remove `../` sequences

#### SQL Injection

```bash
# Find potential SQL injection
grep -rn "query\|execute" src/ | grep -E "\`.*\$\{|\+.*\+"
```

**Mitigation:**
- Always use parameterized queries
- Use ORM/query builders (TypeORM, Prisma, Knex)
- Never concatenate user input into SQL
- Enable prepared statements

#### Cross-Site Scripting (XSS)

```bash
# Find innerHTML/outerHTML usage
grep -rn "\.innerHTML\|\.outerHTML" src/
```

**Mitigation:**
- Use `textContent` instead of `innerHTML`
- Sanitize HTML with libraries like DOMPurify
- Use framework-provided safe rendering (React, Vue, Angular)
- Implement Content Security Policy (CSP)

#### Insecure Deserialization

```bash
# Find JSON parsing of user input
grep -rn "JSON.parse" src/
```

**Mitigation:**
- Validate JSON schema before parsing
- Use libraries like `ajv` or `zod` for validation
- Never deserialize untrusted data without validation
- Consider using safer formats like Protocol Buffers

#### Weak Cryptography

```bash
# Find crypto usage
grep -rn "crypto\|randomBytes\|Math.random" src/
```

**Mitigation:**
- Use `crypto.randomBytes()` not `Math.random()` for security
- Use modern algorithms (AES-256-GCM, not DES/RC4)
- Use bcrypt/argon2 for password hashing, not MD5/SHA1
- Generate keys with proper entropy (256 bits minimum)

### 4. Set Up CI/CD Security Pipeline

#### GitHub Actions

```bash
# Copy the GitHub Actions workflow
mkdir -p .github/workflows
cp stacks/typescript/pipelines/github-actions/security.yml .github/workflows/security.yml
```

#### Concourse CI

```bash
# Copy the Concourse pipeline
mkdir -p ci
cp stacks/typescript/pipelines/concourse/pipeline.yml ci/security-pipeline.yml

# Set the pipeline
fly -t <target> set-pipeline \
  -p typescript-security \
  -c ci/security-pipeline.yml
```

### 5. Dependency Security Best Practices

```bash
# Lock dependencies
npm ci  # Use in CI/CD instead of npm install

# Check for outdated packages with known vulnerabilities
npm outdated

# Use npm-check-updates for safer updates
npx npm-check-updates -u

# Enable package-lock.json and commit it
npm config set package-lock true
```

### 6. Runtime Security

#### Enable Secure Headers (Express Example)

```typescript
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));
```

#### Input Validation

```typescript
import { z } from 'zod';

const UserSchema = z.object({
  username: z.string().min(3).max(20).regex(/^[a-zA-Z0-9_]+$/),
  email: z.string().email(),
  age: z.number().int().min(0).max(150),
});

// Validate user input
try {
  const user = UserSchema.parse(req.body);
  // Safe to use validated data
} catch (error) {
  // Handle validation error
}
```

### 7. Security Checklist

Before deploying:

- [ ] All dependencies scanned with Trivy and npm audit
- [ ] SAST scanning with Semgrep completed
- [ ] ESLint security plugin enabled and passing
- [ ] No secrets committed (Gitleaks scan clean)
- [ ] Input validation implemented for all user inputs
- [ ] Parameterized queries used for all database access
- [ ] Secure headers configured (Helmet.js or equivalent)
- [ ] HTTPS enforced in production
- [ ] Environment variables used for secrets (not hardcoded)
- [ ] Error messages don't leak sensitive information
- [ ] Rate limiting implemented for APIs
- [ ] CORS configured properly
- [ ] Dependencies locked with package-lock.json/pnpm-lock.yaml

### 8. Continuous Monitoring

```bash
# Set up automated dependency updates (Dependabot, Renovate)
# GitHub: .github/dependabot.yml

# Schedule weekly security scans
# GitHub Actions: see security.yml cron schedule

# Monitor npm advisories
npm audit --audit-level=moderate
```

## Common CWE Coverage

This workflow addresses:

- CWE-22: Path Traversal
- CWE-78: OS Command Injection
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-95: Code Injection (eval)
- CWE-338: Weak PRNG
- CWE-502: Deserialization of Untrusted Data
- CWE-798: Hard-coded Credentials
- CWE-1321: Prototype Pollution
- CWE-1333: ReDoS

## References

- OWASP Top 10 2021: https://owasp.org/www-project-top-ten/
- Node.js Security Best Practices: https://nodejs.org/en/docs/guides/security/
- Semgrep Rules: https://semgrep.dev/explore
- NPM Security: https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities
