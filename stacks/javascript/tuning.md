# JavaScript Security Tuning Guide

## Overview

JavaScript and Node.js applications face unique security challenges due to their dynamic nature, extensive dependency ecosystems, and dual client/server execution contexts. This guide provides stack-specific tuning recommendations for security scanners and common vulnerability patterns.

## Scanner Tuning

### Semgrep

**High-priority rules to enable:**
```yaml
# Add to configs/.semgrep.yml
rules:
  - p/javascript
  - p/nodejs
  - p/security-audit
  - p/owasp-top-ten
```

**Custom rule tuning:**
- **Reduce false positives** for eval detection in build tools (webpack, vite) by excluding config files
- **Tighten** innerHTML detection for frameworks (React, Vue) - most should use framework-safe methods
- **Expand** SQL injection patterns to cover Sequelize, Knex, Prisma ORM usage

**Framework-specific adjustments:**
```yaml
# React: allow dangerouslySetInnerHTML only with DOMPurify
- id: react-xss-dompurify
  pattern: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(...) }}
  severity: INFO

# Express: detect missing helmet middleware
- id: express-missing-helmet
  pattern: |
    app = express()
    ...
    app.listen(...)
  message: "Express app missing helmet security headers"
```

### ESLint Security Plugin

**Adjust rule severity:**
```json
{
  "rules": {
    "security/detect-object-injection": "warn",  // High false positive rate
    "security/detect-non-literal-regexp": "warn", // Often benign in Node.js
    "security/detect-unsafe-regex": "error",     // ReDoS is critical
    "security/detect-eval-with-expression": "error"
  }
}
```

**Suppress false positives:**
```javascript
// eslint-disable-next-line security/detect-object-injection
const value = obj[userControlledKey];  // Only if validated above
```

### Trivy

**JavaScript-specific tuning:**
```yaml
# configs/trivy.yaml
severity:
  - CRITICAL
  - HIGH

# Ignore dev dependencies in production scans
ignore-dev-deps: true

# Adjust severity for JavaScript ecosystem
vulnerability-overrides:
  - id: CVE-2021-23337
    severity: MEDIUM  # lodash prototype pollution - mitigated by framework
```

**Exclude directories:**
```yaml
scan:
  skip-dirs:
    - node_modules
    - dist
    - build
    - coverage
    - .next        # Next.js
    - .nuxt        # Nuxt.js
    - .output      # Nitro/Nuxt
    - .astro       # Astro
```

### npm audit

**Configure audit level:**
```bash
# Fail CI on moderate+ vulnerabilities
npm audit --audit-level=moderate

# Production-only check (ignores devDependencies)
npm audit --production

# Generate detailed report
npm audit --json > audit-report.json
```

**Audit exceptions:**
```json
// package.json
{
  "overrides": {
    "problematic-package": "safe-version"
  }
}
```

## Vulnerability-Specific Guidance

### XSS Prevention

**Client-side frameworks:**
- **React:** Use JSX (auto-escapes), avoid `dangerouslySetInnerHTML`
- **Vue:** Use `{{ }}` interpolation (auto-escapes), avoid `v-html`
- **Angular:** Use `{{ }}` interpolation (auto-escapes), avoid `[innerHTML]`
- **Svelte:** Use `{value}` (auto-escapes), avoid `{@html}`

**Server-side rendering:**
```javascript
// BAD
res.send(`<h1>${req.query.name}</h1>`);

// GOOD
const escapeHtml = require('escape-html');
res.send(`<h1>${escapeHtml(req.query.name)}</h1>`);

// BEST - use template engine with auto-escaping
res.render('template', { name: req.query.name });
```

### Prototype Pollution

**High-risk functions:**
- `Object.assign()` with user input
- `_.merge()`, `_.set()` (lodash/underscore)
- `JSON.parse()` + object merge
- Any recursive merge implementation

**Mitigation strategies:**
```javascript
// Strategy 1: Freeze prototypes (app startup)
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);

// Strategy 2: Use Map instead of objects
const config = new Map();
config.set(userKey, value);  // Cannot pollute prototype

// Strategy 3: Validate keys before assignment
const BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype'];
function safeMerge(target, source) {
  for (let key in source) {
    if (!BLOCKED_KEYS.includes(key)) {
      target[key] = source[key];
    }
  }
}

// Strategy 4: Use schema validation (Zod, Joi, Yup)
const schema = z.object({
  username: z.string(),
  email: z.string().email()
});
const validated = schema.parse(userInput);  // Blocks unknown keys
```

### eval() and Code Injection

**Legitimate use cases (rare):**
- Math expression evaluation → Use `mathjs` or `expr-eval`
- Template rendering → Use `handlebars`, `ejs`, `pug`
- Dynamic requires → Use static imports + mapping

**Dangerous patterns:**
```javascript
// eval variants
eval(code);
Function(code)();
setTimeout(code, 100);      // string argument
setInterval(code, 100);     // string argument
new Function('return ' + code)();

// Indirect eval (still dangerous)
const globalEval = eval;
globalEval(code);
```

### Client-Side Storage

**Security tiers:**

| Storage Type        | Security Level | Use For                  | Avoid For           |
| ------------------- | -------------- | ------------------------ | ------------------- |
| httpOnly Cookie     | High           | Session tokens, auth     | -                   |
| sessionStorage      | Medium         | Temporary UI state       | Tokens, PII         |
| localStorage        | Low            | User preferences, theme  | Anything sensitive  |
| IndexedDB           | Low            | Cached data, offline     | Unencrypted secrets |
| In-memory (closure) | Highest        | Sensitive runtime state  | -                   |

**Token storage best practices:**
```javascript
// BAD - XSS can steal token
localStorage.setItem('token', authToken);

// GOOD - httpOnly cookie (server-side set)
res.cookie('session', token, {
  httpOnly: true,
  secure: true,        // HTTPS only
  sameSite: 'strict',  // CSRF protection
  maxAge: 3600000      // 1 hour
});

// ALTERNATIVE - in-memory with refresh token in httpOnly cookie
let accessToken = null;  // Memory only
function setToken(token) {
  accessToken = token;   // Lost on page refresh (by design)
}
```

### CORS Misconfiguration

**Risk levels:**

| Configuration                        | Risk Level | Notes                              |
| ------------------------------------ | ---------- | ---------------------------------- |
| `Access-Control-Allow-Origin: *`     | CRITICAL   | Never use with credentials         |
| Reflected origin without validation  | HIGH       | Bypasses CORS protection           |
| Static allowlist (wrong)             | MEDIUM     | May include compromised subdomains |
| Dynamic allowlist (validated)        | LOW        | Recommended approach               |
| No CORS headers (default deny)       | SAFE       | Most secure, may break SPAs        |

**Secure configuration:**
```javascript
const ALLOWED_ORIGINS = [
  'https://app.example.com',
  'https://admin.example.com'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```

### Dependency Supply Chain Attacks

**Risk mitigation layers:**

1. **Vetting** (before install):
   - Check npm package score: `npm view <package>`
   - Review GitHub repo: stars, issues, last commit
   - Check maintainers: `npm view <package> maintainers`
   - Use Socket.dev or Snyk Advisor

2. **Integrity** (during install):
   ```bash
   # Lock files prevent version drift
   npm ci  # CI/CD: fails if lock file out of sync

   # Verify package integrity
   npm audit signatures
   ```

3. **Monitoring** (post-install):
   ```bash
   # Automated vulnerability scanning
   npm audit

   # Integrate with CI/CD
   - uses: actions/dependency-review-action@v4
   ```

4. **Isolation** (runtime):
   - Use `--ignore-scripts` to prevent postinstall attacks
   - Run builds in isolated containers
   - Use lockfile + offline mirror for air-gapped deploys

**High-risk patterns:**
- Typosquatting: `loadash` vs `lodash`
- Abandoned packages: last publish > 2 years
- Obfuscated code in dependencies
- Unexpected network requests in install scripts

## Framework-Specific Hardening

### Express

```javascript
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

app.use(helmet());  // Security headers
app.use(express.json({ limit: '10mb' }));  // Body size limit
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));
```

### Next.js

```javascript
// next.config.js
module.exports = {
  headers: async () => [{
    source: '/:path*',
    headers: [
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
    ]
  }]
};
```

### React

```javascript
// CSP meta tag
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self' 'unsafe-inline'" />

// Safe HTML rendering
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
```

## Continuous Monitoring

**Pre-commit hooks:**
```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "npm audit && eslint ."
    }
  }
}
```

**Automated scans:**
- Daily: `npm audit` via cron or CI schedule
- Weekly: Full Trivy + Semgrep scan
- PR-triggered: All scanners + dependency review

## References

- [OWASP Top 10 - JavaScript](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [npm Security Advisories](https://github.com/advisories)
- [Snyk Vulnerability Database](https://security.snyk.io/)
