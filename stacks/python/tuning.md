# Python Security Tuning Guide

## Overview

This guide provides security-specific tuning for Python applications, covering common vulnerability patterns, framework-specific hardening, and scanner configuration best practices.

---

## Common Vulnerability Patterns

### 1. Insecure Deserialization (CWE-502)

**Risk:** Arbitrary code execution via pickle, YAML, or other deserialization formats.

**Vulnerable Code:**
```python
import pickle
data = pickle.loads(user_input)  # DANGEROUS

import yaml
config = yaml.load(user_input)  # DANGEROUS
```

**Secure Code:**
```python
import json
data = json.loads(user_input)  # SAFE (JSON only supports primitives)

import yaml
config = yaml.safe_load(user_input)  # SAFE (restricted types)
```

**Semgrep Detection:**
```yaml
rules:
  - id: python-pickle-deserialization
    pattern-either:
      - pattern: pickle.loads($INPUT)
      - pattern: pickle.load($FILE)
```

---

### 2. SQL Injection (CWE-89)

**Risk:** Database compromise via unsanitized SQL queries.

**Vulnerable Code:**
```python
# String concatenation
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# String formatting
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# Django ORM .extra() with user input
User.objects.extra(where=[f"name = '{user_input}'"])
```

**Secure Code:**
```python
# Parameterized queries (raw SQL)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Django ORM (safe by default)
User.objects.filter(id=user_id)

# SQLAlchemy (safe by default)
session.query(User).filter(User.id == user_id)
```

**Semgrep Detection:**
```yaml
rules:
  - id: python-sql-injection
    pattern-either:
      - pattern: cursor.execute($SQL + $VAR)
      - pattern: cursor.execute(f"... {$VAR} ...")
```

---

### 3. Command Injection (CWE-78)

**Risk:** Arbitrary OS command execution.

**Vulnerable Code:**
```python
import os
os.system("ping " + user_input)  # DANGEROUS

import subprocess
subprocess.call("ls " + directory, shell=True)  # DANGEROUS
```

**Secure Code:**
```python
import subprocess
subprocess.run(["ping", user_input], shell=False, timeout=5)  # SAFE

# Or use shlex.quote() if shell=True is necessary
import shlex
subprocess.run(f"ping {shlex.quote(user_input)}", shell=True)
```

**Bandit Detection:**
```python
# B602: subprocess with shell=True
# B605: Starting process with shell=True
# B607: Starting process with partial path
```

---

### 4. Server-Side Template Injection (CWE-94)

**Risk:** Code execution via template engines (Jinja2, Mako).

**Vulnerable Code:**
```python
from jinja2 import Template
template = Template(user_input)  # DANGEROUS
output = template.render(data)

from jinja2 import Environment
env = Environment()
template = env.from_string(user_input)  # DANGEROUS
```

**Secure Code:**
```python
# Use pre-defined templates only
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('templates'))
template = env.get_template('safe_template.html')
output = template.render(user_data=sanitized_input)

# If dynamic rendering is required, use sandboxed environment
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
```

**Semgrep Detection:**
```yaml
rules:
  - id: python-jinja2-ssti
    pattern: jinja2.Template($INPUT).render(...)
```

---

### 5. Server-Side Request Forgery (CWE-918)

**Risk:** Internal network access via unvalidated URLs.

**Vulnerable Code:**
```python
import requests
url = request.args.get('url')
response = requests.get(url)  # DANGEROUS
```

**Secure Code:**
```python
import requests
from urllib.parse import urlparse

def is_safe_url(url):
    parsed = urlparse(url)
    # Block private IP ranges
    if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
        return False
    # Allow only HTTPS
    if parsed.scheme != 'https':
        return False
    # Whitelist domains
    allowed_domains = ['api.example.com', 'cdn.example.com']
    if parsed.hostname not in allowed_domains:
        return False
    return True

url = request.args.get('url')
if is_safe_url(url):
    response = requests.get(url, timeout=5)
```

---

### 6. Insecure Cryptography (CWE-327, CWE-338)

**Risk:** Weak hashing or predictable random values.

**Vulnerable Code:**
```python
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # WEAK

import random
token = random.randint(1000, 9999)  # PREDICTABLE
```

**Secure Code:**
```python
import hashlib
password_hash = hashlib.sha256(password.encode()).hexdigest()  # BETTER

# Or use bcrypt/argon2 for passwords
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

import secrets
token = secrets.token_urlsafe(32)  # CRYPTOGRAPHICALLY SECURE
```

**Bandit Detection:**
```python
# B303: Use of insecure MD5 hash
# B311: Use of random module for security
```

---

## Framework-Specific Hardening

### Django

**Security Middleware (settings.py):**
```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',  # HTTPS enforcement
    'django.middleware.clickjacking.XFrameOptionsMiddleware',  # Clickjacking
    'django.middleware.csrf.CsrfViewMiddleware',  # CSRF protection
]

# Security settings
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
```

**SQL Injection Prevention:**
```python
# SAFE: Django ORM automatically escapes
User.objects.filter(username=user_input)

# UNSAFE: .extra() and .raw() require care
User.objects.extra(where=["username = %s"], params=[user_input])
```

**Template Auto-Escaping:**
```html
<!-- Auto-escaped by default -->
{{ user_input }}

<!-- Mark as safe ONLY if sanitized -->
{{ trusted_html|safe }}
```

---

### Flask

**Security Headers (flask-talisman):**
```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app,
         force_https=True,
         strict_transport_security=True,
         content_security_policy={
             'default-src': "'self'",
             'script-src': "'self'",
             'style-src': "'self'"
         })
```

**CSRF Protection (flask-wtf):**
```python
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
csrf = CSRFProtect(app)
```

**SQL Injection Prevention (SQLAlchemy):**
```python
# SAFE: Parameterized queries
db.session.execute("SELECT * FROM users WHERE id = :id", {'id': user_id})

# SAFE: ORM
User.query.filter_by(username=user_input).first()
```

---

### FastAPI

**Security Dependencies:**
```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/secure")
async def secure_endpoint(token: str = Depends(oauth2_scheme)):
    # Verify token
    pass
```

**Input Validation (Pydantic):**
```python
from pydantic import BaseModel, Field, validator

class UserInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, regex="^[a-zA-Z0-9_]+$")
    email: str

    @validator('email')
    def validate_email(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email')
        return v
```

---

## Scanner Configuration Best Practices

### Semgrep

**Custom Rules for Business Logic:**
```yaml
rules:
  - id: custom-payment-validation
    pattern: process_payment($AMOUNT)
    message: Ensure payment amount validation before processing
    severity: WARNING
    languages: [python]
```

**Exclude Patterns:**
```yaml
# .semgrepignore
tests/
migrations/
venv/
__pycache__/
```

---

### Bandit

**Baseline for False Positives:**
```bash
# Generate baseline
bandit -r . -f json -o bandit-baseline.json

# Future scans compare against baseline
bandit -r . -b bandit-baseline.json
```

**Custom Blacklist:**
```yaml
# bandit.yaml
blacklist:
  calls:
    my_unsafe_function:
      message: "Custom unsafe function detected"
      level: HIGH
```

---

### Trivy

**Ignore Specific CVEs:**
```yaml
# .trivyignore
CVE-2023-12345  # False positive - does not affect our usage
CVE-2023-67890  # Fix pending in upstream
```

**Policy as Code:**
```rego
# policy.rego
package trivy

default ignore = false

ignore {
    input.PkgName == "requests"
    input.VulnerabilityID == "CVE-2023-XXXXX"
}
```

---

## Common CWE Mappings

| CWE      | Description                      | Scanner         | Severity |
| -------- | -------------------------------- | --------------- | -------- |
| CWE-89   | SQL Injection                    | Semgrep, Bandit | CRITICAL |
| CWE-78   | OS Command Injection             | Semgrep, Bandit | CRITICAL |
| CWE-502  | Insecure Deserialization         | Semgrep, Bandit | CRITICAL |
| CWE-94   | Server-Side Template Injection   | Semgrep         | CRITICAL |
| CWE-918  | SSRF                             | Semgrep         | HIGH     |
| CWE-327  | Weak Cryptography                | Bandit          | MEDIUM   |
| CWE-338  | Insecure Random                  | Bandit          | MEDIUM   |
| CWE-798  | Hardcoded Secrets                | Gitleaks        | HIGH     |
| CWE-22   | Path Traversal                   | Semgrep, Bandit | HIGH     |
| CWE-601  | Open Redirect                    | Semgrep         | MEDIUM   |
| CWE-295  | Improper Certificate Validation  | Bandit          | HIGH     |
| CWE-117  | Log Injection                    | Semgrep         | MEDIUM   |
| CWE-611  | XML External Entity (XXE)        | Semgrep         | HIGH     |
| CWE-798  | Use of Hard-coded Credentials    | Gitleaks        | HIGH     |
| CWE-1004 | Sensitive Cookie Without HttpOnly| Semgrep         | MEDIUM   |

---

## Continuous Improvement

### Metrics to Track

1. **Mean Time to Remediate (MTTR)** per severity
2. **False Positive Rate** per scanner
3. **Coverage**: % of code scanned
4. **Vulnerability Density**: findings per KLOC
5. **Trend**: new vs. fixed vulnerabilities over time

### Regular Reviews

- **Weekly**: Triage new findings
- **Monthly**: Update scanner rules and configurations
- **Quarterly**: Audit baseline exceptions and whitelist
- **Annually**: Review and update security policies

---

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Semgrep Python Rules](https://semgrep.dev/r?lang=python)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
