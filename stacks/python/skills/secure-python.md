---
name: secure-python
description: Set up security scanning for Python projects using Semgrep, Bandit, Trivy, and Gitleaks
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
context: fork
---

# Secure Python Setup Skill

## Objective

Integrate comprehensive security scanning into Python projects using industry-standard tools:
- **SAST**: Semgrep + Bandit
- **SCA**: Trivy + pip-audit
- **Secrets**: Gitleaks
- **DAST**: ZAP (for web frameworks)

## Pre-flight Checklist

1. Identify Python version and framework
2. Detect package manager (pip, poetry, pipenv, uv)
3. Locate dependency files (requirements.txt, Pipfile, poetry.lock, pyproject.toml)
4. Identify CI platform (GitHub Actions, Concourse, GitLab CI)
5. Check for existing security tooling

## Execution Steps

### 1. Environment Detection

```bash
# Detect Python version
python --version || python3 --version

# Detect framework
grep -r "django\|flask\|fastapi\|tornado\|aiohttp" requirements.txt pyproject.toml setup.py 2>/dev/null

# Detect package manager
if [ -f "poetry.lock" ]; then
  echo "Package manager: Poetry"
elif [ -f "Pipfile.lock" ]; then
  echo "Package manager: Pipenv"
elif [ -f "requirements.txt" ]; then
  echo "Package manager: pip"
elif [ -f "uv.lock" ]; then
  echo "Package manager: uv"
fi
```

### 2. Copy Security Configurations

```bash
# From secure-language-stacks repo root
cp stacks/python/configs/.semgrep.yml .semgrep.yml
cp stacks/python/configs/bandit.yaml bandit.yaml
cp stacks/python/configs/trivy.yaml trivy.yaml
cp shared/gitleaks.toml .gitleaks.toml
```

### 3. Install Security Tools (Local)

```bash
# Semgrep
pip install semgrep

# Bandit
pip install bandit[toml]

# Trivy (binary install)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# pip-audit
pip install pip-audit

# Gitleaks (binary install)
curl -sfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz | tar xz -C /usr/local/bin
```

### 4. Run Initial Scans

```bash
# SAST: Semgrep
semgrep --config .semgrep.yml --config p/python --json --output semgrep-results.json .

# SAST: Bandit
bandit -r . -c bandit.yaml -f json -o bandit-results.json

# SCA: Trivy
trivy fs --config trivy.yaml --format json --output trivy-results.json .

# SCA: pip-audit
pip-audit -r requirements.txt --format json --output pip-audit-results.json

# Secrets: Gitleaks
gitleaks detect --config .gitleaks.toml --report-format json --report-path gitleaks-results.json --no-git
```

### 5. Integrate into CI

**GitHub Actions:**
```bash
cp stacks/python/pipelines/github-actions/security.yml .github/workflows/security.yml
```

**Concourse:**
```bash
cp stacks/python/pipelines/concourse/pipeline.yml ci/security-pipeline.yml
```

### 6. Configure Pre-commit Hooks (Optional)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.50.0
    hooks:
      - id: semgrep
        args: ['--config', '.semgrep.yml', '--error']

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-c', 'bandit.yaml']

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

## Framework-Specific Configurations

### Django

```bash
# Add Django-specific Semgrep rules
semgrep --config p/django --json .

# Check for Django security middleware
grep -r "SecurityMiddleware\|XFrameOptionsMiddleware" settings.py
```

### Flask

```bash
# Add Flask-specific Semgrep rules
semgrep --config p/flask --json .

# Check for Flask security headers
grep -r "flask_talisman\|CSP" .
```

### FastAPI

```bash
# Check for security dependencies
grep -E "python-jose|passlib|bcrypt" requirements.txt pyproject.toml
```

## Validation

```bash
# Verify all scanners are working
semgrep --version
bandit --version
trivy --version
pip-audit --version
gitleaks version

# Check for configuration files
ls -la .semgrep.yml bandit.yaml trivy.yaml .gitleaks.toml

# Verify CI pipeline
gh workflow view security.yml 2>/dev/null || echo "GitHub Actions workflow created"
```

## Post-Setup Actions

1. Review scan results and triage findings
2. Create baseline exceptions for false positives
3. Configure CI to fail on high-severity findings
4. Set up SARIF upload for GitHub Security tab
5. Schedule weekly dependency scans
6. Document security baseline in README

## Common Python Security Issues to Monitor

- **CWE-89**: SQL Injection (use parameterized queries)
- **CWE-78**: Command Injection (avoid shell=True)
- **CWE-502**: Insecure Deserialization (never use pickle with untrusted data)
- **CWE-94**: Server-Side Template Injection (sanitize Jinja2 templates)
- **CWE-918**: SSRF (validate URLs)
- **CWE-327**: Weak Cryptography (use SHA-256+)
- **CWE-338**: Insecure Random (use secrets module)
- **CWE-798**: Hardcoded Secrets (use environment variables)

## References

- [Semgrep Python Rules](https://semgrep.dev/r?lang=python)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Trivy Python Scanning](https://aquasecurity.github.io/trivy/latest/docs/scanner/vulnerability/)
- [pip-audit](https://github.com/pypa/pip-audit)
- [OWASP Python Security](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
