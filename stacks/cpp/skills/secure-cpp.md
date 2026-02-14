---
name: secure-cpp
description: Set up and configure security scanning for C++ projects with Semgrep, Cppcheck, Trivy, and Gitleaks
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
context: fork
---

# Secure C++ - Security Scanning Setup

This skill configures comprehensive security scanning for C++ projects using industry-standard tools.

## Tools Configured

1. **Semgrep** - SAST for C/C++ code patterns
2. **Cppcheck** - Static analysis for C++ code
3. **Trivy** - SCA for dependencies and container scanning
4. **Gitleaks** - Secret detection

## Security Checks Covered

### Memory Safety
- Buffer overflows (strcpy, strcat, gets, scanf)
- Use-after-free and double-free
- Null pointer dereference
- Memory leaks
- Uninitialized variables

### Code Injection
- Command injection (system, popen)
- Format string vulnerabilities
- Path traversal

### Integer Safety
- Integer overflow and wraparound
- Sign conversion issues

### Cryptographic
- Weak random number generation (rand)

### Best Practices
- RAII pattern enforcement
- Smart pointer usage
- Exception handling
- Resource management

## Execution Steps

### 1. Analyze Project Structure

Identify the C++ project type and build system:

```bash
# Check for CMake
ls CMakeLists.txt

# Check for Conan
ls conanfile.txt conanfile.py

# Check for vcpkg
ls vcpkg.json

# Check for Meson
ls meson.build

# Identify source directories
find . -type d -name "src" -o -name "include"
```

### 2. Install Security Tools

```bash
# Install Semgrep
pip install semgrep

# Install Cppcheck (Ubuntu/Debian)
sudo apt-get install cppcheck

# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Install Gitleaks
brew install gitleaks  # macOS
# or
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks-linux-amd64
chmod +x gitleaks-linux-amd64
sudo mv gitleaks-linux-amd64 /usr/local/bin/gitleaks
```

### 3. Copy Security Configurations

```bash
# Create security config directory
mkdir -p .security

# Copy Semgrep config
cp stacks/cpp/configs/.semgrep.yml .security/

# Copy Cppcheck config
cp stacks/cpp/configs/cppcheck.cfg .security/

# Copy Trivy config
cp stacks/cpp/configs/trivy.yaml .security/

# Copy Gitleaks config (from shared)
cp shared/configs/gitleaks.toml .security/
```

### 4. Run Security Scans

#### Semgrep SAST
```bash
semgrep scan \
  --config=.security/.semgrep.yml \
  --config=p/c \
  --error \
  --verbose \
  --sarif \
  --output=semgrep-results.sarif \
  .
```

#### Cppcheck
```bash
cppcheck \
  --enable=warning,style,performance,portability \
  --error-exitcode=1 \
  --xml \
  --xml-version=2 \
  --output-file=cppcheck-results.xml \
  --suppress='*:*/test/*' \
  --suppress='*:*/tests/*' \
  --verbose \
  src/
```

#### Trivy SCA
```bash
trivy fs \
  --config=.security/trivy.yaml \
  --severity CRITICAL,HIGH,MEDIUM \
  --exit-code 1 \
  --format json \
  --output trivy-results.json \
  .
```

#### Gitleaks
```bash
gitleaks detect \
  --config=.security/gitleaks.toml \
  --report-path=gitleaks-results.json \
  --report-format=json \
  --verbose \
  --exit-code=1
```

### 5. Set Up CI Pipeline

Choose your CI platform:

**GitHub Actions:**
```bash
mkdir -p .github/workflows
cp stacks/cpp/pipelines/github-actions/security.yml .github/workflows/
```

**Concourse CI:**
```bash
mkdir -p ci
cp stacks/cpp/pipelines/concourse/pipeline.yml ci/security-pipeline.yml

# Apply pipeline
fly -t <target> set-pipeline \
  -p cpp-security \
  -c ci/security-pipeline.yml
```

### 6. Configure Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config', '.security/.semgrep.yml', '--error']

  - repo: local
    hooks:
      - id: cppcheck
        name: cppcheck
        entry: cppcheck
        language: system
        args: ['--enable=warning', '--error-exitcode=1', 'src/']

      - id: gitleaks
        name: gitleaks
        entry: gitleaks
        language: system
        args: ['detect', '--config', '.security/gitleaks.toml', '--no-git']
EOF

# Install hooks
pre-commit install
```

### 7. Verify Setup

```bash
# Run all scans
semgrep scan --config=.security/.semgrep.yml --config=p/c .
cppcheck --enable=warning src/
trivy fs --config=.security/trivy.yaml .
gitleaks detect --config=.security/gitleaks.toml

# Test pre-commit hooks
pre-commit run --all-files
```

## Integration with IDEs

### VS Code
```json
{
  "semgrep.scan": {
    "configuration": [".security/.semgrep.yml", "p/c"],
    "exclude": ["test", "tests", "third_party"]
  },
  "C_Cpp.codeAnalysis.clangTidy.enabled": true,
  "C_Cpp.codeAnalysis.runAutomatically": true
}
```

### CLion
- Enable Cppcheck plugin
- Configure inspection profile for memory safety
- Enable sanitizers in CMake configuration

## Common Issues and Solutions

### Issue: Too many false positives
**Solution:** Add suppressions to `.security/cppcheck.cfg` or use inline comments

### Issue: Build system not detected
**Solution:** Explicitly set include paths in Cppcheck config

### Issue: Container scan fails
**Solution:** Ensure Dockerfile uses security-hardened base images

### Issue: Secrets scan too slow
**Solution:** Add `.gitleaksignore` for known false positives

## Security Best Practices

1. **Enable compiler warnings**: `-Wall -Wextra -Werror`
2. **Use sanitizers**: AddressSanitizer, UndefinedBehaviorSanitizer, ThreadSanitizer
3. **Enable stack protection**: `-fstack-protector-strong`
4. **Use modern C++ features**: Smart pointers, RAII, std::string
5. **Avoid deprecated functions**: gets, strcpy, sprintf
6. **Validate all inputs**: Bounds checking, null checks
7. **Use const correctness**: Prevent unintended modifications

## References

- [OWASP C++ Security Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SEI CERT C++ Coding Standard](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88046682)
- [Semgrep C/C++ Rules](https://semgrep.dev/p/c)
