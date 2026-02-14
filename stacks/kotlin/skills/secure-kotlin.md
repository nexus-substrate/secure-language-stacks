---
name: secure-kotlin
description: Security scanning and remediation for Kotlin projects (JVM, Android, Ktor, Spring Boot)
allowed-tools: [Read, Grep, Glob, Bash]
context: fork
---

# Secure Kotlin

Comprehensive security scanning workflow for Kotlin projects including JVM applications, Android apps, Ktor services, and Spring Boot applications.

## Capabilities

- SAST scanning with Semgrep (Kotlin rulesets) and Detekt
- SCA scanning with Trivy and OWASP Dependency-Check
- Secret detection with Gitleaks
- Android-specific security checks (WebView, intent handling, exported components)
- Ktor/Spring Boot security configuration validation
- Container image scanning for Dockerized Kotlin apps
- SARIF output for GitHub Security integration

## Usage

Run comprehensive security scan on a Kotlin project:

```bash
# Full scan with all tools
secure-kotlin /path/to/kotlin/project

# Scan specific framework
secure-kotlin /path/to/android/app --framework android
secure-kotlin /path/to/ktor/service --framework ktor
secure-kotlin /path/to/spring/app --framework spring-boot

# CI/CD integration
secure-kotlin . --ci github-actions
secure-kotlin . --ci concourse
```

## Workflow

### 1. Project Detection

Detect Kotlin project type and framework:

```bash
# Check for Kotlin project markers
if [ -f "build.gradle.kts" ] || [ -f "build.gradle" ]; then
  echo "Gradle project detected"
  PROJECT_TYPE="gradle"
elif [ -f "pom.xml" ]; then
  echo "Maven project detected"
  PROJECT_TYPE="maven"
fi

# Detect framework
if grep -q "com.android.application" build.gradle* 2>/dev/null; then
  FRAMEWORK="android"
elif grep -q "io.ktor" build.gradle* 2>/dev/null; then
  FRAMEWORK="ktor"
elif grep -q "spring-boot" build.gradle* pom.xml 2>/dev/null; then
  FRAMEWORK="spring-boot"
else
  FRAMEWORK="kotlin-jvm"
fi

echo "Detected: $PROJECT_TYPE / $FRAMEWORK"
```

### 2. Semgrep SAST Scan

Run Semgrep with Kotlin-specific rules:

```bash
# Run Semgrep with p/kotlin ruleset + custom rules
semgrep --config p/kotlin \
        --config stacks/kotlin/configs/.semgrep.yml \
        --sarif \
        --output semgrep-results.sarif \
        --error \
        --verbose

# Generate JSON report
semgrep --config p/kotlin \
        --config stacks/kotlin/configs/.semgrep.yml \
        --json \
        --output semgrep-results.json
```

**Key Kotlin vulnerabilities detected:**

- SQL injection via string concatenation
- Intent injection (Android)
- WebView JavaScript enabled without validation
- Hardcoded secrets and API keys
- Insecure cryptography (MD5, SHA1)
- Path traversal vulnerabilities
- Command injection via Runtime.exec()
- Insecure SSL/TLS configuration
- Coroutine context leaks (GlobalScope usage)
- Unsafe null assertion operators

### 3. Detekt Static Analysis

Run Detekt with security rules:

```bash
# Run Detekt (requires Gradle/Maven)
./gradlew detekt --no-daemon --stacktrace

# Check results
if [ -f "build/reports/detekt/detekt.sarif" ]; then
  echo "Detekt SARIF report generated"
fi
```

**Detekt security checks:**

- Complexity thresholds (method complexity, nesting depth)
- Exception handling patterns
- Coroutine best practices (GlobalScope detection)
- Empty catch blocks
- Magic numbers and hardcoded values
- Potential bugs (unsafe casts, null safety violations)

### 4. Trivy Dependency Scan

Scan dependencies for known vulnerabilities:

```bash
# Download Trivy DB
trivy --download-db-only

# Scan filesystem (Gradle lockfiles, Maven POMs)
trivy fs \
  --config stacks/kotlin/configs/trivy.yaml \
  --format sarif \
  --output trivy-results.sarif \
  --severity CRITICAL,HIGH,MEDIUM \
  .

# Generate JSON report
trivy fs \
  --format json \
  --output trivy-results.json \
  --severity CRITICAL,HIGH,MEDIUM \
  .
```

**Trivy scans:**

- Gradle dependency lockfiles (`gradle.lockfile`)
- Maven POM files (`pom.xml`)
- Transitive dependencies
- Known CVEs in Kotlin libraries
- Android SDK component vulnerabilities

### 5. OWASP Dependency-Check

Run comprehensive dependency analysis:

```bash
# Download and run Dependency-Check
curl -L https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip -o dc.zip
unzip -q dc.zip

# Run scan
./dependency-check/bin/dependency-check.sh \
  --project "Kotlin Security Scan" \
  --scan . \
  --suppression stacks/kotlin/configs/dependency-check.xml \
  --format ALL \
  --out dependency-check-results \
  --failOnCVSS 7 \
  --nvdApiKey $NVD_API_KEY
```

**Dependency-Check features:**

- NVD CVE database lookup
- Suppression management for false positives
- CVSS score-based failure thresholds
- Multiple output formats (HTML, JSON, XML, SARIF)

### 6. Gitleaks Secret Detection

Scan for hardcoded secrets:

```bash
# Run Gitleaks
gitleaks detect \
  --source . \
  --report-format sarif \
  --report-path gitleaks-results.sarif \
  --verbose

# Generate JSON report
gitleaks detect \
  --source . \
  --report-format json \
  --report-path gitleaks-results.json \
  --verbose
```

**Common secrets in Kotlin projects:**

- API keys in `local.properties` (Android)
- Database credentials in `application.properties` (Spring Boot)
- OAuth tokens in Kotlin code
- AWS credentials in configuration files
- Private keys in resource directories

### 7. Android-Specific Security Checks

For Android projects, perform additional checks:

```bash
# Check AndroidManifest.xml for security issues
if [ -f "app/src/main/AndroidManifest.xml" ]; then
  echo "=== Android Security Checks ==="

  # Exported components without permissions
  grep -n 'android:exported="true"' app/src/main/AndroidManifest.xml | \
    grep -v 'android:permission' && \
    echo "WARNING: Exported components without permission found"

  # Backup allowance enabled
  grep -n 'android:allowBackup="true"' app/src/main/AndroidManifest.xml && \
    echo "WARNING: Backup allowance enabled (consider disabling for sensitive apps)"

  # Debuggable builds
  grep -n 'android:debuggable="true"' app/src/main/AndroidManifest.xml && \
    echo "ERROR: Debuggable flag enabled in manifest"

  # Clear text traffic
  grep -n 'android:usesCleartextTraffic="true"' app/src/main/AndroidManifest.xml && \
    echo "WARNING: Clear text traffic allowed"
fi

# Check for WebView JavaScript enabled
grep -rn 'javaScriptEnabled = true' --include="*.kt" && \
  echo "WARNING: WebView JavaScript enabled (ensure proper validation)"

# Check for insecure intent handling
grep -rn 'Intent.parseUri' --include="*.kt" && \
  echo "WARNING: Intent.parseUri usage found (validate intent data)"

# Check for exported BroadcastReceivers
grep -rn 'registerReceiver' --include="*.kt" | \
  grep -v 'permission' && \
  echo "WARNING: BroadcastReceiver registered without permission"
```

### 8. Ktor Security Configuration

For Ktor applications, validate security settings:

```bash
# Check for HTTPS enforcement
grep -rn 'install(HTTPS)' --include="*.kt" || \
  echo "WARNING: HTTPS plugin not configured"

# Check for CORS configuration
grep -rn 'install(CORS)' --include="*.kt" && \
  echo "INFO: CORS configured (ensure restrictive origins)"

# Check for authentication
grep -rn 'install(Authentication)' --include="*.kt" || \
  echo "WARNING: No authentication plugin found"

# Check for rate limiting
grep -rn 'RateLimit' --include="*.kt" || \
  echo "INFO: Consider adding rate limiting"

# Check for session security
grep -rn 'Sessions' --include="*.kt" && \
  grep -rn 'cookie.*httpOnly' --include="*.kt" || \
  echo "WARNING: Session cookies may not have httpOnly flag"
```

### 9. Spring Boot Security Configuration

For Spring Boot applications, check security settings:

```bash
# Check for Spring Security
grep -rn '@EnableWebSecurity' --include="*.kt" || \
  echo "WARNING: Spring Security not enabled"

# Check for CSRF protection
grep -rn 'csrf()' --include="*.kt" && \
  grep -rn 'csrf().disable()' --include="*.kt" && \
  echo "WARNING: CSRF protection disabled"

# Check for SQL injection prevention
grep -rn '@Query' --include="*.kt" && \
  grep -rn 'nativeQuery.*true' --include="*.kt" && \
  echo "WARNING: Native queries found (ensure parameterization)"

# Check for password encoding
grep -rn 'PasswordEncoder' --include="*.kt" || \
  echo "WARNING: No password encoder configured"

# Check application.properties for security misconfigurations
if [ -f "src/main/resources/application.properties" ]; then
  grep -n 'spring.security.enabled=false' src/main/resources/application.properties && \
    echo "ERROR: Spring Security disabled"

  grep -n 'management.security.enabled=false' src/main/resources/application.properties && \
    echo "WARNING: Management endpoint security disabled"
fi
```

### 10. Container Image Scan (if Dockerized)

Scan Docker images for vulnerabilities:

```bash
# Check for Dockerfile
if [ -f "Dockerfile" ]; then
  echo "=== Container Security Scan ==="

  # Build image
  docker build -t kotlin-app:scan .

  # Scan with Trivy
  trivy image \
    --severity CRITICAL,HIGH \
    --format sarif \
    --output trivy-image.sarif \
    kotlin-app:scan

  # Check base image
  BASE_IMAGE=$(grep '^FROM' Dockerfile | head -1 | awk '{print $2}')
  echo "Base image: $BASE_IMAGE"

  # Scan base image
  trivy image \
    --severity CRITICAL,HIGH \
    $BASE_IMAGE
fi
```

### 11. Aggregate Results and Report

Generate consolidated security report:

```bash
#!/bin/bash

echo "=== Kotlin Security Scan Summary ==="
echo ""

# Count Semgrep findings
if [ -f semgrep-results.json ]; then
  SEMGREP_COUNT=$(jq '.results | length' semgrep-results.json)
  SEMGREP_ERROR=$(jq '[.results[] | select(.extra.severity=="ERROR")] | length' semgrep-results.json)
  SEMGREP_WARNING=$(jq '[.results[] | select(.extra.severity=="WARNING")] | length' semgrep-results.json)
  echo "Semgrep SAST:"
  echo "  Total: $SEMGREP_COUNT"
  echo "  Errors: $SEMGREP_ERROR"
  echo "  Warnings: $SEMGREP_WARNING"
  echo ""
fi

# Count Trivy vulnerabilities
if [ -f trivy-results.json ]; then
  TRIVY_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' trivy-results.json)
  TRIVY_HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' trivy-results.json)
  TRIVY_MEDIUM=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' trivy-results.json)
  echo "Trivy SCA:"
  echo "  Critical: $TRIVY_CRITICAL"
  echo "  High: $TRIVY_HIGH"
  echo "  Medium: $TRIVY_MEDIUM"
  echo ""
fi

# Count Gitleaks secrets
if [ -f gitleaks-results.json ]; then
  GITLEAKS_COUNT=$(jq '. | length' gitleaks-results.json)
  echo "Gitleaks Secrets: $GITLEAKS_COUNT"
  echo ""
fi

# Detekt summary
if [ -f build/reports/detekt/detekt.xml ]; then
  DETEKT_COUNT=$(grep -c '<error' build/reports/detekt/detekt.xml || echo 0)
  echo "Detekt Issues: $DETEKT_COUNT"
  echo ""
fi

echo "Detailed reports:"
echo "  - semgrep-results.sarif"
echo "  - trivy-results.sarif"
echo "  - gitleaks-results.sarif"
echo "  - build/reports/detekt/detekt.sarif"
echo "  - dependency-check-results/dependency-check-report.html"
```

## CI/CD Integration

### GitHub Actions

Use the provided workflow template:

```yaml
# .github/workflows/security.yml
# See: stacks/kotlin/pipelines/github-actions/security.yml
```

### Concourse

Use the provided pipeline template:

```yaml
# ci/security-pipeline.yml
# See: stacks/kotlin/pipelines/concourse/pipeline.yml
```

## Remediation Guidance

### High Priority Fixes

1. **SQL Injection**: Use parameterized queries or ORM frameworks
   ```kotlin
   // BAD
   val query = "SELECT * FROM users WHERE id = $userId"

   // GOOD
   val query = "SELECT * FROM users WHERE id = ?"
   preparedStatement.setInt(1, userId)
   ```

2. **Insecure Cryptography**: Use strong algorithms
   ```kotlin
   // BAD
   MessageDigest.getInstance("MD5")

   // GOOD
   MessageDigest.getInstance("SHA-256")
   ```

3. **Hardcoded Secrets**: Use environment variables or secret managers
   ```kotlin
   // BAD
   val apiKey = "sk_live_12345"

   // GOOD
   val apiKey = System.getenv("API_KEY")
   ```

4. **Intent Injection (Android)**: Validate intent data
   ```kotlin
   // BAD
   val intent = Intent.parseUri(untrustedUri, 0)

   // GOOD
   val intent = Intent.parseUri(untrustedUri, Intent.URI_INTENT_SCHEME)
   if (intent.component?.packageName == packageName) {
     startActivity(intent)
   }
   ```

5. **WebView Security (Android)**: Disable JavaScript or validate content
   ```kotlin
   // BAD
   webView.settings.javaScriptEnabled = true
   webView.loadUrl(untrustedUrl)

   // GOOD
   webView.settings.javaScriptEnabled = false
   // Or with validation
   if (trustedUrl.startsWith("https://trusted.example.com")) {
     webView.settings.javaScriptEnabled = true
     webView.loadUrl(trustedUrl)
   }
   ```

### Medium Priority Fixes

1. **Coroutine Context Leaks**: Use structured concurrency
   ```kotlin
   // BAD
   GlobalScope.launch { /* work */ }

   // GOOD
   viewModelScope.launch { /* work */ }
   // or
   CoroutineScope(Dispatchers.IO).launch { /* work */ }
   ```

2. **Null Safety**: Avoid unsafe null assertions
   ```kotlin
   // BAD
   val value = nullableValue!!

   // GOOD
   val value = nullableValue ?: defaultValue
   // or
   nullableValue?.let { /* use it */ }
   ```

3. **Exported Components (Android)**: Add permissions
   ```xml
   <!-- BAD -->
   <activity android:name=".SecureActivity" android:exported="true" />

   <!-- GOOD -->
   <activity
     android:name=".SecureActivity"
     android:exported="true"
     android:permission="android.permission.MY_CUSTOM_PERMISSION" />
   ```

## Exit Codes

- `0`: All scans passed with no critical findings
- `1`: Critical or high-severity vulnerabilities found
- `2`: Scanner execution failed

## Notes

- Requires JDK 17+ for Kotlin compilation and Gradle/Maven execution
- Android scans require Android SDK setup (`$ANDROID_HOME`)
- NVD API key recommended for Dependency-Check (avoid rate limiting)
- Container scans require Docker daemon running
- Null safety in Kotlin is a security feature (prevents NPE vulnerabilities)
- Coroutine context is critical for Android lifecycle management
