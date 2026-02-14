# Kotlin Security Scanning Tuning Guide

Guidance for optimizing security scanners for Kotlin projects (JVM, Android, Ktor, Spring Boot).

---

## Semgrep Tuning

### Kotlin-Specific Rules

**Android Security:**

- **Intent Injection**: Kotlin's type-safe builders don't prevent intent injection when using raw strings
  ```kotlin
  // Vulnerable pattern
  val intent = Intent(action).apply {
    data = Uri.parse(userInput)  // Potential injection
  }
  ```

- **WebView JavaScript**: Common in Kotlin Android apps with WebView
  ```kotlin
  // High-risk pattern
  webView.settings.apply {
    javaScriptEnabled = true
    domStorageEnabled = true
  }
  ```

- **Exported Components**: Check `AndroidManifest.xml` for exported activities/services without permissions

**Ktor Security:**

- **CORS Misconfiguration**: Allow-all origins in production
  ```kotlin
  // Vulnerable pattern
  install(CORS) {
    anyHost()  // Allows any origin
  }
  ```

- **Missing HTTPS Enforcement**: No redirect from HTTP to HTTPS
  ```kotlin
  // Missing security
  embeddedServer(Netty, port = 8080) { /* no HTTPS */ }
  ```

**Spring Boot Security:**

- **CSRF Disabled**: Common in REST APIs but risky for web apps
  ```kotlin
  // Vulnerable pattern
  http.csrf().disable()  // Should be justified
  ```

- **SQL Injection in Native Queries**: Kotlin string templates in JPA queries
  ```kotlin
  // Vulnerable pattern
  @Query("SELECT * FROM users WHERE name = '$name'", nativeQuery = true)
  ```

### False Positive Suppression

**Test Code**: Exclude test directories
```yaml
paths:
  exclude:
    - "**/test/**"
    - "**/androidTest/**"
    - "**/commonTest/**"
```

**Third-Party Libraries**: Suppress findings in generated code
```yaml
paths:
  exclude:
    - "**/build/generated/**"
    - "**/generated/**"
```

**Null Safety**: Kotlin's nullable types reduce NPE risk
```yaml
# Suppress unsafe null assertion in controlled contexts
rules:
  - id: kotlin-unsafe-null-assertion
    pattern: $VAR!!
    paths:
      exclude:
        - "**/test/**"
```

---

## Detekt Tuning

### Security-Relevant Rules

**Enable Security Rules**:

```yaml
potential-bugs:
  active: true
  UnsafeCast:
    active: true
  UnsafeCallOnNullableType:
    active: true

exceptions:
  active: true
  SwallowedException:
    active: true
    ignoredExceptionTypes:
      - InterruptedException
      - NumberFormatException

coroutines:
  active: true
  GlobalCoroutineUsage:
    active: true  # Detects GlobalScope leaks
```

**Adjust Complexity Thresholds**:

```yaml
complexity:
  ComplexMethod:
    threshold: 15  # Lower for security-critical code
  LongMethod:
    threshold: 60
  TooManyFunctions:
    thresholdInFiles: 20
```

**Android-Specific**:

```yaml
naming:
  active: true
  ForbiddenClassName:
    active: true
    forbiddenName:
      - 'Util'
      - 'Helper'
      - 'Manager'  # Encourage specific naming
```

### False Positives

**Lateinit in Android**: Common pattern for dependency injection
```yaml
potential-bugs:
  LateinitUsage:
    active: false
    excludeAnnotatedProperties:
      - 'Inject'
      - 'Autowired'
```

**Data Classes**: Allow functions in data classes for Android Parcelize
```yaml
style:
  DataClassContainsFunctions:
    active: false
```

---

## Trivy Tuning

### Gradle/Maven Scanning

**Lock Files**: Ensure lock files are committed
```bash
# Generate Gradle lockfile
./gradlew dependencies --write-locks

# Commit lock files
git add gradle.lockfile
git add gradle/dependency-locks/*.lockfile
```

**Exclude Test Dependencies**:

```yaml
gradle:
  configurations:
    - runtimeClasspath
    - compileClasspath
  exclude-test-configs: true
```

**Android SDK**: Suppress false positives in Android build tools
```yaml
vulnerability:
  ignore:
    - CVE-XXXX  # Android build tools vulnerability (dev only)
```

### Container Scanning (Kotlin Apps)

**Base Image Selection**: Prefer distroless or slim images
```dockerfile
# BAD
FROM openjdk:17

# GOOD
FROM gcr.io/distroless/java17-debian11
```

**Multi-Stage Builds**: Reduce attack surface
```dockerfile
FROM gradle:8.5-jdk17 AS build
WORKDIR /app
COPY . .
RUN gradle build --no-daemon

FROM gcr.io/distroless/java17-debian11
COPY --from=build /app/build/libs/app.jar /app.jar
CMD ["app.jar"]
```

---

## OWASP Dependency-Check Tuning

### Suppression Rules

**Android SDK**: Development dependencies not in final APK
```xml
<suppress>
  <notes>Android build tools are dev dependencies only</notes>
  <gav regex="true">^com\.android\.tools.*:.*:.*$</gav>
</suppress>
```

**Kotlin Compiler**: Build-time only
```xml
<suppress>
  <notes>Kotlin compiler is build-time dependency</notes>
  <gav regex="true">^org\.jetbrains\.kotlin:kotlin-compiler.*:.*$</gav>
</suppress>
```

**Transitive Dependencies with Mitigation**:
```xml
<suppress>
  <notes>
  Vulnerability in kotlinx-coroutines transitive dependency.
  Mitigated by input validation. Expires: 2024-12-31
  </notes>
  <packageUrl regex="true">^pkg:maven/org\.jetbrains\.kotlinx/.*$</packageUrl>
  <cve>CVE-2023-XXXXX</cve>
  <until>2024-12-31Z</until>
</suppress>
```

### Performance Optimization

**NVD API Key**: Avoid rate limiting
```bash
./dependency-check.sh \
  --nvdApiKey $NVD_API_KEY \
  --project "Kotlin App"
```

**Caching**: Enable DB caching
```bash
./dependency-check.sh \
  --cveValidForHours 24 \
  --data /tmp/dependency-check-data
```

---

## Gitleaks Tuning

### Kotlin-Specific Secrets

**Android `local.properties`**: Contains SDK paths and API keys
```toml
[[rules]]
id = "android-local-properties-api-key"
description = "Android API key in local.properties"
regex = '''(?i)(api[_-]?key|api[_-]?secret)\s*=\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?'''
path = '''local\.properties'''
```

**Spring Boot `application.properties`**: Database credentials
```toml
[[rules]]
id = "spring-boot-db-password"
description = "Database password in application.properties"
regex = '''spring\.datasource\.password\s*=\s*['\"]?[^\s'\"]+['\"]?'''
path = '''application\.properties'''
```

**Kotlin Code**: Hardcoded secrets in `const val`
```toml
[[rules]]
id = "kotlin-hardcoded-secret"
description = "Hardcoded secret in Kotlin code"
regex = '''const\s+val\s+(API_KEY|SECRET|PASSWORD|TOKEN)\s*=\s*['"][A-Za-z0-9_\-]{20,}['"]'''
path = '''\.kt$'''
```

### Allowlist False Positives

**Test Fixtures**: Dummy credentials in test code
```toml
[allowlist]
paths = [
  '''.*_test\.kt$''',
  '''.*Test\.kt$''',
  '''.*Tests\.kt$''',
  '''androidTest/.*'''
]
```

**Example Strings**: Documentation examples
```toml
[allowlist]
regexes = [
  '''example\.com''',
  '''your-api-key-here''',
  '''sk_test_.*'''  # Stripe test keys
]
```

---

## Android-Specific Tuning

### Manifest Security Checks

**Automated Checks**:

```bash
#!/bin/bash
# android-security-check.sh

MANIFEST="app/src/main/AndroidManifest.xml"

# Check 1: Exported components without permissions
echo "Checking exported components..."
grep -n 'android:exported="true"' $MANIFEST | grep -v 'android:permission' && \
  echo "❌ Exported components without permission found" || \
  echo "✅ All exported components have permissions"

# Check 2: Backup allowance
grep -q 'android:allowBackup="true"' $MANIFEST && \
  echo "⚠️  Backup allowance enabled (consider disabling for sensitive apps)"

# Check 3: Debuggable flag
grep -q 'android:debuggable="true"' $MANIFEST && \
  echo "❌ Debuggable flag enabled in manifest" || \
  echo "✅ Debuggable flag not set"

# Check 4: Clear text traffic
grep -q 'android:usesCleartextTraffic="true"' $MANIFEST && \
  echo "⚠️  Clear text traffic allowed"

# Check 5: Network security config
grep -q 'android:networkSecurityConfig' $MANIFEST || \
  echo "⚠️  No network security config specified"
```

### ProGuard/R8 Configuration

**Security-Relevant Rules**:

```proguard
# Keep security-critical classes
-keep class com.example.security.** { *; }

# Obfuscate sensitive strings
-adaptresourcefilecontents **.properties

# Remove logging in production
-assumenosideeffects class android.util.Log {
  public static *** d(...);
  public static *** v(...);
  public static *** i(...);
}

# Remove debug info
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable
```

---

## Ktor Security Hardening

### Security Plugin Configuration

**HTTPS Enforcement**:

```kotlin
install(HTTPS) {
    redirectPort = 8443
    permanentRedirect = true
}
```

**CORS Restrictive Configuration**:

```kotlin
install(CORS) {
    // BAD: anyHost()

    // GOOD: Specific origins
    allowHost("example.com", schemes = listOf("https"))
    allowCredentials = false
    allowNonSimpleContentTypes = false
}
```

**Rate Limiting**:

```kotlin
install(RateLimit) {
    global {
        rateLimiter(limit = 100, refillPeriod = 60.seconds)
    }
}
```

**Session Security**:

```kotlin
install(Sessions) {
    cookie<UserSession>("SESSION") {
        cookie.path = "/"
        cookie.httpOnly = true
        cookie.secure = true  // HTTPS only
        cookie.extensions["SameSite"] = "Strict"
    }
}
```

---

## Spring Boot Security Hardening

### Security Configuration

**Enable CSRF for Web Apps**:

```kotlin
@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            csrf { }  // Enabled by default
            headers {
                contentSecurityPolicy {
                    policyDirectives = "default-src 'self'"
                }
            }
        }
        return http.build()
    }
}
```

**Password Encoding**:

```kotlin
@Bean
fun passwordEncoder(): PasswordEncoder {
    return BCryptPasswordEncoder(12)  // Strength 12
}
```

**SQL Injection Prevention**:

```kotlin
// BAD: String interpolation in native query
@Query("SELECT * FROM users WHERE name = '$name'", nativeQuery = true)

// GOOD: Parameterized query
@Query("SELECT * FROM users WHERE name = :name", nativeQuery = true)
fun findByName(@Param("name") name: String): User
```

**Disable Actuator Endpoints in Production**:

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      show-details: when-authorized
```

---

## Null Safety as a Security Feature

Kotlin's null safety prevents entire classes of vulnerabilities:

**NPE Prevention**:

```kotlin
// BAD (Java-style)
val user: User? = getUser()
val name = user.name  // Compiler error!

// GOOD (Kotlin)
val name = user?.name ?: "Unknown"
```

**Safe Property Access in Security Checks**:

```kotlin
// BAD
if (request.headers["Authorization"] != null) {
  val token = request.headers["Authorization"]!!.split(" ")[1]
  // Potential NPE
}

// GOOD
val token = request.headers["Authorization"]
  ?.split(" ")
  ?.getOrNull(1)
  ?: return@post call.respond(HttpStatusCode.Unauthorized)
```

---

## Coroutine Security

### Context Leaks

**GlobalScope Usage**: Avoid in Android
```kotlin
// BAD: Survives Activity destruction
GlobalScope.launch {
  repository.fetchData()  // Leaks context
}

// GOOD: Scoped to ViewModel
viewModelScope.launch {
  repository.fetchData()
}
```

**Structured Concurrency**:

```kotlin
// BAD: Unstructured
launch {
  // Parent doesn't wait for child
  launch { riskyOperation() }
}

// GOOD: Structured
coroutineScope {
  launch { riskyOperation() }
  // Parent waits for all children
}
```

### Exception Handling

```kotlin
// BAD: Silent failure
launch {
  riskyOperation()
  // Exception swallowed
}

// GOOD: Explicit handler
launch {
  try {
    riskyOperation()
  } catch (e: Exception) {
    logger.error("Operation failed", e)
    // Handle or propagate
  }
}
```

---

## CI/CD Integration Tuning

### GitHub Actions

**Cache Dependencies**:

```yaml
- name: Cache Gradle
  uses: actions/cache@v4
  with:
    path: |
      ~/.gradle/caches
      ~/.gradle/wrapper
    key: ${{ runner.os }}-gradle-${{ hashFiles('**/*.gradle*') }}
```

**Parallel Scanning**:

```yaml
jobs:
  security:
    strategy:
      matrix:
        scanner: [semgrep, detekt, trivy, gitleaks]
    steps:
      - name: Run ${{ matrix.scanner }}
        run: ./scripts/scan-${{ matrix.scanner }}.sh
```

### Concourse

**Resource Caching**:

```yaml
resources:
  - name: trivy-db
    type: registry-image
    source:
      repository: ghcr.io/aquasecurity/trivy-db
      tag: latest
    check_every: 24h  # Update daily
```

---

## Performance Optimization

### Gradle Build Optimization

**Parallel Execution**:

```properties
# gradle.properties
org.gradle.parallel=true
org.gradle.caching=true
org.gradle.configureondemand=true
```

**Dependency Resolution**:

```kotlin
// build.gradle.kts
configurations.all {
    resolutionStrategy {
        cacheDynamicVersionsFor(10, "minutes")
        cacheChangingModulesFor(4, "hours")
    }
}
```

### Scanner Execution Order

Run fast scanners first for quick feedback:

1. **Gitleaks** (fastest, secret detection)
2. **Semgrep** (fast, SAST)
3. **Detekt** (medium, requires Gradle)
4. **Trivy** (medium, dependency scan)
5. **Dependency-Check** (slow, comprehensive SCA)

---

## Summary

- **Android**: Focus on manifest security, WebView config, intent validation
- **Ktor**: Enforce HTTPS, restrictive CORS, session security
- **Spring Boot**: Enable CSRF, use parameterized queries, secure actuators
- **Null Safety**: Leverage Kotlin's type system for security
- **Coroutines**: Use structured concurrency, avoid GlobalScope
- **CI/CD**: Cache dependencies, run scanners in parallel
- **False Positives**: Suppress test code, generated code, dev dependencies
