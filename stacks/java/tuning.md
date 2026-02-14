# Java Security Scanner Tuning Guide

This guide provides detailed tuning recommendations for Java security scanners to reduce false positives, improve detection accuracy, and address Java-specific vulnerability patterns.

## Table of Contents

1. [Semgrep Custom Rules](#semgrep-custom-rules)
2. [SpotBugs Configuration](#spotbugs-configuration)
3. [Trivy Optimization](#trivy-optimization)
4. [OWASP Dependency-Check](#owasp-dependency-check)
5. [Java-Specific Vulnerability Patterns](#java-specific-vulnerability-patterns)
6. [Framework-Specific Guidance](#framework-specific-guidance)

---

## Semgrep Custom Rules

### High-Impact Patterns

#### 1. Insecure Deserialization (CWE-502)

**Risk**: Remote code execution via malicious serialized objects.

**Detection Rule**:

```yaml
- id: java-unsafe-deserialization-custom
  pattern-either:
    - pattern: |
        ObjectInputStream $OIS = new ObjectInputStream(...);
        ...
        $OIS.readObject()
    - pattern: |
        $OIS.readObject()
  pattern-not-inside: |
    $OIS.setObjectInputFilter(...)
  message: Unsafe deserialization without input filter. Implement allowlist-based filtering.
  severity: ERROR
  metadata:
    cwe: CWE-502
    fix: Use ObjectInputFilter (Java 9+) or validate class types before deserializing
```

**Mitigation**:

```java
// Java 9+ with allowlist filter
Set<Class<?>> allowedClasses = Set.of(MyClass.class, OtherClass.class);
ois.setObjectInputFilter(filterInfo -> {
    if (filterInfo.serialClass() != null) {
        return allowedClasses.contains(filterInfo.serialClass())
            ? ObjectInputFilter.Status.ALLOWED
            : ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.UNDECIDED;
});

// Pre-Java 9: use custom ObjectInputStream
class SafeObjectInputStream extends ObjectInputStream {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        if (!allowedClasses.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization attempt");
        }
        return super.resolveClass(desc);
    }
}
```

#### 2. XXE (XML External Entity) (CWE-611)

**Risk**: Information disclosure, SSRF, denial of service via malicious XML.

**Detection Rule**:

```yaml
- id: java-xxe-comprehensive
  pattern-either:
    - pattern: |
        $FACTORY = DocumentBuilderFactory.newInstance();
        ...
        $BUILDER = $FACTORY.newDocumentBuilder();
    - pattern: |
        $FACTORY = SAXParserFactory.newInstance();
    - pattern: |
        XMLInputFactory.newInstance()
    - pattern: |
        TransformerFactory.newInstance()
  pattern-not-inside: |
    $FACTORY.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  message: XML parser not hardened against XXE attacks
  severity: ERROR
```

**Comprehensive Mitigation**:

```java
// DocumentBuilderFactory
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

// SAXParserFactory
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// XMLInputFactory (StAX)
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

#### 3. Expression Language Injection (CWE-94)

**Risk**: Remote code execution via EL/OGNL/SpEL expression evaluation.

**Detection Rule**:

```yaml
- id: java-el-injection-spring
  pattern-either:
    - pattern: |
        new SpelExpressionParser().parseExpression($USER_INPUT)
    - pattern: |
        ExpressionParser.parseExpression($USER_INPUT)
    - pattern: |
        $PARSER.parseExpression($VAR)
  message: SpEL injection risk - do not parse user-controlled expressions
  severity: ERROR
  metadata:
    framework: Spring
```

**Mitigation**:

```java
// NEVER evaluate user input as expressions
// BAD
String expr = request.getParameter("expr");
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(expr); // VULNERABLE

// GOOD: Use parameterized templates
StandardEvaluationContext context = new StandardEvaluationContext();
context.setVariable("userValue", sanitizedInput);
Expression exp = parser.parseExpression("#userValue");
```

#### 4. LDAP Injection (CWE-90)

**Detection Rule**:

```yaml
- id: java-ldap-injection
  pattern-either:
    - pattern: |
        $CTX.search($BASE, $FILTER + $INPUT, ...)
    - pattern: |
        new SearchControls().setFilter($X + $INPUT)
  message: LDAP injection - escape special characters in user input
  severity: ERROR
```

**Mitigation**:

```java
// Use LDAP encoder to escape special characters
import org.owasp.encoder.Encode;

String escapedUsername = Encode.forLdap(username);
String filter = "(&(uid=" + escapedUsername + ")(ou=People))";

// LDAP special characters to escape: * ( ) \ NUL
```

---

## SpotBugs Configuration

### Tune FindSecBugs for Low False Positives

#### Priority Tuning

```xml
<!-- Focus on high-confidence security bugs -->
<Match>
  <Bug category="SECURITY" />
  <Priority value="1" />  <!-- High priority only -->
</Match>

<!-- Medium priority for specific patterns -->
<Match>
  <Bug pattern="HARD_CODE_PASSWORD,PREDICTABLE_RANDOM,COOKIE_USAGE" />
  <Priority value="2" />
</Match>
```

#### Exclude Test Code

```xml
<!-- Reduce noise from test files -->
<Match>
  <Class name="~.*Test$" />
  <Not>
    <Bug pattern="SQL_INJECTION,XXE_DOCUMENT,OBJECT_DESERIALIZATION" />
  </Not>
</Match>

<Match>
  <Package name="~.*\.test\..*" />
  <Bug pattern="HARD_CODE_PASSWORD" />  <!-- Allow test credentials -->
</Match>
```

#### Framework-Specific Exclusions

```xml
<!-- Spring Framework false positives -->
<Match>
  <Class name="~.*Configuration$" />
  <Bug pattern="SPRING_CSRF_PROTECTION_DISABLED" />
  <Method name="corsConfigurer" />
</Match>

<!-- Lombok-generated code -->
<Match>
  <Class name="~.*Builder$" />
  <Bug pattern="EI_EXPOSE_REP2" />
</Match>
```

---

## Trivy Optimization

### Reduce False Positives in Java Dependencies

#### Ignore Unfixed Vulnerabilities in Development

```yaml
# trivy.yaml
ignore-unfixed: true  # Set to false in production pipelines

# Ignore specific CVEs with justification
vulnerability:
  ignore:
    - id: CVE-2021-12345
      reason: False positive - affects Windows only, we deploy on Linux
      expiry: 2026-12-31
```

#### Dependency Scope Filtering

```yaml
# Only scan runtime dependencies (exclude test/provided)
java:
  maven:
    # Skip test-scoped dependencies
    skip-test-dependencies: true
  gradle:
    # Skip configurations
    skip-configs:
      - testCompileClasspath
      - testRuntimeClasspath
```

#### License Compliance

```yaml
license:
  full: true
  ignored:
    - MIT
    - Apache-2.0
    - BSD-3-Clause
  prohibited:
    - GPL-3.0    # Copyleft license
    - AGPL-3.0   # Network copyleft
```

---

## OWASP Dependency-Check

### Advanced Suppression Strategies

#### Suppress by CVSS Score

```xml
<suppress>
  <notes>
    CVE-2020-XXXXX has CVSS 4.0 (Medium) and is addressed in our WAF layer.
    Re-evaluate after Q2 2026 vendor patch.
  </notes>
  <packageUrl regex="true">^pkg:maven/com\.example/library@.*$</packageUrl>
  <cvssBelow>7.0</cvssBelow>  <!-- Only suppress if below HIGH -->
</suppress>
```

#### Suppress Transitive Dependencies

```xml
<suppress until="2026-06-30">
  <notes>
    Transitive dependency of spring-boot-starter-web.
    Fixed in Spring Boot 3.2.0 (scheduled upgrade Q2 2026).
  </notes>
  <packageUrl regex="true">^pkg:maven/org\.yaml/snakeyaml@.*$</packageUrl>
  <cve>CVE-2022-1471</cve>
</suppress>
```

#### Suppress by CWE Category

```xml
<suppress>
  <notes>
    CWE-400 (Uncontrolled Resource Consumption) - mitigated via rate limiting.
  </notes>
  <cwe>400</cwe>
  <filePath regex="true">.*commons-io-2\.11\.0\.jar</filePath>
</suppress>
```

---

## Java-Specific Vulnerability Patterns

### 1. Log4Shell (CVE-2021-44228)

**Detection**:

```bash
# Check for vulnerable Log4j versions
trivy fs --severity CRITICAL --vuln-type library | grep log4j-core
```

**Mitigation**:

```xml
<!-- Upgrade to Log4j 2.17.1+ -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.20.0</version>
</dependency>
```

**Runtime Mitigation**:

```bash
# JVM flag to disable JNDI lookups
-Dlog4j2.formatMsgNoLookups=true
```

### 2. Spring4Shell (CVE-2022-22965)

**Detection**:

```yaml
# Semgrep rule for class parameter binding
- id: spring4shell-class-binding
  pattern: |
    @RequestMapping(...)
    public void $METHOD(@ModelAttribute $CLASS $PARAM) { ... }
  message: Potential Spring4Shell - avoid binding to Class parameter
  severity: WARNING
```

**Mitigation**:

```java
// Upgrade Spring Framework to 5.3.18+ or 5.2.20+
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-core</artifactId>
  <version>5.3.27</version>
</dependency>

// Disallow class property access
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setDisallowedFields("class.*", "Class.*", "*.class.*");
}
```

### 3. Java Deserialization Gadget Chains

**High-Risk Libraries**:

- Commons Collections 3.x
- Spring Framework (specific versions)
- Apache Commons BeanUtils
- Groovy
- XStream

**Detection**:

```bash
# Scan for known gadget chain libraries
trivy fs --severity HIGH --scanners vuln | grep -E "(commons-collections|xstream|groovy)"
```

**Mitigation**:

```xml
<!-- Upgrade or exclude vulnerable libraries -->
<dependency>
  <groupId>commons-collections</groupId>
  <artifactId>commons-collections</artifactId>
  <version>3.2.2</version>
  <scope>provided</scope>  <!-- Exclude from runtime if possible -->
</dependency>
```

---

## Framework-Specific Guidance

### Spring Boot

#### Security Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .headers(headers -> headers
                .contentSecurityPolicy("default-src 'self'")
                .frameOptions().deny()
                .xssProtection().block(true)
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .sessionFixation().migrateSession()
            );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);  // Never use MD5/SHA1
    }
}
```

#### Semgrep Rules for Spring

```yaml
- id: spring-csrf-disabled
  pattern: |
    http.csrf().disable()
  message: CSRF protection disabled - only disable for stateless APIs
  severity: WARNING

- id: spring-weak-password-encoder
  pattern-either:
    - pattern: new NoOpPasswordEncoder()
    - pattern: PasswordEncoderFactories.createDelegatingPasswordEncoder("{noop}")
  message: Weak password encoding - use BCryptPasswordEncoder
  severity: ERROR
```

### Jakarta EE / Java EE

#### Input Validation

```java
// Use Bean Validation (JSR 380)
public class UserDTO {
    @NotNull
    @Pattern(regexp = "^[a-zA-Z0-9_]{3,20}$")
    private String username;

    @Email
    private String email;

    @Size(min = 8, max = 128)
    private String password;
}
```

### Quarkus

#### Security Extensions

```xml
<!-- Add security extensions -->
<dependency>
  <groupId>io.quarkus</groupId>
  <artifactId>quarkus-security</artifactId>
</dependency>
<dependency>
  <groupId>io.quarkus</groupId>
  <artifactId>quarkus-elytron-security-properties-file</artifactId>
</dependency>
```

---

## Common False Positive Patterns

### 1. Hard-Coded Passwords in Tests

```xml
<!-- Suppress for test resources -->
<Match>
  <Class name="~.*TestData$" />
  <Bug pattern="HARD_CODE_PASSWORD" />
</Match>
```

### 2. SQL Injection in Query Builders

```java
// JPA Criteria API is safe from SQLi
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery<User> cq = cb.createQuery(User.class);
Root<User> user = cq.from(User.class);
cq.where(cb.equal(user.get("username"), userInput));  // SAFE - uses parameterization
```

### 3. Path Traversal in Static Resources

```java
// Spring ResourceLoader is safe when configured correctly
@GetMapping("/resources/{filename}")
public ResponseEntity<Resource> getResource(@PathVariable String filename) {
    Resource resource = resourceLoader.getResource("classpath:static/" + filename);
    // SAFE if resources are within classpath and not user-writable
}
```

---

## Security Testing Integration

### Unit Tests for Security

```java
@Test
void testSqlInjectionPrevention() {
    String maliciousInput = "admin' OR '1'='1";
    User user = userRepository.findByUsername(maliciousInput);
    assertNull(user, "SQL injection should not return results");
}

@Test
void testXxePrevention() throws Exception {
    String xxePayload = """
        <?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>
        """;

    assertThrows(SAXParseException.class, () -> {
        xmlParser.parse(new InputSource(new StringReader(xxePayload)));
    });
}
```

### Continuous Compliance

```bash
# Run security scans in pre-commit hook
#!/bin/bash
echo "Running security checks..."

# Quick Semgrep scan
semgrep --config=.semgrep.yml --error --quiet .

# Check for secrets
gitleaks detect --no-git --quiet

exit $?
```

---

## References

- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [FindSecBugs Bug Patterns](https://find-sec-bugs.github.io/bugs.htm)
- [Semgrep Java Rules](https://semgrep.dev/r?lang=java)
- [Spring Security Documentation](https://docs.spring.io/spring-security/reference/)
- [Java Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
