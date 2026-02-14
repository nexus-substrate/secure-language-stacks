---
name: secure-java
description: Set up comprehensive security scanning for Java projects using Semgrep, SpotBugs, Trivy, OWASP Dependency-Check, and GitLeaks
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
context: fork
---

# Secure Java Development Workflow

This skill guides you through setting up a complete security scanning pipeline for Java projects, covering SAST, SCA, secret scanning, and container security.

## Overview

The Java security stack provides:

- **SAST**: Semgrep (custom rules) + SpotBugs with FindSecBugs plugin
- **SCA**: Trivy + OWASP Dependency-Check for vulnerability scanning
- **Secret Scanning**: GitLeaks for credential detection
- **DAST**: OWASP ZAP for Spring Boot/Jakarta EE applications
- **Container Security**: Trivy image scanning for Dockerized applications

## Prerequisites

Verify Java project structure and build system:

```bash
# Detect Maven or Gradle
if [ -f pom.xml ]; then
  BUILD_SYSTEM="maven"
  echo "Maven project detected"
elif [ -f build.gradle ] || [ -f build.gradle.kts ]; then
  BUILD_SYSTEM="gradle"
  echo "Gradle project detected"
else
  echo "No Maven or Gradle build file found"
  exit 1
fi
```

## Step 1: Install Security Scanners

### Semgrep

```bash
# Install via pip
pip install semgrep

# Verify installation
semgrep --version
```

### SpotBugs with FindSecBugs

For Maven projects, add to `pom.xml`:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.github.spotbugs</groupId>
      <artifactId>spotbugs-maven-plugin</artifactId>
      <version>4.8.3.0</version>
      <configuration>
        <plugins>
          <plugin>
            <groupId>com.h3xstream.findsecbugs</groupId>
            <artifactId>findsecbugs-plugin</artifactId>
            <version>1.12.0</version>
          </plugin>
        </plugins>
        <excludeFilterFile>stacks/java/configs/spotbugs-security.xml</excludeFilterFile>
      </configuration>
    </plugin>
  </plugins>
</build>
```

For Gradle projects, add to `build.gradle`:

```groovy
plugins {
    id 'com.github.spotbugs' version '5.2.5'
}

spotbugs {
    toolVersion = '4.8.3'
    excludeFilter = file('stacks/java/configs/spotbugs-security.xml')
}

dependencies {
    spotbugsPlugins 'com.h3xstream.findsecbugs:findsecbugs-plugin:1.12.0'
}
```

### Trivy

```bash
# Install Trivy (Linux)
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Verify installation
trivy --version
```

### OWASP Dependency-Check

```bash
# Download Dependency-Check CLI
wget https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.0/dependency-check-9.0.0-release.zip
unzip dependency-check-9.0.0-release.zip -d /opt/dependency-check

# Add to PATH
export PATH=$PATH:/opt/dependency-check/bin

# Verify installation
dependency-check.sh --version
```

### GitLeaks

```bash
# Install GitLeaks (Linux)
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
tar -xzf gitleaks_8.18.2_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Verify installation
gitleaks version
```

## Step 2: Copy Configuration Files

```bash
# Copy Semgrep rules
cp stacks/java/configs/.semgrep.yml .semgrep.yml

# Copy SpotBugs security config
cp stacks/java/configs/spotbugs-security.xml spotbugs-security.xml

# Copy Trivy config
cp stacks/java/configs/trivy.yaml trivy.yaml

# Copy Dependency-Check suppressions
cp stacks/java/configs/dependency-check.xml dependency-check.xml
```

## Step 3: Run Security Scans Locally

### SAST with Semgrep

```bash
# Run Semgrep with Java rules
semgrep --config=.semgrep.yml \
        --config=p/java \
        --json \
        --output=semgrep-results.json \
        .

# Generate SARIF for GitHub integration
semgrep --config=.semgrep.yml \
        --config=p/java \
        --sarif \
        --output=semgrep.sarif \
        .
```

### SAST with SpotBugs

```bash
# Maven
mvn clean compile spotbugs:check

# Gradle
./gradlew clean build spotbugsMain
```

### SCA with Trivy

```bash
# Scan filesystem dependencies
trivy fs --config=trivy.yaml \
         --severity CRITICAL,HIGH \
         --format json \
         --output trivy-fs.json \
         .

# Generate SBOM
trivy fs --format cyclonedx --output trivy-sbom.json .
```

### SCA with OWASP Dependency-Check

```bash
# Requires NVD API key (set as environment variable)
export NVD_API_KEY="your-nvd-api-key"

dependency-check.sh \
  --scan . \
  --format JSON \
  --out dependency-check-report.json \
  --suppression dependency-check.xml \
  --nvdApiKey $NVD_API_KEY \
  --failOnCVSS 7
```

### Secret Scanning with GitLeaks

```bash
# Scan entire repository history
gitleaks detect \
         --source=. \
         --report-format=json \
         --report-path=gitleaks-report.json \
         --verbose
```

## Step 4: Set Up CI/CD Pipeline

### GitHub Actions

```bash
# Copy GitHub Actions workflow
mkdir -p .github/workflows
cp stacks/java/pipelines/github-actions/security.yml .github/workflows/security.yml

# Add required secrets in GitHub repository settings:
# - NVD_API_KEY: OWASP NVD API key
```

### Concourse

```bash
# Copy Concourse pipeline
mkdir -p ci
cp stacks/java/pipelines/concourse/pipeline.yml ci/security-pipeline.yml

# Set pipeline in Concourse
fly -t <target> set-pipeline \
    -p java-security \
    -c ci/security-pipeline.yml \
    -l ci/credentials.yml
```

## Step 5: Review and Triage Findings

### Semgrep Results

```bash
# View critical findings
jq '.results[] | select(.extra.severity == "ERROR") | {file: .path, line: .start.line, message: .extra.message}' semgrep-results.json

# Filter by CWE
jq '.results[] | select(.extra.metadata.cwe == "CWE-89")' semgrep-results.json
```

### Trivy Results

```bash
# View critical vulnerabilities
jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | {package: .PkgName, version: .InstalledVersion, cve: .VulnerabilityID, title: .Title}' trivy-fs.json

# Group by severity
jq '[.Results[]?.Vulnerabilities[]?] | group_by(.Severity) | map({severity: .[0].Severity, count: length})' trivy-fs.json
```

### GitLeaks Results

```bash
# View detected secrets
jq '.[] | {file: .File, line: .StartLine, rule: .RuleID, match: .Match}' gitleaks-report.json
```

## Step 6: Fix Common Java Vulnerabilities

### SQL Injection (CWE-89)

**Vulnerable Code:**

```java
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Secure Code:**

```java
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, userInput);
ResultSet rs = pstmt.executeQuery();
```

### XXE (XML External Entity) (CWE-611)

**Vulnerable Code:**

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(xmlInput);
```

**Secure Code:**

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(xmlInput);
```

### Insecure Deserialization (CWE-502)

**Vulnerable Code:**

```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
```

**Secure Code:**

```java
// Use allowlist-based deserialization filter (Java 9+)
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filterInfo -> {
    if (filterInfo.serialClass() != null) {
        return allowedClasses.contains(filterInfo.serialClass())
            ? ObjectInputFilter.Status.ALLOWED
            : ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.UNDECIDED;
});
Object obj = ois.readObject();
```

### LDAP Injection (CWE-90)

**Vulnerable Code:**

```java
String filter = "(&(uid=" + username + ")(ou=People))";
NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, controls);
```

**Secure Code:**

```java
// Escape LDAP special characters
String escapedUsername = LdapEncoder.filterEncode(username);
String filter = "(&(uid=" + escapedUsername + ")(ou=People))";
NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, controls);
```

## Step 7: Establish Security Baseline

```bash
# Create baseline report
cat > security-baseline.md <<EOF
# Java Security Baseline

**Date**: $(date +%Y-%m-%d)
**Project**: $(basename $(pwd))

## Scan Results

- **Semgrep**: $(jq '.results | length' semgrep-results.json) findings
- **Trivy Critical**: $(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' trivy-fs.json)
- **Trivy High**: $(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' trivy-fs.json)
- **GitLeaks**: $(jq 'length' gitleaks-report.json) secrets

## Accepted Risks

Document any suppressed findings here with justification.

## Next Review

Scheduled for: $(date -d "+30 days" +%Y-%m-%d)
EOF
```

## Best Practices

1. **Run scans on every commit** via CI/CD pipeline
2. **Fail builds on critical findings** to enforce security gates
3. **Review suppressions quarterly** to ensure they're still valid
4. **Keep scanners updated** to detect latest vulnerabilities
5. **Use NVD API key** for faster Dependency-Check scans
6. **Integrate with GitHub Security** for centralized vulnerability tracking
7. **Train developers** on secure coding practices specific to Java
8. **Monitor dependencies** for newly disclosed CVEs

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Semgrep Java Rules](https://semgrep.dev/p/java)
- [FindSecBugs Documentation](https://find-sec-bugs.github.io/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)

## Troubleshooting

### SpotBugs not finding vulnerabilities

Ensure FindSecBugs plugin is installed and configured correctly. Check Maven/Gradle output for plugin loading confirmation.

### Trivy database update fails

Run `trivy image --download-db-only` to manually update the vulnerability database.

### Dependency-Check slow scans

Use NVD API key and enable database caching: `--data /var/cache/dependency-check`

### GitLeaks false positives

Add false positives to `.gitleaksignore` file with justification comments.
