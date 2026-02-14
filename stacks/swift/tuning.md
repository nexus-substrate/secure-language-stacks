# Swift Security Scanning Tuning Guide

## Overview

This guide provides tuning recommendations for Swift security scanners to reduce false positives and improve detection accuracy.

## Semgrep Tuning

### False Positive Patterns

1. **Test Files**
```yaml
# In .semgrep.yml, add paths exclusion
paths:
  exclude:
    - "Tests/"
    - "*Tests.swift"
    - "*Mock.swift"
    - "*Stub.swift"
```

2. **Development/Debug Code**
```swift
// Suppress specific rules for debug builds
#if DEBUG
// nosemgrep: swift-nslog-sensitive-data
NSLog("Debug token: \(token)")
#endif
```

3. **Known Safe Patterns**
```yaml
# Exclude framework-generated code
paths:
  exclude:
    - ".build/"
    - "DerivedData/"
    - "*.xcodeproj/"
```

### Custom Rules for Swift-Specific Risks

**Insecure UserDefaults Storage**
```yaml
rules:
  - id: swift-userdefaults-sensitive
    pattern-either:
      - pattern: UserDefaults.standard.set($VAL, forKey: $KEY)
    metavariable-pattern:
      metavariable: $KEY
      patterns:
        - pattern-regex: '(password|token|secret|pin|credential)'
    message: Storing sensitive data in UserDefaults (unencrypted)
    severity: ERROR
    metadata:
      cwe: CWE-311
```

**Insecure Data Storage in Documents**
```yaml
rules:
  - id: swift-documents-sensitive-data
    pattern: |
      FileManager.default.urls(for: .documentDirectory, ...).write(...)
    message: Writing potentially sensitive data to Documents directory
    severity: WARNING
    metadata:
      cwe: CWE-922
```

## Trivy Tuning

### Dependency Allowlisting

```yaml
# In trivy.yaml, ignore known false positives
vulnerability:
  ignore:
    - CVE-2023-XXXXX  # Not applicable to Swift Package Manager
```

### Swift Package Manager Specific

```yaml
swift:
  package-manager: swift
  scan-dependencies: true
  ignore-packages:
    - "TestPackage"  # Development-only dependency
```

## Gitleaks Tuning

### Swift-Specific Allowlists

```toml
# In .gitleaks.toml
[[rules]]
id = "swift-api-key"
description = "Swift API Key"
regex = '''(?i)(api[_-]?key|apikey)\s*=\s*['"][a-zA-Z0-9]{32,}['"]'''

[rules.allowlist]
paths = [
    '''Tests/.*''',
    '''.*Mock\.swift''',
    '''.*Example\.swift'''
]
```

## Keychain Security Best Practices

### Recommended kSecAttrAccessible Values

| Value                                          | Use Case                          | Security Level |
| ---------------------------------------------- | --------------------------------- | -------------- |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Highest security, no iCloud sync  | HIGH           |
| `kSecAttrAccessibleWhenUnlocked`               | Standard security with iCloud     | MEDIUM         |
| `kSecAttrAccessibleAfterFirstUnlock`           | Background access required        | LOW            |
| `kSecAttrAccessibleAlways`                     | DEPRECATED - do not use           | NONE           |

### Keychain Access Control

```swift
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .biometryCurrentSet,
    nil
)

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: account,
    kSecValueData as String: data,
    kSecAttrAccessControl as String: access as Any
]
```

## App Transport Security (ATS) Configuration

### Gradual ATS Enforcement

```xml
<!-- Start restrictive, add exceptions only when needed -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>
```

## Binary Protection Hardening

### Xcode Build Settings

Enable these settings for all release builds:

```
ENABLE_BITCODE = YES
ENABLE_TESTABILITY = NO (Release)
GCC_GENERATE_DEBUGGING_SYMBOLS = YES
GCC_OPTIMIZATION_LEVEL = s (Release)
SWIFT_OPTIMIZATION_LEVEL = -O (Release)
STRIP_INSTALLED_PRODUCT = YES (Release)
SYMBOLS_HIDDEN_BY_DEFAULT = YES
```

### Code Signing Configuration

```bash
# Verify code signing
codesign -dv --verbose=4 YourApp.app

# Check for hardened runtime (macOS)
codesign -d --entitlements :- YourApp.app
```

## Jailbreak Detection Tuning

### Comprehensive Detection

```swift
func enhancedJailbreakDetection() -> Bool {
    // File system checks
    let jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
        "/private/var/lib/apt/", "/private/var/lib/cydia",
        "/private/var/stash"
    ]

    // URI scheme checks
    if UIApplication.shared.canOpenURL(URL(string: "cydia://")!) {
        return true
    }

    // Sandbox integrity check
    do {
        try "test".write(toFile: "/private/jailbreak-test.txt", atomically: true, encoding: .utf8)
        return true  // Shouldn't be able to write here
    } catch {
        // Expected - sandboxed app
    }

    // Dyld check
    if let libraries = _dyld_image_count() {
        for i in 0..<libraries {
            if let name = _dyld_get_image_name(i) {
                let path = String(cString: name)
                if path.contains("MobileSubstrate") || path.contains("Substrate") {
                    return true
                }
            }
        }
    }

    return false
}
```

## Certificate Pinning Implementation

### Trust Evaluation

```swift
import CommonCrypto

class CertificatePinner {
    static let shared = CertificatePinner()
    private let pinnedCertificates: [Data]

    init() {
        guard let certPath = Bundle.main.path(forResource: "certificate", ofType: "der"),
              let certData = try? Data(contentsOf: URL(fileURLWithPath: certPath)) else {
            fatalError("Pinned certificate not found")
        }
        self.pinnedCertificates = [certData]
    }

    func evaluateTrust(_ trust: SecTrust) -> Bool {
        let certificateCount = SecTrustGetCertificateCount(trust)

        for i in 0..<certificateCount {
            if let certificate = SecTrustGetCertificateAtIndex(trust, i) {
                let certificateData = SecCertificateCopyData(certificate) as Data

                if pinnedCertificates.contains(certificateData) {
                    return true
                }
            }
        }

        return false
    }
}
```

## Data Protection API Guidelines

### File Protection Levels

```swift
// Critical data (authentication tokens, encryption keys)
try data.write(to: url, options: .completeFileProtection)

// User data (documents, photos)
try data.write(to: url, options: .completeFileProtectionUnlessOpen)

// Cache data (safe to lose)
try data.write(to: url, options: .completeFileProtectionUntilFirstUserAuthentication)
```

### Keychain vs File System

| Data Type              | Storage                  | Protection                                     |
| ---------------------- | ------------------------ | ---------------------------------------------- |
| Passwords              | Keychain                 | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| OAuth Tokens           | Keychain                 | `kSecAttrAccessibleWhenUnlocked`               |
| Encryption Keys        | Keychain                 | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| User Documents         | File System              | `.completeFileProtection`                      |
| Temporary Cache        | File System (tmp)        | `.completeFileProtectionUntilFirstUserAuthentication` |
| Configuration Files    | File System (App Support)| `.completeFileProtection`                      |

## SQL Injection Prevention (Swift)

### Parameterized Queries (SQLite.swift)

```swift
// DO: Parameterized query
let stmt = try db.prepare("SELECT * FROM users WHERE id = ?")
try stmt.run(userId)

// DON'T: String interpolation
let query = "SELECT * FROM users WHERE id = \(userId)"
try db.execute(query)
```

## Performance Considerations

### Scanner Execution Time

| Scanner     | Typical Duration (10k LOC) | CPU Usage |
| ----------- | -------------------------- | --------- |
| Semgrep     | 30-60s                     | Medium    |
| Trivy       | 10-20s                     | Low       |
| Gitleaks    | 5-15s                      | Low       |

### CI/CD Optimization

- Run scanners in parallel
- Cache Swift package dependencies
- Use incremental analysis for PRs
- Run full scans on main branch only

## References

- Apple Secure Coding Guide: https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/
- OWASP Mobile Security Testing Guide: https://github.com/OWASP/owasp-mstg
- Swift Package Manager Security: https://swift.org/package-manager/
