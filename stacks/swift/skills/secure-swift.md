# Secure Swift Development Skill

**Skill ID**: `secure-swift`
**Stack**: Swift
**Category**: Compiled Language Security
**Compliance**: OWASP Top 10, CWE Top 25

## Overview

This skill provides secure development guidance for Swift applications on iOS, macOS, watchOS, and tvOS platforms.

## Security Scanning Tools

| Tool      | Purpose           | Configuration                |
| --------- | ----------------- | ---------------------------- |
| Semgrep   | SAST              | `configs/.semgrep.yml`       |
| Trivy     | SCA               | `configs/trivy.yaml`         |
| Gitleaks  | Secret Detection  | Shared config                |

## Key Security Principles

### 1. Keychain Security

**DO:**
```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "user@example.com",
    kSecValueData as String: "secret".data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

**DON'T:**
```swift
// Missing kSecAttrAccessible protection class
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecValueData as String: "secret".data(using: .utf8)!
]
SecItemAdd(query as CFDictionary, nil)
```

### 2. App Transport Security (ATS)

**DO:**
```xml
<!-- Info.plist: Only allow specific exceptions -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
        </dict>
    </dict>
</dict>
```

**DON'T:**
```xml
<!-- Blanket ATS bypass -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

### 3. Logging Sensitive Data

**DO:**
```swift
import os.log
let log = OSLog(subsystem: "com.example.app", category: "auth")
os_log("Authentication successful for user ID: %{public}@", log: log, type: .info, userID)
```

**DON'T:**
```swift
// Logging sensitive data to console
print("Password: \(password)")
NSLog("Token: \(apiToken)")
```

### 4. Cryptographic Randomness

**DO:**
```swift
var bytes = [UInt8](repeating: 0, count: 32)
let result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
guard result == errSecSuccess else {
    fatalError("Failed to generate random bytes")
}
```

**DON'T:**
```swift
// Weak randomness for cryptographic purposes
let randomValue = arc4random()
```

### 5. URL Scheme Validation

**DO:**
```swift
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    guard let scheme = url.scheme, scheme == "myapp" else {
        return false
    }
    guard let host = url.host, ["auth", "profile"].contains(host) else {
        return false
    }
    // Process validated URL
    return true
}
```

**DON'T:**
```swift
// No validation of deep link scheme/host
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    UIApplication.shared.open(url)
    return true
}
```

### 6. Certificate Pinning

**DO:**
```swift
class PinnedURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let pinnedCertificateData = /* Load pinned certificate */
        // Validate server certificate against pinned certificate
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
```

### 7. Binary Protections

**DO:**
Enable in Xcode build settings:
- PIE (Position Independent Executable)
- Stack Canaries
- ARC (Automatic Reference Counting)
- Code Signing
- Hardened Runtime (macOS)

## Common Vulnerabilities

| CWE       | Vulnerability                 | Semgrep Rule ID                |
| --------- | ----------------------------- | ------------------------------ |
| CWE-798   | Hardcoded Credentials         | `swift-hardcoded-secret`       |
| CWE-311   | Missing Encryption            | `swift-insecure-keychain`      |
| CWE-532   | Sensitive Data in Logs        | `swift-nslog-sensitive-data`   |
| CWE-319   | Cleartext Transmission        | `swift-ats-bypass`             |
| CWE-939   | URL Scheme Injection          | `swift-unvalidated-url-scheme` |
| CWE-327   | Weak Cryptography             | `swift-weak-crypto`            |
| CWE-338   | Weak Random                   | `swift-insecure-random`        |
| CWE-89    | SQL Injection                 | `swift-sql-injection`          |
| CWE-732   | Incorrect Permissions         | `swift-file-permission-insecure`|
| CWE-79    | Cross-site Scripting (WebView)| `swift-webview-javascript-enabled`|

## Jailbreak Detection

```swift
func isJailbroken() -> Bool {
    #if targetEnvironment(simulator)
    return false
    #else
    let paths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt"
    ]
    for path in paths {
        if FileManager.default.fileExists(atPath: path) {
            return true
        }
    }
    return false
    #endif
}
```

## Data Protection API

```swift
// File protection levels
try data.write(to: fileURL, options: .completeFileProtection)
// .completeFileProtection - Only when device unlocked
// .completeFileProtectionUnlessOpen - Until first unlock
// .completeFileProtectionUntilFirstUserAuthentication - After boot
```

## CI/CD Integration

Use the provided pipelines:
- **Concourse**: `pipelines/concourse/pipeline.yml`
- **GitHub Actions**: `pipelines/github-actions/security.yml`

## References

- Apple Security Guide: https://support.apple.com/guide/security/
- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/
- Swift Security Best Practices: https://swift.org/security/
- CWE Top 25: https://cwe.mitre.org/top25/

## Tuning Guide

See `tuning.md` for scanner-specific tuning and false positive management.
