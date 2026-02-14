# Secure PHP Development

**Skill:** secure-php
**Category:** language-security
**Stack:** PHP
**Expertise:** Security-first PHP development with OWASP compliance

## Overview

This skill guides secure PHP development practices, covering common vulnerabilities, framework-specific security (Laravel, Symfony, WordPress), and compliance with OWASP Top 10 and CWE Top 25.

## Critical PHP Security Risks

### 1. SQL Injection (CWE-89)
**Risk:** Unsanitized user input in SQL queries enables database manipulation.

**Vulnerable Code:**
```php
// NEVER DO THIS
$userId = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $userId";
$result = mysqli_query($conn, $query);
```

**Secure Code:**
```php
// Use prepared statements with parameterized queries
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$result = $stmt->get_result();
```

**Laravel ORM (Eloquent):**
```php
// Eloquent automatically uses prepared statements
$user = User::where('id', $userId)->first();

// Query Builder
$user = DB::table('users')->where('id', $userId)->first();

// AVOID DB::raw with user input
// NEVER: DB::raw("... $userInput ...")
```

### 2. Cross-Site Scripting (XSS) (CWE-79)
**Risk:** Unescaped output allows malicious scripts to execute in user browsers.

**Vulnerable Code:**
```php
echo $_GET['name'];  // NEVER
echo "<div>$userInput</div>";  // NEVER
```

**Secure Code:**
```php
// Always escape output
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// Laravel Blade (auto-escapes)
{{ $name }}  // Safe

// Raw output (use ONLY for trusted content)
{!! $trustedHtml !!}  // Dangerous if not validated
```

**Content Security Policy:**
```php
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```

### 3. Local/Remote File Inclusion (LFI/RFI) (CWE-98)
**Risk:** Attacker can include arbitrary files, leading to code execution.

**Vulnerable Code:**
```php
// NEVER DO THIS
$page = $_GET['page'];
include($page . '.php');

// Remote file inclusion
$url = $_GET['url'];
include($url);
```

**Secure Code:**
```php
// Use allowlist validation
$allowedPages = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';

if (!in_array($page, $allowedPages, true)) {
    $page = 'home';
}

include(__DIR__ . '/pages/' . $page . '.php');

// Disable remote file inclusion in php.ini
// allow_url_fopen = Off
// allow_url_include = Off
```

### 4. Object Injection (CWE-502)
**Risk:** `unserialize()` on untrusted data can trigger magic methods and lead to RCE.

**Vulnerable Code:**
```php
// NEVER DO THIS
$data = unserialize($_COOKIE['data']);
```

**Secure Code:**
```php
// Use JSON instead
$data = json_decode($_COOKIE['data'], true);

// If you MUST use unserialize, restrict allowed classes
$data = unserialize($input, ['allowed_classes' => ['MyClass']]);

// Or verify integrity with HMAC
$hmac = hash_hmac('sha256', $serialized, $secret);
if (hash_equals($hmac, $providedHmac)) {
    $data = unserialize($serialized);
}
```

**Laravel signed serialization:**
```php
// Encrypt and sign
$encrypted = encrypt($data);

// Decrypt (throws exception if tampered)
$data = decrypt($encrypted);
```

### 5. Command Injection (CWE-78)
**Risk:** User input in shell commands allows arbitrary command execution.

**Vulnerable Code:**
```php
// NEVER DO THIS
$file = $_GET['file'];
system("cat $file");
exec("ping -c 1 $host");
```

**Secure Code:**
```php
// AVOID shell commands entirely - use PHP functions
$content = file_get_contents($file);

// If shell commands are unavoidable, use escapeshellarg()
$file = escapeshellarg($_GET['file']);
exec("cat $file", $output, $returnCode);

// Better: use allowlist
$allowedCommands = ['start', 'stop', 'status'];
$cmd = $_GET['cmd'];
if (in_array($cmd, $allowedCommands, true)) {
    exec("/usr/bin/service myapp $cmd");
}
```

### 6. Type Juggling (CWE-697)
**Risk:** PHP's loose comparison can cause authentication bypasses (e.g., magic hashes).

**Vulnerable Code:**
```php
// NEVER USE == for security checks
if ($_POST['password'] == $hashedPassword) {
    // Login - BYPASSED by "0e" magic hashes
}

// Magic hash bypass
// "0e123" == "0e456" evaluates to true (both are scientific notation for 0)
```

**Secure Code:**
```php
// ALWAYS use strict comparison (===)
if (hash_equals($expectedHash, $providedHash)) {
    // Login
}

// Use password_verify for password checks
if (password_verify($_POST['password'], $hashedPassword)) {
    // Login
}

// Strict array search
if (in_array($value, $array, true)) {  // Third parameter = strict
    // Process
}
```

**Magic Hash Prevention:**
```php
// NEVER compare hashes with ==
// md5('240610708') == md5('QNKCDZO')  // Both start with "0e", evaluate to 0

// Use hash_equals() or password_verify()
```

### 7. Session Security (CWE-384, CWE-598)
**Risk:** Session fixation, hijacking, or prediction.

**Secure Session Configuration:**
```php
// Regenerate session ID on privilege changes
session_start();
session_regenerate_id(true);  // Delete old session

// Secure session configuration
ini_set('session.cookie_httponly', '1');  // Prevent JavaScript access
ini_set('session.cookie_secure', '1');    // HTTPS only
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1'); // No session ID in URL

// Custom session settings
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '.example.com',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

**Laravel session security:**
```php
// config/session.php
'secure' => env('SESSION_SECURE_COOKIE', true),
'http_only' => true,
'same_site' => 'strict',
```

### 8. Cryptography (CWE-327, CWE-330)
**Risk:** Weak hashing or random number generation.

**Vulnerable Code:**
```php
// NEVER use weak hash functions for passwords
$hash = md5($password);
$hash = sha1($password);

// NEVER use weak random for security
$token = md5(uniqid(rand(), true));
```

**Secure Code:**
```php
// Password hashing
$hash = password_hash($password, PASSWORD_ARGON2ID);

// Password verification
if (password_verify($inputPassword, $hash)) {
    // Check if rehash needed (algorithm/cost changed)
    if (password_needs_rehash($hash, PASSWORD_ARGON2ID)) {
        $newHash = password_hash($inputPassword, PASSWORD_ARGON2ID);
        // Update database
    }
}

// Cryptographically secure random
$token = bin2hex(random_bytes(32));

// HMAC for data integrity
$hmac = hash_hmac('sha256', $data, $secret);
```

### 9. Path Traversal (CWE-22)
**Risk:** Attacker accesses files outside intended directory.

**Vulnerable Code:**
```php
// NEVER DO THIS
$file = $_GET['file'];
$content = file_get_contents("/var/www/uploads/$file");
```

**Secure Code:**
```php
// Use realpath() and validate base directory
$baseDir = '/var/www/uploads/';
$requestedFile = $_GET['file'];

$fullPath = realpath($baseDir . $requestedFile);

// Ensure file is within base directory
if ($fullPath === false || strpos($fullPath, $baseDir) !== 0) {
    die('Invalid file path');
}

$content = file_get_contents($fullPath);
```

### 10. Open Redirect (CWE-601)
**Risk:** Attacker redirects users to malicious sites via trusted domain.

**Vulnerable Code:**
```php
// NEVER DO THIS
header("Location: " . $_GET['redirect']);
```

**Secure Code:**
```php
// Use allowlist
$allowedRedirects = ['/home', '/profile', '/dashboard'];
$redirect = $_GET['redirect'] ?? '/home';

if (!in_array($redirect, $allowedRedirects, true)) {
    $redirect = '/home';
}

header("Location: $redirect");

// Or validate internal URLs
$parsedUrl = parse_url($redirect);
if (isset($parsedUrl['host']) && $parsedUrl['host'] !== $_SERVER['HTTP_HOST']) {
    die('External redirects not allowed');
}
```

## Framework-Specific Security

### Laravel Security Checklist

**1. Mass Assignment Protection:**
```php
// Model definition
class User extends Model {
    // Allow only these fields
    protected $fillable = ['name', 'email'];

    // OR block these fields
    protected $guarded = ['is_admin', 'role'];
}

// NEVER use create() with all input
User::create($request->all());  // DANGEROUS

// Use validated input
User::create($request->validated());
```

**2. CSRF Protection:**
```blade
{{-- Blade templates auto-include CSRF token --}}
<form method="POST" action="/profile">
    @csrf
    {{-- ... --}}
</form>
```

**3. SQL Injection Prevention:**
```php
// Eloquent/Query Builder auto-escapes
DB::table('users')->where('email', $email)->get();  // Safe

// NEVER concatenate user input
DB::raw("SELECT * WHERE email = '$email'");  // DANGEROUS
```

**4. Authorization (Policies):**
```php
// Define policy
class PostPolicy {
    public function update(User $user, Post $post) {
        return $user->id === $post->user_id;
    }
}

// Use in controller
$this->authorize('update', $post);
```

### WordPress Security Checklist

**1. Nonce Validation:**
```php
// Generate nonce
wp_nonce_field('my_action', 'my_nonce');

// Verify nonce
if (!isset($_POST['my_nonce']) || !wp_verify_nonce($_POST['my_nonce'], 'my_action')) {
    die('Security check failed');
}
```

**2. Data Sanitization:**
```php
// Sanitize input
$name = sanitize_text_field($_POST['name']);
$email = sanitize_email($_POST['email']);
$url = esc_url_raw($_POST['url']);

// Escape output
echo esc_html($name);
echo esc_url($url);
echo esc_attr($attribute);
```

**3. Prepared Statements:**
```php
global $wpdb;

// Use prepare()
$results = $wpdb->get_results(
    $wpdb->prepare("SELECT * FROM $wpdb->posts WHERE post_author = %d", $authorId)
);
```

**4. Capability Checks:**
```php
if (!current_user_can('edit_posts')) {
    wp_die('Unauthorized');
}
```

### Symfony Security Checklist

**1. Parameterized Queries (Doctrine):**
```php
// Use parameter binding
$query = $entityManager->createQuery(
    'SELECT u FROM User u WHERE u.email = :email'
);
$query->setParameter('email', $email);
```

**2. CSRF Protection:**
```php
// Form with CSRF token
$form = $this->createFormBuilder()
    ->add('task', TextType::class)
    ->add('save', SubmitType::class)
    ->getForm();
```

**3. Output Escaping (Twig):**
```twig
{# Auto-escapes by default #}
{{ user.name }}

{# Raw output (dangerous) #}
{{ user.bio|raw }}
```

## PHP Configuration Hardening

**php.ini security settings:**
```ini
# Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

# Hide PHP version
expose_php = Off

# Disable remote file access
allow_url_fopen = Off
allow_url_include = Off

# Error handling (production)
display_errors = Off
log_errors = On
error_log = /var/log/php/error.log

# Session security
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
session.use_only_cookies = 1

# Upload limits
upload_max_filesize = 2M
post_max_size = 8M

# Open basedir restriction
open_basedir = /var/www/html:/tmp
```

## Compliance

### OWASP Top 10 Coverage
- A01:2021 – Broken Access Control: Authorization checks, path traversal prevention
- A02:2021 – Cryptographic Failures: Strong hashing, secure random
- A03:2021 – Injection: SQL injection, command injection, XSS prevention
- A04:2021 – Insecure Design: Type juggling prevention, strict comparison
- A05:2021 – Security Misconfiguration: php.ini hardening, error handling
- A06:2021 – Vulnerable Components: Composer audit, dependency scanning
- A07:2021 – Authentication Failures: Password hashing, session security
- A08:2021 – Software Integrity Failures: Object injection prevention
- A09:2021 – Logging Failures: Error logging configuration
- A10:2021 – SSRF: URL validation, allowlisting

### CWE Top 25 Coverage
Key CWEs addressed: 22, 78, 79, 89, 98, 327, 330, 384, 502, 601, 697, 798, 915

## Security Scanning Integration

**Run all scans:**
```bash
# SAST - Semgrep
semgrep scan --config=stacks/php/configs/.semgrep.yml .

# SAST - PHPStan
./vendor/bin/phpstan analyse --configuration=stacks/php/configs/phpstan.neon

# SCA - Trivy
trivy fs --config=stacks/php/configs/trivy.yaml .

# SCA - Composer Audit
composer audit --format=json

# Secrets
gitleaks detect --source=. --verbose
```

## Quick Reference

| Vulnerability       | Secure Practice                               |
| ------------------- | --------------------------------------------- |
| SQL Injection       | Prepared statements, ORM                      |
| XSS                 | htmlspecialchars(), framework escaping        |
| File Inclusion      | Allowlist, realpath(), disable allow_url_*    |
| Object Injection    | Avoid unserialize(), use JSON                 |
| Command Injection   | Avoid shell, escapeshellarg(), allowlist      |
| Type Juggling       | Strict comparison (===), hash_equals()        |
| Session Issues      | Regenerate ID, secure cookies, httponly       |
| Weak Crypto         | password_hash(), random_bytes()               |
| Path Traversal      | realpath(), base directory validation         |
| Open Redirect       | Allowlist, parse_url() validation             |
| Hardcoded Secrets   | Environment variables, .env files             |
| Mass Assignment     | $fillable, $guarded (Laravel)                 |
| CSRF                | Framework tokens (@csrf in Laravel)           |
| Missing AuthZ       | Policies, capability checks                   |

## Resources
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [Laravel Security Best Practices](https://laravel.com/docs/security)
- [WordPress Security Hardening](https://wordpress.org/support/article/hardening-wordpress/)
- [Symfony Security](https://symfony.com/doc/current/security.html)
