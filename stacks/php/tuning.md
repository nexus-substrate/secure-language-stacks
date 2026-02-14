# PHP Security Scanner Tuning Guide

## Overview

This guide helps tune security scanners for PHP projects, addressing false positives, framework-specific configurations, and optimization strategies.

## Common False Positives

### 1. File Inclusion in Frameworks

**Issue:** Semgrep flags framework routing includes as LFI.

**Framework pattern (Laravel):**
```php
// routes/web.php - Safe pattern
Route::get('/{locale}', function ($locale) {
    return view("pages.{$locale}.home");
});
```

**Tuning:**
```yaml
# .semgrep.yml - Exclude framework directories
paths:
  exclude:
    - routes/
    - config/
    - vendor/
```

### 2. ORM Query Builder Raw Statements

**Issue:** Flagged as SQL injection when used safely with constants.

**Safe pattern:**
```php
// Safe - no user input
DB::table('users')->select(DB::raw('COUNT(*) as total'));

// Unsafe - has user input
DB::table('users')->whereRaw("status = '$status'");  // Flag this
```

**Tuning:**
```yaml
# .semgrep.yml
rules:
  - id: php-sql-injection-raw
    pattern: DB::raw("..." + $VAR + "...")
    message: SQL injection in raw query with user input
    # Don't flag DB::raw with only string literals
```

### 3. Echo with Framework Helpers

**Issue:** XSS warnings for output functions that auto-escape.

**Safe pattern (Laravel Blade):**
```blade
{{-- Auto-escaped --}}
{{ $user->name }}

{{-- Raw output - should be flagged --}}
{!! $user->bio !!}
```

**Tuning:**
```yaml
# Exclude Blade templates from echo rule
paths:
  exclude:
    - resources/views/
```

### 4. Type Juggling in Tests

**Issue:** Loose comparison in test assertions.

**Safe pattern:**
```php
// tests/UserTest.php - Often uses loose comparison intentionally
$this->assertEquals(200, $response->status());  // May use ==
```

**Tuning:**
```yaml
paths:
  exclude:
    - tests/
    - Test/
```

## Framework-Specific Tuning

### Laravel

**Common false positives:**
```yaml
# .semgrep.yml
rules:
  - id: laravel-safe-patterns
    pattern-not:
      # Mass assignment with validated input is safe
      - pattern: $MODEL->create($request->validated())
      - pattern: $MODEL->fill($request->validated())

      # Eloquent query builder auto-escapes
      - pattern: DB::table($TABLE)->where($COLUMN, $VALUE)
      - pattern: Model::where($COLUMN, $VALUE)
```

**PHPStan adjustments:**
```neon
# phpstan.neon
parameters:
    excludePaths:
        - database/migrations/*
        - database/seeders/*
        - bootstrap/cache/*
        - storage/*

    # Ignore Eloquent magic methods
    ignoreErrors:
        - '#Call to an undefined method Illuminate\\Database#'
        - '#Property .* does not accept#'
```

### WordPress

**Common false positives:**
```yaml
# .semgrep.yml
rules:
  - id: wordpress-safe-db
    pattern-not:
      # wpdb->prepare is safe
      - pattern: $wpdb->prepare(...)

      # Sanitization functions
      - pattern: sanitize_text_field(...)
      - pattern: sanitize_email(...)
```

**PHPStan:**
```neon
# phpstan.neon
parameters:
    bootstrapFiles:
        - wordpress-stubs.php  # Install via composer: php-stubs/wordpress-stubs

    excludePaths:
        - wp-content/plugins/vendor/*
        - wp-content/themes/vendor/*
```

### Symfony

**Doctrine ORM tuning:**
```yaml
# .semgrep.yml
rules:
  - id: symfony-doctrine-safe
    pattern-not:
      # Doctrine DQL with parameter binding
      - pattern: $query->setParameter(...)

      # Query builder
      - pattern: $qb->where($qb->expr()->eq(...))
```

## PHPStan Level Recommendations

**Project maturity levels:**

| Project Stage        | PHPStan Level | Rationale                                    |
| -------------------- | ------------- | -------------------------------------------- |
| New project          | 8             | Start strict, enforce from day one           |
| Legacy migration     | 4             | Baseline, incrementally increase             |
| Open source library  | 8             | Strict types, no magic                       |
| WordPress plugin     | 6             | Balance strictness with WP globals           |
| Laravel application  | 7             | Framework magic, but strict business logic   |
| Production critical  | 8             | Maximum type safety                          |

**Baseline for legacy code:**
```bash
# Generate baseline to ignore existing errors
./vendor/bin/phpstan analyse --generate-baseline

# phpstan.neon
includes:
    - phpstan-baseline.neon

# Fix new code first, gradually reduce baseline
```

## Semgrep Performance Optimization

**Large codebases (1M+ lines):**
```yaml
# .semgrep.yml
rules:
  - id: performance-optimized
    options:
      # Use specific languages
      languages: [php]

      # Limit depth
      max_target_bytes: 500000

      # Incremental scanning
      baseline_commit: main
```

**Exclude vendor dependencies:**
```yaml
paths:
  exclude:
    - vendor/
    - node_modules/
    - bootstrap/cache/
    - storage/framework/
```

## Trivy Tuning

**Ignore development dependencies in production scans:**
```yaml
# trivy.yaml
ignore-dev-dependencies: true

vulnerability:
  ignore-unfixed: true  # Focus on fixable issues
```

**Suppress known false positives:**
```yaml
# .trivyignore
CVE-2023-XXXXX  # False positive for internal package
```

## Composer Audit Tuning

**Ignore abandoned packages (if unavoidable):**
```bash
# composer.json
{
  "config": {
    "allow-plugins": {
      "abandoned/package": true
    }
  }
}
```

**Audit only production dependencies:**
```bash
composer audit --no-dev --format=json
```

## Security-Specific Patterns

### Magic Hashes

**High-risk authentication code:**
```yaml
# .semgrep.yml
rules:
  - id: magic-hash-risk
    patterns:
      - pattern: |
          if ($hash == $provided) { ... }
      - pattern-inside: |
          function login(...) { ... }
    message: Use hash_equals() to prevent magic hash bypass
    severity: ERROR
```

### WordPress SQL Injection

**WordPress-specific patterns:**
```yaml
rules:
  - id: wordpress-sql-injection
    patterns:
      - pattern-either:
          - pattern: $wpdb->query("..." . $VAR . "...")
          - pattern: $wpdb->get_results("..." . $VAR . "...")
      - pattern-not-inside: $wpdb->prepare(...)
    message: Use $wpdb->prepare() for queries
```

### Laravel Route Model Binding

**Safe implicit binding (not SQL injection):**
```php
// Route model binding is safe - Eloquent handles it
Route::get('/users/{user}', function (User $user) {
    return $user;  // Safe - no SQL injection
});
```

**Tuning:**
```yaml
# Exclude route files from SQL injection rules
paths:
  exclude:
    - routes/web.php
    - routes/api.php
```

## Performance Benchmarks

**Scan times (example 100k LOC Laravel app):**

| Scanner        | Time (default) | Time (tuned) | Findings (default) | Findings (tuned) |
| -------------- | -------------- | ------------ | ------------------ | ---------------- |
| Semgrep        | 45s            | 18s          | 127                | 34               |
| PHPStan        | 90s            | 60s          | 523                | 89               |
| Trivy          | 12s            | 8s           | 67                 | 23               |
| Composer Audit | 3s             | 2s           | 12                 | 4                |

**Tuning steps:**
1. Exclude vendor/tests directories
2. Use specific rule sets (not `p/security-audit` catch-all)
3. Enable PHPStan result cache
4. Run Trivy with `--ignore-unfixed`

## CI/CD Integration

**Fail-fast strategy:**
```yaml
# .github/workflows/security.yml
jobs:
  quick-scan:
    # Run fastest scanners first
    steps:
      - gitleaks (3s)
      - composer audit (2s)

  deep-scan:
    needs: quick-scan
    steps:
      - semgrep (18s)
      - phpstan (60s)
      - trivy (8s)
```

**Progressive enforcement:**
```bash
# Week 1: Warning only
semgrep --severity ERROR --config=... || true

# Week 2: Block HIGH+
semgrep --severity HIGH,CRITICAL --config=... || exit 1

# Week 3: Block all
semgrep --config=... || exit 1
```

## Baseline Management

**PHPStan baseline workflow:**
```bash
# 1. Generate baseline (first run)
phpstan analyse --generate-baseline

# 2. Fix new violations only
phpstan analyse  # Ignores baseline errors

# 3. Reduce baseline monthly
phpstan analyse --generate-baseline  # Regenerate with fewer errors
```

**Semgrep baseline:**
```bash
# Generate baseline
semgrep --config=... --baseline

# Run against baseline
semgrep --config=... --baseline-commit=main
```

## False Negative Reduction

**Increase coverage for critical paths:**
```yaml
# High-security modules - stricter rules
rules:
  - id: auth-strict-checks
    paths:
      include:
        - app/Http/Controllers/Auth/
        - app/Services/Payment/
    options:
      max_depth: 10  # Deeper analysis
      strict_mode: true
```

## Known Limitations

### Semgrep
- **Dynamic property access:** Cannot track `$obj->$prop`
- **Magic methods:** Misses `__call()` vulnerabilities
- **Complex data flow:** Limited taint tracking

**Mitigation:** Combine with PHPStan for type-level checks.

### PHPStan
- **Reflection usage:** Cannot analyze `call_user_func()`
- **Framework magic:** May flag safe framework patterns
- **Dynamic configuration:** Cannot track config-driven behavior

**Mitigation:** Use baseline + Semgrep for injection patterns.

### Trivy
- **Unpatched CVEs:** Reports unfixable vulnerabilities
- **Indirect dependencies:** May miss nested risks

**Mitigation:** Use `--ignore-unfixed`, combine with Composer audit.

## Recommended Tuning Workflow

1. **Baseline establishment (Week 1):**
   - Run all scanners with defaults
   - Generate baselines (PHPStan, Semgrep)
   - Document false positives

2. **Exclude configuration (Week 2):**
   - Add `vendor/`, `tests/` to exclusions
   - Framework-specific ignores (routes, migrations)
   - Review and categorize findings

3. **Rule refinement (Week 3):**
   - Disable low-value rules
   - Tune severity thresholds
   - Add custom framework patterns

4. **CI integration (Week 4):**
   - Fail on HIGH/CRITICAL only
   - Progressive enforcement schedule
   - Scheduled full scans (weekly)

5. **Continuous improvement (Ongoing):**
   - Monthly baseline review
   - Quarterly rule updates
   - Track false positive rate (target <5%)

## Metrics

**Track scanner effectiveness:**
```bash
# False positive rate
FPR = (False Positives) / (Total Findings) * 100

# Coverage
Coverage = (Lines Scanned) / (Total Lines) * 100

# Mean time to remediate
MTTR = (Time to Fix) / (True Positives)
```

**Target KPIs:**
- FPR < 5%
- Coverage > 95% (excluding vendor)
- MTTR < 24 hours (HIGH/CRITICAL)
- Zero HIGH+ findings in production

## Resources
- [Semgrep PHP Rules](https://semgrep.dev/r?lang=php)
- [PHPStan Rule Levels](https://phpstan.org/user-guide/rule-levels)
- [Trivy PHP Support](https://aquasecurity.github.io/trivy/latest/docs/scanner/vulnerability/)
- [OWASP PHP Security](https://owasp.org/www-project-php-security/)
