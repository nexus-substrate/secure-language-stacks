# Ruby Security Scanner Tuning Guide

This guide provides tuning recommendations for Ruby security scanners to reduce false positives and improve detection accuracy.

## Common Ruby Security Vulnerabilities

### 1. Rails-Specific Issues

#### Mass Assignment
**Risk:** Attackers modify unintended model attributes via form parameters.

**Detection Pattern:**
```ruby
# Vulnerable
User.create(params[:user])
User.update(params[:user])
User.new(params[:user])
```

**Mitigation:**
- Always use strong parameters with `permit`/`require`
- Enable `config.active_record.mass_assignment_sanitizer = :strict`
- Use `attr_accessible` or `attr_protected` in older Rails versions

**False Positive Scenarios:**
- Internal admin controllers with trusted input
- Test fixtures and factories
- Background job parameters

#### CSRF Token Bypass
**Risk:** Cross-site request forgery attacks on state-changing operations.

**Detection Pattern:**
```ruby
# Vulnerable
protect_from_forgery with: :null_session
skip_before_action :verify_authenticity_token
protect_from_forgery except: [:create, :update]
```

**Mitigation:**
- Use `protect_from_forgery with: :exception` (default in Rails 5+)
- Only skip CSRF for stateless API endpoints with token auth
- Use `protect_from_forgery with: :reset_session` for API controllers

**False Positive Scenarios:**
- JSON API endpoints with JWT/OAuth authentication
- Webhooks from external services
- Public read-only endpoints

#### SQL Injection in ActiveRecord
**Risk:** Unsafe interpolation allows database manipulation.

**Detection Pattern:**
```ruby
# Vulnerable
User.where("email = '#{params[:email]}'")
User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
```

**Mitigation:**
- Use parameterized queries: `where("email = ?", email)`
- Use hash conditions: `where(email: params[:email])`
- Use Arel for complex queries
- Sanitize with `ActiveRecord::Base.connection.quote`

**False Positive Scenarios:**
- Static SQL strings without interpolation
- SQL fragments from trusted configuration files
- Queries built with `Arel` or `sanitize_sql_array`

### 2. Unsafe Deserialization

#### Marshal.load
**Risk:** Remote code execution via crafted serialized objects.

**Detection Pattern:**
```ruby
# Vulnerable
Marshal.load(cookies[:session])
Marshal.restore(params[:data])
```

**Mitigation:**
- **Never** deserialize untrusted data with Marshal
- Use JSON for external data
- Use MessagePack for internal serialization
- Sign/encrypt serialized data with `ActiveSupport::MessageVerifier`

**False Positive Scenarios:**
- Deserialization of self-generated cache data
- Internal background job arguments (with proper signing)

#### YAML.load
**Risk:** Arbitrary code execution via YAML tags.

**Detection Pattern:**
```ruby
# Vulnerable
YAML.load(File.read(params[:config]))
YAML.load(request.body.read)
```

**Mitigation:**
- Use `YAML.safe_load` with `permitted_classes` allowlist
- Use `JSON.parse` for external data
- Validate YAML structure before parsing

**Secure Example:**
```ruby
YAML.safe_load(
  data,
  permitted_classes: [Symbol, Date, Time],
  permitted_symbols: [],
  aliases: false
)
```

**False Positive Scenarios:**
- Loading from version-controlled config files
- Parsing trusted fixture data in tests

### 3. ERB Template Injection

#### html_safe and raw
**Risk:** XSS attacks via unescaped user content.

**Detection Pattern:**
```ruby
# Vulnerable
<%= user_content.html_safe %>
<%= raw(params[:message]) %>
```

**Mitigation:**
- Never mark user input as `html_safe`
- Use `sanitize` with explicit tag allowlist
- Default ERB escaping (`<%= %>`) for all user content
- Use `content_tag` helpers for dynamic HTML

**Secure Example:**
```ruby
<%= sanitize(user_bio, tags: %w[p br strong em], attributes: %w[href]) %>
```

**False Positive Scenarios:**
- Rendering pre-sanitized content from database
- Admin-authored content from trusted CMS
- HTML from gem-provided helpers (e.g., `simple_format`)

### 4. Open Redirect

**Risk:** Phishing attacks via attacker-controlled redirect targets.

**Detection Pattern:**
```ruby
# Vulnerable
redirect_to params[:return_to]
redirect_to request.referer
redirect_to params[:url] if params[:url].start_with?("http")
```

**Mitigation:**
- Validate URLs against allowlist of domains
- Use path-only redirects when possible
- Check URL scheme and host explicitly

**Secure Example:**
```ruby
ALLOWED_HOSTS = ['example.com', 'app.example.com'].freeze

def safe_redirect(url)
  uri = URI.parse(url)
  if uri.relative? || ALLOWED_HOSTS.include?(uri.host)
    redirect_to url
  else
    redirect_to root_path, alert: "Invalid redirect"
  end
rescue URI::InvalidURIError
  redirect_to root_path
end
```

**False Positive Scenarios:**
- Redirects to static internal paths
- OAuth callback URLs (when validated properly)

### 5. File Upload Vulnerabilities

#### Unrestricted File Upload
**Risk:** Malicious file execution, storage exhaustion, path traversal.

**Detection Pattern:**
```ruby
# Vulnerable
File.write("uploads/#{params[:filename]}", params[:file].read)
send_file params[:path]
```

**Mitigation:**
- Validate file extensions and MIME types
- Store uploads outside web root
- Generate random filenames
- Limit file size
- Scan uploaded files with antivirus
- Use dedicated storage services (S3, CloudFiles)

**Secure Example:**
```ruby
ALLOWED_EXTENSIONS = %w[.jpg .jpeg .png .pdf].freeze
MAX_FILE_SIZE = 10.megabytes

def validate_upload(file)
  ext = File.extname(file.original_filename).downcase

  unless ALLOWED_EXTENSIONS.include?(ext)
    return { error: "Invalid file type" }
  end

  if file.size > MAX_FILE_SIZE
    return { error: "File too large" }
  end

  # Validate MIME type
  unless file.content_type.in?(%w[image/jpeg image/png application/pdf])
    return { error: "Invalid content type" }
  end

  { success: true }
end
```

**False Positive Scenarios:**
- Admin file uploads with authentication
- Internal document processing systems

### 6. Regular Expression DoS (ReDoS)

**Risk:** CPU exhaustion via malicious input to catastrophic backtracking regex.

**Detection Pattern:**
```ruby
# Vulnerable
/^(a+)+$/.match(user_input)
/(.*)*/.match(params[:query])
/(a|a)*b/.match(request_data)
```

**Mitigation:**
- Avoid nested quantifiers: `(a+)+`, `(.*)*`
- Use possessive quantifiers: `(?>...)`
- Set regex timeout limits
- Use simpler patterns when possible
- Test regex with tools like [regex101.com](https://regex101.com/)

**Secure Example:**
```ruby
require 'timeout'

def safe_regex_match(pattern, input, timeout: 1)
  Timeout.timeout(timeout) do
    pattern.match(input)
  end
rescue Timeout::Error
  Rails.logger.warn "Regex timeout on input: #{input[0..100]}"
  nil
end

# Or use simpler patterns
/^[a-z0-9_-]+$/.match(username)  # Instead of /^([a-z]+)+$/
```

**False Positive Scenarios:**
- Simple patterns without nesting: `/\d+/`, `/[a-z]+/`
- Anchored patterns with limited scope

## Scanner-Specific Tuning

### Semgrep

**High False Positive Areas:**
1. **Test files** - Add to skip list if not testing security
2. **Generated code** - Skip `db/schema.rb`, `vendor/`, `node_modules/`
3. **Internal admin tools** - May have relaxed security controls

**Configuration:**
```yaml
# .semgrep.yml
rules:
  - id: sql-injection
    paths:
      exclude:
        - "test/**"
        - "spec/**"
        - "db/schema.rb"
```

**Recommended Rulesets:**
- `p/ruby` - General Ruby security
- `p/rails` - Rails framework-specific
- `p/owasp-top-ten` - OWASP coverage
- `p/security-audit` - Comprehensive security

### Brakeman

**Configuration Tuning:**
```yaml
# brakeman.yml
ignore_file: config/brakeman.ignore
min_confidence: 2  # 1=high, 2=medium, 3=weak

skip_checks:
  # Disable if not applicable
  - SymbolDoS  # If on Ruby 2.2+
  - I18nXSS    # If not using Rails i18n

skip_files:
  - lib/legacy/**/*
  - vendor/**/*
```

**Common False Positives:**
- **Mass Assignment** in admin controllers
- **SQL Injection** with `sanitize_sql_array`
- **Redirect** to internal paths
- **File Access** from configuration

**Ignore Example:**
```yaml
# config/brakeman.ignore
---
:warnings:
- :warning_type: MassAssignment
  :fingerprint: abc123def456
  :note: "Admin controller with authentication"
```

### Trivy

**Gemfile.lock Scanning:**
```yaml
# trivy.yaml
vulnerability:
  ignore-unfixed: false  # Report all vulns, not just fixed

ignore:
  cves:
    # Example: ignore if upgrade breaks compatibility
    - CVE-2023-XXXXX
```

**Common Issues:**
- **Dev dependencies** - Consider excluding with `--skip-files Gemfile`
- **Transitive deps** - May require gem updates or Bundler resolution
- **Old Rails versions** - Upgrade path may be complex

### Bundler Audit

**Configuration:**
```yaml
# .bundler-audit.yml
ignore:
  # Ignore specific advisories
  - CVE-2023-XXXXX  # Reason: not exploitable in our context
```

**Workflow:**
1. Run `bundle-audit update` regularly
2. Check for vulnerabilities: `bundle-audit check`
3. Update vulnerable gems: `bundle update <gem>`
4. Document ignored issues in project README

## False Positive Reduction Strategies

### 1. Context-Aware Rules
- Differentiate between admin and public controllers
- Account for authentication/authorization wrappers
- Recognize framework-provided sanitization

### 2. Path-Based Exclusions
```yaml
exclude:
  - test/**/*
  - spec/**/*
  - vendor/**/*
  - db/schema.rb
  - config/initializers/**/*
```

### 3. Confidence Thresholds
- Start with high confidence findings
- Gradually lower threshold as false positives are tuned
- Document exceptions with business justification

### 4. Developer Training
- Educate team on secure coding patterns
- Establish code review guidelines
- Create internal secure coding standards

## Compliance Mapping

### OWASP Top 10 2021 Coverage

| OWASP Category | Ruby Vulnerability | Scanner |
|----------------|-------------------|---------|
| A01: Broken Access Control | Mass Assignment, Open Redirect | Brakeman, Semgrep |
| A02: Cryptographic Failures | Weak Hash (MD5/SHA1) | Semgrep |
| A03: Injection | SQL Injection, Command Injection, ERB Injection | Semgrep, Brakeman |
| A04: Insecure Design | CSRF Bypass | Brakeman |
| A05: Security Misconfiguration | CSRF Disabled, Debug Mode | Brakeman |
| A06: Vulnerable Components | Gem Vulnerabilities | Trivy, Bundler Audit |
| A07: Authentication Failures | Weak Session Config, Hardcoded Secrets | Semgrep, Gitleaks |
| A08: Data Integrity Failures | Unsafe Deserialization (Marshal, YAML) | Semgrep, Brakeman |
| A09: Logging Failures | (Manual review) | - |
| A10: SSRF | HTTP Request with User Input | Semgrep |

### CWE Top 25 Coverage

| CWE ID | Vulnerability | Scanner |
|--------|--------------|---------|
| CWE-89 | SQL Injection | Semgrep, Brakeman |
| CWE-79 | XSS | Semgrep, Brakeman |
| CWE-78 | OS Command Injection | Semgrep, Brakeman |
| CWE-22 | Path Traversal | Semgrep, Brakeman |
| CWE-352 | CSRF | Brakeman |
| CWE-502 | Deserialization | Semgrep, Brakeman |
| CWE-798 | Hardcoded Credentials | Gitleaks |
| CWE-327 | Weak Crypto | Semgrep |
| CWE-601 | Open Redirect | Semgrep, Brakeman |
| CWE-1333 | ReDoS | Semgrep |

## Continuous Improvement

1. **Baseline Establishment** - Document current finding count
2. **Regular Updates** - Keep scanner rules and databases current
3. **Feedback Loop** - Report false positives to scanner maintainers
4. **Metrics Tracking** - Monitor trends over time
5. **Integration Testing** - Verify fixes don't reintroduce issues

## References

- [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [OWASP Ruby on Rails Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html)
- [Brakeman Warning Types](https://brakemanscanner.org/docs/warning_types/)
- [Semgrep Ruby Registry](https://semgrep.dev/r?lang=ruby)
- [Bundler Audit Documentation](https://github.com/rubysec/bundler-audit)
- [Ruby Security Advisory Database](https://rubysec.com/)
