---
name: secure-ruby
description: Analyze Ruby codebases for security vulnerabilities using secure-language-stacks scanner configurations
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
context: fork
---

# Secure Ruby Analysis Skill

This skill analyzes Ruby codebases for security vulnerabilities using the secure-language-stacks Ruby scanner configurations.

## Capabilities

1. **SAST Analysis** - Semgrep and Brakeman static analysis
2. **SCA Scanning** - Trivy and Bundler Audit dependency analysis
3. **Secret Detection** - Gitleaks secret scanning
4. **Rails Security** - Framework-specific vulnerability detection
5. **Compliance Mapping** - OWASP Top 10 and CWE Top 25

## Usage

When analyzing Ruby projects:

1. **Identify project type** - Detect if Rails, Sinatra, Hanami, or Grape
2. **Run applicable scanners** - Execute framework-specific tools
3. **Prioritize findings** - Focus on CRITICAL/HIGH severity
4. **Provide remediation** - Offer secure code alternatives

## Common Ruby Security Issues

### 1. SQL Injection
**Vulnerable:**
```ruby
User.where("email = '#{params[:email]}'")
```

**Secure:**
```ruby
User.where(email: params[:email])
User.where("email = ?", params[:email])
```

### 2. Command Injection
**Vulnerable:**
```ruby
system("ping -c 1 #{params[:host]}")
```

**Secure:**
```ruby
system("ping", "-c", "1", params[:host])
require 'shellwords'
system("ping -c 1 #{Shellwords.escape(params[:host])}")
```

### 3. Mass Assignment
**Vulnerable:**
```ruby
User.create(params[:user])
```

**Secure:**
```ruby
User.create(user_params)

private
def user_params
  params.require(:user).permit(:name, :email)
end
```

### 4. Unsafe Deserialization
**Vulnerable:**
```ruby
Marshal.load(params[:data])
YAML.load(File.read(params[:file]))
```

**Secure:**
```ruby
JSON.parse(params[:data])
YAML.safe_load(File.read(params[:file]), permitted_classes: [Symbol, Date])
```

### 5. XSS in ERB
**Vulnerable:**
```ruby
<%= user_input.html_safe %>
<%= raw(params[:message]) %>
```

**Secure:**
```ruby
<%= sanitize(user_input, tags: %w[p br]) %>
<%= params[:message] %>  # Auto-escaped by default
```

### 6. Open Redirect
**Vulnerable:**
```ruby
redirect_to params[:url]
```

**Secure:**
```ruby
ALLOWED_DOMAINS = ['example.com', 'app.example.com']

def safe_redirect(url)
  uri = URI.parse(url)
  if uri.host.nil? || ALLOWED_DOMAINS.include?(uri.host)
    redirect_to url
  else
    redirect_to root_path
  end
end
```

### 7. Path Traversal
**Vulnerable:**
```ruby
File.read(params[:filename])
```

**Secure:**
```ruby
filename = File.basename(params[:filename])
safe_path = Rails.root.join('public', 'uploads', filename)
File.read(safe_path) if File.exist?(safe_path)
```

### 8. Weak Cryptography
**Vulnerable:**
```ruby
Digest::MD5.hexdigest(password)
Digest::SHA1.hexdigest(token)
```

**Secure:**
```ruby
require 'bcrypt'
BCrypt::Password.create(password)

# For tokens
require 'securerandom'
SecureRandom.hex(32)
```

### 9. CSRF Bypass
**Vulnerable:**
```ruby
class ApiController < ApplicationController
  protect_from_forgery with: :null_session
end
```

**Secure:**
```ruby
class ApiController < ApplicationController
  skip_before_action :verify_authenticity_token
  before_action :authenticate_api_token!

  private
  def authenticate_api_token!
    authenticate_or_request_with_http_token do |token, options|
      ActiveSupport::SecurityUtils.secure_compare(
        token,
        Rails.application.credentials.api_token
      )
    end
  end
end
```

### 10. Regular Expression DoS
**Vulnerable:**
```ruby
/^(a+)+$/.match(params[:input])
/(.*)*/.match(user_input)
```

**Secure:**
```ruby
require 'timeout'

def safe_match(pattern, input)
  Timeout.timeout(1) do
    pattern.match(input)
  end
rescue Timeout::Error
  nil
end

# Or use simpler patterns
/^[a-z]+$/.match(params[:input])
```

## Scanner Execution

### Semgrep SAST
```bash
semgrep scan \
  --config=stacks/ruby/configs/.semgrep.yml \
  --config=p/ruby \
  --config=p/rails \
  --json \
  --severity=ERROR \
  --severity=WARNING \
  .
```

### Brakeman (Rails)
```bash
brakeman \
  --config-file=stacks/ruby/configs/brakeman.yml \
  --format=json \
  --output=brakeman-results.json \
  .
```

### Trivy SCA
```bash
trivy fs \
  --config=stacks/ruby/configs/trivy.yaml \
  --format=json \
  --severity=CRITICAL,HIGH,MEDIUM \
  --scanners=vuln \
  .
```

### Bundler Audit
```bash
bundle-audit update
bundle-audit check --format json
```

### Gitleaks
```bash
gitleaks detect \
  --source=. \
  --report-format=json \
  --no-git
```

## Analysis Workflow

1. **Scan Execution** - Run all applicable scanners
2. **Finding Triage** - Categorize by severity and exploitability
3. **Deduplication** - Remove duplicate findings across tools
4. **Context Analysis** - Examine code context for false positives
5. **Remediation Plan** - Provide prioritized fix recommendations

## Output Format

Provide findings as:

```markdown
## Security Findings Summary

**Total Issues:** X
**Critical:** X | **High:** X | **Medium:** X | **Low:** X

### Critical Findings

#### 1. [CWE-XXX] Issue Title
- **File:** path/to/file.rb:line
- **Severity:** CRITICAL
- **Scanner:** Semgrep
- **Description:** [detailed description]
- **Remediation:** [secure code example]

### Recommendations

1. **Immediate Actions** (Critical/High)
2. **Short-term Improvements** (Medium)
3. **Best Practices** (Low/Info)
```

## References

- [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [OWASP Ruby on Rails Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html)
- [Brakeman Warning Types](https://brakemanscanner.org/docs/warning_types/)
- [Semgrep Ruby Rules](https://semgrep.dev/r?lang=ruby)
