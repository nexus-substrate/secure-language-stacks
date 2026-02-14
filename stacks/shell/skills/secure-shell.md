---
name: secure-shell
description: |
  Security scanning guidance for Shell/Bash scripts.
  Triggers on "secure shell", "shell security", "scan shell".
allowed-tools: Read, Grep, Glob, Bash
context: fork
---

# Secure Shell Development - nexus-agents Skill

**Skill ID:** `secure-shell`
**Category:** Security Engineering
**Language Stack:** Shell (bash, zsh, sh)

## Purpose

Guide secure shell script development with security-first patterns, prevent command injection, protect against path traversal, implement proper quoting and variable handling, and enforce secure temp file creation.

## Core Security Principles

### 1. Variable Quoting (CWE-78)

**ALWAYS quote variables to prevent word splitting and globbing:**

```bash
# ❌ DANGEROUS - Unquoted variable
rm -rf $USER_INPUT

# ✅ SECURE - Quoted variable
rm -rf "$USER_INPUT"

# ❌ DANGEROUS - Unquoted in test
if [ $STATUS = "active" ]; then

# ✅ SECURE - Quoted in test
if [ "$STATUS" = "active" ]; then
```

**Why:** Unquoted variables allow attackers to inject spaces, wildcards, or command separators.

### 2. Command Injection Prevention (CWE-78)

**NEVER use eval or sh -c with untrusted input:**

```bash
# ❌ CRITICAL - Command injection via eval
eval "$USER_COMMAND"

# ❌ CRITICAL - Command injection via sh -c
sh -c "$USER_INPUT"

# ✅ SECURE - Use arrays for command construction
command_args=("$arg1" "$arg2")
"${command_args[@]}"

# ✅ SECURE - Validate and sanitize input
if [[ "$input" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  process "$input"
else
  echo "Invalid input" >&2
  exit 1
fi
```

**Why:** `eval` and `sh -c` execute arbitrary code. Attackers can break out of quotes and execute malicious commands.

### 3. Secure Temp Files (CWE-377)

**NEVER use predictable temp file paths:**

```bash
# ❌ DANGEROUS - Predictable path (symlink attack)
echo "data" > /tmp/myfile.txt

# ❌ DANGEROUS - Predictable path with PID (still guessable)
echo "data" > /tmp/myfile.$$.txt

# ✅ SECURE - mktemp creates unpredictable paths with secure permissions
tempfile=$(mktemp) || exit 1
echo "data" > "$tempfile"
trap 'rm -f "$tempfile"' EXIT

# ✅ SECURE - mktemp directory
tempdir=$(mktemp -d) || exit 1
trap 'rm -rf "$tempdir"' EXIT
```

**Why:** Predictable temp file names allow symlink attacks where an attacker creates a symlink from the predictable name to a sensitive file, causing your script to overwrite it.

### 4. Path Traversal Prevention (CWE-22)

**Validate user-supplied paths:**

```bash
# ❌ DANGEROUS - Unchecked user path
cat "/var/log/$USER_FILE"

# ✅ SECURE - Validate basename (no directory components)
if [[ "$(basename "$USER_FILE")" == "$USER_FILE" ]] && \
   [[ "$USER_FILE" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  cat "/var/log/$USER_FILE"
else
  echo "Invalid filename" >&2
  exit 1
fi

# ✅ SECURE - Resolve and validate realpath
safe_base="/var/log"
target=$(realpath -m "$safe_base/$USER_FILE")
if [[ "$target" == "$safe_base"/* ]]; then
  cat "$target"
else
  echo "Path traversal attempt detected" >&2
  exit 1
fi
```

**Why:** User input like `../../etc/passwd` can escape intended directories.

### 5. Credential Management (CWE-798)

**NEVER hardcode credentials:**

```bash
# ❌ CRITICAL - Hardcoded password in script
PASSWORD="MySecretPass123"
mysql -u root -p"$PASSWORD" -e "SELECT * FROM users"

# ✅ SECURE - Read from environment variable
if [ -z "$DB_PASSWORD" ]; then
  echo "DB_PASSWORD not set" >&2
  exit 1
fi
mysql -u root -p"$DB_PASSWORD" -e "SELECT * FROM users"

# ✅ SECURE - Read from file with restricted permissions
DB_PASSWORD=$(cat /run/secrets/db_password)
mysql -u root -p"$DB_PASSWORD" -e "SELECT * FROM users"

# ✅ BEST - Use credential helper or secret manager
DB_PASSWORD=$(vault kv get -field=password secret/database)
```

**Why:** Hardcoded credentials in scripts are exposed in version control, logs, and process listings.

### 6. Safe Remote Script Execution

**NEVER pipe remote content directly to shell:**

```bash
# ❌ CRITICAL - No integrity check, attacker controls content
curl https://example.com/install.sh | bash

# ✅ SECURE - Download, verify checksum, then execute
curl -fsSL https://example.com/install.sh -o install.sh
echo "expected_sha256_hash  install.sh" | sha256sum -c - || exit 1
bash install.sh
rm install.sh

# ✅ BETTER - Use package manager or signed releases
# Verify GPG signature before execution
```

**Why:** Piping to shell executes code as it downloads, even if download fails mid-stream. No integrity verification.

### 7. Signal Handling and Cleanup

**Always clean up on exit:**

```bash
#!/bin/bash
set -euo pipefail

# Create cleanup trap BEFORE creating resources
cleanup() {
  rm -f "$tempfile"
  rm -rf "$tempdir"
  # Kill background jobs
  jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT INT TERM

tempfile=$(mktemp)
tempdir=$(mktemp -d)

# Script continues...
# Resources automatically cleaned up on exit, interrupt, or termination
```

**Why:** Scripts can be interrupted (SIGINT, SIGTERM) leaving temp files, locks, or background processes.

### 8. Strict Error Handling

**Use strict mode:**

```bash
#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# -e: exit on error
# -u: exit on undefined variable
# -o pipefail: pipelines fail if any command fails
# IFS: prevent word splitting on spaces (only newlines/tabs)

# ❌ Without strict mode, errors are silently ignored
cd /nonexistent
rm -rf *  # Executes in wrong directory!

# ✅ With set -e, script exits on cd failure
cd /nonexistent || exit 1  # Explicit error handling
```

**Why:** Default bash continues after errors, leading to cascading failures.

### 9. Input Validation

**Validate all external input:**

```bash
# Whitelist validation for identifiers
validate_identifier() {
  if [[ ! "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Invalid identifier: $1" >&2
    return 1
  fi
}

# Numeric validation
validate_port() {
  if [[ ! "$1" =~ ^[0-9]+$ ]] || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
    echo "Invalid port: $1" >&2
    return 1
  fi
}

# Path validation
validate_path() {
  local base="/safe/directory"
  local target
  target=$(realpath -m "$base/$1")
  if [[ "$target" != "$base"/* ]]; then
    echo "Path traversal detected: $1" >&2
    return 1
  fi
}
```

### 10. Avoid Dangerous Patterns

**Never use these patterns:**

```bash
# ❌ DANGEROUS - IFS manipulation affects global state
IFS=',' read -ra ADDR <<< "$data"

# ✅ SECURE - Local IFS scope
while IFS=',' read -ra ADDR; do
  # Process
done <<< "$data"

# ❌ DANGEROUS - Uncontrolled find -exec
find . -name "*.log" -exec rm {} \;

# ✅ SECURE - Use -delete or null-terminated xargs
find . -name "*.log" -delete
# OR
find . -name "*.log" -print0 | xargs -0 rm

# ❌ DANGEROUS - PATH injection
PATH="$USER_INPUT:$PATH"

# ✅ SECURE - Never trust user input for PATH
# Use absolute paths for critical commands
/usr/bin/rm -f "$file"
```

## Security Scanning Integration

### ShellCheck

Run ShellCheck on all scripts:

```bash
shellcheck --config-file=stacks/shell/configs/.shellcheckrc script.sh
```

**Critical checks:**
- SC2086: Unquoted variable expansion
- SC2046: Quote to prevent word splitting
- SC2068: Quote array expansions
- SC2006: Use `$(...)` not backticks
- SC2164: Check cd return value

### Semgrep

Run Semgrep for security patterns:

```bash
semgrep --config=stacks/shell/configs/.semgrep.yml \
  --config=p/bash \
  --severity=ERROR \
  .
```

**Detects:**
- Command injection via eval/sh -c
- Unquoted variable expansion in dangerous contexts
- curl|bash patterns
- Predictable temp files
- Hardcoded credentials

### Gitleaks

Scan for secrets:

```bash
gitleaks detect --config=shared/configs/.gitleaks.toml --source=.
```

## Workflow Integration

1. **Pre-commit:** Run ShellCheck + Semgrep locally
2. **CI Pipeline:** Full scan suite on every PR
3. **Security Gate:** Block merge if ERROR-level findings
4. **Scheduled Scan:** Weekly full repository scan

## Common Pitfalls

| Pitfall | Impact | Fix |
|---------|--------|-----|
| Unquoted `$VAR` | Word splitting, globbing, injection | Always quote: `"$VAR"` |
| `eval "$input"` | Arbitrary code execution | Never use eval with user input |
| `/tmp/predictable` | Symlink attack | Use `mktemp` |
| `curl \| bash` | No integrity check | Download, verify hash, execute |
| Hardcoded passwords | Credential exposure | Use env vars or secret manager |
| Missing `set -e` | Silent failures | Use `set -euo pipefail` |
| No input validation | Injection attacks | Whitelist validation |

## References

- [ShellCheck Wiki](https://www.shellcheck.net/wiki/)
- [Bash Pitfalls](https://mywiki.wooledge.org/BashPitfalls)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [OWASP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
