# Shell Security Tuning Guide

## Overview

Shell scripts are a critical attack surface in infrastructure and DevOps workflows. This guide covers security hardening beyond basic best practices.

## Critical Security Vectors

### 1. Command Injection (CWE-78)

**Attack Surface:**
- Variable expansion in eval/sh -c
- Unquoted variables in commands
- User-controlled command arguments
- IFS manipulation

**Hardening:**

```bash
# Strict quoting discipline
declare -r SAFE_CHARS='^[a-zA-Z0-9._-]+$'

validate_input() {
  local input="$1"
  if [[ ! "$input" =~ $SAFE_CHARS ]]; then
    echo "Validation failed: $input" >&2
    return 1
  fi
}

# Use arrays for complex commands (preserves word boundaries)
cmd_args=()
cmd_args+=("--flag")
cmd_args+=("$user_input")
command "${cmd_args[@]}"

# Prefer built-ins over external commands
# Built-in: [[ "$var" =~ regex ]]
# Avoid: echo "$var" | grep -E regex
```

**Detection Tuning:**
- Semgrep rule: `shell-command-injection-variable-expansion`
- ShellCheck: SC2086, SC2046, SC2068
- Severity: ERROR (block merge)

### 2. Temporary File Race Conditions (CWE-377)

**Attack Surface:**
- Predictable `/tmp/` paths
- Time-of-check-time-of-use (TOCTOU) gaps
- Shared temp directory access
- Signal-based temp file cleanup race

**Hardening:**

```bash
# Atomic temp file creation with restricted permissions
create_secure_temp() {
  local template="${1:-secure.XXXXXX}"
  local temp

  # mktemp creates with mode 0600 atomically
  temp=$(mktemp -t "$template") || {
    echo "mktemp failed" >&2
    return 1
  }

  # Further restrict permissions if needed
  chmod 0400 "$temp"

  echo "$temp"
}

# Cleanup on ALL exit paths
cleanup_temps() {
  local -a temps=("$@")
  local f
  for f in "${temps[@]}"; do
    if [ -f "$f" ]; then
      # Secure wipe for sensitive data
      shred -u "$f" 2>/dev/null || rm -f "$f"
    fi
  done
}

# Register cleanup early
temp1=$(create_secure_temp) || exit 1
temp2=$(create_secure_temp) || exit 1
trap 'cleanup_temps "$temp1" "$temp2"' EXIT INT TERM HUP
```

**Detection Tuning:**
- Semgrep rule: `shell-insecure-temp-file`
- Pattern: `/tmp/$...` or `/var/tmp/$...`
- Severity: WARNING (review required)

### 3. Path Traversal (CWE-22)

**Attack Surface:**
- User-controlled file paths
- Symlink following in file operations
- Relative path resolution
- Archive extraction (zip bombs, path escape)

**Hardening:**

```bash
# Canonical path validation
validate_safe_path() {
  local base="$1"
  local user_path="$2"
  local resolved

  # Resolve to absolute path (follow symlinks)
  resolved=$(realpath -e "$base/$user_path" 2>/dev/null) || {
    echo "Path resolution failed: $user_path" >&2
    return 1
  }

  # Ensure resolved path is within base
  if [[ "$resolved" != "$base"/* ]]; then
    echo "Path traversal detected: $user_path -> $resolved" >&2
    return 1
  fi

  echo "$resolved"
}

# Safe archive extraction
safe_extract() {
  local archive="$1"
  local dest="$2"

  # Extract to temp, validate paths, then move
  local temp
  temp=$(mktemp -d) || return 1
  trap 'rm -rf "$temp"' RETURN

  tar -xzf "$archive" -C "$temp" || return 1

  # Validate no path traversal in archive
  find "$temp" -type f -o -type d | while IFS= read -r path; do
    if [[ "$path" == *../* ]] || [[ "$path" == /* ]]; then
      echo "Malicious path in archive: $path" >&2
      return 1
    fi
  done

  mv "$temp"/* "$dest"/
}
```

**Detection Tuning:**
- Manual review of all file operations with user input
- No automated detection (context-dependent)
- Focus on: `cat`, `cp`, `mv`, `rm`, `tar`, `unzip` with user-supplied paths

### 4. Credential Exposure (CWE-798, CWE-214)

**Attack Surface:**
- Hardcoded passwords in scripts
- Credentials in environment variables (visible in `/proc`)
- Secrets in command-line arguments (`ps` visible)
- Credentials in logs or error messages

**Hardening:**

```bash
# Read from file descriptor (not visible in ps)
# Caller: script.sh 3< /run/secrets/password
read_secret() {
  local fd="${1:-3}"
  local secret

  if [ ! -t "$fd" ]; then
    IFS= read -r secret <&"$fd"
    echo "$secret"
  else
    echo "Secret file descriptor not available" >&2
    return 1
  fi
}

DB_PASSWORD=$(read_secret 3)

# Prevent credential leakage in logs
safe_log() {
  local message="$1"
  # Redact common secret patterns
  message=$(echo "$message" | sed -E \
    -e 's/(password|token|key|secret)=[^[:space:]]*/\1=REDACTED/gi' \
    -e 's/(Bearer|Basic) [^[:space:]]*/\1 REDACTED/g')
  echo "$message" | logger -t "$(basename "$0")"
}

# Clear sensitive variables after use
use_credential() {
  local password="$1"
  # Use password
  mysql -u root -p"$password" -e "..."
  # Clear from memory (best effort)
  password="XXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
  unset password
}
```

**Detection Tuning:**
- Gitleaks: Scan for patterns like `PASSWORD="..."`, `API_KEY="..."`
- Semgrep rule: `shell-hardcoded-credentials`
- Manual review: All authentication/API calls
- Severity: ERROR (block merge)

### 5. Remote Code Execution (CWE-494)

**Attack Surface:**
- `curl | bash` installer patterns
- Sourcing untrusted files
- Dynamic script downloads without verification
- Supply chain attacks on install scripts

**Hardening:**

```bash
# Secure remote script execution
execute_remote_script() {
  local url="$1"
  local expected_hash="$2"
  local temp

  temp=$(mktemp) || return 1
  trap 'rm -f "$temp"' RETURN

  # Download with timeout and fail on error
  if ! curl -fsSL --max-time 30 "$url" -o "$temp"; then
    echo "Download failed: $url" >&2
    return 1
  fi

  # Verify checksum
  local actual_hash
  actual_hash=$(sha256sum "$temp" | awk '{print $1}')
  if [ "$actual_hash" != "$expected_hash" ]; then
    echo "Hash mismatch: expected $expected_hash, got $actual_hash" >&2
    return 1
  fi

  # Execute with restricted environment
  env -i bash "$temp"
}

# NEVER source from /tmp or other world-writable locations
# ❌ source /tmp/config.sh
# ✅ Source only from trusted, permission-checked paths
source_config() {
  local config="$1"

  # Verify ownership and permissions
  if [ "$(stat -c '%u' "$config")" -ne 0 ]; then
    echo "Config not owned by root: $config" >&2
    return 1
  fi

  if [ "$(stat -c '%a' "$config")" != "644" ]; then
    echo "Insecure permissions on config: $config" >&2
    return 1
  fi

  # shellcheck source=/dev/null
  source "$config"
}
```

**Detection Tuning:**
- Semgrep rules: `shell-curl-pipe-bash`, `shell-source-untrusted-file`
- Pattern: `curl ... | bash`, `source /tmp/...`
- Severity: ERROR (block merge)

### 6. Signal Handling and Resource Cleanup

**Attack Surface:**
- SIGINT/SIGTERM leaving orphaned processes
- Lock files not cleaned up
- Temp files persisting after kill
- Background jobs not terminated

**Hardening:**

```bash
#!/bin/bash
set -euo pipefail

# Global cleanup state
declare -a CLEANUP_FILES=()
declare -a CLEANUP_DIRS=()
declare -a CLEANUP_PIDS=()

# Central cleanup function
cleanup() {
  local exit_code=$?

  # Kill background jobs
  local pid
  for pid in "${CLEANUP_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 0.1
      kill -9 "$pid" 2>/dev/null || true
    fi
  done

  # Remove temp files
  local file
  for file in "${CLEANUP_FILES[@]}"; do
    [ -f "$file" ] && rm -f "$file"
  done

  # Remove temp directories
  local dir
  for dir in "${CLEANUP_DIRS[@]}"; do
    [ -d "$dir" ] && rm -rf "$dir"
  done

  exit "$exit_code"
}

# Register cleanup on ALL signals
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' INT    # SIGINT (Ctrl+C)
trap 'trap - EXIT; cleanup; exit 143' TERM   # SIGTERM
trap 'trap - EXIT; cleanup; exit 129' HUP    # SIGHUP

# Register resources for cleanup
register_temp_file() {
  CLEANUP_FILES+=("$1")
}

register_temp_dir() {
  CLEANUP_DIRS+=("$1")
}

register_background_pid() {
  CLEANUP_PIDS+=("$1")
}

# Example usage
tempfile=$(mktemp)
register_temp_file "$tempfile"

background_job &
register_background_pid $!
```

### 7. IFS and Globbing Attacks

**Attack Surface:**
- IFS manipulation affecting word splitting
- Unquoted variable expansion enabling globbing
- Filename-based code injection (`-rf` as filename)

**Hardening:**

```bash
# Set safe IFS globally
IFS=$'\n\t'

# Local IFS for specific operations
process_csv() {
  local line
  while IFS=',' read -ra fields; do
    # Process fields
    echo "Field 1: ${fields[0]}"
  done < "$1"
  # IFS automatically restored after function
}

# Disable globbing when processing user input
set -f  # Disable globbing
user_files=($USER_INPUT)
set +f  # Re-enable globbing

# Safe iteration over files
find . -name "*.log" -print0 | while IFS= read -r -d '' file; do
  process_file "$file"
done
```

## Scanner Configuration

### ShellCheck Severity Mapping

```
SC2086 (unquoted expansion) -> ERROR
SC2046 (word splitting) -> ERROR
SC2068 (array expansion) -> ERROR
SC2155 (masked return value) -> WARNING
SC2164 (cd without check) -> WARNING
SC1090 (can't follow source) -> INFO (expected)
```

### Semgrep Rule Priorities

```yaml
HIGH (block merge):
  - command-injection-variable-expansion
  - curl-pipe-bash
  - hardcoded-credentials
  - source-untrusted-file

MEDIUM (review required):
  - insecure-temp-file
  - unquoted-variable-expansion
  - dangerous-find-exec
```

### Gitleaks Pattern Tuning

```toml
# Reduce false positives
[[rules]]
id = "shell-password-variable"
description = "Password in shell variable"
regex = '''(?i)(password|passwd|pwd)\s*=\s*["'].{8,}["']'''
# Exclude test files and documentation
[rules.allowlist]
paths = ['''(test|spec|example)/.*\.sh$''']
```

## Continuous Monitoring

1. **Pre-commit:** ShellCheck + Semgrep (fast checks only)
2. **PR:** Full scan suite with SARIF upload to GitHub Security
3. **Weekly:** Deep scan with all rules, trend analysis
4. **Production:** Runtime monitoring for anomalous process execution

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Bash Security Best Practices](https://mywiki.wooledge.org/BashGuide/Practices)
- [ShellCheck Wiki](https://www.shellcheck.net/wiki/)
