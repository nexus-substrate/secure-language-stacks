# Rust Security Tuning Guide

Security hardening guidance for Rust projects.

## Unsafe Code Minimization

### Strategy

Rust's memory safety guarantees are voided in `unsafe` blocks. Minimize their use and audit rigorously.

**Guidelines:**

1. **Isolate unsafe**: Wrap `unsafe` in safe abstractions with documented invariants
2. **Limit scope**: Keep unsafe blocks as small as possible
3. **Document safety**: Explain why each unsafe block is sound
4. **Audit frequency**: Review all unsafe code during security reviews

**Example:**

```rust
// ❌ BAD - Large unsafe scope
pub fn process_buffer(buf: *const u8, len: usize) -> Vec<u8> {
    unsafe {
        let slice = std::slice::from_raw_parts(buf, len);
        // ... 50 lines of processing ...
        slice.to_vec()
    }
}

// ✅ GOOD - Minimal unsafe scope
pub fn process_buffer(buf: *const u8, len: usize) -> Vec<u8> {
    // SAFETY: Caller guarantees buf is valid for len bytes
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };

    // Safe processing
    slice.iter().map(|&b| b ^ 0xFF).collect()
}
```

**Tools:**

- `cargo-geiger`: Measure unsafe usage across dependencies
- `#[deny(unsafe_code)]`: Forbid unsafe in modules where not needed
- `#[forbid(unsafe_code)]`: Cannot be overridden (strongest)

### FFI Boundaries

Foreign Function Interface (FFI) calls are inherently unsafe and require careful handling.

**Critical concerns:**

1. **Memory ownership**: Who allocates? Who frees?
2. **Null pointers**: C functions may return NULL
3. **String encoding**: UTF-8 vs C strings (null-terminated)
4. **Data alignment**: Ensure proper struct alignment with `#[repr(C)]`
5. **Callbacks**: Rust closures cannot be directly passed to C

**Example:**

```rust
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

extern "C" {
    fn external_process(input: *const c_char) -> *mut c_char;
}

pub fn safe_process(input: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Convert Rust string to C string
    let c_input = CString::new(input)?;

    // SAFETY: c_input is valid null-terminated string
    let result_ptr = unsafe { external_process(c_input.as_ptr()) };

    if result_ptr.is_null() {
        return Err("external_process returned NULL".into());
    }

    // SAFETY: Assuming external_process returns valid UTF-8
    let result = unsafe {
        let c_str = CStr::from_ptr(result_ptr);
        let str_slice = c_str.to_str()?;
        let owned = str_slice.to_owned();

        // Free C-allocated memory
        libc::free(result_ptr as *mut libc::c_void);

        owned
    };

    Ok(result)
}
```

**Checklist:**

- [ ] All pointers checked for NULL before dereferencing
- [ ] Memory ownership documented
- [ ] String encoding validated
- [ ] Proper cleanup on all code paths (use RAII)
- [ ] Thread safety considered

## Integer Overflow

Rust checks for overflow in debug builds but **not in release mode** by default.

### Configuration

Enable overflow checks in release:

```toml
# Cargo.toml
[profile.release]
overflow-checks = true
```

**Trade-off:** ~5-10% performance overhead for arithmetic operations.

### Safe Alternatives

Use checked/saturating/wrapping arithmetic explicitly:

```rust
// ❌ RISKY - Silent wraparound in release
let total = a + b + c;

// ✅ SAFE - Explicit error handling
let total = a.checked_add(b)
    .and_then(|sum| sum.checked_add(c))
    .ok_or("arithmetic overflow")?;

// ✅ SAFE - Saturating for bounds
let clamped = value.saturating_add(increment);

// ✅ EXPLICIT - Intentional wraparound
let hash = a.wrapping_mul(b);
```

**When to use:**

- `checked_*`: Financial calculations, array indexing, security-critical math
- `saturating_*`: Pixel values, volume controls, bounded quantities
- `wrapping_*`: Hash functions, checksums (where overflow is intentional)

### Parser Security

Integer overflows in parsers can lead to buffer overflows:

```rust
// ❌ VULNERABLE
fn parse_length(bytes: &[u8]) -> usize {
    let len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    len * 8  // Can overflow on 32-bit systems
}

// ✅ SAFE
fn parse_length(bytes: &[u8]) -> Result<usize, Error> {
    let len = u32::from_le_bytes(bytes.get(0..4)
        .ok_or(Error::TooShort)?
        .try_into()
        .unwrap()) as usize;

    len.checked_mul(8)
        .filter(|&total| total <= MAX_ALLOCATION)
        .ok_or(Error::LengthOverflow)
}
```

## Memory Safety with Raw Pointers

Raw pointers (`*const T`, `*mut T`) bypass Rust's borrow checker.

### Safety Requirements

Before dereferencing a raw pointer, ensure:

1. **Non-null**: Pointer is not NULL
2. **Aligned**: Properly aligned for type T
3. **Valid**: Points to initialized memory of type T
4. **Live**: Memory has not been freed
5. **Access**: No data races (for `*mut`)

**Example:**

```rust
// ❌ UNSAFE - No validation
unsafe fn read_value(ptr: *const i32) -> i32 {
    *ptr
}

// ✅ SAFE - Validation before use
unsafe fn read_value(ptr: *const i32) -> Option<i32> {
    if ptr.is_null() {
        return None;
    }

    // Check alignment
    if (ptr as usize) % std::mem::align_of::<i32>() != 0 {
        return None;
    }

    // SAFETY: Pointer is non-null and aligned
    Some(*ptr)
}
```

### Smart Pointer Alternatives

Prefer safe abstractions:

- `Box<T>`: Heap allocation with ownership
- `Rc<T>` / `Arc<T>`: Shared ownership
- `RefCell<T>` / `Mutex<T>`: Interior mutability
- `Pin<T>`: Prevent memory moves

## Dependency Supply Chain

### Verification

1. **Audit dependencies**: Review `Cargo.toml` for unexpected crates
2. **Check sources**: Ensure all deps come from crates.io or trusted git repos
3. **Pin versions**: Use exact versions for reproducibility
4. **Review updates**: Don't blindly `cargo update`

### Tools

```bash
# Check for known vulnerabilities
cargo audit

# Generate SBOM
cargo tree --format "{p} {l}" > sbom.txt

# Find duplicate dependencies
cargo tree --duplicates

# Measure unsafe code
cargo install cargo-geiger
cargo geiger

# Detect supply chain attacks
cargo install cargo-supply-chain
cargo supply-chain
```

### Dependency Pinning

```toml
# ❌ RISKY - Accepts any minor/patch version
reqwest = "0.11"

# ✅ SAFE - Exact version
reqwest = "=0.11.22"

# ⚠️  MODERATE - Accepts patches only
reqwest = "~0.11.22"
```

**Trade-off:** Exact pinning prevents automatic security updates. Requires active maintenance.

### Recommended Practice

- Pin versions in applications
- Use ranges in libraries (for compatibility)
- Run `cargo audit` in CI
- Enable Dependabot/Renovate for automated updates

## Timing Attacks

Prevent timing side-channels in cryptographic code.

### Constant-Time Comparisons

```rust
// ❌ VULNERABLE - Early exit reveals information
fn verify_token(input: &[u8], expected: &[u8]) -> bool {
    if input.len() != expected.len() {
        return false;
    }

    for (a, b) in input.iter().zip(expected.iter()) {
        if a != b {
            return false;  // Timing leak
        }
    }

    true
}

// ✅ SAFE - Constant-time comparison
use subtle::ConstantTimeEq;

fn verify_token(input: &[u8], expected: &[u8]) -> bool {
    if input.len() != expected.len() {
        return false;
    }

    input.ct_eq(expected).into()
}
```

**Use constant-time functions for:**

- Password/hash comparisons
- HMAC verification
- Cryptographic signatures
- Session token validation

### Libraries

- `subtle`: Constant-time operations
- `zeroize`: Securely clear sensitive memory
- `secrecy`: Type-safe secret handling

**Example:**

```rust
use secrecy::{Secret, ExposeSecret};
use zeroize::Zeroize;

struct Credentials {
    username: String,
    password: Secret<String>,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.username.zeroize();
        // password auto-zeroized by Secret
    }
}

fn authenticate(creds: &Credentials, db: &Database) -> bool {
    let stored_hash = db.get_password_hash(&creds.username)?;
    verify_password(creds.password.expose_secret(), &stored_hash)
}
```

## Serialization Security

### Deserialization Attacks

Untrusted deserialization can lead to:

- Denial of Service (deeply nested structures)
- Memory exhaustion (large allocations)
- Type confusion

**Mitigation:**

```rust
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
struct UserInput {
    #[serde(deserialize_with = "validate_username")]
    username: String,

    #[serde(default)]
    #[serde(deserialize_with = "validate_age")]
    age: u8,
}

fn validate_username<'de, D>(d: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(d)?;

    if s.len() > 32 {
        return Err(serde::de::Error::custom("username too long"));
    }

    if !s.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(serde::de::Error::custom("invalid characters"));
    }

    Ok(s)
}

fn validate_age<'de, D>(d: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let age = u8::deserialize(d)?;

    if age > 120 {
        return Err(serde::de::Error::custom("invalid age"));
    }

    Ok(age)
}
```

### Resource Limits

```rust
use serde_json::Deserializer;

fn parse_limited_json(input: &str) -> Result<Value, Error> {
    let mut de = Deserializer::from_str(input);

    // Limit recursion depth
    de.disable_recursion_limit();

    let value: Value = serde_path_to_error::deserialize(&mut de)?;

    // Check size limits
    if value.as_object()
        .map(|o| o.len())
        .unwrap_or(0) > 1000
    {
        return Err(Error::TooManyFields);
    }

    Ok(value)
}
```

## Compilation Flags

Security-relevant `rustc` flags:

```toml
# .cargo/config.toml
[build]
rustflags = [
    "-C", "relocation-model=pic",        # Position-independent code
    "-C", "overflow-checks=on",          # Enable overflow checks
    "-D", "warnings",                    # Deny all warnings
    "-Z", "sanitizer=address",           # AddressSanitizer (nightly)
]

[profile.release]
overflow-checks = true
lto = true              # Link-time optimization
codegen-units = 1       # Better optimization (slower build)
strip = true            # Strip symbols
panic = "abort"         # Smaller binary, no unwinding
```

**Environment-specific:**

```bash
# Development
RUSTFLAGS="-Z sanitizer=address" cargo +nightly build

# Production
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Security Checklist

### Pre-deployment

- [ ] `cargo audit` passes with no vulnerabilities
- [ ] `cargo clippy` with security lints passes
- [ ] All `unsafe` blocks documented with SAFETY comments
- [ ] Overflow checks enabled in release profile
- [ ] Dependencies pinned to exact versions
- [ ] Secrets not hardcoded (use env vars or vault)
- [ ] Constant-time operations for crypto comparisons
- [ ] Input validation on all deserialization
- [ ] Memory is zeroized for sensitive data
- [ ] Fuzzing coverage for parsers/decoders

### CI/CD Integration

- [ ] Automated `cargo audit` on every commit
- [ ] Semgrep SAST integrated
- [ ] Trivy SCA scanning
- [ ] Gitleaks secret detection
- [ ] SARIF reports uploaded to GitHub Security
- [ ] Security findings fail the build

### Runtime

- [ ] Panic handler configured appropriately
- [ ] Resource limits enforced (memory, CPU, connections)
- [ ] Structured logging with security events
- [ ] Metrics exported for monitoring
- [ ] Security headers set for web services

## References

- [Rust Security Guidelines (ANSSI)](https://anssi-fr.github.io/rust-guide/)
- [RustSec Advisory Database](https://rustsec.org/)
- [Secure Rust Guidelines](https://github.com/ANSSI-FR/rust-guide)
- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
