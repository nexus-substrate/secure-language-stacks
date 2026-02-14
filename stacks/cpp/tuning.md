# C++ Security Tuning Guide

This document provides guidance on tuning security scanners for C++ projects and addressing common vulnerability patterns.

## Common C++ Vulnerabilities

### 1. Buffer Overflows

**Vulnerability Pattern:**
```cpp
char buffer[10];
strcpy(buffer, user_input);  // UNSAFE
```

**Secure Alternative:**
```cpp
// Use std::string
std::string buffer = user_input;

// Or use strncpy with proper null termination
char buffer[10];
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';

// Best: Use C++17 string_view
std::string_view safe_view(user_input, std::min(strlen(user_input), size_t(9)));
```

**Scanner Configuration:**
- Semgrep: Enable buffer overflow rules
- Cppcheck: Enable `bufferAccessOutOfBounds` check
- Configure to fail on strcpy, strcat, gets, sprintf

### 2. Use-After-Free

**Vulnerability Pattern:**
```cpp
int* ptr = new int(42);
delete ptr;
*ptr = 100;  // UNSAFE - use after free
```

**Secure Alternative:**
```cpp
// Use smart pointers
std::unique_ptr<int> ptr = std::make_unique<int>(42);
// ptr automatically deleted when out of scope

// Or use shared_ptr for shared ownership
std::shared_ptr<int> ptr = std::make_shared<int>(42);
```

**Scanner Configuration:**
- Cppcheck: Enable `useAfterFree` check
- AddressSanitizer: Compile with `-fsanitize=address`
- Semgrep: Add custom rules for delete patterns

### 3. Double Free

**Vulnerability Pattern:**
```cpp
int* ptr = new int(42);
delete ptr;
delete ptr;  // UNSAFE - double free
```

**Secure Alternative:**
```cpp
// Use smart pointers (automatic management)
std::unique_ptr<int> ptr = std::make_unique<int>(42);

// Or set to nullptr after delete
int* raw_ptr = new int(42);
delete raw_ptr;
raw_ptr = nullptr;  // Prevents double free
```

**Scanner Configuration:**
- Cppcheck: Enable `doubleFree` check
- AddressSanitizer: Detects at runtime
- Valgrind: Memory error detection

### 4. Integer Overflow

**Vulnerability Pattern:**
```cpp
int size = user_size * sizeof(int);  // May overflow
int* buffer = new int[size];
```

**Secure Alternative:**
```cpp
// Check for overflow before multiplication
if (user_size > INT_MAX / sizeof(int)) {
    throw std::overflow_error("Size too large");
}
int size = user_size * sizeof(int);

// Or use safe arithmetic
#include <stdexcept>
int safe_multiply(int a, int b) {
    if (a > 0 && b > 0 && a > INT_MAX / b) {
        throw std::overflow_error("Multiplication overflow");
    }
    return a * b;
}
```

**Scanner Configuration:**
- Semgrep: Integer overflow detection rules
- Cppcheck: Enable `integerOverflow` check
- UndefinedBehaviorSanitizer: `-fsanitize=undefined`

### 5. Format String Vulnerabilities

**Vulnerability Pattern:**
```cpp
printf(user_input);  // UNSAFE
fprintf(log_file, user_input);  // UNSAFE
```

**Secure Alternative:**
```cpp
printf("%s", user_input);  // Safe
fprintf(log_file, "%s", user_input);  // Safe

// Better: Use C++ streams
std::cout << user_input;
```

**Scanner Configuration:**
- Semgrep: Format string vulnerability rules
- Cppcheck: Flag all printf-family with variable format
- Static analysis for format string usage

### 6. Null Pointer Dereference

**Vulnerability Pattern:**
```cpp
int* ptr = nullptr;
*ptr = 42;  // UNSAFE
```

**Secure Alternative:**
```cpp
int* ptr = get_pointer();
if (ptr != nullptr) {
    *ptr = 42;
}

// Or use std::optional
std::optional<int> maybe_value = get_optional_value();
if (maybe_value.has_value()) {
    int value = maybe_value.value();
}
```

**Scanner Configuration:**
- Cppcheck: Enable `nullPointer` check
- Clang Static Analyzer: Null dereference detection
- AddressSanitizer: Runtime detection

### 7. Dangling Pointers

**Vulnerability Pattern:**
```cpp
int* get_pointer() {
    int local = 42;
    return &local;  // UNSAFE - returns address of local
}
```

**Secure Alternative:**
```cpp
// Return by value
int get_value() {
    int local = 42;
    return local;  // Safe - copied
}

// Or use heap allocation with smart pointer
std::unique_ptr<int> get_pointer() {
    return std::make_unique<int>(42);
}
```

**Scanner Configuration:**
- Cppcheck: Enable lifetime analysis
- Clang Static Analyzer: Stack address escape detection
- Compiler warnings: `-Wreturn-stack-address`

## RAII Patterns

Resource Acquisition Is Initialization (RAII) is fundamental to C++ safety:

```cpp
// Manual resource management (error-prone)
FILE* file = fopen("data.txt", "r");
// ... operations that might throw
fclose(file);  // Might not be called if exception thrown

// RAII pattern (safe)
class FileHandle {
    FILE* file;
public:
    FileHandle(const char* name) : file(fopen(name, "r")) {
        if (!file) throw std::runtime_error("Failed to open file");
    }
    ~FileHandle() { if (file) fclose(file); }
    FILE* get() { return file; }
};

// Or use standard RAII types
std::ifstream file("data.txt");  // Automatically closed
std::lock_guard<std::mutex> lock(mutex);  // Automatically unlocked
std::unique_ptr<Resource> res(new Resource);  // Automatically deleted
```

## Compiler Security Flags

### GCC/Clang Recommended Flags

```bash
# Compilation flags
-Wall -Wextra -Werror              # Enable all warnings as errors
-Wformat=2                         # Format string security
-Wformat-security                  # Additional format checks
-Wnull-dereference                 # Null pointer warnings
-Wstack-protector                  # Stack protection warnings
-Wtrampolines                      # Executable stack warnings
-fstack-protector-strong           # Stack canary protection
-fPIE -pie                         # Position independent executable
-D_FORTIFY_SOURCE=2                # Buffer overflow detection
-fstack-clash-protection           # Stack clash protection
-Wl,-z,relro,-z,now                # Full RELRO

# C++17/20 specific
-std=c++17                         # Or c++20
-fconcepts                         # Enable concepts (C++20)
```

### MSVC Recommended Flags

```bash
/W4                   # Warning level 4
/WX                   # Treat warnings as errors
/sdl                  # Security Development Lifecycle checks
/guard:cf             # Control Flow Guard
/GS                   # Buffer security check
/DYNAMICBASE          # ASLR
/NXCOMPAT             # DEP
```

## Sanitizers

### AddressSanitizer (ASan)
Detects memory errors at runtime:

```bash
# Compile with ASan
g++ -fsanitize=address -g -O1 main.cpp -o main

# Run
./main
```

Detects:
- Buffer overflows
- Use-after-free
- Use-after-return
- Use-after-scope
- Double free
- Memory leaks

### UndefinedBehaviorSanitizer (UBSan)
Detects undefined behavior:

```bash
# Compile with UBSan
g++ -fsanitize=undefined -g main.cpp -o main
```

Detects:
- Integer overflow
- Null pointer dereference
- Misaligned pointer use
- Division by zero
- Invalid casts

### ThreadSanitizer (TSan)
Detects data races:

```bash
# Compile with TSan
g++ -fsanitize=thread -g main.cpp -o main
```

Detects:
- Data races
- Deadlocks
- Thread leaks

### Combining Sanitizers

```bash
# ASan + UBSan (compatible)
g++ -fsanitize=address,undefined -g main.cpp -o main

# Cannot combine ASan with TSan (use separately)
```

## Scanner Tuning

### Semgrep

**Reduce false positives:**
```yaml
rules:
  - id: custom-buffer-check
    patterns:
      - pattern: strcpy($BUF, $SRC)
      - pattern-not-inside: |
          if (strlen($SRC) < sizeof($BUF)) {
            ...
          }
```

**Add project-specific rules:**
```yaml
rules:
  - id: project-specific-check
    message: Use project's safe_string_copy function
    languages: [cpp]
    severity: WARNING
    patterns:
      - pattern: strcpy(...)
      - pattern-not: safe_string_copy(...)
```

### Cppcheck

**Custom suppressions:**
```xml
<suppressions>
  <suppress>
    <id>unusedFunction</id>
    <fileName>src/test_helpers.cpp</fileName>
  </suppress>
  <suppress>
    <id>*</id>
    <fileName>*/third_party/*</fileName>
  </suppress>
</suppressions>
```

**Platform-specific configs:**
```xml
<platforms>
  <platform>unix64</platform>
  <define name="CUSTOM_PLATFORM_MACRO"/>
</platforms>
```

### Trivy

**Ignore specific CVEs (with justification):**
```yaml
# .trivyignore
CVE-2021-12345  # False positive - not applicable to our use case
CVE-2022-67890  # Acknowledged - fix planned for next release
```

**Custom severity overrides:**
```yaml
severity-overrides:
  CVE-2023-11111:
    severity: LOW
    reason: Limited exposure in our architecture
```

## Valgrind Integration

```bash
# Memory leak detection
valgrind --leak-check=full --show-leak-kinds=all ./main

# Detailed memory error detection
valgrind --track-origins=yes ./main

# Generate suppression file
valgrind --gen-suppressions=all ./main 2>&1 | tee valgrind.log
```

## CMake Integration

```cmake
# Security flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Werror
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
    )
    add_link_options(-Wl,-z,relro,-z,now)
endif()

# Sanitizers (development builds)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -g)
    add_link_options(-fsanitize=address)
endif()

option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined -g)
    add_link_options(-fsanitize=undefined)
endif()
```

## Performance Considerations

Security features impact performance:

| Feature | Performance Impact | When to Use |
|---------|-------------------|-------------|
| ASan | ~2x slower | Development, CI |
| UBSan | ~20% slower | Development, CI |
| TSan | ~5-15x slower | Development |
| Stack protector | <1% slower | Always (production) |
| FORTIFY_SOURCE | <1% slower | Always (production) |
| PIE/ASLR | <1% slower | Always (production) |

## References

- [CERT C++ Coding Standard](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88046682)
- [CppCoreGuidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [AddressSanitizer Documentation](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [Modern C++ Security Best Practices](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)
