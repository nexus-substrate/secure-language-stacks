# TypeScript Security Tuning Guide

Language-specific security guidance for TypeScript and Node.js projects.

## Table of Contents

1. [Prototype Pollution Prevention](#prototype-pollution-prevention)
2. [Regular Expression Denial of Service (ReDoS)](#regular-expression-denial-of-service-redos)
3. [Server-Side Template Injection](#server-side-template-injection)
4. [Dependency Confusion Attacks](#dependency-confusion-attacks)
5. [Unsafe Deserialization](#unsafe-deserialization)
6. [Path Traversal in Node.js](#path-traversal-in-nodejs)
7. [Common CWEs for TypeScript](#common-cwes-for-typescript)

---

## Prototype Pollution Prevention

**CWE-1321: Prototype Pollution**

### What is Prototype Pollution?

Prototype pollution occurs when an attacker can inject properties into JavaScript object prototypes, affecting all objects that inherit from the polluted prototype.

### Vulnerable Code Examples

```typescript
// VULNERABLE: Direct assignment to __proto__
function merge(target: any, source: any) {
  for (const key in source) {
    target[key] = source[key];  // Allows __proto__ pollution
  }
}

// VULNERABLE: JSON.parse with user input
const userInput = '{"__proto__": {"isAdmin": true}}';
const obj = JSON.parse(userInput);
Object.assign({}, obj);  // Pollutes Object.prototype

// VULNERABLE: Recursive merge without key validation
function deepMerge(target: any, source: any): any {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];  // No key validation
    }
  }
  return target;
}
```

### Secure Alternatives

```typescript
// SECURE: Use Object.create(null) for dictionaries
const safeDict = Object.create(null);
safeDict.someKey = 'value';  // No prototype chain

// SECURE: Validate keys before assignment
function secureMerge(target: Record<string, unknown>, source: Record<string, unknown>) {
  const dangerousKeys = ['__proto__', 'constructor', 'prototype'];

  for (const key in source) {
    if (dangerousKeys.includes(key)) {
      continue;  // Skip dangerous keys
    }
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      target[key] = source[key];
    }
  }
}

// SECURE: Use Map instead of plain objects
const secureMap = new Map<string, unknown>();
secureMap.set('__proto__', 'value');  // Safe, no prototype pollution

// SECURE: Use Object.assign with filtered keys
function safeAssign(target: object, source: Record<string, unknown>) {
  const filteredSource = Object.keys(source)
    .filter(key => !['__proto__', 'constructor', 'prototype'].includes(key))
    .reduce((obj, key) => ({ ...obj, [key]: source[key] }), {});

  return Object.assign(target, filteredSource);
}

// SECURE: Schema validation with Zod
import { z } from 'zod';

const UserSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  age: z.number().int().positive(),
});

// Only validated keys are allowed
const user = UserSchema.parse(untrustedInput);
```

### Detection and Mitigation

```bash
# Semgrep rule to detect prototype pollution
semgrep --config 'r/typescript.lang.security.audit.prototype-pollution'

# ESLint rule
npm install --save-dev eslint-plugin-security
# Enable: security/detect-object-injection
```

**Mitigation Checklist:**

- [ ] Use `Object.create(null)` for dictionaries
- [ ] Validate object keys before assignment
- [ ] Prefer Map/Set over plain objects for dynamic data
- [ ] Use schema validation (Zod, AJV) for user input
- [ ] Enable `--frozen-intrinsics` flag in production
- [ ] Audit dependencies for known prototype pollution (Lodash < 4.17.21)

---

## Regular Expression Denial of Service (ReDoS)

**CWE-1333: Inefficient Regular Expression Complexity**

### What is ReDoS?

ReDoS exploits exponential time complexity in regex engines by providing input that causes catastrophic backtracking.

### Vulnerable Patterns

```typescript
// VULNERABLE: Nested quantifiers
const emailRegex = /^([a-zA-Z0-9_\.\-])+@([a-zA-Z0-9\-])+\.([a-zA-Z0-9\-])+$/;
// Attack: "aaaaaaaaaaaaaaaaaaaaaaaaa!"

// VULNERABLE: Overlapping patterns
const urlRegex = /(https?:\/\/)?(www\.)?([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}/;
// Attack: "http://aaaaaaaaaaaaaaaaaaaaaa!"

// VULNERABLE: Unanchored alternation
const jsonRegex = /"[^"]*"|'[^']*'|true|false|null|\d+/;
// Attack: long string of non-matching characters
```

### Secure Alternatives

```typescript
// SECURE: Use simple, anchored patterns
const safeEmailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// SECURE: Set timeout for regex execution
function safeRegexTest(pattern: RegExp, input: string, timeoutMs = 100): boolean {
  const worker = new Worker('regex-worker.js');

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      worker.terminate();
      reject(new Error('Regex timeout'));
    }, timeoutMs);

    worker.onmessage = (e) => {
      clearTimeout(timeout);
      resolve(e.data);
    };

    worker.postMessage({ pattern: pattern.source, input });
  });
}

// SECURE: Use non-backtracking parsers for complex formats
import { parse } from 'url';  // Use built-in parsers

function validateUrl(input: string): boolean {
  try {
    const url = new URL(input);
    return ['http:', 'https:'].includes(url.protocol);
  } catch {
    return false;
  }
}

// SECURE: Use atomic grouping (when supported)
const safePattern = /^(?>[a-zA-Z0-9]+)@(?>[a-zA-Z0-9]+)\.(?>[a-zA-Z]{2,})$/;
```

### Testing for ReDoS

```bash
# Use redos-checker
npx redos-checker "/(a+)+$/"

# Use Semgrep
semgrep --config 'r/javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp'
```

**Mitigation Checklist:**

- [ ] Avoid nested quantifiers: `(a+)+`, `(a*)*`, `(a+)*`
- [ ] Anchor patterns with `^` and `$`
- [ ] Test regex with https://devina.io/redos-checker
- [ ] Set execution timeouts for user-provided patterns
- [ ] Use built-in parsers (URL, JSON) instead of regex
- [ ] Enable ESLint rule: `security/detect-unsafe-regex`

---

## Server-Side Template Injection

**CWE-94: Code Injection via Template Engines**

### What is SSTI?

SSTI occurs when user input is embedded into template engines without proper sanitization, allowing code execution.

### Vulnerable Code Examples

```typescript
// VULNERABLE: Handlebars with triple-stash (unescaped)
import Handlebars from 'handlebars';

app.get('/profile', (req, res) => {
  const template = Handlebars.compile('<h1>Hello {{{name}}}</h1>');
  res.send(template({ name: req.query.name }));  // XSS risk
});

// VULNERABLE: EJS with unescaped output
import ejs from 'ejs';

app.get('/welcome', (req, res) => {
  const html = ejs.render('<%- userInput %>', { userInput: req.query.input });
  res.send(html);  // Code injection
});

// VULNERABLE: Pug with unescaped interpolation
app.get('/greeting', (req, res) => {
  res.render('template', { message: req.query.msg });
});
// template.pug: p!=message  // Unescaped
```

### Secure Alternatives

```typescript
// SECURE: Use double-stash (escaped) in Handlebars
const template = Handlebars.compile('<h1>Hello {{name}}</h1>');
res.send(template({ name: req.query.name }));  // Auto-escaped

// SECURE: Use <%= %> for escaped output in EJS
const html = ejs.render('<%= userInput %>', { userInput: req.query.input });

// SECURE: Default escaped output in Pug
// template.pug: p= message  // Escaped by default

// SECURE: Sanitize HTML with DOMPurify
import DOMPurify from 'isomorphic-dompurify';

app.get('/content', (req, res) => {
  const clean = DOMPurify.sanitize(req.query.html);
  res.send(clean);
});

// SECURE: Use React/Vue for automatic escaping
import React from 'react';

function UserProfile({ name }: { name: string }) {
  return <h1>Hello {name}</h1>;  // Auto-escaped
}
```

**Mitigation Checklist:**

- [ ] Always use escaped template syntax by default
- [ ] Sanitize HTML with DOMPurify before rendering
- [ ] Use modern frameworks (React, Vue) with built-in escaping
- [ ] Implement Content Security Policy (CSP)
- [ ] Never allow user control over template selection
- [ ] Validate and sanitize all user input

---

## Dependency Confusion Attacks

**CWE-494: Download of Code Without Integrity Check**

### What is Dependency Confusion?

Attackers publish malicious packages with the same name as internal packages to public registries, tricking package managers into installing the malicious version.

### Vulnerable Configuration

```json
// VULNERABLE: No registry scoping
{
  "name": "my-app",
  "dependencies": {
    "internal-utils": "^1.0.0"  // Could be hijacked
  }
}
```

### Secure Configuration

```json
// SECURE: Use .npmrc to scope packages
// .npmrc
@mycompany:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

```json
// package.json
{
  "name": "@mycompany/my-app",
  "dependencies": {
    "@mycompany/internal-utils": "^1.0.0"  // Scoped to private registry
  }
}
```

**Mitigation Checklist:**

- [ ] Use scoped packages (@yourcompany/package)
- [ ] Configure `.npmrc` to lock scopes to private registries
- [ ] Use package-lock.json/pnpm-lock.yaml and commit them
- [ ] Enable npm audit in CI/CD
- [ ] Monitor for unexpected package downloads
- [ ] Use integrity hashes (npm automatically includes in lock files)

---

## Unsafe Deserialization

**CWE-502: Deserialization of Untrusted Data**

### Vulnerable Code Examples

```typescript
// VULNERABLE: Direct JSON.parse without validation
app.post('/api/data', (req, res) => {
  const data = JSON.parse(req.body.input);  // No validation
  processData(data);
});

// VULNERABLE: eval on user input
const userCode = req.query.code;
const result = eval(userCode);  // RCE vulnerability

// VULNERABLE: Function constructor
const fn = new Function('return ' + req.body.expression);
const result = fn();  // Code injection
```

### Secure Alternatives

```typescript
// SECURE: Schema validation with Zod
import { z } from 'zod';

const DataSchema = z.object({
  id: z.number(),
  name: z.string().max(100),
  tags: z.array(z.string()),
});

app.post('/api/data', (req, res) => {
  try {
    const data = DataSchema.parse(JSON.parse(req.body.input));
    processData(data);  // Safe - validated structure
  } catch (error) {
    res.status(400).send('Invalid data');
  }
});

// SECURE: Use safe-eval or vm2 for sandboxed execution
import safeEval from 'safe-eval';

const result = safeEval(req.body.expression, {
  // Provide only safe context
  Math: Math,
  // No access to require, process, etc.
});

// SECURE: Use Protocol Buffers instead of JSON
import protobuf from 'protobufjs';

const Message = protobuf.Type.fromJSON('Message', {
  fields: {
    id: { type: 'uint32', id: 1 },
    name: { type: 'string', id: 2 },
  },
});

const decoded = Message.decode(buffer);  // Strict schema enforcement
```

**Mitigation Checklist:**

- [ ] Never use `eval()` or `Function()` constructor
- [ ] Validate JSON schema before processing
- [ ] Use Zod/AJV for runtime type validation
- [ ] Consider Protocol Buffers for strict serialization
- [ ] Limit JSON parse depth and size
- [ ] Use allowlists for permitted data structures

---

## Path Traversal in Node.js

**CWE-22: Path Traversal**

### Vulnerable Code Examples

```typescript
// VULNERABLE: Direct path concatenation
app.get('/files/:filename', (req, res) => {
  const file = `./uploads/${req.params.filename}`;
  res.sendFile(file);  // Attack: ../../../etc/passwd
});

// VULNERABLE: Unvalidated path.join
import path from 'path';

app.get('/download', (req, res) => {
  const filePath = path.join('./data', req.query.file);
  res.sendFile(filePath);  // Still vulnerable
});
```

### Secure Alternatives

```typescript
// SECURE: Validate and resolve paths
import path from 'path';

app.get('/files/:filename', (req, res) => {
  const uploadsDir = path.resolve('./uploads');
  const requestedFile = path.resolve(uploadsDir, req.params.filename);

  // Ensure the resolved path is within uploads directory
  if (!requestedFile.startsWith(uploadsDir)) {
    return res.status(403).send('Access denied');
  }

  res.sendFile(requestedFile);
});

// SECURE: Use allowlist of permitted files
const ALLOWED_FILES = new Set(['report.pdf', 'invoice.pdf']);

app.get('/download', (req, res) => {
  const filename = path.basename(req.query.file);  // Strip path components

  if (!ALLOWED_FILES.has(filename)) {
    return res.status(403).send('File not allowed');
  }

  res.sendFile(path.join('./data', filename));
});

// SECURE: Use fs.promises with proper validation
import { promises as fs } from 'fs';

async function safeReadFile(userPath: string): Promise<string> {
  const baseDir = path.resolve('./safe-directory');
  const safePath = path.resolve(baseDir, userPath);

  if (!safePath.startsWith(baseDir)) {
    throw new Error('Path traversal detected');
  }

  const stats = await fs.stat(safePath);
  if (!stats.isFile()) {
    throw new Error('Not a file');
  }

  return fs.readFile(safePath, 'utf-8');
}
```

**Mitigation Checklist:**

- [ ] Always use `path.resolve()` and check result
- [ ] Validate paths are within allowed directory
- [ ] Use `path.basename()` to strip directory components
- [ ] Implement allowlist of permitted files
- [ ] Never trust user-supplied file paths
- [ ] Use `path.normalize()` to remove `../` sequences

---

## Common CWEs for TypeScript

| CWE     | Description                         | Mitigation                                |
| ------- | ----------------------------------- | ----------------------------------------- |
| CWE-22  | Path Traversal                      | Validate paths, use path.resolve()        |
| CWE-78  | OS Command Injection                | Use execFile with argument arrays         |
| CWE-79  | Cross-site Scripting (XSS)          | Use textContent, sanitize HTML            |
| CWE-89  | SQL Injection                       | Use parameterized queries                 |
| CWE-94  | Code Injection (SSTI)               | Escape template output, use CSP           |
| CWE-95  | Eval Injection                      | Never use eval(), Function()              |
| CWE-338 | Weak PRNG                           | Use crypto.randomBytes()                  |
| CWE-502 | Unsafe Deserialization              | Validate JSON schema, use Protocol Buffers|
| CWE-798 | Hard-coded Credentials              | Use environment variables                 |
| CWE-1321| Prototype Pollution                 | Validate keys, use Object.create(null)    |
| CWE-1333| ReDoS                               | Avoid nested quantifiers, set timeouts    |

---

## Additional Resources

- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Semgrep TypeScript Rules](https://semgrep.dev/p/typescript)
- [Snyk Vulnerability Database](https://security.snyk.io/)
- [npm Security Advisories](https://www.npmjs.com/advisories)
