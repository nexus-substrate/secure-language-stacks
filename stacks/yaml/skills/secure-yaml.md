---
name: secure-yaml
description: |
  Security scanning guidance for YAML/Kubernetes manifests.
  Triggers on "secure yaml", "yaml security", "scan kubernetes".
allowed-tools: Read, Grep, Glob, Bash
context: fork
---

# Secure YAML Development - nexus-agents Skill

**Skill ID:** `secure-yaml`
**Category:** Security Engineering
**Language Stack:** YAML (Kubernetes, Docker Compose, Ansible, GitHub Actions, Concourse)

## Purpose

Guide secure YAML configuration development for infrastructure and CI/CD, prevent Kubernetes misconfigurations, enforce security contexts, implement RBAC and network policies, and protect secrets in CI/CD pipelines.

## Core Security Principles

### 1. Kubernetes Security Context (CWE-250)

**ALWAYS configure pod and container security contexts:**

```yaml
# ❌ DANGEROUS - No security context (runs as root)
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: myapp:1.0

# ✅ SECURE - Comprehensive security context
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  # Pod-level security context
  securityContext:
    runAsNonRoot: true      # Enforce non-root user
    runAsUser: 1000         # Specific UID
    runAsGroup: 3000        # Specific GID
    fsGroup: 2000           # Volume ownership group
    seccompProfile:
      type: RuntimeDefault  # Default seccomp profile

  containers:
    - name: app
      image: myapp:1.0

      # Container-level security context
      securityContext:
        allowPrivilegeEscalation: false  # Prevent privilege escalation
        readOnlyRootFilesystem: true     # Immutable container filesystem
        privileged: false                # Never run privileged
        capabilities:
          drop:
            - ALL                        # Drop all capabilities
          add:
            - NET_BIND_SERVICE           # Add only required capabilities

      # Resource limits (prevent DoS)
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
        requests:
          cpu: "250m"
          memory: "256Mi"

      # Volume mounts (if read-only root filesystem)
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache

  volumes:
    - name: tmp
      emptyDir: {}
    - name: cache
      emptyDir: {}
```

**Why:** Default Kubernetes pods run as root with full capabilities, enabling container escape and host compromise.

### 2. RBAC Least Privilege (CWE-732)

**Grant minimal required permissions:**

```yaml
# ❌ CRITICAL - ClusterAdmin role
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin  # Full cluster access!
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: default

# ✅ SECURE - Role with specific permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  # Read pods
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]

  # Read/write config maps (app configuration)
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "update"]
    resourceNames: ["app-config"]  # Specific ConfigMap only

  # Read secrets (limited)
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
    resourceNames: ["app-db-credentials"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-role
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: production

---
# Service account with automount disabled
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
automountServiceAccountToken: false  # Disable if not needed
```

**Why:** Overly permissive RBAC allows lateral movement and privilege escalation.

### 3. Network Policies (CWE-284)

**Implement network segmentation:**

```yaml
# ❌ MISSING - No network policy (all traffic allowed)
# Default Kubernetes allows all pod-to-pod traffic

# ✅ SECURE - Deny all by default, allow specific ingress/egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: myapp

  policyTypes:
    - Ingress
    - Egress

  # Ingress: Only from frontend
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080

  # Egress: Only to database and external HTTPS
  egress:
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
        - podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53

    # Allow database
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432

    # Allow external HTTPS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443

---
# Default deny all policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

**Why:** Without network policies, compromised pods can access any other pod in the cluster.

### 4. Secrets Management (CWE-798)

**NEVER store plaintext secrets in YAML:**

```yaml
# ❌ CRITICAL - Plaintext secret in YAML
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
stringData:
  username: admin
  password: SuperSecret123!  # Plaintext in version control!

# ✅ BETTER - Base64 encoded (still visible in etcd)
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
data:
  username: YWRtaW4=  # base64 encoded
  password: U3VwZXJTZWNyZXQxMjMh

# ✅ BEST - External secret manager (sealed secrets, external secrets operator)
# Use SealedSecrets
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  encryptedData:
    username: AgB8... # Encrypted, safe to commit
    password: AgC9... # Encrypted, safe to commit

---
# Or use External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: db-credentials
    creationPolicy: Owner
  data:
    - secretKey: username
      remoteRef:
        key: prod/db/username
    - secretKey: password
      remoteRef:
        key: prod/db/password
```

**Why:** Secrets in YAML are stored plaintext in version control and Kubernetes etcd.

**Additional measures:**
- Encrypt etcd at rest
- Enable Kubernetes encryption providers
- Use RBAC to restrict secret access
- Rotate secrets regularly

### 5. Container Image Security (CWE-829)

**Pin image versions and use trusted registries:**

```yaml
# ❌ DANGEROUS - Latest tag (mutable)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:latest  # Unpredictable, changes without notice

# ✅ SECURE - Pinned version with digest
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myregistry.io/myapp:v1.2.3@sha256:abcd1234...  # Immutable

          # Image pull policy
          imagePullPolicy: Always  # Always verify signature

      # Image pull secrets for private registry
      imagePullSecrets:
        - name: registry-credentials
```

**Why:** `latest` tag is mutable and can be overwritten with malicious images.

### 6. Pod Security Standards (CWE-250)

**Enforce Pod Security Standards:**

```yaml
# Namespace-level enforcement
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Enforce restricted Pod Security Standard
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted

---
# Or use PodSecurityPolicy (deprecated) / Pod Security Admission
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
```

### 7. CI/CD Pipeline Security

**GitHub Actions hardening:**

```yaml
# ❌ DANGEROUS - Script injection vulnerability
name: CI
on:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ❌ CRITICAL - Untrusted input in run
      - name: Greet
        run: echo "Hello ${{ github.event.pull_request.title }}"

# ✅ SECURE - Environment variable intermediary
name: CI
on:
  pull_request:

permissions:
  contents: read  # Minimal permissions

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ✅ SECURE - Use environment variable
      - name: Greet
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "Hello $PR_TITLE"

      # Pin action versions
      - name: Setup Node
        uses: actions/setup-node@v4.0.2  # Pinned version

      # Use GITHUB_TOKEN with minimal scope
      - name: Create comment
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: gh pr comment ${{ github.event.pull_request.number }} --body "Build started"
```

**Concourse pipeline hardening:**

```yaml
# ❌ DANGEROUS - Credentials in pipeline
resources:
  - name: repo
    type: git
    source:
      uri: https://github.com/org/repo
      username: admin
      password: password123  # Hardcoded!

# ✅ SECURE - Use credential manager
resources:
  - name: repo
    type: git
    source:
      uri: https://github.com/org/repo
      username: ((github-username))  # From credential manager
      password: ((github-password))

jobs:
  - name: deploy
    plan:
      - get: repo
      - task: deploy
        config:
          platform: linux
          image_resource:
            type: registry-image
            source:
              repository: ubuntu
              tag: "22.04"  # Pinned version
          run:
            path: sh
            args:
              - -exc
              - |
                # Secure script execution
                set -euo pipefail
                echo "Deploying..."
```

**Ansible playbook hardening:**

```yaml
# ✅ SECURE - Ansible best practices
---
- name: Deploy application
  hosts: webservers
  become: yes
  vars:
    # No hardcoded passwords
    ansible_become_pass: "{{ lookup('env', 'ANSIBLE_BECOME_PASSWORD') }}"

  tasks:
    # Use no_log for sensitive operations
    - name: Create database user
      postgresql_user:
        name: appuser
        password: "{{ db_password }}"
      no_log: true  # Prevent password from appearing in logs

    # Validate inputs
    - name: Ensure app_version is defined
      assert:
        that:
          - app_version is defined
          - app_version is match('^[0-9]+\.[0-9]+\.[0-9]+$')
        fail_msg: "app_version must be semantic version (x.y.z)"

    # Use vault for secrets
    - name: Load secrets
      include_vars:
        file: secrets.yml  # Encrypted with ansible-vault
```

### 8. Docker Compose Security

```yaml
# ❌ DANGEROUS - Privileged container
version: '3.8'
services:
  app:
    image: myapp:latest
    privileged: true  # Full host access!
    network_mode: host

# ✅ SECURE - Restricted container
version: '3.8'
services:
  app:
    image: myapp:1.2.3  # Pinned version

    # Security options
    security_opt:
      - no-new-privileges:true

    # Drop capabilities
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

    # Read-only root filesystem
    read_only: true

    # Tmpfs for writable directories
    tmpfs:
      - /tmp
      - /var/run

    # User
    user: "1000:1000"

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M

    # Network isolation
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
    internal: true  # No external access
```

## Security Scanning Integration

### Semgrep

Run Semgrep for YAML pattern matching:

```bash
semgrep --config=stacks/yaml/configs/.semgrep.yml --config=p/kubernetes .
```

**Detects:**
- Privileged containers
- Missing security contexts
- Host namespace usage
- Plaintext secrets
- Missing resource limits

### Kubesec

Run Kubesec for Kubernetes security scoring:

```bash
kubesec scan deployment.yaml
```

**Detects:**
- Security context issues
- Capability misconfigurations
- Resource limit violations

### KubeLinter

Run KubeLinter for best practices:

```bash
kube-linter lint --config=stacks/yaml/configs/.kube-linter.yaml .
```

**Detects:**
- Image tag issues (latest, no digest)
- Missing liveness/readiness probes
- Security best practice violations

### Checkov

Run Checkov for policy-as-code:

```bash
checkov -d . --framework kubernetes
```

**Detects:**
- 1000+ built-in policies
- CIS Kubernetes Benchmark violations

## Workflow Integration

1. **Pre-commit:** yamllint, basic Semgrep checks
2. **CI Pipeline:** Full scan suite on every PR
3. **Security Gate:** Block merge if ERROR-level findings
4. **Runtime:** OPA/Gatekeeper admission controller enforcement
5. **Monitoring:** Falco runtime security monitoring

## Common Pitfalls

| Pitfall | Impact | Fix |
|---------|--------|-----|
| No security context | Root execution | Set runAsNonRoot, drop capabilities |
| Privileged containers | Container escape | Never use privileged: true |
| Host namespaces | Isolation bypass | Avoid hostNetwork/hostPID/hostIPC |
| No network policies | Lateral movement | Implement deny-all + allowlist |
| Plaintext secrets | Credential exposure | Use SealedSecrets or external secret manager |
| Latest image tag | Supply chain attack | Pin versions with digest |
| No resource limits | Resource exhaustion | Set CPU/memory limits |
| ClusterAdmin RBAC | Privilege escalation | Use least privilege roles |

## References

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
