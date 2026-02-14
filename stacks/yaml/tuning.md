# YAML Security Tuning Guide

## Overview

YAML configurations drive infrastructure, CI/CD, and orchestration. Misconfigurations can expose entire environments. This guide covers advanced security hardening for Kubernetes, CI/CD pipelines, and configuration management.

## Critical Security Vectors

### 1. Kubernetes Container Escape (CWE-250, CWE-269)

**Attack Surface:**
- Privileged containers
- hostPID/hostIPC/hostNetwork namespace sharing
- hostPath volume mounts
- Excessive capabilities (CAP_SYS_ADMIN, CAP_NET_RAW)
- allowPrivilegeEscalation: true

**Hardening:**

```yaml
# Maximum security deployment template
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
  labels:
    app: secure-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
      annotations:
        # Admission controller annotations
        container.apparmor.security.beta.kubernetes.io/app: runtime/default
    spec:
      # Pod-level security
      securityContext:
        runAsNonRoot: true
        runAsUser: 10000
        runAsGroup: 10000
        fsGroup: 10000
        supplementalGroups: [10000]
        seccompProfile:
          type: RuntimeDefault
        # SELinux (if available)
        seLinuxOptions:
          level: "s0:c123,c456"

      # Service account
      serviceAccountName: app-sa
      automountServiceAccountToken: false

      # No host namespaces
      hostNetwork: false
      hostPID: false
      hostIPC: false

      # DNS policy
      dnsPolicy: ClusterFirst

      containers:
        - name: app
          image: registry.io/app:v1.2.3@sha256:abc123...
          imagePullPolicy: Always

          # Container security context
          securityContext:
            runAsNonRoot: true
            runAsUser: 10000
            allowPrivilegeEscalation: false
            privileged: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
              # Only add if absolutely required
              # add:
              #   - NET_BIND_SERVICE

          # Resource limits (prevent DoS)
          resources:
            limits:
              cpu: "1000m"
              memory: "1Gi"
              ephemeral-storage: "2Gi"
            requests:
              cpu: "100m"
              memory: "128Mi"
              ephemeral-storage: "1Gi"

          # Probes
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
              scheme: HTTP
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3

          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5

          startupProbe:
            httpGet:
              path: /startup
              port: 8080
            failureThreshold: 30
            periodSeconds: 10

          # Environment variables (non-sensitive)
          env:
            - name: APP_ENV
              value: "production"
            - name: LOG_LEVEL
              value: "info"

          # Secret references
          envFrom:
            - secretRef:
                name: app-secrets

          # Volume mounts
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /app/cache
            - name: config
              mountPath: /app/config
              readOnly: true

      # Volumes (no hostPath)
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: "1Gi"
        - name: cache
          emptyDir:
            sizeLimit: "2Gi"
        - name: config
          configMap:
            name: app-config
            defaultMode: 0440

      # Affinity rules (spread across nodes/zones)
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - secure-app
                topologyKey: kubernetes.io/hostname

      # Tolerations (if needed for node taints)
      tolerations: []

      # Priority class
      priorityClassName: production-high

      # Termination grace period
      terminationGracePeriodSeconds: 30
```

**Detection Tuning:**
- Semgrep rules: `kubernetes-privileged-container`, `kubernetes-host-network`, `kubernetes-allow-privilege-escalation`
- Kubesec: Score < 0 = critical, < 5 = needs improvement
- Admission controller: OPA/Gatekeeper policy enforcement

### 2. RBAC Misconfiguration (CWE-732)

**Attack Surface:**
- ClusterAdmin role granted to service accounts
- Wildcard permissions (`*` for resources/verbs)
- Overly broad ClusterRoles instead of namespaced Roles
- ServiceAccount token automount when not needed

**Hardening:**

```yaml
# Least privilege service account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
automountServiceAccountToken: false
---
# Minimal role for application needs
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  # Read own pod
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
    # Restrict to own pod via field selector (enforced by admission controller)

  # Read specific ConfigMap
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "watch"]
    resourceNames: ["app-config", "app-feature-flags"]

  # Read specific Secret
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
    resourceNames: ["app-db-credentials"]

  # Create events (for observability)
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]

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
# Audit-only ClusterRole for visibility (read-only)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: audit-viewer
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets"]
    verbs: ["get", "list", "watch"]
  # NO write permissions

---
# Emergency break-glass role (time-limited, logged)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: emergency-admin
  annotations:
    description: "Emergency access - requires incident ticket and audit trail"
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - nonResourceURLs: ["*"]
    verbs: ["*"]
# NOTE: Only bind to specific users during incidents, then revoke
```

**Detection Tuning:**
- KubeLinter: `no-wildcard-verb`, `no-wildcard-resource`
- Semgrep: `kubernetes-automount-service-account-token`
- Custom policy: Alert on any ClusterRoleBinding to cluster-admin

### 3. Network Policy Gaps (CWE-284)

**Attack Surface:**
- No network policies (default allow all)
- Overly permissive egress (all internet access)
- Missing DNS egress rules (breaks applications)
- Cross-namespace traffic when not required

**Hardening:**

```yaml
# Default deny all traffic
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

---
# Application-specific network policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
    - Ingress
    - Egress

  ingress:
    # Allow from ingress controller
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
        - podSelector:
            matchLabels:
              app: nginx-ingress
      ports:
        - protocol: TCP
          port: 8080

    # Allow from same namespace
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080

  egress:
    # Allow DNS (kube-dns/CoreDNS)
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

    # Allow PostgreSQL in same namespace
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432

    # Allow Redis
    - to:
        - podSelector:
            matchLabels:
              app: redis
      ports:
        - protocol: TCP
          port: 6379

    # Allow specific external services (by CIDR or FQDN via Calico)
    - to:
        - podSelector: {}
      ports:
        - protocol: TCP
          port: 443
    # Use Calico NetworkPolicy for FQDN-based egress filtering

---
# Calico GlobalNetworkPolicy for egress filtering by domain
apiVersion: crd.projectcalico.org/v1
kind: GlobalNetworkPolicy
metadata:
  name: allow-external-apis
spec:
  selector: app == 'myapp'
  types:
    - Egress
  egress:
    # Allow specific external APIs by domain
    - action: Allow
      protocol: TCP
      destination:
        domains:
          - "api.stripe.com"
          - "api.github.com"
        ports:
          - 443
```

**Detection Tuning:**
- Manual review: Check for namespaces without NetworkPolicy
- Admission controller: Require NetworkPolicy for all namespaces
- Monitoring: Alert on unexpected external connections (Falco)

### 4. Secrets in CI/CD Pipelines (CWE-532, CWE-798)

**Attack Surface:**
- Secrets in workflow logs
- Secrets in environment variables (visible in process list)
- Hardcoded credentials in pipeline YAML
- Overly permissive GITHUB_TOKEN scope

**Hardening:**

**GitHub Actions:**

```yaml
name: Secure CI/CD
on:
  pull_request:
  push:
    branches: [main]

# Minimal permissions (deny-by-default)
permissions:
  contents: read
  pull-requests: write

jobs:
  build:
    runs-on: ubuntu-latest

    # Environment protection rules
    environment:
      name: production
      url: https://app.example.com

    steps:
      - uses: actions/checkout@v4

      # Pin all action versions with SHA
      - name: Setup Node
        uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v4.0.2

      # Secrets from GitHub Secrets (not hardcoded)
      - name: Deploy
        env:
          # NEVER: run: echo ${{ secrets.API_KEY }}
          # ALWAYS: Use env var intermediary
          API_KEY: ${{ secrets.API_KEY }}
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
        run: |
          # Secrets are in environment, not visible in logs
          ./deploy.sh
          # Script uses $API_KEY and $DB_PASSWORD

      # Prevent accidental secret exposure
      - name: Mask secrets in logs
        run: |
          echo "::add-mask::${{ secrets.API_KEY }}"
          echo "Secret is masked: ${{ secrets.API_KEY }}"

      # Use OIDC for AWS (no long-lived credentials)
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      # Least privilege GITHUB_TOKEN
      - name: Comment on PR
        uses: actions/github-script@v7
        with:
          # Uses GITHUB_TOKEN with minimal scope (pull-requests: write)
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Build completed'
            })
```

**Concourse:**

```yaml
jobs:
  - name: deploy
    plan:
      - get: repo
      - task: deploy-task
        config:
          platform: linux
          image_resource:
            type: registry-image
            source:
              repository: ubuntu
              tag: "22.04"

          # Params from credential manager (not hardcoded)
          params:
            AWS_ACCESS_KEY_ID: ((aws-access-key-id))
            AWS_SECRET_ACCESS_KEY: ((aws-secret-access-key))
            DB_PASSWORD: ((db-password))

          run:
            path: sh
            args:
              - -exc
              - |
                # Credentials in environment, not visible in pipeline YAML
                ./deploy.sh

        # No output logging for sensitive tasks
        ensure:
          task: cleanup-secrets
          config:
            platform: linux
            run:
              path: sh
              args:
                - -c
                - |
                  unset AWS_ACCESS_KEY_ID
                  unset AWS_SECRET_ACCESS_KEY
                  unset DB_PASSWORD
```

**Ansible:**

```yaml
---
- name: Deploy application
  hosts: webservers
  become: yes

  # Load encrypted vars
  vars_files:
    - vars/secrets.yml  # Encrypted with ansible-vault

  tasks:
    # Use no_log for sensitive operations
    - name: Configure database
      template:
        src: db_config.j2
        dest: /etc/app/db.conf
        mode: '0600'
      no_log: true  # Prevent credentials in logs

    - name: Restart service
      systemd:
        name: app
        state: restarted
      no_log: false  # Safe to log

# Encrypt secrets with ansible-vault
# ansible-vault encrypt vars/secrets.yml
# ansible-playbook playbook.yml --ask-vault-pass
```

**Detection Tuning:**
- Semgrep: `github-actions-script-injection`, `ansible-no-log-missing`
- Gitleaks: Scan for hardcoded API keys, passwords in YAML
- Manual review: Check for `${{ secrets.* }}` in `run:` blocks

### 5. Supply Chain Attacks (CWE-829)

**Attack Surface:**
- Mutable image tags (`:latest`, `:v1`)
- Unsigned container images
- Untrusted registries
- Unverified GitHub Actions from marketplace

**Hardening:**

```yaml
# Kubernetes: Image digest pinning + signature verification
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          # Pin to immutable digest
          image: registry.io/app:v1.2.3@sha256:abcdef1234567890...

      # Image pull policy
      imagePullPolicy: Always

      # Image pull secret
      imagePullSecrets:
        - name: registry-creds

---
# Admission controller policy (OPA Gatekeeper)
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredimagedigest
spec:
  crd:
    spec:
      names:
        kind: K8sRequireImageDigest
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredimagedigest

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not contains(container.image, "@sha256:")
          msg := sprintf("Container %v uses tag instead of digest", [container.name])
        }

---
# GitHub Actions: Pin actions by commit SHA
name: CI
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # ❌ BAD: uses: actions/checkout@v4
      # ✅ GOOD: Pin to specific commit SHA
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1

      # Verify signatures of third-party actions (when available)
      - uses: sigstore/cosign-installer@main
        with:
          cosign-release: 'v2.2.0'

      - name: Verify action signature
        run: |
          cosign verify github.com/actions/checkout@sha256:...
```

**Detection Tuning:**
- Semgrep: `kubernetes-latest-tag`
- Admission controller: Block deployments without image digest
- CI: Scan images with Trivy/Grype before deployment

## Scanner Configuration

### Semgrep Rule Priorities

```yaml
HIGH (block merge):
  - kubernetes-privileged-container
  - kubernetes-host-network
  - kubernetes-allow-privilege-escalation
  - kubernetes-secret-plaintext
  - github-actions-script-injection

MEDIUM (review required):
  - kubernetes-missing-resource-limits
  - kubernetes-container-as-root
  - kubernetes-host-path-mount
  - kubernetes-default-namespace
```

### Kubesec Scoring

```
Score < 0:   CRITICAL - Block deployment
Score 0-5:   Needs improvement
Score 6-10:  Good
Score > 10:  Excellent
```

### Admission Controller Integration

```yaml
# OPA Gatekeeper deployment
apiVersion: v1
kind: Namespace
metadata:
  name: gatekeeper-system

---
# Install Gatekeeper
# kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Policy: Require security context
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequireSecurityContext
metadata:
  name: require-security-context
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet"]
  parameters:
    requiredDropCapabilities: ["ALL"]
    allowPrivilegeEscalation: false
    runAsNonRoot: true
```

## Continuous Monitoring

1. **Pre-commit:** yamllint, basic Semgrep checks
2. **PR:** Full scan suite with SARIF upload
3. **Admission:** OPA/Gatekeeper runtime enforcement
4. **Runtime:** Falco behavioral monitoring
5. **Compliance:** Weekly CIS Kubernetes Benchmark scan

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
