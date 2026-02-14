
> secure-language-stacks@1.0.0 matrix /home/william/git/secure-language-stacks
> tsx scripts/generate-matrix.ts

# Compatibility Matrix

_Auto-generated. Do not edit manually._

| Language | SAST | SCA | Secrets | DAST | Container |
|----------|------|-----|---------|------|-----------|
| C++ | semgrep, cppcheck | trivy | gitleaks | -- | trivy |
| Go | semgrep, gosec | trivy, govulncheck | gitleaks | -- | trivy |
| HCL | semgrep, tfsec | trivy | gitleaks | -- | -- |
| Java | semgrep, spotbugs | trivy, dependency-check | gitleaks | zap | trivy |
| JavaScript | semgrep, eslint-plugin-security | trivy, npm-audit | gitleaks | zap | trivy |
| Kotlin | semgrep, detekt | trivy, dependency-check | gitleaks | zap | trivy |
| PHP | semgrep, phpstan | trivy, composer-audit | gitleaks | zap | trivy |
| Python | semgrep, bandit | trivy, pip-audit | gitleaks | zap | trivy |
| Ruby | semgrep, brakeman | trivy, bundler-audit | gitleaks | zap | trivy |
| Rust | semgrep | trivy, cargo-audit | gitleaks | -- | trivy |
| Shell | semgrep, shellcheck | -- | gitleaks | -- | -- |
| SQL | semgrep, sqlfluff | -- | gitleaks | -- | -- |
| Swift | semgrep | trivy | gitleaks | -- | -- |
| TypeScript | semgrep, eslint-plugin-security | trivy, npm-audit | gitleaks | zap | trivy |
| YAML | semgrep | -- | gitleaks | -- | -- |

