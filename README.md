# Secure Language Stacks

Security toolchain reference for the top 15 GitHub languages. Each stack provides scanner configs, reusable CI templates (Concourse + GitHub Actions), and [nexus-agents](https://github.com/williamzujkowski/nexus-agents) skills.

[![Validate Stacks](https://github.com/williamzujkowski/secure-language-stacks/actions/workflows/validate.yml/badge.svg)](https://github.com/williamzujkowski/secure-language-stacks/actions/workflows/validate.yml)

## Languages

| Language | Category | SAST | SCA | Secrets | DAST | Container |
|----------|----------|------|-----|---------|------|-----------|
| [TypeScript](stacks/typescript/) | compiled | semgrep, eslint-security | trivy, npm-audit | gitleaks | zap | trivy |
| [JavaScript](stacks/javascript/) | interpreted | semgrep, eslint-security | trivy, npm-audit | gitleaks | zap | trivy |
| [Python](stacks/python/) | interpreted | semgrep, bandit | trivy, pip-audit | gitleaks | zap | trivy |
| [Java](stacks/java/) | compiled | semgrep, spotbugs | trivy, dependency-check | gitleaks | zap | trivy |
| [Go](stacks/go/) | compiled | semgrep, gosec | trivy, govulncheck | gitleaks | -- | trivy |
| [Rust](stacks/rust/) | compiled | semgrep | trivy, cargo-audit | gitleaks | -- | trivy |
| [C++](stacks/cpp/) | compiled | semgrep, cppcheck | trivy | gitleaks | -- | trivy |
| [Kotlin](stacks/kotlin/) | compiled | semgrep, detekt | trivy, dependency-check | gitleaks | zap | trivy |
| [Swift](stacks/swift/) | compiled | semgrep | trivy | gitleaks | -- | -- |
| [SQL](stacks/sql/) | infrastructure | semgrep, sqlfluff | -- | gitleaks | -- | -- |
| [Ruby](stacks/ruby/) | interpreted | semgrep, brakeman | trivy, bundler-audit | gitleaks | zap | trivy |
| [PHP](stacks/php/) | interpreted | semgrep, phpstan | trivy, composer-audit | gitleaks | zap | trivy |
| [Shell](stacks/shell/) | interpreted | semgrep, shellcheck | -- | gitleaks | -- | -- |
| [HCL](stacks/hcl/) | infrastructure | semgrep, tfsec | trivy | gitleaks | -- | -- |
| [YAML](stacks/yaml/) | infrastructure | semgrep | -- | gitleaks | -- | -- |

## Usage

### As a Reference

Browse `stacks/{language}/` for scanner configs, CI templates, and security guidance.

### With nexus-agents

Each stack includes a skill file (`skills/secure-{lang}.md`) loadable by nexus-agents for automated security scanning guidance.

### CI Integration

Copy pipeline templates from `stacks/{language}/pipelines/` into your project:

- **Concourse:** `pipelines/concourse/pipeline.yml`
- **GitHub Actions:** `pipelines/github-actions/security.yml`

Both reference shared reusable templates in `shared/`.

## Validation

```bash
pnpm install
pnpm validate   # Validate all stack.yaml files
pnpm matrix     # Generate compatibility matrix
```

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## Architecture Decisions

- [ADR-0001: Stack Schema Design](docs/ADR-0001-stack-schema.md)

## License

MIT
