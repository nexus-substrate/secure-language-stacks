# Secure Language Stacks — Claude Code Instructions

**Project:** Security toolchain reference for top 15 GitHub languages
**Repository:** github.com/williamzujkowski/secure-language-stacks

## Quick Reference

```bash
pnpm install          # Install dependencies
pnpm validate         # Validate all stack.yaml files against Zod schema
pnpm matrix           # Generate compatibility matrix to stdout
pnpm typecheck        # TypeScript type check
pnpm lint             # Check formatting
```

## Structure

```
stacks/{language}/
├── stack.yaml           # Canonical definition (Zod-validated)
├── configs/             # Scanner configs (.semgrep.yml, trivy.yaml, etc.)
├── pipelines/
│   ├── concourse/       # Concourse CI pipeline
│   └── github-actions/  # GitHub Actions workflow
├── skills/              # nexus-agents skill file
└── tuning.md            # Language-specific security guidance
```

## Key Rules

1. **Schema validation** — Every `stack.yaml` must pass `schemas/stack-schema.ts` (Zod)
2. **File references** — All paths in `stack.yaml` (ciTemplates, skill, configs) must point to real files
3. **Shared templates** — Reuse `shared/concourse/` and `shared/github-actions/` templates; only create language-specific configs when needed
4. **Skill format** — Skills use nexus-agents YAML frontmatter (`name`, `description`, `allowed-tools`, `context: fork`)
5. **No runtime code** — This repo is pure reference data (YAML, configs, docs). No application logic.

## Adding a Language

1. Create `stacks/{lang}/` with all required files
2. Write `stack.yaml` following the schema
3. Add scanner configs in `configs/`
4. Add Concourse + GitHub Actions pipelines
5. Add nexus-agents skill
6. Run `pnpm validate` to verify

## Scanner Categories

- **SAST** — Static Application Security Testing (semgrep, language-specific linters)
- **SCA** — Software Composition Analysis (trivy, language audit tools)
- **Secrets** — Secret detection (gitleaks)
- **DAST** — Dynamic Application Security Testing (zap, for web frameworks)
- **Container** — Container image scanning (trivy image mode)
