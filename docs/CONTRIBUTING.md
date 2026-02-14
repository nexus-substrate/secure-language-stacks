# Contributing

## Adding a New Language Stack

1. Create `stacks/{language}/` with the following structure:

```
stacks/{language}/
├── stack.yaml                        # Canonical definition (Zod-validated)
├── configs/                          # Scanner configuration files
│   ├── .semgrep.yml
│   ├── trivy.yaml
│   └── ...
├── pipelines/
│   ├── concourse/pipeline.yml        # Concourse CI pipeline
│   └── github-actions/security.yml   # GitHub Actions workflow
├── skills/secure-{language}.md       # nexus-agents skill file
└── tuning.md                         # Language-specific security guidance
```

2. Ensure `stack.yaml` passes Zod validation: `pnpm validate`
3. Reference shared scanner templates from `shared/` where possible
4. Add language-specific scanner configs only when the shared templates are insufficient

## Stack YAML Requirements

- `name` must match the directory name
- All file references (`ciTemplates`, `skill`, scanner `config`) must point to existing files
- Use `config: shared` for scanners that use the shared Concourse/GHA templates without custom config

## Skill File Format

Skills follow the nexus-agents format with YAML frontmatter:

```yaml
---
name: secure-{language}
description: |
  Security scanning guidance for {Language} projects.
allowed-tools: Read, Grep, Glob, Bash
context: fork
---
```

## Validation

Run before submitting PRs:

```bash
pnpm validate    # Validate all stack.yaml files
pnpm typecheck   # TypeScript type check
pnpm lint        # Formatting check
```
