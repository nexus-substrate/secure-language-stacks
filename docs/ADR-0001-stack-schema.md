# ADR-0001: Stack Schema Design

## Status

Accepted

## Context

We need a consistent format for defining security toolchains per language. The schema must capture scanners across five categories (SAST, SCA, secrets, DAST, container), CI template references, and nexus-agents skill links.

## Decision

Use a YAML-based `stack.yaml` per language directory, validated at CI time by a Zod schema (`schemas/stack-schema.ts`).

Key design choices:

1. **YAML over JSON** — More readable for DevSecOps practitioners who will consume and customize these configs.
2. **Zod validation** — Type-safe schema with clear error messages. Shared between validation script and TypeScript consumers.
3. **Five scanner categories** — SAST, SCA, secrets, DAST, container. Mirrors OWASP DevSecOps pipeline stages.
4. **Dual CI support** — Both Concourse and GitHub Actions templates per stack, reflecting real-world enterprise diversity.
5. **Flat directory structure** — `stacks/{lang}/` with predictable subdirectories. No nesting beyond one level.

## Consequences

- Adding a new language requires creating a full directory with stack.yaml, configs, pipelines, and skill.
- Schema changes require updating all existing stacks (validated by CI).
- Scanner configs are language-specific but reference shared Concourse/GHA templates.
