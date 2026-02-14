import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { glob } from 'glob';
import yaml from 'js-yaml';
import { StackSchema, type Stack } from '../schemas/stack-schema.js';

const ROOT = resolve(import.meta.dirname, '..');

function scannerNames(entries: Stack['scanners']['sast']): string {
  if (entries.length === 0) return '--';
  return entries.map((e) => e.name).join(', ');
}

async function main(): Promise<void> {
  const stackFiles = await glob('stacks/*/stack.yaml', { cwd: ROOT });
  const stacks: Stack[] = [];

  for (const relPath of stackFiles.sort()) {
    const raw = readFileSync(join(ROOT, relPath), 'utf-8');
    const data: unknown = yaml.load(raw);
    const result = StackSchema.safeParse(data);
    if (result.success) {
      stacks.push(result.data);
    }
  }

  const lines: string[] = [
    '# Compatibility Matrix',
    '',
    '_Auto-generated. Do not edit manually._',
    '',
    '| Language | SAST | SCA | Secrets | DAST | Container |',
    '|----------|------|-----|---------|------|-----------|',
  ];

  for (const s of stacks) {
    lines.push(
      `| ${s.displayName} | ${scannerNames(s.scanners.sast)} | ${scannerNames(s.scanners.sca)} | ${scannerNames(s.scanners.secrets)} | ${scannerNames(s.scanners.dast)} | ${scannerNames(s.scanners.container)} |`
    );
  }

  lines.push('');
  console.log(lines.join('\n'));
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
