import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { glob } from 'glob';
import yaml from 'js-yaml';
import { StackSchema } from '../schemas/stack-schema.js';

const ROOT = resolve(import.meta.dirname, '..');

async function main(): Promise<void> {
  const stackFiles = await glob('stacks/*/stack.yaml', { cwd: ROOT });

  if (stackFiles.length === 0) {
    console.error('No stack.yaml files found');
    process.exit(1);
  }

  let errors = 0;

  for (const relPath of stackFiles.sort()) {
    const absPath = join(ROOT, relPath);
    const raw = readFileSync(absPath, 'utf-8');
    const data: unknown = yaml.load(raw);

    const result = StackSchema.safeParse(data);
    if (!result.success) {
      console.error(`FAIL ${relPath}:`);
      for (const issue of result.error.issues) {
        console.error(`  - ${issue.path.join('.')}: ${issue.message}`);
      }
      errors++;
      continue;
    }

    const stack = result.data;

    // Validate referenced files exist
    const stackDir = join(ROOT, 'stacks', stack.name);
    const refs = [
      stack.ciTemplates.concourse,
      stack.ciTemplates.githubActions,
      stack.skill,
    ];
    for (const ref of refs) {
      const refPath = join(stackDir, ref);
      if (!existsSync(refPath)) {
        console.error(`FAIL ${relPath}: referenced file missing: ${ref}`);
        errors++;
      }
    }

    // Validate scanner configs exist (skip "shared" references)
    for (const category of Object.values(stack.scanners)) {
      for (const scanner of category) {
        if (scanner.config && scanner.config !== 'shared') {
          const configPath = join(stackDir, scanner.config);
          if (!existsSync(configPath)) {
            console.error(
              `FAIL ${relPath}: scanner config missing: ${scanner.config}`
            );
            errors++;
          }
        }
      }
    }

    if (errors === 0) {
      console.log(`OK   ${relPath} (${stack.displayName})`);
    }
  }

  console.log(`\n${stackFiles.length} stacks validated, ${errors} errors`);
  if (errors > 0) process.exit(1);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
