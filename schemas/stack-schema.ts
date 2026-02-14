import { z } from 'zod';

const ScannerEntrySchema = z.object({
  name: z.string().min(1),
  rulesets: z.array(z.string()).optional(),
  scanType: z.string().optional(),
  config: z.string().optional(),
  applicableTo: z.array(z.string()).optional(),
});

export const StackSchema = z.object({
  name: z.string().min(1),
  displayName: z.string().min(1),
  category: z.enum(['compiled', 'interpreted', 'infrastructure']),
  packageManagers: z.array(z.string()).default([]),
  buildTools: z.array(z.string()).default([]),
  frameworks: z.array(z.string()).default([]),
  scanners: z.object({
    sast: z.array(ScannerEntrySchema).default([]),
    sca: z.array(ScannerEntrySchema).default([]),
    secrets: z.array(ScannerEntrySchema).default([]),
    dast: z.array(ScannerEntrySchema).default([]),
    container: z.array(ScannerEntrySchema).default([]),
  }),
  ciTemplates: z.object({
    concourse: z.string(),
    githubActions: z.string(),
  }),
  skill: z.string(),
  compliance: z.array(z.string()).default([]),
});

export type Stack = z.infer<typeof StackSchema>;
export type ScannerEntry = z.infer<typeof ScannerEntrySchema>;
