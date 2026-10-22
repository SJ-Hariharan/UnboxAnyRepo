import { readManifest } from './util.ts';
import type { DetectInput } from './util.ts';
import type { Confidence } from '../checks/types.ts';

export interface GoFacts {
  confidence: Confidence;
  evidence: string[];
  notes: string[];
  blocker?: string;
  requireCount: number;
  vendored: boolean;
  hasTests: boolean;
  /** e.g. "1.22" from the `go` directive, validated. */
  goVersion?: string;
}

const MODULE_RE = /^module\s+("?)[A-Za-z0-9._~\/-]+\1\s*(\/\/.*)?$/m;
const GO_RE = /^go\s+(1\.\d{1,3})(\.\d{1,3})?\s*(\/\/.*)?$/m;

export function detectGo(input: DetectInput, present: ReadonlySet<string>): GoFacts | null {
  if (!present.has('go.mod')) return null;
  const evidence = ['go.mod'];
  if (present.has('go.sum')) evidence.push('go.sum');
  const notes: string[] = [];
  const base = { evidence, notes, requireCount: 0, vendored: false, hasTests: false };

  const m = readManifest(input, 'go.mod', present);
  if (m.state !== 'ok') return { ...base, confidence: 'low', blocker: 'go.mod is too large or not valid UTF-8.' };
  if (!MODULE_RE.test(m.text)) return { ...base, confidence: 'low', blocker: 'go.mod has no valid module directive.' };

  let requireCount = 0;
  let inBlock = false;
  for (const raw of m.text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (inBlock) {
      if (line === ')') inBlock = false;
      else if (line !== '') requireCount++;
      continue;
    }
    if (/^require\s*\($/.test(line)) inBlock = true;
    else if (/^require\s+\S+/.test(line)) requireCount++;
  }

  const goVersion = GO_RE.exec(m.text)?.[1];
  const vendored = present.has('vendor/modules.txt');
  if (vendored) {
    evidence.push('vendor/modules.txt');
    notes.push('Vendored modules found; checks use -mod=vendor and need no download.');
  }
  if (present.has('go.work')) notes.push('go.work is ignored (GOWORK=off); only the root module is checked.');
  const hasTests = input.files.some((f) => f.path.endsWith('_test.go'));

  return {
    ...base,
    confidence: hasTests ? 'high' : 'medium',
    requireCount,
    vendored,
    hasTests,
    ...(goVersion ? { goVersion } : {}),
  };
}
