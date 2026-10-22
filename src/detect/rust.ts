import { parse as parseToml } from 'smol-toml';
import { readManifest, isPlainObject, ownObject } from './util.ts';
import type { DetectInput } from './util.ts';
import type { Confidence } from '../checks/types.ts';

export interface RustFacts {
  confidence: Confidence;
  evidence: string[];
  notes: string[];
  blocker?: string;
  /** Dependencies that must be downloaded (registry or git), excluding local path deps. */
  remoteDependencyCount: number;
  locked: boolean;
}

const DEP_TABLES = ['dependencies', 'dev-dependencies', 'build-dependencies'];

function countRemote(table: Record<string, unknown> | undefined, notes: string[]): number {
  let n = 0;
  for (const value of Object.values(table ?? {})) {
    if (isPlainObject(value)) {
      if (Object.hasOwn(value, 'git') && !notes.includes('git dependencies cannot be fetched by the sandbox.')) {
        notes.push('git dependencies cannot be fetched by the sandbox.');
      }
      const local = Object.hasOwn(value, 'path') && !Object.hasOwn(value, 'version') && !Object.hasOwn(value, 'git');
      const inherited = value.workspace === true;
      if (!local && !inherited) n++;
    } else {
      n++;
    }
  }
  return n;
}

export function detectRust(input: DetectInput, present: ReadonlySet<string>): RustFacts | null {
  if (!present.has('Cargo.toml')) return null;
  const evidence = ['Cargo.toml'];
  const locked = present.has('Cargo.lock');
  if (locked) evidence.push('Cargo.lock');
  const notes: string[] = [];
  const base = { evidence, notes, remoteDependencyCount: 0, locked };

  const m = readManifest(input, 'Cargo.toml', present);
  if (m.state !== 'ok') return { ...base, confidence: 'low', blocker: 'Cargo.toml is too large or not valid UTF-8.' };
  let doc: unknown;
  try {
    doc = parseToml(m.text);
  } catch {
    return { ...base, confidence: 'low', blocker: 'Cargo.toml could not be parsed.' };
  }
  if (!isPlainObject(doc)) return { ...base, confidence: 'low', blocker: 'Cargo.toml could not be parsed.' };
  const pkg = ownObject(doc, 'package');
  const workspace = ownObject(doc, 'workspace');
  if (!pkg && !workspace) return { ...base, confidence: 'low', blocker: 'Cargo.toml has neither [package] nor [workspace].' };

  let remote = 0;
  for (const t of DEP_TABLES) remote += countRemote(ownObject(doc, t), notes);
  const target = ownObject(doc, 'target');
  for (const cfg of Object.values(target ?? {})) {
    if (isPlainObject(cfg)) for (const t of DEP_TABLES) remote += countRemote(ownObject(cfg, t), notes);
  }
  if (workspace) {
    remote += countRemote(ownObject(workspace, 'dependencies'), notes);
    notes.push('Cargo workspace: member crates may declare more dependencies; all are fetched by cargo.');
    if (remote === 0) remote = 1; // members are not inspected; assume a fetch may be needed
  }
  if (present.has('rust-toolchain') || present.has('rust-toolchain.toml')) {
    notes.push('A pinned rust-toolchain file is present; the sandbox only has its image toolchain, so the run may fail.');
  }
  if (!locked && remote > 0) notes.push('No Cargo.lock: dependency versions are resolved at fetch time.');

  return { ...base, confidence: 'medium', remoteDependencyCount: remote };
}
