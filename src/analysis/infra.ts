/**
 * Container, Compose and CI configuration, parsed without running anything.
 * YAML is parsed with alias limits; documents that fail to parse are reported
 * as such rather than guessed at.
 */
import { parseAllDocuments } from 'yaml';
import type { SourceView } from './source.ts';
import type { DockerfileInfo, ComposeInfo, CiInfo, EnvVarInfo } from './types.ts';
import { isDockerfile, isComposeFile, ciProviderOf, isVendored, isEnvExample, isCommittedEnvFile } from './paths.ts';
import { isPlainObject, displayText } from '../detect/util.ts';

export interface DockerInstruction {
  line: number;
  op: string;
  args: string;
}

export interface ParsedDockerfile {
  path: string;
  instructions: DockerInstruction[];
}

export interface ParsedYaml {
  path: string;
  doc: Record<string, unknown> | undefined;
  text: string;
  error?: string;
}

export interface InfraAnalysis {
  dockerfiles: DockerfileInfo[];
  compose: ComposeInfo[];
  ci: CiInfo[];
  parsedDockerfiles: ParsedDockerfile[];
  parsedCompose: ParsedYaml[];
  parsedWorkflows: ParsedYaml[];
  parseErrors: string[];
}

/** Join continuation lines and split a Dockerfile into instructions. */
export function parseDockerfile(text: string): DockerInstruction[] {
  const out: DockerInstruction[] = [];
  const rawLines = text.split(/\r?\n/);
  let buf = '';
  let start = 0;
  for (let i = 0; i < rawLines.length && out.length < 2000; i++) {
    const line = rawLines[i] as string;
    if (buf === '' && /^\s*(#|$)/.test(line)) continue;
    if (buf === '') start = i + 1;
    if (/\\\s*$/.test(line)) {
      buf += `${line.replace(/\\\s*$/, '')} `;
      continue;
    }
    buf += line;
    const m = /^\s*([A-Za-z]+)\s+([\s\S]*)$/.exec(buf);
    if (m) out.push({ line: start, op: (m[1] as string).toUpperCase(), args: (m[2] as string).trim() });
    buf = '';
  }
  return out;
}

export function parseYamlDoc(text: string): { doc: Record<string, unknown> | undefined; error?: string } {
  try {
    const docs = parseAllDocuments(text, { prettyErrors: false, uniqueKeys: false });
    const list = Array.isArray(docs) ? docs : [docs];
    const first = list[0];
    if (!first) return { doc: undefined };
    if (first.errors.length > 0) return { doc: undefined, error: first.errors[0]?.message.split('\n')[0] ?? 'parse error' };
    const value: unknown = first.toJS({ maxAliasCount: 50 });
    return { doc: isPlainObject(value) ? value : undefined };
  } catch (err) {
    return { doc: undefined, error: err instanceof Error ? err.message.split('\n')[0] : 'parse error' };
  }
}

function asStrings(v: unknown, max = 50): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.filter((x): x is string | number => typeof x === 'string' || typeof x === 'number').slice(0, max).map(String);
  if (isPlainObject(v)) return Object.keys(v).slice(0, max);
  return [];
}

export function analyseInfra(src: SourceView): InfraAnalysis {
  const res: InfraAnalysis = { dockerfiles: [], compose: [], ci: [], parsedDockerfiles: [], parsedCompose: [], parsedWorkflows: [], parseErrors: [] };
  for (const f of src.files) {
    if (isVendored(f.path)) continue;
    if (isDockerfile(f.path) && res.dockerfiles.length < 20) {
      const text = src.text(f.path);
      if (text === undefined) continue;
      const ins = parseDockerfile(text);
      res.parsedDockerfiles.push({ path: f.path, instructions: ins });
      const froms = ins.filter((i) => i.op === 'FROM').map((i) => displayText(i.args.replace(/--platform=\S+\s+/, '').split(/\s+/)[0] ?? '', 120));
      const exposes = ins
        .filter((i) => i.op === 'EXPOSE')
        .flatMap((i) => i.args.split(/\s+/))
        .map((p) => Number.parseInt(p, 10))
        .filter((n) => Number.isInteger(n) && n > 0 && n < 65536);
      const users = ins.filter((i) => i.op === 'USER');
      res.dockerfiles.push({
        path: f.path,
        baseImages: [...new Set(froms)].slice(0, 10),
        exposes: [...new Set(exposes)].slice(0, 20),
        ...(users.length ? { user: displayText((users.at(-1) as DockerInstruction).args, 60) } : {}),
        stages: froms.length,
      });
    } else if (isComposeFile(f.path) && res.compose.length < 10) {
      const text = src.text(f.path);
      if (text === undefined) continue;
      const { doc, error } = parseYamlDoc(text);
      res.parsedCompose.push({ path: f.path, doc, text, ...(error ? { error } : {}) });
      if (error) res.parseErrors.push(`${f.path}: ${displayText(error, 160)}`);
      const services = doc && isPlainObject(doc.services) ? doc.services : {};
      res.compose.push({
        path: f.path,
        services: Object.entries(services)
          .slice(0, 40)
          .map(([name, svc]) => {
            const s = isPlainObject(svc) ? svc : {};
            return {
              name: displayText(name, 60),
              ...(typeof s.image === 'string' ? { image: displayText(s.image, 120) } : {}),
              build: s.build !== undefined,
              ports: asStrings(s.ports, 20).map((p) => displayText(p, 40)),
              dependsOn: asStrings(s.depends_on, 20).map((p) => displayText(p, 60)),
            };
          }),
      });
    } else {
      const provider = ciProviderOf(f.path);
      if (!provider || res.ci.length >= 30) continue;
      const text = src.text(f.path);
      let jobs: string[] = [];
      let triggers: string[] = [];
      if (text !== undefined && provider !== 'Jenkins') {
        const { doc, error } = parseYamlDoc(text);
        if (provider === 'GitHub Actions') res.parsedWorkflows.push({ path: f.path, doc, text, ...(error ? { error } : {}) });
        if (error) res.parseErrors.push(`${f.path}: ${displayText(error, 160)}`);
        if (doc) {
          jobs = asStrings(provider === 'GitHub Actions' ? doc.jobs : Object.fromEntries(Object.entries(doc).filter(([k, v]) => isPlainObject(v) && !k.startsWith('.'))), 30);
          // YAML 1.1 parsers read the key `on` as boolean true; the yaml package keeps "on".
          triggers = asStrings(doc.on ?? doc.true, 20);
        }
      }
      res.ci.push({ path: f.path, provider, jobs: jobs.map((j) => displayText(j, 60)), triggers: triggers.map((t) => displayText(t, 40)) });
    }
  }
  return res;
}

// ------------------------------------------------------------------ env vars

const ENV_NAME = '[A-Z][A-Z0-9_]{1,63}';
const ENV_PATTERNS: [RegExp, RegExp][] = [
  // [file filter, pattern with the name in group 1]
  [/\.(m?[jt]sx?|cjs|mts|cts|vue|svelte|astro)$/, new RegExp(`process\\.env\\.(${ENV_NAME})\\b|process\\.env\\[['"](${ENV_NAME})['"]\\]|import\\.meta\\.env\\.(${ENV_NAME})\\b|Deno\\.env\\.get\\(['"](${ENV_NAME})['"]`, 'g')],
  [/\.py$/, new RegExp(`os\\.environ\\.get\\(\\s*['"](${ENV_NAME})['"]|os\\.environ\\[\\s*['"](${ENV_NAME})['"]|os\\.getenv\\(\\s*['"](${ENV_NAME})['"]|env\\(\\s*['"](${ENV_NAME})['"]`, 'g')],
  [/\.go$/, new RegExp(`os\\.(?:Getenv|LookupEnv)\\(\\s*"(${ENV_NAME})"`, 'g')],
  [/\.rs$/, new RegExp(`env::var(?:_os)?\\(\\s*"(${ENV_NAME})"|env!\\(\\s*"(${ENV_NAME})"`, 'g')],
  [/\.rb$/, new RegExp(`ENV\\[['"](${ENV_NAME})['"]\\]|ENV\\.fetch\\(['"](${ENV_NAME})['"]`, 'g')],
  [/\.php$/, new RegExp(`getenv\\(['"](${ENV_NAME})['"]|\\$_ENV\\[['"](${ENV_NAME})['"]|env\\(['"](${ENV_NAME})['"]`, 'g')],
  [/\.java$|\.kt$/, new RegExp(`System\\.getenv\\(\\s*"(${ENV_NAME})"`, 'g')],
];
/** Variables every process has; listing them as "required" would be noise. */
const AMBIENT = new Set(['NODE_ENV', 'PATH', 'HOME', 'PWD', 'USER', 'SHELL', 'TERM', 'CI', 'LANG', 'TZ', 'TMPDIR', 'DEBUG', 'HOSTNAME', 'GITHUB_ACTIONS', 'VERCEL', 'NETLIFY']);

export function analyseEnv(src: SourceView, infra: InfraAnalysis): { vars: EnvVarInfo[]; exampleFiles: string[]; committedEnvFiles: string[] } {
  const map = new Map<string, { sources: string[]; documented: boolean }>();
  const note = (name: string, source: string, documented = false) => {
    if (AMBIENT.has(name) || (map.size >= 300 && !map.has(name))) return;
    const e = map.get(name) ?? { sources: [], documented: false };
    if (e.sources.length < 5 && !e.sources.includes(source)) e.sources.push(source);
    if (documented) e.documented = true;
    map.set(name, e);
  };
  const exampleFiles: string[] = [];
  const committedEnvFiles: string[] = [];
  for (const f of src.files) {
    if (isVendored(f.path)) continue;
    if (isCommittedEnvFile(f.path)) committedEnvFiles.push(f.path);
    if (isEnvExample(f.path) || isCommittedEnvFile(f.path)) {
      if (isEnvExample(f.path)) exampleFiles.push(f.path);
      const t = src.text(f.path);
      if (!t) continue;
      t.split(/\r?\n/).slice(0, 500).forEach((line, i) => {
        // Names only; values are never read into the result.
        const m = new RegExp(`^\\s*(?:export\\s+)?(${ENV_NAME})\\s*=`).exec(line);
        if (m) note(m[1] as string, `${f.path}:${i + 1}`, isEnvExample(f.path));
      });
    }
  }
  for (const p of src.textPaths()) {
    if (isVendored(p)) continue;
    const rule = ENV_PATTERNS.find(([fileRe]) => fileRe.test(p));
    if (!rule) continue;
    const t = src.text(p);
    if (!t || t.length > 2_000_000) continue;
    const re = new RegExp(rule[1].source, 'g');
    let m: RegExpExecArray | null;
    let count = 0;
    while ((m = re.exec(t)) !== null && count++ < 200) {
      const name = m.slice(1).find((g) => g !== undefined);
      if (!name) continue;
      let line = 1;
      for (let i = 0; i < m.index; i++) if (t.charCodeAt(i) === 10) line++;
      note(name, `${p}:${line}`);
    }
  }
  for (const d of infra.parsedDockerfiles) {
    for (const ins of d.instructions) {
      if (ins.op !== 'ENV' && ins.op !== 'ARG') continue;
      const m = new RegExp(`^(${ENV_NAME})`).exec(ins.args);
      if (m) note(m[1] as string, `${d.path}:${ins.line}`);
    }
  }
  for (const c of infra.parsedCompose) {
    const services = c.doc && isPlainObject(c.doc.services) ? c.doc.services : {};
    for (const svc of Object.values(services)) {
      if (!isPlainObject(svc)) continue;
      const env = svc.environment;
      const names = Array.isArray(env) ? env.filter((x): x is string => typeof x === 'string').map((x) => x.split('=')[0] as string) : isPlainObject(env) ? Object.keys(env) : [];
      for (const n of names.slice(0, 100)) if (new RegExp(`^${ENV_NAME}$`).test(n)) note(n, c.path, true);
    }
  }
  const vars = [...map.entries()]
    .map(([name, v]) => ({ name, sources: v.sources, documented: v.documented }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return { vars, exampleFiles, committedEnvFiles };
}
