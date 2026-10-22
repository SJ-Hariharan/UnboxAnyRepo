import { parse as parseToml } from 'smol-toml';
import { readManifest, isPlainObject, ownObject } from './util.ts';
import type { DetectInput } from './util.ts';
import { parseRequirements, isSafeSpec, MAX_SPECS } from './requirements.ts';
import type { Confidence } from '../checks/types.ts';

export interface PythonFacts {
  confidence: Confidence;
  evidence: string[];
  notes: string[];
  /** Why dependencies can't be determined safely; checks are then unavailable. */
  blocker?: string;
  specs: string[];
  usesPytest: boolean;
  hasTests: boolean;
  /** Start directory for unittest discovery: 'tests', 'test' or '.'. */
  unittestStart: 'tests' | 'test' | '.';
  srcLayout: boolean;
}

const ROOT_REQ_RE = /^(requirements|requirements[-_](dev|test|tests|testing)|(dev|test|tests)[-_]requirements)\.txt$/;
const DIR_REQ_RE = /^requirements\/(base|common|dev|test|tests|testing)\.txt$/;
const TEST_GROUPS = new Set(['test', 'tests', 'testing', 'dev']);

function stringArray(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  return v.every((x) => typeof x === 'string') ? (v as string[]) : null;
}

export function detectPython(input: DetectInput, present: ReadonlySet<string>): PythonFacts | null {
  const evidence: string[] = [];
  for (const f of ['pyproject.toml', 'setup.py', 'setup.cfg', 'Pipfile', 'poetry.lock', 'tox.ini', 'pytest.ini', 'conftest.py']) {
    if (present.has(f)) evidence.push(f);
  }
  const reqFiles = [...present].filter((p) => ROOT_REQ_RE.test(p) || DIR_REQ_RE.test(p)).sort();
  evidence.push(...reqFiles);

  const pyFiles = input.files.filter((f) => f.path.endsWith('.py'));
  if (evidence.length === 0 && pyFiles.length === 0) return null;
  if (evidence.length === 0 && pyFiles.length > 0) {
    // Loose .py files without any project metadata: too ambiguous to plan anything.
    return {
      confidence: 'low',
      evidence: ['*.py files'],
      notes: [],
      blocker: 'Python files found, but no project metadata (pyproject.toml, setup.py or requirements.txt).',
      specs: [],
      usesPytest: false,
      hasTests: false,
      unittestStart: '.',
      srcLayout: false,
    };
  }

  const notes: string[] = [];
  const specs: string[] = [];
  let blocker: string | undefined;
  let usesPytest = present.has('pytest.ini') || present.has('conftest.py') || present.has('tests/conftest.py');
  let projectDeclaresDeps = false;
  let poetryOnly = false;

  const pp = readManifest(input, 'pyproject.toml', present);
  if (pp.state === 'ok') {
    let doc: unknown;
    try {
      doc = parseToml(pp.text);
    } catch {
      blocker = 'pyproject.toml could not be parsed.';
    }
    if (isPlainObject(doc)) {
      const project = ownObject(doc, 'project');
      const tool = ownObject(doc, 'tool');
      if (tool && ownObject(tool, 'pytest')) usesPytest = true;
      if (project) {
        projectDeclaresDeps = true;
        const deps = Object.hasOwn(project, 'dependencies') ? stringArray(project.dependencies) : [];
        if (deps === null) blocker = 'pyproject.toml [project].dependencies is not a list of strings.';
        else specs.push(...deps);
        const optional = ownObject(project, 'optional-dependencies');
        for (const [group, list] of Object.entries(optional ?? {})) {
          if (!TEST_GROUPS.has(group)) continue;
          const arr = stringArray(list);
          if (arr === null) blocker = `pyproject.toml optional dependency group "${group}" is not a list of strings.`;
          else specs.push(...arr);
        }
        const dynamic = stringArray(project.dynamic) ?? [];
        if (dynamic.includes('dependencies')) {
          notes.push('pyproject.toml declares dynamic dependencies, which cannot be read without running the build backend.');
          projectDeclaresDeps = false;
        }
      } else if (tool && ownObject(tool, 'poetry')) {
        poetryOnly = true;
      }
      const groups = ownObject(doc, 'dependency-groups');
      for (const [group, list] of Object.entries(groups ?? {})) {
        if (!TEST_GROUPS.has(group) || !Array.isArray(list)) continue;
        for (const item of list) if (typeof item === 'string') specs.push(item);
      }
    }
  } else if (pp.state === 'too_large' || pp.state === 'invalid_encoding') {
    blocker = 'pyproject.toml is too large or not valid UTF-8.';
  }

  for (const cfg of ['setup.cfg', 'tox.ini']) {
    const r = readManifest(input, cfg, present);
    if (r.state === 'ok' && /^\[(tool:)?pytest\]/m.test(r.text)) usesPytest = true;
  }

  // Requirements files: root requirements.txt variants first.
  for (const file of reqFiles) {
    const res = parseRequirements(file, (p) => {
      const r = readManifest(input, p, present);
      return r.state === 'ok' ? r.text : undefined;
    });
    if (res.rejected) {
      blocker = `${file}: ${res.rejected}.`;
      break;
    }
    specs.push(...res.specs);
    for (const w of res.warnings) if (!notes.includes(w)) notes.push(w);
  }

  // Validate every spec from every source with the same strict rule.
  if (!blocker) {
    for (const s of specs) {
      if (!isSafeSpec(s.trim())) {
        blocker = `Dependency "${s.replace(/[^\x20-\x7e]/g, '?').slice(0, 60)}" is not a plain package specifier (URLs, paths and VCS references are not supported).`;
        break;
      }
    }
  }
  const unique = [...new Set(specs.map((s) => s.trim()))];
  if (!blocker && unique.length > MAX_SPECS) blocker = `More than ${MAX_SPECS} dependencies declared.`;
  if (unique.some((s) => /^pytest(?![A-Za-z0-9._-])/i.test(s))) usesPytest = true;

  if (!blocker && poetryOnly && reqFiles.length === 0) {
    blocker = 'Poetry-managed dependencies are not supported in this version.';
  }
  if (!blocker && !projectDeclaresDeps && reqFiles.length === 0 && (present.has('setup.py') || present.has('setup.cfg') || present.has('Pipfile'))) {
    blocker = 'Dependencies are declared in a format that cannot be read without executing project code (setup.py / setup.cfg / Pipfile).';
  }

  const testFiles = pyFiles.filter((f) => /(^|\/)(test_[^/]*|[^/]*_test)\.py$/.test(f.path));
  const hasTests = testFiles.length > 0;
  const unittestStart = testFiles.some((f) => f.path.startsWith('tests/'))
    ? 'tests'
    : testFiles.some((f) => f.path.startsWith('test/'))
      ? 'test'
      : '.';
  const srcLayout = input.files.some((f) => f.path.startsWith('src/') && f.path.endsWith('.py'));
  if (srcLayout) notes.push('src/ layout detected; src/ is added to PYTHONPATH (the project itself is not pip-installed).');

  const confidence: Confidence = blocker ? 'low' : hasTests ? 'high' : 'medium';
  return {
    confidence,
    evidence,
    notes,
    ...(blocker ? { blocker } : {}),
    specs: unique,
    usesPytest,
    hasTests,
    unittestStart,
    srcLayout,
  };
}
