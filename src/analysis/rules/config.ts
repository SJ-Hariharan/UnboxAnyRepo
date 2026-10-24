/**
 * Configuration rules: install/lifecycle scripts, Dockerfiles, Compose files
 * and GitHub Actions workflows. These inspect parsed structure, so most
 * results are "confirmed" facts about the configuration; whether they are
 * exploitable depends on how the project is deployed.
 */
import type { Finding } from '../types.ts';
import type { InfraAnalysis } from '../infra.ts';
import type { StackAnalysis } from '../stack.ts';
import { make, excerpt } from './finding.ts';
import { isPlainObject } from '../../detect/util.ts';

const NETWORK_IN_SCRIPT = /\b(curl|wget|Invoke-WebRequest|iwr|nc|ncat)\b|https?:\/\/|\bnode\s+-e\b|\bpython3?\s+-c\b|\bbash\s+-c\b|\beval\b|base64\s+(-d|--decode)/;
const DB_PORTS = new Set(['5432', '3306', '6379', '27017', '9200', '5672', '11211', '1433', '2379']);
const DANGEROUS_CAPS = new Set(['ALL', 'SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'SYS_MODULE', 'DAC_READ_SEARCH']);
const UNTRUSTED_CONTEXT = /\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.(?:message|author\.(?:name|email))|commits\b[^}]*\.(?:message|author)|pages\b[^}]*\.page_name)|head_ref)\s*\}\}/;

function lineOf(text: string, needle: RegExp): number | undefined {
  const lines = text.split(/\r?\n/);
  const i = lines.findIndex((l) => needle.test(l));
  return i === -1 ? undefined : i + 1;
}

export function scanConfig(stack: StackAnalysis, infra: InfraAnalysis): Finding[] {
  const out: Finding[] = [];

  // ------------------------------------------------------ lifecycle scripts
  for (const s of stack.scripts) {
    if (s.source !== 'package.json' || s.kind !== 'lifecycle') continue;
    const runsOnInstall = /^(pre|post)?install$/.test(s.name);
    const suspicious = NETWORK_IN_SCRIPT.test(s.command);
    out.push(
      make('CFG', {
        ruleId: suspicious ? 'install.lifecycle-network' : 'install.lifecycle-script',
        title: suspicious ? `"${s.name}" script downloads or evaluates code` : `"${s.name}" lifecycle script runs automatically`,
        category: 'install-script',
        severity: suspicious ? 'high' : runsOnInstall ? 'low' : 'info',
        confidence: suspicious ? 'medium' : 'high',
        status: suspicious ? 'heuristic' : 'informational',
        file: 'package.json',
        evidence: `scripts.${s.name}: ${excerpt(s.command, 160)}`,
        risk: runsOnInstall
          ? `npm runs "${s.name}" automatically during npm install, before you have run anything yourself.${suspicious ? ' It reaches the network or evaluates code, a pattern also used by malicious packages.' : ''}`
          : `npm runs "${s.name}" automatically in some workflows (for example prepare runs on install from Git).${suspicious ? ' It reaches the network or evaluates code.' : ''}`,
        remediation: 'Read the script before installing. Install with --ignore-scripts to skip it, then run only the steps you need.',
        method: 'manifest-analysis',
        references: ['https://docs.npmjs.com/cli/using-npm/scripts#life-cycle-scripts'],
        cwe: 'CWE-829',
      }),
    );
  }

  // ------------------------------------------------------------ Dockerfiles
  for (const d of infra.parsedDockerfiles) {
    const ins = d.instructions;
    const froms = ins.filter((i) => i.op === 'FROM');
    const users = ins.filter((i) => i.op === 'USER');
    const lastUser = users.at(-1);
    const finalFromLine = froms.at(-1)?.line ?? 0;
    const userAfterFinalFrom = users.filter((u) => u.line > finalFromLine).at(-1);
    if (froms.length > 0 && (!userAfterFinalFrom || /^(root|0)(:|$)/.test(userAfterFinalFrom.args.trim()))) {
      out.push(
        make('CFG', {
          ruleId: 'docker.runs-as-root',
          title: 'Container runs as root',
          category: 'docker',
          severity: 'medium',
          confidence: 'high',
          status: 'confirmed',
          file: d.path,
          startLine: lastUser?.line ?? finalFromLine,
          evidence: userAfterFinalFrom ? `USER ${excerpt(userAfterFinalFrom.args, 40)}` : 'No USER instruction in the final stage',
          risk: 'Processes in the container run as root, so a compromise of the application gives root inside the container and makes escapes more damaging.',
          remediation: 'Create an unprivileged user and add USER <name> (or a numeric uid) to the final stage.',
          method: 'builtin-rule',
          references: ['https://docs.docker.com/build/building/best-practices/#user'],
          cwe: 'CWE-250',
        }),
      );
    }
    for (const f of froms) {
      const image = f.args.replace(/--platform=\S+\s+/, '').split(/\s+/)[0] ?? '';
      if (image === 'scratch' || /^\$/.test(image) || froms.some((x) => new RegExp(`\\bAS\\s+${image.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(x.args))) continue;
      const untagged = !image.includes('@') && (!/:[^/]+$/.test(image) || image.endsWith(':latest'));
      if (untagged) {
        out.push(
          make('CFG', {
            ruleId: 'docker.unpinned-base-image',
            title: 'Base image is not pinned',
            category: 'docker',
            severity: 'low',
            confidence: 'high',
            status: 'confirmed',
            file: d.path,
            startLine: f.line,
            evidence: `FROM ${excerpt(image, 80)}`,
            risk: 'An untagged or :latest base image changes over time, so builds are not reproducible and may silently pick up breaking or compromised versions.',
            remediation: 'Pin a specific tag, ideally with a digest (name:tag@sha256:...).',
            method: 'builtin-rule',
            references: ['https://docs.docker.com/build/building/best-practices/#pin-base-image-versions'],
            cwe: 'CWE-1104',
          }),
        );
      }
    }
    for (const i of ins) {
      if (i.op === 'ADD' && /https?:\/\//.test(i.args)) {
        out.push(
          make('CFG', {
            ruleId: 'docker.add-remote-url', title: 'ADD downloads from a URL', category: 'docker', severity: 'medium', confidence: 'high', status: 'confirmed',
            file: d.path, startLine: i.line, evidence: `ADD ${excerpt(i.args, 120)}`,
            risk: 'Remote content is added without integrity verification.',
            remediation: 'Download with a pinned checksum (ADD --checksum=sha256:... or curl + sha256sum -c).',
            method: 'builtin-rule', references: ['https://docs.docker.com/reference/dockerfile/#add'], cwe: 'CWE-494',
          }),
        );
      }
      if (i.op === 'RUN' && /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/.test(i.args)) {
        out.push(
          make('CFG', {
            ruleId: 'docker.curl-pipe-shell', title: 'Image build pipes a download into a shell', category: 'docker', severity: 'medium', confidence: 'high', status: 'confirmed',
            file: d.path, startLine: i.line, evidence: `RUN ${excerpt(i.args, 140)}`,
            risk: 'The build executes whatever the remote server returns at build time, without verification.',
            remediation: 'Download to a file, verify a checksum or signature, then run it.',
            method: 'builtin-rule', references: [], cwe: 'CWE-494',
          }),
        );
      }
      if ((i.op === 'ENV' || i.op === 'ARG') && /^([A-Za-z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_]*)[= ]\s*["']?[^\s"'$]{4,}/i.test(i.args)) {
        const name = /^([A-Za-z0-9_]+)/.exec(i.args)?.[1] ?? '';
        out.push(
          make('CFG', {
            ruleId: 'docker.secret-in-env', title: `Secret-like value baked into the image (${i.op} ${name})`, category: 'secret', severity: 'high', confidence: 'medium', status: 'unverified',
            file: d.path, startLine: i.line, evidence: `${i.op} ${name}=…[redacted]`,
            risk: 'ENV and ARG values are stored in image layers and metadata, visible to anyone who can pull the image.',
            remediation: 'Pass secrets at runtime (environment or secret mounts such as RUN --mount=type=secret), not at build time.',
            method: 'builtin-rule', references: ['https://docs.docker.com/build/building/secrets/'], cwe: 'CWE-522',
          }),
        );
      }
    }
  }

  // ---------------------------------------------------------------- Compose
  for (const c of infra.parsedCompose) {
    const services = c.doc && isPlainObject(c.doc.services) ? c.doc.services : {};
    for (const [name, raw] of Object.entries(services)) {
      if (!isPlainObject(raw)) continue;
      const svc = raw;
      const at = (re: RegExp) => lineOf(c.text, re);
      const base = { file: c.path, method: 'builtin-rule' as const, status: 'confirmed' as const, confidence: 'high' as const, category: 'docker' as const };
      if (svc.privileged === true) {
        out.push(make('CFG', { ...base, ruleId: 'compose.privileged', title: `Service "${name}" runs privileged`, severity: 'high', startLine: at(/privileged:\s*true/), evidence: `${name}: privileged: true`,
          risk: 'A privileged container has nearly full access to the host kernel and devices; escaping it is trivial.', remediation: 'Remove privileged and grant only the specific capabilities or devices required.', references: ['https://docs.docker.com/reference/compose-file/services/#privileged'], cwe: 'CWE-250' }));
      }
      const volumes = Array.isArray(svc.volumes) ? svc.volumes : [];
      for (const v of volumes) {
        const src = typeof v === 'string' ? v.split(':')[0] : isPlainObject(v) && typeof v.source === 'string' ? v.source : '';
        if (src && /docker\.sock$/.test(src)) {
          out.push(make('CFG', { ...base, ruleId: 'compose.docker-socket', title: `Service "${name}" mounts the Docker socket`, severity: 'critical', startLine: at(/docker\.sock/), evidence: `${name}: volume ${excerpt(String(src), 80)}`,
            risk: 'Access to the Docker socket is equivalent to root on the host: the container can start privileged containers and mount the host filesystem.', remediation: 'Avoid mounting the socket; if unavoidable, use a filtering socket proxy with a minimal allowlist.', references: ['https://docs.docker.com/engine/security/#docker-daemon-attack-surface'], cwe: 'CWE-250' }));
        } else if (src === '/' || src === '/etc' || src === '/root' || src === '/var/run') {
          out.push(make('CFG', { ...base, ruleId: 'compose.sensitive-host-mount', title: `Service "${name}" mounts a sensitive host path`, severity: 'high', startLine: at(new RegExp(`["']?${src.replace(/\//g, '\\/')}:`)), evidence: `${name}: volume ${src}`,
            risk: 'Mounting system directories exposes or allows modification of the host.', remediation: 'Mount only the specific project directories the service needs, read-only where possible.', references: [], cwe: 'CWE-732' }));
        }
      }
      if (svc.network_mode === 'host') {
        out.push(make('CFG', { ...base, ruleId: 'compose.host-network', title: `Service "${name}" uses the host network`, severity: 'medium', startLine: at(/network_mode:\s*["']?host/), evidence: `${name}: network_mode: host`,
          risk: 'The container shares the host network stack, can bind any host port and reach services bound to localhost.', remediation: 'Use a bridge network and publish only the ports needed.', references: [], cwe: 'CWE-668' }));
      }
      const caps = Array.isArray(svc.cap_add) ? svc.cap_add.filter((x): x is string => typeof x === 'string') : [];
      const bad = caps.filter((cap) => DANGEROUS_CAPS.has(cap.toUpperCase().replace(/^CAP_/, '')));
      if (bad.length) {
        out.push(make('CFG', { ...base, ruleId: 'compose.dangerous-capability', title: `Service "${name}" adds powerful capabilities`, severity: 'high', startLine: at(/cap_add/), evidence: `${name}: cap_add ${bad.join(', ')}`,
          risk: 'These capabilities allow kernel-level operations that make container escape much easier.', remediation: 'Drop them; grant the narrowest capability that works.', references: [], cwe: 'CWE-250' }));
      }
      const ports = Array.isArray(svc.ports) ? svc.ports.map((p) => (typeof p === 'number' ? String(p) : typeof p === 'string' ? p : isPlainObject(p) ? `${String(p.published ?? '')}:${String(p.target ?? '')}` : '')) : [];
      for (const p of ports) {
        const parts = p.split(':');
        const target = (parts.at(-1) ?? '').split('/')[0] ?? '';
        const boundLocal = parts.length === 3 && /^(127\.0\.0\.1|localhost|\[::1\])$/.test(parts[0] ?? '');
        if (DB_PORTS.has(target) && !boundLocal) {
          out.push(make('CFG', { ...base, ruleId: 'compose.database-port-exposed', title: `Service "${name}" publishes a database port on all interfaces`, severity: 'medium', confidence: 'medium', startLine: at(new RegExp(`${target}`)), evidence: `${name}: ports ${excerpt(p, 40)}`,
            risk: 'Publishing a database port without a host IP binds it on every interface, so it is reachable from the network if the host firewall allows it.', remediation: `Bind to localhost ("127.0.0.1:${target}:${target}") or remove the port mapping and connect over the Compose network.`, references: [], cwe: 'CWE-668' }));
        }
      }
      const env = svc.environment;
      const pairs: [string, string][] = Array.isArray(env)
        ? env.filter((x): x is string => typeof x === 'string' && x.includes('=')).map((x) => [x.slice(0, x.indexOf('=')), x.slice(x.indexOf('=') + 1)])
        : isPlainObject(env) ? Object.entries(env).map(([k, v]) => [k, v === null || v === undefined ? '' : String(v)]) : [];
      for (const [k, v] of pairs) {
        if (/PASSWORD|SECRET|TOKEN|API_KEY/i.test(k) && v !== '' && !/^\$\{?[A-Za-z_]/.test(v)) {
          out.push(make('CFG', { ...base, ruleId: 'compose.hardcoded-credential', category: 'secret', status: 'unverified', confidence: 'medium', title: `Service "${name}" sets ${k.slice(0, 40)} to a literal value`, severity: /^(postgres|password|root|admin|example|changeme|secret)$/i.test(v) ? 'low' : 'medium', startLine: at(new RegExp(k)), evidence: `${name}: ${k.slice(0, 40)}=…[redacted ${v.length} chars]`,
            risk: 'Credentials written into the Compose file are shared with everyone who can read the repository, and default values are often left unchanged in deployments.', remediation: 'Reference variables from an untracked .env file (${VAR}) or Docker secrets.', references: ['https://docs.docker.com/compose/how-tos/use-secrets/'], cwe: 'CWE-798' }));
        }
      }
    }
  }

  // --------------------------------------------------------- GitHub Actions
  for (const w of infra.parsedWorkflows) {
    const doc = w.doc;
    if (!doc) continue;
    const on = doc.on ?? doc.true;
    const triggers = typeof on === 'string' ? [on] : Array.isArray(on) ? on.filter((x): x is string => typeof x === 'string') : isPlainObject(on) ? Object.keys(on) : [];
    const jobs = isPlainObject(doc.jobs) ? doc.jobs : {};
    const base = { file: w.path, category: 'ci' as const, method: 'builtin-rule' as const };
    const topPerms = doc.permissions;
    const jobsWithoutPerms = Object.entries(jobs).filter(([, j]) => isPlainObject(j) && j.permissions === undefined).map(([k]) => k);
    if (topPerms === undefined && jobsWithoutPerms.length > 0) {
      out.push(make('CFG', { ...base, ruleId: 'ci.default-token-permissions', title: 'Workflow does not restrict GITHUB_TOKEN permissions', severity: 'low', confidence: 'high', status: 'informational', startLine: 1, evidence: `No top-level permissions; jobs without permissions: ${jobsWithoutPerms.slice(0, 5).join(', ')}`,
        risk: 'Without an explicit permissions block the token gets the repository default, which may include write access. A compromised step could then push code or tamper with releases.', remediation: 'Add "permissions: contents: read" at the top and grant more only to jobs that need it.', references: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token'], cwe: 'CWE-250' }));
    }
    const permsList: [string, unknown][] = [['workflow', topPerms], ...Object.entries(jobs).map(([k, j]) => [`job ${k}`, isPlainObject(j) ? j.permissions : undefined] as [string, unknown])];
    for (const [where, p] of permsList) {
      if (p === 'write-all') {
        out.push(make('CFG', { ...base, ruleId: 'ci.write-all-permissions', title: `GITHUB_TOKEN has write-all permissions (${where})`, severity: 'high', confidence: 'high', status: 'confirmed', startLine: lineOf(w.text, /write-all/), evidence: `${where}: permissions: write-all`,
          risk: 'Every step, including third-party actions, can write to the repository, packages, releases and more.', remediation: 'Grant only the scopes each job needs (for example contents: read).', references: [], cwe: 'CWE-250' }));
      }
    }
    const prTarget = triggers.includes('pull_request_target') || triggers.includes('workflow_run');
    for (const [jobName, job] of Object.entries(jobs)) {
      if (!isPlainObject(job)) continue;
      const steps = Array.isArray(job.steps) ? job.steps : [];
      if (job['runs-on'] && /self-hosted/.test(JSON.stringify(job['runs-on'])) && triggers.includes('pull_request')) {
        out.push(make('CFG', { ...base, ruleId: 'ci.self-hosted-on-pr', title: `Job "${jobName}" runs pull requests on a self-hosted runner`, severity: 'medium', confidence: 'medium', status: 'heuristic', startLine: lineOf(w.text, /self-hosted/), evidence: `${jobName}: runs-on self-hosted, on: pull_request`,
          risk: 'In a public repository, pull requests from forks can run code on the self-hosted machine.', remediation: 'Use GitHub-hosted runners for untrusted pull requests, or require approval for fork runs.', references: ['https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security'], cwe: 'CWE-829' }));
      }
      for (const st of steps) {
        if (!isPlainObject(st)) continue;
        const uses = typeof st.uses === 'string' ? st.uses : undefined;
        const run = typeof st.run === 'string' ? st.run : undefined;
        if (uses && prTarget && /^actions\/checkout@/.test(uses)) {
          const ref = isPlainObject(st.with) ? String(st.with.ref ?? '') : '';
          if (/github\.event\.pull_request\.head|github\.head_ref|refs\/pull\//.test(ref)) {
            out.push(make('CFG', { ...base, ruleId: 'ci.pr-target-checkout', title: `Privileged workflow checks out untrusted pull request code (${jobName})`, severity: 'critical', confidence: 'medium', status: 'heuristic', startLine: lineOf(w.text, /github\.event\.pull_request\.head|head_ref|refs\/pull/), evidence: `on: pull_request_target/workflow_run; checkout ref: ${excerpt(ref, 80)}`,
              risk: 'pull_request_target runs with repository secrets and a write token. Checking out and building the contributor\'s code lets any fork run code with those privileges ("pwn request").', remediation: 'Use the pull_request trigger for untrusted code, or split into an unprivileged build and a privileged follow-up that never executes PR code.', references: ['https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/'], cwe: 'CWE-829' }));
          }
        }
        if (uses && !uses.startsWith('./') && !uses.startsWith('docker://') && !/@[0-9a-f]{40}$/.test(uses) && !/^(actions|github)\//.test(uses)) {
          out.push(make('CFG', { ...base, ruleId: 'ci.unpinned-third-party-action', title: 'Third-party action is not pinned to a commit SHA', severity: 'low', confidence: 'high', status: 'confirmed', startLine: lineOf(w.text, new RegExp(uses.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))), evidence: `uses: ${excerpt(uses, 100)}`,
            risk: 'Tags can be moved. If the action\'s repository is compromised, the new code runs in this workflow with its token and secrets.', remediation: 'Pin to a full commit SHA and let a dependency bot propose updates.', references: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions'], cwe: 'CWE-829' }));
        }
        if (run && UNTRUSTED_CONTEXT.test(run)) {
          out.push(make('CFG', { ...base, ruleId: 'ci.script-injection', title: `Untrusted event data interpolated into a shell step (${jobName})`, severity: 'high', confidence: 'high', status: 'confirmed', startLine: lineOf(w.text, UNTRUSTED_CONTEXT), evidence: excerpt(UNTRUSTED_CONTEXT.exec(run)?.[0] ?? '', 120),
            risk: 'Titles, bodies, branch names and commit messages are attacker-controlled. Interpolated with ${{ }} into run:, they become shell code.', remediation: 'Pass the value through an environment variable (env: TITLE: ${{ ... }}) and reference "$TITLE" in the script.', references: ['https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections'], cwe: 'CWE-78' }));
        }
      }
    }
  }
  return out;
}
