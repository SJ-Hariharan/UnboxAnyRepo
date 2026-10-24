/**
 * Secret detection. Values are never stored: evidence shows only a short
 * prefix and the length. A match is "unverified" because RepoRadar never
 * tries a credential to see whether it works (doing so would itself be misuse).
 */
import type { Finding, Severity } from '../types.ts';
import type { SourceView } from '../source.ts';
import { isVendored, isLockfile, isBinaryByName, isTestPath, isCommittedEnvFile, isEnvExample } from '../paths.ts';
import { make, redactValue, downgrade } from './finding.ts';

interface SecretPattern {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  /** Group index holding the secret value (0 = whole match). */
  group: number;
}

const PATTERNS: SecretPattern[] = [
  { id: 'secret.private-key', title: 'Private key committed', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/, severity: 'critical', group: 0 },
  { id: 'secret.aws-access-key', title: 'AWS access key ID', re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/, severity: 'high', group: 1 },
  { id: 'secret.github-token', title: 'GitHub token', re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/, severity: 'critical', group: 1 },
  { id: 'secret.slack-token', title: 'Slack token', re: /\b(xox[abposr]-[A-Za-z0-9-]{10,200})\b/, severity: 'high', group: 1 },
  { id: 'secret.slack-webhook', title: 'Slack webhook URL', re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,})/, severity: 'medium', group: 1 },
  { id: 'secret.stripe-live-key', title: 'Stripe live secret key', re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,99})\b/, severity: 'critical', group: 1 },
  { id: 'secret.google-api-key', title: 'Google API key', re: /\b(AIza[0-9A-Za-z_-]{35})\b/, severity: 'medium', group: 1 },
  { id: 'secret.openai-key', title: 'OpenAI API key', re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b/, severity: 'high', group: 1 },
  { id: 'secret.anthropic-key', title: 'Anthropic API key', re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,120})\b/, severity: 'high', group: 1 },
  { id: 'secret.npm-token', title: 'npm access token', re: /\b(npm_[A-Za-z0-9]{36})\b/, severity: 'high', group: 1 },
  { id: 'secret.sendgrid-key', title: 'SendGrid API key', re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/, severity: 'high', group: 1 },
  { id: 'secret.twilio-key', title: 'Twilio API key', re: /\b(SK[0-9a-f]{32})\b/, severity: 'medium', group: 1 },
  { id: 'secret.gcp-service-account', title: 'Google Cloud service-account key', re: /"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key"\s*:\s*"(-----BEGIN)/, severity: 'critical', group: 1 },
  { id: 'secret.url-credentials', title: 'Credentials in a connection URL', re: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:/@'"]{1,64}:([^\s@'"/]{6,128})@[^\s'"]+)/, severity: 'high', group: 2 },
];

/** Generic assignment of a secret-looking value to a secret-looking name. */
const GENERIC = /\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|token))\b["']?\s*(?:[:=]|:=|=>)\s*["'`]([^"'`\s]{8,200})["'`]/i;
const PLACEHOLDER = /^(?:x+|\*+|\.+|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[A-Za-z_]+%|\$[A-Za-z_][A-Za-z0-9_]*)$|change[-_]?me|example|placeholder|your[-_]|dummy|sample|fake|test|redacted|xxxx|replace|insert|todo|secret_here|password_here|^(password|secret|token|none|null|undefined|empty)$/i;
/** Documented AWS example credentials are not secrets. */
const AWS_EXAMPLES = new Set(['AKIAIOSFODNN7EXAMPLE', 'AKIAI44QH8DHBEXAMPLE']);

function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function scanSecrets(src: SourceView, maxFindings = 200): Finding[] {
  const out: Finding[] = [];
  for (const path of src.textPaths()) {
    if (out.length >= maxFindings) break;
    if (isVendored(path) || isBinaryByName(path) || isLockfile(path)) continue;
    const text = src.text(path);
    if (text === undefined) continue;
    const inTests = isTestPath(path) || /(^|\/)(examples?|fixtures?|samples?|docs?)\//i.test(path);
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length && out.length < maxFindings; i++) {
      const line = lines[i] as string;
      if (line.length > 4000) continue;
      let matched = false;
      for (const p of PATTERNS) {
        const m = p.re.exec(p.id === 'secret.gcp-service-account' ? lines.slice(i, i + 12).join('\n') : line);
        if (!m) continue;
        const value = m[p.group] ?? m[0];
        if (AWS_EXAMPLES.has(value)) continue;
        // Example env files and connection strings commonly hold placeholders.
        if ((p.id === 'secret.url-credentials' || isEnvExample(path)) && PLACEHOLDER.test(value)) continue;
        matched = true;
        out.push(
          make('SEC', {
            ruleId: p.id,
            title: p.title,
            category: 'secret',
            severity: inTests ? downgrade(p.severity) : p.severity,
            confidence: 'high',
            status: 'unverified',
            file: path,
            startLine: i + 1,
            endLine: i + 1,
            evidence: p.id === 'secret.private-key' || p.id === 'secret.gcp-service-account' ? `${p.title} header at line ${i + 1} (contents redacted)` : `Value matching the ${p.title} format: ${redactValue(value)}`,
            risk: `If this is a real credential it is public to anyone who can read the repository and its history, and should be treated as compromised.${inTests ? ' It is in test or example code, which lowers the likelihood that it is live.' : ''}`,
            remediation: 'Revoke and rotate the credential with its issuer, remove it from the code and from Git history, and load it from an environment variable or secret manager instead.',
            method: 'builtin-rule',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            cwe: 'CWE-798',
          }),
        );
        break;
      }
      if (matched) continue;
      const g = GENERIC.exec(line);
      if (g) {
        const name = g[1] as string;
        const value = g[2] as string;
        if (PLACEHOLDER.test(value) || entropy(value) < 3 || /^(process\.env|os\.environ|env\(|getenv|config\.|settings\.)/.test(value)) continue;
        if (/^(true|false|null|none|\d+)$/i.test(value) || /^[a-z]+(\.[a-z]+)+$/i.test(value)) continue;
        out.push(
          make('SEC', {
            ruleId: 'secret.hardcoded-credential',
            title: `Hard-coded value assigned to "${name.slice(0, 40)}"`,
            category: 'secret',
            severity: inTests ? 'low' : 'medium',
            confidence: 'low',
            status: 'heuristic',
            file: path,
            startLine: i + 1,
            endLine: i + 1,
            evidence: `${name.slice(0, 40)} = ${redactValue(value)}`,
            risk: 'A credential-like name is assigned a literal value. If it is a real secret, it is exposed to everyone who can read the code.',
            remediation: 'Load secrets from environment variables or a secret manager; keep only placeholders in the repository.',
            method: 'builtin-rule',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            cwe: 'CWE-798',
          }),
        );
      }
    }
  }
  for (const f of src.files) {
    if (!isCommittedEnvFile(f.path) || isVendored(f.path)) continue;
    out.push(
      make('SEC', {
        ruleId: 'secret.committed-env-file',
        title: 'Environment file committed to the repository',
        category: 'secret',
        severity: 'high',
        confidence: 'medium',
        status: 'unverified',
        file: f.path,
        evidence: `${f.path} (${f.size} bytes) is tracked; its values are not shown`,
        risk: '.env files usually hold credentials. Committing one publishes whatever it contains, now and in Git history.',
        remediation: 'Remove the file from the repository and history, rotate any real values, add it to .gitignore, and commit a .env.example with placeholders instead.',
        method: 'builtin-rule',
        references: ['https://cwe.mitre.org/data/definitions/538.html'],
        cwe: 'CWE-538',
      }),
    );
  }
  return out;
}
