/**
 * Best-effort redaction of credentials in log text. The sandbox never receives
 * application secrets, so this is defense in depth against repositories that
 * print tokens (their own or planted ones) and against configuration mistakes.
 */

const PATTERNS: [RegExp, string][] = [
  [/\b(gh[pousr]_[A-Za-z0-9]{30,255})\b/g, '[REDACTED:github-token]'],
  [/\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g, '[REDACTED:github-token]'],
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED:aws-key-id]'],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED:slack-token]'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, '[REDACTED:google-api-key]'],
  [/\b(sk|rk)_live_[0-9A-Za-z]{16,}\b/g, '[REDACTED:stripe-key]'],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, '[REDACTED:npm-token]'],
  [/\b(authorization\s*[:=]\s*(?:bearer|token|basic)\s+)[^\s'"]+/gi, '$1[REDACTED]'],
  [/\b([a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:)[^\s/@]+@/gi, '$1[REDACTED]@'],
  [/\b((?:aws_secret_access_key|secret[_-]?key|api[_-]?key|password|passwd|token)\s*[:=]\s*['"]?)[^\s'"]{8,}/gi, '$1[REDACTED]'],
];

const PRIVATE_KEY_BEGIN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const PRIVATE_KEY_END = /-----END [A-Z0-9 ]*PRIVATE KEY-----/;

export class Redactor {
  private readonly exact: string[];
  private inPrivateKey = false;

  constructor(secretValues: readonly string[] = []) {
    // Longest first so overlapping secrets are fully covered.
    this.exact = [...new Set(secretValues.filter((s) => s.length >= 8))].sort((a, b) => b.length - a.length);
  }

  /** Redact one complete line (no newline). Stateful across lines for PEM blocks. */
  line(input: string): string {
    if (this.inPrivateKey) {
      if (PRIVATE_KEY_END.test(input)) this.inPrivateKey = false;
      return '[REDACTED:private-key]';
    }
    if (PRIVATE_KEY_BEGIN.test(input)) {
      if (!PRIVATE_KEY_END.test(input)) this.inPrivateKey = true;
      return '[REDACTED:private-key]';
    }
    let out = input;
    for (const s of this.exact) if (out.includes(s)) out = out.split(s).join('[REDACTED]');
    for (const [re, repl] of PATTERNS) out = out.replace(re, repl);
    return out;
  }
}
