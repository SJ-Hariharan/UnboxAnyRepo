import { hasControlChars } from './text.ts';
import { BRAND, slugify } from './brand.ts';

/**
 * Environment-driven configuration. Everything is validated here, once, so the
 * rest of the code can trust these values. Invalid configuration throws at
 * startup instead of silently degrading into a weaker mode.
 */

export const UNSAFE_LOCAL_ACK = 'i-understand-runc-is-not-a-strong-sandbox';

export type RunnerMode = 'disabled' | 'docker';
export type DockerRuntime = 'runsc' | 'runc';
export type Ecosystem = 'node' | 'python' | 'go' | 'rust';

export interface Limits {
  /** Hard cap on gzip archive bytes downloaded from GitHub. */
  archiveMaxCompressedBytes: number;
  /** Cap on the sum of regular-file bytes after decompression. */
  archiveMaxUncompressedBytes: number;
  archiveMaxFiles: number;
  archiveMaxFileBytes: number;
  /** Reject before download when GitHub reports a larger repository (KiB). */
  repoMaxReportedKiB: number;
  fetchTimeoutMs: number;
  runCpus: number;
  runMemoryMiB: number;
  runPids: number;
  runWorkspaceMiB: number;
  installTimeoutSec: number;
  checkTimeoutSec: number;
  logHeadBytes: number;
  logTailBytes: number;
  maxConcurrentRuns: number;
  maxQueuedRuns: number;
  maxConcurrentInspections: number;
  runsPerIpPerHour: number;
  inspectionsPerIpPer10Min: number;
  runRetentionSec: number;
  inspectionRetentionSec: number;
  /** Memory cap for all held inspections (source archives + analysis). */
  inspectionStoreBytes: number;
  /** Text read for static analysis: per file and in total. */
  analysisMaxFileBytes: number;
  analysisMaxTotalBytes: number;
  scannerTimeoutMs: number;
  previewTtlSec: number;
  previewMaxBytes: number;
  previewStoreBytes: number;
  previewsPerSession: number;
}

export type ScannerName = 'semgrep' | 'gitleaks';

export interface AnalysisConfig {
  /** 'auto' = use each external scanner if its binary is installed. */
  scanners: 'auto' | 'off' | ScannerName[];
  semgrepBin: string;
  gitleaksBin: string;
  /** Query the OSV.dev API for known dependency vulnerabilities. */
  osv: boolean;
  /** Read published repository security advisories from the GitHub API. */
  githubAdvisories: boolean;
}

export interface SandboxVerificationConfig {
  /** Attestation written by `npm run sandbox -- --verify`. */
  file: string;
  maxAgeDays: number;
}

export interface RunnerConfig {
  mode: RunnerMode;
  runtime: DockerRuntime;
  unsafeLocalAcknowledged: boolean;
  dockerBin: string;
  dockerHost: string | undefined;
  fetchNetwork: string | undefined;
  fetchProxyUrl: string | undefined;
  images: Record<Ecosystem, string>;
}

export interface Config {
  productName: string;
  host: string;
  port: number;
  production: boolean;
  trustProxy: boolean;
  secureCookies: boolean;
  publicOrigin: string | undefined;
  githubSource: 'live' | 'fixtures';
  githubToken: string | undefined;
  outboundProxy: string | undefined;
  userAgent: string;
  runner: RunnerConfig;
  limits: Limits;
  analysis: AnalysisConfig;
  /**
   * domain: previews are served at the root of <token>.<domain>, a separate site from
   * the app (needs wildcard DNS in production; *.localhost works locally in most browsers).
   */
  preview: { enabled: boolean; domain: string | undefined };
  sandboxVerification: SandboxVerificationConfig;
  /** Secret values that must be redacted from any log or error we return. */
  secretValues: string[];
}

export class ConfigError extends Error {}

type Env = Record<string, string | undefined>;

function str(env: Env, key: string): string | undefined {
  const v = env[key];
  if (v === undefined) return undefined;
  const t = v.trim();
  return t === '' ? undefined : t;
}

function int(env: Env, key: string, def: number, min: number, max: number): number {
  const v = str(env, key);
  if (v === undefined) return def;
  if (!/^\d+$/.test(v)) throw new ConfigError(`${key} must be a whole number`);
  const n = Number(v);
  if (n < min || n > max) throw new ConfigError(`${key} must be between ${min} and ${max}`);
  return n;
}

function num(env: Env, key: string, def: number, min: number, max: number): number {
  const v = str(env, key);
  if (v === undefined) return def;
  if (!/^\d+(\.\d+)?$/.test(v)) throw new ConfigError(`${key} must be a number`);
  const n = Number(v);
  if (n < min || n > max) throw new ConfigError(`${key} must be between ${min} and ${max}`);
  return n;
}

function bool(env: Env, key: string, def: boolean): boolean {
  const v = str(env, key);
  if (v === undefined) return def;
  if (['1', 'true', 'yes'].includes(v.toLowerCase())) return true;
  if (['0', 'false', 'no'].includes(v.toLowerCase())) return false;
  throw new ConfigError(`${key} must be true or false`);
}

/** Docker image references: registry/name[:tag][@sha256:digest]. No spaces, no leading dash. */
const IMAGE_RE = /^[a-z0-9][a-z0-9._\-/:]*(@sha256:[a-f0-9]{64})?$/;
const DOCKER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$/;

function image(env: Env, key: string, def: string): string {
  const v = str(env, key) ?? def;
  if (!IMAGE_RE.test(v) || v.length > 255) throw new ConfigError(`${key} is not a valid image reference`);
  return v;
}

function httpUrl(env: Env, key: string): string | undefined {
  const v = str(env, key);
  if (v === undefined) return undefined;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new ConfigError(`${key} must be a URL`);
  }
  if (u.protocol !== 'http:' || u.username || u.password || u.pathname !== '/' || u.search || u.hash) {
    throw new ConfigError(`${key} must look like http://host:port (no credentials or path)`);
  }
  return `http://${u.host}`;
}

export const DEFAULT_IMAGES: Record<Ecosystem, string> = {
  node: 'node:24-bookworm-slim',
  python: 'python:3.13-slim-bookworm',
  go: 'golang:1.25-bookworm',
  rust: 'rust:1-slim-bookworm',
};

export function loadConfig(env: Env, argv: readonly string[] = []): Config {
  const production = str(env, 'NODE_ENV') === 'production';
  const productName = str(env, 'UNBOX_PRODUCT_NAME') ?? BRAND.name;
  if (productName.length > 40 || /[<>"'&]/.test(productName) || hasControlChars(productName)) {
    throw new ConfigError('UNBOX_PRODUCT_NAME must be ≤ 40 plain characters');
  }

  const demo = argv.includes('--demo');
  const sourceRaw = demo ? 'fixtures' : (str(env, 'UNBOX_GITHUB_SOURCE') ?? 'live');
  if (sourceRaw !== 'live' && sourceRaw !== 'fixtures') {
    throw new ConfigError('UNBOX_GITHUB_SOURCE must be "live" or "fixtures"');
  }

  const modeRaw = str(env, 'UNBOX_RUNNER') ?? 'disabled';
  if (modeRaw !== 'disabled' && modeRaw !== 'docker') {
    throw new ConfigError('UNBOX_RUNNER must be "disabled" or "docker"');
  }
  const runtimeRaw = str(env, 'UNBOX_DOCKER_RUNTIME') ?? 'runsc';
  if (runtimeRaw !== 'runsc' && runtimeRaw !== 'runc') {
    throw new ConfigError('UNBOX_DOCKER_RUNTIME must be "runsc" (gVisor) or "runc"');
  }
  const dockerBin = str(env, 'UNBOX_DOCKER_BIN') ?? 'docker';
  if (!/^[A-Za-z0-9_./-]+$/.test(dockerBin) || dockerBin.startsWith('-')) {
    throw new ConfigError('UNBOX_DOCKER_BIN must be a plain path');
  }
  const dockerHost = str(env, 'UNBOX_DOCKER_HOST');
  if (dockerHost !== undefined && !/^(unix|tcp|ssh):\/\/[A-Za-z0-9@._:/-]+$/.test(dockerHost)) {
    throw new ConfigError('UNBOX_DOCKER_HOST must be a unix://, tcp:// or ssh:// address');
  }
  const fetchNetwork = str(env, 'UNBOX_FETCH_NETWORK');
  if (fetchNetwork !== undefined && !DOCKER_NAME_RE.test(fetchNetwork)) {
    throw new ConfigError('UNBOX_FETCH_NETWORK must be a plain Docker network name');
  }
  const fetchProxyUrl = httpUrl(env, 'UNBOX_FETCH_PROXY_URL');
  if ((fetchNetwork === undefined) !== (fetchProxyUrl === undefined)) {
    throw new ConfigError('Set both UNBOX_FETCH_NETWORK and UNBOX_FETCH_PROXY_URL, or neither');
  }

  const outboundProxy = httpUrl(env, 'UNBOX_OUTBOUND_PROXY');
  const githubToken = str(env, 'GITHUB_TOKEN');

  const limits: Limits = {
    archiveMaxCompressedBytes: int(env, 'UNBOX_ARCHIVE_MAX_MB', 50, 1, 500) * 1024 * 1024,
    archiveMaxUncompressedBytes: int(env, 'UNBOX_ARCHIVE_MAX_UNCOMPRESSED_MB', 250, 1, 2000) * 1024 * 1024,
    archiveMaxFiles: int(env, 'UNBOX_ARCHIVE_MAX_FILES', 20000, 10, 200000),
    archiveMaxFileBytes: int(env, 'UNBOX_ARCHIVE_MAX_FILE_MB', 25, 1, 500) * 1024 * 1024,
    repoMaxReportedKiB: int(env, 'UNBOX_REPO_MAX_REPORTED_MB', 500, 1, 10000) * 1024,
    fetchTimeoutMs: int(env, 'UNBOX_FETCH_TIMEOUT_SEC', 30, 5, 300) * 1000,
    runCpus: num(env, 'UNBOX_RUN_CPUS', 1, 0.25, 16),
    runMemoryMiB: int(env, 'UNBOX_RUN_MEMORY_MB', 2048, 256, 65536),
    runPids: int(env, 'UNBOX_RUN_PIDS', 256, 32, 4096),
    runWorkspaceMiB: int(env, 'UNBOX_RUN_WORKSPACE_MB', 2048, 64, 65536),
    installTimeoutSec: int(env, 'UNBOX_INSTALL_TIMEOUT_SEC', 300, 10, 3600),
    checkTimeoutSec: int(env, 'UNBOX_CHECK_TIMEOUT_SEC', 600, 10, 3600),
    logHeadBytes: int(env, 'UNBOX_LOG_HEAD_KB', 256, 16, 4096) * 1024,
    logTailBytes: int(env, 'UNBOX_LOG_TAIL_KB', 64, 4, 1024) * 1024,
    maxConcurrentRuns: int(env, 'UNBOX_MAX_CONCURRENT_RUNS', 2, 1, 64),
    maxQueuedRuns: int(env, 'UNBOX_MAX_QUEUED_RUNS', 8, 0, 1000),
    maxConcurrentInspections: int(env, 'UNBOX_MAX_CONCURRENT_INSPECTIONS', 4, 1, 64),
    runsPerIpPerHour: int(env, 'UNBOX_RUNS_PER_IP_PER_HOUR', 6, 1, 10000),
    inspectionsPerIpPer10Min: int(env, 'UNBOX_INSPECTIONS_PER_IP_PER_10_MIN', 30, 1, 10000),
    runRetentionSec: int(env, 'UNBOX_RUN_RETENTION_SEC', 3600, 60, 86400),
    inspectionRetentionSec: int(env, 'UNBOX_INSPECTION_RETENTION_SEC', 900, 60, 86400),
    inspectionStoreBytes: int(env, 'UNBOX_INSPECTION_STORE_MB', 512, 16, 16384) * 1024 * 1024,
    analysisMaxFileBytes: int(env, 'UNBOX_ANALYSIS_MAX_FILE_KB', 512, 16, 8192) * 1024,
    analysisMaxTotalBytes: int(env, 'UNBOX_ANALYSIS_MAX_TOTAL_MB', 40, 1, 512) * 1024 * 1024,
    scannerTimeoutMs: int(env, 'UNBOX_SCANNER_TIMEOUT_SEC', 90, 5, 900) * 1000,
    previewTtlSec: int(env, 'UNBOX_PREVIEW_TTL_SEC', 1800, 60, 86400),
    previewMaxBytes: int(env, 'UNBOX_PREVIEW_MAX_MB', 40, 1, 1024) * 1024 * 1024,
    previewStoreBytes: int(env, 'UNBOX_PREVIEW_STORE_MB', 256, 8, 16384) * 1024 * 1024,
    previewsPerSession: int(env, 'UNBOX_PREVIEWS_PER_SESSION', 2, 1, 50),
  };

  const scannersRaw = (str(env, 'UNBOX_SCANNERS') ?? 'auto').toLowerCase();
  let scanners: AnalysisConfig['scanners'];
  if (scannersRaw === 'auto' || scannersRaw === 'off') scanners = scannersRaw;
  else {
    const names = scannersRaw.split(',').map((x) => x.trim()).filter(Boolean);
    for (const n of names) if (n !== 'semgrep' && n !== 'gitleaks') throw new ConfigError('UNBOX_SCANNERS must be auto, off, or a list of: semgrep, gitleaks');
    scanners = [...new Set(names)] as ScannerName[];
  }
  const plainBin = (key: string, def: string) => {
    const v = str(env, key) ?? def;
    if (!/^[A-Za-z0-9_./-]+$/.test(v) || v.startsWith('-')) throw new ConfigError(`${key} must be a plain path`);
    return v;
  };
  const isFixtures = sourceRaw === 'fixtures';
  const analysis: AnalysisConfig = {
    scanners,
    semgrepBin: plainBin('UNBOX_SEMGREP_BIN', 'semgrep'),
    gitleaksBin: plainBin('UNBOX_GITLEAKS_BIN', 'gitleaks'),
    // Demo mode is offline by design: no OSV or GitHub calls unless explicitly enabled.
    osv: bool(env, 'UNBOX_OSV', !isFixtures),
    githubAdvisories: bool(env, 'UNBOX_GITHUB_ADVISORIES', !isFixtures),
  };
  const loopback = ['127.0.0.1', 'localhost', '::1'].includes(str(env, 'HOST') ?? '127.0.0.1');
  const previewDomainRaw = str(env, 'UNBOX_PREVIEW_DOMAIN') ?? (!production && loopback ? 'preview.localhost' : undefined);
  const previewDomain = previewDomainRaw === 'off' ? undefined : previewDomainRaw?.toLowerCase();
  if (previewDomain !== undefined && !/^(?=.{1,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(previewDomain)) {
    throw new ConfigError('UNBOX_PREVIEW_DOMAIN must be a plain domain such as preview.example.com, or "off"');
  }
  const verificationFile = str(env, 'UNBOX_SANDBOX_VERIFICATION_FILE') ?? '.unbox/sandbox-verification.json';
  if (hasControlChars(verificationFile) || verificationFile.length > 512) throw new ConfigError('UNBOX_SANDBOX_VERIFICATION_FILE must be a plain path');

  const host = str(env, 'HOST') ?? '127.0.0.1';
  const port = int(env, 'PORT', 8787, 0, 65535);
  const publicOrigin = str(env, 'UNBOX_PUBLIC_ORIGIN');
  if (publicOrigin !== undefined && !/^https?:\/\/[A-Za-z0-9.-]+(:\d+)?$/.test(publicOrigin)) {
    throw new ConfigError('UNBOX_PUBLIC_ORIGIN must look like https://example.com');
  }

  const secretValues = [githubToken].filter((v): v is string => typeof v === 'string' && v.length >= 8);

  return {
    productName,
    host,
    port,
    production,
    trustProxy: bool(env, 'UNBOX_TRUST_PROXY', false),
    secureCookies: bool(env, 'UNBOX_SECURE_COOKIES', production),
    publicOrigin,
    githubSource: sourceRaw,
    githubToken,
    outboundProxy,
    userAgent: `${slugify(productName)}/${BRAND.version} (repository inspector)`,
    runner: {
      mode: modeRaw,
      runtime: runtimeRaw,
      unsafeLocalAcknowledged: str(env, 'UNBOX_ALLOW_UNSAFE_LOCAL_RUNNER') === UNSAFE_LOCAL_ACK,
      dockerBin,
      dockerHost,
      fetchNetwork,
      fetchProxyUrl,
      images: {
        node: image(env, 'UNBOX_IMAGE_NODE', DEFAULT_IMAGES.node),
        python: image(env, 'UNBOX_IMAGE_PYTHON', DEFAULT_IMAGES.python),
        go: image(env, 'UNBOX_IMAGE_GO', DEFAULT_IMAGES.go),
        rust: image(env, 'UNBOX_IMAGE_RUST', DEFAULT_IMAGES.rust),
      },
    },
    limits,
    analysis,
    preview: { enabled: bool(env, 'UNBOX_PREVIEW', true), domain: previewDomain },
    sandboxVerification: { file: verificationFile, maxAgeDays: int(env, 'UNBOX_SANDBOX_VERIFICATION_MAX_AGE_DAYS', 30, 1, 365) },
    secretValues,
  };
}
