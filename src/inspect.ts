/**
 * Inspection pipeline: URL → metadata → pinned commit → bounded archive →
 * sanitized snapshot → detection. Never executes anything.
 */
import type { Limits, AnalysisConfig } from './config.ts';
import { analyseRepository } from './analysis/index.ts';
import { textSkipReason, looksBinary, isSecondaryText } from './analysis/paths.ts';
import type { Transport } from './github/fetcher.ts';
import { parseRepoUrl, RepoUrlError } from './github/url.ts';
import { GitHubError } from './github/client.ts';
import type { GitHubClient } from './github/client.ts';
import { sanitizeArchive, ArchiveError } from './source/archive.ts';
import { detectProject } from './detect/index.ts';
import type { Inspection, InspectionStore } from './runs/inspections.ts';

export class InspectError extends Error {
  readonly code: string;
  readonly status: number;
  readonly retryAfterSec: number | undefined;
  constructor(code: string, status: number, message: string, retryAfterSec?: number) {
    super(message);
    this.code = code;
    this.status = status;
    this.retryAfterSec = retryAfterSec;
  }
}

export interface InspectServiceOptions {
  github: GitHubClient;
  store: InspectionStore;
  limits: Limits;
  goImage: string;
  analysis: AnalysisConfig;
  userAgent: string;
  osvTransport?: Transport;
}

export class InspectService {
  private readonly opts: InspectServiceOptions;
  private inFlight = 0;

  constructor(opts: InspectServiceOptions) {
    this.opts = opts;
  }

  async inspect(rawUrl: unknown, sessionId: string, signal?: AbortSignal): Promise<Inspection> {
    let ref;
    try {
      ref = parseRepoUrl(rawUrl);
    } catch (err) {
      if (err instanceof RepoUrlError) throw new InspectError('invalid_url', 400, err.message);
      throw err;
    }
    if (this.inFlight >= this.opts.limits.maxConcurrentInspections) {
      throw new InspectError('busy', 503, 'Too many repositories are being inspected right now. Try again in a moment.', 10);
    }
    this.inFlight++;
    try {
      const { github, limits } = this.opts;
      const meta = await github.getRepo(ref.owner, ref.repo, signal);
      if (meta.sizeKiB > limits.repoMaxReportedKiB) {
        throw new InspectError('too_large', 413, `This repository is larger than this deployment allows (${Math.round(limits.repoMaxReportedKiB / 1024)} MB).`);
      }
      const sha = ref.pinnedSha ? await github.verifyCommit(meta, ref.pinnedSha, signal) : await github.resolveBranch(meta, meta.defaultBranch, signal);
      const gz = await github.downloadArchive(meta, sha, limits.archiveMaxCompressedBytes, signal);
      const snap = await sanitizeArchive(
        gz,
        {
          maxCompressedBytes: limits.archiveMaxCompressedBytes,
          maxUncompressedBytes: limits.archiveMaxUncompressedBytes,
          maxFiles: limits.archiveMaxFiles,
          maxFileBytes: limits.archiveMaxFileBytes,
        },
        {
          expectedSha: sha,
          collectText: {
            maxTotalBytes: limits.analysisMaxTotalBytes,
            maxSecondaryBytes: Math.floor(limits.analysisMaxTotalBytes / 4),
            isSecondary: isSecondaryText,
            skipReason: (p, size) => textSkipReason(p, size, limits.analysisMaxFileBytes),
            isBinary: looksBinary,
          },
        },
      );
      const detection = detectProject(snap, { goImage: this.opts.goImage });
      const analysis = await analyseRepository(
        {
          files: snap.files,
          dirs: snap.dirs,
          texts: snap.texts,
          textStats: snap.textStats,
          totalBytes: snap.totalBytes,
          skippedSymlinks: snap.skippedSymlinkCount,
          repo: { fullName: meta.fullName, htmlUrl: meta.htmlUrl, name: meta.name },
          commitSha: sha,
          ...(github.listAdvisories ? { listAdvisories: (s?: AbortSignal) => github.listAdvisories!(meta, s) } : {}),
        },
        {
          config: this.opts.analysis,
          limits,
          userAgent: this.opts.userAgent,
          ...(signal ? { signal } : {}),
          ...(this.opts.osvTransport ? { osvTransport: this.opts.osvTransport } : {}),
        },
      );
      const notices: string[] = [];
      if (ref.notice) notices.push(ref.notice);
      if (ref.pinnedSha) notices.push('Commits selected by SHA may come from any fork in the repository network.');
      if (meta.archived) notices.push('This repository is archived.');
      return this.opts.store.add({
        sessionId,
        repo: meta,
        commitSha: sha,
        commitSource: ref.pinnedSha ? 'url' : 'default_branch',
        demo: github.kind === 'fixtures',
        notice: notices.length > 0 ? notices.join(' ') : undefined,
        source: {
          fileCount: snap.files.length,
          totalBytes: snap.totalBytes,
          skippedSymlinkCount: snap.skippedSymlinkCount,
          skippedSymlinks: snap.skippedSymlinks,
        },
        detection,
        analysis,
        sanitizedTarGz: snap.sanitizedTarGz,
      });
    } catch (err) {
      throw mapInspectError(err);
    } finally {
      this.inFlight--;
    }
  }
}

export function mapInspectError(err: unknown): InspectError {
  if (err instanceof InspectError) return err;
  if (err instanceof GitHubError) {
    const status: Record<string, number> = {
      not_found: 404,
      not_public: 404,
      rate_limited: 429,
      unavailable: 451,
      too_large: 413,
      timeout: 504,
      network: 502,
      upstream: 502,
    };
    return new InspectError(`github_${err.code}`, status[err.code] ?? 502, err.message, err.retryAfterSec);
  }
  if (err instanceof ArchiveError) {
    if (err.code === 'too_large' || err.code === 'too_many_files' || err.code === 'file_too_large') {
      return new InspectError('source_too_large', 413, `${err.message}. This deployment limits repository size for safety.`);
    }
    return new InspectError('unsafe_source', 422, `The repository archive was rejected: ${err.message}.`);
  }
  return new InspectError('internal', 500, 'Something went wrong while inspecting the repository.');
}
