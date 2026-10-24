import { analyseRepository } from '../../src/analysis/index.ts';
import type { SourceSnapshot } from '../../src/source/archive.ts';
import type { AnalysisResult } from '../../src/analysis/types.ts';

/** Offline analysis of a snapshot: no OSV, no GitHub, no external scanners. */
export function analyseOffline(snap: SourceSnapshot, repo = { fullName: 'o/r', htmlUrl: 'https://github.com/o/r', name: 'r' }, sha = 'a'.repeat(40)): Promise<AnalysisResult> {
  return analyseRepository(
    { files: snap.files, dirs: snap.dirs, texts: snap.texts, textStats: snap.textStats, totalBytes: snap.totalBytes, skippedSymlinks: snap.skippedSymlinkCount, repo, commitSha: sha },
    {
      config: { scanners: 'off', semgrepBin: 'semgrep', gitleaksBin: 'gitleaks', osv: false, githubAdvisories: false },
      limits: { scannerTimeoutMs: 30_000, fetchTimeoutMs: 5_000 },
      userAgent: 'test',
    },
  );
}
