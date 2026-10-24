/**
 * Pull the sandbox images configured for this deployment onto the sandbox host.
 * The runner never pulls implicitly (--pull never), so run this after setup and
 * whenever you change UNBOX_IMAGE_*.
 *
 *   node scripts/pull-images.ts
 */
import { spawnSync } from 'node:child_process';
import { loadConfig } from '../src/config.ts';

const config = loadConfig(process.env);
const env = { ...process.env, ...(config.runner.dockerHost ? { DOCKER_HOST: config.runner.dockerHost } : {}) };
let failed = false;
for (const [ecosystem, image] of Object.entries(config.runner.images)) {
  console.log(`\n# ${ecosystem}: ${image}`);
  const r = spawnSync(config.runner.dockerBin, ['pull', image], { stdio: 'inherit', env, shell: false });
  if (r.status !== 0) failed = true;
}
if (failed) {
  console.error('\nSome images could not be pulled. Checks for those ecosystems will show as unavailable.');
  process.exit(1);
}
