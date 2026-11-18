// Find a Gitleaks binary, or download the pinned official release and verify its checksum.
// Gitleaks (https://github.com/gitleaks/gitleaks) is MIT licensed, (c) Zachary Rice. Not vendored.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { homedir, platform, arch, tmpdir } from 'node:os';
import { join } from 'node:path';

export const GITLEAKS_VERSION = '8.30.1';

function onPath(cmd) {
  const r = spawnSync(cmd, ['version'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

export function assetName(version = GITLEAKS_VERSION, p = platform(), a = arch()) {
  const os = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[p];
  const cpu = { x64: 'x64', arm64: 'arm64', ia32: 'x32', arm: 'armv7' }[a];
  if (!os || !cpu) return null;
  return `gitleaks_${version}_${os}_${cpu}.${os === 'windows' ? 'zip' : 'tar.gz'}`;
}

async function fetchBuf(url) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`Download failed (${res.status}) for ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

export async function ensureGitleaks({ log = () => {}, allowDownload = true } = {}) {
  if (process.env.GITLEAKS_BIN && existsSync(process.env.GITLEAKS_BIN)) return process.env.GITLEAKS_BIN;
  if (onPath('gitleaks')) return 'gitleaks';
  const cacheDir = join(process.env.SECRET_GUARD_CACHE || join(homedir(), '.cache', 'blitzhash-secret-guard'), GITLEAKS_VERSION);
  const bin = join(cacheDir, platform() === 'win32' ? 'gitleaks.exe' : 'gitleaks');
  if (existsSync(bin)) return bin;
  if (!allowDownload) throw new Error('Gitleaks not found. Install it (brew install gitleaks / scoop install gitleaks) or drop --no-download.');
  const asset = assetName();
  if (!asset) throw new Error(`No official Gitleaks build for ${platform()}/${arch()}. Install Gitleaks manually.`);
  if (asset.endsWith('.zip')) throw new Error('On Windows, install Gitleaks first (winget install gitleaks or scoop install gitleaks), then rerun.');
  const base = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}`;
  log(`Gitleaks not found, downloading official v${GITLEAKS_VERSION} (${asset})...`);
  const [archive, sums] = await Promise.all([fetchBuf(`${base}/${asset}`), fetchBuf(`${base}/gitleaks_${GITLEAKS_VERSION}_checksums.txt`)]);
  const expected = sums.toString('utf8').split('\n').map(l => l.trim().split(/\s+/)).find(([, n]) => n === asset)?.[0];
  const actual = createHash('sha256').update(archive).digest('hex');
  if (!expected || expected !== actual) throw new Error('Gitleaks checksum did not match the official checksums file. Aborting.');
  mkdirSync(cacheDir, { recursive: true });
  const tmp = join(tmpdir(), `sg-${process.pid}-${asset}`);
  writeFileSync(tmp, archive);
  execFileSync('tar', ['-xzf', tmp, '-C', cacheDir, 'gitleaks']);
  rmSync(tmp, { force: true });
  chmodSync(bin, 0o755);
  log(`Checksum verified. Cached at ${bin}`);
  return bin;
}
