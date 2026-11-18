import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { rotationFor } from './rotation.mjs';

export const CONFIG_PATH = join(dirname(fileURLToPath(import.meta.url)), 'gitleaks-extra.toml');
const SPECIFIC_FIRST = id => (/^(jwt|generic-api-key)$/.test(id) ? 1 : 0);

export function git(cwd, args) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : null;
}

export function isGitRepo(dir) {
  return git(dir, ['rev-parse', '--is-inside-work-tree'])?.trim() === 'true';
}

// Runs Gitleaks and returns its raw findings. Secret values stay in memory; the temp report is deleted.
export function runGitleaks(bin, target, { mode = 'history', config = CONFIG_PATH } = {}) {
  const tmp = mkdtempSync(join(tmpdir(), 'secret-guard-'));
  const report = join(tmp, 'report.json');
  const common = ['--config', config, '--report-format', 'json', '--report-path', report, '--no-banner', '--exit-code', '0', '--log-level', 'error'];
  const args = mode === 'dir' ? ['dir', target, ...common]
    : mode === 'staged' ? ['git', '--pre-commit', '--staged', target, ...common]
    : ['git', target, ...common];
  try {
    const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (r.error) throw r.error;
    if (r.status !== 0) throw new Error(`Gitleaks failed (exit ${r.status}): ${(r.stderr || r.stdout).trim().slice(0, 500)}`);
    return existsSync(report) ? JSON.parse(readFileSync(report, 'utf8') || '[]') : [];
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export function redact(secret = '') {
  const s = String(secret);
  return `${s.slice(0, 4)}${'•'.repeat(6)} (${s.length} chars)`;
}

// Groups findings per unique secret and works out whether it is still in the current code.
export function analyze(findings, repoDir, { inGit = true } = {}) {
  const groups = new Map();
  for (const f of findings) {
    const key = createHash('sha256').update(String(f.Secret)).digest('hex');
    const g = groups.get(key) || { id: key.slice(0, 10), secret: f.Secret, rules: new Set(), locations: [] };
    g.rules.add(f.RuleID);
    const loc = { file: f.File, line: f.StartLine, commit: f.Commit ? f.Commit.slice(0, 8) : '', date: f.Date ? f.Date.slice(0, 10) : '', author: f.Author || '' };
    if (!g.locations.some(l => l.file === loc.file && l.line === loc.line && l.commit === loc.commit)) g.locations.push(loc);
    groups.set(key, g);
  }
  const out = [];
  for (const g of groups.values()) {
    const rule = [...g.rules].sort((a, b) => SPECIFIC_FIRST(a) - SPECIFIC_FIRST(b))[0];
    const files = [...new Set(g.locations.map(l => l.file))];
    let inCurrentCode = !inGit;
    if (inGit) {
      for (const file of files) {
        const head = git(repoDir, ['show', `HEAD:${file}`]);
        const wt = existsSync(join(repoDir, file)) ? readFileSync(join(repoDir, file), 'utf8') : null;
        if ((head && head.includes(g.secret)) || (wt && wt.includes(g.secret))) { inCurrentCode = true; break; }
      }
    }
    const rot = rotationFor(rule);
    g.locations.sort((a, b) => (a.date || '').localeCompare(b.date || ''));
    out.push({
      id: g.id, rule, kind: rot.name, severity: rot.severity, where: rot.where, steps: rot.steps,
      preview: redact(g.secret), inCurrentCode, historyOnly: inGit && !inCurrentCode,
      firstSeen: g.locations[0]?.date || '', commits: [...new Set(g.locations.map(l => l.commit).filter(Boolean))],
      locations: g.locations, secret: g.secret,
    });
  }
  const sev = { critical: 0, high: 1, medium: 2 };
  return out.sort((a, b) => sev[a.severity] - sev[b.severity] || Number(b.inCurrentCode) - Number(a.inCurrentCode));
}

export function remoteInfo(repoDir) {
  const url = git(repoDir, ['remote', 'get-url', 'origin'])?.trim() || '';
  return { url: url.replace(/\/\/[^@/]+@/, '//'), hosted: /github\.com|gitlab|bitbucket/.test(url) };
}

export function scanTarget(bin, target, { staged = false } = {}) {
  const dir = resolve(target);
  const inGit = isGitRepo(dir);
  const mode = staged ? 'staged' : inGit ? 'history' : 'dir';
  const findings = runGitleaks(bin, dir, { mode });
  const commitCount = inGit ? Number(git(dir, ['rev-list', '--all', '--count'])?.trim() || 0) : 0;
  return { dir, inGit, mode, commitCount, remote: inGit ? remoteInfo(dir) : { url: '', hosted: false }, leaks: analyze(findings, dir, { inGit: inGit && !staged }) };
}
