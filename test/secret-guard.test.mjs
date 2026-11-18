import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, statSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ensureGitleaks, assetName } from '../src/gitleaks.mjs';
import { scanTarget, redact } from '../src/scan.mjs';
import { renderReport } from '../src/report.mjs';
import { rotationFor } from '../src/rotation.mjs';
import { cleanupPlan, writeReplacements, installHook, initAction } from '../src/cleanup.mjs';
import { makeDemoRepo } from '../src/demo.mjs';

const bin = await ensureGitleaks();
const CLI = join(import.meta.dirname ?? new URL('.', import.meta.url).pathname, '..', 'bin', 'secret-guard.mjs');
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const rnd = n => randomBytes(n).toString('base64url').replace(/[-_]/g, 'x').slice(0, n);

function repo() {
  const d = mkdtempSync(join(tmpdir(), 'sg-test-'));
  const g = (...a) => execFileSync('git', a, { cwd: d, stdio: 'ignore' });
  g('init', '-q', '-b', 'main'); g('config', 'user.email', 't@example.com'); g('config', 'user.name', 'T'); g('config', 'commit.gpgsign', 'false');
  return { d, g };
}

test('asset names match official Gitleaks releases', () => {
  assert.equal(assetName('8.30.1', 'linux', 'x64'), 'gitleaks_8.30.1_linux_x64.tar.gz');
  assert.equal(assetName('8.30.1', 'darwin', 'arm64'), 'gitleaks_8.30.1_darwin_arm64.tar.gz');
  assert.equal(assetName('8.30.1', 'win32', 'x64'), 'gitleaks_8.30.1_windows_x64.zip');
});

test('rotation guidance picks the specific provider', () => {
  assert.match(rotationFor('supabase-service-role-jwt').name, /Supabase/);
  assert.match(rotationFor('stripe-access-token').name, /Stripe/);
  assert.match(rotationFor('aws-access-token').name, /AWS/);
  assert.equal(rotationFor('something-new').severity, 'medium');
});

test('redact never shows more than 4 characters', () => {
  assert.equal(redact('sb_secret_abcdefghijklmnop'), 'sb_s•••••• (26 chars)');
});

test('demo: deleted key is still found in history, live key flagged as current', () => {
  const dir = makeDemoRepo();
  try {
    const r = scanTarget(bin, dir);
    assert.equal(r.leaks.length, 2);
    const supa = r.leaks.find(l => l.rule === 'supabase-secret-key');
    const stripe = r.leaks.find(l => l.rule === 'stripe-access-token');
    assert.ok(supa.historyOnly && !supa.inCurrentCode);
    assert.ok(stripe.inCurrentCode);
    const md = renderReport(r);
    assert.match(md, /1 still in your current code, 1 deleted but still in git history/);
    for (const l of r.leaks) assert.ok(!md.includes(l.secret), 'report must not contain raw secrets');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('Supabase legacy service_role JWT is named precisely (not just "jwt")', () => {
  const { d, g } = repo();
  const jwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'abcdefghijklmnop', role: 'service_role', iat: 1730000000, exp: 2045000000 })}.${rnd(43)}`;
  writeFileSync(join(d, 'server.ts'), `export const admin = createClient(url, "${jwt}");\n`);
  g('add', '.'); g('commit', '-q', '-m', 'admin client');
  const r = scanTarget(bin, d);
  assert.equal(r.leaks.length, 1);
  assert.equal(r.leaks[0].rule, 'supabase-service-role-jwt');
  rmSync(d, { recursive: true, force: true });
});

test('clean repo reports no secrets and CLI exits 0', () => {
  const { d, g } = repo();
  writeFileSync(join(d, 'index.js'), 'const key = process.env.STRIPE_SECRET_KEY;\n');
  g('add', '.'); g('commit', '-q', '-m', 'env only');
  const out = spawnSync(process.execPath, [CLI, 'scan', d], { encoding: 'utf8' });
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /No secrets found/);
  rmSync(d, { recursive: true, force: true });
});

test('CLI exits 1 when secrets are found, 0 with --no-fail', () => {
  const dir = makeDemoRepo();
  try {
    assert.equal(spawnSync(process.execPath, [CLI, 'scan', dir], { encoding: 'utf8' }).status, 1);
    assert.equal(spawnSync(process.execPath, [CLI, 'scan', dir, '--no-fail'], { encoding: 'utf8' }).status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('cleanup plan changes nothing; replacements file is mode 600 and maps every secret', () => {
  const dir = makeDemoRepo();
  const rep = join(mkdtempSync(join(tmpdir(), 'sg-rep-')), 'replacements.txt');
  try {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' });
    const r = scanTarget(bin, dir);
    writeReplacements(r.leaks, rep);
    const plan = cleanupPlan(r, rep);
    assert.match(plan, /Rotate first/);
    assert.match(plan, /git filter-repo --replace-text/);
    assert.equal(statSync(rep).mode & 0o777, 0o600);
    const lines = readFileSync(rep, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);
    assert.ok(lines.every(l => l.includes('==>REMOVED-BY-SECRET-GUARD-')));
    assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }), head, 'history untouched');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('pre-commit hook behaviour', () => {
  const { d, g } = repo();
  writeFileSync(join(d, 'a.txt'), 'hello\n'); g('add', '.'); g('commit', '-q', '-m', 'init');
  installHook(d, bin);
  writeFileSync(join(d, 'pay.js'), `const k = '${['sk', 'live', rnd(32)].join('_')}';\n`);
  execFileSync('git', ['add', 'pay.js'], { cwd: d });
  const blocked = spawnSync('git', ['commit', '-q', '-m', 'leak'], { cwd: d, encoding: 'utf8' });
  assert.notEqual(blocked.status, 0, 'commit with a secret must be blocked');
  assert.match(blocked.stdout + blocked.stderr, /Secret Guard blocked this commit/);
  writeFileSync(join(d, 'pay.js'), 'const k = process.env.STRIPE_SECRET_KEY;\n');
  execFileSync('git', ['add', 'pay.js'], { cwd: d });
  assert.equal(spawnSync('git', ['commit', '-q', '-m', 'ok'], { cwd: d }).status, 0);
  rmSync(d, { recursive: true, force: true });
});

test('existing foreign hook is not overwritten without --force', () => {
  const { d } = repo();
  writeFileSync(join(d, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\necho mine\n');
  assert.throws(() => installHook(d, bin), /already exists/);
  installHook(d, bin, { force: true });
  assert.ok(existsSync(join(d, '.git', 'hooks', 'pre-commit.bak')));
  rmSync(d, { recursive: true, force: true });
});

test('init-action writes a full-history workflow', () => {
  const { d } = repo();
  const f = initAction(d);
  const y = readFileSync(f, 'utf8');
  assert.match(y, /fetch-depth: 0/);
  assert.match(y, /blitzhash360-web\/blitzhash-secret-guard@v1/);
  assert.throws(() => initAction(d), /already exists/);
  rmSync(d, { recursive: true, force: true });
});
