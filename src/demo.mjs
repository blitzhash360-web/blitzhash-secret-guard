import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';

// Builds a throwaway repo with FAKE keys, generated at runtime (nothing real, nothing committed here).
const rand = (n, set = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') =>
  [...randomBytes(n)].map(b => set[b % set.length]).join('');

export function makeDemoRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'secret-guard-demo-'));
  const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  const commit = (msg, date) => execFileSync('git', ['commit', '-q', '-m', msg], { cwd: dir, env: { ...process.env, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } });
  g('init', '-q', '-b', 'main');
  g('config', 'user.email', 'demo@example.com');
  g('config', 'user.name', 'Demo Founder');
  g('config', 'commit.gpgsign', 'false');
  const supa = ['sb', 'secret', rand(40)].join('_');
  const stripe = ['sk', 'live', rand(32)].join('_');
  writeFileSync(join(dir, '.env'), `NEXT_PUBLIC_SUPABASE_URL=https://demo.supabase.co\nSUPABASE_SECRET_KEY=${supa}\n`);
  writeFileSync(join(dir, 'README.md'), '# my-lovable-app\n');
  g('add', '.'); commit('first version from Lovable', '2026-11-02T10:00:00Z');
  rmSync(join(dir, '.env'));
  writeFileSync(join(dir, '.gitignore'), '.env\n');
  g('add', '-A'); commit('remove .env (oops)', '2026-11-03T10:00:00Z');
  writeFileSync(join(dir, 'checkout.js'), `import Stripe from 'stripe';\nconst stripe = new Stripe('${stripe}');\nexport default stripe;\n`);
  g('add', '.'); commit('add payments', '2026-11-05T10:00:00Z');
  return dir;
}
