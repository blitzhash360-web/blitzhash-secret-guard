#!/usr/bin/env node
import { writeFileSync, rmSync, appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ensureGitleaks, GITLEAKS_VERSION } from '../src/gitleaks.mjs';
import { scanTarget, isGitRepo } from '../src/scan.mjs';
import { renderReport } from '../src/report.mjs';
import { cleanupPlan, writeReplacements, installHook, initAction } from '../src/cleanup.mjs';
import { makeDemoRepo } from '../src/demo.mjs';

const HELP = `blitzhash-secret-guard: find leaked keys in your whole git history, rotate them, clean up, and stop new ones.
Built on Gitleaks v${GITLEAKS_VERSION} (MIT). Secret values are never printed.

Usage: secret-guard <command> [path] [options]

Commands:
  scan [path]          Scan the full git history (all branches) or a plain folder. Default command.
  demo                 Run on a throwaway repo with fake planted keys, to see the report.
  cleanup-plan [path]  Print a safe, step-by-step history cleanup plan. Changes nothing.
  install-hook [path]  Add a pre-commit hook that blocks staged secrets.
  init-action [path]   Add .github/workflows/secret-guard.yml (scans every push and PR).
  staged [path]        Scan staged changes only (what the hook runs).

Options:
  --out <file>                  Also write the report to a file (markdown).
  --summary <file>              Append the report to a file (used for GITHUB_STEP_SUMMARY).
  --no-fail                     Exit 0 even when secrets are found (default exits 1).
  --write-replacements <file>   cleanup-plan: write the git-filter-repo replacements file (contains raw secrets, mode 600).
  --force                       install-hook / init-action: replace an existing file (hook keeps a .bak).
  --no-download                 Never download Gitleaks; use one on PATH or GITLEAKS_BIN.
  -h, --help                    Show this help.
`;

function parse(argv) {
  const o = { _: [], fail: true, download: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '--no-fail') o.fail = false;
    else if (a === '--no-download') o.download = false;
    else if (a === '--force') o.force = true;
    else if (a === '--no-color') o.noColor = true;
    else if (a === '--out' || a === '--summary' || a === '--write-replacements') o[a.slice(2).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = argv[++i];
    else if (a.startsWith('-')) { console.error(`Unknown option ${a}\n`); o.help = true; o.bad = true; }
    else o._.push(a);
  }
  return o;
}

async function main() {
  const o = parse(process.argv.slice(2));
  if (o.help) { process.stdout.write(HELP); return o.bad ? 2 : 0; }
  const cmds = ['scan', 'demo', 'cleanup-plan', 'install-hook', 'init-action', 'staged'];
  const cmd = cmds.includes(o._[0]) ? o._.shift() : 'scan';
  const target = resolve(o._[0] || '.');
  const log = m => console.error(m);

  if (cmd === 'init-action') {
    const f = initAction(target, { force: o.force });
    console.log(`Added ${f}\nCommit it; every push and pull request will now be scanned (full history) and fail if a secret is found.`);
    return 0;
  }
  const bin = await ensureGitleaks({ log, allowDownload: o.download });
  if (cmd === 'install-hook') {
    if (!isGitRepo(target)) throw new Error('install-hook needs a git repository.');
    const { hook } = installHook(target, bin, { force: o.force });
    console.log(`Installed ${hook}\nStaged secrets will now block the commit. Test it: put a fake key in a file, git add it, and try to commit.`);
    return 0;
  }
  let demoDir;
  const scanDir = cmd === 'demo' ? (demoDir = makeDemoRepo()) : target;
  try {
    const result = scanTarget(bin, scanDir, { staged: cmd === 'staged' });
    if (cmd === 'cleanup-plan') {
      if (!result.inGit) throw new Error('cleanup-plan needs a git repository.');
      let rep;
      if (o.writeReplacements) rep = writeReplacements(result.leaks, resolve(o.writeReplacements));
      process.stdout.write(cleanupPlan(result, rep));
      return 0;
    }
    const md = renderReport(result);
    process.stdout.write(md);
    if (o.out) writeFileSync(o.out, md);
    if (o.summary) appendFileSync(o.summary, md);
    if (cmd === 'demo') console.log('\n(Demo repo with fake keys was deleted. Now run it on your own project: npx -y github:blitzhash360-web/blitzhash-secret-guard scan .)');
    return result.leaks.length && o.fail && cmd !== 'demo' ? 1 : 0;
  } finally {
    if (demoDir) rmSync(demoDir, { recursive: true, force: true });
  }
}

main().then(code => process.exit(code), err => { console.error(`secret-guard: ${err.message}`); process.exit(2); });
