import { writeFileSync, chmodSync, existsSync, readFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { git } from './scan.mjs';
import { CONFIG_PATH } from './scan.mjs';

// Writes a git-filter-repo replacements file (secret ==> placeholder). It contains the raw secrets,
// so it is created with 0600 permissions OUTSIDE the repo by default and must be deleted after use.
export function writeReplacements(leaks, file) {
  const body = leaks.map(l => `${l.secret}==>REMOVED-BY-SECRET-GUARD-${l.id}`).join('\n') + '\n';
  writeFileSync(file, body, { mode: 0o600 });
  chmodSync(file, 0o600);
  return file;
}

export function cleanupPlan(result, replacementsFile) {
  const { leaks, dir, remote } = result;
  const branch = git(dir, ['rev-parse', '--abbrev-ref', 'HEAD'])?.trim() || 'main';
  const L = ['# History cleanup plan (nothing has been changed)', ''];
  if (!leaks.length) return L.concat(['No secrets found, nothing to clean.']).join('\n') + '\n';
  const live = leaks.filter(l => l.inCurrentCode);
  L.push('Read all of it before running anything. Rewriting history changes every commit hash after the leak.', '');
  L.push('## 0. Rotate first', '', 'Cleaning history does NOT un-leak a key. Clones, forks, CI logs and caches may still have it. Confirm every key in the report is rotated before you continue.', '');
  if (live.length) L.push(`## 0b. Remove from current code`, '', `${live.length} secret(s) are still in your current files (${[...new Set(live.flatMap(l => l.locations.map(x => x.file)))].map(f => `\`${f}\``).join(', ')}). Move them to environment variables and commit that change first.`, '');
  L.push('## 1. Back up', '', '```sh', `git clone --mirror ${remote.url || '<your-repo-url>'} backup-before-cleanup.git`, '```', '');
  L.push('## 2. Install git-filter-repo', '', 'The tool GitHub recommends for this (https://github.com/newren/git-filter-repo):', '', '```sh', 'pip install git-filter-repo   # or: brew install git-filter-repo', '```', '');
  L.push('## 3. Replace the secrets in every commit', '', 'Run in a fresh clone:', '', '```sh', `git filter-repo --replace-text ${replacementsFile || '<replacements-file>'}`, '```', '');
  L.push(replacementsFile
    ? `The replacements file \`${replacementsFile}\` contains the raw secrets (permissions 600). Delete it as soon as the rewrite is done: \`rm ${replacementsFile}\`.`
    : 'Create the replacements file with `secret-guard cleanup-plan --write-replacements ~/secret-guard-replacements.txt` (kept outside the repo, permissions 600).', '');
  L.push('## 4. Check, then force-push', '', '```sh', 'npx -y github:blitzhash360-web/blitzhash-secret-guard scan .   # should report 0 history findings', `git remote add origin ${remote.url || '<your-repo-url>'}   # filter-repo removes the remote on purpose`, 'git push --force --all && git push --force --tags', '```', '');
  L.push('## 5. Tell everyone else', '', '- Collaborators must re-clone (old clones still contain the secret and can push it back).', '- Close or rebase open pull requests that include old commits.', '- On GitHub, old commits can stay reachable through cached views and pull request refs; GitHub Support can remove them (see GitHub docs: "Removing sensitive data from a repository").', '- Clear build caches on your host (Vercel/Netlify) if a key was ever in a build.', '');
  L.push('## 6. Prevent it', '', '```sh', 'npx -y github:blitzhash360-web/blitzhash-secret-guard install-hook', 'npx -y github:blitzhash360-web/blitzhash-secret-guard init-action', '```');
  return L.join('\n') + '\n';
}

export function installHook(repoDir, gitleaksBin, { force = false } = {}) {
  const gitDir = git(repoDir, ['rev-parse', '--git-common-dir'])?.trim();
  if (!gitDir) throw new Error('Not a git repository.');
  const hooksDir = gitDir.startsWith('/') ? join(gitDir, 'hooks') : join(repoDir, gitDir, 'hooks');
  const cfgDir = gitDir.startsWith('/') ? gitDir : join(repoDir, gitDir);
  mkdirSync(hooksDir, { recursive: true });
  const hook = join(hooksDir, 'pre-commit');
  if (existsSync(hook) && !readFileSync(hook, 'utf8').includes('blitzhash-secret-guard') && !force) {
    throw new Error(`A pre-commit hook already exists at ${hook}. Rerun with --force to replace it (a .bak copy is kept), or add the gitleaks line to it yourself.`);
  }
  if (existsSync(hook) && force) copyFileSync(hook, `${hook}.bak`);
  const cfg = join(cfgDir, 'secret-guard.toml');
  copyFileSync(CONFIG_PATH, cfg);
  const binRef = gitleaksBin === 'gitleaks' ? 'gitleaks' : `"${gitleaksBin}"`;
  writeFileSync(hook, `#!/bin/sh
# blitzhash-secret-guard pre-commit hook (runs Gitleaks on staged changes only)
# Skip once in an emergency: git commit --no-verify   (then rotate anything you committed)
${binRef} git --pre-commit --staged --redact --no-banner --log-level warn -v --config "${cfg}" .
status=$?
if [ $status -ne 0 ]; then
  echo ""
  echo "Secret Guard blocked this commit: a key or password is staged."
  echo "Move it into an environment variable (.env, listed in .gitignore) and commit again."
  exit 1
fi
`, { mode: 0o755 });
  chmodSync(hook, 0o755);
  return { hook, cfg };
}

export const WORKFLOW = `name: Secret Guard
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history, so old leaks are caught too
      - uses: blitzhash360-web/blitzhash-secret-guard@v1
`;

export function initAction(repoDir, { force = false } = {}) {
  const dir = join(repoDir, '.github', 'workflows');
  const file = join(dir, 'secret-guard.yml');
  if (existsSync(file) && !force) throw new Error(`${file} already exists (use --force to overwrite).`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(file, WORKFLOW);
  return file;
}
