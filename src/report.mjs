const ICON = { critical: '🔴', high: '🟠', medium: '🟡' };

export function renderReport(result, { color = false } = {}) {
  const { leaks, dir, mode, commitCount, remote } = result;
  const L = [];
  L.push('# Secret Guard report', '');
  L.push(`Scanned: \`${dir}\` (${mode === 'history' ? `full git history, ${commitCount} commits, all branches` : mode === 'staged' ? 'staged changes' : 'folder, no git history'})`);
  L.push(`Engine: Gitleaks default rules + BlitzHash rules for Supabase and Resend keys. Secret values are never printed.`, '');
  if (!leaks.length) {
    L.push('✅ No secrets found.', '', 'Keep it that way: `secret-guard install-hook` blocks secrets before they are committed, and `secret-guard init-action` checks every push and pull request.');
    return L.join('\n') + '\n';
  }
  const live = leaks.filter(l => l.inCurrentCode).length;
  const hist = leaks.filter(l => l.historyOnly).length;
  L.push(`**${leaks.length} secret(s) found**: ${live} still in your current code, ${hist} deleted but still in git history.`, '');
  if (hist) L.push('> Deleting a key from your code does not remove it. Anyone who can clone this repo can read every old commit. A key that was ever pushed is a leaked key: **rotate it first**, then clean history.', '');
  if (remote.hosted) L.push(`> This repo has a hosted remote (${remote.url}). If it is or ever was public, assume bots already copied these keys.`, '');
  L.push('## Fix in this order', '', '1. **Rotate** every key below at the provider (steps per key). This is the only step that actually stops abuse.', '2. **Move** keys into environment variables (Vercel/Netlify/Hostinger env settings, `.env` in `.gitignore`).', '3. **Clean history** with `secret-guard cleanup-plan` (optional once rotated, but stops the old key showing up in future scans and forks).', '4. **Prevent** repeats: `secret-guard install-hook` and `secret-guard init-action`.', '');
  L.push('## Findings', '');
  leaks.forEach((l, i) => {
    L.push(`### ${i + 1}. ${ICON[l.severity]} ${l.kind}  \`${l.preview}\``, '');
    L.push(`- Status: ${l.inCurrentCode ? '**still in your current code**' : 'deleted from code, **still in git history**'}`);
    L.push(`- Rule: \`${l.rule}\`${l.firstSeen ? `, first committed ${l.firstSeen}` : ''}${l.commits.length ? `, in ${l.commits.length} commit(s)` : ''}`);
    const locs = l.locations.slice(0, 5).map(x => `\`${x.file}:${x.line}\`${x.commit ? ` @ ${x.commit}` : ''}`);
    L.push(`- Where: ${locs.join(', ')}${l.locations.length > 5 ? ` and ${l.locations.length - 5} more` : ''}`);
    L.push(`- Rotate at: ${l.where}`);
    l.steps.forEach(s => L.push(`  - [ ] ${s}`));
    L.push('');
  });
  L.push('## Going to production?', '', 'Rotating keys fixes today. If your app was built with Lovable, Bolt, Cursor or v0, leaked keys are usually a sign of bigger gaps (open database tables, unsigned webhooks, no rate limits). BlitzHash does a free assessment: https://blitzhash.com');
  return L.join('\n') + '\n';
}
