// Where and how to rotate each kind of leaked key. Matched against the Gitleaks rule id.
const R = (match, name, where, steps, severity = 'critical') => ({ match, name, where, steps, severity });

export const ROTATION = [
  R(/^supabase-service-role|^supabase-secret-key/, 'Supabase service_role / secret key',
    'Supabase dashboard -> Project Settings -> API Keys',
    ['Create a new secret key (or roll the JWT secret on legacy projects).', 'Update it in your server env (Vercel/Netlify/Hostinger) and redeploy.', 'Delete the old key. This key bypasses Row Level Security, so check your tables for unexpected changes.']),
  R(/^supabase-access-token/, 'Supabase personal access token', 'supabase.com/dashboard/account/tokens',
    ['Revoke the token.', 'Create a new one only where you need it (CI secret, not code).']),
  R(/^stripe/, 'Stripe secret or restricted key', 'Stripe Dashboard -> Developers -> API keys',
    ['Roll the key (Stripe lets you set the old one to expire).', 'Update server env and redeploy.', 'Check Developers -> Logs for requests you did not make.']),
  R(/^openai/, 'OpenAI API key', 'platform.openai.com/api-keys',
    ['Revoke the key.', 'Create a project-scoped key with a usage limit.', 'Check Usage for spikes; leaked AI keys are abused within hours.']),
  R(/^anthropic/, 'Anthropic API key', 'console.anthropic.com -> API Keys',
    ['Disable and delete the key.', 'Create a new key in a workspace with a spend limit.', 'Check usage for spikes.']),
  R(/^aws/, 'AWS access key', 'AWS Console -> IAM -> Users -> Security credentials',
    ['Deactivate, then delete the access key.', 'Create a new least-privilege key (or move to OIDC / roles).', 'Check CloudTrail and Billing for unknown activity in every region.']),
  R(/^gcp|^google/, 'Google Cloud / Firebase API key', 'Google Cloud Console -> APIs & Services -> Credentials',
    ['Regenerate the key.', 'Add API and HTTP referrer restrictions.', 'Check Billing for unknown usage.']),
  R(/^github/, 'GitHub token', 'github.com/settings/tokens (or the app/org settings)',
    ['Revoke the token.', 'Use a fine-grained token scoped to one repo, with an expiry.']),
  R(/^slack/, 'Slack token or webhook', 'api.slack.com/apps -> your app',
    ['Rotate the token / regenerate the webhook URL.', 'Check workspace access logs.'], 'high'),
  R(/^sendgrid|^mailgun|^postmark|^resend|^sendinblue|^mailchimp/, 'Email provider API key', "Your email provider's API keys page",
    ['Delete the key and create a new one with send-only scope.', 'Check sending logs; leaked email keys are used for spam and hurt your domain reputation.'], 'high'),
  R(/^twilio/, 'Twilio key', 'Twilio Console -> Account -> API keys & tokens',
    ['Delete the key; rotate the auth token if it leaked.', 'Check usage for unknown SMS/calls.'], 'high'),
  R(/^private-key/, 'Private key (SSH / TLS / JWT signing)', 'Wherever this key is trusted',
    ['Generate a new key pair.', 'Replace the public key everywhere it is trusted (servers, deploy keys, JWT verifiers).', 'Remove the old public key.']),
  R(/^jwt/, 'JSON Web Token', 'The service that issued it',
    ['If it is long-lived or a service key, rotate the signing secret or the key.', 'Short-lived user session tokens usually expire on their own, but check.'], 'high'),
  R(/^generic-api-key|.*/, 'API key or password (generic match)', 'The service the variable name points to',
    ['Confirm whether it is a real credential (Gitleaks matched a key-like value).', 'If real: revoke it at the provider, create a new one, store it in env vars, redeploy.'], 'medium'),
];

export function rotationFor(ruleId = '') {
  return ROTATION.find(r => r.match.test(ruleId));
}
