# Key rotation checklist

A key that was ever pushed to a shared or public repo is leaked, even if you deleted it a minute later. Bots scan new GitHub commits continuously. Rotate first, clean up second.

## For every leaked key

- [ ] Create the new key at the provider (scoped as narrowly as possible, with a spend limit where offered).
- [ ] Put it in your host's environment variables (Vercel, Netlify, Railway, Hostinger, Supabase Edge Function secrets), not in code.
- [ ] Redeploy, and check the app still works.
- [ ] Revoke / delete the old key.
- [ ] Check the provider's usage, logs and billing for activity you did not make.

## Provider quick links

| Key | Where to rotate | Extra check |
|---|---|---|
| Supabase `sb_secret_` / `service_role` | Project Settings -> API Keys (legacy projects: roll the JWT secret) | It bypasses Row Level Security: check tables and Auth users for unexpected changes |
| Supabase personal access token `sbp_` | supabase.com/dashboard/account/tokens | Review projects and org members |
| Stripe `sk_live_` / `rk_live_` | Developers -> API keys -> Roll key | Developers -> Logs, and webhooks you did not add |
| OpenAI | platform.openai.com/api-keys | Usage page; set a monthly limit |
| Anthropic | console.anthropic.com -> API Keys | Usage; workspace spend limit |
| AWS access key | IAM -> Users -> Security credentials | CloudTrail and Billing in every region |
| Google Cloud / Firebase | APIs & Services -> Credentials | Add API + referrer restrictions |
| GitHub token | github.com/settings/tokens | Use fine-grained, single-repo, expiring tokens |
| Email (Resend, SendGrid, Mailgun, Postmark) | Provider API keys page | Sending logs; spam from your domain hurts deliverability |
| Twilio | Console -> API keys & tokens | SMS/call usage |
| SSH / TLS / signing private key | Wherever the public key is trusted | Remove the old public key everywhere |

## Afterwards

- [ ] `secret-guard install-hook` on every developer machine.
- [ ] `secret-guard init-action` so every push and pull request is scanned.
- [ ] Turn on GitHub secret scanning and push protection (repo Settings -> Code security) if available on your plan.
