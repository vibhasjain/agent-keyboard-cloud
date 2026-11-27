# Agent Keyboard Cloud

[![A glowing prompt bar between a pixel-art typewriter and a website, on a purple sky with balloons](https://agentkeyboard.com/cloud-og.jpg)](https://agentkeyboard.com/start)

Your own coding agent, living inside your website, running on your own [Fly.io Sprite](https://sprites.dev).

Open [agentkeyboard.com/start](https://agentkeyboard.com/start), sign in with GitHub, Fly and Claude, and about a minute later your site has a prompt bar in the corner. Type or hold to talk ("make the headline say hello", "add a dark mode"), and a real Claude Code session edits your site's repo, commits and ships it. You watch every step, and the page updates when it's done.

This repo is the part that sets that up and runs it for you: the sign-up, the provisioning and the dashboard. The bar and the agent server it installs are open source at [vibhasjain/agent-keyboard](https://github.com/vibhasjain/agent-keyboard).

## How it works

1. **GitHub.** Pick a repo that already has a site, or "I don't have a site yet" and we create a starter one.
2. **Fly.** We show a short code: open fly.io and enter it. That's Fly's auth.md agent sign-up, so we never handle your Fly password and the agent works in your own account.
3. **Claude.** Sign in to Claude once. Your token goes straight into a **Sprites connector** scoped to your Sprite, so it never reaches us.
4. **Your Sprite.** We create `ak-<your-site>`, a Sprite in your Fly account, install the Agent Keyboard server on it, and give it a deploy key for just your repo.
5. **Your site.** It's hosted on Cloudflare Pages (or wherever it already deploys) with the bar on it. From then on, you change your site by asking it.

Your Sprite, your connector, your bill. Each site runs in its own Sprite.

## What else you get

- **A dashboard** at [agentkeyboard.com/dashboard](https://agentkeyboard.com/dashboard): status, restart, update, delete. Sprites auto-update when a new version ships, unless a job is running.
- **Custom domains** on Cloudflare Pages, set up from the dashboard.
- **Email from your own domain** (through your Resend account) for @mentions and notifications.
- **Claude as a remote control.** Add `https://agentkeyboard.com/mcp` as a connector in Claude to set up sites, or ask a site's agent for a change, from any Claude chat. Your sites' agents can also message each other.
- **Moving in.** Already running Agent Keyboard yourself? "Bring them over" moves your notes, memory and settings to your Sprite.

## Inside the repo

No build step; Node 22+.

- `src/fly.mjs`: Fly auth.md (register, claim poll, mint from `identity_assertion`) and the Sprites API (create, public URL, connectors, exec).
- `src/github.mjs`: repo lookup, starter repo creation, deploy keys. Takes any token with repo rights (a PAT today, GitHub App installation tokens later).
- `src/server.mjs`: the web app. `/start` (GitHub sign-in → pick a repo or "no site yet" → Fly code → Claude sign-in → provision) and `/dashboard` (status, Restart, Update, Auto-update, Delete; auto-update is on by default: right after each release (agent-keyboard's deploy workflow POSTs `/cloud/release` with `x-release-key: $RELEASE_KEY`) and hourly as a retry, a Sprite behind the latest `server/`+`widget/` commits reinstalls unless a job is running), JSON API under `/cloud/`; `/cloud/events` is server push (SSE): a per-user revision that moves when their sites or Cloudflare/Claude connections change, opened on the Fly app directly via the signed URL in `/cloud/me` (Netlify buffers proxied streams). Instances live in `<DATA_DIR>/instances.json`, the Fly assertion AES-GCM encrypted with `CLOUD_KEY`. agentkeyboard.com proxies `/start`, `/dashboard` and `/cloud/*` here (Netlify rewrites), so the session cookie is first-party.
- `src/githubapp.mjs`: the "Agent Keyboard" GitHub App: user sign-in, installs, and the one-time manifest flow that creates the App (`/cloud/github/setup?key=$SETUP_KEY`, saved to `<DATA_DIR>/github-app.json`).
- `src/claude.mjs`: Claude sign-in relayed from the page. `claude setup-token` runs in tmux on the user's Sprite; the page shows its link and posts the code back; the Sprite itself puts the token into a Custom API connector (policy: that Sprite only). The token never reaches us.
- `src/provision.mjs`: one instance end to end. Mint Fly tokens → find the Anthropic connector → create the `ak-<site>` Sprite and make its URL public → (no repo: create a starter repo whose `index.html` carries the script tag) → write `~/ak.env` → run `server/sprite-install.sh` from the public repo → add the Sprite's deploy key to the repo → `/health` → invite the email to the bar's Supabase.

```
GITHUB_TOKEN=… SUPABASE_URL=… SUPABASE_ANON_KEY=… SUPABASE_SERVICE_KEY=… \
  node bin/provision.mjs --creds fly-creds.json --email you@x.com --name my-site          # starter site
  node bin/provision.mjs --creds fly-creds.json --email you@x.com --repo you/site --domain site.com   # existing site
```

`fly-creds.json` holds the `identity_assertion` from a claimed auth.md registration (chmod 600, never committed).

## Deploy (Fly app `agent-keyboard-cloud`, in Lingxiao's Fly account)

```
fly apps create agent-keyboard-cloud && fly volumes create cloud_data -a agent-keyboard-cloud -r iad -s 1
fly secrets set -a agent-keyboard-cloud CLOUD_KEY=$(openssl rand -hex 32) SETUP_KEY=… SUPABASE_URL=… SUPABASE_ANON_KEY=… SUPABASE_SERVICE_KEY=… RELEASE_KEY=$(openssl rand -hex 32)  # RELEASE_KEY: also the AK_RELEASE_KEY Actions secret on agent-keyboard
fly deploy   # after that, every push to main deploys (.github/workflows/deploy.yml, repo secret FLY_API_TOKEN = fly tokens create deploy -a agent-keyboard-cloud)
```
Then open `https://agentkeyboard.com/cloud/github/setup?key=$SETUP_KEY` once, signed in to the GitHub account that should own the App (`&org=<org>` for an org).
