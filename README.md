# agent-keyboard-cloud
Managed Agent Keyboard on Fly.io Sprites: auth.md sign-up, provisioning, dashboard. Spec: Notes #12 on agentkeyboard.com.

No dependencies; Node 22+.

- `src/fly.mjs`: Fly auth.md (register, claim poll, mint from `identity_assertion`) and the Sprites API (create, public URL, connectors, exec).
- `src/github.mjs`: repo lookup, starter repo creation, deploy keys. Takes any token with repo rights (a PAT today, GitHub App installation tokens later).
- `src/server.mjs`: the web app. `/start` (GitHub sign-in → pick a repo or "no site yet" → Fly code → Claude sign-in → provision) and `/dashboard` (status, Restart, Update, Delete), JSON API under `/cloud/`. Instances live in `<DATA_DIR>/instances.json`, the Fly assertion AES-GCM encrypted with `CLOUD_KEY`. agentkeyboard.com proxies `/start`, `/dashboard` and `/cloud/*` here (Netlify rewrites), so the session cookie is first-party.
- `src/githubapp.mjs`: the "Agent Keyboard" GitHub App: user sign-in, installs, and the one-time manifest flow that creates the App (`/cloud/github/setup?key=$SETUP_KEY`, saved to `<DATA_DIR>/github-app.json`).
- `src/claude.mjs`: Claude sign-in relayed from the page. `claude setup-token` runs in tmux on the user's Sprite; the page shows its link and posts the code back; the Sprite itself puts the token into a Custom API connector (policy: that Sprite only). The token never reaches us.
- `src/provision.mjs`: one instance end to end. Mint Fly tokens → find the Anthropic connector → create the `ak-<site>` Sprite and make its URL public → (no repo: create a starter repo whose `index.html` carries the script tag; the Sprite hosts it via `serve:true`) → write `~/ak.env` → run `server/sprite-install.sh` from the public repo → add the Sprite's deploy key to the repo → `/health` → invite the email to the bar's Supabase.

```
GITHUB_TOKEN=… SUPABASE_URL=… SUPABASE_ANON_KEY=… SUPABASE_SERVICE_KEY=… \
  node bin/provision.mjs --creds fly-creds.json --email you@x.com --name my-site          # starter site
  node bin/provision.mjs --creds fly-creds.json --email you@x.com --repo you/site --domain site.com   # existing site
```

`fly-creds.json` holds the `identity_assertion` from a claimed auth.md registration (chmod 600, never committed).

## Deploy (Fly app `agent-keyboard-cloud`, in Lingxiao's Fly account)

```
fly apps create agent-keyboard-cloud && fly volumes create cloud_data -a agent-keyboard-cloud -r iad -s 1
fly secrets set -a agent-keyboard-cloud CLOUD_KEY=$(openssl rand -hex 32) SETUP_KEY=… SUPABASE_URL=… SUPABASE_ANON_KEY=… SUPABASE_SERVICE_KEY=…
fly deploy   # after that, every push to main deploys (.github/workflows/deploy.yml, repo secret FLY_API_TOKEN = fly tokens create deploy -a agent-keyboard-cloud)
```
Then open `https://agentkeyboard.com/cloud/github/setup?key=$SETUP_KEY` once, signed in to the GitHub account that should own the App (`&org=<org>` for an org).
