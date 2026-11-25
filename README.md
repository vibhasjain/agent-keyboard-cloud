# agent-keyboard-cloud
Managed Agent Keyboard on Fly.io Sprites: auth.md sign-up, provisioning, dashboard. Spec: Notes #12 on agentkeyboard.com.

No dependencies; Node 22+.

- `src/fly.mjs`: Fly auth.md (register, claim poll, mint from `identity_assertion`) and the Sprites API (create, public URL, connectors, exec).
- `src/github.mjs`: repo lookup, starter repo creation, deploy keys. Takes any token with repo rights (a PAT today, GitHub App installation tokens later).
- `src/provision.mjs`: one instance end to end. Mint Fly tokens → find the Anthropic connector → create the `ak-<site>` Sprite and make its URL public → (no repo: create a starter repo whose `index.html` carries the script tag; the Sprite hosts it via `serve:true`) → write `~/ak.env` → run `server/sprite-install.sh` from the public repo → add the Sprite's deploy key to the repo → `/health` → invite the email to the bar's Supabase.

```
GITHUB_TOKEN=… SUPABASE_URL=… SUPABASE_ANON_KEY=… SUPABASE_SERVICE_KEY=… \
  node bin/provision.mjs --creds fly-creds.json --email you@x.com --name my-site          # starter site
  node bin/provision.mjs --creds fly-creds.json --email you@x.com --repo you/site --domain site.com   # existing site
```

`fly-creds.json` holds the `identity_assertion` from a claimed auth.md registration (chmod 600, never committed).
