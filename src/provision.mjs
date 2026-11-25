// Provision one managed Agent Keyboard: a Sprite in the user's own Fly account running
// the bar for one site. With `repo` the user brings their site and gets a script tag;
// without it we create a starter repo that the Sprite also hosts (SITES serve:true).

import { randomBytes } from "node:crypto";
import { mint, sprites } from "./fly.mjs";
import { addDeployKey, createRepo, getRepo } from "./github.mjs";

const INSTALL_URL = "https://raw.githubusercontent.com/vibhasjain/agent-keyboard/{ref}/server/sprite-install.sh";
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

export const slug = (s) => s.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "site";

/** Create the Sprite `name` unless it exists, make its URL public, return the URL. */
export async function ensureSprite(api, name) {
  let sprite = await api.get(name).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
  sprite ??= await api.create(name);
  await api.setPublic(name);
  return sprite.url.replace(/\/$/, "");
}

export function scriptTag(spriteUrl, siteId) {
  return `<script src="${spriteUrl}/widget.js" data-site="${siteId}" defer></script>`;
}

export function starterIndex(name, tag) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${name}</title>
<style>
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; font: 18px/1.5 system-ui, sans-serif; background: #faf9f7; color: #1a1a1a; }
  main { max-width: 34rem; padding: 2rem; }
  h1 { font-size: 2.2rem; line-height: 1.15; margin: 0 0 1rem; }
  p { color: #555; }
</style>
</head>
<body>
<main>
  <h1>${name}</h1>
  <p>This is your new site. Tap the bar in the corner and tell it what to build.</p>
</main>
${tag}
</body>
</html>
`;
}

/**
 * opts: {
 *   assertion,             // the user's Fly identity_assertion
 *   email,                 // verified email: ALLOWED_EMAIL and the bar's sign-in
 *   repo?,                 // "owner/name" of their site; omit for a starter site
 *   domain?,               // their site's host (CORS); default: the repo's homepage
 *   name?,                 // starter repo name (default "my-site")
 *   githubToken,           // repo rights on `repo` / the user's account
 *   supabase: { url, anonKey, serviceKey },
 *   ref?,                  // agent-keyboard git ref to install (default "main")
 *   connector?,            // the Sprites connector for Anthropic (default: the custom_api one for api.anthropic.com)
 * }
 * progress(step) is called before each step. Returns { sprite, url, siteId, repo, tag, starter }.
 */
export async function provision(opts, progress = () => {}) {
  const { email, githubToken, supabase } = opts;
  const userToken = opts.userToken ?? githubToken; // creating a repo needs a user token
  const ref = opts.ref ?? "main";
  const starter = !opts.repo;

  progress("fly: minting tokens");
  const api = sprites(await mint(opts.assertion));

  progress("github: checking the repo");
  let repo = starter ? null : await getRepo(githubToken, opts.repo);
  const siteId = slug(starter ? opts.name ?? "my-site" : repo.name);
  const name = `ak-${siteId}`;

  progress("claude: finding the connector");
  const conns = await api.connections();
  const conn = opts.connector
    ? conns.find((c) => c.id === opts.connector)
    : conns.find((c) => c.provider === "custom_api" && c.provider_info?.base_api_url === "https://api.anthropic.com");
  if (!conn) throw new Error("no Anthropic connector in this Fly account (custom_api for https://api.anthropic.com)");
  if (!name.startsWith(conn.access_policy?.name_prefix ?? "\0")) await api.setPolicy(conn.id, "ak-");

  progress(`sprite: creating ${name}`);
  const url = await ensureSprite(api, name);
  // A starter site lives on the Sprite; a brought site is wherever its homepage is.
  const homepage = repo?.homepage && (/^https?:\/\//.test(repo.homepage) ? repo.homepage : `https://${repo.homepage}`);
  const domain = starter ? new URL(url).host : opts.domain ?? (homepage && new URL(homepage).host);
  if (!domain) throw new Error(`no domain for ${repo.full_name}: pass the site's host (the repo has no homepage)`);

  if (starter) {
    progress("github: creating the starter repo");
    const repoName = opts.name ?? "my-site";
    repo = await createRepo(userToken, repoName, "My site, built with Agent Keyboard", {
      "index.html": starterIndex(repoName, scriptTag(url, siteId)),
    });
  }

  const site = { id: siteId, repo: repo.ssh_url, branch: repo.default_branch || "main", domain, ...(starter ? { serve: true } : {}) };
  const env = {
    PORT: "8080",
    AGENT_DATA_DIR: "/data",
    IS_SANDBOX: "1",
    NODE_ENV: "production",
    SITES: JSON.stringify([site]),
    SUPABASE_URL: supabase.url,
    SUPABASE_ANON_KEY: supabase.anonKey,
    ALLOWED_EMAIL: email,
    AK_INTERNAL_SECRET: randomBytes(24).toString("hex"),
    ANTHROPIC_BASE_URL: `https://api.sprites.dev/v1/gateway/custom_api/${conn.id}`,
    CLAUDE_CODE_OAUTH_TOKEN: "placeholder", // the connector swaps in the real token
  };
  const envFile = Object.entries(env).map(([k, v]) => `${k}=${shq(v)}`).join("\n") + "\n";

  progress("sprite: installing Agent Keyboard");
  const { out } = await api.exec(
    name,
    [
      `umask 077; printf %s ${shq(Buffer.from(envFile).toString("base64"))} | base64 -d > ~/ak.env`,
      `curl -fsSL ${shq(INSTALL_URL.replace("{ref}", ref))} -o ~/sprite-install.sh`,
      `AK_REF=${shq(ref)} bash ~/sprite-install.sh`,
    ].join(" && "),
  );
  const pubkey = out.split("\n").reverse().find((l) => l.startsWith("ssh-ed25519 "));
  if (!pubkey) throw new Error(`install printed no deploy key: ${out.slice(-400)}`);

  progress("github: adding the deploy key");
  await addDeployKey(githubToken, repo.full_name, `Agent Keyboard (${name})`, pubkey);

  progress("bar: checking it's live");
  const health = await fetch(`${url}/health`).then((r) => r.ok, () => false);
  if (!health) throw new Error(`${url}/health is not answering`);

  progress("bar: sign-in account");
  await ensureBarUser(supabase, email);

  return { sprite: name, url, siteId, repo: repo.full_name, domain, connection: conn.id, tag: scriptTag(url, siteId), starter };
}

/** The bar signs in against our Supabase: invite the email unless it already has an account. */
async function ensureBarUser({ url, serviceKey }, email) {
  const res = await fetch(`${url}/auth/v1/invite`, {
    method: "POST",
    headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (res.ok || res.status === 422) return; // 422: already registered
  throw new Error(`supabase invite: ${res.status} ${(await res.text()).slice(0, 200)}`);
}
