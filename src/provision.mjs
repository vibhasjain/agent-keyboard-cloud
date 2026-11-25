// Provision one managed Agent Keyboard: a Sprite in the user's own Fly account running
// the bar for one site. With `repo` the user brings their site and gets a script tag;
// without it we create a starter repo that the Sprite also hosts (SITES serve:true).

import { randomBytes } from "node:crypto";
import { mint, sprites } from "./fly.mjs";
import { addDeployKey, addTag, createRepo, ensureBranch, getRepo, isBlank, putFile } from "./github.mjs";

const INSTALL_URL = "https://raw.githubusercontent.com/vibhasjain/agent-keyboard/{ref}/server/sprite-install.sh";
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

export const slug = (s) => s.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "site";

/** Our Sprites are all named ak-*; don't double the prefix ("ak-test" stays "ak-test"). */
export const spriteName = (siteId) => (siteId.startsWith("ak-") ? siteId : `ak-${siteId}`);

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

const STAGING = "ak-staging";

/** The Sprite agent's user memory for a staged site: where changes go and how to ship them. */
function stagingMemory(url, staging, live) {
  return `# Staging and live

This site is staged. Your pushes go to the \`${staging}\` branch, which this Sprite serves as a preview at ${url}. Nothing you push there reaches the live site.
If the repo has an npm `dev` script, the preview runs it (hot reload); after changing dependencies, run `npm install` in the checkout.

The live site deploys from \`${live}\` (wherever the owner's host builds it). When the owner asks to deploy, publish, ship or "go live":
1. Make sure everything is committed and pushed to \`${staging}\`.
2. \`git fetch origin ${live}\` and merge it into \`${staging}\` if it moved (resolve conflicts, push \`${staging}\`).
3. \`git push origin ${staging}:${live}\`. Their host redeploys from that.
4. Reply with what shipped. If you don't know the live URL, ask for it once and remember it.

Never push to \`${live}\` for any other reason.
`;
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
  let starter = !opts.repo; // starter: the Sprite hosts the site (a new repo, or a blank one the user picked)

  progress("fly: minting tokens");
  const api = sprites(await mint(opts.assertion));

  progress("github: checking the repo");
  let repo = starter ? null : await getRepo(githubToken, opts.repo);
  const blank = repo && (await isBlank(githubToken, repo.full_name));
  if (blank) starter = true;
  const siteId = slug(repo ? repo.name : opts.name ?? "my-site");
  const name = spriteName(siteId);

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
  // A brought site with no domain is staged: the Sprite serves the STAGING branch as a preview and the
  // bar pushes there; "deploy to live" (its ~/.claude/CLAUDE.md) pushes it to the default branch.
  const staging = !starter && !opts.domain;
  const domain = starter || staging ? new URL(url).host : opts.domain;

  if (blank) {
    progress("github: adding a starter page");
    await putFile(githubToken, repo.full_name, "index.html", starterIndex(repo.name, scriptTag(url, siteId)), "Starter site: index.html");
    repo = await getRepo(githubToken, repo.full_name); // an empty repo gets its default branch now
  } else if (starter) {
    progress("github: creating the starter repo");
    const repoName = opts.name ?? "my-site";
    repo = await createRepo(userToken, repoName, "My site, built with Agent Keyboard", {
      "index.html": starterIndex(repoName, scriptTag(url, siteId)),
    });
  }

  const live = repo.default_branch || "main";
  let tagPath = null;
  if (staging) {
    progress(`github: creating the ${STAGING} branch`);
    await ensureBranch(githubToken, repo.full_name, live, STAGING);
    tagPath = await addTag(githubToken, repo.full_name, scriptTag(url, siteId), STAGING).catch(() => null);
  }
  const site = { id: siteId, repo: repo.ssh_url, branch: staging ? STAGING : live, domain, ...(starter || staging ? { serve: true } : {}) };
  const memory = staging ? stagingMemory(url, STAGING, live) : "";
  const env = {
    PORT: "8080",
    AGENT_DATA_DIR: "/data",
    IS_SANDBOX: "1",
    NODE_ENV: "production",
    SITES: JSON.stringify([site]),
    SUPABASE_URL: supabase.url,
    SUPABASE_ANON_KEY: supabase.anonKey,
    ALLOWED_EMAIL: email,
    AK_RECOVER_URL: "https://agentkeyboard.com/dashboard", // the bar's "forgot password?"
    AK_INTERNAL_SECRET: randomBytes(24).toString("hex"),
    ANTHROPIC_BASE_URL: `https://api.sprites.dev/v1/gateway/custom_api/${conn.id}`,
    CLAUDE_CODE_OAUTH_TOKEN: "placeholder", // the connector swaps in the real token
    // A blank repo is hosted on the Sprite for now; let the bar work once its own domain points here.
    ...(blank && opts.domain ? { EXTRA_ORIGINS: `https://${opts.domain},https://www.${opts.domain}` } : {}),
  };
  const envFile = Object.entries(env).map(([k, v]) => `${k}=${shq(v)}`).join("\n") + "\n";

  progress("sprite: installing Agent Keyboard");
  const { out } = await api.exec(
    name,
    [
      `umask 077; printf %s ${shq(Buffer.from(envFile).toString("base64"))} | base64 -d > ~/ak.env`,
      ...(memory ? [`mkdir -p ~/.claude && printf %s ${shq(Buffer.from(memory).toString("base64"))} | base64 -d > ~/.claude/CLAUDE.md`] : []),
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

  return { sprite: name, url, siteId, repo: repo.full_name, domain, connection: conn.id, tag: scriptTag(url, siteId), starter, staging, tagPath };
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
