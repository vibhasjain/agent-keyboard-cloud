// The control plane's web server: /start (sign up and provision), /signin, /dashboard (manage),
// and their JSON API under /cloud/. Zero deps. agentkeyboard.com proxies these paths here.
//
// Env: PORT, DATA_DIR, PUBLIC_URL (https://agentkeyboard.com), CLOUD_KEY (64 hex: encrypts
// stored Fly assertions + signs cookies), SETUP_KEY (guards the one-time App manifest page),
// SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY, AK_REF (agent-keyboard ref, default main),
// GH_APP_* (or the manifest flow).

import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { claudeLoginFinish, claudeLoginStart } from "./claude.mjs";
import { mint, pollClaim, register, sprites } from "./fly.mjs";
import { appReady, authorizeUrl, createdFromManifest, installationPage, installUrl, loadApp, manifest, refreshUser, signIn, userRepos } from "./githubapp.mjs";
import { mcp } from "./mcp.mjs";
import { addTag, getRepo, putSecret, putVariable, writeFile } from "./github.mjs";
import { TOKEN_URL, WORKFLOW, addPagesDomain, addRecords, cnameOf, ensureProject, findZone, isApex, pagesDomain, pagesMemory, pointDns, removePagesDomain, verify, accountLabel } from "./cloudflare.mjs";
import { provision, slug, spriteName } from "./provision.mjs";
import { checkKey, deleteKey, ensureDomain, fqdn, getDomain, sendingKey, verifyDomain } from "./resend.mjs";

const env = process.env;
const DATA = env.DATA_DIR ?? "./data";
const BASE = (env.PUBLIC_URL ?? `http://localhost:${env.PORT ?? 8787}`).replace(/\/$/, "");
const KEY = Buffer.from(env.CLOUD_KEY ?? "", "hex");
if (KEY.length !== 32) throw new Error("CLOUD_KEY must be 64 hex chars");
const REF = env.AK_REF ?? "main";
const supabase = { url: env.SUPABASE_URL, anonKey: env.SUPABASE_ANON_KEY, serviceKey: env.SUPABASE_SERVICE_KEY };
mkdirSync(DATA, { recursive: true });
loadApp(DATA);
const PAGES = new URL("../public/", import.meta.url);

// ---- store: one JSON file of instances; the Fly assertion is AES-256-GCM encrypted ----
const DB = `${DATA}/instances.json`;
// Oldest first: upsert re-appends what it updates, so the file's order moves whenever a site changes.
const load = () => (existsSync(DB) ? JSON.parse(readFileSync(DB, "utf8")) : []).sort((a, b) => String(a.createdAt ?? "").localeCompare(String(b.createdAt ?? "")));
function save(list) {
  const before = new Map(load().map((i) => [i.id, JSON.stringify(i)])), after = new Set(list.map((i) => i.id));
  for (const i of list) if (before.get(i.id) !== JSON.stringify(i)) notify(i.email);
  for (const i of load()) if (!after.has(i.id)) notify(i.email);
  writeFileSync(`${DB}.tmp`, JSON.stringify(list, null, 1), { mode: 0o600 });
  renameSync(`${DB}.tmp`, DB);
}
// ---- server push: /cloud/events streams a revision per user; it moves whenever their sites or connections change ----
const streams = new Map(), revs = new Map(), BOOT = Date.now(); // email → Set(res) / revision
function notify(email) {
  if (!email) return;
  const rev = (revs.get(email) ?? BOOT) + 1;
  revs.set(email, rev);
  for (const res of streams.get(email) ?? []) res.write(`data: ${rev}\n\n`);
}
const eventsUrl = (email) => {
  const e64 = Buffer.from(email).toString("base64url"), exp = Date.now() + 24 * 3600e3;
  return `${env.FLY_APP_NAME ? `https://${env.FLY_APP_NAME}.fly.dev` : BASE}/cloud/events?t=${e64}.${exp}.${mac(`events ${email} ${exp}`)}`;
};
const upsert = (inst) => save([...load().filter((i) => i.id !== inst.id), { ...inst, updatedAt: new Date().toISOString() }]);
function seal(s) {
  const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", KEY, iv);
  const enc = Buffer.concat([c.update(s, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString("base64");
}
function open(s) {
  const b = Buffer.from(s, "base64"), d = createDecipheriv("aes-256-gcm", KEY, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
}
const pub = ({ assertion, joins, ...i }) => i; // never send the assertion (or teammates' join tokens) anywhere

// ---- sessions: signed cookie {login,email,exp}; the GitHub user token stays in memory ----
const mac = (s) => createHmac("sha256", KEY).update(s).digest("base64url");
function cookies(req) {
  return Object.fromEntries((req.headers.cookie ?? "").split(/;\s*/).filter(Boolean).map((c) => [c.slice(0, c.indexOf("=")), decodeURIComponent(c.slice(c.indexOf("=") + 1))]));
}
function session(req) {
  const [v, sig] = (cookies(req).akc ?? "").split(".");
  if (!v || !sig || sig.length !== mac(v).length || !timingSafeEqual(Buffer.from(sig), Buffer.from(mac(v)))) return null;
  const s = JSON.parse(Buffer.from(v, "base64url").toString());
  return s.exp > Date.now() ? s : null;
}
const secure = BASE.startsWith("https:") ? "; Secure" : "";
function setSession(res, s) {
  const v = Buffer.from(JSON.stringify({ ...s, exp: Date.now() + 7 * 864e5 })).toString("base64url");
  res.setHeader("Set-Cookie", `akc=${v}.${mac(v)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secure}`);
}
// login → { token, installations, exp }: GitHub user tokens, sealed on the volume so deploys don't sign people out.
const USERS = `${DATA}/users.json`;
let users;
try { users = new Map(Object.entries(existsSync(USERS) ? JSON.parse(open(readFileSync(USERS, "utf8"))) : {})); } catch { users = new Map(); }
const saveUsers = () => writeFileSync(USERS, seal(JSON.stringify(Object.fromEntries(users))), { mode: 0o600 });
// email → { token (sealed), accountId, accountName }: the user's Cloudflare connection, reused for every instance (spec #13).
const CF = `${DATA}/cloudflare.json`;
let cfs;
try { cfs = new Map(Object.entries(existsSync(CF) ? JSON.parse(open(readFileSync(CF, "utf8"))) : {})); } catch { cfs = new Map(); }
const saveCfs = () => writeFileSync(CF, seal(JSON.stringify(Object.fromEntries(cfs))), { mode: 0o600 });
// email → { key (sealed), label }: the user's Resend connection (spec #17), reused for every site's email.
const RS = `${DATA}/resend.json`;
let resends;
try { resends = new Map(Object.entries(existsSync(RS) ? JSON.parse(open(readFileSync(RS, "utf8"))) : {})); } catch { resends = new Map(); }
const saveResends = () => writeFileSync(RS, seal(JSON.stringify(Object.fromEntries(resends))), { mode: 0o600 });
const resendKey = (email) => resends.get(email) && open(resends.get(email).key);
const ghUser = (login) => { const u = users.get(login); return u && u.exp > Date.now() ? u : null; };
const keep = (u) => ({ token: u.token, exp: Date.now() + (u.expiresIn ?? 8 * 3600) * 1000 - 60e3, refresh: u.refresh, refreshExp: u.refresh && Date.now() + (u.refreshExpiresIn ?? 15552000) * 1000 - 60e3 });
// An expired GitHub user token is swapped for a new one with its refresh token, so sign-ins (and MCP connectors) last.
const refreshing = new Map();
async function fresh(login) {
  const u = users.get(login);
  if (!u || u.exp > Date.now() || !u.refresh || !(u.refreshExp > Date.now())) return;
  if (!refreshing.has(login)) refreshing.set(login, refreshUser(u.refresh).then((t) => { users.set(login, { ...u, ...keep(t) }); saveUsers(); }, (e) => console.error("refresh", login, e.message)).finally(() => refreshing.delete(login)));
  await refreshing.get(login);
}
const flows = new Map(); // email → the start flow in progress
const states = new Map(); // oauth state → "start" | "dashboard"

// ---- the start flow ----
const ipHits = new Map();
function limited(ip) {
  const now = Date.now(), hits = (ipHits.get(ip) ?? []).filter((t) => now - t < 3600e3);
  hits.push(now);
  ipHits.set(ip, hits);
  return hits.length > 5;
}

function step(flow, s, extra = {}) {
  Object.assign(flow, { step: s, detail: "", error: null }, extra);
}

// Fly and Claude are connected once per account, like Cloudflare (accounts.json), and shared by every site:
// one Claude connector for all the user's ak-* Sprites. Users from before keep their newest site's.
const ACCT = `${DATA}/accounts.json`;
let accts;
try { accts = new Map(Object.entries(existsSync(ACCT) ? JSON.parse(open(readFileSync(ACCT, "utf8"))) : {})); } catch { accts = new Map(); }
const setAcct = (email, v) => { accts.set(email, { ...accts.get(email), ...v }); writeFileSync(ACCT, seal(JSON.stringify(Object.fromEntries(accts))), { mode: 0o600 }); notify(email); };
const newest = (email) => load().filter((i) => i.email === email).sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? ""))[0];
const flyOf = (email) => accts.get(email)?.assertion ?? (newest(email) && open(newest(email).assertion));
const claudeOf = (email) => accts.get(email)?.claude ?? newest(email)?.connection;
const LOGIN = "ak-claude-signin"; // a short-lived Sprite the Claude sign-in runs on, deleted after

// The start flow: Fly (once), Claude (once), then the site if one was picked; with none it ends at "ready".
async function runFly(flow) {
  try {
    const known = flyOf(flow.email);
    let creds = known ? await mint(known).catch(() => null) : null;
    const reg = creds ? null : await register(flow.email);
    if (reg) step(flow, "fly", { userCode: reg.claim.user_code, verifyUrl: reg.claim.verification_uri_complete ?? reg.claim.verification_uri });
    const until = Date.now() + (reg?.claim.expires_in ?? 600) * 1000;
    while (!creds) {
      if (Date.now() > until) throw new Error("The Fly code expired. Start again.");
      await new Promise((r) => setTimeout(r, Math.max(5, reg.claim.interval ?? 5) * 1000));
      creds = await pollClaim(reg.claim_token);
    }
    flow.assertion = creds.identity_assertion ?? known;
    if (flow.assertion !== accts.get(flow.email)?.assertion) setAcct(flow.email, { assertion: flow.assertion });
    const api = sprites(creds), conn = claudeOf(flow.email);
    if (conn && (await api.connections()).some((c) => c.id === conn)) {
      if (conn !== accts.get(flow.email)?.claude) setAcct(flow.email, { claude: conn });
      return await runSite(flow);
    }
    step(flow, "claude", { detail: "starting Claude sign-in" });
    if (!(await api.get(LOGIN).catch((e) => (e.status === 404 ? null : Promise.reject(e))))) await api.create(LOGIN);
    flow.loginUrl = await claudeLoginStart(api, LOGIN);
    step(flow, "claude"); // the code the user pastes continues in runClaude
  } catch (e) {
    step(flow, "error", { error: e.message });
  }
}

// Reconnect Claude (same or another account): a fresh sign-in on the LOGIN Sprite, a new connector, every site's
// ANTHROPIC_BASE_URL pointed at it (one restart each), then the old connector removed. Runs in the
// background (it outlasts the proxy's timeout); the dashboard polls GET /cloud/claude/switch.
const switches = new Map(); // email → { step: "starting" | "code" | "switching" | "done" | "error", url, error, failed }
async function claudeSwitch(email, code) {
  const st = switches.get(email);
  try {
    const creds = await mint(flyOf(email)), api = sprites(creds);
    if (!code) {
      if (!(await api.get(LOGIN).catch((e) => (e.status === 404 ? null : Promise.reject(e))))) await api.create(LOGIN);
      return Object.assign(st, { step: "code", url: await claudeLoginStart(api, LOGIN) });
    }
    const conn = await claudeLoginFinish(api, LOGIN, code, creds);
    await api.setPolicy(conn, "ak-");
    api.remove(LOGIN).catch((e) => console.error("remove", LOGIN, e.message));
    const old = claudeOf(email), failed = [];
    for (const i of load().filter((i) => i.email === email)) {
      try {
        const sapi = sprites(await mint(open(i.assertion)));
        if (!(await sapi.connections()).some((c) => c.id === conn)) throw new Error("on another Fly account");
        const line = `ANTHROPIC_BASE_URL=${shq(`https://api.sprites.dev/v1/gateway/custom_api/${conn}`)}\n`;
        await sapi.exec(i.id, [
          `grep -v '^ANTHROPIC_BASE_URL=' ~/ak.env > ~/ak.env.new`,
          `printf %s ${shq(Buffer.from(line).toString("base64"))} | base64 -d >> ~/ak.env.new`,
          `chmod 600 ~/ak.env.new && mv ~/ak.env.new ~/ak.env`,
          `sprite-env services restart ak`,
        ].join(" && "), { timeoutMs: 120e3 });
        upsert({ ...(load().find((x) => x.id === i.id) ?? i), connection: conn });
      } catch (e) {
        console.error("claude switch", i.id, e.message);
        failed.push(i.id);
      }
    }
    setAcct(email, { claude: conn });
    if (old && old !== conn && !failed.length) await api.removeConnection(old).catch((e) => (e.status === 404 ? null : console.error("remove connector", e.message)));
    Object.assign(st, { step: "done", failed });
  } catch (e) {
    Object.assign(st, { step: "error", error: e.message });
  }
}

async function runClaude(flow, code) {
  try {
    step(flow, "connector", { detail: "signing in to Claude" });
    const creds = await mint(flow.assertion), api = sprites(creds);
    const connection = await claudeLoginFinish(api, LOGIN, code, creds);
    await api.setPolicy(connection, "ak-"); // every one of the user's Sprites
    setAcct(flow.email, { claude: connection });
    flow.loginUrl = null;
    api.remove(LOGIN).catch((e) => console.error("remove", LOGIN, e.message));
    await runSite(flow);
  } catch (e) {
    // Claude's login is single-use: drop the old link (the page waits) and start a fresh one.
    if (flow.step === "connector") flow.loginUrl = null;
    step(flow, flow.step === "connector" ? "claude" : "error", { error: e.message });
    if (flow.step === "claude") {
      mint(flow.assertion).then((c) => claudeLoginStart(sprites(c), LOGIN)).then((u) => (flow.loginUrl = u), (e2) => step(flow, "error", { error: e2.message }));
    }
  }
}

async function runSite(flow) {
  if (!flow.sprite) return step(flow, "ready");
  step(flow, "install");
  const user = ghUser(flow.login);
  if (!user) throw new Error("Your GitHub sign-in expired. Sign in again.");
  const r = await provision(
    { assertion: flow.assertion, email: flow.email, repo: flow.repo, domain: flow.domain, name: flow.name, ref: REF, githubToken: user.token, supabase, connector: claudeOf(flow.email) },
    (d) => (flow.detail = d),
  );
  // A brought site gets the tag committed to its index.html; if there isn't one, the page shows it to paste.
  const { path: tagPath, previous } = r.starter ? { path: null, previous: null } : await addTag(user.token, r.repo, r.tag).catch(() => ({ path: null, previous: null }));
  upsert({ id: r.sprite, tagPath, previous, email: flow.email, login: flow.login, siteId: r.siteId, repo: r.repo, domain: r.domain, url: r.url, connection: r.connection, starter: r.starter, tag: r.tag, feedback: r.feedback, via: flow.via, ref: REF, createdAt: new Date().toISOString(), assertion: seal(flow.assertion) });
  flow.assertion = null;
  // Every site is hosted on Cloudflare Pages (connected before the flow starts).
  flow.detail = "hosting your site on Cloudflare Pages";
  await setupPages(r.sprite, user.token, cfs.get(flow.email));
  const pages = load().find((i) => i.id === r.sprite)?.pages ?? {};
  step(flow, "done", { result: { url: pages.live ?? r.url, pagesError: pages.state === "error" ? pages.error : null, tag: r.tag, starter: r.starter, repo: r.repo, tagPath, previous } });
}

const flowView = (f) => f && { step: f.step, detail: f.detail, error: f.error, userCode: f.userCode, verifyUrl: f.verifyUrl, loginUrl: f.loginUrl, result: f.result, sprite: f.sprite };

// ---- Cloudflare Pages (spec #13): project, repo secret + variables, the workflow, then the Sprite's config ----
const WORKFLOW_PATH = ".github/workflows/agent-keyboard-pages.yml";
async function setupPages(id, ghToken, c) {
  const set = (pages) => { const i = load().find((x) => x.id === id); if (i) upsert({ ...i, pages: { ...i.pages, ...pages } }); };
  try {
    const inst = load().find((x) => x.id === id);
    const token = open(c.token);
    set({ state: "setting up", detail: "creating the Pages project", error: null });
    const gr = await getRepo(ghToken, inst.repo), live = gr.default_branch || "main";
    const p = await ensureProject(token, c.accountId, inst.siteId, live, { id: gr.id, owner: gr.owner?.login, name: gr.name });
    set({ detail: p.git ? `using your Pages project ${p.name}` : "adding the deploy workflow to your repo", project: p.name, sub: p.subdomain, git: !!p.git });
    // A project already Git-connected to the repo deploys every push itself: a workflow too would deploy twice.
    if (!p.git) {
      await putSecret(ghToken, inst.repo, "CLOUDFLARE_API_TOKEN", token);
      await putVariable(ghToken, inst.repo, "CLOUDFLARE_ACCOUNT_ID", c.accountId);
      await putVariable(ghToken, inst.repo, "CLOUDFLARE_PAGES_PROJECT", p.name);
      await writeFile(ghToken, inst.repo, live, WORKFLOW_PATH, WORKFLOW, "Deploy to Cloudflare Pages (Agent Keyboard)");
    }
    set({ detail: "turning on sandboxes" });
    // The Sprite: sandbox previews on Pages, the Pages origins allowed to call the bar, and the agent's memory.
    const api = sprites(await mint(open(inst.assertion)));
    const { out } = await api.exec(id, `. ~/ak.env; printf '%s\\n%s' "$SITES" "$EXTRA_ORIGINS"`, { timeoutMs: 60e3 });
    const [sitesJson, had = ""] = out.trim().split("\n");
    const sites = JSON.parse(sitesJson);
    sites[0].branch = live; // the bar commits to the live branch (older sites were staged on ak-staging)
    sites[0].sandbox = { preview: `https://{branch}.${p.subdomain}` };
    const extra = [...new Set([...had.split(",").filter(Boolean), `https://${p.subdomain}`])].join(",");
    const lines = `SITES=${shq(JSON.stringify(sites))}\nEXTRA_ORIGINS=${shq(extra)}\nCLOUDFLARE_API_TOKEN=${shq(token)}\nCLOUDFLARE_ACCOUNT_ID=${shq(c.accountId)}\n`;
    const memory = pagesMemory({ sub: p.subdomain, live, domain: inst.customDomain?.host, git: p.git });
    await api.exec(id, [
      `grep -v -e '^SITES=' -e '^EXTRA_ORIGINS=' -e '^CLOUDFLARE_API_TOKEN=' -e '^CLOUDFLARE_ACCOUNT_ID=' ~/ak.env > ~/ak.env.new`,
      `printf %s ${shq(Buffer.from(lines).toString("base64"))} | base64 -d >> ~/ak.env.new`,
      `chmod 600 ~/ak.env.new && mv ~/ak.env.new ~/ak.env`,
      `mkdir -p ~/.claude && touch ~/.claude/CLAUDE.md && { grep '^<!-- ak-' ~/.claude/CLAUDE.md || true; } > ~/.ak-keep && printf %s ${shq(Buffer.from(memory).toString("base64"))} | base64 -d > ~/.claude/CLAUDE.md && sed 's/^/\\n/' ~/.ak-keep >> ~/.claude/CLAUDE.md`,
      `sprite-env services restart ak`,
    ].join(" && "), { timeoutMs: 120e3 });
    set({ state: "live", detail: "", branch: live, live: `https://${p.subdomain}` });
  } catch (e) {
    console.error("pages", id, e.message);
    const perms = /Resource not accessible by integration/.test(e.message);
    const permsUrl = perms ? await installationPage(ghToken, load().find((x) => x.id === id)?.repo.split("/")[0] ?? "").catch(() => null) : null;
    set({ state: "error", detail: "", permsUrl, error: perms ? "Agent Keyboard needs new GitHub permissions (secrets, variables, workflows). Accept them on GitHub, then try again." : e.message });
  }
}
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

// ---- custom domain (spec #13 M4): attach to Pages, point DNS when the zone is on Cloudflare, else show what to add ----
const HOST = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
async function checkDomain(id, c) {
  const inst = load().find((x) => x.id === id);
  const d = inst?.customDomain;
  if (!d) return;
  const token = open(c.token), { project, sub } = inst.pages;
  const next = { ...d, checkedAt: Date.now(), error: null };
  try {
    const z = await findZone(token, c.accountId, d.host);
    next.zone = z && { status: z.status, ns: z.name_servers ?? [] };
    if (z && !d.dns) { await pointDns(token, z.id, d.host, sub); next.dns = true; }
    if (!z) [next.apex, next.now] = await Promise.all([isApex(d.host), cnameOf(d.host)]);
    const pd = await pagesDomain(token, c.accountId, project, d.host);
    next.status = pd.status === "active" ? "active" : "pending";
  } catch (e) {
    console.error("domain", id, e.message);
    next.error = e.message;
  }
  const cur = load().find((x) => x.id === id);
  if (cur?.customDomain?.host !== d.host) return;
  upsert({ ...cur, customDomain: next });
  // Email was on before the domain changed: set it up again on the new one.
  if (next.status === "active" && d.status !== "active" && cur.mailWanted && !cur.mail && resendKey(cur.email)) {
    upsert({ ...load().find((x) => x.id === id), mailWanted: false, mail: { status: "setting up", detail: "starting" } });
    setupEmail(id);
  }
}
/** After a custom domain change: let the bar on `origin` call the Sprite (CORS, EXTRA_ORIGINS), and
 *  rewrite the agent's memory so it knows the site's address and has the Cloudflare token. */
async function syncDomain(id, c, origin) {
  const inst = load().find((x) => x.id === id);
  const api = sprites(await mint(open(inst.assertion)));
  const { out } = await api.exec(id, `. ~/ak.env; printf '%s' "$EXTRA_ORIGINS"`, { timeoutMs: 60e3 });
  const had = out.trim().split(",").filter(Boolean);
  const lines = `EXTRA_ORIGINS=${shq([...new Set([...had, ...(origin ? [origin] : [])])].join(","))}\nCLOUDFLARE_API_TOKEN=${shq(open(c.token))}\nCLOUDFLARE_ACCOUNT_ID=${shq(c.accountId)}\n`;
  const memory = pagesMemory({ sub: inst.pages.sub, live: inst.pages.branch ?? "main", domain: inst.customDomain?.host, git: inst.pages.git });
  await api.exec(id, [
    `grep -v -e '^EXTRA_ORIGINS=' -e '^CLOUDFLARE_API_TOKEN=' -e '^CLOUDFLARE_ACCOUNT_ID=' ~/ak.env > ~/ak.env.new`,
    `printf %s ${shq(Buffer.from(lines).toString("base64"))} | base64 -d >> ~/ak.env.new`,
    `chmod 600 ~/ak.env.new && mv ~/ak.env.new ~/ak.env`,
    `mkdir -p ~/.claude && touch ~/.claude/CLAUDE.md && { grep '^<!-- ak-' ~/.claude/CLAUDE.md || true; } > ~/.ak-keep && printf %s ${shq(Buffer.from(memory).toString("base64"))} | base64 -d > ~/.claude/CLAUDE.md && sed 's/^/\\n/' ~/.ak-keep >> ~/.claude/CLAUDE.md`,
    `sprite-env services restart ak`,
  ].join(" && "), { timeoutMs: 120e3 });
}

// ---- dashboard actions ----
const INSTALL = `curl -fsSL https://raw.githubusercontent.com/vibhasjain/agent-keyboard/${REF}/server/sprite-install.sh -o ~/sprite-install.sh && AK_REF=${REF} bash ~/sprite-install.sh`;
// The version a Sprite runs = the last commits touching server/ and widget/ at REF (site/ changes don't count).
let latestCache = { at: 0, v: null };
async function latest() {
  if (Date.now() - latestCache.at < 600e3) return latestCache.v;
  const shas = await Promise.all(["server", "widget"].map(async (path) => {
    const r = await fetch(`https://api.github.com/repos/vibhasjain/agent-keyboard/commits?sha=${REF}&path=${path}&per_page=1`, { headers: { "User-Agent": "agent-keyboard-cloud" } });
    if (!r.ok) throw new Error(`github ${r.status}`);
    return (await r.json())[0].sha.slice(0, 7);
  }));
  latestCache = { at: Date.now(), v: shas.join("+") };
  return latestCache.v;
}
// Spec 23: each Sprite holds AK_FEEDBACK_KEY so its agent can send us bug reports; we keep only the hash.
// A Sprite without one gets it on its next (re)install: `cmd` writes it into ~/ak.env before INSTALL restarts the bar.
const sha = (k) => createHash("sha256").update(k).digest("hex");
function feedbackKey(inst) {
  if (inst.feedback) return { cmd: "", hash: inst.feedback };
  const k = randomBytes(24).toString("hex");
  return { cmd: `{ grep -v '^AK_FEEDBACK_KEY=' ~/ak.env || true; } > ~/ak.env.new && echo AK_FEEDBACK_KEY=${k} >> ~/ak.env.new && chmod 600 ~/ak.env.new && mv ~/ak.env.new ~/ak.env && `, hash: sha(k) };
}
const feedbackCounts = new Map(); // instance → { day, n }
async function feedback(req, res) {
  const inst = load().find((i) => i.feedback && i.feedback === sha(String(req.headers["x-ak-feedback"] ?? "")));
  if (!inst) return send(res, 401, { error: "unknown instance" });
  let raw = "";
  for await (const c of req) if ((raw += c).length > 25e3) return send(res, 413, { error: "too large" });
  let f;
  try { f = JSON.parse(raw); } catch { return send(res, 400, { error: "JSON body required" }); }
  const str = (v, n) => (typeof v === "string" ? v : "").slice(0, n);
  if (!str(f.title, 1).trim() || !str(f.body, 1).trim()) return send(res, 400, { error: "title and body required" });
  const day = new Date().toISOString().slice(0, 10), c = feedbackCounts.get(inst.id);
  const n = c?.day === day ? c.n + 1 : 1;
  if (n > 20) return send(res, 429, { error: "20 reports a day per site; try again tomorrow" });
  feedbackCounts.set(inst.id, { day, n });
  const report = { id: `fb_${randomBytes(6).toString("hex")}`, instance: inst.id, site: str(f.site, 100) || inst.siteId, owner: inst.email, at: new Date().toISOString(), title: str(f.title, 120), body: str(f.body, 20e3), page: str(f.page, 300), sender: str(f.sender, 200) };
  appendFileSync(`${DATA}/feedback.jsonl`, JSON.stringify(report) + "\n", { mode: 0o600 });
  const r = await fetch(env.FEEDBACK_INBOX_URL ?? "https://agent-keyboard.fly.dev/sites/halo/feedback-inbox", {
    method: "POST", headers: { "Content-Type": "application/json", "x-ak-feedback": env.FEEDBACK_INBOX_SECRET ?? "" }, body: JSON.stringify(report), signal: AbortSignal.timeout(20e3),
  }).catch((e) => ({ ok: false, status: e.message }));
  if (!r.ok) console.error("feedback inbox", report.id, r.status); // kept in feedback.jsonl either way
  send(res, 200, { ok: true, id: report.id });
}
// Auto-update (on unless the owner turned it off): hourly, each Sprite behind the latest version reinstalls,
// skipping any that is running a job (a Claude CLI turn) so nothing is cut off; it tries again in 5 minutes.
async function autoUpdate() {
  const version = await latest();
  let busy = false;
  for (const inst of load().filter((i) => i.autoUpdate !== false && i.version !== version)) {
    try {
      const fk = feedbackKey(inst);
      const { out } = await sprites(await mint(open(inst.assertion))).exec(inst.id, `if cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' ' | grep -q 'output-forma[t] stream-json'; then echo AK_BUSY; else ${fk.cmd}${INSTALL}; fi`);
      if (out.includes("AK_BUSY")) { busy = true; console.log("autoupdate", inst.id, "busy, retrying in 5 min"); continue; }
      const cur = load().find((i) => i.id === inst.id);
      if (cur) upsert({ ...cur, ref: REF, version, feedback: fk.hash });
      console.log("autoupdate", inst.id, version);
    } catch (e) { console.error("autoupdate", inst.id, e.message); }
  }
  if (busy) setTimeout(tick, 300e3).unref(); // a busy Sprite gets another try soon, not at the next hourly pass
}
let updating = null; // one pass at a time (the hourly timer and a release ping can coincide)
const tick = () => (updating ??= autoUpdate().catch((e) => console.error("autoupdate", e.message)).finally(() => { updating = null; }));
setTimeout(tick, 60e3).unref(); // also right after a deploy, so frequent deploys never starve it
setInterval(tick, 3600e3).unref();

async function act(inst, action) {
  const creds = await mint(open(inst.assertion));
  const api = sprites(creds);
  if (action === "restart") await api.exec(inst.id, "sprite-env services restart ak", { timeoutMs: 60e3 });
  else if (action === "update") {
    const version = await latest().catch(() => null), fk = feedbackKey(inst);
    await api.exec(inst.id, fk.cmd + INSTALL);
    upsert({ ...(load().find((i) => i.id === inst.id) ?? inst), ref: REF, version, feedback: fk.hash });
  } else if (action === "delete") {
    await api.remove(inst.id).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
    // The Claude connector is shared by the user's sites: it stays while the account or another site uses it.
    const shared = (c) => c === inst.connection && (c === accts.get(inst.email)?.claude || load().some((o) => o.id !== inst.id && o.connection === c));
    for (const c of [inst.connection, inst.mcp?.connection].filter((c) => c && !shared(c))) await api.removeConnection(c).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
    mcpServer.revoke(inst.id);
    save(load().filter((i) => i.id !== inst.id));
  }
}

// The page the bar lives on: the custom domain or Pages, the Sprite, or the owner's own host.
function siteUrl(inst) {
  const pg = inst.pages?.state === "live" && inst.pages;
  return pg ? (inst.customDomain?.status === "active" ? `https://${inst.customDomain.host}` : pg.live) : inst.starter ? inst.url : `https://${inst.domain}`;
}
/** The site, already signed in to the bar as `email`: a single-use magic-link token the widget redeems from #ak_handoff=. */
async function handoff(inst, email) {
  const site = siteUrl(inst);
  const r = await fetch(`${supabase.url}/auth/v1/admin/generate_link`, {
    method: "POST",
    headers: { apikey: supabase.serviceKey, Authorization: `Bearer ${supabase.serviceKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ type: "magiclink", email }),
  }).catch(() => null);
  const d = (await r?.json().catch(() => null)) ?? {};
  const token = d.hashed_token ?? d.properties?.hashed_token;
  return token ? `${site}/#ak_handoff=${encodeURIComponent(token)}` : site;
}
// ---- spec 19: bring an older bar's notes, memory, settings and skills over ----
// The Sprite's own server pulls the bundle from the old instance (POST /sites/:id/import, internal secret, loopback).
async function runImport(inst, auth) {
  const cur = () => load().find((x) => x.id === inst.id) ?? inst;
  if (cur().migrate?.state === "running") return { error: "Already bringing them over" };
  upsert({ ...cur(), migrate: { state: "running" } });
  try {
    const api = sprites(await mint(open(inst.assertion)));
    const payload = Buffer.from(JSON.stringify({ origin: inst.previous.origin, site: inst.previous.siteId, ...auth })).toString("base64");
    const { out } = await api.exec(inst.id, `. ~/ak.env; printf %s ${shq(payload)} | base64 -d | curl -sS -X POST "http://127.0.0.1:$PORT/sites/${inst.siteId}/import" -H "x-ak-internal: $AK_INTERNAL_SECRET" -H 'Content-Type: application/json' --data-binary @- -w '\n%{http_code}'`, { timeoutMs: 600e3 });
    const lines = out.trim().split("\n"), code = Number(lines.pop());
    const r = JSON.parse(lines.join("\n") || "{}");
    if (code !== 200) throw new Error(r.error ?? `import answered ${code}`);
    r.applied = await applyMoved(api, inst.id, r).catch((e) => (console.error("import apply", inst.id, e.message), null));
    const report = importReport(r, inst.previous.origin);
    upsert({ ...cur(), migrate: { state: "done", result: r, report, at: new Date().toISOString() } });
    return { ...r, report };
  } catch (e) {
    console.error("import", inst.id, e.message);
    upsert({ ...cur(), migrate: { state: "error", error: e.message } });
    return { error: e.message };
  }
}
/** The old site's origins (CORS) and sandbox preview pattern, onto the Sprite: origins are added, a preview
 *  only when it has none yet (Connect Cloudflare sets its own later). Returns what it applied. */
async function applyMoved(api, id, r) {
  const origins = (r.origins ?? []).filter((o) => /^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(o));
  if (!origins.length && !r.sandboxPreview) return null;
  const { out } = await api.exec(id, `. ~/ak.env; printf '%s\\n%s' "$SITES" "$EXTRA_ORIGINS"`, { timeoutMs: 60e3 });
  const [sitesJson, had = ""] = out.trim().split("\n");
  const sites = JSON.parse(sitesJson), was = had.split(",").filter(Boolean);
  const preview = !sites[0].sandbox && r.sandboxPreview ? r.sandboxPreview : null;
  if (preview) sites[0].sandbox = { preview };
  const added = origins.filter((o) => !was.includes(o));
  if (!added.length && !preview) return null;
  const lines = `SITES=${shq(JSON.stringify(sites))}\nEXTRA_ORIGINS=${shq([...was, ...added].join(","))}\n`;
  await api.exec(id, [
    `grep -v -e '^SITES=' -e '^EXTRA_ORIGINS=' ~/ak.env > ~/ak.env.new`,
    `printf %s ${shq(Buffer.from(lines).toString("base64"))} | base64 -d >> ~/ak.env.new`,
    `chmod 600 ~/ak.env.new && mv ~/ak.env.new ~/ak.env`,
    `sprite-env services restart ak`,
  ].join(" && "), { timeoutMs: 120e3 });
  return { origins: added, preview };
}
/** What came over, in a sentence (the popup, the dashboard and the MCP say the same). */
function importReport(r, origin) {
  const host = new URL(origin).host;
  if (r.error) return r.error;
  const what = r.notesOnly ? `${r.notes} notes (memory and settings need ${host} updated first)` : `${r.notes} notes, ${r.memories} memories, settings${r.env?.length ? `, keys (${r.env.join(", ")})` : ""}${r.files ? `, ${r.files} working files` : ""}${r.skills?.length ? `, ${r.skills.length} skills` : ""}${r.sandboxes?.length ? ` and ${r.sandboxes.length} open sandboxes` : ""}`;
  const a = r.applied;
  return `Brought over ${what} from ${host}.` +
    (a?.origins?.length ? ` The bar now also works on ${a.origins.map((o) => o.replace(/^https:\/\//, "")).join(", ")}.` : "") +
    (a?.preview ? ` Sandboxes preview at ${a.preview}.` : "") +
    (r.envNames?.length ? ` Paste these values again by asking the bar: ${r.envNames.join(", ")}.` : "");
}
const page = (title, inner) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title><link rel="stylesheet" href="/cloud/cloud.css"></head><body><div class="wrap"><main class="card">${inner}</main></div></body></html>`;
const escH = (v) => String(v).replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
const importDone = (r) => page("Agent Keyboard", `<p${r.error ? ' class="err"' : ""}>${escH(r.error ?? r.report)}</p><p class="small">You can close this window. The dashboard shows what came over.</p><script>setTimeout(() => window.opener && window.close(), 4000)</script>`);
function oldSignIn(inst, sb, anon) {
  const host = new URL(inst.previous.origin).host, js = (v) => JSON.stringify(v).replace(/</g, "\\u003c");
  return page("Bring your notes over", `<h2>Sign in to ${escH(host)}</h2>
<p class="small">That Agent Keyboard is older and can only send its notes. Sign in with the email and password you use on its bar. Your password goes to it, not to us.</p>
<form id="f"><label for="em">Email</label><input id="em" type="email" autocomplete="username" required><label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" required><div class="row"><button class="btn">Bring the notes over</button></div></form><p id="msg" role="alert"></p>
<script>
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const b = e.target.querySelector("button"), msg = (t, err) => { const m = document.getElementById("msg"); m.textContent = t; m.className = err ? "err" : ""; };
  b.disabled = true; msg("Signing in…");
  try {
    const s = await fetch(${js(sb)} + "/auth/v1/token?grant_type=password", { method: "POST", headers: { apikey: ${js(anon)}, "Content-Type": "application/json" }, body: JSON.stringify({ email: document.getElementById("em").value.trim(), password: document.getElementById("pw").value }) }).then((r) => r.json());
    if (!s.access_token) throw new Error(s.error_description || s.msg || "Wrong email or password.");
    msg("Bringing the notes over…");
    const r = await fetch("/cloud/instances/${inst.id}/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ bearer: s.access_token }) }).then((r) => r.json());
    if (r.error) throw new Error(r.error);
    msg(r.report + " You can close this window."); setTimeout(() => window.opener && window.close(), 3000);
  } catch (err) { msg(err.message, true); b.disabled = false; }
};
</script>`);
}

// Spec #16: "Allow this agent to talk with your other sites' agents". A grant in a Custom API connector for BASE (this Sprite only):
// the Sprite's egress adds it, so the token never reaches the Sprite. ~/ak-mcp.json points Claude Code at the
// gateway; the Sprite server passes it only to owners' turns. A marked line in ~/.claude/CLAUDE.md says what it's for.
const MCP_NOTE = "<!-- ak-mcp -->";
async function siteMcp(inst, talk, manage) {
  const on = talk || manage;
  const api = sprites(await mint(open(inst.assertion)));
  if (inst.mcp?.connection) await api.removeConnection(inst.mcp.connection).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
  mcpServer.revoke(inst.id);
  let mcp = null;
  if (on) {
    const conn = await api.createConnection({ name: `ak-mcp-${inst.id}`, base_api_url: BASE, access_token: mcpServer.grant(inst, talk, manage), auth_method: "header", auth_header_prefix: "Bearer" });
    await api.setPolicy(conn.id, inst.id);
    mcp = { connection: conn.id, talk: !!talk, manage: !!manage };
  }
  upsert({ ...(load().find((i) => i.id === inst.id) ?? inst), mcp });
  const cfg = JSON.stringify({ mcpServers: { "agent-keyboard": { type: "http", url: `https://api.sprites.dev/v1/gateway/custom_api/${mcp?.connection}/mcp` } } });
  const note = `${MCP_NOTE} You have the agent-keyboard MCP tools when the site's owner sends a message (not for teammates): use them ${[talk && "to read the owner's other Agent Keyboard sites' conversations and to ask those sites' agents for changes (send_message)", manage && "to manage the owner's sites, this one included (restart, update, delete, domains, teammates; confirm destructive steps first)"].filter(Boolean).join(", and ")}. Use only these injected tools: never add another MCP server, run an OAuth flow, or send anyone an Agent Keyboard sign-in link.`;
  await api.exec(inst.id, [
    `mkdir -p ~/.claude && touch ~/.claude/CLAUDE.md && sed -i '/${MCP_NOTE}/d' ~/.claude/CLAUDE.md`,
    on ? `printf '%s\n' ${shq(cfg)} > ~/ak-mcp.json && printf '\n%s\n' ${shq(note)} >> ~/.claude/CLAUDE.md` : "rm -f ~/ak-mcp.json",
  ].join(" && "), { timeoutMs: 60e3 });
}
// ---- email from the site's own domain (spec #17) ----
// With the user's Resend key (connected once, like Cloudflare): the domain in Resend (the Cloudflare zone's root, e.g.
// example.com), its DNS records in that zone, and a sending-only key for that one domain, which goes on the Sprite.
const EMAIL_NOTE = "<!-- ak-email -->";
const setMail = (id, patch) => { const cur = load().find((x) => x.id === id); if (cur?.mail) upsert({ ...cur, mail: { ...cur.mail, ...patch } }); };
async function setupEmail(id) {
  try {
    const inst = load().find((x) => x.id === id), c = cfs.get(inst.email), token = c && open(c.token), key = resendKey(inst.email);
    if (!c) throw new Error("Connect Cloudflare first");
    if (!key) throw new Error("Connect Resend first");
    const zone = await findZone(token, c.accountId, inst.customDomain.host);
    const domain = zone?.name ?? inst.customDomain.host.replace(/^www\./, "");
    setMail(id, { domain, detail: "adding the domain to Resend" });
    const d = await ensureDomain(key, domain);
    // In Cloudflare we write full names; elsewhere the user gets Resend's own (relative) names, as on resend.com.
    const records = (d.records ?? []).map((r) => ({ type: r.type, name: zone ? fqdn(r.name, domain) : r.name, content: r.value, ...(r.priority != null ? { priority: r.priority } : {}) }));
    if (zone) { setMail(id, { detail: "adding its DNS records to Cloudflare" }); await addRecords(token, zone.id, records); }
    setMail(id, { domainId: d.id, from: `notify@${domain}`, records: zone ? null : records, since: Date.now() });
    if (d.status === "verified") return await installEmail(id);
    await verifyDomain(key, d.id).catch(() => {});
    setMail(id, { status: "verifying", detail: "" });
    watchEmail(id);
  } catch (e) {
    console.error("email", id, e.message);
    setMail(id, { status: "error", detail: "", error: e.message });
  }
}
/** Once the domain is verified: a sending key on the Sprite. Not before, so the bar never offers email that Resend would refuse. */
async function installEmail(id) {
  const inst = load().find((x) => x.id === id), key = resendKey(inst.email);
  if (inst.mail.keyId) await deleteKey(key, inst.mail.keyId).catch(() => {});
  const k = await sendingKey(key, inst.mail.domainId, `Agent Keyboard (${inst.siteId})`);
  setMail(id, { keyId: k.id, detail: "installing it on your Sprite" });
  await emailOnSprite(inst, { token: k.token, domain: inst.mail.domain });
  setMail(id, { status: "active", detail: "", records: null });
}
/** Poll Resend until the domain verifies (every 30 s, asking it to re-check every 5 min); Resend gives up after 72 h. Resumes at boot. */
async function watchEmail(id) {
  for (let t = 1; ; t++) {
    await new Promise((r) => setTimeout(r, 30e3));
    const i = load().find((x) => x.id === id), key = i && resendKey(i.email);
    if (i?.mail?.status !== "verifying" || !key) return;
    const now = (await getDomain(key, i.mail.domainId).catch(() => null))?.status;
    if (now === "verified") return installEmail(id).catch((e) => setMail(id, { status: "error", detail: "", error: e.message }));
    if (now === "failed" || Date.now() - (i.mail.since ?? 0) > 72 * 3600e3) return setMail(id, { status: "error", error: `Resend couldn't verify ${i.mail.domain}. Check its DNS records, then set up email again.` });
    if (t % 10 === 0) await verifyDomain(key, i.mail.domainId).catch(() => {});
  }
}
for (const i of load()) {
  if (i.mail?.status === "verifying") watchEmail(i.id);
  else if (i.mail?.status === "setting up") upsert({ ...i, mail: { ...i.mail, status: "error", detail: "", error: "Setup was interrupted. Try again." } });
}
/** Put the sending key on the Sprite (or take it off: e = null), with a line in the agent's memory, and restart the bar. */
async function emailOnSprite(inst, e) {
  const lines = e ? `RESEND_API_KEY=${shq(e.token)}\nEMAIL_FROM=${shq(`Agent Keyboard <notify@${e.domain}>`)}\n` : "";
  const note = e && `${EMAIL_NOTE} RESEND_API_KEY (in the environment) sends email for this site through Resend's API, only from addresses at ${e.domain} (EMAIL_FROM is the default sender). It can't send from other domains or manage the Resend account.`;
  await sprites(await mint(open(inst.assertion))).exec(inst.id, [
    `{ grep -v -e '^RESEND_API_KEY=' -e '^EMAIL_FROM=' ~/ak.env || true; } > ~/ak.env.new`,
    `printf %s ${shq(Buffer.from(lines).toString("base64"))} | base64 -d >> ~/ak.env.new`,
    `chmod 600 ~/ak.env.new && mv ~/ak.env.new ~/ak.env`,
    `mkdir -p ~/.claude && touch ~/.claude/CLAUDE.md && sed -i '/${EMAIL_NOTE}/d' ~/.claude/CLAUDE.md`,
    ...(note ? [`printf '\n%s\n' ${shq(note)} >> ~/.claude/CLAUDE.md`] : []),
    `sprite-env services restart ak`,
  ].join(" && "), { timeoutMs: 120e3 });
}
/** Stop sending email: the key comes off the Sprite and is deleted on Resend. `wanted`: set it up again on the next domain. */
async function removeEmail(inst, wanted = false) {
  await emailOnSprite(inst, null);
  const key = resendKey(inst.email);
  if (key && inst.mail?.keyId) await deleteKey(key, inst.mail.keyId).catch(() => {});
  upsert({ ...(load().find((x) => x.id === inst.id) ?? inst), mail: null, mailWanted: wanted });
}
/** Add or remove a teammate on the Sprite's bar allow-list (the server rereads it within 10 s). */
async function teamOnSprite(inst, email, add) {
  const js = `const fs=require("fs"),p=(process.env.AGENT_DATA_DIR||"/data")+"/agent-keyboard/allowed-emails.json",e=${JSON.stringify(email)};let l=[];try{l=JSON.parse(fs.readFileSync(p,"utf8"))}catch{}if(!Array.isArray(l))l=[];l=l.filter(x=>(typeof x==="string"?x:x&&x.email||"").toLowerCase()!==e);${add ? "l.push(e);" : ""}fs.mkdirSync(require("path").dirname(p),{recursive:true});fs.writeFileSync(p+".tmp",JSON.stringify(l,null,2));fs.renameSync(p+".tmp",p)`;
  await sprites(await mint(open(inst.assertion))).exec(inst.id, `set -a; . ~/ak.env; set +a; node -e ${shq(js)}`, { timeoutMs: 60e3 });
}
/** A bar sign-in account for a teammate, confirmed, no email sent (their join link signs them in). */
async function barAccount(email) {
  const r = await fetch(`${supabase.url}/auth/v1/admin/users`, {
    method: "POST",
    headers: { apikey: supabase.serviceKey, Authorization: `Bearer ${supabase.serviceKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email, email_confirm: true }),
  });
  if (!r.ok && r.status !== 422) throw new Error(`supabase: ${r.status} ${(await r.text()).slice(0, 200)}`);
}

async function status(inst) {
  const c = inst.customDomain?.status === "pending" && Date.now() - (inst.customDomain.checkedAt ?? 0) > 30e3 && cfs.get(inst.email);
  if (c) { await checkDomain(inst.id, c); inst = load().find((x) => x.id === inst.id) ?? inst; }
  try {
    const s = await sprites(await mint(open(inst.assertion))).get(inst.id);
    return { ...pub(inst), status: s.status ?? "unknown" };
  } catch (e) {
    return { ...pub(inst), status: e.status === 401 || e.status === 400 ? "reconnect Fly" : "unknown" };
  }
}

// ---- http ----
function send(res, code, body, type = "application/json") {
  res.writeHead(code, { "Content-Type": type, "Cache-Control": "no-store" });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}
const redirect = (res, to) => (res.writeHead(302, { Location: to }), res.end());
async function body(req) {
  if (!/^application\/json/.test(req.headers["content-type"] ?? "")) throw Object.assign(new Error("JSON only"), { code: 415 });
  let s = "";
  for await (const c of req) if ((s += c).length > 1e4) throw Object.assign(new Error("too large"), { code: 413 });
  return s ? JSON.parse(s) : {};
}

const routes = {
  "GET /": (q, req, res) => redirect(res, "/start"),
  // Sign-in redirects happen here, before the page renders, so there's no flash of the wrong page.
  "GET /start": (q, req, res, s) => {
    if (appReady() && !(s && ghUser(s.login))) return redirect(res, "/signin?next=start");
    send(res, 200, readFileSync(new URL("start.html", PAGES)), "text/html; charset=utf-8");
  },
  "GET /dashboard": (q, req, res, s) => {
    if (!s) return redirect(res, "/signin");
    if (!load().some((i) => i.email === s.email)) return redirect(res, "/start");
    send(res, 200, readFileSync(new URL("dashboard.html", PAGES)), "text/html; charset=utf-8");
  },
  "GET /signin": (q, req, res, s) => {
    if (s && ghUser(s.login)) return redirect(res, q.get("next") === "start" ? "/start" : "/dashboard");
    send(res, 200, readFileSync(new URL("signin.html", PAGES)), "text/html; charset=utf-8");
  },
  "GET /cloud/cloud.css": (q, req, res) => send(res, 200, readFileSync(new URL("cloud.css", PAGES)), "text/css"),
  "GET /cloud/health": (q, req, res) => send(res, 200, { ok: true, app: appReady() }),

  // One-time: create the GitHub App from our manifest (whoever opens this owns the App).
  "GET /cloud/github/setup": (q, req, res) => {
    if (!env.SETUP_KEY || q.get("key") !== env.SETUP_KEY || appReady()) return send(res, 404, { error: "not found" });
    const m = JSON.stringify(manifest(BASE)).replace(/&/g, "&amp;").replace(/"/g, "&quot;");
    const org = q.get("org");
    const action = org ? `https://github.com/organizations/${encodeURIComponent(org)}/settings/apps/new` : "https://github.com/settings/apps/new";
    send(res, 200, `<form method="post" action="${action}"><input type="hidden" name="manifest" value="${m}"><button>Create the Agent Keyboard GitHub App</button></form><script>document.forms[0].submit()</script>`, "text/html");
  },
  "GET /cloud/github/created": async (q, req, res) => {
    if (appReady()) return send(res, 404, { error: "already set up" });
    const a = await createdFromManifest(q.get("code"), DATA);
    send(res, 200, `GitHub App "${a.slug}" created and saved. <a href="/start">Continue</a>`, "text/html");
  },

  "GET /cloud/github/login": (q, req, res) => {
    if (!appReady()) return send(res, 503, { error: "GitHub App not set up yet" });
    const state = randomBytes(16).toString("hex");
    const n = q.get("next") ?? "";
    states.set(state, n === "dashboard" || n.startsWith("/oauth/authorize?") ? n : "start");
    redirect(res, authorizeUrl(state));
  },
  // OAuth callback, and the App's post-install redirect (which also carries a code).
  // Accepting new App permissions also lands here (setup_action=update): back to the dashboard, retrying the
  // Pages setups that failed for lack of them.
  "GET /cloud/github/callback": async (q, req, res, s) => {
    const update = q.get("setup_action") === "update";
    const next = update ? "dashboard" : states.get(q.get("state")) ?? "start";
    states.delete(q.get("state"));
    const retry = (email, token) => {
      const c = cfs.get(email);
      if (c) for (const i of load().filter((i) => i.email === email && i.pages?.permsUrl)) {
        upsert({ ...i, pages: { ...i.pages, state: "setting up", detail: "starting", error: null, permsUrl: null } });
        setupPages(i.id, token, c);
      }
    };
    if (!q.get("code")) {
      const gu = update && s && ghUser(s.login);
      if (gu) retry(s.email, gu.token);
      return redirect(res, `/${next}`);
    }
    const u = await signIn(q.get("code"));
    users.set(u.login, { installations: u.installations, ...keep(u) });
    saveUsers();
    setSession(res, { login: u.login, email: u.email });
    if (update) retry(u.email, u.token);
    if (next === "start" && !u.installations.length) {
      const state = randomBytes(16).toString("hex");
      states.set(state, "start");
      return redirect(res, installUrl(state));
    }
    redirect(res, next.startsWith("/") ? next : `/${next}`);
  },
  "POST /cloud/logout": (q, req, res, s) => {
    if (s && users.delete(s.login)) saveUsers();
    res.setHeader("Set-Cookie", `akc=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
    send(res, 200, { ok: true });
  },

  // Opened straight on the Fly app (Netlify's proxy buffers streams), so it's authorized by the signed URL from
  // /cloud/me rather than the cookie. Signed out or expired: 204, which tells EventSource not to reconnect.
  "GET /cloud/events": (q, req, res) => {
    const [e64 = "", exp = "0", sig = ""] = (q.get("t") ?? "").split(".");
    const email = Buffer.from(e64, "base64url").toString(), want = mac(`events ${email} ${exp}`);
    const s = email && Number(exp) > Date.now() && sig.length === want.length && timingSafeEqual(Buffer.from(sig), Buffer.from(want)) && { email };
    res.setHeader("Access-Control-Allow-Origin", "*"); // the stream only carries a revision number
    if (!s) return (res.writeHead(204), res.end());
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store", "X-Accel-Buffering": "no" });
    res.write(`retry: 3000\ndata: ${revs.get(s.email) ?? BOOT}\n\n`);
    const set = streams.get(s.email) ?? new Set();
    streams.set(s.email, set.add(res));
    const ping = setInterval(() => res.write(": ping\n\n"), 20e3);
    res.on("close", () => { clearInterval(ping); set.delete(res); if (!set.size) streams.delete(s.email); });
  },
  "GET /cloud/me": (q, req, res, s) => {
    if (!s) return send(res, 200, { signedIn: false, app: appReady() });
    const inst = load().find((i) => i.email === s.email);
    send(res, 200, { signedIn: true, login: s.login, email: s.email, github: !!ghUser(s.login), installUrl: appReady() ? installUrl("start") : null, instance: inst && pub(inst), claudeAccount: !!claudeOf(s.email), cloudflare: accountLabel(cfs.get(s.email)?.accountName), resend: resends.get(s.email)?.label ?? null, fly: !!flyOf(s.email), claudeSignIn: !!claudeOf(s.email), cloudflareTokenUrl: TOKEN_URL, claude: mcpServer.claude(s.login), events: eventsUrl(s.email), flow: flowView(flows.get(s.email)) });
  },
  "GET /cloud/repos": async (q, req, res, s) => {
    const u = s && ghUser(s.login);
    if (!u) return send(res, 401, { error: "Sign in with GitHub again" });
    send(res, 200, { repos: await userRepos(u.token, u.installations) });
  },
  "POST /cloud/start": async (q, req, res, s, b) => {
    const u = s && ghUser(s.login);
    if (!u) return send(res, 401, { error: "Sign in with GitHub again" });
    if (!cfs.get(s.email)) return send(res, 400, { error: "Connect Cloudflare first" });
    const f = flows.get(s.email);
    if (f && !["error", "done", "ready"].includes(f.step)) return send(res, 200, flowView(f));
    if (limited(req.headers["x-nf-client-connection-ip"] ?? req.headers["fly-client-ip"] ?? req.socket.remoteAddress)) return send(res, 429, { error: "Too many attempts. Try again in an hour." });
    let repo = null, domain = null, name = null;
    if (b.account === true) {
      const flow = { email: s.email, login: s.login }; // Fly and Claude only; the site is picked after
      step(flow, "fly", { detail: "registering with Fly" });
      flows.set(s.email, flow);
      runFly(flow);
      return send(res, 200, flowView(flow));
    }
    if (b.repo) {
      if (!(await userRepos(u.token, u.installations)).some((r) => r.full_name === b.repo)) return send(res, 400, { error: "Pick a repo you gave Agent Keyboard access to" });
      repo = b.repo;
      domain = String(b.domain ?? "").trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase() || null; // none: staged on the Sprite
      if (domain && !/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/.test(domain)) return send(res, 400, { error: "Enter your site's domain, like example.com, or leave it blank" });
    } else {
      name = slug(String(b.name ?? "my-site"));
    }
    const flow = { email: s.email, login: s.login, repo, domain, name, via: b.via === "mcp" ? "mcp" : undefined, sprite: spriteName(slug(repo ? repo.split("/")[1] : name)) };
    if (flow.sprite === LOGIN || load().some((i) => i.id === flow.sprite)) return send(res, 409, { error: `You already have ${flow.sprite}. Manage it from the dashboard, or pick another repo or name.` });
    step(flow, "fly", { detail: "registering with Fly" });
    flows.set(s.email, flow);
    runFly(flow);
    send(res, 200, flowView(flow));
  },
  "GET /cloud/start": (q, req, res, s) => send(res, 200, (s && flowView(flows.get(s.email))) ?? { step: null }),
  "POST /cloud/start/claude": (q, req, res, s, b) => {
    const f = s && flows.get(s.email);
    if (!f || f.step !== "claude") return send(res, 409, { error: "No Claude sign-in is waiting" });
    if (!/^[\w#.~-]{10,400}$/.test(String(b.code ?? "").trim())) return send(res, 400, { error: "Paste the code Claude showed you" });
    runClaude(f, String(b.code).trim());
    step(f, "connector", { detail: "signing in to Claude" });
    send(res, 200, flowView(f));
  },

  // Connect Cloudflare once (spec #13): verify the pasted token and keep it sealed for this user's instances.
  "POST /cloud/cloudflare": async (q, req, res, s, b) => {
    if (!s) return send(res, 401, { error: "Sign in" });
    const token = String(b.token ?? "").trim();
    if (!/^[\w-]{30,80}$/.test(token)) return send(res, 400, { error: "Paste the token Cloudflare showed you" });
    const a = await verify(token);
    cfs.set(s.email, { token: seal(token), ...a });
    saveCfs();
    notify(s.email);
    const gu = ghUser(s.login);
    if (gu) for (const i of load().filter((i) => i.email === s.email && !["live", "setting up"].includes(i.pages?.state))) {
      upsert({ ...i, pages: { ...i.pages, state: "setting up", detail: "starting", error: null, permsUrl: null } });
      setupPages(i.id, gu.token, cfs.get(s.email));
    }
    send(res, 200, { accountName: a.accountName });
  },

  // Connect Resend once (spec #17): check the pasted key can manage domains, keep it sealed for every site's email.
  "POST /cloud/resend": async (q, req, res, s, b) => {
    if (!s) return send(res, 401, { error: "Sign in" });
    const key = String(b.key ?? "").trim();
    if (!/^re_[\w-]{10,}$/.test(key)) return send(res, 400, { error: "Paste the API key Resend showed you (it starts with re_)" });
    await checkKey(key);
    resends.set(s.email, { key: seal(key), label: `key …${key.slice(-4)}` });
    saveResends();
    notify(s.email);
    send(res, 200, { ok: true });
  },

  // Disconnect: forget our sealed copy. Copies already handed out (repo secrets, each site's own key) stay until revoked at the source.
  "POST /cloud/cloudflare/remove": (q, req, res, s) => {
    if (!s) return send(res, 401, { error: "Sign in" });
    if (cfs.delete(s.email)) saveCfs();
    notify(s.email);
    send(res, 200, { ok: true });
  },
  "POST /cloud/resend/remove": (q, req, res, s) => {
    if (!s) return send(res, 401, { error: "Sign in" });
    if (resends.delete(s.email)) saveResends();
    notify(s.email);
    send(res, 200, { ok: true });
  },

  // Delete my account, once every site is deleted: the shared Claude connector, then every credential and record we keep for this user.
  "POST /cloud/account/delete": async (q, req, res, s) => {
    if (!s) return send(res, 401, { error: "Sign in" });
    if (load().some((i) => i.email === s.email)) return send(res, 400, { error: "Delete your sites first" });
    if (["install", "connector"].includes(flows.get(s.email)?.step)) return send(res, 409, { error: "A site is being set up. Let it finish and delete it first" });
    const a = accts.get(s.email);
    let warning = null;
    if (a?.claude && a.assertion) await mint(a.assertion).then((c) => sprites(c).removeConnection(a.claude)).catch((e) => { if (e.status !== 404) warning = "We couldn't remove the Agent Keyboard Claude connector from your Fly account. Delete it there yourself."; });
    flows.delete(s.email);
    if (accts.delete(s.email)) writeFileSync(ACCT, seal(JSON.stringify(Object.fromEntries(accts))), { mode: 0o600 });
    if (cfs.delete(s.email)) saveCfs();
    if (resends.delete(s.email)) saveResends();
    if (users.delete(s.login)) saveUsers();
    mcpServer.forget(s.login, s.email);
    res.setHeader("Set-Cookie", `akc=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
    send(res, 200, { ok: true, warning });
  },

  "GET /cloud/claude/switch": (q, req, res, s) => send(res, s ? 200 : 401, s ? switches.get(s.email) ?? { step: null } : { error: "Sign in" }),
  "POST /cloud/claude/switch": (q, req, res, s, b) => {
    if (!s) return send(res, 401, { error: "Sign in" });
    if (!flyOf(s.email)) return send(res, 400, { error: "Connect Fly first" });
    const st = switches.get(s.email), code = String(b.code ?? "").trim();
    if (code) {
      if (st?.step !== "code") return send(res, 409, { error: "No Claude sign-in is waiting. Start again." });
      if (!/^[\w#.~-]{10,400}$/.test(code)) return send(res, 400, { error: "Paste the code Claude showed you" });
      st.step = "switching";
    } else {
      if (["starting", "switching"].includes(st?.step)) return send(res, 409, { error: "Already in progress" });
      switches.set(s.email, { step: "starting" });
    }
    claudeSwitch(s.email, code);
    send(res, 200, switches.get(s.email));
  },

  "GET /cloud/instances": async (q, req, res, s) => {
    if (!s) return send(res, 401, { error: "Sign in" });
    send(res, 200, { instances: await Promise.all(load().filter((i) => i.email === s.email).map(status)), latest: await latest().catch(() => null) });
  },
};

// Every page and /cloud/ API route. The MCP server calls this too, with the session its access token stands for.
async function dispatch(req, res, u, s, b) {
    // Open the site already signed in to the bar: a single-use magic-link token the widget
    // redeems from #ak_handoff= (the same handoff sandboxes use).
    const o = u.pathname.match(/^\/cloud\/open\/([\w-]+)$/);
    if (req.method === "GET" && o) {
      const inst = s && load().find((i) => i.id === o[1] && i.email === s.email);
      if (!inst) return redirect(res, "/dashboard");
      return redirect(res, await handoff(inst, inst.email));
    }
    // Spec 19: bring an older bar's notes and memory over. The popup goes to the old instance's consent page,
    // which signs in there and comes back to .../done with a single-use export token; the Sprite pulls the bundle itself.
    const im = u.pathname.match(/^\/cloud\/import\/([\w-]+)(\/done)?$/);
    if (req.method === "GET" && im) {
      const inst = s && load().find((i) => i.id === im[1] && i.email === s.email);
      if (!inst?.previous) return send(res, 404, "Nothing to bring over.", "text/plain; charset=utf-8");
      const { origin, siteId } = inst.previous;
      if (im[2]) {
        if (u.searchParams.get("origin") !== origin || u.searchParams.get("site") !== siteId || !u.searchParams.get("token")) return send(res, 400, "That link doesn't match this site.", "text/plain; charset=utf-8");
        const r = await runImport(inst, { token: u.searchParams.get("token") });
        return send(res, 200, importDone(r), "text/html; charset=utf-8");
      }
      const consent = `${origin}/export-consent?site=${encodeURIComponent(siteId)}&return=${encodeURIComponent(`${BASE}/cloud/import/${inst.id}/done`)}`;
      const st = await fetch(consent).then((r) => r.status, () => 0);
      if (st === 200) return redirect(res, consent);
      if (st !== 404) return send(res, 200, importDone({ error: st ? `${new URL(origin).host} doesn't have the site ${siteId} any more (${st}).` : `Couldn't reach ${new URL(origin).host}.` }), "text/html; charset=utf-8");
      // Older instances have no /export: sign in to their Supabase here (in the browser) and bring the notes over.
      const js = await fetch(`${origin}/widget.js`).then((r) => (r.ok ? r.text() : ""), () => "");
      const sb = js.match(/https:\/\/[a-z0-9-]+\.supabase\.(?:co|in)/)?.[0], anon = js.match(/eyJ[\w-]+\.[\w-]+\.[\w-]+|sb_publishable_[\w-]+/)?.[0];
      if (!sb || !anon) return send(res, 200, importDone({ error: `${new URL(origin).host} is an older Agent Keyboard. Update it first (tell its bar "update yourself"), then try again.` }), "text/html; charset=utf-8");
      return send(res, 200, oldSignIn(inst, sb, anon), "text/html; charset=utf-8");
    }
    // A teammate's join link: single-use, 7 days. Signs them in to the bar on that site.
    const j = u.pathname.match(/^\/cloud\/join\/([\w-]{20,})$/);
    if (req.method === "GET" && j) {
      const h = createHash("sha256").update(j[1]).digest("base64url");
      const inst = load().find((i) => i.joins?.[h]);
      const join = inst?.joins[h];
      if (!join) return send(res, 410, "This invite link was already used or has expired. Ask whoever invited you for a new one.", "text/plain; charset=utf-8");
      const { [h]: _, ...rest } = inst.joins;
      upsert({ ...inst, joins: rest });
      if (join.exp < Date.now() || !inst.team?.includes(join.email)) return send(res, 410, "This invite link has expired. Ask whoever invited you for a new one.", "text/plain; charset=utf-8");
      return redirect(res, await handoff(inst, join.email));
    }
    // agent-keyboard's deploy workflow pings this after each server/widget push, so Sprites update now, not at the next hourly pass.
    if (req.method === "POST" && u.pathname === "/cloud/release") {
      const k = Buffer.from(req.headers["x-release-key"] ?? ""), want = Buffer.from(env.RELEASE_KEY ?? "");
      if (!want.length || k.length !== want.length || !timingSafeEqual(k, want)) return send(res, 401, "unauthorized", "text/plain");
      latestCache.at = 0;
      (updating ?? Promise.resolve()).then(tick); // after any pass already running (it may have used the old version)
      return send(res, 202, "updating", "text/plain");
    }
    const m = u.pathname.match(/^\/cloud\/instances\/([\w-]+)\/(restart|update|autoupdate|delete|tag|pages|domain|domain-remove|invite|uninvite|mcp|email|email-remove|import|import-skip)$/);
    if (req.method === "POST" && m) {
      const inst = s && load().find((i) => i.id === m[1] && i.email === s.email);
      if (!inst) return send(res, 404, { error: "No such instance" });
      if (m[2] === "autoupdate") {
        upsert({ ...inst, autoUpdate: inst.autoUpdate === false });
        return send(res, 200, { ok: true });
      }
      if (m[2] === "import-skip") {
        upsert({ ...inst, migrate: { state: "skipped" } });
        return send(res, 200, { ok: true });
      }
      if (m[2] === "import") { // the notes-only fallback page, with the user's session on the old instance
        if (!inst.previous || typeof b?.bearer !== "string") return send(res, 400, { error: "Nothing to bring over" });
        return send(res, 200, await runImport(inst, { bearer: b.bearer }));
      }
      if (m[2] === "mcp") {
        await siteMcp(inst, b?.talk === true, b?.manage === true);
        return send(res, 200, { ok: true });
      }
      if (m[2] === "invite" || m[2] === "uninvite") {
        const email = String(b?.email ?? "").trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return send(res, 400, { error: "Type an email like name@example.com" });
        if (email === inst.email) return send(res, 400, { error: "That's you, the owner" });
        const add = m[2] === "invite";
        if (add) await barAccount(email);
        await teamOnSprite(inst, email, add);
        const team = (inst.team ?? []).filter((e) => e !== email).concat(add ? [email] : []);
        const now = Date.now(), joins = Object.fromEntries(Object.entries(inst.joins ?? {}).filter(([, v]) => v.exp > now && v.email !== email));
        const token = add && randomBytes(24).toString("base64url");
        if (token) joins[createHash("sha256").update(token).digest("base64url")] = { email, exp: now + 7 * 864e5 };
        upsert({ ...inst, team, joins });
        return send(res, 200, add ? { ok: true, link: `${BASE}/cloud/join/${token}` } : { ok: true });
      }
      if (m[2] === "tag") {
        const gu = ghUser(s.login);
        if (!gu || inst.starter) return send(res, gu ? 400 : 401, { error: gu ? "Starter sites already have the bar" : "Sign in with GitHub again" });
        const { path, previous } = await addTag(gu.token, inst.repo, inst.tag);
        upsert({ ...inst, tagPath: path, previous: inst.previous ?? previous });
        return send(res, 200, { ok: true, path });
      }
      if (m[2] === "domain" || m[2] === "domain-remove") {
        const c = cfs.get(s.email);
        if (!c || inst.pages?.state !== "live") return send(res, 400, { error: "Host the site on Cloudflare Pages first" });
        const token = open(c.token);
        if (m[2] === "domain-remove") {
          if (inst.mail) await removeEmail(inst, true); // the sender has to be on the site's domain; it follows to the next one
          if (inst.customDomain) await removePagesDomain(token, c.accountId, inst.pages.project, inst.customDomain.host);
          upsert({ ...load().find((x) => x.id === inst.id), customDomain: null });
          await syncDomain(inst.id, c);
          return send(res, 200, { ok: true });
        }
        const host = String(b?.host ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[/:].*$/, "").replace(/\.$/, "");
        if (!HOST.test(host) || /\.(pages\.dev|sprites\.app|workers\.dev)$/.test(host)) return send(res, 400, { error: "Type a domain like www.example.com" });
        await addPagesDomain(token, c.accountId, inst.pages.project, host);
        upsert({ ...inst, customDomain: { host, status: "pending" } });
        await syncDomain(inst.id, c, `https://${host}`);
        await checkDomain(inst.id, c);
        return send(res, 200, { ok: true });
      }
      if (m[2] === "email") {
        if (inst.customDomain?.status !== "active" || !cfs.get(s.email)) return send(res, 400, { error: "Connect your own domain first" });
        if (!resends.get(s.email)) return send(res, 400, { error: "Connect Resend first" });
        if (inst.mail?.status === "setting up") return send(res, 409, { error: "Already setting up" });
        upsert({ ...inst, mail: { ...inst.mail, status: "setting up", detail: "starting", error: null } });
        setupEmail(inst.id);
        return send(res, 200, { ok: true });
      }
      if (m[2] === "email-remove") {
        await removeEmail(inst);
        return send(res, 200, { ok: true });
      }
      if (m[2] === "pages") {
        const gu = ghUser(s.login), c = cfs.get(s.email);
        if (!gu) return send(res, 401, { error: "Sign in with GitHub again" });
        if (!c) return send(res, 400, { error: "Connect Cloudflare first" });
        if (inst.pages?.state === "setting up") return send(res, 409, { error: "Already setting up" });
        upsert({ ...inst, pages: { ...inst.pages, state: "setting up", detail: "starting", error: null, permsUrl: null } });
        setupPages(inst.id, gu.token, c);
        return send(res, 200, { ok: true });
      }
      await act(inst, m[2]);
      return send(res, 200, { ok: true });
    }
    const h = routes[`${req.method} ${u.pathname.replace(/\/$/, "") || "/"}`];
    if (!h) return send(res, 404, { error: "not found" });
    await h(u.searchParams, req, res, s, b);
}

const mcpServer = mcp({ notify, BASE, DATA, seal, open, session, ghUser, fresh, dispatch, send, redirect, mac, load, supabase });
createServer(async (req, res) => {
  const u = new URL(req.url, BASE);
  const s = session(req);
  try {
    if (s) await fresh(s.login);
    if (await mcpServer(req, res, u, s)) return;
    if (req.method === "POST" && u.pathname === "/cloud/feedback") return await feedback(req, res); // its own 20 KB body cap
    await dispatch(req, res, u, s, req.method === "POST" ? await body(req) : null);
  } catch (e) {
    console.error(req.method, u.pathname, e.message);
    if (!res.headersSent) send(res, e.code >= 400 && e.code < 600 ? e.code : 500, { error: e.message });
  }
}).listen(Number(env.PORT ?? 8787), () => console.log(`agent-keyboard-cloud on ${BASE}`));
