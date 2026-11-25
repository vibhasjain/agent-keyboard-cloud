// The control plane's web server: /start (sign up and provision), /signin, /dashboard (manage),
// and their JSON API under /cloud/. Zero deps. agentkeyboard.com proxies these paths here.
//
// Env: PORT, DATA_DIR, PUBLIC_URL (https://agentkeyboard.com), CLOUD_KEY (64 hex: encrypts
// stored Fly assertions + signs cookies), SETUP_KEY (guards the one-time App manifest page),
// SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY, AK_REF (agent-keyboard ref, default main),
// GH_APP_* (or the manifest flow).

import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { claudeLoginFinish, claudeLoginStart } from "./claude.mjs";
import { mint, pollClaim, register, sprites } from "./fly.mjs";
import { appReady, authorizeUrl, createdFromManifest, installationPage, installUrl, loadApp, manifest, refreshUser, signIn, userRepos } from "./githubapp.mjs";
import { mcp } from "./mcp.mjs";
import { addTag, getRepo, putSecret, putVariable, writeFile } from "./github.mjs";
import { TOKEN_URL, WORKFLOW, addPagesDomain, cnameOf, ensureProject, findZone, isApex, pagesDomain, pagesMemory, pointDns, removePagesDomain, verify } from "./cloudflare.mjs";
import { ensureSprite, provision, slug, spriteName } from "./provision.mjs";

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
const load = () => (existsSync(DB) ? JSON.parse(readFileSync(DB, "utf8")) : []);
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
const pub = ({ assertion, ...i }) => i; // never send the assertion anywhere

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

async function runFly(flow) {
  try {
    // Another instance's Fly access still works: reuse it and skip the code.
    const prev = load().find((i) => i.email === flow.email);
    const prevAssertion = prev && open(prev.assertion);
    let creds = prev ? await mint(prevAssertion).catch(() => null) : null;
    const reg = creds ? null : await register(flow.email);
    if (reg) step(flow, "fly", { userCode: reg.claim.user_code, verifyUrl: reg.claim.verification_uri_complete ?? reg.claim.verification_uri });
    const until = Date.now() + (reg?.claim.expires_in ?? 600) * 1000;
    while (!creds) {
      if (Date.now() > until) throw new Error("The Fly code expired. Start again.");
      await new Promise((r) => setTimeout(r, Math.max(5, reg.claim.interval ?? 5) * 1000));
      creds = await pollClaim(reg.claim_token);
    }
    flow.assertion = creds.identity_assertion ?? prevAssertion;
    step(flow, "sprite", { detail: `creating ${flow.sprite}` });
    const api = sprites(creds);
    flow.url = await ensureSprite(api, flow.sprite);
    step(flow, "sprite", { detail: "starting Claude sign-in" });
    flow.loginUrl = await claudeLoginStart(api, flow.sprite);
    step(flow, "claude");
  } catch (e) {
    step(flow, "error", { error: e.message });
  }
}

async function runProvision(flow, code) {
  try {
    step(flow, "connector", { detail: "signing in to Claude" });
    const creds = await mint(flow.assertion);
    const connection = await claudeLoginFinish(sprites(creds), flow.sprite, code, creds);
    flow.loginUrl = null;
    step(flow, "install");
    const user = ghUser(flow.login);
    if (!user) throw new Error("Your GitHub sign-in expired. Sign in again.");
    const r = await provision(
      { assertion: flow.assertion, email: flow.email, repo: flow.repo, domain: flow.domain, name: flow.name, ref: REF, githubToken: user.token, supabase, connector: connection },
      (d) => (flow.detail = d),
    );
    // A brought site gets the tag committed to its index.html; if there isn't one, the page shows it to paste.
    const tagPath = r.starter || r.staging ? r.tagPath : await addTag(user.token, r.repo, r.tag).catch(() => null);
    upsert({ id: r.sprite, tagPath, email: flow.email, login: flow.login, siteId: r.siteId, repo: r.repo, domain: r.domain, url: r.url, connection: r.connection, starter: r.starter, staging: r.staging, tag: r.tag, via: flow.via, ref: REF, createdAt: new Date().toISOString(), assertion: seal(flow.assertion) });
    flow.assertion = null;
    // Every site is hosted on Cloudflare Pages (connected before the flow starts).
    flow.detail = "hosting your site on Cloudflare Pages";
    await setupPages(r.sprite, user.token, cfs.get(flow.email));
    const pages = load().find((i) => i.id === r.sprite)?.pages ?? {};
    step(flow, "done", { result: { url: pages.staging ?? pages.live ?? r.url, pagesError: pages.state === "error" ? pages.error : null, tag: r.tag, starter: r.starter, staging: r.staging, repo: r.repo, tagPath } });
  } catch (e) {
    // Claude's login is single-use: drop the old link (the page waits) and start a fresh one.
    if (flow.step === "connector") flow.loginUrl = null;
    step(flow, flow.step === "connector" ? "claude" : "error", { error: e.message });
    if (flow.step === "claude") {
      mint(flow.assertion).then((c) => claudeLoginStart(sprites(c), flow.sprite)).then((u) => (flow.loginUrl = u), (e2) => step(flow, "error", { error: e2.message }));
    }
  }
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
    const live = (await getRepo(ghToken, inst.repo)).default_branch || "main";
    const p = await ensureProject(token, c.accountId, inst.siteId, live);
    set({ detail: "adding the deploy workflow to your repo", project: p.name, sub: p.subdomain });
    await putSecret(ghToken, inst.repo, "CLOUDFLARE_API_TOKEN", token);
    await putVariable(ghToken, inst.repo, "CLOUDFLARE_ACCOUNT_ID", c.accountId);
    await putVariable(ghToken, inst.repo, "CLOUDFLARE_PAGES_PROJECT", p.name);
    for (const b of inst.staging ? ["ak-staging", live] : [live]) await writeFile(ghToken, inst.repo, b, WORKFLOW_PATH, WORKFLOW, "Deploy to Cloudflare Pages (Agent Keyboard)");
    set({ detail: "turning on sandboxes" });
    // The Sprite: sandbox previews on Pages, the Pages origins allowed to call the bar, and the agent's memory.
    const api = sprites(await mint(open(inst.assertion)));
    const { out } = await api.exec(id, `. ~/ak.env; printf '%s\\n%s' "$SITES" "$EXTRA_ORIGINS"`, { timeoutMs: 60e3 });
    const [sitesJson, had = ""] = out.trim().split("\n");
    const sites = JSON.parse(sitesJson);
    sites[0].sandbox = { preview: `https://{branch}.${p.subdomain}` };
    const extra = [...new Set([...had.split(",").filter(Boolean), `https://${p.subdomain}`, `https://ak-staging.${p.subdomain}`])].join(",");
    const lines = `SITES=${shq(JSON.stringify(sites))}\nEXTRA_ORIGINS=${shq(extra)}\n`;
    const memory = pagesMemory({ sub: p.subdomain, live, staging: inst.staging });
    await api.exec(id, [
      `grep -v -e '^SITES=' -e '^EXTRA_ORIGINS=' ~/ak.env > ~/ak.env.new`,
      `printf %s ${shq(Buffer.from(lines).toString("base64"))} | base64 -d >> ~/ak.env.new`,
      `chmod 600 ~/ak.env.new && mv ~/ak.env.new ~/ak.env`,
      `mkdir -p ~/.claude && printf %s ${shq(Buffer.from(memory).toString("base64"))} | base64 -d > ~/.claude/CLAUDE.md`,
      `sprite-env services restart ak`,
    ].join(" && "), { timeoutMs: 120e3 });
    set({ state: "live", detail: "", live: `https://${p.subdomain}`, staging: inst.staging ? `https://ak-staging.${p.subdomain}` : null });
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
  if (cur?.customDomain?.host === d.host) upsert({ ...cur, customDomain: next });
}
/** Let the bar on `origin` call the Sprite (CORS): add it to the Sprite's EXTRA_ORIGINS. */
async function addOrigin(inst, origin) {
  const api = sprites(await mint(open(inst.assertion)));
  const { out } = await api.exec(inst.id, `. ~/ak.env; printf '%s' "$EXTRA_ORIGINS"`, { timeoutMs: 60e3 });
  const had = out.trim().split(",").filter(Boolean);
  if (had.includes(origin)) return;
  const line = `EXTRA_ORIGINS=${shq([...had, origin].join(","))}\n`;
  await api.exec(inst.id, [
    `grep -v '^EXTRA_ORIGINS=' ~/ak.env > ~/ak.env.new`,
    `printf %s ${shq(Buffer.from(line).toString("base64"))} | base64 -d >> ~/ak.env.new`,
    `chmod 600 ~/ak.env.new && mv ~/ak.env.new ~/ak.env`,
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
// Auto-update (on unless the owner turned it off): hourly, each Sprite behind the latest version reinstalls,
// skipping any that is running a job (a Claude CLI turn) so nothing is cut off; it tries again next hour.
async function autoUpdate() {
  const version = await latest();
  for (const inst of load().filter((i) => i.autoUpdate !== false && i.version !== version)) {
    try {
      const { out } = await sprites(await mint(open(inst.assertion))).exec(inst.id, `if cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' ' | grep -q 'output-forma[t] stream-json'; then echo AK_BUSY; else ${INSTALL}; fi`);
      if (out.includes("AK_BUSY")) continue;
      const cur = load().find((i) => i.id === inst.id);
      if (cur) upsert({ ...cur, ref: REF, version });
      console.log("autoupdate", inst.id, version);
    } catch (e) { console.error("autoupdate", inst.id, e.message); }
  }
}
const tick = () => autoUpdate().catch((e) => console.error("autoupdate", e.message));
setTimeout(tick, 60e3).unref(); // also right after a deploy, so frequent deploys never starve it
setInterval(tick, 3600e3).unref();

async function act(inst, action) {
  const creds = await mint(open(inst.assertion));
  const api = sprites(creds);
  if (action === "restart") await api.exec(inst.id, "sprite-env services restart ak", { timeoutMs: 60e3 });
  else if (action === "update") {
    const version = await latest().catch(() => null);
    await api.exec(inst.id, INSTALL);
    upsert({ ...(load().find((i) => i.id === inst.id) ?? inst), ref: REF, version });
  } else if (action === "delete") {
    await api.remove(inst.id).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
    await api.removeConnection(inst.connection).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
    save(load().filter((i) => i.id !== inst.id));
  }
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
    send(res, 200, { signedIn: true, login: s.login, email: s.email, github: !!ghUser(s.login), installUrl: appReady() ? installUrl("start") : null, instance: inst && pub(inst), cloudflare: cfs.get(s.email)?.accountName ?? null, cloudflareTokenUrl: TOKEN_URL, claude: mcpServer.claude(s.login), events: eventsUrl(s.email), flow: flowView(flows.get(s.email)) });
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
    if (f && !["error", "done"].includes(f.step)) return send(res, 200, flowView(f));
    if (limited(req.headers["x-nf-client-connection-ip"] ?? req.headers["fly-client-ip"] ?? req.socket.remoteAddress)) return send(res, 429, { error: "Too many attempts. Try again in an hour." });
    let repo = null, domain = null, name = null;
    if (b.repo) {
      if (!(await userRepos(u.token, u.installations)).some((r) => r.full_name === b.repo)) return send(res, 400, { error: "Pick a repo you gave Agent Keyboard access to" });
      repo = b.repo;
      domain = String(b.domain ?? "").trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase() || null; // none: staged on the Sprite
      if (domain && !/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/.test(domain)) return send(res, 400, { error: "Enter your site's domain, like example.com, or leave it blank" });
    } else {
      name = slug(String(b.name ?? "my-site"));
    }
    const flow = { email: s.email, login: s.login, repo, domain, name, via: b.via === "mcp" ? "mcp" : undefined, sprite: spriteName(slug(repo ? repo.split("/")[1] : name)) };
    if (load().some((i) => i.id === flow.sprite)) return send(res, 409, { error: `You already have ${flow.sprite}. Manage it from the dashboard, or pick another repo or name.` });
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
    runProvision(f, String(b.code).trim());
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
      const pg = inst.pages?.state === "live" && inst.pages;
      const site = pg ? pg.staging ?? (inst.customDomain?.status === "active" ? `https://${inst.customDomain.host}` : pg.live) : inst.starter ? inst.url : `https://${inst.domain}`;
      const r = await fetch(`${supabase.url}/auth/v1/admin/generate_link`, {
        method: "POST",
        headers: { apikey: supabase.serviceKey, Authorization: `Bearer ${supabase.serviceKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ type: "magiclink", email: inst.email }),
      }).catch(() => null);
      const d = (await r?.json().catch(() => null)) ?? {};
      const token = d.hashed_token ?? d.properties?.hashed_token;
      return redirect(res, token ? `${site}/#ak_handoff=${encodeURIComponent(token)}` : site);
    }
    const m = u.pathname.match(/^\/cloud\/instances\/([\w-]+)\/(restart|update|autoupdate|delete|tag|pages|domain|domain-remove)$/);
    if (req.method === "POST" && m) {
      const inst = s && load().find((i) => i.id === m[1] && i.email === s.email);
      if (!inst) return send(res, 404, { error: "No such instance" });
      if (m[2] === "autoupdate") {
        upsert({ ...inst, autoUpdate: inst.autoUpdate === false });
        return send(res, 200, { ok: true });
      }
      if (m[2] === "tag") {
        const gu = ghUser(s.login);
        if (!gu || inst.starter) return send(res, gu ? 400 : 401, { error: gu ? "Starter sites already have the bar" : "Sign in with GitHub again" });
        const path = await addTag(gu.token, inst.repo, inst.tag, inst.staging ? "ak-staging" : undefined);
        upsert({ ...inst, tagPath: path });
        return send(res, 200, { ok: true, path });
      }
      if (m[2] === "domain" || m[2] === "domain-remove") {
        const c = cfs.get(s.email);
        if (!c || inst.pages?.state !== "live") return send(res, 400, { error: "Host the site on Cloudflare Pages first" });
        const token = open(c.token);
        if (m[2] === "domain-remove") {
          if (inst.customDomain) await removePagesDomain(token, c.accountId, inst.pages.project, inst.customDomain.host);
          upsert({ ...inst, customDomain: null });
          return send(res, 200, { ok: true });
        }
        const host = String(b?.host ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[/:].*$/, "").replace(/\.$/, "");
        if (!HOST.test(host) || /\.(pages\.dev|sprites\.app|workers\.dev)$/.test(host)) return send(res, 400, { error: "Type a domain like www.example.com" });
        await addPagesDomain(token, c.accountId, inst.pages.project, host);
        upsert({ ...inst, customDomain: { host, status: "pending" } });
        await addOrigin(inst, `https://${host}`);
        await checkDomain(inst.id, c);
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
    await dispatch(req, res, u, s, req.method === "POST" ? await body(req) : null);
  } catch (e) {
    console.error(req.method, u.pathname, e.message);
    if (!res.headersSent) send(res, e.code >= 400 && e.code < 600 ? e.code : 500, { error: e.message });
  }
}).listen(Number(env.PORT ?? 8787), () => console.log(`agent-keyboard-cloud on ${BASE}`));
