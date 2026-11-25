// The control plane's web server: /start (sign up and provision), /dashboard (manage),
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
import { appReady, authorizeUrl, createdFromManifest, installUrl, loadApp, manifest, signIn, userRepos } from "./githubapp.mjs";
import { ensureSprite, provision, slug } from "./provision.mjs";

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
  writeFileSync(`${DB}.tmp`, JSON.stringify(list, null, 1), { mode: 0o600 });
  renameSync(`${DB}.tmp`, DB);
}
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
const users = new Map(); // login → { token, installations }  (GitHub user token, in memory only)
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
    const reg = await register(flow.email);
    step(flow, "fly", { userCode: reg.claim.user_code, verifyUrl: reg.claim.verification_uri_complete ?? reg.claim.verification_uri });
    const until = Date.now() + (reg.claim.expires_in ?? 600) * 1000;
    let creds = null;
    while (!creds) {
      if (Date.now() > until) throw new Error("The Fly code expired. Start again.");
      await new Promise((r) => setTimeout(r, Math.max(5, reg.claim.interval ?? 5) * 1000));
      creds = await pollClaim(reg.claim_token);
    }
    flow.assertion = creds.identity_assertion;
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
    const user = users.get(flow.login);
    if (!user) throw new Error("Your GitHub sign-in expired. Sign in again.");
    const r = await provision(
      { assertion: flow.assertion, email: flow.email, repo: flow.repo, domain: flow.domain, name: flow.name, ref: REF, githubToken: user.token, supabase, connector: connection },
      (d) => (flow.detail = d),
    );
    upsert({ id: r.sprite, email: flow.email, login: flow.login, siteId: r.siteId, repo: r.repo, domain: r.domain, url: r.url, connection: r.connection, starter: r.starter, tag: r.tag, ref: REF, createdAt: new Date().toISOString(), assertion: seal(flow.assertion) });
    flow.assertion = null;
    step(flow, "done", { result: { url: r.url, tag: r.tag, starter: r.starter, repo: r.repo } });
  } catch (e) {
    step(flow, flow.step === "connector" ? "claude" : "error", { error: e.message });
    if (flow.step === "claude") {
      // Claude's login is single-use: start a fresh one so the user can retry.
      mint(flow.assertion).then((c) => claudeLoginStart(sprites(c), flow.sprite)).then((u) => (flow.loginUrl = u), () => {});
    }
  }
}

const flowView = (f) => f && { step: f.step, detail: f.detail, error: f.error, userCode: f.userCode, verifyUrl: f.verifyUrl, loginUrl: f.loginUrl, result: f.result, sprite: f.sprite };

// ---- dashboard actions ----
async function act(inst, action) {
  const creds = await mint(open(inst.assertion));
  const api = sprites(creds);
  if (action === "restart") await api.exec(inst.id, "sprite-env services restart ak", { timeoutMs: 60e3 });
  else if (action === "update") {
    await api.exec(inst.id, `curl -fsSL https://raw.githubusercontent.com/vibhasjain/agent-keyboard/${REF}/server/sprite-install.sh -o ~/sprite-install.sh && AK_REF=${REF} bash ~/sprite-install.sh`);
    upsert({ ...inst, ref: REF });
  } else if (action === "delete") {
    await api.remove(inst.id).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
    await api.removeConnection(inst.connection).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
    save(load().filter((i) => i.id !== inst.id));
  }
}

async function status(inst) {
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
  "GET /start": (q, req, res) => send(res, 200, readFileSync(new URL("start.html", PAGES)), "text/html; charset=utf-8"),
  "GET /dashboard": (q, req, res) => send(res, 200, readFileSync(new URL("dashboard.html", PAGES)), "text/html; charset=utf-8"),
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
    states.set(state, q.get("next") === "dashboard" ? "dashboard" : "start");
    redirect(res, authorizeUrl(state));
  },
  // OAuth callback, and the App's post-install redirect (which also carries a code).
  "GET /cloud/github/callback": async (q, req, res) => {
    const next = states.get(q.get("state")) ?? "start";
    states.delete(q.get("state"));
    if (!q.get("code")) return redirect(res, `/${next}`);
    const u = await signIn(q.get("code"));
    users.set(u.login, { token: u.token, installations: u.installations });
    setSession(res, { login: u.login, email: u.email });
    if (next === "start" && !u.installations.length) {
      const state = randomBytes(16).toString("hex");
      states.set(state, "start");
      return redirect(res, installUrl(state));
    }
    redirect(res, `/${next}`);
  },
  "POST /cloud/logout": (q, req, res) => {
    res.setHeader("Set-Cookie", `akc=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
    send(res, 200, { ok: true });
  },

  "GET /cloud/me": (q, req, res, s) => {
    if (!s) return send(res, 200, { signedIn: false, app: appReady() });
    const inst = load().find((i) => i.email === s.email);
    send(res, 200, { signedIn: true, login: s.login, email: s.email, github: users.has(s.login), installUrl: appReady() ? installUrl("start") : null, instance: inst && pub(inst), flow: flowView(flows.get(s.email)) });
  },
  "GET /cloud/repos": async (q, req, res, s) => {
    const u = s && users.get(s.login);
    if (!u) return send(res, 401, { error: "Sign in with GitHub again" });
    send(res, 200, { repos: await userRepos(u.token, u.installations) });
  },
  "POST /cloud/start": async (q, req, res, s, b) => {
    const u = s && users.get(s.login);
    if (!u) return send(res, 401, { error: "Sign in with GitHub again" });
    if (load().some((i) => i.email === s.email)) return send(res, 409, { error: "You already have an instance. Manage it from the dashboard." });
    const f = flows.get(s.email);
    if (f && !["error", "done"].includes(f.step)) return send(res, 200, flowView(f));
    if (limited(req.headers["x-nf-client-connection-ip"] ?? req.headers["fly-client-ip"] ?? req.socket.remoteAddress)) return send(res, 429, { error: "Too many attempts. Try again in an hour." });
    let repo = null, domain = null, name = null;
    if (b.repo) {
      if (!(await userRepos(u.token, u.installations)).some((r) => r.full_name === b.repo)) return send(res, 400, { error: "Pick a repo you gave Agent Keyboard access to" });
      repo = b.repo;
      domain = String(b.domain ?? "").trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();
      if (!/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/.test(domain)) return send(res, 400, { error: "Enter your site's domain, like example.com" });
    } else {
      name = slug(String(b.name ?? "my-site"));
    }
    const flow = { email: s.email, login: s.login, repo, domain, name, sprite: `ak-${slug(repo ? repo.split("/")[1] : name)}` };
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

  "GET /cloud/instances": async (q, req, res, s) => {
    if (!s) return send(res, 401, { error: "Sign in" });
    send(res, 200, { instances: await Promise.all(load().filter((i) => i.email === s.email).map(status)) });
  },
};

createServer(async (req, res) => {
  const u = new URL(req.url, BASE);
  const s = session(req);
  try {
    const m = u.pathname.match(/^\/cloud\/instances\/([\w-]+)\/(restart|update|delete)$/);
    if (req.method === "POST" && m) {
      await body(req);
      const inst = s && load().find((i) => i.id === m[1] && i.email === s.email);
      if (!inst) return send(res, 404, { error: "No such instance" });
      await act(inst, m[2]);
      return send(res, 200, { ok: true });
    }
    const h = routes[`${req.method} ${u.pathname.replace(/\/$/, "") || "/"}`];
    if (!h) return send(res, 404, { error: "not found" });
    await h(u.searchParams, req, res, s, req.method === "POST" ? await body(req) : null);
  } catch (e) {
    console.error(req.method, u.pathname, e.message);
    if (!res.headersSent) send(res, e.code >= 400 && e.code < 600 ? e.code : 500, { error: e.message });
  }
}).listen(Number(env.PORT ?? 8787), () => console.log(`agent-keyboard-cloud on ${BASE}`));
