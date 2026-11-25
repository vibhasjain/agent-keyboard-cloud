// The Agent Keyboard MCP server (spec #14): set up and manage your sites from Claude.
// Streamable HTTP at /mcp, behind MCP authorization (OAuth 2.1 + PKCE, dynamic client registration).
// The authorize step is our GitHub sign-in plus a consent screen, so every site set up from Claude
// belongs to the same account as the dashboard. Tools call the same routes as /start and the
// dashboard (dispatch), with the session the access token stands for. Secrets (the Cloudflare token,
// the Claude code) are pasted on /start, never into the chat.

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const ACCESS_TTL = 3600e3, REFRESH_TTL = 90 * 864e5, CODE_TTL = 5 * 60e3;
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const sha = (s) => createHash("sha256").update(s).digest("base64url");
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization, Content-Type, Mcp-Protocol-Version", "Access-Control-Expose-Headers": "WWW-Authenticate" };

async function read(req, limit = 1e6) {
  let s = "";
  for await (const c of req) if ((s += c).length > limit) throw Object.assign(new Error("too large"), { code: 413 });
  if (/^application\/json/.test(req.headers["content-type"] ?? "")) return s ? JSON.parse(s) : {};
  return Object.fromEntries(new URLSearchParams(s));
}

export function mcp({ BASE, DATA, seal, open, ghUser, fresh, dispatch, send, redirect, mac }) {
  const FILE = `${DATA}/oauth.json`;
  let db = null;
  try { if (existsSync(FILE)) db = JSON.parse(open(readFileSync(FILE, "utf8"))); } catch {}
  db ??= { clients: {}, access: {}, refresh: {} };
  const save = () => writeFileSync(FILE, seal(JSON.stringify(db)), { mode: 0o600 });
  const codes = new Map(); // code → { client, redirect_uri, challenge, login, email, exp }

  const json = (res, code, body, headers = {}) => (res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS, ...headers }), res.end(JSON.stringify(body)));
  function issue(grant) {
    const now = Date.now();
    for (const k of ["access", "refresh"]) for (const [h, v] of Object.entries(db[k])) if (v.exp < now) delete db[k][h];
    const access = randomBytes(32).toString("base64url"), refresh = randomBytes(32).toString("base64url");
    db.access[sha(access)] = { ...grant, exp: now + ACCESS_TTL };
    db.refresh[sha(refresh)] = { ...grant, exp: now + REFRESH_TTL };
    save();
    return { access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL / 1000, refresh_token: refresh, scope: "sites" };
  }
  const okRedirect = (r) => { try { const x = new URL(r); return x.protocol === "https:" || (x.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(x.hostname)); } catch { return false; } };
  const back = (p, params) => { const x = new URL(p.redirect_uri); for (const [k, v] of Object.entries(params)) if (v != null) x.searchParams.set(k, v); return x.href; };

  const metaResource = { resource: `${BASE}/mcp`, authorization_servers: [BASE], scopes_supported: ["sites"], bearer_methods_supported: ["header"], resource_name: "Agent Keyboard" };
  const metaServer = {
    issuer: BASE,
    authorization_endpoint: `${BASE}/oauth/authorize`,
    token_endpoint: `${BASE}/oauth/token`,
    registration_endpoint: `${BASE}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["sites"],
  };

  // The consent screen, after the GitHub sign-in.
  function consent(res, p, s) {
    const c = db.clients[p.client_id];
    const hidden = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "resource", "scope"].map((k) => p[k] != null ? `<input type="hidden" name="${k}" value="${esc(p[k])}">` : "").join("");
    send(res, 200, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Allow access · Agent Keyboard</title>
<link rel="icon" href="https://agentkeyboard.com/favicon.png"><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet"><link rel="stylesheet" href="/cloud/cloud.css"></head>
<body><div class="wrap"><div class="top"><a class="brand" href="https://agentkeyboard.com"><img src="https://agentkeyboard.com/typewriter-mark.png" alt=""><b>Agent Keyboard</b></a></div>
<h1>Allow <em>${esc(c.client_name || "this app")}</em> to manage your Agent Keyboard?</h1>
<div class="card"><p>Signed in as <b>${esc(s.login)}</b> (${esc(s.email)}). It will be able to list your repos and sites, set up new ones, restart, update or delete them, and manage their domains. Tokens and sign-in codes stay on our pages; it never sees them.</p>
<p class="small">It sends you back to <b>${esc(new URL(p.redirect_uri).host)}</b>.</p>
<form method="post" action="/oauth/authorize">${hidden}<input type="hidden" name="csrf" value="${esc(mac(`${s.login} ${p.client_id} ${p.redirect_uri} ${p.code_challenge}`))}">
<div class="row"><button class="btn" name="allow" value="1">Allow</button><button class="btn ghost" name="deny" value="1">Cancel</button></div></form></div></div></body></html>`, "text/html; charset=utf-8");
  }

  return async function handle(req, res, u, s) {
    const path = u.pathname.replace(/\/$/, "");
    if (req.method === "OPTIONS" && (path === "/mcp" || path.startsWith("/oauth/") || path.startsWith("/.well-known/oauth-"))) return (res.writeHead(204, { ...CORS, "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS" }), res.end(), true);
    if (req.method === "GET" && path.startsWith("/.well-known/oauth-protected-resource")) return (json(res, 200, metaResource), true);
    if (req.method === "GET" && (path.startsWith("/.well-known/oauth-authorization-server") || path.startsWith("/.well-known/openid-configuration"))) return (json(res, 200, metaServer), true);

    // Dynamic client registration (public clients, PKCE only).
    if (req.method === "POST" && path === "/oauth/register") {
      const b = await read(req, 1e4);
      const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris.map(String) : [];
      if (!uris.length || uris.length > 5 || !uris.every(okRedirect)) return (json(res, 400, { error: "invalid_redirect_uri", error_description: "https redirect URIs (or http on localhost) only" }), true);
      const client = { client_id: randomBytes(16).toString("hex"), client_name: String(b.client_name ?? "").slice(0, 100), redirect_uris: uris, created: Date.now() };
      db.clients[client.client_id] = client;
      save();
      return (json(res, 201, { ...client, client_id_issued_at: Math.floor(client.created / 1000), token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }), true);
    }

    if (path === "/oauth/authorize" && (req.method === "GET" || req.method === "POST")) {
      const p = req.method === "GET" ? Object.fromEntries(u.searchParams) : await read(req, 1e4);
      const c = db.clients[p.client_id];
      if (!c || !c.redirect_uris.includes(p.redirect_uri)) return (send(res, 400, "Unknown app or redirect address. Remove the connector in Claude and add it again.", "text/plain; charset=utf-8"), true);
      if (p.response_type && p.response_type !== "code" || p.code_challenge_method !== "S256" || !p.code_challenge) return (redirect(res, back(p, { error: "invalid_request", error_description: "PKCE S256 required", state: p.state })), true);
      if (!s || !ghUser(s.login)) return (redirect(res, `/cloud/github/login?next=${encodeURIComponent(`/oauth/authorize?${new URLSearchParams({ ...p, response_type: "code" })}`)}`), true);
      if (req.method === "GET") return (consent(res, p, s), true);
      if (p.csrf !== mac(`${s.login} ${p.client_id} ${p.redirect_uri} ${p.code_challenge}`)) return (send(res, 403, "This page expired. Start again from Claude.", "text/plain; charset=utf-8"), true);
      if (p.deny) return (redirect(res, back(p, { error: "access_denied", state: p.state })), true);
      const code = randomBytes(32).toString("base64url");
      codes.set(code, { client: p.client_id, redirect_uri: p.redirect_uri, challenge: p.code_challenge, login: s.login, email: s.email, exp: Date.now() + CODE_TTL });
      return (redirect(res, back(p, { code, state: p.state, iss: BASE })), true);
    }

    if (req.method === "POST" && path === "/oauth/token") {
      const b = await read(req, 1e4);
      if (b.grant_type === "authorization_code") {
        const c = codes.get(b.code);
        codes.delete(b.code);
        if (!c || c.exp < Date.now() || c.client !== b.client_id || c.redirect_uri !== b.redirect_uri || sha(String(b.code_verifier ?? "")) !== c.challenge) return (json(res, 400, { error: "invalid_grant" }), true);
        return (json(res, 200, issue({ login: c.login, email: c.email, client: c.client })), true);
      }
      if (b.grant_type === "refresh_token") {
        const h = sha(String(b.refresh_token ?? "")), g = db.refresh[h];
        if (!g || g.exp < Date.now() || (b.client_id && b.client_id !== g.client)) return (json(res, 400, { error: "invalid_grant" }), true);
        delete db.refresh[h];
        return (json(res, 200, issue({ login: g.login, email: g.email, client: g.client })), true);
      }
      return (json(res, 400, { error: "unsupported_grant_type" }), true);
    }

    if (path === "/mcp") {
      const tok = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
      const g = tok && db.access[sha(tok)];
      if (!g || g.exp < Date.now()) return (json(res, 401, { error: "invalid_token" }, { "WWW-Authenticate": `Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource"` }), true);
      await fresh(g.login);
      for (const [k, v] of Object.entries(CORS)) res.setHeader(k, v);
      const server = tools({ login: g.login, email: g.email }, req);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => { transport.close(); server.close(); });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.method === "POST" ? await read(req) : undefined);
      return true;
    }
    return false;
  };

  // ---- tools ----
  function tools(s, req) {
    // Call a /cloud/ route as this user and return its JSON (errors become tool errors).
    async function call(method, path, b = null) {
      const out = { code: 200, body: null };
      const res = { headersSent: false, setHeader() {}, writeHead(c) { out.code = c; }, end(x) { if (x) try { out.body = JSON.parse(x); } catch { out.body = String(x); } } };
      await dispatch({ method, headers: req.headers, socket: req.socket }, res, new URL(path, BASE), s, b);
      if (out.code >= 400) throw new Error(out.body?.error === "Sign in with GitHub again" ? `Your GitHub sign-in expired. Open ${BASE}/signin to sign in again, then retry.` : out.body?.error ?? `HTTP ${out.code}`);
      return out.body;
    }
    const text = (o) => ({ content: [{ type: "text", text: typeof o === "string" ? o : JSON.stringify(o, null, 1) }] });
    const site = z.string().regex(/^[\w-]+$/).describe("The site's Sprite id, e.g. ak-my-site (from list_sites)");
    const open = (id) => `${BASE}/cloud/open/${id}`;

    function describe(f) {
      if (!f?.step) return "No setup in progress. Call start_setup.";
      if (f.step === "error") return `Setup failed: ${f.error}. Call start_setup to try again.`;
      if (f.step === "fly" && f.userCode) return `Step: connect Fly.io. Ask the user to open ${f.verifyUrl}, sign in to Fly (or sign up), and enter the code ${f.userCode} if asked. Then call setup_status.`;
      if (f.step === "claude") return `${f.error ? `${f.error}\n` : ""}Step: sign in to Claude. Ask the user to open ${BASE}/start in their browser: it has the Claude sign-in link and a box for the code Claude shows. They paste that code there, never in this chat. Then call setup_status.`;
      if (f.step === "done") {
        const r = f.result;
        return [
          r.pagesError ? `Cloudflare Pages hosting didn't finish: ${r.pagesError} Retry with site_action { site: "${f.sprite}", action: "pages" }.` : null,
          `Done. Site ${f.sprite}: ${r.url}`,
          `Open it signed in to the bar: ${open(f.sprite)}`,
          r.staging ? `It's staged: the bar commits to the ak-staging branch (that preview). Tell the bar "deploy to live" to ship.` : null,
          !r.starter && !r.staging && !r.tagPath ? `We couldn't find an index.html for the bar. Add this tag before </body> on the site's pages:\n${r.tag}` : null,
          `Manage it at ${BASE}/dashboard.`,
        ].filter(Boolean).join("\n");
      }
      return `Working: ${f.detail || f.step}. Call setup_status again in about 15 seconds.`;
    }
    function domainText(i) {
      const d = i.customDomain;
      if (!d) return `No custom domain. Add one with add_domain.`;
      if (d.error) return `${d.host}: ${d.error}`;
      if (d.status === "active") return `${d.host} is live ✓`;
      if (d.zone?.status === "active") return `${d.host}: DNS points at Pages; Cloudflare is issuing the certificate (a few minutes).`;
      if (d.zone) return `${d.host} is in their Cloudflare account but not active: at the registrar, set the nameservers to ${d.zone.ns.join(" and ")}.`;
      if (d.apex) return `${d.host} is a root domain: its DNS must be on Cloudflare. Add it at https://dash.cloudflare.com/?to=/:account/add-site and switch the nameservers at the registrar; we point it at the site once it appears. Or use a subdomain like www.${d.host}.`;
      return `${d.host}: at the DNS provider add CNAME ${d.host} → ${i.pages.sub}. ${d.now === i.pages.sub ? "✓ Found it; waiting for Cloudflare." : `✗ Not there yet${d.now ? ` (points to ${d.now})` : ""}.`}`;
    }
    const sites = async () => (await call("GET", "/cloud/instances")).instances;
    const find = async (id) => (await sites()).find((i) => i.id === id) ?? Promise.reject(new Error(`No site ${id}. Call list_sites.`));

    const server = new McpServer({ name: "agent-keyboard", version: "1.0.0" }, {
      instructions: `Agent Keyboard puts a prompt bar on a website; a Claude Code session behind it edits the site's repo and ships. These tools set it up and manage it for the signed-in user, the same as ${BASE}/start and ${BASE}/dashboard. Setup order: connect_cloudflare, list_repos, start_setup, then setup_status until done (it says what the user does at each step). Never ask the user to paste a token, password or code into the chat: those go on ${BASE}/start.`,
    });

    server.registerTool("whoami", { description: "The signed-in Agent Keyboard account: GitHub login, email, Cloudflare connection, number of sites, and any setup in progress.", annotations: { readOnlyHint: true } }, async () => {
      const me = await call("GET", "/cloud/me");
      return text({ login: me.login, email: me.email, cloudflare: me.cloudflare ?? "not connected (call connect_cloudflare)", sites: (await sites()).length, setup: me.flow?.step ?? "none" });
    });
    server.registerTool("list_repos", { description: "GitHub repos the user gave Agent Keyboard access to (candidates for start_setup), and the link to give it access to more.", annotations: { readOnlyHint: true } }, async () => {
      const [{ repos }, me] = await Promise.all([call("GET", "/cloud/repos"), call("GET", "/cloud/me")]);
      return text({ repos: repos.map((r) => r.homepage ? `${r.full_name} (${r.homepage})` : r.full_name), missing_a_repo: me.installUrl });
    });
    server.registerTool("connect_cloudflare", { description: "Check the Cloudflare connection (required: sites are hosted on Cloudflare Pages in the user's own account). If missing, returns the page where the user pastes their token.", annotations: { readOnlyHint: true } }, async () => {
      const me = await call("GET", "/cloud/me");
      if (me.cloudflare) return text(`Cloudflare is connected (${me.cloudflare}).`);
      return text(`Not connected yet. Ask the user to open ${BASE}/start in their browser (signing in with GitHub if asked): it links to Cloudflare's pre-filled token form and has the box to paste the token. They paste it there, never in this chat. Then call connect_cloudflare again.`);
    });
    server.registerTool("start_setup", {
      description: "Set up Agent Keyboard for a repo (or a new starter site): a Sprite in the user's Fly account, signed in to their Claude plan, hosted on Cloudflare Pages. Returns the first step; then call setup_status.",
      inputSchema: {
        repo: z.string().optional().describe("owner/name from list_repos. Omit to create a new starter site."),
        domain: z.string().optional().describe("The repo's live domain if it already deploys somewhere. Omit to stage: the bar works on a preview and ships when told."),
        name: z.string().optional().describe("Name for a new starter site (no repo)."),
      },
    }, async ({ repo, domain, name }) => text(describe(await call("POST", "/cloud/start", repo ? { repo, domain, via: "mcp" } : { name, via: "mcp" }))));
    server.registerTool("setup_status", { description: "Where the setup in progress is, and what the user should do next.", annotations: { readOnlyHint: true } }, async () => text(describe(await call("GET", "/cloud/start"))));
    server.registerTool("list_sites", { description: "The user's Agent Keyboard sites: status, repo, URLs, hosting and domain.", annotations: { readOnlyHint: true } }, async () =>
      text((await sites()).map((i) => ({
        site: i.id, name: i.siteId, status: i.status, repo: i.repo,
        url: i.customDomain?.status === "active" ? `https://${i.customDomain.host}` : i.pages?.staging ?? i.pages?.live ?? i.url,
        staged: !!i.staging, hosting: i.pages?.state === "live" ? "Cloudflare Pages" : i.pages?.state ? `Cloudflare Pages: ${i.pages.state}${i.pages.error ? ` (${i.pages.error})` : ""}` : "not on Pages",
        domain: i.pages?.state === "live" ? domainText(i) : undefined, open_signed_in: open(i.id), created: i.createdAt?.slice(0, 10), via: i.via ?? "web",
      }))));
    server.registerTool("site_action", {
      description: "restart or update a site's Sprite, (re)host it on Cloudflare Pages (pages), commit the bar's script tag to its index.html (tag), or delete it (removes the Sprite and its Claude connector from the user's Fly account; the repo stays).",
      inputSchema: { site, action: z.enum(["restart", "update", "pages", "tag", "delete"]), confirm: z.boolean().optional().describe("Required true for delete, after the user confirms.") },
      annotations: { destructiveHint: true },
    }, async ({ site: id, action, confirm }) => {
      if (action === "delete" && confirm !== true) return text(`Deleting ${id} removes its Sprite and Claude connector from the user's Fly account (the repo stays). Ask the user to confirm, then call again with confirm: true.`);
      const r = await call("POST", `/cloud/instances/${id}/${action}`, {});
      return text(action === "tag" ? `Added the tag to ${r.path}.` : action === "pages" ? "Setting up Cloudflare Pages; check list_sites in a minute." : `${id}: ${action} done.`);
    });
    server.registerTool("add_domain", { description: "Serve a site (hosted on Cloudflare Pages) at the user's own domain. Returns what's left to do, if anything.", inputSchema: { site, host: z.string().describe("e.g. www.example.com") } }, async ({ site: id, host }) => {
      await call("POST", `/cloud/instances/${id}/domain`, { host });
      return text(domainText(await find(id)));
    });
    server.registerTool("domain_status", { description: "Check a site's custom domain and what's left to do.", inputSchema: { site }, annotations: { readOnlyHint: true } }, async ({ site: id }) => text(domainText(await find(id))));
    server.registerTool("remove_domain", { description: "Remove a site's custom domain from Cloudflare Pages (its DNS record stays).", inputSchema: { site }, annotations: { destructiveHint: true } }, async ({ site: id }) => {
      await call("POST", `/cloud/instances/${id}/domain-remove`, {});
      return text("Removed. Its DNS record stays; delete it at the DNS provider if it's no longer needed.");
    });
    server.registerTool("open_site", { description: "A link that opens the site already signed in to the bar (in a browser signed in at agentkeyboard.com).", inputSchema: { site }, annotations: { readOnlyHint: true } }, async ({ site: id }) => text(`Open ${open((await find(id)).id)} to use the bar on it.`));
    return server;
  }
}
