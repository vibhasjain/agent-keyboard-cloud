// The "Agent Keyboard" GitHub App: sign-in (user-to-server OAuth), installs, and the
// one-click manifest flow that creates the App itself. Credentials come from env
// (GH_APP_*) or from <DATA_DIR>/github-app.json written by the manifest flow.

import { existsSync, readFileSync, writeFileSync } from "node:fs";

const API = "https://api.github.com";
let app = null;

export function loadApp(dataDir) {
  const f = `${dataDir}/github-app.json`;
  const e = process.env;
  if (e.GH_APP_ID) app = { id: e.GH_APP_ID, slug: e.GH_APP_SLUG, client_id: e.GH_APP_CLIENT_ID, client_secret: e.GH_APP_CLIENT_SECRET, pem: e.GH_APP_PRIVATE_KEY };
  else if (existsSync(f)) app = JSON.parse(readFileSync(f, "utf8"));
  return app;
}
export const appReady = () => !!app;

async function gh(token, method, path, body) {
  const res = await fetch(path.startsWith("https:") ? path : `${API}${path}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.error) throw Object.assign(new Error(`github ${path}: ${res.status} ${data.message ?? data.error_description ?? data.error ?? ""}`), { status: res.status });
  return data;
}

/** The manifest for "Create GitHub App" (POSTed by a form to github.com/settings/apps/new). */
export function manifest(base) {
  return {
    name: "Agent Keyboard",
    url: "https://agentkeyboard.com",
    description: "A prompt bar that edits the site it's on. Installs a deploy key on the repo you pick.",
    redirect_url: `${base}/cloud/github/created`,
    callback_urls: [`${base}/cloud/github/callback`],
    setup_url: `${base}/cloud/github/callback`,
    setup_on_update: true,
    request_oauth_on_install: true,
    public: true,
    hook_attributes: { url: `${base}/cloud/github/hook`, active: false },
    default_permissions: { administration: "write", contents: "write", metadata: "read", emails: "read", secrets: "write", actions_variables: "write", workflows: "write" },
  };
}

/** Finish the manifest flow: swap the one-time code for the App's credentials and keep them. */
export async function createdFromManifest(code, dataDir) {
  const d = await gh(null, "POST", `/app-manifests/${encodeURIComponent(code)}/conversions`);
  app = { id: String(d.id), slug: d.slug, client_id: d.client_id, client_secret: d.client_secret, pem: d.pem };
  writeFileSync(`${dataDir}/github-app.json`, JSON.stringify(app), { mode: 0o600 });
  return app;
}

export const authorizeUrl = (state) => `https://github.com/login/oauth/authorize?client_id=${app.client_id}&state=${state}`;
export const installUrl = (state) => `https://github.com/apps/${app.slug}/installations/new?state=${state}`;

/** OAuth code → the signed-in user: { token, login, email, installations: [id] }. */
export async function signIn(code) {
  const t = await gh(null, "POST", "https://github.com/login/oauth/access_token", { client_id: app.client_id, client_secret: app.client_secret, code });
  const token = t.access_token;
  const [user, emails, inst] = await Promise.all([gh(token, "GET", "/user"), gh(token, "GET", "/user/emails"), gh(token, "GET", "/user/installations")]);
  const email = (emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified))?.email;
  if (!email) throw new Error("your GitHub account has no verified email");
  const installations = inst.installations.filter((i) => i.app_id === Number(app.id)).map((i) => i.id);
  return { token, expiresIn: t.expires_in, login: user.login, email: email.toLowerCase(), installations };
}

/** The page where GitHub asks `owner` to accept the App's new permissions (straight to it: on mobile the "Review request" button is off-screen). */
export async function installationPage(token, owner) {
  const d = await gh(token, "GET", "/user/installations?per_page=100");
  const i = d.installations.find((i) => i.app_id === Number(app.id) && i.account.login.toLowerCase() === owner.toLowerCase());
  return i ? `${i.html_url}/permissions/update` : null;
}

/** Repos the user gave the App, as "owner/name" with homepage. */
export async function userRepos(token, installations) {
  const out = [];
  for (const id of installations) {
    const d = await gh(token, "GET", `/user/installations/${id}/repositories?per_page=100`);
    for (const r of d.repositories) out.push({ full_name: r.full_name, homepage: r.homepage || "" });
  }
  return out;
}
