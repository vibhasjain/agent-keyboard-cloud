// GitHub calls for provisioning. Takes any token with repo rights: today a PAT,
// later a GitHub App installation token minted per action (spec #12).

const API = "https://api.github.com";

async function gh(token, method, path, body) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`github ${method} ${path}: ${res.status} ${data.message ?? ""} ${JSON.stringify(data.errors ?? "")}`.trim());
    err.status = res.status;
    throw err;
  }
  return data;
}

export const getRepo = (token, fullName) => gh(token, "GET", `/repos/${fullName}`);

/** A new private repo under the token's user, holding just `files` ({path: content}). */
export async function createRepo(token, name, description, files) {
  const repo = await gh(token, "POST", "/user/repos", { name, description, private: true, auto_init: false });
  for (const [path, content] of Object.entries(files)) {
    await gh(token, "PUT", `/repos/${repo.full_name}/contents/${path}`, {
      message: `Starter site: ${path}`,
      content: Buffer.from(content).toString("base64"),
    });
  }
  return repo;
}

/** True when the repo has nothing but a README/LICENSE/.gitignore (or no commits): no site yet. */
export async function isBlank(token, fullName) {
  const files = await gh(token, "GET", `/repos/${fullName}/contents/`).catch((e) => (e.status === 404 ? [] : Promise.reject(e)));
  return files.every((f) => /^(readme|license|copying|\.git)/i.test(f.name));
}

/** Add `path` to the repo's default branch (it must not exist yet). */
export const putFile = (token, fullName, path, content, message) =>
  gh(token, "PUT", `/repos/${fullName}/contents/${path}`, { message, content: Buffer.from(content).toString("base64") });

/** Give the Sprite push access with its own public key (the private half never leaves it). */
export async function addDeployKey(token, fullName, title, key) {
  try {
    await gh(token, "POST", `/repos/${fullName}/keys`, { title, key, read_only: false });
  } catch (e) {
    if (e.status === 422 && /already in use/.test(e.message)) return; // re-run: same key, already there
    throw e;
  }
}

const OLD_BAR = /<script\b(?=[^>]*\/widget\.js["'])(?=[^>]*\bdata-site=)[^>]*>\s*<\/script>/gi;

/** The new tag, carrying over the old tag's data-* settings it doesn't set itself (data-accent, data-theme…). */
function mergeTag(tag, old) {
  const extra = [...old.matchAll(/\s(data-[\w-]+)(?:=("[^"]*"|'[^']*'|[^\s>]+))?/g)]
    .filter((m) => !new RegExp(`\\s${m[1]}[\\s=>]`).test(tag))
    .map((m) => m[0])
    .join("");
  return tag.replace(/><\/script>$/, `${extra}></script>`);
}

/** Where an old bar tag pointed: its server's base URL (the src minus /widget.js) and site id (null for a relative src). */
function previousOf(old) {
  const src = old.match(/\ssrc=["']?([^"'\s>]+)/)?.[1], siteId = old.match(/\sdata-site=["']?([^"'\s>]+)/)?.[1];
  return /^https?:\/\//.test(src ?? "") && siteId ? { origin: src.replace(/\/widget\.js([?#].*)?$/, ""), siteId } : null;
}

/**
 * Put the bar's script tag on the site. Other Agent Keyboard bars (an older instance, or self-hosted)
 * are swapped for it on every .html page (and in code files that write the tag), keeping their data-* settings, so each page has one bar.
 * With none, it goes into the site's index.html before </body>. One commit. Returns { path: the first
 * page changed, previous: the replaced bar's { origin, siteId } or null }. With `hold`, a site that already has
 * another bar is left as it is ({ path: null, previous }): it switches once its notes are brought over or skipped.
 */
export async function addTag(token, fullName, tag, branch, hold) {
  branch ??= (await getRepo(token, fullName)).default_branch;
  const src = tag.match(/src="([^"]+)"/)[1];
  const read = async (path) => {
    const f = await gh(token, "GET", `/repos/${fullName}/contents/${path}?ref=${encodeURIComponent(branch)}`).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
    return f?.content ? Buffer.from(f.content, "base64").toString("utf8") : null;
  };
  const { tree } = await gh(token, "GET", `/repos/${fullName}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  // Pages, and code that writes the tag itself (a Pages Function, a layout component…); not dependencies or build output.
  const pages = tree
    .filter((t) => t.type === "blob" && t.size < 512e3 && /\.(html?|[cm]?[jt]sx?|vue|svelte|astro|php|py|rb|go|liquid|njk|hbs|erb|ejs)$/i.test(t.path) && !/(^|\/)(node_modules|vendor|dist|build|out|\.next|\.svelte-kit|_site)\//.test(t.path) && !/\.min\.js$/.test(t.path))
    .sort((a, b) => /\.html?$/i.test(b.path) - /\.html?$/i.test(a.path))
    .slice(0, 300);
  const changes = {};
  let current = null, previous = null;
  for (const { path } of pages) {
    const html = await read(path);
    if (!html) continue;
    if (html.includes(src)) current ??= path;
    const next = html.replace(OLD_BAR, (old) => (old.includes(src) ? old : ((previous ??= previousOf(old)), mergeTag(tag, old))));
    if (next !== html) changes[path] = next;
  }
  if (hold && previous) return { path: null, previous };
  if (!Object.keys(changes).length) {
    if (current) return { path: current, previous: null }; // already there
    // The usual places first, then any other index.html (e.g. frontend/index.html), shallowest first.
    const others = pages.map((p) => p.path).filter((p) => /(^|\/)index\.html$/i.test(p)).sort((a, b) => a.split("/").length - b.split("/").length);
    for (const path of new Set(["index.html", "public/index.html", "site/index.html", "docs/index.html", "src/index.html", ...others])) {
      const html = await read(path);
      const i = html?.toLowerCase().lastIndexOf("</body>") ?? -1;
      if (i >= 0) { changes[path] = `${html.slice(0, i)}${tag}\n${html.slice(i)}`; break; }
    }
  }
  const paths = Object.keys(changes);
  if (!paths.length) throw Object.assign(new Error("Couldn't find an index.html with a </body> to add it to. Paste the tag into your pages yourself."), { code: 422 });
  const ref = await gh(token, "GET", `/repos/${fullName}/git/ref/heads/${branch}`);
  const parent = await gh(token, "GET", `/repos/${fullName}/git/commits/${ref.object.sha}`);
  const t = await gh(token, "POST", `/repos/${fullName}/git/trees`, {
    base_tree: parent.tree.sha,
    tree: paths.map((path) => ({ path, mode: "100644", type: "blob", content: changes[path] })),
  });
  const c = await gh(token, "POST", `/repos/${fullName}/git/commits`, { message: "Add the Agent Keyboard bar", tree: t.sha, parents: [ref.object.sha] });
  await gh(token, "PATCH", `/repos/${fullName}/git/refs/heads/${branch}`, { sha: c.sha });
  return { path: paths[0], previous };
}

/** An Actions secret, sealed to the repo's public key (libsodium sealed box, as GitHub requires). */
export async function putSecret(token, fullName, name, value) {
  const { default: sodium } = await import("libsodium-wrappers");
  await sodium.ready;
  const { key, key_id } = await gh(token, "GET", `/repos/${fullName}/actions/secrets/public-key`);
  const sealed = sodium.crypto_box_seal(sodium.from_string(value), sodium.from_base64(key, sodium.base64_variants.ORIGINAL));
  await gh(token, "PUT", `/repos/${fullName}/actions/secrets/${name}`, { encrypted_value: sodium.to_base64(sealed, sodium.base64_variants.ORIGINAL), key_id });
}

/** An Actions variable (created, or updated if it exists). */
export async function putVariable(token, fullName, name, value) {
  await gh(token, "PATCH", `/repos/${fullName}/actions/variables/${name}`, { name, value }).catch((e) =>
    e.status === 404 ? gh(token, "POST", `/repos/${fullName}/actions/variables`, { name, value }) : Promise.reject(e));
}

/** Write `path` on `branch` (created or replaced). Returns false when it was already identical. */
export async function writeFile(token, fullName, branch, path, content, message) {
  const f = await gh(token, "GET", `/repos/${fullName}/contents/${path}?ref=${encodeURIComponent(branch)}`).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
  if (f?.content && Buffer.from(f.content, "base64").toString("utf8") === content) return false;
  await gh(token, "PUT", `/repos/${fullName}/contents/${path}`, { message, branch, content: Buffer.from(content).toString("base64"), ...(f ? { sha: f.sha } : {}) });
  return true;
}


/** Undo the Pages deploy setup on delete: the workflow file, the secret and the variables (each skipped when already gone). */
export async function removeDeploySetup(token, fullName, path) {
  const gone = (e) => (e.status === 404 ? null : Promise.reject(e));
  await gh(token, "DELETE", `/repos/${fullName}/actions/secrets/CLOUDFLARE_API_TOKEN`).catch(gone);
  for (const v of ["CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_PAGES_PROJECT"]) await gh(token, "DELETE", `/repos/${fullName}/actions/variables/${v}`).catch(gone);
  const f = await gh(token, "GET", `/repos/${fullName}/contents/${path}`).catch(gone);
  if (f?.sha) await gh(token, "DELETE", `/repos/${fullName}/contents/${path}`, { message: "Remove the Cloudflare Pages deploy (Agent Keyboard site deleted)", sha: f.sha });
}
