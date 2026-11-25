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

/** A new public repo under the token's user, holding just `files` ({path: content}). */
export async function createRepo(token, name, description, files) {
  const repo = await gh(token, "POST", "/user/repos", { name, description, auto_init: false });
  for (const [path, content] of Object.entries(files)) {
    await gh(token, "PUT", `/repos/${repo.full_name}/contents/${path}`, {
      message: `Starter site: ${path}`,
      content: Buffer.from(content).toString("base64"),
    });
  }
  return repo;
}

/** Give the Sprite push access with its own public key (the private half never leaves it). */
export async function addDeployKey(token, fullName, title, key) {
  try {
    await gh(token, "POST", `/repos/${fullName}/keys`, { title, key, read_only: false });
  } catch (e) {
    if (e.status === 422 && /already in use/.test(e.message)) return; // re-run: same key, already there
    throw e;
  }
}

/** Commit the bar's script tag into the site's index.html, before </body>. Returns the path. */
export async function addTag(token, fullName, tag) {
  for (const path of ["index.html", "public/index.html", "site/index.html", "docs/index.html", "src/index.html"]) {
    const f = await gh(token, "GET", `/repos/${fullName}/contents/${path}`).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
    if (!f?.content) continue;
    const html = Buffer.from(f.content, "base64").toString("utf8");
    if (html.includes(tag.match(/src="([^"]+)"/)[1])) return path; // already there
    const i = html.toLowerCase().lastIndexOf("</body>");
    if (i < 0) continue;
    const next = `${html.slice(0, i)}${tag}\n${html.slice(i)}`;
    await gh(token, "PUT", `/repos/${fullName}/contents/${path}`, {
      message: "Add the Agent Keyboard bar",
      content: Buffer.from(next).toString("base64"),
      sha: f.sha,
    });
    return path;
  }
  throw Object.assign(new Error("Couldn't find an index.html with a </body> to add it to. Paste the tag into your pages yourself."), { code: 422 });
}
