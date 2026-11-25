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
