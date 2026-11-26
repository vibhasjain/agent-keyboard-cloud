// Fly.io through auth.md (https://fly.io/auth.md, service_auth) and the Sprites REST API.
// We keep only the user's identity_assertion; every action mints fresh 24 h tokens.

const FLY = "https://fly.io";

async function json(res, what) {
  const body = await res.text();
  let data;
  try {
    data = body ? JSON.parse(body) : {};
  } catch {
    data = { raw: body.slice(0, 300) };
  }
  if (!res.ok) {
    const err = new Error(`${what}: ${res.status} ${data.error ?? data.message ?? data.raw ?? ""}`.trim());
    err.status = res.status;
    err.code = data.error;
    throw err;
  }
  return data;
}

/** Step 3: register for `email`. Returns { claim_token, claim: { user_code, verification_uri, interval, ... } }. */
export async function register(email) {
  const res = await fetch(`${FLY}/agent/identity`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "service_auth", login_hint: email }),
  });
  return json(res, "fly register");
}

async function token(params) {
  const res = await fetch(`${FLY}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  });
  return json(res, "fly token");
}

/** Step 4: one poll. Returns the credentials, or null while the user hasn't confirmed yet. */
export async function pollClaim(claimToken) {
  try {
    return await token({ grant_type: "urn:workos:agent-auth:grant-type:claim", claim_token: claimToken });
  } catch (e) {
    if (e.code === "authorization_pending" || e.code === "slow_down" || e.status === 503) return null;
    throw e;
  }
}

/** Step 5: fresh { access_token, sprites_token, sprites_api } from the stored assertion. */
export function mint(identityAssertion) {
  return token({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: identityAssertion });
}

/** A Sprites API client for one set of minted tokens. */
export function sprites({ sprites_api, sprites_token }) {
  const call = async (method, path, body) =>
    json(
      await fetch(`${sprites_api}${path}`, {
        method,
        headers: { Authorization: `Bearer ${sprites_token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      }),
      `sprites ${method} ${path}`,
    );
  return {
    get: (name) => call("GET", `/sprites/${name}`).then((d) => d.data ?? d),
    create: (name) => call("POST", "/sprites", { name }).then((d) => d.data ?? d),
    remove: (name) => call("DELETE", `/sprites/${name}`),
    setPublic: (name) => call("PUT", `/sprites/${name}`, { url_settings: { auth: "public" } }),
    createConnection: (body) => call("POST", "/oauth/connections/custom_api", body).then((d) => d.connection ?? d.data ?? d),
    connections: () => call("GET", "/oauth/connections").then((d) => d.connections ?? d.data ?? d),
    removeConnection: (id) => call("DELETE", `/oauth/connections/${id}`),
    setPolicy: (id, namePrefix) => call("PUT", `/oauth/connections/${id}`, { access_policy: { name_prefix: namePrefix } }),
    /** Run `bash -lc script` on the Sprite. Returns { out, code }; throws on a non-zero exit. */
    async exec(name, script, { timeoutMs = 15 * 60_000 } = {}) {
      const q = new URLSearchParams([["cmd", "bash"], ["cmd", "-lc"], ["cmd", script]]);
      const res = await fetch(`${sprites_api}/sprites/${name}/exec?${q}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sprites_token}` },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) await json(res, `sprites exec ${name}`);
      // The body is framed: 0x01 stdout / 0x02 stderr markers, then 0x03 <exit code> at the end.
      let buf = Buffer.from(await res.arrayBuffer());
      let code = null;
      if (buf.length >= 2 && buf[buf.length - 2] === 3) {
        code = buf[buf.length - 1];
        buf = buf.subarray(0, -2);
      }
      const out = Buffer.from(buf.filter((b) => b !== 1 && b !== 2))
        .toString("utf8")
        .split("\n")
        .filter((l) => !l.includes("bind: warning: line editing not enabled"))
        .join("\n")
        .trim();
      if (code !== 0) throw new Error(`exec on ${name} exited ${code}: ${out.slice(-800)}`);
      return { out, code };
    },
  };
}
