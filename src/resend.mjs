// Email from the site's own domain (spec #17), with the user's Resend key. The full key is only held in
// memory while we set up; the Sprite gets a sending-only key for that one domain.

async function rs(key, method, path, body) {
  const res = await fetch(`https://api.resend.com${path}`, {
    method,
    headers: { Authorization: `Bearer ${key}`, "User-Agent": "agent-keyboard-cloud", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = res.status === 401 || res.status === 403 || /api key/i.test(data.message ?? "") ? "Resend didn't accept that key. Create a Full access key on resend.com/api-keys and paste it again." : `Resend: ${data.message ?? res.statusText}`;
    throw Object.assign(new Error(msg), { status: res.status, code: res.status < 500 ? 400 : 502 });
  }
  return data;
}

/** The Resend domain `name` (created if missing), with its DNS records. */
export async function ensureDomain(key, name) {
  const { data = [] } = await rs(key, "GET", "/domains");
  const d = data.find((x) => x.name === name);
  return d ? rs(key, "GET", `/domains/${d.id}`) : rs(key, "POST", "/domains", { name });
}
export const getDomain = (key, id) => rs(key, "GET", `/domains/${id}`);
export const verifyDomain = (key, id) => rs(key, "POST", `/domains/${id}/verify`);
/** A key that can only send, and only from this domain. Returns { id, token }. */
export const sendingKey = (key, domainId, name) => rs(key, "POST", "/api-keys", { name, permission: "sending_access", domain_id: domainId });
export const deleteKey = (key, id) => rs(key, "DELETE", `/api-keys/${id}`).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
/** A record's full name: Resend gives names relative to the domain ("send", "resend._domainkey"). */
export const fqdn = (name, domain) => (!name || name === "@" || name === domain ? domain : name.endsWith(`.${domain}`) ? name : `${name}.${domain}`);
