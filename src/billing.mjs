// Spec 27: "Use Agent Keyboard's Claude" — a site's agent runs on our Anthropic API key through a metering proxy,
// paid for with prepaid credit bought on Stripe. Amounts are micro-dollars (1 USD = 1e6).

import { createHmac, timingSafeEqual } from "node:crypto";

export const MARKUP = 1.25;
export const FREE = 2e6; // new users' credit
export const MIN = 0.5e6; // no request below this balance, so one long turn can't run far past zero
export const DAILY = 20e6; // per-user spend cap per UTC day
export const TOPUPS = [10, 25, 50];

// $ per million tokens: [input, output, cache read]. Cache writes are 1.25× input (5 min) or 2× (1 h).
const PRICES = [
  [/opus-5-5/, 4, 20, 0.2], [/opus/, 5, 25, 0.5],
  [/fable-5-2|mythos-5-2/, 8, 40, 0.2], [/fable|mythos/, 10, 50, 1],
  [/sonnet-5-5/, 2, 10, 0.1], [/sonnet-5/, 2, 10, 0.2], [/sonnet/, 3, 15, 0.3],
  [/haiku-5-5/, 0.1, 0.5, 0.01], [/haiku/, 1, 5, 0.1],
];
/** What one response costs the user (markup included), from the model id and its `usage`. Unknown models pay Fable's price. */
export function cost(model, u = {}) {
  const [, i, o, r] = PRICES.find(([re]) => re.test(model ?? "")) ?? [, 10, 50, 1];
  const c1h = u.cache_creation?.ephemeral_1h_input_tokens ?? 0, c5m = (u.cache_creation_input_tokens ?? 0) - c1h;
  const usd = ((u.input_tokens ?? 0) * i + (u.output_tokens ?? 0) * o + (u.cache_read_input_tokens ?? 0) * r + c5m * i * 1.25 + c1h * i * 2) / 1e6
    * (u.speed === "fast" ? 2 : 1) + (u.server_tool_use?.web_search_requests ?? 0) * 0.01;
  return Math.ceil(usd * MARKUP * 1e6);
}

/**
 * Forward one Claude Code request to Anthropic on our key and stream the reply back untouched,
 * reading `usage` on the way (message_start, then each message_delta's running totals). Resolves to the cost.
 */
export async function forward(req, res, path, key) {
  let raw = Buffer.alloc(0);
  for await (const c of req) if ((raw = Buffer.concat([raw, c])).length > 64e6) throw Object.assign(new Error("too large"), { code: 413 });
  const beta = String(req.headers["anthropic-beta"] ?? "").split(",").map((s) => s.trim()).filter((s) => s && !s.startsWith("oauth-")).join(",");
  const up = await fetch(`https://api.anthropic.com${path}`, {
    method: "POST", body: raw,
    headers: { "x-api-key": key, "content-type": "application/json", "anthropic-version": req.headers["anthropic-version"] ?? "2023-06-01", ...(beta ? { "anthropic-beta": beta } : {}) },
  });
  const type = up.headers.get("content-type") ?? "application/json";
  res.writeHead(up.status, { "Content-Type": type, "Cache-Control": "no-store", ...(up.headers.get("request-id") ? { "request-id": up.headers.get("request-id") } : {}) });
  let model, usage = {}, buf = "";
  const read = (ev) => {
    if (ev.type === "message_start") { model = ev.message?.model; usage = { ...ev.message?.usage }; }
    if (ev.type === "message_delta" && ev.usage) usage = { ...usage, ...Object.fromEntries(Object.entries(ev.usage).filter(([, v]) => v != null)) };
  };
  const dec = new TextDecoder();
  for await (const chunk of up.body ?? []) {
    res.write(chunk);
    if (!type.includes("event-stream")) { buf += dec.decode(chunk, { stream: true }); continue; }
    buf += dec.decode(chunk, { stream: true });
    let n;
    while ((n = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, n); buf = buf.slice(n + 2);
      const data = block.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("");
      if (data) try { read(JSON.parse(data)); } catch {}
    }
  }
  res.end();
  if (!type.includes("event-stream") && up.ok) try { const j = JSON.parse(buf); model = j.model; usage = j.usage ?? {}; } catch {}
  return up.ok && path.startsWith("/v1/messages") && !path.includes("count_tokens") ? cost(model, usage) : 0;
}

// ---- Stripe: a Checkout Session per top-up; its webhook adds the credit ----
async function stripe(key, path, form) {
  const r = await fetch(`https://api.stripe.com/v1${path}`, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(`Stripe: ${d.error?.message ?? r.status}`), { code: 502 });
  return d;
}
/** A Stripe Checkout URL for `usd` of credit for `email`. */
export const checkout = (key, email, usd, back) => stripe(key, "/checkout/sessions", {
  mode: "payment", customer_email: email, "metadata[email]": email, "metadata[credit_usd]": String(usd),
  "line_items[0][quantity]": "1", "line_items[0][price_data][currency]": "usd", "line_items[0][price_data][unit_amount]": String(usd * 100),
  "line_items[0][price_data][product_data][name]": `Agent Keyboard credit ($${usd})`,
  success_url: `${back}?topup=done`, cancel_url: back,
}).then((d) => d.url);
/** The verified event from a Stripe webhook body, or null (signature `t=…,v1=…`, HMAC-SHA256 of "t.body", 5-minute window). */
export function stripeEvent(secret, raw, header = "") {
  const p = Object.fromEntries(header.split(",").map((kv) => kv.split("=")));
  const want = createHmac("sha256", secret).update(`${p.t}.${raw}`).digest("hex");
  const ok = header.split(",").some((kv) => kv.startsWith("v1=") && kv.length - 3 === want.length && timingSafeEqual(Buffer.from(kv.slice(3)), Buffer.from(want)));
  return ok && Math.abs(Date.now() / 1000 - Number(p.t)) < 300 ? JSON.parse(raw) : null;
}
