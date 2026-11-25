// Claude sign-in relayed from a web page: Claude Code's own `setup-token` runs inside the
// user's Sprite (in tmux), we show its sign-in URL, and the user pastes the code back.
// The resulting token goes straight from the Sprite into a Custom API connector in the
// user's Fly account; it never reaches our servers or the Sprite's disk.

const S = "ak-login";
const PANE = `tmux capture-pane -p -J -t ${S}`;
const b64 = (s) => Buffer.from(s).toString("base64");

/** Start the login on `name`. Returns the claude.ai sign-in URL. */
export async function claudeLoginStart(api, name) {
  const { out } = await api.exec(
    name,
    `tmux kill-session -t ${S} 2>/dev/null; ` +
      `tmux new-session -d -s ${S} -x 500 -y 60 "env -u ANTHROPIC_BASE_URL -u CLAUDE_CODE_OAUTH_TOKEN ~/.local/bin/claude setup-token"; ` +
      `for i in $(seq 40); do sleep 1; ${PANE} | grep -q oauth/authorize && break; done; ` +
      `${PANE} | grep -o 'https://[^ ]*oauth/authorize[^ ]*' | head -1`,
    { timeoutMs: 90_000 },
  );
  const url = out.split("\n").find((l) => l.startsWith("https://"));
  if (!url) throw new Error("Claude's sign-in link did not appear on the Sprite");
  return url;
}

/**
 * Paste `code` into the waiting login, then, on the Sprite, create the Custom API connector
 * holding the token (policy: this Sprite only). Returns the connection id.
 */
export async function claudeLoginFinish(api, name, code, { sprites_api, sprites_token }) {
  const create = `
const t = process.env.T, api = process.env.API, st = process.env.ST, name = process.env.NAME;
const h = { Authorization: "Bearer " + st, "Content-Type": "application/json" };
const r = await fetch(api + "/oauth/connections/custom_api", { method: "POST", headers: h, body: JSON.stringify({
  name: "anthropic-" + name, base_api_url: "https://api.anthropic.com", access_token: t, auth_method: "header", auth_header_prefix: "Bearer" }) });
const d = await r.json().catch(() => ({}));
if (!r.ok) { console.error("connector: " + r.status + " " + (d.error ?? d.message ?? "")); process.exit(1); }
const id = (d.connection ?? d).id;
const p = await fetch(api + "/oauth/connections/" + id, { method: "PUT", headers: h, body: JSON.stringify({ access_policy: { name_prefix: name } }) });
if (!p.ok) { console.error("connector policy: " + p.status); process.exit(1); }
console.log("CONNECTION " + id);`;
  const { out } = await api.exec(
    name,
    `tmux has-session -t ${S} 2>/dev/null || { echo "no Claude sign-in is waiting; start again" >&2; exit 1; }; ` +
      `tmux send-keys -t ${S} -l "$(echo ${b64(code.trim())} | base64 -d)"; tmux send-keys -t ${S} Enter; ` +
      `T=; for i in $(seq 60); do sleep 1; T=$(${PANE} | tr -d ' ' | grep -o 'sk-ant-oat[A-Za-z0-9_-]*' | head -1); [ -n "$T" ] && break; done; ` +
      `TAIL=$(${PANE} | grep -v '^\\s*$' | tail -4 | grep -v sk-ant); tmux kill-session -t ${S}; ` +
      `[ -n "$T" ] || { echo "Claude sign-in did not finish: $TAIL" >&2; exit 1; }; ` +
      `T="$T" API=${b64(sprites_api)} ST=${b64(sprites_token)} NAME=${name} ` +
      `bash -c 'API=$(echo $API | base64 -d) ST=$(echo $ST | base64 -d) node --input-type=module -e "$(echo ${b64(create)} | base64 -d)"'`,
    { timeoutMs: 120_000 },
  );
  const id = out.match(/CONNECTION (\S+)/)?.[1];
  if (!id) throw new Error("connector was not created");
  return id;
}
