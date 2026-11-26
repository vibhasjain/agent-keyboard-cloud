// Cloudflare Pages hosting (spec #13): the user's own Cloudflare account, deployed by a GitHub
// Actions workflow in their repo. We only use their token to verify it and create the project.

const API = "https://api.cloudflare.com/client/v4";

/** The pre-filled "Create token" form: Pages edit, DNS edit, Zone read, account read. */
export const TOKEN_URL =
  "https://dash.cloudflare.com/profile/api-tokens?accountId=*&zoneId=all&name=Agent%20Keyboard&permissionGroupKeys=" +
  encodeURIComponent(JSON.stringify([
    { key: "page", type: "edit" },
    { key: "dns", type: "edit" },
    { key: "zone", type: "read" },
    { key: "account_settings", type: "read" },
  ]));

async function cf(token, method, path, body) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.success === false) {
    const msg = data.errors?.map((e) => e.message).join("; ") || res.statusText;
    throw Object.assign(new Error(`Cloudflare ${method} ${path}: ${res.status} ${msg}`), { status: res.status });
  }
  return data.result;
}

/** Cloudflare names a new account "<Email>'s Account" with the first letter capitalized; emails are lowercase. */
export const accountLabel = (name) => name?.replace(/^\S+@\S+(?='s Account$)/i, (e) => e.toLowerCase()) ?? null;

/** Check a pasted token. Returns { accountId, accountName }. */
export async function verify(token) {
  const t = await cf(token, "GET", "/user/tokens/verify").catch(() => null);
  if (t?.status !== "active") throw Object.assign(new Error("Cloudflare didn't accept that token. Copy it again from the token page."), { code: 400 });
  const accounts = await cf(token, "GET", "/accounts?per_page=50").catch(() => []);
  if (!accounts.length) throw Object.assign(new Error("That token can't see a Cloudflare account. Create it from our link so it has the right permissions."), { code: 400 });
  return { accountId: accounts[0].id, accountName: accountLabel(accounts[0].name) };
}

/** The Pages project `name` (Direct Upload), created if missing. Returns { name, subdomain } (subdomain = "x.pages.dev"). */
export async function ensureProject(token, accountId, name, productionBranch) {
  const path = `/accounts/${accountId}/pages/projects`;
  const p = (await cf(token, "GET", `${path}/${name}`).catch((e) => (e.status === 404 ? null : Promise.reject(e))))
    ?? (await cf(token, "POST", path, { name, production_branch: productionBranch }));
  return { name: p.name, subdomain: p.subdomain };
}

/** The workflow committed to the user's repo: build (if there's a build script) and deploy every branch. */
export const WORKFLOW = `# Added by Agent Keyboard: deploys every push to Cloudflare Pages
# (the live branch to production, every other branch to its own preview URL).
name: Cloudflare Pages
on: push
permissions:
  contents: read
concurrency:
  group: pages-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  deploy:
    if: \${{ vars.CLOUDFLARE_PAGES_PROJECT != '' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Build and deploy
        env:
          CLOUDFLARE_API_TOKEN: \${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: \${{ vars.CLOUDFLARE_ACCOUNT_ID }}
          PROJECT: \${{ vars.CLOUDFLARE_PAGES_PROJECT }}
        run: |
          DIR=
          if [ -f package.json ] && node -e 'process.exit(require("./package.json").scripts?.build ? 0 : 1)'; then
            if [ -f package-lock.json ]; then npm ci; else npm install; fi
            npm run build
            for d in dist build out _site; do if [ -d "$d" ]; then DIR=$d; break; fi; done
          fi
          if [ -z "$DIR" ]; then
            DIR=$RUNNER_TEMP/site; mkdir -p "$DIR"
            tar --exclude='*/.*' --exclude=./node_modules --exclude=./functions -cf - . | tar -xf - -C "$DIR"
          fi
          npx -y wrangler@4 pages deploy "$DIR" --project-name="$PROJECT" --branch="$GITHUB_REF_NAME" --commit-dirty=true
`;

/** The Sprite agent's memory once the site is on Pages (replaces the Sprite-preview staging memory). */
export function pagesMemory({ sub, live, staging, domain }) {
  const hosting = `Every push deploys to Cloudflare Pages through the GitHub Actions workflow \`.github/workflows/agent-keyboard-pages.yml\` (about a minute after the push): \`${live}\` → https://${sub}${domain ? ` and the custom domain https://${domain} (the site's real address: use it in links, metadata and replies)` : ""}, any other branch → https://<branch>.${sub} (lowercase, \`/\` → \`-\`). Never remove that workflow. The site must build to static files (Pages Functions in \`functions/\` are fine); a database has to be hosted (e.g. Supabase), not on this machine.

\`CLOUDFLARE_API_TOKEN\` and \`CLOUDFLARE_ACCOUNT_ID\` in your environment are the owner's Cloudflare token and account (Pages: Edit, DNS: Edit, Zone: Read, Account Settings: Read). Use them for DNS records on their zones and for this Pages project, never ask the owner for another token for those, and never print the token. They can't change redirect rules, page rules or other zone settings: for those, tell the owner exactly what to set in the Cloudflare dashboard.`;
  const managed = `# Managed by Agent Keyboard\n\nThis is a managed instance: it was set up and is managed at https://agentkeyboard.com/dashboard (or from Claude through the Agent Keyboard connector). You can't invite people, restart, update or delete this instance yourself. When the owner asks to add a teammate (or remove one), tell them to use Teammates on https://agentkeyboard.com/dashboard, or ask Claude with the Agent Keyboard connector (invite_teammate). They get a join link to send.\n`;
  if (!staging) return `${managed}\n# Hosting\n\n${hosting}\n`;
  return `${managed}
# Staging and live

This site is staged. Your pushes go to the \`ak-staging\` branch, previewed at https://ak-staging.${sub}. Nothing you push there reaches the live site.

${hosting}

When the owner asks to deploy, publish, ship or "go live":
1. Make sure everything is committed and pushed to \`ak-staging\`.
2. \`git fetch origin ${live}\` and merge it into \`ak-staging\` if it moved (resolve conflicts, push \`ak-staging\`).
3. \`git push origin ak-staging:${live}\`. That deploys https://${sub}, and their own host too if they have one.
4. Reply with what shipped.

Never push to \`${live}\` for any other reason.
`;
}

// ---- custom domains (M4) ----
const domains = (a, p) => `/accounts/${a}/pages/projects/${p}/domains`;
const ok404 = (e) => (e.status === 404 ? null : Promise.reject(e));
/** Attach `host` to the Pages project (fine if it already is). */
export const addPagesDomain = (token, a, p, host) =>
  cf(token, "POST", domains(a, p), { name: host }).catch((e) => (/already/i.test(e.message) ? null : Promise.reject(e)));
export const removePagesDomain = (token, a, p, host) => cf(token, "DELETE", `${domains(a, p)}/${host}`).catch(ok404);
/** Pages' view of the domain: { status: "active" | "pending" | …, verification_data, validation_data }. */
export const pagesDomain = (token, a, p, host) => cf(token, "GET", `${domains(a, p)}/${host}`);

/** The zone in this account that holds `host` (host itself or a parent), or null. */
export async function findZone(token, accountId, host) {
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const [z] = await cf(token, "GET", `/zones?name=${labels.slice(i).join(".")}&account.id=${accountId}`);
    if (z) return z;
  }
  return null;
}

/** Point `host` at the Pages project: one proxied CNAME, replacing the name's A/AAAA/CNAME records. */
export async function pointDns(token, zoneId, host, target) {
  const recs = await cf(token, "GET", `/zones/${zoneId}/dns_records?name=${host}&per_page=50`);
  const done = recs.some((r) => r.type === "CNAME" && r.content === target);
  for (const r of recs) if (["A", "AAAA", "CNAME"].includes(r.type) && !(r.type === "CNAME" && r.content === target)) await cf(token, "DELETE", `/zones/${zoneId}/dns_records/${r.id}`);
  if (!done) await cf(token, "POST", `/zones/${zoneId}/dns_records`, { type: "CNAME", name: host, content: target, proxied: true, ttl: 1 });
}

// Public DNS (DNS-over-HTTPS), for domains whose DNS isn't on Cloudflare.
async function doh(name, type) {
  const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`).then((r) => r.json()).catch(() => ({}));
  return (r.Answer ?? []).map((a) => ({ ...a, name: a.name.replace(/\.$/, ""), data: String(a.data).replace(/\.$/, "") }));
}
/** A root domain (it has its own SOA) needs its DNS on Cloudflare for Pages. */
export const isApex = async (host) => (await doh(host, "SOA")).some((a) => a.type === 6 && a.name === host);
/** What `host` is a CNAME for right now, or null. */
export const cnameOf = async (host) => (await doh(host, "CNAME")).find((a) => a.type === 5)?.data ?? null;
