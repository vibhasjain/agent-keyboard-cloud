#!/usr/bin/env node
// Provision from the command line (Day 2; the web flow wraps the same function).
//   node bin/provision.mjs --creds <fly-creds.json> --email you@x.com [--repo owner/name [--domain host] | --name my-site] [--ref main]
// Env: GITHUB_TOKEN, SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY.

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { provision } from "../src/provision.mjs";

const { values: a } = parseArgs({
  options: { creds: { type: "string" }, email: { type: "string" }, repo: { type: "string" }, domain: { type: "string" }, name: { type: "string" }, ref: { type: "string" } },
});
const env = (k) => process.env[k] || (console.error(`missing env ${k}`), process.exit(2));
if (!a.creds || !a.email) {
  console.error("usage: provision.mjs --creds <fly-creds.json> --email <email> [--repo owner/name [--domain host] | --name my-site] [--ref main]");
  process.exit(2);
}

const result = await provision(
  {
    assertion: JSON.parse(readFileSync(a.creds, "utf8")).identity_assertion,
    email: a.email,
    repo: a.repo,
    domain: a.domain,
    name: a.name,
    ref: a.ref,
    githubToken: env("GITHUB_TOKEN"),
    supabase: { url: env("SUPABASE_URL"), anonKey: env("SUPABASE_ANON_KEY"), serviceKey: env("SUPABASE_SERVICE_KEY") },
  },
  (step) => console.error(`… ${step}`),
);
console.log(JSON.stringify(result, null, 2));
