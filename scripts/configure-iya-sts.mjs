#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
/**
 * Configure a running iya-sts for the GNAP demo: register the demo as a GNAP client instance.
 *
 * In GNAP a client is its KEY, and the demo makes one in every browser (non-extractable, kept in
 * IndexedDB). Nobody registers those keys: each grant request names this application in
 * `client.class_id`, and iya-sts accepts the browser's key as an instance of it (#1216,
 * `gnap.unregisteredInstances`, on by default). The application is registered once, with no key:
 *
 *   ADMIN_API_CLIENT_SECRET=… node scripts/configure-iya-sts.mjs
 *   node scripts/configure-iya-sts.mjs --public-url http://localhost:3000
 *   node scripts/configure-iya-sts.mjs --dry-run          # print the calls, send nothing
 *
 * It writes the application in the realm the configuration file's grant endpoint is in (the default
 * realm, `<base>/admin-api`, for the default file), with:
 *
 *   - kind `gnap-client`, protocol GNAP;
 *   - no key: every browser's key is an instance of the application, named by its class_id;
 *   - `gnapFinishUri`: <public-url>/callback, the redirect finish URI. Product mode uses only a listed
 *     one, and it is what makes an unregistered browser key safe to serve: the interaction reference
 *     goes only there;
 *   - `gnapInteractionStartModes`: redirect;
 *   - `appCorsOrigin`: the demo's origin, so the browser may read iya-sts's answers;
 *   - `gnapInstanceId`: the identifier, which is the `client_id` iya-sts writes in the GNAP access
 *     tokens it issues. Its CORS check finds the application a token names through this attribute
 *     (or oauthClientId); without it the SSF calls the browser makes with the token are blocked;
 *   - `oauthAllowedScope`: the Shared Signals rights the file's `access` names (ssf.read, ssf.manage):
 *     iya-sts grants those protected rights only to an application that declares them (STS-GNAP-0719).
 *     `"signals": false` omits both, so neither is declared and neither role is added;
 *   - `gnapDisplayUri`: the demo's address, shown on the approval page.
 *
 * It also adds the application to the native roles SSF_READ and SSF_MANAGE (application members), for
 * whichever of those rights the file asks for. `"signals": false` skips both. It creates a test user
 * (default gnap-demo-user) to approve the
 * grant. Its password is GNAP_DEMO_USER_PASSWORD, or one is generated and written to
 * demo/generated/<user>.password (mode 0600); only that path is printed, never the password. An existing
 * user keeps its password. Running it again adds the same values to the existing application.
 *
 * The management API token is minted the way iya-sts/tests/tools/admin-api-token.js mints one: the
 * seeded client `sts-api-client`, `client_credentials` with HTTP Basic, audienced to
 * `<base>/admin-api`, scope `admin:read admin:write`. The secret is STS_ADMIN_API_CLIENT_SECRET or
 * ADMIN_API_CLIENT_SECRET; on the compose stack it lives in OpenBao (iya-sts docs/management-api.md).
 *
 * TLS: every call is verified. With --ca (or IYA_STS_CA), against that PEM file. Without one, the
 * script first learns the anchor on first use: it reads the chain the handshake presents, unverified,
 * requires the leaf to name the host and every certificate to be signed by the next, takes the
 * self-signed root, prints its SHA-256 to compare with iya-sts's PKI page, and verifies every
 * management call against it.
 */

import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { dirname, resolve } from 'node:path';
import { checkServerIdentity } from 'node:tls';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');
/** Where a generated test-user password is written. */
export const GENERATED_DIR = resolve(repoRoot, 'demo/generated');

export const SSF_ROLES = [
  { scope: 'ssf.read', role: 'SSF_READ' },
  { scope: 'ssf.manage', role: 'SSF_MANAGE' },
];

export function usage() {
  return `Usage: node scripts/configure-iya-sts.mjs [--config path] [--public-url url]
                                         [--identifier id]
                                         [--test-user name | --no-test-user] [--dry-run]
                                         [--ca file]

  --config       The demo's GNAP file, with grantEndpoint and access (default: demo/public/gnap.json)
  --public-url   Where the demo is served. The finish URI is <public-url>/callback
                 (default: $PUBLIC_URL). Without it, the origin is http://localhost:<port>,
                 <port> being the running demo's PORT, then $PORT, or 3000.
  --identifier   The application's identifier, which the demo sends as class_id
                 (default: the file's "application", else gnap-caep-demo)
  --test-user    The test user to create (default: gnap-demo-user). Its password is
                 $GNAP_DEMO_USER_PASSWORD, or one is generated and written to
                 demo/generated/<user>.password (mode 0600). It is never printed.
  --no-test-user Do not create a test user.
  --dry-run      Print the management API calls, and send nothing.
  --ca           PEM file to verify iya-sts against (default: $IYA_STS_CA). Without one,
                 the root iya-sts presents is taken on first use and its SHA-256 printed.

The management API secret is STS_ADMIN_API_CLIENT_SECRET or ADMIN_API_CLIENT_SECRET.`;
}

export function parseArgs(argv, env = process.env) {
  const out = {
    config: resolve(repoRoot, 'demo/public/gnap.json'),
    publicUrl: String(env.PUBLIC_URL ?? '').replace(/\/+$/, ''),
    // Set when --public-url or a non-empty PUBLIC_URL was given. The default does not count.
    publicUrlGiven: Boolean(env.PUBLIC_URL),
    testUser: 'gnap-demo-user',
    identifier: undefined,
    dryRun: false,
    help: false,
    ca: env.IYA_STS_CA ? resolve(env.IYA_STS_CA) : '',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${arg} needs a value\n${usage()}`);
      return v;
    };
    if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--config') out.config = resolve(value());
    else if (arg === '--public-url') {
      out.publicUrl = String(value()).replace(/\/+$/, '');
      out.publicUrlGiven = true;
    }
    else if (arg === '--identifier') out.identifier = String(value()).trim();
    else if (arg === '--test-user') out.testUser = String(value()).trim();
    else if (arg === '--no-test-user') out.testUser = '';
    else if (arg === '--dry-run') out.dryRun = true;
    else if (arg === '--ca') {
      const file = String(value());
      if (!file) throw new Error('--ca needs a file');
      out.ca = resolve(file);
    }
    else throw new Error(`Unknown argument ${arg}\n${usage()}`);
  }
  if (out.publicUrlGiven && !out.publicUrl) throw new Error('--public-url is empty');
  return out;
}

/** The container's PORT wins. Otherwise the environment. An empty or unusable value is absent. */
export function demoPort(envPort, containerPortValue) {
  const raw = String(containerPortValue ?? '').trim() || String(envPort ?? '').trim();
  if (!raw) return undefined;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  return port;
}

/**
 * The origin the demo is registered under. An explicit public URL is kept.
 * Otherwise it is http://localhost on the port the demo listens on, or 3000.
 */
export function publicUrlFor({ publicUrl, publicUrlGiven, envPort, containerPort: containerPortValue }) {
  if (publicUrlGiven) return publicUrl;
  return `http://localhost:${demoPort(envPort, containerPortValue) ?? 3000}`;
}

/** PORT from the running caep-demo container, when compose has one. Docker being absent is not an error. */
export function containerPort(cwd = repoRoot) {
  try {
    const id = execFileSync('docker', ['compose', 'ps', '-q', 'caep-demo'], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim().split('\n')[0];
    if (!id) return undefined;
    const env = execFileSync('docker', ['inspect', '-f', '{{range .Config.Env}}{{println .}}{{end}}', id], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    return env.split('\n').find((line) => line.startsWith('PORT='))?.slice('PORT='.length);
  } catch {
    return undefined;
  }
}

/**
 * The demo's GNAP file: its grant endpoint, the realm base the management API is under, and the
 * Shared Signals rights it asks for.
 */
export function readGnapFile(text, path = 'gnap.json') {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new Error(`Could not read ${path}: ${err.message}`);
  }
  const grantEndpoint = String(doc.grantEndpoint ?? '').trim();
  if (!grantEndpoint) throw new Error(`${path} must contain grantEndpoint`);
  const url = new URL(grantEndpoint);
  if (!/\/gnap$/.test(url.pathname)) throw new Error(`grantEndpoint must be the grant endpoint, <base>/gnap, not ${grantEndpoint}`);
  if (/^\/[^/]+\/gnap$/.test(url.pathname) && !/^\/realm\//.test(url.pathname)) {
    throw new Error(`${grantEndpoint} names an authorization server profile (/{as}/gnap); register in its realm's /gnap instead`);
  }
  const realmBase = `${url.origin}${url.pathname.replace(/\/gnap$/, '')}`;
  const access = Array.isArray(doc.access) ? doc.access : [];
  const signalsOff = doc.signals === false;
  const scopes = [...new Set(access.flatMap((r) => (typeof r === 'string' ? [r] : r?.type === 'ssf' ? (r.actions ?? []).map((a) => (a === 'write' ? 'ssf.manage' : 'ssf.read')) : []))
    .filter((s) => /^ssf\./.test(s) && !(signalsOff && (s === 'ssf.read' || s === 'ssf.manage'))))];
  return { grantEndpoint: url.href, realmBase, origin: url.origin, scopes, application: String(doc.application ?? '').trim() || undefined };
}

/**
 * Every management API call, in order, as `{ method, path, body, why }`. Pure: `main()` sends them,
 * `--dry-run` prints them.
 */
export function planFor({ file, identifier, publicUrl, testUser }) {
  const site = new URL(publicUrl);
  const finishUri = new URL('/callback', `${site.href.replace(/\/+$/, '')}/`).href;
  const displayUri = new URL('/', `${site.href.replace(/\/+$/, '')}/`).href;
  const fields = {
    gnapFinishUri: [finishUri],
    gnapInteractionStartModes: ['redirect'],
    appCorsOrigin: [site.origin],
    // CORS on iya-sts: a request presenting a GNAP access token is judged against the application its
    // `client_id` names, and a GNAP JWT's client_id is this identifier. iya-sts looks that name up in
    // oauthClientId or gnapInstanceId only, so without this every SSF and resource call presenting the
    // token gets no CORS headers and the browser blocks it.
    gnapInstanceId: identifier,
    gnapDisplayUri: displayUri,
    ...(file.scopes.length ? { oauthAllowedScope: file.scopes } : {}),
  };
  const calls = [{
    method: 'POST', path: '/applications/create', why: `create the GNAP client ${identifier}`,
    body: { identifier, kind: 'gnap-client', name: 'gnap-caep-client demo', protocols: ['gnap'], fields },
    onExists: 'update',
  }];
  for (const { scope, role } of SSF_ROLES.filter((r) => file.scopes.includes(r.scope))) {
    calls.push({ method: 'POST', path: '/roles/add-member', why: `let ${identifier} be granted ${scope}`, body: { role, kind: 'application', member: identifier } });
  }
  if (testUser) calls.push({ method: 'USER', path: '/users/create', why: `create the test user ${testUser}`, body: { username: testUser } });
  return { calls, fields, finishUri };
}

/**
 * Writes a generated password to <dir>/<username>.password, readable by its owner only, and returns the
 * path. The password itself is never printed (rcbj: a log line is not a place for a credential).
 */
export function savePassword(username, password, dir = GENERATED_DIR) {
  if (!/^[A-Za-z0-9._-]+$/.test(username)) throw new Error(`cannot name a file after the user ${JSON.stringify(username)}`);
  mkdirSync(dir, { recursive: true });
  const path = resolve(dir, `${username}.password`);
  writeFileSync(path, `${password}\n`, { mode: 0o600 });
  // writeFileSync's mode applies only when it creates the file; an existing one is narrowed too.
  chmodSync(path, 0o600);
  return path;
}

/** Single-valued attributes are SET on an existing entry; the others are ADDED to. */
export const SINGLE_VALUED = new Set(['gnapDisplayUri', 'gnapInstanceId']);

const BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const TIMEOUT_MS = 10_000;

/**
 * What a first use can still check without an anchor: the leaf names the host, and every
 * certificate is signed by the next one up. Returns the self-signed root at the top.
 */
export function rootOnFirstUse(hostname, certs) {
  if (!certs.length) throw new Error('the handshake presented no certificate');
  const mismatch = checkServerIdentity(hostname, certs[0].toLegacyObject());
  if (mismatch) throw mismatch;
  for (let i = 0; i + 1 < certs.length; i += 1) {
    if (!certs[i].checkIssued(certs[i + 1]) || !certs[i].verify(certs[i + 1].publicKey)) {
      throw new Error(`certificate ${i + 1} of the presented chain is not signed by certificate ${i + 2}`);
    }
  }
  const top = certs[certs.length - 1];
  if (top.subject !== top.issuer || !top.verify(top.publicKey)) {
    throw new Error('the presented chain does not end in a self-signed root; pass --ca with the iya-sts Root CA');
  }
  return top;
}

// The chain the handshake presents, leaf first, from a GET of /tls/server-certificate that carries
// no credential. Unverified: this is how the anchor is learned, and rootOnFirstUse() checks the chain
// before anything else is sent. Every later call is verified against the root it yields.
function presentedChain(base) {
  return new Promise((resolvePromise, reject) => {
    const u = new URL('/tls/server-certificate', base);
    const certs = [];
    const req = https.request({
      hostname: u.hostname,
      port: u.port,
      path: `${u.pathname}${u.search}`,
      method: 'GET',
      agent: false,
      minVersion: 'TLSv1.2',
      timeout: TIMEOUT_MS,
      rejectUnauthorized: false,
    }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolvePromise({ status: res.statusCode, text, certs }));
    });
    req.once('response', (res) => {
      const seen = new Set();
      let current = res.socket.getPeerCertificate(true);
      while (current?.raw && current.fingerprint256 && !seen.has(current.fingerprint256)) {
        seen.add(current.fingerprint256);
        certs.push(new X509Certificate(current.raw));
        const next = current.issuerCertificate;
        if (!next || next === current || !next.raw) break;
        current = next;
      }
    });
    req.on('timeout', () => req.destroy(new Error(`${base} did not answer within ${TIMEOUT_MS / 1000} s`)));
    req.on('error', reject);
    req.end();
  });
}

/** The PEM every management call is verified against: --ca's file, or the root taken on first use. */
export async function trustAnchor(base, caFile) {
  if (caFile) {
    const pem = readFileSync(caFile, 'utf8');
    if (!(pem.match(BLOCK) ?? []).length) throw new Error(`${caFile} holds no PEM certificate`);
    return { pem, firstUse: false };
  }
  const root = rootOnFirstUse(new URL(base).hostname, (await presentedChain(base)).certs);
  return { pem: `${root.toString().trim()}\n`, firstUse: true, root };
}

let trustedCa = '';

function request(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolvePromise, reject) => {
    const u = new URL(url);
    const payload = body === undefined ? null : Buffer.from(body);
    const req = https.request({
      hostname: u.hostname, port: u.port, path: `${u.pathname}${u.search}`, method,
      headers: payload ? { ...headers, 'content-length': payload.length } : headers,
      // Verified against trustAnchor()'s PEM, host name included.
      ca: trustedCa,
      minVersion: 'TLSv1.2',
      agent: false,
    }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolvePromise({ status: res.statusCode, text }));
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function mintAdminToken(origin, secret) {
  const audience = `${origin}/admin-api`;
  const form = `grant_type=client_credentials&scope=${encodeURIComponent('admin:read admin:write')}&resource=${encodeURIComponent(audience)}`;
  const reply = await request(`${origin}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`sts-api-client:${secret}`).toString('base64')}` },
    body: form,
  });
  if (reply.status !== 200) throw new Error(`the token endpoint answered ${reply.status} ${reply.text.slice(0, 300)}`);
  const body = JSON.parse(reply.text);
  if (!body.access_token) throw new Error('the token endpoint answered 200 with no access_token');
  return body.access_token;
}

async function admin(realmBase, token, method, path, body) {
  const reply = await request(`${realmBase}/admin-api${path}`, {
    method,
    headers: { accept: 'application/json', authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let parsed;
  try {
    parsed = reply.text ? JSON.parse(reply.text) : {};
  } catch {
    throw new Error(`${method} ${path} answered ${reply.status} with non-JSON: ${reply.text.slice(0, 300)}`);
  }
  if (reply.status === 401 || reply.status === 403) throw new Error(`${method} ${path} answered ${reply.status}: ${JSON.stringify(parsed).slice(0, 300)}`);
  return { status: reply.status, body: parsed };
}

const errorsOf = (body) => [].concat(body?.errors ?? []).map(String);

async function ensureApplication(realmBase, token, call) {
  const created = await admin(realmBase, token, 'POST', call.path, call.body);
  const { identifier, fields } = call.body;
  if (created.body.ok) {
    console.log(`Created the GNAP client ${identifier} at ${realmBase}.`);
    return;
  }
  if (!errorsOf(created.body).some((e) => /already in this registry/i.test(e))) {
    throw new Error(`POST /admin-api/applications/create refused ${identifier}: ${JSON.stringify(created.body).slice(0, 500)}`);
  }
  console.log(`${identifier} is already registered; adding the demo's values.`);
  const add = async (mode, attribute, value) => {
    const r = await admin(realmBase, token, 'POST', `/applications/${mode}`, { application: identifier, attribute, value });
    if (!r.body.ok && !errorsOf(r.body).some((e) => /already/i.test(e))) {
      throw new Error(`${mode} ${attribute}=${value} was refused: ${JSON.stringify(r.body).slice(0, 300)}`);
    }
  };
  await add('add', 'appAllowedProtocol', 'gnap');
  for (const [attribute, raw] of Object.entries(fields)) {
    if (SINGLE_VALUED.has(attribute)) {
      await add('set', attribute, raw);
    } else {
      for (const value of [].concat(raw)) await add('add', attribute, String(value));
    }
  }
}

async function grantRole(realmBase, token, call) {
  const r = await admin(realmBase, token, call.method, call.path, call.body);
  const already = errorsOf(r.body).some((e) => /already holds/i.test(e));
  if (!r.body.ok && !already) throw new Error(`adding ${call.body.member} to ${call.body.role} was refused: ${JSON.stringify(r.body).slice(0, 300)}`);
  console.log(`${call.body.member} ${already ? 'already holds' : 'now holds'} ${call.body.role}.`);
}

async function ensureTestUser(realmBase, token, username) {
  const found = await admin(realmBase, token, 'GET', `/users?user=${encodeURIComponent(username)}`);
  if (found.body.known === true) {
    console.log(`User ${username} already exists; its password is unchanged.`);
    return;
  }
  const password = process.env.GNAP_DEMO_USER_PASSWORD || '';
  // The attributes a realm's attribute policy commonly requires of every person (uid is the username).
  const attributes = { cn: `GNAP Demo ${username}`, givenName: 'GNAP', sn: 'Demo', displayName: `GNAP Demo ${username}`, mail: `${username}@gnap-demo.test` };
  const body = password
    ? { username, invent: false, credential: 'password', password, passwordConfirm: password, attributes }
    : { username, invent: false, credential: 'generate', attributes };
  const created = await admin(realmBase, token, 'POST', '/users/create', body);
  if (!created.body.ok) throw new Error(`creating ${username} was refused: ${JSON.stringify(created.body).slice(0, 300)}`);
  console.log(`Created user ${username}.`);
  if (created.body.password) console.log(`Generated password for ${username} written to ${savePassword(username, created.body.password)} (mode 0600).`);
  if (created.body.credentialError) console.warn(`WARNING: the password was not set: ${created.body.credentialError}`);
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return;
  }
  const file = readGnapFile(readFileSync(args.config, 'utf8'), args.config);
  const identifier = args.identifier || file.application || 'gnap-caep-demo';
  const publicUrl = publicUrlFor({
    publicUrl: args.publicUrl,
    publicUrlGiven: args.publicUrlGiven,
    envPort: process.env.PORT,
    containerPort: args.publicUrlGiven ? undefined : containerPort(),
  });
  const plan = planFor({ file, identifier, publicUrl, testUser: args.testUser });

  if (args.dryRun) {
    console.log(`# ${file.realmBase}/admin-api (nothing is sent)`);
    for (const c of plan.calls) console.log(`${c.method === 'USER' ? 'POST' : c.method} ${c.path}  # ${c.why}\n${JSON.stringify(c.body, null, 2)}`);
    return;
  }
  const secret = process.env.STS_ADMIN_API_CLIENT_SECRET || process.env.ADMIN_API_CLIENT_SECRET || '';
  if (!secret) throw new Error('neither STS_ADMIN_API_CLIENT_SECRET nor ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.');
  if (file.realmBase !== file.origin) {
    console.warn(`The grant endpoint is in a trust realm (${file.realmBase}); the management token is minted in the default realm.`);
  }
  const anchor = await trustAnchor(file.origin, args.ca);
  trustedCa = anchor.pem;
  if (anchor.firstUse) {
    console.log(`TLS: trusting ${file.origin}'s root on first use: ${anchor.root.subject.replace(/\n/g, ', ')}`);
    console.log(`  sha256 ${anchor.root.fingerprint256}`);
    console.log('  Compare it with the Root CA on iya-sts\'s Server configuration, PKI page, or pass --ca.');
  } else {
    console.log(`TLS: verifying ${file.origin} against ${args.ca}`);
  }
  const token = await mintAdminToken(file.origin, secret);
  for (const call of plan.calls) {
    if (call.path === '/applications/create') await ensureApplication(file.realmBase, token, call);
    else if (call.path === '/roles/add-member') await grantRole(file.realmBase, token, call);
    else if (call.method === 'USER') await ensureTestUser(file.realmBase, token, call.body.username);
  }
  console.log(`application:   ${identifier}`);
  console.log(`grant endpoint ${file.grantEndpoint}`);
  console.log(`finish URI:    ${plan.finishUri}`);
  console.log(`CORS origin:   ${new URL(publicUrl).origin}`);
  console.log(`SSF scopes:    ${file.scopes.join(' ') || '(none)'}`);
  console.log(`client keys:   none registered: each browser's key is an instance of ${identifier} (class_id)`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
