/**
 * Static server for the GNAP + CAEP demo SPA.
 *
 * The GNAP client instance runs IN THE BROWSER: its key is generated there (non-extractable, in
 * IndexedDB), every request is signed there, and the access tokens are bound to that key. This process
 * holds no tokens, no keys and no configuration. It serves:
 *   /                 the SPA (also at /callback, the interaction finish URI)
 *   /lib/             the gnap-caep-client library, as ES modules
 *   /vendor/jose/     jose's Web-API build, which the library imports
 * with the response headers a browser-based OAuth client should have (see securityHeaders()).
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

const env = (name) => process.env[name] || undefined;
const PORT = Number(env('PORT') ?? 3000);
const PUBLIC_URL = (env('PUBLIC_URL') ?? `http://localhost:${PORT}`).replace(/\/+$/, '');

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const PUBLIC_DIR = join(here, 'public');
const LIB_DIR = dirname(require.resolve('gnap-caep-client'));
const JOSE_DIR = dirname(require.resolve('jose'));

// The page carries one inline script: its import map (external import maps are not supported
// everywhere). The CSP allows exactly that script by hash and nothing else inline.
const INDEX = readFileSync(join(PUBLIC_DIR, 'index.html'), 'utf8');
const importMap = /<script type="importmap">([\s\S]*?)<\/script>/.exec(INDEX)?.[1];
if (!importMap) throw new Error('index.html has no import map');
const IMPORT_MAP_HASH = `'sha256-${createHash('sha256').update(importMap).digest('base64')}'`;

/**
 * Security headers for a browser-based GNAP client (the same a browser OAuth client needs):
 * - CSP: scripts only from this origin (plus the hashed import map), no inline script or eval, no
 *   plugins, no framing; fetch() may reach any https origin (the AS is configured at run time) and
 *   loopback http for a local AS.
 * - Referrer-Policy no-referrer: the interaction finish (hash, interact_ref) is in the callback URL and
 *   must not leak to other origins through the Referer header.
 * - frame-ancestors 'none' + X-Frame-Options: no clickjacking of the sign-in button (RFC 9700 §4.16).
 * - Cross-Origin-Opener-Policy: no cross-window references into this page.
 */
function securityHeaders(_req, res, next) {
  res.set({
    'Content-Security-Policy': [
      "default-src 'none'",
      `script-src 'self' ${IMPORT_MAP_HASH}`,
      "style-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
    ].join('; '),
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  });
  next();
}

const app = express();
app.disable('x-powered-by');
app.use(securityHeaders);

// The SPA shell, at / and at the finish URI. Never cached: the callback URL carries an interaction reference.
const sendIndex = (_req, res) => res.set('Cache-Control', 'no-store').type('html').send(INDEX);
app.get(['/', '/index.html', '/callback'], sendIndex);

app.use('/lib', express.static(LIB_DIR, { index: false }));
app.use('/vendor/jose', express.static(JOSE_DIR, { index: false }));
app.use(express.static(PUBLIC_DIR, { index: false }));

app.listen(PORT, () => {
  console.log(`GNAP + CAEP demo SPA on ${PUBLIC_URL}`);
  console.log(`  interaction finish URI: ${PUBLIC_URL}/callback`);
  console.log('  The GNAP client instance runs in the browser with its own key; this server holds no tokens.');
});
