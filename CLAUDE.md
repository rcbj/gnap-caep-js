# gnap-caep-js

A GNAP client (RFC 9635) for a browser application, and a CAEP receiver. The published package name is `gnap-caep-client`. The page holds a non-extractable key and identifies the registered application with a `class_id`. The source is JavaScript with JSDoc, and the only runtime dependency is `jose`.

The server-side library is [gnap-caep-risc-nodejs](https://github.com/rcbj/gnap-caep-risc-nodejs). That one holds a private key and proves it with mutual TLS, an HTTP message signature, or a detached JWS. Configuration names match where the two overlap.

Documentation: <https://rcbj.github.io/gnap-caep-js/>. The license is the MIT License in `LICENSE`. The Business Source License used by iya-sts does not apply here.

Node.js 24.22.1 or later. That is the engines field and the only version in the test matrix. It is the release that fixes HTTP2Shell (CVE-2026-111497).

## Layout

| Path | What it is |
|---|---|
| `packages/gnap-caep-client` | The library published to npm as `gnap-caep-client`. Source is `src/*.js` (`gnap-client.js`, `keys.js`, `httpsig.js`, `grant-set.js`, `accounts.js`, `caep/`). Tests are `test/`. The package is published from the source. `npm run build:types` writes declarations that are not committed. |
| `demo` | The static demo. `demo/server.js` serves `demo/public/` (`app.js`, `gnap.json`). |
| `scripts` | `configure-iya-sts.mjs` registers the finish URI on iya-sts. `version.mjs` stamps the published version. |
| `docs` | The GitHub Pages site. |
| `tools/apidocs` | TypeDoc and JSDoc. It is outside the npm workspace. It overrides minimatch to 11 (GHSA-g3hv-75wg-m249), and `minimatch-compat.mjs`, loaded before TypeDoc, restores the `matchOne()` TypeDoc 0.28.20 still calls; remove both when TypeDoc moves to minimatch 11. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose publishes `PORT` to the same host port. |

The root `package.json` is a private workspace named `gnap-caep-client-monorepo`. Committed manifests stay at `M.N.0` from the root `VERSION` file.

## Usage

```sh
npm install gnap-caep-client
```

```js
import { GNAPClient, IndexedDBKeyStore, TokenManager } from 'gnap-caep-client';

const client = await GNAPClient.discover({
  grantEndpoint: 'https://as.example.com/gnap',
  finishUri: `${location.origin}/callback`,
  access: ['ssf.read'],
  classId: 'my-spa',
  keyStore: new IndexedDBKeyStore(),
});
```

The finish URI is `location.origin` plus `/callback`. The package README is the reference.

## Tests

```sh
npm ci
npm test
npm run test:types
npm run version:check
```

`npm test` runs `node:test` on `packages/gnap-caep-client/test/*.test.js` and `scripts/*.test.mjs`, against a strict in-memory grant server, resource server, and SSF transmitter. `test:types` builds the declarations and type-checks consumers, including the `ts` examples in the documentation. `version:check` fails unless every manifest is `M.N.0`.

`.github/workflows/tests.yml` also builds the demo image and checks the page. That job publishes host port 3000. Do not run it while a demo is already bound there. The in-process commands above do not need the container.

## Live test and the nightly suite

`scripts/live_iya_sts.py` is host Python, standard library only. It starts a fresh iya-sts (`IYA_STS_IMAGE`, or a clone of `main` built here, or a running one at `IYA_STS_URL` that it never stops) on `127.0.0.1:${LIVE_STS_PORT:-18505}` with `STS_PERSISTENCE_MODE=memory`, `STS_CLUSTER_MODE=off` and no workers. It runs `scripts/configure-iya-sts.mjs` in `node:24.22.1-alpine` against a `gnap.json` pointing at that iya-sts, with `--public-url http://127.0.0.1:${LIVE_DEMO_PORT:-18605}` (the page's finish URI is `location.origin` plus `/callback`, so that origin is exactly what is registered) and the test user `gnap-demo-user`. It serves the demo image with that `gnap.json` mounted over `demo/public/gnap.json`, on the host network.

`scripts/live_browser.py` runs only in `gnap-caep-js-live:browser`, built by `scripts/live-browser.Dockerfile` from `mcr.microsoft.com/playwright/python:v1.55.0-noble` (that image has the browsers but not the `playwright` package or `certutil`), and drives headless Chromium: Sign in on the page, which starts a GNAP grant with the browser's key; iya-sts's `/gnap/interact` sends it to the `/authn` username and password screen (an optional step's skip is pressed), then to `/gnap/approve/{id}`, where every right and the subject information are ticked and Allow is pressed; iya-sts redirects to the finish URI. It keeps the page open and answers `status` on stdin with the page's `#live-status` JSON. The host script emits `credential-change` and `session-revoked` through `POST /admin-api/caep/emit` and requires the first while `signedIn` is true and the second with `signedIn` false. The page receives both by polling the application's SSF stream from the browser with its GNAP token.

`#live-status` is a hidden element `app.js` redraws with every log render: `signedIn`, the subject of the account the tab has (or last had) active, the receiver state (`connected` while polling) and its last poll error, and each received event's `type` URI and `jti`. Never a token, a grant or a payload.

The demo's signal handlers await `accounts.end()`. Ending an account stops its stream from inside the handler; until #18 `SSFReceiver.stop()` waited for the poll in flight, which was the one running the handler, so the demo had to start the end on a timer. Now `stop()` called while a polled SET's handlers run returns at once and leaves the acknowledgements (and `deleteStream`) to the end of the poll.

TLS: the host script takes the one self-signed certificate from the chain `GET /tls/server-certificate` serves (`CN = sts Root CA`), verifies iya-sts against it, and mounts it into the browser container, which adds it to Chromium's NSS database (`certutil`, trust `C,,`). The browser is never told to ignore certificate errors. Every `ssl.SSLContext` the script makes sets TLS 1.2 as the minimum. Secrets (the management API secret, the test user's password) reach containers as `-e NAME`, never on a command line, and nothing derived from them is printed. Container names: `iya-sts-live-gnap-caep-js`, `gnap-caep-js-live-demo`, `gnap-caep-js-live-browser`; images `gnap-caep-js-live:demo` and `gnap-caep-js-live:browser`. Never bind 3000, 8081 or 18481 to 18495.

`.github/workflows/nightly.yml` runs at 06:19 UTC (`19 6 * * *`) and on demand: the unit suite in `node:24.22.1-bookworm-slim`, then the live test. That image has no `openssl`, and `scripts/configure-iya-sts.test.mjs` mints the TLS suite's certificates with it, so the job installs `openssl` before `npm test` (#39). `tests.yml` has no schedule.

`scripts/configure-iya-sts.mjs` never prints a generated test-user password: it writes it to `demo/generated/<user>.password` (mode 0600) and prints the path. `demo/generated/` is in `.gitignore` and `.dockerignore`. Every management call is verified, against `--ca` (the live driver passes the root it checked) or against the root taken on first use after the host-name and link checks.

## Demo

Compose maps `${PORT:-3000}:${PORT:-3000}`. The page's finish URI is `location.origin` plus `/callback`, so registration has to use that same origin. `scripts/configure-iya-sts.mjs` sets the finish URI and the display URI on the origin for `PORT`, unless an explicit public URL is set.

```sh
npm install
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in. The image health check requests `http://127.0.0.1:${PORT}/`.

An explicit `PUBLIC_URL` replaces the origin and keeps the path. The default `http://localhost:3000` is not explicit. `pollIntervalMs` is a millisecond pause, not a port.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes nothing, so every release tag is on `main`. `M.N.P-next.R` under `next` comes only from running the workflow by hand on `main`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory (not its tests), `VERSION`, or `package-lock.json`. A change that is only this file, the demo, the docs, the tests, `scripts/version.mjs`, or that workflow does not publish. Every publish, `latest` and `next`, gets a tag and a GitHub Release; `next` is marked a pre-release. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
