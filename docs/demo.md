---
title: Running the demo
---

# Running the demo

The demo is a single-page app built on `gnap-caep-client`. The GNAP client instance runs in the browser; a small static server in one container serves the page, the library and the security headers. It holds no tokens and no keys.

## Start it

```sh
docker compose up --build
```

Open <http://localhost:3000>. The page reads [`demo/public/gnap.json`](https://github.com/rcbj/gnap-caep-js/blob/main/demo/public/gnap.json):

| Member | Default | Purpose |
|---|---|---|
| `grantEndpoint` | `https://localhost:8081/gnap` | iya-sts's grant endpoint in the default realm |
| `transmitterIssuer` | `https://localhost:8081` | the SSF transmitter |
| `idTokenIssuer` | `https://localhost:8081` | verifies the `id_token` subject assertion |
| `application` | `gnap-caep-demo` | the registered application, sent as `class_id`; also the assertion's expected audience |
| `access` | `["ssf.read", "ssf.manage"]` | the rights asked for |
| `subIdFormats`, `assertionFormats` | `["iss_sub", "opaque"]`, `["id_token"]` | who the person is |

The browser talks to iya-sts directly, so iya-sts must allow CORS from the demo's origin, and the browser must trust iya-sts's certificate: open <https://localhost:8081> once and accept it.

| Variable | Default | Purpose |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:3000` | The URL browsers use. The finish URI is `${PUBLIC_URL}/callback`. |

## Register the demo on iya-sts

Register the demo **application** once. No client key is registered: every browser makes its own, and the page names the application in each grant request's `class_id`, so iya-sts accepts the browser's key as an instance of it (`gnap.unregisteredInstances`, on by default). Such an instance always shows you the approval page.

```sh
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
```

[`scripts/configure-iya-sts.mjs`](https://github.com/rcbj/gnap-caep-js/blob/main/scripts/configure-iya-sts.mjs) gets a management API token as `sts-api-client`, then:

- creates the application `gnap-caep-demo`, kind `gnap-client`, protocol GNAP, with no key, `gnapFinishUri` (`<public-url>/callback`, the only address the interaction is sent to), `gnapInteractionStartModes` (`redirect`), `appCorsOrigin` (the demo's origin), `gnapInstanceId` (the identifier: the `client_id` in the access tokens, which iya-sts's CORS check resolves the application by), `gnapDisplayUri`, and `oauthAllowedScope` (`ssf.read ssf.manage`, the protected rights the grant asks for);
- adds the application to `SSF_READ` and `SSF_MANAGE`;
- creates a test user, `gnap-demo-user`. Its password is `GNAP_DEMO_USER_PASSWORD`, or one is generated and printed once.

| Option | Use |
|---|---|
| `--public-url url` | The demo isn't on `http://localhost:3000`. |
| `--config path` | Another GNAP file. |
| `--identifier id` | Another application identifier (set the same `application` in `gnap.json`, which the page sends as `class_id`). |
| `--test-user name`, `--no-test-user` | Name the test user, or skip it. |
| `--dry-run` | Print every management API call, and send nothing. |

The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. Every step can be repeated safely.

## What it does

- **Sign in** sends a signed grant request; iya-sts asks you to sign in and approve, sends the browser back to `/callback` with the interaction hash, and the continuation returns a key-bound access token and who you are.
- **Token cache** shows the token's expiry and the auto-rotation countdown; **Rotate now** and **Revoke this token** use its management URI.
- **Grant** shows the access token, the continuation and management URIs, the grant's CAEP session ids and the subject information.
- **CAEP events**: the application's stream, polled with the active account's token. Each event is routed to the account it names: `session-revoked` for `gnap-grant:<id>` ends the account holding that grant.

Try it: revoke the grant on your iya-sts portal (**Your account → GNAP grants**), or revoke the token from the page, and watch the event log.

## Several accounts

Each tab has one active account; the others stay signed in, dormant. **Sign out** revokes that account's grant only. A dormant account's grant can still be ended by a CAEP event the active account's poll receives.

## The server

[`demo/server.js`](https://github.com/rcbj/gnap-caep-js/blob/main/demo/server.js) serves the page (also at `/callback`), `/gnap.json`, the library and `jose` as ES modules, with a CSP allowing only this origin's scripts and the import map by its hash, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and `Cache-Control: no-store` on the page.
