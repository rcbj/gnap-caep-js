# Building a browser single-page app with gnap-caep-client

This guide shows how to build a browser single-page app (SPA) on `gnap-caep-client`. By the end, your app signs people in through a GNAP authorization server, keeps their key-bound access tokens fresh, calls your APIs with signed requests, and reacts within seconds when the authorization server reports a change through CAEP.

Everything runs in the browser. Your web server only serves files and security headers; it holds no tokens, no keys and no secrets.

The [README](../README.md) is the API reference. The demo in this repository ([`demo/`](../../../demo)) is a working app built this way.

## Contents

1. [How GNAP differs from OpenID Connect](#1-how-gnap-differs-from-openid-connect)
2. [Set up the authorization server](#2-set-up-the-authorization-server)
3. [Serve the app](#3-serve-the-app)
4. [Create the client](#4-create-the-client)
5. [Sign in](#5-sign-in)
6. [Call your APIs](#6-call-your-apis)
7. [Several accounts in one browser](#7-several-accounts-in-one-browser)
8. [Receive CAEP events](#8-receive-caep-events)
9. [Sign out](#9-sign-out)
10. [Errors](#10-errors)
11. [Security checklist](#11-security-checklist)
12. [Troubleshooting](#12-troubleshooting)

## 1. How GNAP differs from OpenID Connect

| OpenID Connect | GNAP (RFC 9635) |
|---|---|
| A registered `client_id` | A **key**: the client presents it, and signs every request with it |
| A redirect URI and `state` | A **finish URI** and an **interaction hash** over two nonces and the grant endpoint |
| An ID token says who signed in | The grant's **subject information** (`sub_ids`, optionally an `id_token` assertion) |
| Refresh tokens | **Token rotation** at the token's management URI |
| DPoP binds tokens to a key | Every token is **bound to the client key** unless the AS marks it bearer |
| RP-initiated logout | **Revoking the grant**; iya-sts then sends CAEP `session-revoked` for it |

```
 Browser (your SPA)                                   Authorization server
 ───────────────────                                  ────────────────────
 GNAPClient ── POST /gnap (signed, key by value) ───▶ grant endpoint
            ◀── interact.redirect, continue ─────────
 browser ───────────── interaction (sign in, approve) ─▶ approval page
 browser ◀──────── finish URI ?hash=…&interact_ref=…──
 GNAPClient ── POST continue (signed) ──────────────▶ access token + subject
 SSFReceiver ─ create / poll stream (GNAP token, signed) ▶ SSF transmitter
 your APIs ◀── fetchResource(): GNAP token + signature
```

## 2. Set up the authorization server

Register your app as a GNAP client instance:

| Setting | Value |
|---|---|
| Finish URI | your callback page, e.g. `https://app.example.com/callback` |
| Start modes | `redirect` |
| CORS origin | your app's origin |
| Allowed rights | what you ask for; on iya-sts the Shared Signals rights `ssf.read`, `ssf.manage` must be declared in `oauthAllowedScope` |

**Register the application, not the key.** Every browser makes its own key, kept in `IndexedDBKeyStore` so it is the same key across tabs and restarts. Nobody registers it: pass the application's identifier as `classId`, the request names it in `client.class_id`, and the AS accepts the browser's key as an instance of the application. On iya-sts that is the default (`gnap.unregisteredInstances`). Such an instance always shows the person the approval page, and the interaction goes only to the application's registered finish URI.

**CORS is required.** The browser calls the AS directly: the `OPTIONS` discovery request, the grant endpoint, continuation, token management and every SSF endpoint. Every signed request carries `Signature`, `Signature-Input` and `Content-Digest` headers, so the AS must allow them in its preflight answer (iya-sts does).

### iya-sts

[`scripts/configure-iya-sts.mjs`](../../../scripts/configure-iya-sts.mjs) does all of this for the demo: it creates the `gnap-client` application with the key, finish URI, start mode, CORS origin and SSF scopes, adds it to the `SSF_READ` and `SSF_MANAGE` roles, and creates a test user. Run it with `--dry-run` to see each management API call.

## 3. Serve the app

Serve your page at the finish path too (`/callback`): the AS sends the browser back there with `hash` and `interact_ref`. Send these headers:

```http
Content-Security-Policy: default-src 'none'; script-src 'self' 'sha256-<hash of the import map>'; style-src 'self'; connect-src 'self' https:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
Referrer-Policy: no-referrer
X-Frame-Options: DENY
Cache-Control: no-store            (on the HTML page)
```

The interaction reference arrives in the URL, so `Referrer-Policy: no-referrer` keeps it out of `Referer` headers, and the callback should remove it with `history.replaceState`. [`demo/server.js`](../../../demo/server.js) is a complete example.

## 4. Create the client

```js
import { GNAPClient, IndexedDBKeyStore } from 'gnap-caep-client';

const client = await GNAPClient.discover({
  grantEndpoint: 'https://as.example.com/gnap',
  finishUri: `${location.origin}/callback`,
  access: ['ssf.read', 'ssf.manage'],
  subject: { subIdFormats: ['iss_sub', 'opaque'], assertionFormats: ['id_token'] },
  idToken: { issuer: 'https://as.example.com', audience: 'my-app' },
  display: { name: 'My app', uri: `${location.origin}/` },
  classId: 'my-app',                             // the registered application; no key registration
  keyStore: new IndexedDBKeyStore(),
});
```

`discover()` sends `OPTIONS` to the grant endpoint (RFC 9635 section 9) and checks the answer: it must name this grant endpoint, accept `httpsig`, and offer the redirect interaction. The subject formats asked for are narrowed to those the AS supports.

## 5. Sign in

```js
const tokens = new TokenManager(client);

async function signIn() {
  const result = await client.createGrantRequest();
  if (result.url) location.assign(result.url);       // the person approves at the AS
  else await tokens.set('user', result.grantSet);     // a trusted client: issued at once
}

if (location.pathname === '/callback') {
  try {
    const grant = await client.callback(location.href);
    await tokens.set('user', grant);
    showUser(grant.claims);                            // iss, sub, and verified id_token claims
  } finally {
    history.replaceState(null, '', '/');
  }
}
```

`callback()` finds the grant the `hash` belongs to (recomputing the interaction hash with each pending grant's nonces), removes it so it can't be used twice, and continues the grant with `interact_ref`. A refusal at the AS arrives as a `GNAPError` with `error: 'user_denied'`.

**Who signed in** is `grant.claims`: `iss` and `sub` from an `iss_sub` identifier, plus `email`, `name` and the like from an `id_token` assertion when one was verified. Use `{ expectedSub }` on `createGrantRequest()` to refuse a grant approved by anybody else.

## 6. Call your APIs

```js
const grant = await tokens.getTokenSet('user');       // rotated first if due
const res = await client.fetchResource(grant, 'https://api.example.com/orders', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(order),                         // a string: its digest is signed
});
```

The request carries `Authorization: GNAP <token>` and a signature over the method, the URI, the token and the body digest. Your API verifies the signature with the key the token is bound to (on iya-sts: introspect the token at `/gnap/introspect`, RFC 9767).

## 7. Several accounts in one browser

Use `AccountManager` instead of `TokenManager`. Each tab has one active account, the others are dormant, and the cache is shared by the tabs. `signOut(key)` revokes that account's grant only. See the README's *Several accounts in one browser*.

## 8. Receive CAEP events

```js
const receiver = new SSFReceiver({
  transmitterIssuer: 'https://as.example.com',
  authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
});
receiver
  .onSessionRevoked(async (evt) => signOutLocally('Your grant was revoked.'))
  .onTokenClaimsChange(async () => tokens.rotate('user'));
await receiver.start({ catchUp: true });
```

With a GNAP token the stream is the **application's**: on iya-sts it hears about every person who approved a grant to it. Before acting, check who an event is about:

```js
const mine = subjectMatches(evt.subject, { iss: user.iss, sub: user.sub, sid: grant.sessionIds() });
```

A `session-revoked` whose session is `gnap-grant:<id>` means that grant was revoked (by the person on their portal, an administrator, or a global sign-out); `gnap-token:<jti>` means one access token was. Keep the stream id (for example in `localStorage`) and pass it as `streamId` next time, with `catchUp: true`.

## 9. Sign out

```js
await receiver.stop();
await tokens.delete('user', { revoke: true });        // DELETE on the continuation URI: the grant ends
```

GNAP has no front-channel logout: ending the grant is what signs the person out of your app. Their session at the AS is theirs to end there.

## 10. Errors

| Class | When | Examples of `code` / `error` |
|---|---|---|
| `GNAPError` | The AS answered with a GNAP error (RFC 9635 section 3.6) | `invalid_client` (unknown key, bad signature), `user_denied`, `invalid_interaction`, `invalid_continuation`, `invalid_rotation`, `too_fast`, `request_denied` |
| `ValidationError` | A response failed a check | `hash_mismatch`, `hash_missing`, `interaction_reused`, `transaction_expired`, `grant_endpoint_mismatch`, `front_channel_token`, `bearer_downgrade`, `untrusted_endpoint`, `invalid_assertion`, `subject_mismatch`, `account_mismatch` |
| `SETValidationError` | A security event was refused | `invalid_key`, `invalid_audience` |
| `SSFError` | The transmitter can't be used as configured | `untrusted_endpoint`, `insecure_endpoint` |
| `GNAPClientError` | Everything else | `network_error`, `http_error`, `insecure_endpoint`, `no_tokens`, `no_subject` |

## 11. Security checklist

- [ ] The key is non-extractable (`IndexedDBKeyStore`), and its public half is registered at the AS.
- [ ] `requireBoundTokens` is on: no bearer tokens.
- [ ] The CSP has no inline script and no `eval`, and `frame-ancestors 'none'` is set.
- [ ] `Referrer-Policy: no-referrer` is set, and the callback strips the interaction reference from the URL.
- [ ] The AS allows only your exact finish URI and your origin for CORS.
- [ ] The app asks for only the rights it uses.
- [ ] The receiver catches up (`start({ catchUp: true })`) before a restored session is used.
- [ ] CAEP handlers check `subjectMatches()` before acting.
- [ ] Signing out revokes the grant and clears any stored events.

## 12. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `invalid_client` on the first request | `classId` names no registered client the AS accepts instances of (iya-sts: a registered GNAP client with a registered finish URI, `STS-GNAP-0906`), the AS requires registered keys, or the request was altered between signing and sending (a proxy rewriting the body or the URL). |
| `network_error` / "Failed to fetch" | CORS: the AS does not list your origin, or the browser doesn't trust its certificate. |
| `hash_mismatch` on the callback | The grant was started in another tab or browser, or the finish URL was edited. Start again. |
| `transaction_expired` | The approval took longer than 10 minutes. |
| `request_denied` asking for `ssf.*` | iya-sts: the application does not declare the right in `oauthAllowedScope` (STS-GNAP-0719). |
| `invalid_request` at the grant endpoint | iya-sts: the rights name no resource server (STS-GNAP-0904). `ssf.read` names its own transmitter. |
| The SSF calls answer 401 | The token's signature did not verify, or the token was rotated or revoked. |
