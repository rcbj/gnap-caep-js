---
title: Configuring gnap-caep-client
---

# Configuring gnap-caep-client

This page covers everything you set up to run `gnap-caep-client`: the authorization server's side, the client's options, where keys and tokens are kept, how people are identified, the CAEP receiver, and the page's HTTP headers. The [SPA guide](spa-guide.md) walks through building an app step by step; the [API reference](reference.md) lists every method and event.

* TOC
{:toc}

## What you configure, and where

| Where | What | Once per |
|---|---|---|
| The authorization server (AS) | The application: its finish URI, CORS origin, allowed rights | application |
| Your web server | The page, served at `/` and at the finish URI, with security headers | deployment |
| `GNAPClient` | The grant endpoint, the finish URI, the access asked for, the application's `classId`, where the key lives | page load |
| `AccountManager` or `TokenManager` | Where grants are cached, how early tokens are rotated | page load |
| `SSFReceiver` | The transmitter, the event types, the handlers | signed-in account |

**No client key is registered.** In GNAP a client is its key, and every browser makes its own. Register the **application** once; each request names it in `client.class_id`, and the AS accepts the browser's key as an instance of it.

## The authorization server

### iya-sts

The demo's [`scripts/configure-iya-sts.mjs`](https://github.com/rcbj/gnap-caep-js/blob/main/scripts/configure-iya-sts.mjs) does all of this for one application, and `--dry-run` prints each call. By hand, through the management API:

```bash
api applications/create '{
  "identifier": "my-spa", "kind": "gnap-client", "protocols": ["gnap"],
  "fields": {
    "gnapFinishUri": ["https://app.example.com/callback"],
    "gnapInteractionStartModes": ["redirect"],
    "appCorsOrigin": ["https://app.example.com"],
    "gnapInstanceId": "my-spa",
    "gnapDisplayUri": "https://app.example.com/",
    "oauthAllowedScope": ["ssf.read", "ssf.manage"]
  }}'
api roles/add-member '{"role": "SSF_READ", "kind": "application", "member": "my-spa"}'
api roles/add-member '{"role": "SSF_MANAGE", "kind": "application", "member": "my-spa"}'
```

| Attribute | Why it is needed |
|---|---|
| `kind: gnap-client`, protocol GNAP | It is a GNAP client instance's class. |
| `gnapFinishUri` | Where the browser returns after the person approves. Product mode sends the interaction **only** to a listed URI, which is what makes an unregistered browser key safe to serve. |
| `gnapInteractionStartModes: redirect` | The only start mode this library uses. |
| `appCorsOrigin` | The page calls iya-sts directly; without the origin, the browser blocks every answer. |
| `gnapInstanceId` set to the identifier | iya-sts's access tokens name the application in `client_id`, and its CORS check finds the application by `oauthClientId` or `gnapInstanceId`. Without it, the calls that present the token (the CAEP stream) get no CORS headers. |
| `oauthAllowedScope` | iya-sts grants its protected Shared Signals rights (`ssf.read`, `ssf.manage`) only to an application that declares them (`STS-GNAP-0719`). |
| `SSF_READ`, `SSF_MANAGE` role membership | The issuance policy's role check for those rights. |

The realm settings that matter, with their defaults:

| Setting | Default | What this library needs |
|---|---|---|
| `gnap.unregisteredInstances` | `true` | On: a browser's key is accepted as an instance of the application its `class_id` names. Off: every key must be registered (`invalid_client`). |
| `gnap.instanceIds` | `true` | Either. The same key at the same application gets the same `instance_id` back. |
| `gnap.keyProofs` | includes `httpsig` | `httpsig` must be offered. |
| `gnap.interactionStartModes`, `gnap.finishMethods` | include `redirect` | `redirect` must be offered for both. |
| `gnap.subIdFormats` | includes `iss_sub`, `account`, `opaque` | `iss_sub` (who), `account` (their username, `uid`). |
| `gnap.grantLifetimeS` | `86400` | How long a grant can be continued and its tokens rotated. |
| `gnap.accessTokenLifetimeS` | `3600` | How often the library rotates. |
| `gnap.continueWaitS` | `5` | The `wait` a continuation is told; the library retries `too_fast` within `maxWaitSec`. |

Every iya-sts endpoint the browser calls must also present a certificate the browser trusts. In development, open the AS's URL once and accept its certificate.

### Any GNAP authorization server

The library needs an AS that:

- answers RFC 9635 discovery (`OPTIONS` on the grant endpoint) with `grant_request_endpoint`, and allows `OPTIONS` in its CORS preflight answer;
- accepts `httpsig` key proofs (RFC 9421, with `Content-Digest`), the `redirect` start mode and the `redirect` finish method;
- accepts a key it has not seen from a browser, either for any client or as an instance of the class named in `class_id`; or else lets each key be registered;
- allows the `Signature`, `Signature-Input`, `Content-Digest` and `Authorization` request headers from your origin.

## The client: `GNAPClient`

```js
import { GNAPClient, IndexedDBKeyStore } from 'gnap-caep-client';

const client = await GNAPClient.discover({
  grantEndpoint: 'https://as.example.com/gnap',
  finishUri: `${location.origin}/callback`,
  classId: 'my-spa',
  access: ['ssf.read', 'ssf.manage'],
  subject: { subIdFormats: ['iss_sub', 'account'], assertionFormats: ['id_token'] },
  idToken: { issuer: 'https://as.example.com', audience: 'my-spa' },
  display: { name: 'My app', uri: `${location.origin}/` },
  keyStore: new IndexedDBKeyStore(),
});
```

### Required

| Option | What it is |
|---|---|
| `grantEndpoint` | The AS's grant endpoint. `discover()` sends `OPTIONS` there and checks that the answer names this endpoint (the mix-up defence). Pass `metadata` instead to skip discovery. |
| `finishUri` | Your callback page. It must use `https`, or `http` on a loopback address, and be registered at the AS. |
| `access` | The rights to ask for, by default: reference strings (`"ssf.read"`) or RFC 9635 section 8 objects (`{ type, actions, locations }`). `createGrantRequest({ access })` overrides it per request. |
| `classId` | The registered application's identifier, sent as `client.class_id`. Needed whenever the AS does not know the browser's key, which is the usual case. |

### Who the person is: `subject` and `idToken`

| Option | Default | Effect |
|---|---|---|
| `subject.subIdFormats` | `['iss_sub', 'opaque']` | RFC 9493 formats to ask for, narrowed to what the AS offers. `iss_sub` sets `claims.iss` and `claims.sub`; `opaque` is a fallback `sub`; `account` (`acct:user@host`) sets `claims.uid`, the person's username, and is what to display. |
| `subject.assertionFormats` | none | `['id_token']` asks for an OpenID Connect ID token as well. |
| `subject: false` | — | Ask for nothing: tokens only, nobody signed in. `AccountManager` needs a subject. |
| `idToken` | none | `{ issuer, jwksUri?, audience?, algorithms? }`: verify the ID token assertion against the issuer's keys (found through its OpenID configuration when `jwksUri` is absent). It must name the same `sub`, and its profile claims (`name`, `email`, `email_verified`, ...) are added to `claims`. Without `idToken`, an assertion is kept as received and **never decoded**. |

On iya-sts, ask for `account`: its ID token carries no profile claims, and `sub` is an opaque `urn:uuid:…`.

### The key

| Option | Default | Effect |
|---|---|---|
| `keyStore` | `MemoryKeyStore` | Where the key pair is kept. `IndexedDBKeyStore`: **non-extractable**, kept across tabs and restarts (recommended). `WebStorageKeyStore`: an extractable copy in sessionStorage, for this tab only. Memory: a new client instance on every page load. |
| `alg` | `ES256` | `ES256`, `ES384`, `PS256` or `RS256`. |
| `key` | — | A `ClientKey` you made yourself; overrides `keyStore`. |
| `useInstanceId` | `false` | Send the `instance_id` the AS handed out instead of the key by value. Leave it off with iya-sts's unregistered instances: the key and `class_id` already identify the browser. |
| `instanceStore` | memory | Where an `instance_id` is kept when `useInstanceId` is on. |

**Keep the key for the life of the grants.** Every token is bound to the key that made the grant. If a browser's key is lost (its site data cleared), its cached grants stop working and the person signs in again.

### Tokens and protections

| Option | Default | Effect |
|---|---|---|
| `requireBoundTokens` | `true` | Refuse a token issued with the `bearer` flag, and never rotate a bound token into a bearer one. |
| `hashMethod` | `sha-256` | The interaction hash method to ask for (`sha-256` or `sha-512`). |
| `transactionStore` | sessionStorage | Where a pending grant waits for the callback (the client's nonce, the AS's nonce, the continuation). |
| `transactionTtlSec` | `600` | How long a pending grant stays redeemable. |
| `maxWaitSec` | `10` | How long, in all, to wait out `too_fast` continuation answers. |
| `allowInsecureRequests` | `false` | Allow plain `http` beyond loopback. Development only. |
| `display` | — | `{ name, uri, logo_uri }` shown on the approval page, marked by the AS as the client's own claim. |
| `httpTimeoutMs`, `clockToleranceSec`, `discoveryCacheTtlMs`, `fetch` | `10000`, `30`, 1 hour, global `fetch` | Transport. |

## Caching grants

### One person: `TokenManager`

```js
const tokens = new TokenManager(client, { refreshSkewSec: 60 });
await tokens.set('user', await client.callback(location.href));
const grant = await tokens.getTokenSet('user');        // rotated first when due
```

| Option | Default | Effect |
|---|---|---|
| `store` | `MemoryTokenStore` | Where grants are kept. |
| `refreshSkewSec` | `60` | Rotate this early, capped at half the token's lifetime. |
| `autoRefresh` | `true` | Rotate in the background before expiry. |
| `minRefreshDelayMs`, `retryDelayMs` | `1000`, `5000` | Scheduling. |

### Several people: `AccountManager`

```js
const accounts = await new AccountManager(client, {
  store: new WebStorageTokenStore(),                    // this tab only; the default is IndexedDB
  onActivate: async (account, { getTokenSet }) => { /* start this account's CAEP receiver */ },
  onDeactivate: (account) => { /* stop it */ },
  onLeave: async (account, { getTokenSet }) => { /* signed out or ended */ },
}).init();
```

| Option | Default | Effect |
|---|---|---|
| `store` | `IndexedDBTokenStore` (memory without IndexedDB) | The grant cache shared by every tab. |
| `tabStore` | sessionStorage | Where a tab remembers its active account. |
| `storeKey` | `accounts` | Name of the account list; use one per AS. |
| `maxAccounts` | `10` | Past it, the account that left longest ago is forgotten; with every account signed in, a further sign-in is refused. |
| `rememberSignedOutDays` | `30` | How long a signed-out account stays listed. |
| `refreshSkewSec` | `60` | As for `TokenManager`. |
| `broadcast` | `true` | Tell this origin's other tabs about changes. |

Which store to choose:

| Store | Survives | Shared by tabs | Trade-off |
|---|---|---|---|
| `MemoryTokenStore` | nothing | no | Smallest exposure; sign in after every reload. |
| `WebStorageTokenStore` (sessionStorage) | reloads, the trip to the AS | no | One sign-in per tab. |
| `IndexedDBTokenStore` | closing the browser | yes | Any tab can switch to any cached account. Pair it with `IndexedDBKeyStore`. |

## CAEP: `SSFReceiver`

```js
const receiver = new SSFReceiver({
  transmitterIssuer: 'https://as.example.com',
  authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
  eventsRequested: [CAEP.SESSION_REVOKED, CAEP.CREDENTIAL_CHANGE],
  pollIntervalMs: 5000,
});
```

| Option | Default | Effect |
|---|---|---|
| `transmitterIssuer` | required | Its `/.well-known/ssf-configuration` is read. On iya-sts, the realm's base URL. |
| `authorizationHeaders` | — | Returns the headers for one call: `client.resourceHeaders(grant, req)` signs it with the key, over the body's digest. |
| `streamId` | — | Use an existing stream; keep it (for example in `localStorage`) to catch up on what was queued meanwhile. |
| `eventsRequested` | every CAEP type | The event types a new stream asks for. |
| `pollIntervalMs`, `maxEvents` | `5000`, `25` | Polling. |
| `maxDeliveryAttempts` | `5` | Redeliveries of a SET whose handler threw, before it is acknowledged anyway. |
| `maxSetAgeSec` | `0` (none) | Refuse SETs older than this. |
| `onEventReceived` | `logEventReceived` | Runs for every event before the typed handlers; `null` turns it off. |
| `trustedPollOrigins` | — | Origins besides the transmitter's that the poll endpoint may be on. |
| `deleteOnPageHide` | `false` | Delete the stream when the page unloads for good. |

**With a GNAP token, the stream belongs to the application** and, on iya-sts, hears about everybody who approved a grant to it. Route each event with `accounts.accountsForSubject(evt.subject)`. A revoked grant arrives as `session-revoked` whose session is `gnap-grant:<id>`; a revoked token, `gnap-token:<jti>`. Each account's `sid` holds both, so it matches.

## Serving the page

Serve the page at `/` and at the finish path, and send:

```http
Content-Security-Policy: default-src 'none'; script-src 'self' 'sha256-<hash of the import map>'; style-src 'self'; img-src 'self' data:; connect-src 'self' https:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store            (on the HTML page)
```

The finish redirect carries `hash` and `interact_ref` in the URL. `Referrer-Policy: no-referrer` keeps them out of `Referer` headers, and the callback should remove them with `history.replaceState`. Narrow `connect-src` to the AS's origin and your APIs' once you know them. [`demo/server.js`](https://github.com/rcbj/gnap-caep-js/blob/main/demo/server.js) is a complete server, including the import map's hash.

## A checklist

- [ ] The application is registered with its finish URI, CORS origin and the rights it asks for, and no key.
- [ ] `classId` is the application's identifier.
- [ ] The key is in `IndexedDBKeyStore` (non-extractable).
- [ ] `requireBoundTokens` is on.
- [ ] `subject.subIdFormats` includes `account` when you display the person's username.
- [ ] The page sends the headers above, and the callback strips the URL.
- [ ] The CAEP receiver catches up (`start({ catchUp: true })`) before a restored session is used, and handlers check `subjectMatches()` or `accountsForSubject()` before acting.
