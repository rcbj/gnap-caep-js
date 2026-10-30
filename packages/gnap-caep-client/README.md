# gnap-caep-client

A **GNAP** client library for **browser apps** ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635), the Grant Negotiation and Authorization Protocol), usable from JavaScript and TypeScript, configured from the authorization server's discovery document. It covers:

- signing users in: a grant the person approves at the authorization server (AS), whose subject information says who they are;
- caching access tokens and rotating them before they expire;
- subscribing to **CAEP** events through the OpenID Shared Signals Framework, with **one handler per CAEP event**.

In GNAP the client is its **key**. There is no `client_id` and no secret: the library generates a key in the browser (non-extractable WebCrypto), presents it in the first request, and signs every request with it using HTTP message signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)). Every access token is bound to that key.

It uses Web APIs only (`fetch`, WebCrypto, `URL`, Web Storage, IndexedDB), so it runs in browsers and in Node.js 24.22.1 or later (the release that fixes HTTP2Shell, CVE-2026-111497). Its only dependency is [`jose`](https://github.com/panva/jose).

**New to the library?** [Building a browser single-page app](docs/spa-guide.md) walks through it step by step. This README is the reference.

## Installing

```sh
npm install gnap-caep-client
```

```json
{
  "dependencies": {
    "gnap-caep-client": "^0.1.0"
  }
}
```

**Versions** are ordinary semver: `^0.1.0` takes every later 0.1 release and nothing from 0.2. **Release channels:** `latest` (the default) is built from `main`; `next` is built from `develop` as pre-releases such as `0.1.1-next.3` (`npm install gnap-caep-client@next`).

**TypeScript.** The package ships declarations generated from the source's JSDoc. Use `"module": "NodeNext"` (or a bundler's resolution) so TypeScript reads the package's `exports`. The exported types include `GNAPClientConfig`, `GrantSet`, `SSFReceiverConfig`, `SecurityEvent`, `SecurityEventHandler`, `SSFErrorContext`, `Account`, `AccountManagerOptions`, `TokenStore` and `KeyStore`.

**Loading it in the browser.** With a bundler, `import { GNAPClient } from 'gnap-caep-client'`. Without one, serve `node_modules/gnap-caep-client/src/` and `jose`'s browser build (`node_modules/jose/dist/webapi/`) and map them in an import map, as the demo does:

```html
<script type="importmap">{"imports":{"jose":"/vendor/jose/index.js","gnap-caep-client":"/lib/index.js"}}</script>
```

## Security features

| Protection | What the library does |
|---|---|
| **The key is the client** | A key pair generated with WebCrypto, **non-extractable** by default: script in the page can ask it to sign but can never read it out. `IndexedDBKeyStore` keeps it across page loads; `WebStorageKeyStore` keeps an extractable copy per tab. The JWK's `kid` is its RFC 7638 thumbprint. |
| **Every request signed** (`httpsig`, RFC 9635 section 7.3.1) | An RFC 9421 HTTP message signature over `@method`, `@target-uri`, `content-digest` (RFC 9530, SHA-256) when there is content, and `authorization` when a token is presented, with `created`, a fresh `nonce`, `keyid` and the `gnap` tag. An AS that does not list `httpsig` in `key_proofs_supported` is refused. |
| **Key-bound access tokens** | Tokens are presented as `Authorization: GNAP <token>` with a signature. A token issued with the `bearer` flag is refused (`requireBoundTokens`, default on), and a key-bound token is never rotated into a bearer one. |
| **Interaction hash** (section 4.2.3) | The redirect finish carries `hash` and `interact_ref`, never a token. The hash is recomputed from the client's nonce, the AS's nonce, `interact_ref` and the grant endpoint, and compared in constant time. It is how the client recognises its grant: each pending grant is **single use**, **expires** after `transactionTtlSec` (default 10 minutes) and is bound to the grant endpoint and key that started it. |
| **Finish hygiene** | Refuses tokens in the finish redirect (`access_token`, `value`, ... including in the fragment) and repeated parameters. |
| **Mix-up defence** (section 11.12) | The discovery document must name the configured grant endpoint, and the interaction hash covers it. |
| **Continuation and management URIs** | The AS's `continue.uri` and `manage.uri` receive tokens, so they must use TLS and be on the grant endpoint's origin. |
| **Subject information** (section 3.4) | Asks only for the `sub_id_formats` and `assertion_formats` the AS supports. `iss_sub` gives the person's `iss` and `sub`; `opaque` gives `sub` with the grant endpoint as `iss`. An `id_token` assertion is verified when `idToken` is configured (signature, `iss`, `aud`, `exp`) and must name the same `sub`; otherwise it is kept as received and **never decoded** into `claims`. |
| **Account binding** | `expectedSub` (and `AccountManager.reauthenticate()`) refuses a grant approved by anybody else (`account_mismatch`) and revokes it. |
| **TLS** | The grant endpoint, the finish URI, the interaction URI, the JWKS and every SSF URL must use `https`; loopback `http` is allowed for development. |
| **Rotation** | Concurrent rotations are merged into one request, and across tabs a Web Lock ensures a management token is never presented twice. A deletion waits for a rotation in flight. |
| **Token storage** | A `GrantSet`'s `claims` come only from the client's own validation; the response cannot set its prototype, methods, `claims` or expiry. |

**Not included:**

- Key proofs other than `httpsig` (`mtls`, `jwsd`, `jws`).
- Interaction start modes other than `redirect` (`app`, `user_code`, `user_code_uri`), and the `push` finish, which a browser cannot receive.
- Several access tokens in one grant, and tokens bound to a key other than the client's.
- A grant that waits for a person elsewhere (the AS answering with neither an interaction nor a token).
- CAEP push delivery, which a browser can't receive.

Your page also needs strict HTTP headers: a CSP with no inline script, `Referrer-Policy: no-referrer` (the interaction reference arrives in the URL) and `frame-ancestors 'none'`.

## Signing in

```js
import { GNAPClient, IndexedDBKeyStore, TokenManager } from 'gnap-caep-client';

const client = await GNAPClient.discover({
  grantEndpoint: 'https://as.example.com/gnap',       // OPTIONS here is the discovery request
  finishUri: `${location.origin}/callback`,
  access: ['ssf.read', { type: 'photo-api', actions: ['read'] }],
  subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] },
  idToken: { issuer: 'https://as.example.com' },       // verify the id_token assertion
  classId: 'my-spa',                                   // the registered application this key is an instance of
  keyStore: new IndexedDBKeyStore(),                    // one non-extractable key for this browser
});
const tokens = new TokenManager(client);               // in memory, auto-rotating

// 1. Start: the client's nonce and the continuation wait in sessionStorage.
const { url } = await client.createGrantRequest();
location.assign(url);

// 2. On /callback: the hash finds the grant (once), then the continuation returns the token.
const grant = await client.callback(location.href);
history.replaceState(null, '', '/');
console.log(grant.claims.sub);                          // who approved it
await tokens.set('user', grant);

// 3. Call APIs: Authorization: GNAP <token>, signed with the client key.
const res = await client.fetchResource(await tokens.getTokenSet('user'), 'https://api.example.com/me');

// 4. Sign out: revoke the grant (section 5.4); iya-sts then sends CAEP session-revoked for it.
await tokens.delete('user', { revoke: true });
```

A trusted client the AS issues tokens to with nobody asked gets `{ grantSet }` from `createGrantRequest()` instead of `{ url }`.

**No key registration.** In GNAP the AS knows a client by its key, and every browser makes its own. Register the **application** once (its finish URI, CORS origin and allowed rights) and pass its identifier as `classId`: the request sends it as `client.class_id`, and an AS that accepts unregistered instances of a registered client accepts each browser's key as an instance of it. iya-sts does so by default (`gnap.unregisteredInstances`), never lets such an instance skip the approval page, and sends the interaction only to the application's registered finish URI. An AS that requires every key to be registered refuses an unknown key `invalid_client`; `client.key.keyObject()` is then what to register.

## The grant after sign-in

| Method | RFC 9635 | What it does |
|---|---|---|
| `rotate(grantSet)` | 6.1 | A new access token; the old one stops working. The continuation and subject carry over. |
| `revokeToken(grantSet)` | 6.2 | Revokes the access token. |
| `modifyGrant(grantSet, { access })` | 5.3 | Moves the grant onto other access. Throws `interaction_required` if the AS needs the person again. |
| `revokeGrant(grantSet)` | 5.4 | Ends the whole grant: every token under it stops working. |

A continuation answered `too_fast` is retried after its `wait`, within `maxWaitSec` (default 10).

`GrantSet` fields: `access_token` (the value), `token_type` (`"GNAP"`), `bearer`, `flags`, `access`, `manage`, `continue`, `grant_id`, `instance_id`, `grant_endpoint`, `key_thumbprint`, `subject` (as the AS sent it), `claims` (as the client validated it), `expires_at`, `issued_at`. Methods: `isExpired(skew)`, `expiresIn()`, `canRotate()`, `sessionIds()`, `toJSON()`, `GrantSet.from(json)`.

`sessionIds()` answers `gnap-grant:<grant id>` and, for a JWT access token, `gnap-token:<jti>`: the sessions iya-sts names in a CAEP `session-revoked` when the grant or the token is revoked.

## Several accounts in one browser

`AccountManager` keeps several people signed in to one browser, with **one active account per tab**: only its grant is reachable (`getTokenSet()` takes no account) and only its token is rotated in the background. The others are dormant. The cache is shared by the tabs (IndexedDB by default).

```js
import { AccountManager } from 'gnap-caep-client';

const accounts = await new AccountManager(client, {
  onActivate: async (account, { getTokenSet }) => { /* receiver.start({ catchUp: true }) */ },
  onDeactivate: (account) => { /* stop polling */ },
  onLeave: async (account, { getTokenSet }) => { /* signed out or ended */ },
}).init();

location.assign((await accounts.signIn()).url);
const { account, added } = await accounts.handleCallback(location.href);
await accounts.activate(otherKey);
const grant = await accounts.getTokenSet();            // the ACTIVE account's
await accounts.signOut(key);                           // revokes that account's grant
```

- `reauthenticate(key)` names the person in the request's `user` (`sub_ids: [iss_sub]`) and refuses a grant approved by anybody else (`account_mismatch`, with `err.account`).
- A grant with no subject information signs nobody in: it is revoked and `no_subject` thrown.
- `identity(key)` answers `{ iss, sub, sid, email, email_verified, ... }` with `sid` the account's grant and token session ids, so `accountsForSubject(sub_id)` routes a CAEP event about a revoked grant to the account that held it.
- Statuses: `signed-in`, `tokens-missing`, `signed-out`, `ended`. Past `maxAccounts` (default 10) the account that left longest ago is forgotten.
- Events: `added`, `updated`, `activated`, `rotated`, `signed-out`, `ended`, `forgotten`, `activation_error`, `change`.

## CAEP: one handler per event

```js
import { SSFReceiver } from 'gnap-caep-client';

const caep = new SSFReceiver({
  transmitterIssuer: 'https://as.example.com',          // reads /.well-known/ssf-configuration
  // Every call carries the GNAP token, signed over the method, URI, token and body digest.
  authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
});

caep
  .onSessionRevoked(async (evt) => { /* evt.subject.session.id: gnap-grant:<id> or gnap-token:<jti> */ })
  .onTokenClaimsChange(async (evt) => { /* evt.payload.claims.access: the grant was modified */ })
  .onCredentialChange(async (evt) => { /* evt.payload.credential_type, change_type */ })
  .onAssuranceLevelChange(async (evt) => { /* evt.payload.change_direction */ })
  .onDeviceComplianceChange(async (evt) => { /* evt.payload.current_status */ })
  .onSessionEstablished(async (evt) => {})
  .onSessionPresented(async (evt) => {})
  .onRiskLevelChange(async (evt) => { /* evt.payload.current_level */ })
  .onError((err, ctx) => console.warn(ctx.phase, err));

await caep.start({ catchUp: true });                    // discover, create or reuse the stream, poll
```

**A GNAP web application's stream belongs to the application.** On iya-sts the access token's rights must include `ssf.read` (read, list, poll) or `ssf.manage` (also create, change, delete, verify), the application must declare them in `oauthAllowedScope`, and the stream hears only about people who approved a grant to the application. So one stream serves every account; route each event with `accounts.accountsForSubject(evt.subject)`.

| CAEP event | Method | `handlers` key | Notable `payload` fields |
|---|---|---|---|
| session-revoked | `onSessionRevoked` | `sessionRevoked` | — |
| token-claims-change | `onTokenClaimsChange` | `tokenClaimsChange` | `claims` |
| credential-change | `onCredentialChange` | `credentialChange` | `credential_type`, `change_type` |
| assurance-level-change | `onAssuranceLevelChange` | `assuranceLevelChange` | `current_level`, `previous_level`, `change_direction` |
| device-compliance-change | `onDeviceComplianceChange` | `deviceComplianceChange` | `previous_status`, `current_status` |
| session-established | `onSessionEstablished` | `sessionEstablished` | `fp_ua`, `acr`, `amr` |
| session-presented | `onSessionPresented` | `sessionPresented` | `fp_ua` |
| risk-level-change | `onRiskLevelChange` | `riskLevelChange` | `current_level`, `risk_reason` |
| SSF verification | `onVerification` | `verification` | `state` |
| SSF stream-updated | `onStreamUpdated` | `streamUpdated` | `status`, `reason` |

`onEventReceived` runs once for every accepted event, before the typed handlers; the default, `logEventReceived`, prints the event's name and `jti` only. `onEvent(uri, fn)`, `onAnyEvent(fn)` and `onUnhandledEvent(fn)` handle anything else, RISC included.

**SET validation:** a compact JWS with `typ` `secevent+jwt` and an asymmetric algorithm, verified against the transmitter's JWKS; `iss` the transmitter; `aud` the stream's (fails closed without one); `jti`, `iat` and exactly one event; `iat` not in the future; a stream event about this stream; a replayed `jti` dropped. **Acknowledgement:** only after the handlers ran without throwing, up to `maxDeliveryAttempts` (default 5); only a definitely invalid SET is reported as an error; polls never overlap; `stop()` sends the acknowledgements still owed; the poll endpoint must be on the transmitter's origin.

## API summary

**`GNAPClient`**: `discover(config)`, `init()`, `createGrantRequest(opts)` → `{ url }` or `{ grantSet }`, `callback(url)`, `completeGrant(url)` → `{ grantSet, context }`, `rotate`, `revokeToken`, `modifyGrant`, `revokeGrant`, `resourceHeaders(token, { method, url, body })`, `fetchResource(token, url, init)`, `securityFeatures`, `key`, `metadata`.

| Option | Default |
|---|---|
| `grantEndpoint` or `metadata` | one is required |
| `finishUri` | — (required for the redirect interaction) |
| `access` | — (required per request if not set here) |
| `subject` | `{ subIdFormats: ['iss_sub', 'opaque'] }`; `false` asks for none |
| `display` | — |
| `classId` | — (the registered application's identifier, sent as `class_id`) |
| `key`, `keyStore`, `alg` | a new non-extractable `ES256` key in memory |
| `requireBoundTokens` | `true` |
| `useInstanceId`, `instanceStore` | `false`, memory |
| `hashMethod` | `'sha-256'` (or `'sha-512'`) |
| `idToken` | — (`{ issuer, jwksUri?, audience?, algorithms? }`) |
| `transactionStore`, `transactionTtlSec` | sessionStorage, 600 |
| `maxWaitSec` | 10 |
| `allowInsecureRequests` | `false` |
| `clockToleranceSec`, `httpTimeoutMs`, `discoveryCacheTtlMs`, `fetch` | 30, 10000, 1 hour, global `fetch` |

**`TokenManager(client, { store, refreshSkewSec, autoRefresh })`**: `set`, `get`, `getTokenSet`, `rotate`, `schedule`, `unschedule`, `delete(key, { revoke: true | 'grant' | 'token' })`, `close`. Events: `rotated`, `rotation_error`, `expired`, `removed`.

**`AccountManager(client, opts)`**: `init`, `list`, `get`, `active`, `activeKey`, `identity`, `accountsForSubject`, `signIn`, `addAccount`, `reauthenticate`, `handleCallback`, `activate`, `getTokenSet`, `rotate`, `signOut`, `signOutAll`, `end`, `forget`, `close`.

**Keys and stores:** `ClientKey`, `IndexedDBKeyStore`, `WebStorageKeyStore`, `MemoryKeyStore`, `MemoryTokenStore`, `WebStorageTokenStore`, `IndexedDBTokenStore`, `TransactionStore`. **Low level:** `signRequest`, `contentDigest`, `interactionHash`, `discoverGrantServer`, `validateGrantServerMetadata`, `discoverSSFTransmitter`. **Errors:** `GNAPClientError` (with `code`), `GNAPError` (the AS's error, `error` and `error_description`), `ValidationError`, `SETValidationError`, `SSFError`.

## Tests

```sh
npm test   # from the repo root: node:test against a strict in-memory GNAP AS stub injected via `fetch`
```

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
