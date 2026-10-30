---
title: gnap-caep-client
---

# gnap-caep-client

A **GNAP** ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) client library for **browser single-page apps**. It runs entirely in the page, with no server holding tokens, keys or secrets. It covers:

- **The client is a key:** generated in the browser, non-extractable, and proved on every request with an HTTP message signature (RFC 9421).
- **Signing in:** a grant the person approves at the authorization server through a redirect interaction, checked with the interaction hash, whose subject information (and a verified `id_token` assertion) says who they are.
- **Tokens:** key-bound access tokens, cached and rotated before they expire, safely across tabs.
- **Several accounts:** several people signed in to one browser, with one active account per tab.
- **CAEP:** the application's Shared Signals stream, with one handler per CAEP event and a hook for your own logic.

It uses Web APIs only and depends on nothing but [`jose`](https://github.com/panva/jose). It is the GNAP counterpart of [oidc-caep-client](https://rcbj.github.io/oidc-caep-client/), built against [iya-sts](https://rcbj.github.io/iya-sts/gnap.html).

## Install

```sh
npm install gnap-caep-client
```

## Where to read

- **[Configuring the module](configure.md):** the authorization server's application and settings, every client option, where keys and grants are kept, the CAEP receiver and the page's headers.
- **[Building a browser SPA](spa-guide.md):** the walkthrough, from registering the client key to signing out.
- **[API reference](reference.md):** the security features, every option, method and event.
- **Generated references:** the **[TypeScript API](api/)** (TypeDoc) and the **[JavaScript API](jsdoc/)** (JSDoc).
- **[Running the demo](demo.md):** a complete app, and how to register it on iya-sts.
- **[Development and releases](development.md):** tests, CI, branches and versioning.

## Quick look

**JavaScript**

```js
import { GNAPClient, IndexedDBKeyStore, SSFReceiver, TokenManager } from 'gnap-caep-client';

const client = await GNAPClient.discover({
  grantEndpoint: 'https://as.example.com/gnap',
  finishUri: `${location.origin}/callback`,
  access: ['ssf.read', 'ssf.manage'],
  subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] },
  keyStore: new IndexedDBKeyStore(),
});
const tokens = new TokenManager(client);

// Start a grant, then on /callback:
const grant = await client.callback(location.href);
await tokens.set('user', grant);
console.log('signed in:', grant.claims.sub);

const caep = new SSFReceiver({
  transmitterIssuer: 'https://as.example.com',
  authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
});
caep
  .onSessionRevoked(() => signOutLocally('Your grant was revoked.'))
  .onTokenClaimsChange(() => tokens.rotate('user'))
  .onError((err, ctx) => console.warn('CAEP', ctx.phase, err.message));
await caep.start({ catchUp: true });
```

**TypeScript**

```ts
import {
  GNAPClient, IndexedDBKeyStore, SSFReceiver, subjectMatches, TokenManager,
  type GrantSet, type SecurityEvent, type SSFErrorContext,
} from 'gnap-caep-client';

declare function signOutLocally(reason: string): Promise<void>;

const client: GNAPClient = await GNAPClient.discover({
  grantEndpoint: 'https://as.example.com/gnap',
  finishUri: `${location.origin}/callback`,
  access: ['ssf.read', 'ssf.manage'],
  subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] },
  keyStore: new IndexedDBKeyStore(),
});
const tokens = new TokenManager(client);

const grant: GrantSet = await client.callback(location.href);
await tokens.set('user', grant);

const caep = new SSFReceiver({
  transmitterIssuer: 'https://as.example.com',
  authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
});
caep
  .onSessionRevoked(async (evt: SecurityEvent) => {
    const me = { iss: String(grant.claims?.iss), sub: String(grant.claims?.sub), sid: grant.sessionIds() };
    if (subjectMatches(evt.subject ?? {}, me)) await signOutLocally('Your grant was revoked.');
  })
  .onError((err: Error & { code?: string }, ctx: SSFErrorContext) => console.warn('CAEP', ctx.phase, err.code));
await caep.start({ catchUp: true });
```

MIT licensed. © 2026 Iya CyberSecurity Solutions, LLC.
