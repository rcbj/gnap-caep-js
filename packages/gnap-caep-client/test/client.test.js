import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { generateKeyPair, SignJWT } from 'jose';
import {
  AccountManager, CAEP, clearDiscoveryCache, ClientKey, contentDigest, GNAPClient, GNAPError, GrantSet, interactionHash,
  logEventReceived, MemoryTokenStore, SETValidationError, signRequest, SSF, SSFReceiver, Subject, subjectMatches,
  TokenManager, TransactionStore, validateGrantServerMetadata, WebStorageKeyStore,
} from '../src/index.js';
import { onceEvent } from '../src/util.js';
import { createStubAS } from './stub-as.js';

let as;
beforeEach(async () => {
  clearDiscoveryCache();
  as = await createStubAS();
});

const FINISH = 'https://app.test/callback';
const ACCESS = ['ssf.read', 'ssf.manage'];
const memoryStore = () => new TransactionStore({ storage: null });
const newClient = (extra = {}) => GNAPClient.discover({
  grantEndpoint: as.grantEndpoint, finishUri: FINISH, access: ACCESS, fetch: as.fetch,
  transactionStore: memoryStore(), display: { name: 'Test app' }, ...extra,
});

/** A whole grant: request, the resource owner approving, the finish redirect, the continuation. */
async function signIn(client, sub = 'alice', opts) {
  const { url } = await client.createGrantRequest(opts);
  return client.callback(as.approve(url, sub));
}

describe('configuration', () => {
  it('discovers the AS with OPTIONS on the grant endpoint, and asks only for subject formats it offers', async () => {
    const client = await newClient({ subject: { subIdFormats: ['iss_sub', 'did'], assertionFormats: ['id_token', 'verifiable-credential'] } });
    assert.equal(client.metadata.grant_request_endpoint, as.grantEndpoint);
    assert.deepEqual(client.config.subIdFormats, ['iss_sub']);
    assert.deepEqual(client.config.assertionFormats, ['id_token']);
    assert.equal(client.config.keyProof, 'httpsig');
  });

  it('is identified by a key, never by a client_id or a secret', () => {
    assert.throws(() => new GNAPClient({ grantEndpoint: as.grantEndpoint, clientId: 'x' }), /key/);
    assert.throws(() => new GNAPClient({ grantEndpoint: as.grantEndpoint, clientSecret: 's' }), /key/);
    assert.throws(() => new GNAPClient({}), /grantEndpoint/);
  });

  it('refuses an AS that does not accept httpsig, or does not offer the redirect interaction', async () => {
    await assert.rejects(GNAPClient.discover({ metadata: { ...as.metadata, key_proofs_supported: ['mtls'] }, finishUri: FINISH, fetch: as.fetch }),
      (e) => e.code === 'key_proof_not_supported');
    await assert.rejects(GNAPClient.discover({ metadata: { ...as.metadata, interaction_start_modes_supported: ['user_code'] }, finishUri: FINISH }),
      (e) => e.code === 'interaction_not_supported');
    await assert.rejects(GNAPClient.discover({ metadata: { ...as.metadata, interaction_finish_methods_supported: ['push'] }, finishUri: FINISH }),
      (e) => e.code === 'interaction_not_supported');
  });

  it('refuses a discovery document naming another grant endpoint (mix-up)', async () => {
    assert.throws(() => validateGrantServerMetadata({ grant_request_endpoint: 'https://evil.test/gnap' }, as.grantEndpoint),
      (e) => e.code === 'grant_endpoint_mismatch');
    assert.throws(() => validateGrantServerMetadata({}), /grant_request_endpoint/);
    assert.throws(() => validateGrantServerMetadata({ grant_request_endpoint: as.grantEndpoint, key_proofs_supported: 'httpsig' }), /array/);
  });

  it('requires TLS for the grant endpoint and the finish URI, except loopback', async () => {
    await assert.rejects(GNAPClient.discover({ grantEndpoint: 'http://as.test/gnap', fetch: as.fetch }), (e) => e.code === 'insecure_endpoint');
    await assert.rejects(newClient({ finishUri: 'http://app.test/callback' }), (e) => e.code === 'insecure_redirect_uri');
    await newClient({ finishUri: 'http://localhost:3000/callback' });
    await newClient({ finishUri: 'http://127.0.0.1:3000/callback' });
  });

  it('keeps a non-extractable client key by default, and a session-storage key reloads with the same thumbprint', async () => {
    const client = await newClient();
    assert.equal(client.key.keyPair.privateKey.extractable, false);
    assert.equal(client.key.publicJwk.kid, client.key.thumbprint);
    assert.equal(client.key.keyObject().proof, 'httpsig');
    assert.equal('d' in client.key.keyObject().jwk, false);

    const map = new Map();
    const storage = { getItem: (k) => (map.has(k) ? map.get(k) : null), setItem: (k, v) => map.set(k, String(v)), removeItem: (k) => map.delete(k) };
    const first = await ClientKey.loadOrCreate(new WebStorageKeyStore({ storage, key: 'k' }));
    const again = await ClientKey.loadOrCreate(new WebStorageKeyStore({ storage, key: 'k' }));
    assert.equal(first.thumbprint, again.thumbprint);
    assert.equal(first.keyPair.privateKey.extractable, true);
  });
});

describe('the grant request (RFC 9635 section 2)', () => {
  it('sends the key by value, the access, the redirect interaction with a fresh nonce, and the subject request', async () => {
    const client = await newClient({ subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] } });
    const { url } = await client.createGrantRequest();
    const r = as.state.lastGrantRequest;
    assert.deepEqual(r.access_token.access, ACCESS);
    assert.deepEqual(r.client.key, client.key.keyObject());
    assert.deepEqual(r.client.display, { name: 'Test app' });
    assert.deepEqual(r.interact.start, ['redirect']);
    assert.equal(r.interact.finish.method, 'redirect');
    assert.equal(r.interact.finish.uri, FINISH);
    assert.equal(r.interact.finish.nonce.length, 43);
    assert.deepEqual(r.subject, { sub_id_formats: ['iss_sub'], assertion_formats: ['id_token'] });
    assert.match(url, /^https:\/\/as\.test\/interact\//);
  });

  it('names the registered application in class_id, so an unregistered key is accepted as its instance', async () => {
    const client = await newClient({ classId: 'my-spa' });
    await client.createGrantRequest();
    assert.equal(as.state.lastGrantRequest.client.class_id, 'my-spa');
    assert.deepEqual(as.state.lastGrantRequest.client.key, client.key.keyObject());
  });

  it('signs it: method, target URI and Content-Digest covered, keyid the thumbprint, tag gnap', async () => {
    const client = await newClient();
    await client.createGrantRequest();
    const { components, params } = as.state.lastSignature;
    assert.deepEqual(components, ['@method', '@target-uri', 'content-digest']);
    assert.equal(params.keyid, client.key.thumbprint);
    assert.equal(params.tag, 'gnap');
    assert.ok(params.nonce);
  });

  it('is refused by the AS when the signature is not the key\'s (the stub verifies independently)', async () => {
    const client = await newClient();
    const other = await ClientKey.create();
    // Present this client's key, sign with another one.
    const body = JSON.stringify({ access_token: { access: ACCESS }, client: { key: client.key.keyObject() },
      interact: { start: ['redirect'], finish: { method: 'redirect', uri: FINISH, nonce: 'n' } } });
    const headers = { 'content-type': 'application/json', ...(await signRequest({ method: 'POST', url: as.grantEndpoint, body, key: { thumbprint: client.key.thumbprint, sign: (d) => other.sign(d) } })) };
    const res = await as.fetch(as.grantEndpoint, { method: 'POST', headers, body });
    assert.equal(res.status, 401);
  });

  it('refuses the bearer flag while bound tokens are required, and extra members that would replace its own', async () => {
    const client = await newClient();
    await assert.rejects(client.createGrantRequest({ flags: ['bearer'] }), /bearer/);
    await assert.rejects(client.createGrantRequest({ extra: { interact: {} } }), /extra may not set interact/);
    await assert.rejects(client.createGrantRequest({ access: [] }), /access is required/);
  });

  it('a trusted client is issued the token at once, with no interaction', async () => {
    as.state.trusted = true;
    const client = await newClient();
    const { grantSet, url } = await client.createGrantRequest();
    assert.equal(url, undefined);
    assert.equal(grantSet.claims.sub, 'trusted-user');
    assert.ok(grantSet.access_token);
  });

  it('signals: false requests openid and not ssf.read, and leaves the subject request', async () => {
    const urls = [];
    const fetch = (url, init) => {
      urls.push(String(url));
      return as.fetch(url, init);
    };
    const on = await newClient({ access: ['openid', 'ssf.read'], fetch });
    await on.createGrantRequest();
    const subject = as.state.lastGrantRequest.subject;
    const off = await newClient({ signals: false, access: ['openid', 'ssf.read'], fetch });
    await off.createGrantRequest();
    const access = as.state.lastGrantRequest.access_token.access;
    assert.ok(access.includes('openid'));
    assert.equal(access.includes('ssf.read'), false);
    assert.deepEqual(access, ['openid']);
    assert.deepEqual(as.state.lastGrantRequest.subject, subject);
    assert.equal(urls.some((u) => u.includes('/.well-known/ssf-configuration')), false);

    await off.createGrantRequest({
      access: ['openid', ' ssf.read ', 'ssf.manage', { type: 'ssf.read' }, { type: 'ssf.manage' }, { type: ' ssf.read' }, { type: 'photo-api', actions: ['read'] }],
    });
    assert.deepEqual(as.state.lastGrantRequest.access_token.access, ['openid', { type: ' ssf.read' }, { type: 'photo-api', actions: ['read'] }]);
    await assert.rejects(off.createGrantRequest({ access: ['ssf.read', 'ssf.manage'] }), /signals is false/);
  });

  it('omitted signals does not strip ssf.read', async () => {
    const client = await newClient({ access: ['openid', 'ssf.read'] });
    assert.equal(client.config.signals, true);
    await client.createGrantRequest();
    assert.deepEqual(as.state.lastGrantRequest.access_token.access, ['openid', 'ssf.read']);
    const explicit = await newClient({ signals: true, access: ['openid', 'ssf.read'] });
    await explicit.createGrantRequest();
    assert.deepEqual(as.state.lastGrantRequest.access_token.access, ['openid', 'ssf.read']);
  });

  it('signals: false with only ssf.read and ssf.manage throws', async () => {
    const client = await newClient({ signals: false, access: ['ssf.read', 'ssf.manage'] });
    await assert.rejects(client.createGrantRequest(), (err) => {
      assert.equal(err instanceof TypeError, true);
      assert.match(err.message, /signals is false and access has no rights left after ssf\.read and ssf\.manage were removed/);
      assert.match(err.message, /the caller must name a right this authorization server grants/);
      return true;
    });
    assert.equal(as.state.grantRequests, 0);
    const objects = await newClient({ signals: false, access: [{ type: 'ssf.read' }, ' ssf.manage '] });
    await assert.rejects(objects.createGrantRequest(), /no rights left after ssf\.read and ssf\.manage were removed/);
  });

  it('signals: "no" throws', () => {
    assert.throws(() => new GNAPClient({ grantEndpoint: as.grantEndpoint, signals: 'no' }), (err) => {
      assert.equal(err instanceof TypeError, true);
      assert.equal(err.message, 'signals must be true or false');
      return true;
    });
  });

  it('sends the instance_id by reference when asked to, signed with the same key', async () => {
    const client = await newClient({ useInstanceId: true, instanceStore: new MemoryTokenStore() });
    await signIn(client);
    await client.createGrantRequest();
    assert.match(String(as.state.lastGrantRequest.client), /^inst-/);
    await signIn(client, 'bob');
  });
});

describe('the finish redirect and the continuation', () => {
  it('signs in: the hash recognises the grant, the continuation returns a key-bound token and the subject', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    assert.equal(grant.token_type, 'GNAP');
    assert.equal(grant.bearer, false);
    assert.equal(grant.claims.iss, as.issuer);
    assert.equal(grant.claims.sub, 'alice');
    assert.equal(grant.grant_endpoint, as.grantEndpoint);
    assert.equal(grant.key_thumbprint, client.key.thumbprint);
    assert.ok(grant.manage.uri.startsWith(as.issuer));
    assert.ok(grant.grant_id);
    assert.deepEqual(grant.access, ACCESS);
    assert.ok(grant.expires_at > Math.floor(Date.now() / 1000));
    assert.deepEqual(as.state.lastSignature.components, ['@method', '@target-uri', 'content-digest', 'authorization']);
  });

  it('computes the interaction hash of RFC 9635 section 4.2.3', async () => {
    const { createHash } = await import('node:crypto');
    const parts = ['VJLO6A4CATR0KRO', 'MBDOFXG4Y5CVJCX821LH', '4IFWWIKYB2PQ6U56NL1', 'https://server.example.com/tx'];
    assert.equal(await interactionHash(...parts), createHash('sha256').update(parts.join('\n')).digest('base64url'));
    assert.equal(await interactionHash(...parts, 'sha-512'), createHash('sha512').update(parts.join('\n')).digest('base64url'));
    const client = await newClient({ hashMethod: 'sha-512' });
    await signIn(client);
    assert.equal(as.state.lastGrantRequest.interact.finish.hash_method, 'sha-512');
  });

  it('accepts each finish once', async () => {
    const client = await newClient();
    const { url } = await client.createGrantRequest();
    const back = as.approve(url);
    await client.callback(back);
    await assert.rejects(client.callback(back), (e) => e.code === 'interaction_reused');
  });

  it('refuses a tampered hash or interact_ref, and keeps the genuine finish usable', async () => {
    const client = await newClient();
    const { url } = await client.createGrantRequest();
    const back = new URL(as.approve(url));
    const tampered = new URL(back);
    tampered.searchParams.set('interact_ref', 'forged');
    await assert.rejects(client.callback(tampered.href), (e) => e.code === 'hash_mismatch');
    const noHash = new URL(back);
    noHash.searchParams.delete('hash');
    await assert.rejects(client.callback(noHash.href), (e) => e.code === 'hash_missing');
    assert.equal((await client.callback(back.href)).claims.sub, 'alice');
  });

  it('tells two grants in progress apart by their hashes', async () => {
    const client = await newClient();
    const one = await client.createGrantRequest({ context: { n: 1 } });
    const two = await client.createGrantRequest({ context: { n: 2 } });
    const backTwo = as.approve(two.url, 'bob');
    const backOne = as.approve(one.url, 'alice');
    const b = await client.completeGrant(backTwo);
    const a = await client.completeGrant(backOne);
    assert.deepEqual([a.context.n, a.grantSet.claims.sub, b.context.n, b.grantSet.claims.sub], [1, 'alice', 2, 'bob']);
  });

  it('expires a pending grant after transactionTtlSec', async () => {
    const store = memoryStore();
    const client = await newClient({ transactionStore: store, transactionTtlSec: 60 });
    const { url } = await client.createGrantRequest();
    const [id] = store.ids();
    store.set(id, { ...store.peek(id), createdAt: Date.now() - 61_000 });
    await assert.rejects(client.callback(as.approve(url)), (e) => e.code === 'transaction_expired');
  });

  it('refuses tokens in the front channel and repeated parameters', async () => {
    const client = await newClient();
    const { url } = await client.createGrantRequest();
    const back = as.approve(url);
    await assert.rejects(client.callback(`${back}&access_token=stolen`), (e) => e.code === 'front_channel_token');
    await assert.rejects(client.callback(`${back}#value=x`), (e) => e.code === 'front_channel_token');
    await assert.rejects(client.callback(`${back}&interact_ref=other`), (e) => e.code === 'duplicate_parameter');
  });

  it('a denial is user_denied, with the request\'s context', async () => {
    const client = await newClient();
    const { url } = await client.createGrantRequest({ context: { from: '/orders' } });
    await assert.rejects(client.completeGrant(as.approve(url, 'alice', { deny: true })),
      (e) => e instanceof GNAPError && e.error === 'user_denied' && e.context.from === '/orders');
  });

  it('waits and retries once when the continuation is too_fast, with the continue object the error carries', async () => {
    const client = await newClient();
    const { url } = await client.createGrantRequest();
    as.state.tooFastOnce = true;
    const started = Date.now();
    assert.equal((await client.callback(as.approve(url))).claims.sub, 'alice');
    assert.ok(Date.now() - started >= 900);
  });

  it('refuses a grant approved by somebody other than the person expected, and revokes it', async () => {
    const client = await newClient();
    const { url } = await client.createGrantRequest({ expectedSub: 'alice' });
    await assert.rejects(client.callback(as.approve(url, 'mallory')), (e) => e.code === 'account_mismatch');
    assert.equal(as.state.revokedGrants.length, 1);
  });

  it('never sends a continuation or management token off the grant endpoint\'s origin', async () => {
    const fetch = async (input, init) => {
      const res = await as.fetch(input, init);
      if (String(input) !== as.grantEndpoint || (init?.method ?? 'GET') !== 'POST') return res;
      const body = await res.json();
      body.continue.uri = 'https://evil.test/continue';
      return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    };
    const client = await newClient({ fetch });
    await assert.rejects(client.createGrantRequest(), (e) => e.code === 'untrusted_endpoint');
  });
});

describe('subject information (who signed in)', () => {
  it('verifies an id_token assertion and adds its profile claims', async () => {
    const client = await newClient({ subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] }, idToken: { issuer: as.issuer, audience: 'demo-client' } });
    const grant = await signIn(client, 'carol');
    assert.equal(grant.claims.sub, 'carol');
    assert.equal(grant.claims.email, 'carol@example.com');
    assert.equal(grant.claims.email_verified, true);
    assert.equal(grant.claims.assertion_verified, true);
  });

  it('refuses an id_token about somebody else, or from the wrong audience', async () => {
    const client = await newClient({ subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] }, idToken: { issuer: as.issuer } });
    as.state.idTokenSub = 'mallory';
    await assert.rejects(signIn(client, 'carol'), (e) => e.code === 'subject_mismatch');
    as.state.idTokenSub = undefined;
    const wrongAud = await newClient({ subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] }, idToken: { issuer: as.issuer, audience: 'someone-else' } });
    await assert.rejects(signIn(wrongAud, 'carol'), (e) => e.code === 'invalid_assertion');
  });

  it('keeps an assertion it cannot verify without decoding it into claims', async () => {
    const client = await newClient({ subject: { subIdFormats: ['iss_sub'], assertionFormats: ['id_token'] } });
    const grant = await signIn(client, 'dave');
    assert.equal(grant.claims.sub, 'dave');
    assert.equal(grant.claims.email, undefined);
    assert.equal(grant.subject.assertions[0].format, 'id_token');
  });

  it('takes the username (uid) from an account identifier, where sub names nobody readable', async () => {
    const client = await newClient({ subject: { subIdFormats: ['iss_sub', 'account'] } });
    const grant = await signIn(client, 'frank.o');
    assert.equal(grant.claims.sub, 'frank.o');
    assert.equal(grant.claims.uid, 'frank.o');
    assert.equal(grant.claims.account, 'acct:frank.o@as.test');
    const without = await signIn(await newClient(), 'gina');
    assert.equal(without.claims.uid, undefined, 'no account identifier asked for, so no uid');
  });

  it('falls back to an opaque identifier, with the grant endpoint as iss', async () => {
    const client = await newClient({ subject: { subIdFormats: ['opaque'] } });
    const grant = await signIn(client, 'erin');
    assert.equal(grant.claims.sub, 'op-erin');
    assert.equal(grant.claims.iss, as.grantEndpoint);
  });
});

describe('key-bound access tokens', () => {
  it('calls a resource server with Authorization: GNAP and a signature over the token and the body', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    const res = await client.fetchResource(grant, 'https://rs.test/api/orders', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"n":1}' });
    assert.equal(res.status, 200);
    assert.deepEqual((await res.json()).echoed, { n: 1 });
    assert.deepEqual(as.state.lastSignature.components, ['@method', '@target-uri', 'content-digest', 'authorization']);
  });

  it('the same token with no signature, or signed by another key, is refused by the resource server', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    const unsigned = await as.fetch('https://rs.test/api', { headers: { authorization: `GNAP ${grant.access_token}` } });
    assert.equal(unsigned.status, 401);
    const thief = await newClient();
    assert.equal((await thief.fetchResource(grant, 'https://rs.test/api')).status, 401);
  });

  it('refuses a bearer token when bound tokens are required, and accepts it when they are not', async () => {
    as.state.issueBearer = true;
    await assert.rejects(signIn(await newClient()), (e) => e.code === 'bearer_downgrade');
    const lax = await newClient({ requireBoundTokens: false });
    const grant = await signIn(lax);
    assert.equal(grant.bearer, true);
    assert.deepEqual(await lax.resourceHeaders(grant, { url: 'https://rs.test/api' }), { authorization: `GNAP ${grant.access_token}` });
  });

  it('a signed body must be a string, so its digest can be signed', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    await assert.rejects(client.resourceHeaders(grant, { url: 'https://rs.test/api', method: 'POST', body: new Uint8Array(2) }), TypeError);
    assert.equal(await contentDigest('{"hello": "world"}'), 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:');
  });
});

describe('token management, modification and revocation', () => {
  it('rotates the access token: the old one stops working, the grant and subject carry over', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    const next = await client.rotate(grant);
    assert.notEqual(next.access_token, grant.access_token);
    assert.equal(next.claims.sub, 'alice');
    assert.equal(next.grant_id, grant.grant_id);
    assert.deepEqual(next.continue, grant.continue);
    assert.equal((await client.fetchResource(grant, 'https://rs.test/api')).status, 401);
    assert.equal((await client.fetchResource(next, 'https://rs.test/api')).status, 200);
  });

  it('never rotates a key-bound token into a bearer one', async () => {
    const client = await newClient({ requireBoundTokens: false });
    const grant = await signIn(client);
    as.state.issueBearer = true;
    await assert.rejects(client.rotate(grant), (e) => e.code === 'bearer_downgrade');
  });

  it('modifies the grant onto other access', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    const narrowed = await client.modifyGrant(grant, { access: ['ssf.read'] });
    assert.deepEqual(narrowed.access, ['ssf.read']);
    assert.equal(narrowed.claims.sub, 'alice');
  });

  it('revokes a token, and revokes the whole grant', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    assert.equal(await client.revokeToken(grant), true);
    assert.equal((await client.fetchResource(grant, 'https://rs.test/api')).status, 401);
    const second = await signIn(client);
    assert.equal(await client.revokeGrant(second), true);
    assert.deepEqual(as.state.revokedGrants, [second.grant_id]);
    await assert.rejects(client.rotate(second), (e) => e instanceof GNAPError && e.error === 'invalid_rotation');
  });

  it('names its sessions the way iya-sts names them in a CAEP event', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    const [g, t] = grant.sessionIds();
    assert.equal(g, `gnap-grant:${grant.grant_id}`);
    assert.match(t, /^gnap-token:[0-9a-f]{32}$/);
  });

  it('builds a GrantSet without letting the response set its prototype, claims or methods', () => {
    const ts = new GrantSet(JSON.parse('{"access_token":"a","__proto__":{"polluted":true},"claims":{"sub":"evil"},"isExpired":true,"expires_in":60}'));
    assert.ok(ts instanceof GrantSet);
    assert.equal(ts.polluted, undefined);
    assert.equal(ts.claims, undefined);
    assert.equal(ts.isExpired(), false);
    assert.equal(GrantSet.from(ts.toJSON()).expires_at, ts.expires_at);
  });
});

describe('TokenManager', () => {
  it('rotates on demand inside the skew window', async () => {
    as = await createStubAS({ tokenTtl: 2 });
    const client = await newClient();
    const tm = new TokenManager(client, { refreshSkewSec: 5, autoRefresh: false });
    const initial = await tm.set('u', await signIn(client));
    assert.equal((await tm.getTokenSet('u')).access_token, initial.access_token, 'still fresh');
    await new Promise((r) => setTimeout(r, 1100));
    const ts = await tm.getTokenSet('u');
    assert.notEqual(ts.access_token, initial.access_token);
  });

  it('coalesces concurrent rotations', async () => {
    const client = await newClient();
    const tm = new TokenManager(client, { autoRefresh: false });
    await tm.set('u', await signIn(client));
    const [a, b] = await Promise.all([tm.rotate('u'), tm.rotate('u')]);
    assert.equal(as.state.rotations, 1);
    assert.equal(a.access_token, b.access_token);
  });

  it('rotates automatically in the background before expiry', async () => {
    as = await createStubAS({ tokenTtl: 2 });
    const client = await newClient();
    const tm = new TokenManager(client, { refreshSkewSec: 1, minRefreshDelayMs: 50 });
    const initial = await tm.set('u', await signIn(client));
    const keepAlive = setInterval(() => {}, 100);
    try {
      const [key, rotated] = await onceEvent(tm, 'rotated');
      assert.equal(key, 'u');
      assert.notEqual(rotated.access_token, initial.access_token);
    } finally {
      clearInterval(keepAlive);
      tm.close();
    }
  });

  it('drops the grant when the AS refuses to rotate it', async () => {
    const client = await newClient();
    const tm = new TokenManager(client, { autoRefresh: false });
    const ts = await tm.set('u', await signIn(client));
    await client.revokeGrant(ts);
    as.state.manage.clear();
    const expired = onceEvent(tm, 'expired');
    await assert.rejects(tm.rotate('u'), (e) => e.error === 'invalid_rotation');
    await expired;
    assert.equal(await tm.get('u'), undefined);
  });

  it('delete({ revoke: true }) revokes the grant at the AS', async () => {
    const client = await newClient();
    const tm = new TokenManager(client, { autoRefresh: false });
    const ts = await tm.set('u', await signIn(client));
    await tm.delete('u', { revoke: true });
    assert.deepEqual(as.state.revokedGrants, [ts.grant_id]);
  });
});

describe('AccountManager (one cache for the browser, one active account per tab)', () => {
  const managers = [];
  afterEach(() => { for (const m of managers.splice(0)) m.close(); });
  const tab = async (client, shared, opts = {}) => {
    const m = new AccountManager(client, { store: shared, tabStore: new MemoryTokenStore(), broadcast: false, ...opts });
    managers.push(m);
    return m.init();
  };
  const add = async (accounts, sub, request = (a) => a.addAccount()) => {
    const { url } = await request(accounts);
    return accounts.handleCallback(as.approve(url, sub));
  };

  it('caches every account, but only the active account\'s grant is reachable', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const a = await add(accounts, 'alice');
    assert.equal(a.added, true);
    assert.equal(a.intent, 'add');
    await add(accounts, 'bob');
    assert.equal(accounts.active.sub, 'bob');
    assert.equal((await accounts.getTokenSet()).claims.sub, 'bob');
    const requests = as.state.grantRequests;
    await accounts.activate(a.account.key);
    assert.equal(as.state.grantRequests, requests, 'activating a cached account sends nothing');
    assert.equal((await accounts.getTokenSet()).claims.sub, 'alice');
    assert.doesNotMatch(JSON.stringify(accounts.list()), /eyJ|\bct-[0-9a-f]|\bmt-[0-9a-f]/, 'the account list holds no token');
  });

  it('runs onActivate with the account\'s grant before it becomes active, and aborts on failure', async () => {
    let fail = false;
    const seen = [];
    const accounts = await tab(await newClient(), new MemoryTokenStore(), {
      onActivate: async (account, { getTokenSet }) => {
        seen.push([account.sub, (await getTokenSet()).claims.sub]);
        if (fail && account.sub === 'alice') throw new Error('catch-up failed');
      },
    });
    const a = await add(accounts, 'alice');
    await add(accounts, 'bob');
    assert.deepEqual(seen, [['alice', 'alice'], ['bob', 'bob']]);
    fail = true;
    await assert.rejects(accounts.activate(a.account.key), /catch-up failed/);
    assert.equal(accounts.active.sub, 'bob');
  });

  it('reauthenticate names the person in the request and refuses anybody else', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const { account } = await add(accounts, 'alice');
    const { url } = await accounts.reauthenticate(account.key);
    assert.deepEqual(as.state.lastGrantRequest.user, { sub_ids: [{ format: 'iss_sub', iss: as.issuer, sub: 'alice' }] });
    await assert.rejects(accounts.handleCallback(as.approve(url, 'mallory')), (e) => e.code === 'account_mismatch' && e.account.key === account.key);
    assert.equal(accounts.list().length, 1);
  });

  it('signing out revokes that account\'s grant; the others stay signed in', async () => {
    const left = [];
    const accounts = await tab(await newClient(), new MemoryTokenStore(), { onLeave: async (x, { getTokenSet }) => left.push([x.sub, (await getTokenSet()).claims.sub]) });
    const a = await add(accounts, 'alice');
    const b = await add(accounts, 'bob');
    const bobGrant = await accounts.getTokenSet();
    await accounts.signOut();
    assert.deepEqual(left, [['bob', 'bob']]);
    assert.deepEqual(as.state.revokedGrants, [bobGrant.grant_id]);
    assert.equal(accounts.active.key, a.account.key);
    assert.equal(accounts.get(b.account.key).status, 'signed-out');
    await accounts.signOutAll();
    assert.equal(accounts.active, undefined);
    assert.equal(as.state.revokedGrants.length, 2);
  });

  it('routes a CAEP session-revoked about a grant to the account holding it, and ends that account only', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const a = await add(accounts, 'alice');
    const b = await add(accounts, 'bob');
    const grantSession = (id) => Subject.complex({ user: Subject.issSub(as.issuer, 'alice'), session: Subject.opaque(id) });
    assert.equal(accounts.accountsForSubject(grantSession(`gnap-grant:${a.grantSet.grant_id}`)).length, 1);
    assert.equal(accounts.accountsForSubject(grantSession('gnap-grant:another')).length, 0);
    const tokenSession = a.grantSet.sessionIds()[1];
    assert.equal(accounts.accountsForSubject(grantSession(tokenSession))[0].sub, 'alice');
    await accounts.end(a.account.key, 'session-revoked');
    assert.equal(accounts.get(a.account.key).status, 'ended');
    assert.equal(accounts.active.key, b.account.key);
  });

  it('keeps the uid on the account record, for display', async () => {
    const accounts = await tab(await newClient({ subject: { subIdFormats: ['iss_sub', 'account'] } }), new MemoryTokenStore());
    const { account } = await add(accounts, 'hana');
    assert.equal(account.uid, 'hana');
    assert.equal(accounts.get(account.key).account, 'acct:hana@as.test');
  });

  it('keeps an account\'s session ids current when its token is rotated', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const { account } = await add(accounts, 'alice');
    const before = accounts.get(account.key).sessions;
    const rotated = onceEvent(accounts, 'rotated');
    await accounts.rotate();
    await rotated;
    const after = accounts.get(account.key).sessions;
    assert.equal(after[0], before[0]);
    assert.notEqual(after[1], before[1]);
  });

  it('a trusted client signs in with no redirect', async () => {
    as.state.trusted = true;
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const result = await accounts.signIn();
    assert.equal(result.account.sub, 'trusted-user');
  });

  it('refuses to sign in a grant that names nobody, and revokes it', async () => {
    as.state.subjectFormats = false;
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    await assert.rejects(add(accounts, 'alice'), (e) => e.code === 'no_subject');
    assert.equal(as.state.revokedGrants.length, 1);
  });

  it('tabs share the cache, each with its own active account', async () => {
    const client = await newClient();
    const shared = new MemoryTokenStore();
    const tab1 = await tab(client, shared);
    const alice = await add(tab1, 'alice');
    await add(tab1, 'bob');
    const tab2 = await tab(client, shared);
    assert.equal(tab2.active, undefined);
    await tab2.activate(alice.account.key);
    assert.equal((await tab2.getTokenSet()).claims.sub, 'alice');
    assert.equal((await tab1.getTokenSet()).claims.sub, 'bob');
  });

  it('holds at most maxAccounts', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore(), { maxAccounts: 2 });
    const a = await add(accounts, 'alice');
    await add(accounts, 'bob');
    await assert.rejects(add(accounts, 'carol'), (e) => e.code === 'too_many_accounts');
    await accounts.signOut(a.account.key);
    await add(accounts, 'carol');
    assert.deepEqual(accounts.list().map((x) => x.sub), ['bob', 'carol']);
  });
});

describe('SSF / CAEP receiver with a GNAP access token', () => {
  async function receiver(opts = {}) {
    const client = await newClient();
    const grant = await signIn(client);
    return new SSFReceiver({
      transmitterIssuer: as.issuer,
      authorizationHeaders: (req) => client.resourceHeaders(grant, req),
      fetch: as.fetch,
      pollIntervalMs: 50,
      onEventReceived: null,
      ...opts,
    });
  }
  const stream = (r) => as.state.streams.get(r.stream.stream_id);
  const waitFor = async (fn, label) => {
    const end = Date.now() + 3000;
    while (!(await fn())) {
      if (Date.now() > end) throw new Error(`Timed out waiting for ${label}`);
      await new Promise((res) => setTimeout(res, 20));
    }
  };
  const settle = () => new Promise((resolve) => setTimeout(resolve, 50));
  const alice = () => Subject.issSub(as.issuer, 'alice');

  it('creates a stream with a signed GNAP token, verifies it and dispatches to named handlers', async () => {
    const got = [];
    const r = await receiver();
    r.onDeviceComplianceChange((e) => got.push(e));
    await r.start();
    assert.deepEqual(as.state.lastSignature.components.slice(-1), ['authorization']);
    assert.equal((await r.requestVerification({ timeoutMs: 2000 })).type, SSF.VERIFICATION);
    await r.addSubject(alice());
    stream(r).queue.set('j1', await as.makeSet(stream(r), CAEP.DEVICE_COMPLIANCE_CHANGE, { current_status: 'not-compliant' }, alice()));
    await waitFor(() => got.length === 1, 'event');
    await waitFor(() => stream(r).queue.size === 0, 'acknowledgement');
    await r.stop({ deleteStream: true });
    assert.equal(as.state.streams.size, 0);
  });

  it('the transmitter refuses the token without its key proof', async () => {
    const client = await newClient();
    const grant = await signIn(client);
    const r = new SSFReceiver({ transmitterIssuer: as.issuer, accessToken: () => grant.access_token, fetch: as.fetch, onEventReceived: null });
    await assert.rejects(r.start(), (e) => e.status === 401);
  });

  it('dispatches a session-revoked naming a GNAP grant, which AccountManager can route', async () => {
    const got = [];
    const r = await receiver({ pollIntervalMs: 60_000 });
    r.onSessionRevoked((e) => got.push(e));
    await r.start();
    await settle();
    const subject = Subject.complex({ user: alice(), session: Subject.opaque('gnap-grant:g1') });
    await r.receiveSet(await as.makeSet(stream(r), CAEP.SESSION_REVOKED, {}, subject));
    assert.equal(got[0].subject.session.id, 'gnap-grant:g1');
    assert.ok(subjectMatches(got[0].subject, { iss: as.issuer, sub: 'alice', sid: ['gnap-grant:g1', 'gnap-token:t'] }));
    await r.stop();
  });

  it('catches up on the SETs queued while stopped before start({ catchUp }) resolves', async () => {
    const r1 = await receiver({ pollIntervalMs: 60_000 });
    await r1.start();
    await r1.stop();
    const s = stream(r1);
    s.queue.set('j1', await as.makeSet(s, CAEP.SESSION_REVOKED, {}, alice()));
    const got = [];
    const r2 = await receiver({ streamId: s.stream_id, pollIntervalMs: 60_000 });
    r2.onSessionRevoked((e) => got.push(e.name));
    await r2.start({ catchUp: true });
    assert.deepEqual(got, ['session-revoked']);
    await r2.stop({ deleteStream: true });
  });

  it('calls every CAEP handler type via constructor config', async () => {
    const seen = new Set();
    const names = ['sessionRevoked', 'tokenClaimsChange', 'credentialChange', 'assuranceLevelChange', 'deviceComplianceChange', 'sessionEstablished', 'sessionPresented', 'riskLevelChange'];
    const r = await receiver({ handlers: Object.fromEntries(names.map((n) => [n, (e) => seen.add(e.name)])) });
    await r.start();
    for (const type of Object.values(CAEP)) await r.receiveSet(await as.makeSet(stream(r), type, {}, alice()));
    assert.equal(seen.size, 8);
    await r.stop();
  });

  it('calls onEventReceived before the typed handlers, and logs only name and jti by default', async () => {
    const order = [];
    const r = await receiver({ onEventReceived: (e) => order.push(`hook:${e.name}`) });
    r.onSessionRevoked((e) => order.push(`typed:${e.name}`));
    await r.start();
    await r.receiveSet(await as.makeSet(stream(r), CAEP.SESSION_REVOKED, {}, alice()));
    assert.deepEqual(order, ['hook:session-revoked', 'typed:session-revoked']);
    await r.stop();
    const lines = [];
    const original = console.log;
    console.log = (...args) => lines.push(args);
    try {
      logEventReceived({ name: 'credential-change', jti: 'j', payload: { secret: 1 } });
    } finally {
      console.log = original;
    }
    assert.match(lines[0][0], /^\[gnap-caep-client\] CAEP event received: credential-change \(jti j\)$/);
  });

  it('acknowledges a SET only once its handlers succeed', async () => {
    let calls = 0;
    const r = await receiver({ pollIntervalMs: 60_000 });
    r.onSessionRevoked(() => { calls += 1; if (calls === 1) throw new Error('storage unavailable'); });
    r.onError(() => {});
    await r.start();
    await settle();
    const s = stream(r);
    s.queue.set('j1', await as.makeSet(s, CAEP.SESSION_REVOKED, {}, alice()));
    await r.poll();
    await r.poll();
    assert.equal(calls, 2);
    await r.poll();
    assert.equal(s.queue.size, 0);
    await r.stop();
  });

  it('never sends the token to a poll endpoint off the transmitter', async () => {
    const r = await receiver({ pollIntervalMs: 60_000 });
    await r.start();
    await settle();
    r.stream.delivery.endpoint_url = 'https://evil.example/poll';
    await assert.rejects(r.poll(), (e) => e.code === 'untrusted_endpoint');
    await r.stop();
  });

  it('validates SETs: signature, audience, typ, replay', async () => {
    const r = await receiver();
    await r.start();
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ jti: 'x', events: { [CAEP.SESSION_REVOKED]: {} } }).setProtectedHeader({ alg: 'RS256', kid: 'as-k1', typ: 'secevent+jwt' })
      .setIssuer(as.issuer).setAudience(r.stream.aud).setIssuedAt().sign(privateKey);
    await assert.rejects(r.receiveSet(forged), (e) => e instanceof SETValidationError && e.code === 'invalid_key');
    await assert.rejects(r.receiveSet(await as.makeSet({ ...stream(r), aud: 'other' }, CAEP.SESSION_REVOKED, {}, alice())), (e) => e.code === 'invalid_audience');
    const wrongTyp = await new SignJWT({ jti: randomUUID(), events: { [CAEP.SESSION_REVOKED]: {} } }).setProtectedHeader({ alg: 'RS256', kid: 'as-k1', typ: 'JWT' })
      .setIssuer(as.issuer).setAudience(r.stream.aud).setIssuedAt().sign(as.privateKey);
    await assert.rejects(r.receiveSet(wrongTyp), /typ/);
    const set = await as.makeSet(stream(r), CAEP.CREDENTIAL_CHANGE, {}, alice());
    assert.equal((await r.receiveSet(set)).length, 1);
    assert.deepEqual(await r.receiveSet(set), []);
    await r.stop();
  });

  it('reuses an existing stream when the transmitter is at its limit', async () => {
    const first = await receiver({ description: 'this app', pollIntervalMs: 60_000 });
    await first.start();
    await first.stop();
    as.state.streamLimit = 1;
    const again = await receiver({ description: 'this app', pollIntervalMs: 60_000 });
    await again.start();
    await again.stop();
    assert.equal(again.stream.stream_id, first.stream.stream_id);
  });
});

describe('subjectMatches', () => {
  it('matches the RFC 9493 formats, and a session against any of an identity\'s sessions', () => {
    const id = { iss: 'https://as', sub: 'u1', email: 'A@x.com', email_verified: true, sid: ['gnap-grant:g', 'gnap-token:t'] };
    assert.ok(subjectMatches(Subject.issSub('https://as', 'u1'), id));
    assert.ok(!subjectMatches(Subject.issSub('https://other', 'u1'), id));
    assert.ok(subjectMatches(Subject.email('a@X.com'), id));
    assert.ok(subjectMatches(Subject.complex({ user: Subject.issSub('https://as', 'u1'), session: Subject.opaque('gnap-token:t') }), id));
    assert.ok(!subjectMatches(Subject.complex({ user: Subject.issSub('https://as', 'u1'), session: Subject.opaque('gnap-grant:other') }), id));
    assert.ok(!subjectMatches(Subject.email('a@x.com'), { ...id, email_verified: false }));
    assert.ok(!subjectMatches(Subject.complex({ user: Subject.issSub('https://as', 'u1'), session: Subject.opaque('x') }), { ...id, sid: undefined }));
    assert.ok(!subjectMatches(Subject.complex({ session: Subject.opaque('') }), { sid: [''] }));
  });
});

describe('browser compatibility', () => {
  it('the library imports no Node.js built-ins', async () => {
    const { readdir, readFile } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const root = new URL('../src/', import.meta.url).pathname;
    for (const dir of ['', 'caep/']) {
      for (const f of await readdir(join(root, dir))) {
        if (!f.endsWith('.js')) continue;
        const text = await readFile(join(root, dir, f), 'utf8');
        assert.doesNotMatch(text, /from ['"]node:|require\(|\bBuffer\b|\bprocess\./, join(dir, f));
      }
    }
  });
});
