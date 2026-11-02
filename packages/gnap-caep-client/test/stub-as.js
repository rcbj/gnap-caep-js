// A strict in-memory GNAP authorization server (RFC 9635), resource server and SSF transmitter, for the
// tests. Injected through the library's `fetch` option: no network.
//
// It shares NO signing or verification code with the library. Every HTTP message signature (RFC 9421) is
// parsed and its signature base rebuilt here from the RFC, the Content-Digest (RFC 9530) recomputed and
// the signature checked with node's crypto, and the interaction hash (RFC 9635 section 4.2.3) computed
// here too: a base built by the same function on both sides verifies perfectly and interoperates with
// nobody.
import { createHash, createPublicKey, randomUUID, verify as nodeVerify } from 'node:crypto';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';

const now = () => Math.floor(Date.now() / 1000);
const rnd = () => randomUUID().replaceAll('-', '');
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (v) => createHash('sha256').update(v).digest();

/** Parses `sig1=(...);a=b, sig2=...` into { label: rest } (one level, enough for this client's headers). */
function splitDictionary(text) {
  const out = {};
  let depth = 0;
  let quoted = false;
  let start = 0;
  const push = (piece) => {
    const t = piece.trim();
    const eq = t.indexOf('=');
    if (eq > 0) out[t.slice(0, eq)] = t.slice(eq + 1);
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' && text[i - 1] !== '\\') quoted = !quoted;
    else if (!quoted && c === '(') depth++;
    else if (!quoted && c === ')') depth--;
    else if (!quoted && depth === 0 && c === ',') { push(text.slice(start, i)); start = i + 1; }
  }
  push(text.slice(start));
  return out;
}

const VERIFY_ALGS = {
  ES256: (data, key, sig) => nodeVerify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig),
  ES384: (data, key, sig) => nodeVerify('sha384', data, { key, dsaEncoding: 'ieee-p1363' }, sig),
  RS256: (data, key, sig) => nodeVerify('sha256', data, key, sig),
  PS256: (data, key, sig) => nodeVerify('sha256', data, { key, padding: 6, saltLength: 32 }, sig),
};

export async function createStubAS(opts = {}) {
  const { issuer = 'https://as.test', tokenTtl = 3600, metadataOverride = {} } = opts;
  const grantEndpoint = `${issuer}/gnap`;
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const kid = 'as-k1';
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' }] };

  const state = {
    grants: new Map(), tokens: new Map(), manage: new Map(), nonces: new Set(), streams: new Map(),
    registered: new Map(), productMode: false, trusted: false, denyNext: false, issueBearer: false, tooFastOnce: false,
    subjectFormats: true, idTokenSub: undefined, lastGrantRequest: null, lastSignature: null, grantRequests: 0,
    rotations: 0, revokedGrants: [], revokedTokens: [], lastPoll: null, streamLimit: null, instanceIds: new Map(),
  };

  const metadata = {
    grant_request_endpoint: grantEndpoint,
    interaction_start_modes_supported: ['redirect', 'app', 'user_code'],
    interaction_finish_methods_supported: ['redirect', 'push'],
    key_proofs_supported: ['httpsig', 'mtls', 'jwsd', 'jws'],
    sub_id_formats_supported: ['opaque', 'iss_sub', 'email', 'account'],
    assertion_formats_supported: ['id_token', 'saml2'],
    key_rotation_supported: true,
    ...metadataOverride,
  };
  const ssfMetadata = {
    spec_version: '1_0', issuer, jwks_uri: `${issuer}/jwks`,
    delivery_methods_supported: ['urn:ietf:rfc:8936'],
    configuration_endpoint: `${issuer}/ssf/stream`, status_endpoint: `${issuer}/ssf/status`,
    add_subject_endpoint: `${issuer}/ssf/subjects/add`, verification_endpoint: `${issuer}/ssf/verify`,
  };

  const json = (body, status = 200, headers = {}) => new Response(body === undefined ? null : JSON.stringify(body),
    { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });
  const gnapError = (code, status = 400, extra = {}) => json({ error: { code, description: code }, ...extra }, status);

  /**
   * Verifies the request's HTTP message signature against `jwk`. Answers an error string or ''.
   * @param {{ method: string, url: string, headers: Headers, body: string|undefined }} req
   */
  function verifySignature(req, jwk, { requireAuthorization = false } = {}) {
    const input = req.headers.get('signature-input');
    const sigHeader = req.headers.get('signature');
    if (!input || !sigHeader) return 'unsigned';
    const inputs = splitDictionary(input);
    const sigs = splitDictionary(sigHeader);
    const label = Object.keys(inputs)[0];
    const serialised = inputs[label];
    const m = /^\(([^)]*)\)(.*)$/.exec(serialised);
    if (!m) return 'malformed Signature-Input';
    const components = m[1].split(' ').filter(Boolean).map((c) => c.replace(/^"|"$/g, ''));
    const params = {};
    for (const [, name, , , quoted, num] of m[2].matchAll(/;([a-z]+)=(("([^"]*)")|(\d+))/g)) params[name] = quoted ?? Number(num);
    state.lastSignature = { components, params };
    if (params.tag !== 'gnap') return 'tag is not gnap';
    if (typeof params.created !== 'number' || Math.abs(now() - params.created) > 300) return 'created is stale';
    if (!params.nonce || state.nonces.has(params.nonce)) return 'nonce replayed or missing';
    state.nonces.add(params.nonce);
    if (!components.includes('@method') || !components.includes('@target-uri')) return 'method or target-uri not covered';
    if (req.body) {
      if (!components.includes('content-digest')) return 'content-digest not covered';
      const expected = `sha-256=:${sha256(req.body).toString('base64')}:`;
      if (req.headers.get('content-digest') !== expected) return 'content-digest mismatch';
    }
    if (req.headers.get('authorization') && !components.includes('authorization')) return 'authorization not covered';
    if (requireAuthorization && !components.includes('authorization')) return 'authorization not covered';
    const lines = components.map((c) => {
      if (c === '@method') return `"@method": ${req.method.toUpperCase()}`;
      if (c === '@target-uri') return `"@target-uri": ${req.url}`;
      return `"${c}": ${String(req.headers.get(c) ?? '').trim()}`;
    });
    lines.push(`"@signature-params": ${serialised}`);
    const signature = Buffer.from(String(sigs[label] ?? '').replace(/^:|:$/g, ''), 'base64');
    const alg = jwk.alg ?? 'ES256';
    if (params.keyid !== jwk.kid) return 'keyid does not name the key';
    let ok = false;
    try {
      ok = VERIFY_ALGS[alg](Buffer.from(lines.join('\n')), createPublicKey({ key: jwk, format: 'jwk' }), signature);
    } catch {
      ok = false;
    }
    return ok ? '' : 'bad signature';
  }

  const interactionHash = (clientNonce, serverNonce, ref, method = 'sha-256') =>
    b64u(createHash(method === 'sha-512' ? 'sha512' : 'sha256').update([clientNonce, serverNonce, ref, grantEndpoint].join('\n')).digest());

  async function idToken(sub, extra = {}) {
    return new SignJWT({ email: `${sub}@example.com`, email_verified: true, preferred_username: sub, name: `User ${sub}`, ...extra })
      .setProtectedHeader({ alg: 'RS256', kid }).setIssuer(issuer).setSubject(state.idTokenSub ?? sub)
      .setAudience('demo-client').setIssuedAt().setExpirationTime('5m').sign(privateKey);
  }

  /** An access token: a JWT (so it carries a jti), bound to the grant's key unless bearer. */
  async function issueToken(grant, access) {
    const jti = rnd();
    const value = await new SignJWT({ access, jti, sub: grant.sub }).setProtectedHeader({ alg: 'RS256', kid, typ: 'gnap-at+jwt' })
      .setIssuer(grantEndpoint).setIssuedAt().setExpirationTime(`${Math.max(1, tokenTtl)}s`).sign(privateKey);
    const handle = rnd();
    const mgmt = `mt-${rnd()}`;
    const bearer = state.issueBearer;
    const token = { value, jti, grantId: grant.id, jwk: grant.jwk, access, bearer, handle, mgmt };
    state.tokens.set(value, token);
    state.manage.set(handle, token);
    grant.tokens.add(value);
    return {
      value, access, expires_in: tokenTtl,
      manage: { uri: `${issuer}/gnap/token/${handle}`, access_token: { value: mgmt } },
      ...(bearer ? { flags: ['bearer'] } : {}),
    };
  }

  function continueObject(grant) {
    grant.continueToken = `ct-${rnd()}`;
    return { uri: `${issuer}/gnap/continue/${grant.id}`, access_token: { value: grant.continueToken }, wait: 0 };
  }

  async function subjectFor(grant) {
    if (!grant.subjectRequest || !state.subjectFormats) return undefined;
    const subIds = [];
    if (grant.subjectRequest.sub_id_formats?.includes('iss_sub')) subIds.push({ format: 'iss_sub', iss: issuer, sub: grant.sub });
    if (grant.subjectRequest.sub_id_formats?.includes('opaque')) subIds.push({ format: 'opaque', id: `op-${grant.sub}` });
    // iya-sts's `account`: the directory uid as the RFC 7565 user part.
    if (grant.subjectRequest.sub_id_formats?.includes('account')) subIds.push({ format: 'account', uri: `acct:${encodeURIComponent(grant.sub)}@as.test` });
    const assertions = grant.subjectRequest.assertion_formats?.includes('id_token') ? [{ format: 'id_token', value: await idToken(grant.sub) }] : [];
    return { sub_ids: subIds, ...(assertions.length ? { assertions } : {}), updated_at: new Date().toISOString() };
  }

  /** Authenticates a token presented at the RS or the SSF transmitter. */
  function resourceAuth(req) {
    const [scheme, value] = (req.headers.get('authorization') ?? '').split(' ');
    if (!/^gnap$/i.test(scheme ?? '')) return { error: 'invalid_token' };
    const token = state.tokens.get(value);
    if (!token) return { error: 'invalid_token' };
    if (!token.bearer) {
      const problem = verifySignature(req, token.jwk, { requireAuthorization: true });
      if (problem) return { error: 'invalid_proof', problem };
    }
    return { token };
  }

  async function makeSet(stream, eventType, payload, subId) {
    return new SignJWT({ jti: rnd(), sub_id: subId, events: { [eventType]: payload } })
      .setProtectedHeader({ alg: 'RS256', kid, typ: 'secevent+jwt' }).setIssuer(issuer).setIssuedAt().setAudience(stream.aud).sign(privateKey);
  }

  async function handle(url, init) {
    const u = new URL(url);
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === 'string' ? init.body : undefined;
    const data = body ? JSON.parse(body) : {};
    const req = { method, url: u.href, headers, body };
    const p = u.pathname;

    if (u.origin === 'https://rs.test') {
      const auth = resourceAuth(req);
      if (auth.error) return new Response(null, { status: 401, headers: { 'www-authenticate': `GNAP as_uri="${grantEndpoint}"`, 'x-problem': auth.problem ?? auth.error } });
      return json({ ok: true, sub: auth.token.grantId && state.grants.get(auth.token.grantId)?.sub, method, echoed: data });
    }

    if (p === '/gnap' && method === 'OPTIONS') return json(metadata);
    if (p === '/.well-known/openid-configuration') return json({ issuer, jwks_uri: `${issuer}/jwks` });
    if (p === '/.well-known/ssf-configuration') return json(ssfMetadata);
    if (p === '/jwks') return json(jwks);

    if (p === '/gnap' && method === 'POST') {
      state.grantRequests++;
      state.lastGrantRequest = data;
      let jwk;
      let instanceId;
      if (typeof data.client === 'string') {
        jwk = state.instanceIds.get(data.client);
        if (!jwk) return gnapError('invalid_client', 401);
      } else {
        const key = data.client?.key;
        if (key?.proof !== 'httpsig' || !key.jwk) return gnapError('invalid_client', 401);
        if ('d' in key.jwk) return gnapError('invalid_client', 401);
        jwk = key.jwk;
        const thumb = await calculateJwkThumbprint(jwk, 'sha256');
        if (jwk.kid !== thumb) return gnapError('invalid_client', 401);
        if (state.productMode && !state.registered.has(thumb)) return gnapError('invalid_client', 401);
        instanceId = `inst-${thumb.slice(0, 10)}`;
        state.instanceIds.set(instanceId, jwk);
      }
      const problem = verifySignature(req, jwk);
      if (problem) return gnapError('invalid_client', 401, { problem });
      const access = data.access_token?.access;
      if (!Array.isArray(access) || !access.length) return gnapError('invalid_request');
      if (data.access_token?.flags?.includes('bearer')) state.issueBearer = true;
      const grant = { id: rnd(), jwk, access, subjectRequest: data.subject, user: data.user, tokens: new Set(), sub: undefined, status: 'pending' };
      state.grants.set(grant.id, grant);
      if (state.trusted) {
        grant.sub = 'trusted-user';
        grant.status = 'approved';
        return json({ access_token: await issueToken(grant, access), continue: continueObject(grant), subject: await subjectFor(grant), ...(instanceId ? { instance_id: instanceId } : {}) });
      }
      const finish = data.interact?.finish;
      if (!finish || finish.method !== 'redirect' || !finish.uri || !finish.nonce) return gnapError('invalid_interaction');
      grant.finish = finish;
      grant.serverNonce = `sn-${rnd()}`;
      grant.interactId = rnd();
      return json({
        interact: { redirect: `${issuer}/interact/${grant.interactId}`, finish: grant.serverNonce, expires_in: 600 },
        continue: continueObject(grant),
        ...(instanceId ? { instance_id: instanceId } : {}),
      });
    }

    const cont = /^\/gnap\/continue\/([^/]+)$/.exec(p);
    if (cont) {
      const grant = state.grants.get(cont[1]);
      if (!grant || grant.status === 'revoked') return gnapError('invalid_continuation', 401);
      const [scheme, value] = (headers.get('authorization') ?? '').split(' ');
      if (scheme !== 'GNAP' || value !== grant.continueToken) return gnapError('invalid_continuation', 401);
      const problem = verifySignature(req, grant.jwk, { requireAuthorization: true });
      if (problem) return gnapError('invalid_client', 401, { problem });
      if (method === 'DELETE') {
        grant.status = 'revoked';
        for (const v of grant.tokens) {
          const t = state.tokens.get(v);
          if (t) state.manage.delete(t.handle);
          state.tokens.delete(v);
        }
        state.revokedGrants.push(grant.id);
        return new Response(null, { status: 204 });
      }
      if (method === 'PATCH') {
        for (const v of grant.tokens) state.tokens.delete(v);
        return json({ access_token: await issueToken(grant, data.access_token.access), continue: continueObject(grant) });
      }
      if (state.tooFastOnce) {
        state.tooFastOnce = false;
        // Section 3.6: the error's continue object is the one to use, with a NEW token, as iya-sts answers;
        // the token just presented is spent.
        return gnapError('too_fast', 400, { continue: { ...continueObject(grant), wait: 1 } });
      }
      if (grant.status === 'pending') {
        if (!data.interact_ref || data.interact_ref !== grant.interactRef) return gnapError('invalid_interaction');
        grant.interactRef = undefined;
        if (grant.denied) {
          grant.status = 'denied';
          return json({ continue: continueObject(grant) });
        }
        grant.status = 'approved';
        return json({ access_token: await issueToken(grant, grant.access), continue: continueObject(grant), subject: await subjectFor(grant) });
      }
      return json({ continue: continueObject(grant) });
    }

    const mgmt = /^\/gnap\/token\/([^/]+)$/.exec(p);
    if (mgmt) {
      const token = state.manage.get(mgmt[1]);
      if (!token) return gnapError('invalid_rotation', 401);
      const [scheme, value] = (headers.get('authorization') ?? '').split(' ');
      if (scheme !== 'GNAP' || value !== token.mgmt) return gnapError('invalid_rotation', 401);
      const problem = verifySignature(req, token.jwk, { requireAuthorization: true });
      if (problem) return gnapError('invalid_client', 401, { problem });
      state.manage.delete(mgmt[1]);
      state.tokens.delete(token.value);
      if (method === 'DELETE') {
        state.revokedTokens.push(token.jti);
        return new Response(null, { status: 204 });
      }
      state.rotations++;
      const grant = state.grants.get(token.grantId);
      return json({ access_token: await issueToken(grant, token.access) });
    }

    if (p.startsWith('/ssf/')) {
      const auth = resourceAuth(req);
      if (auth.error) return json({ err: 'invalid_token', description: auth.problem ?? auth.error }, 401, { 'www-authenticate': `GNAP as_uri="${grantEndpoint}"` });
      if (p === '/ssf/stream' && method === 'POST') {
        if (state.streamLimit != null && state.streams.size >= state.streamLimit) return json({ err: 'access_denied' }, 403);
        const id = rnd();
        const stream = { stream_id: id, iss: issuer, aud: 'gnap-demo', delivery: { method: data.delivery.method, endpoint_url: `${issuer}/ssf/poll/${id}` },
          events_requested: data.events_requested, events_delivered: data.events_requested, description: data.description,
          status: 'enabled', subjects: [], queue: new Map() };
        state.streams.set(id, stream);
        const { subjects, queue, ...pub } = stream;
        return json(pub, 201);
      }
      if (p === '/ssf/stream' && method === 'GET' && !u.searchParams.get('stream_id')) {
        return json([...state.streams.values()].map(({ subjects, queue, ...pub }) => pub));
      }
      const stream = state.streams.get(u.searchParams.get('stream_id') ?? data.stream_id ?? p.split('/').pop());
      if (!stream) return json({ error: 'not_found' }, 404);
      const pub = () => { const { subjects, queue, errs, ...rest } = stream; return rest; };
      if (p === '/ssf/stream' && method === 'PATCH') {
        for (const [k, v] of Object.entries(data)) if (k !== 'stream_id') stream[k] = v;
        return json(pub());
      }
      if (p === '/ssf/stream' && method === 'GET') return json(pub());
      if (p === '/ssf/stream' && method === 'DELETE') {
        state.streams.delete(stream.stream_id);
        return new Response(null, { status: 204 });
      }
      if (p === '/ssf/status') {
        if (method === 'POST') stream.status = data.status;
        return json({ stream_id: stream.stream_id, status: stream.status });
      }
      if (p === '/ssf/subjects/add') {
        stream.subjects.push(data.subject);
        return new Response(null, { status: 200 });
      }
      if (p === '/ssf/verify') {
        stream.queue.set(rnd(), await makeSet(stream, 'https://schemas.openid.net/secevent/ssf/event-type/verification', { state: data.state }, { format: 'opaque', id: stream.stream_id }));
        return new Response(null, { status: 204 });
      }
      if (p.startsWith('/ssf/poll/')) {
        for (const jti of data.ack ?? []) stream.queue.delete(jti);
        for (const [jti, err] of Object.entries(data.setErrs ?? {})) {
          (stream.errs ??= {})[jti] = err;
          stream.queue.delete(jti);
        }
        state.lastPoll = data;
        return json({ sets: Object.fromEntries(stream.queue), moreAvailable: false });
      }
    }
    return json({ error: 'not_found' }, 404);
  }

  return {
    issuer, grantEndpoint, metadata, state, privateKey, makeSet, interactionHash,
    fetch: (input, init) => handle(String(input instanceof Request ? input.url : input), init),
    /** Registers a client key, as iya-sts's product mode requires. */
    async register(jwk) { state.registered.set(await calculateJwkThumbprint(jwk, 'sha256'), jwk); },
    /**
     * The resource owner at the interaction URI: signs in as `sub` and approves (or denies). Answers the
     * redirect back to the client's finish URI, with the hash the AS computes.
     */
    approve(interactUrl, sub = 'alice', { deny = false } = {}) {
      const id = new URL(interactUrl).pathname.split('/').pop();
      const grant = [...state.grants.values()].find((g) => g.interactId === id);
      if (!grant) throw new Error('unknown interaction');
      grant.interactId = undefined;
      grant.sub = sub;
      grant.denied = deny;
      grant.interactRef = `ir-${rnd()}`;
      const hash = interactionHash(grant.finish.nonce, grant.serverNonce, grant.interactRef, grant.finish.hash_method);
      const back = new URL(grant.finish.uri);
      back.searchParams.set('hash', hash);
      back.searchParams.set('interact_ref', grant.interactRef);
      return back.href;
    },
    grantFor(grantSet) { return state.grants.get(grantSet.grant_id); },
  };
}
