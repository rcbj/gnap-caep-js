import { createRemoteJWKSet, customFetch, errors as joseErrors, jwtVerify } from 'jose';
import { ASYMMETRIC_JWS_ALGS } from './algs.js';
import { discoverGrantServer, discoverOpenIdProvider, validateGrantServerMetadata } from './discovery.js';
import { GNAPClientError, GNAPError, ValidationError } from './errors.js';
import { GrantSet } from './grant-set.js';
import { httpRequest, readJson } from './http.js';
import { signRequest } from './httpsig.js';
import { CLIENT_KEY_ALGS, ClientKey, MemoryKeyStore } from './keys.js';
import { MemoryTokenStore, TransactionStore } from './stores.js';
import { base64url, Emitter, isSecureUrl, randomToken, timingSafeEqual } from './util.js';


/** Interaction hash methods (RFC 9635 section 4.2.3) this library computes, and their WebCrypto names. */
const HASH_METHODS = { 'sha-256': 'SHA-256', 'sha-512': 'SHA-512' };

/** Parameters that never arrive at a redirect finish URI: GNAP never sends a token through the browser. */
const FRONT_CHANNEL_TOKENS = ['access_token', 'id_token', 'token', 'value', 'continue', 'refresh_token'];

/** Grant request members `extra` may not set: the client sets them, and the callback relies on them. */
const RESERVED_REQUEST_MEMBERS = Object.freeze(['client', 'interact']);

/** Claims of a verified `id_token` assertion this client keeps in `claims`, for display and matching. */
const PROFILE_CLAIMS = ['name', 'given_name', 'family_name', 'preferred_username', 'email', 'email_verified',
  'phone_number', 'phone_number_verified', 'picture', 'acr', 'amr', 'auth_time', 'sid'];

/**
 * @typedef {object} GNAPClientConfig
 * @property {string} [grantEndpoint]           The AS's grant endpoint, e.g. `https://as.example.com/gnap`.
 *           Its discovery document is read with an OPTIONS request (RFC 9635 section 9).
 * @property {Record<string, any>} [metadata]   A discovery document to use instead of discovering one.
 * @property {string} [finishUri]               Where the AS sends the browser back after interaction
 *           (the redirect finish URI, section 2.5.2). Required for a redirect interaction.
 * @property {Array<string|Record<string, any>>} [access]  The access rights to request by default
 *           (section 8): reference strings such as `"ssf.read"`, or objects with `type`, `actions`, ...
 * @property {{ subIdFormats?: string[], assertionFormats?: string[] }|false} [subject]  Who the resource
 *           owner is (section 2.2). Default `{ subIdFormats: ['iss_sub', 'opaque'] }`. `false` asks for nothing.
 * @property {{ name?: string, uri?: string, logo_uri?: string }} [display]  What the approval page shows
 *           about this client (section 2.3.2): self-declared, never a reason for more trust.
 * @property {string} [classId]                 The client's `class_id` (section 2.3): the identifier of the registered
 *           application this key is an instance of. An AS that accepts unregistered instances (iya-sts:
 *           `gnap.unregisteredInstances`, the default) then accepts a browser's key with no registration of its own.
 * @property {ClientKey} [key]                  The client key. Default: loaded from, or created in, `keyStore`.
 * @property {import('./keys.js').KeyStore} [keyStore]  Where the key is kept (default memory: a new client
 *           instance every page load). Use `new IndexedDBKeyStore()` to keep a non-extractable key.
 * @property {string} [alg]                     Client key algorithm (default ES256).
 * @property {boolean} [useInstanceId]          Send the `instance_id` the AS handed out (section 3.5) instead of
 *           the key by value in later requests. Default false.
 * @property {import('./stores.js').TokenStore} [instanceStore]  Where an instance_id is remembered.
 * @property {boolean} [requireBoundTokens]     Refuse an access token issued with the `bearer` flag
 *           (section 3.2.1): this client asks for key-bound tokens. Default true.
 * @property {'sha-256'|'sha-512'} [hashMethod] The interaction hash method to ask for (default sha-256).
 * @property {{ issuer: string, jwksUri?: string, audience?: string|string[], algorithms?: string[] }} [idToken]
 *           Verify an `id_token` subject assertion against this issuer's keys. Without it, an assertion is
 *           kept as received and never decoded.
 * @property {TransactionStore} [transactionStore]  Where pending grants wait for the callback (default sessionStorage).
 * @property {number} [transactionTtlSec]       How long a pending grant stays redeemable (default 600).
 * @property {number} [maxWaitSec]              The longest `wait` (section 3.1) the client sleeps for a `too_fast`
 *           continuation before giving up (default 10).
 * @property {boolean} [allowInsecureRequests]  Allow non-TLS endpoints and finish URIs other than loopback (default false).
 * @property {number} [clockToleranceSec]       Allowed clock skew for an id_token assertion (default 30).
 * @property {number} [httpTimeoutMs]           Per-request timeout (default 10000).
 * @property {number} [discoveryCacheTtlMs]     How long a discovery document is cached (default 1h).
 * @property {typeof fetch} [fetch]             Custom fetch implementation.
 */

/**
 * A GNAP client instance (RFC 9635) for a browser app: it identifies itself by a key, signs every request
 * with it (HTTP message signatures), asks the resource owner to approve a grant through a redirect
 * interaction, and learns who they are from the grant's subject information. Its access tokens are bound
 * to the key.
 *
 * Emits: "tokens" (GrantSet) whenever the AS issues a new access token.
 */
export class GNAPClient extends Emitter {
  /** The AS's discovery document. @type {Record<string, any>} */
  metadata;
  /** @type {ClientKey} */
  key;
  #config;
  #jwks;
  #usedHashes = new Map();
  #subIdFormats = [];
  #assertionFormats = [];

  /** @param {GNAPClientConfig} config */
  constructor(config) {
    super();
    const grantEndpoint = config?.grantEndpoint ?? config?.metadata?.grant_request_endpoint;
    if (!grantEndpoint) throw new TypeError('grantEndpoint or metadata is required');
    for (const unsupported of ['clientSecret', 'clientId']) {
      if (config[unsupported] !== undefined) {
        throw new TypeError(`${unsupported} is not a GNAP concept: a GNAP client is identified by its key`);
      }
    }
    this.#config = {
      clockToleranceSec: 30,
      httpTimeoutMs: 10_000,
      transactionTtlSec: 600,
      maxWaitSec: 10,
      hashMethod: 'sha-256',
      requireBoundTokens: true,
      useInstanceId: false,
      allowInsecureRequests: false,
      subject: { subIdFormats: ['iss_sub', 'opaque'] },
      ...config,
      grantEndpoint,
    };
    if (!HASH_METHODS[this.#config.hashMethod]) {
      throw new TypeError(`hashMethod must be one of ${Object.keys(HASH_METHODS).join(', ')}`);
    }
    if (this.#config.access !== undefined && !Array.isArray(this.#config.access)) throw new TypeError('access must be an array');
    this.#config.transactionStore ??= new TransactionStore({ prefix: 'gnap-caep-client:grant:' });
    this.#config.instanceStore ??= new MemoryTokenStore();
  }

  /**
   * Creates a client and loads the AS's discovery document.
   * @param {GNAPClientConfig} config
   * @returns {Promise<GNAPClient>}
   */
  static async discover(config) {
    const client = new GNAPClient(config);
    await client.init();
    return client;
  }

  /** The grant endpoint (the AS's identity, as an issuer is in OAuth). */
  get grantEndpoint() { return this.#config.grantEndpoint; }

  /** The effective settings, for display. */
  get config() {
    const { metadata, transactionStore, instanceStore, keyStore, key, fetch: _f, ...rest } = this.#config;
    return { ...rest, keyProof: 'httpsig', subIdFormats: this.#subIdFormats, assertionFormats: this.#assertionFormats };
  }

  /** Which security features are active, for display and audit. */
  get securityFeatures() {
    return {
      keyProof: 'httpsig (RFC 9421) with Content-Digest (RFC 9530), tag "gnap"',
      clientKey: this.key ? { alg: this.key.alg, thumbprint: this.key.thumbprint, extractable: !!this.key.keyPair?.privateKey?.extractable } : undefined,
      boundTokens: this.#config.requireBoundTokens ? 'required: a bearer token is refused' : 'preferred',
      interactionHash: `${this.#config.hashMethod}, checked in constant time; each pending grant single use and expiring`,
      finishNonce: 'random 256-bit per grant request',
      continuationOrigin: 'continuation and management URIs must be on the grant endpoint\'s origin',
      subject: this.#subIdFormats.length ? this.#subIdFormats.join(', ') : 'not requested',
      idTokenAssertion: this.#config.idToken ? `verified against ${this.#config.idToken.issuer}` : 'not verified (kept, never decoded)',
      tlsEnforced: !this.#config.allowInsecureRequests,
    };
  }

  async init() {
    const c = this.#config;
    if (!c.allowInsecureRequests && !isSecureUrl(c.grantEndpoint)) {
      throw new ValidationError(`grantEndpoint must use https: ${c.grantEndpoint}`, { code: 'insecure_endpoint' });
    }
    if (c.finishUri && !c.allowInsecureRequests && !isSecureUrl(c.finishUri)) {
      throw new ValidationError(`finishUri must use https (or loopback http): ${c.finishUri}`, { code: 'insecure_redirect_uri' });
    }
    this.metadata = c.metadata
      ? validateGrantServerMetadata(c.metadata, c.metadata.grant_request_endpoint === undefined ? undefined : c.grantEndpoint)
      : await discoverGrantServer(c.grantEndpoint, { timeoutMs: c.httpTimeoutMs, fetch: c.fetch, cacheTtlMs: c.discoveryCacheTtlMs });
    const m = this.metadata;

    const proofs = m.key_proofs_supported;
    if (Array.isArray(proofs) && !proofs.includes('httpsig')) {
      throw new ValidationError(`The AS does not accept httpsig key proofs (it offers ${proofs.join(', ') || 'none'})`, { code: 'key_proof_not_supported' });
    }
    if (c.finishUri) {
      if (Array.isArray(m.interaction_start_modes_supported) && !m.interaction_start_modes_supported.includes('redirect')) {
        throw new ValidationError('The AS does not offer the redirect interaction start mode', { code: 'interaction_not_supported' });
      }
      if (Array.isArray(m.interaction_finish_methods_supported) && !m.interaction_finish_methods_supported.includes('redirect')) {
        throw new ValidationError('The AS does not offer the redirect interaction finish method', { code: 'interaction_not_supported' });
      }
    }
    // Ask only for what the AS says it can answer; ask for nothing it cannot.
    const want = c.subject === false ? {} : (c.subject ?? {});
    const supported = (list, offered) => (Array.isArray(offered) ? (list ?? []).filter((f) => offered.includes(f)) : [...(list ?? [])]);
    this.#subIdFormats = supported(want.subIdFormats, m.sub_id_formats_supported);
    this.#assertionFormats = supported(want.assertionFormats, m.assertion_formats_supported);

    if (!c.key) {
      const alg = c.alg ?? 'ES256';
      if (!CLIENT_KEY_ALGS.includes(alg)) throw new ValidationError(`Unsupported client key alg ${alg}`);
      c.key = await ClientKey.loadOrCreate(c.keyStore ?? new MemoryKeyStore(), { alg });
    }
    this.key = c.key;

    if (c.idToken) {
      if (!c.idToken.issuer) throw new TypeError('idToken.issuer is required');
      let jwksUri = c.idToken.jwksUri;
      if (!jwksUri) {
        jwksUri = (await discoverOpenIdProvider(c.idToken.issuer, { timeoutMs: c.httpTimeoutMs, fetch: c.fetch, cacheTtlMs: c.discoveryCacheTtlMs })).jwks_uri;
      }
      if (!c.allowInsecureRequests && !isSecureUrl(jwksUri)) throw new ValidationError(`jwks_uri must use https: ${jwksUri}`, { code: 'insecure_endpoint' });
      this.#jwks = createRemoteJWKSet(new URL(jwksUri), { timeoutDuration: c.httpTimeoutMs, ...(c.fetch ? { [customFetch]: c.fetch } : {}) });
    }
    c.transactionStore.sweep?.(c.transactionTtlSec * 1000);
    return this;
  }

  #requireInit() {
    if (!this.metadata || !this.key) throw new GNAPClientError('Client not initialised; call init() or GNAPClient.discover()');
  }

  // ---------------------------------------------------------------------------
  // The grant request (RFC 9635 section 2)
  // ---------------------------------------------------------------------------

  /**
   * Starts a grant: a signed request to the grant endpoint asking for an access token and, unless turned
   * off, who the resource owner is, with a redirect interaction that finishes at `finishUri`.
   *
   * When the AS needs the resource owner, this resolves `{ url }`: send the browser there, and complete
   * the grant on the finish URI with `completeGrant()`. When it issues the token at once (a trusted
   * client), it resolves `{ grantSet }` and nothing waits.
   *
   * @param {object} [opts]
   * @param {Array<string|Record<string, any>>} [opts.access]  Access rights; default the configured ones.
   * @param {string} [opts.label]          A label for the access token.
   * @param {string[]} [opts.flags]        Access token flags to ask for (e.g. `durable`). `bearer` is refused
   *           while `requireBoundTokens` is on.
   * @param {Record<string, any>} [opts.user]  Who the client believes the user is (section 2.4): e.g.
   *           `{ sub_ids: [{ format: 'iss_sub', iss, sub }] }`, or an opaque user reference string.
   * @param {string} [opts.expectedSub]    Refuse a grant approved by anybody else (`account_mismatch`).
   * @param {boolean} [opts.subject]       `false` asks for no subject information in this request.
   * @param {any} [opts.context]           JSON-serialisable data handed back by `completeGrant()`.
   * @param {Record<string, any>} [opts.extra]  Further top-level members of the grant request.
   * @returns {Promise<{ url?: string, grantSet?: GrantSet, context?: any }>}
   */
  async createGrantRequest(opts = {}) {
    this.#requireInit();
    const c = this.#config;
    const access = opts.access ?? c.access;
    if (!Array.isArray(access) || !access.length) throw new TypeError('access is required: the rights to ask for (RFC 9635 section 8)');
    const flags = opts.flags ?? [];
    if (c.requireBoundTokens && flags.includes('bearer')) throw new TypeError('The bearer flag is refused while requireBoundTokens is on');
    const reserved = Object.keys(opts.extra ?? {}).filter((k) => RESERVED_REQUEST_MEMBERS.includes(k));
    if (reserved.length) throw new TypeError(`extra may not set ${reserved.join(', ')}: the client sets them itself`);

    const body = { ...opts.extra };
    body.access_token = { access, ...(opts.label ? { label: opts.label } : {}), ...(flags.length ? { flags } : {}) };
    body.client = await this.#clientMember();
    const nonce = randomToken();
    if (c.finishUri) {
      body.interact = {
        start: ['redirect'],
        finish: { method: 'redirect', uri: c.finishUri, nonce, ...(c.hashMethod !== 'sha-256' ? { hash_method: c.hashMethod } : {}) },
      };
    }
    if (opts.subject !== false && (this.#subIdFormats.length || this.#assertionFormats.length)) {
      body.subject = {
        ...(this.#subIdFormats.length ? { sub_id_formats: this.#subIdFormats } : {}),
        ...(this.#assertionFormats.length ? { assertion_formats: this.#assertionFormats } : {}),
      };
    }
    if (opts.user !== undefined) body.user = opts.user;

    const answer = await this.#signedJson('POST', c.grantEndpoint, { body });
    await this.#rememberInstance(answer);

    if (answer?.interact) {
      const redirect = answer.interact.redirect;
      if (typeof redirect !== 'string') {
        throw new ValidationError('The AS answered with an interaction this client did not ask for (no interact.redirect)', { code: 'interaction_not_supported', response: answer });
      }
      if (!c.allowInsecureRequests && !isSecureUrl(redirect)) throw new ValidationError(`interact.redirect must use https: ${redirect}`, { code: 'insecure_endpoint' });
      if (typeof answer.interact.finish !== 'string' || !answer.interact.finish) {
        throw new ValidationError('The AS did not return its interaction finish nonce (interact.finish)', { code: 'invalid_grant_response' });
      }
      const cont = this.#checkContinue(answer.continue);
      c.transactionStore.set(nonce, {
        clientNonce: nonce,
        serverNonce: answer.interact.finish,
        hashMethod: c.hashMethod,
        continue: cont,
        grantEndpoint: c.grantEndpoint,
        keyThumbprint: this.key.thumbprint,
        expectedSub: opts.expectedSub,
        context: opts.context,
        bearerAllowed: !c.requireBoundTokens,
        createdAt: Date.now(),
      });
      return { url: redirect, context: opts.context };
    }
    if (answer?.access_token) {
      const grantSet = await this.#grantSetFrom(answer, {});
      await this.#checkExpectedSub(grantSet, opts.expectedSub);
      this.emit('tokens', grantSet);
      return { grantSet, context: opts.context };
    }
    throw new ValidationError('The AS answered with neither an interaction nor an access token; a grant that waits for somebody elsewhere is not supported',
      { code: 'invalid_grant_response', response: answer });
  }

  /**
   * Completes a grant on the finish URI: finds the pending grant whose interaction hash (section 4.2.3)
   * the returned `hash` is, removes it (single use), and continues the grant with `interact_ref` to
   * receive the access token and the subject information.
   *
   * @param {URLSearchParams|Record<string,string>|string} response The finish URL, or its query parameters.
   * @returns {Promise<GrantSet>}
   */
  async callback(response) {
    return (await this.completeGrant(response)).grantSet;
  }

  /**
   * `callback()`, also answering the `context` the request was created with. A refusal by the resource
   * owner is a GNAPError `user_denied` carrying that context as `err.context`.
   * @param {URLSearchParams|Record<string,string>|string} response
   * @returns {Promise<{ grantSet: GrantSet, context: any }>}
   */
  async completeGrant(response) {
    this.#requireInit();
    const c = this.#config;
    const p = toParams(response);

    const injected = FRONT_CHANNEL_TOKENS.filter((k) => p.has(k));
    if (injected.length) throw new ValidationError(`The finish redirect carries ${injected.join(', ')}; GNAP never sends tokens through the browser`, { code: 'front_channel_token' });
    for (const k of new Set(p.keys())) {
      if (p.getAll(k).length > 1) throw new ValidationError(`The finish redirect repeats "${k}"`, { code: 'duplicate_parameter' });
    }
    const hash = p.get('hash');
    const interactRef = p.get('interact_ref');
    if (!hash || !interactRef) {
      if (p.get('error')) throw new GNAPError({ error: p.get('error'), error_description: p.get('error_description') ?? undefined });
      throw new ValidationError('The finish redirect has no hash or interact_ref', { code: 'hash_missing' });
    }

    // THE HASH IS THE STATE. Recompute it with each pending grant's nonces; the one it matches is ours.
    let id;
    let transaction;
    for (const candidate of c.transactionStore.ids()) {
      const t = c.transactionStore.peek(candidate);
      if (!t?.clientNonce || !t.serverNonce) continue;
      const expected = await interactionHash(t.clientNonce, t.serverNonce, interactRef, t.grantEndpoint, t.hashMethod);
      if (await timingSafeEqual(hash, expected)) {
        id = candidate;
        transaction = t;
        break;
      }
    }
    if (!transaction || !c.transactionStore.take(id)) {
      const reused = this.#usedHashes.has(hash);
      throw new ValidationError(reused
        ? 'This interaction finish was already used'
        : 'The interaction hash matches no grant in progress (unknown, already used, tampered with, or from another tab)',
      { code: reused ? 'interaction_reused' : 'hash_mismatch' });
    }
    this.#rememberHash(hash);
    if (Date.now() - transaction.createdAt > c.transactionTtlSec * 1000) {
      throw new ValidationError(`The approval took longer than ${c.transactionTtlSec}s; start again`, { code: 'transaction_expired' });
    }
    if (transaction.grantEndpoint !== c.grantEndpoint || transaction.keyThumbprint !== this.key.thumbprint) {
      throw new ValidationError('This grant was started with another authorization server or client key', { code: 'grant_endpoint_mismatch' });
    }

    let answer;
    try {
      answer = await this.#continue(transaction.continue, 'POST', { interact_ref: interactRef });
    } catch (err) {
      if (err instanceof GNAPClientError) err.context = transaction.context;
      throw err;
    }
    if (!answer?.access_token) {
      // RFC 9635 section 4.2.1: a denied interaction still finishes; the continuation then issues nothing.
      const err = new GNAPError({ error: 'user_denied', error_description: 'The resource owner did not approve the grant', response: answer });
      err.context = transaction.context;
      throw err;
    }
    let grantSet;
    try {
      grantSet = await this.#grantSetFrom(answer, { previousContinue: transaction.continue });
      await this.#checkExpectedSub(grantSet, transaction.expectedSub);
    } catch (err) {
      if (err instanceof GNAPClientError) err.context = transaction.context;
      throw err;
    }
    this.emit('tokens', grantSet);
    return { grantSet, context: transaction.context };
  }

  async #checkExpectedSub(grantSet, expectedSub) {
    if (expectedSub === undefined || grantSet.claims?.sub === expectedSub) return;
    await this.revokeGrant(grantSet).catch(() => {});
    throw new ValidationError('The grant was approved by a different person from the one requested', {
      code: 'account_mismatch', response: { expected: expectedSub, sub: grantSet.claims?.sub },
    });
  }

  #rememberHash(hash) {
    const now = Date.now();
    this.#usedHashes.set(hash, now);
    const cutoff = now - this.#config.transactionTtlSec * 1000;
    for (const [h, at] of this.#usedHashes) {
      if (at >= cutoff && this.#usedHashes.size <= 1000) break;
      this.#usedHashes.delete(h);
    }
  }

  // ---------------------------------------------------------------------------
  // Continuing, modifying and revoking the grant (section 5)
  // ---------------------------------------------------------------------------

  /**
   * Modifies the grant (section 5.3) onto different access rights; the AS may need the resource owner
   * again, which this client then refuses (`interaction_required`). Resolves a new GrantSet.
   * @param {GrantSet} grantSet
   * @param {{ access: Array<string|Record<string, any>> }} changes
   * @returns {Promise<GrantSet>}
   */
  async modifyGrant(grantSet, { access }) {
    this.#requireInit();
    const previous = GrantSet.from(grantSet);
    if (!previous.continue) throw new GNAPClientError('This grant cannot be continued (no continue)', { code: 'no_continuation' });
    const answer = await this.#continue(previous.continue, 'PATCH', { access_token: { access } });
    if (answer?.interact) throw new GNAPClientError('The AS needs the resource owner again for this change; start a new grant', { code: 'interaction_required', response: answer });
    if (!answer?.access_token) throw new ValidationError('The modification issued no access token', { code: 'invalid_grant_response', response: answer });
    const next = await this.#grantSetFrom(answer, { previousContinue: previous.continue, previous });
    this.emit('tokens', next);
    return next;
  }

  /**
   * Revokes the whole grant (section 5.4): every token issued under it stops working. Resolves false when
   * the grant cannot be continued.
   * @param {GrantSet|{ continue: { uri: string, access_token: { value: string } } }} grantSet
   * @returns {Promise<boolean>}
   */
  async revokeGrant(grantSet) {
    this.#requireInit();
    const cont = grantSet?.continue;
    if (!cont?.uri || !cont.access_token?.value) return false;
    await this.#continue(cont, 'DELETE');
    return true;
  }

  async #continue(cont, method, body) {
    const checked = this.#checkContinue(cont);
    let waited = 0;
    for (;;) {
      try {
        return await this.#signedJson(method, checked.uri, { body, token: checked.access_token.value });
      } catch (err) {
        // Section 3.6 too_fast: wait as told (or a second) and try again, within maxWaitSec in all.
        if (!(err instanceof GNAPError) || err.error !== 'too_fast') throw err;
        const wait = Math.max(1, Number(err.continue?.wait ?? checked.wait ?? 1));
        if (waited + wait > this.#config.maxWaitSec) throw err;
        waited += wait;
        await new Promise((resolve) => setTimeout(resolve, wait * 1000));
      }
    }
  }

  /**
   * A `continue` object the AS returned, checked: a continuation token goes to its URI, so the URI must
   * be on the grant endpoint's origin and use TLS.
   */
  #checkContinue(cont) {
    if (!cont || typeof cont.uri !== 'string' || typeof cont.access_token?.value !== 'string') {
      throw new ValidationError('The AS returned no usable continue object', { code: 'invalid_grant_response', response: cont });
    }
    this.#checkSameOrigin(cont.uri, 'continue.uri');
    if (cont.wait !== undefined && !(Number.isFinite(Number(cont.wait)) && Number(cont.wait) >= 0)) {
      throw new ValidationError(`Invalid continue.wait ${cont.wait}`, { code: 'invalid_grant_response' });
    }
    return { uri: cont.uri, access_token: { value: cont.access_token.value }, ...(cont.wait !== undefined ? { wait: Number(cont.wait) } : {}) };
  }

  #checkSameOrigin(uri, what) {
    let u;
    try {
      u = new URL(uri);
    } catch {
      throw new ValidationError(`${what} is not a URL: ${uri}`, { code: 'invalid_grant_response' });
    }
    if (!this.#config.allowInsecureRequests && !isSecureUrl(u.href)) throw new ValidationError(`${what} must use https: ${uri}`, { code: 'insecure_endpoint' });
    if (u.origin !== new URL(this.#config.grantEndpoint).origin) {
      throw new ValidationError(`${what} ${uri} is not on the grant endpoint's origin; not sending a token there`, { code: 'untrusted_endpoint' });
    }
  }

  // ---------------------------------------------------------------------------
  // Token management (section 6)
  // ---------------------------------------------------------------------------

  /**
   * Rotates the access token (section 6.1): the AS issues a new one and the old one stops working. The
   * grant's continuation and subject carry over. A key-bound token is never rotated into a bearer one.
   * @param {GrantSet} grantSet
   * @returns {Promise<GrantSet>}
   */
  async rotate(grantSet) {
    this.#requireInit();
    const previous = GrantSet.from(grantSet);
    if (!previous.canRotate()) throw new GNAPClientError('This access token cannot be rotated (no manage URI)', { code: 'no_management' });
    this.#checkSameOrigin(previous.manage.uri, 'manage.uri');
    const answer = await this.#signedJson('POST', previous.manage.uri, { token: previous.manage.access_token.value });
    if (!answer?.access_token) throw new ValidationError('The rotation returned no access token', { code: 'invalid_grant_response', response: answer });
    const next = await this.#grantSetFrom({ ...answer, subject: undefined }, { previous, previousContinue: previous.continue });
    if (!previous.bearer && next.bearer) {
      throw new ValidationError('Rotating a key-bound token returned a bearer token', { code: 'bearer_downgrade' });
    }
    this.emit('tokens', next);
    return next;
  }

  /**
   * Revokes the access token (section 6.2). Resolves false when it has no management URI.
   * @param {GrantSet} grantSet
   * @returns {Promise<boolean>}
   */
  async revokeToken(grantSet) {
    this.#requireInit();
    const ts = GrantSet.from(grantSet);
    if (!ts?.canRotate()) return false;
    this.#checkSameOrigin(ts.manage.uri, 'manage.uri');
    await this.#signedJson('DELETE', ts.manage.uri, { token: ts.manage.access_token.value });
    return true;
  }

  // ---------------------------------------------------------------------------
  // Calling resource servers (section 7.2)
  // ---------------------------------------------------------------------------

  /**
   * The headers for a request to a resource server with an access token: `Authorization: GNAP <token>` and,
   * for a key-bound token, an HTTP message signature covering the method, the URI, the token and the
   * content digest.
   *
   * @param {GrantSet|{ access_token: string, bearer?: boolean }|string} token
   * @param {{ method?: string, url: string, body?: string, headers?: Record<string, string> }} request
   * @returns {Promise<Record<string, string>>}
   */
  async resourceHeaders(token, { method = 'GET', url, body, headers = {} }) {
    this.#requireInit();
    const { access_token: value, bearer } = typeof token === 'string' ? { access_token: token, bearer: false } : token;
    if (typeof value !== 'string' || !value) throw new GNAPClientError('No access token', { code: 'no_tokens' });
    const authorization = `GNAP ${value}`;
    if (bearer) return { authorization };
    if (body !== undefined && typeof body !== 'string') throw new TypeError('A signed request body must be a string (its digest is signed)');
    return { authorization, ...(await signRequest({ method, url, headers: { ...headers, authorization }, body, key: this.key })) };
  }

  /**
   * fetch() against a resource server with an access token, signed with the client key. The body, when
   * there is one, must be a string: its digest is part of the signature.
   * @param {GrantSet|{ access_token: string, bearer?: boolean }|string} token
   * @param {string} url
   * @param {RequestInit & { body?: string }} [init]
   */
  async fetchResource(token, url, init = {}) {
    const method = init.method ?? 'GET';
    const headers = Object.fromEntries(new Headers(init.headers ?? {}).entries());
    const signed = await this.resourceHeaders(token, { method, url, body: init.body ?? undefined, headers });
    return httpRequest(url, { timeoutMs: this.#config.httpTimeoutMs, fetch: this.#config.fetch, ...init, headers: { ...headers, ...signed } });
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  async #clientMember() {
    const c = this.#config;
    if (c.useInstanceId) {
      const held = await c.instanceStore.get(this.#instanceKey());
      if (held?.instance_id) return held.instance_id;
    }
    return {
      key: this.key.keyObject(),
      ...(c.display ? { display: c.display } : {}),
      ...(c.classId ? { class_id: c.classId } : {}),
    };
  }

  #instanceKey() { return `instance:${this.#config.grantEndpoint}:${this.key.thumbprint}`; }

  async #rememberInstance(answer) {
    if (this.#config.useInstanceId && typeof answer?.instance_id === 'string' && answer.instance_id) {
      await this.#config.instanceStore.set(this.#instanceKey(), { instance_id: answer.instance_id });
    }
  }

  /** A signed request with a JSON body (or none), answered as JSON. */
  async #signedJson(method, url, { body, token } = {}) {
    const text = body === undefined ? undefined : JSON.stringify(body);
    const headers = { accept: 'application/json' };
    if (text !== undefined) headers['content-type'] = 'application/json';
    if (token) headers.authorization = `GNAP ${token}`;
    Object.assign(headers, await signRequest({ method, url, headers, body: text, key: this.key }));
    const res = await httpRequest(url, { timeoutMs: this.#config.httpTimeoutMs, fetch: this.#config.fetch, method, headers, body: text });
    return readJson(res);
  }

  /** Builds and checks a GrantSet from a grant, continuation, modification or rotation response. */
  async #grantSetFrom(answer, { previous, previousContinue } = {}) {
    const c = this.#config;
    const at = answer.access_token;
    if (Array.isArray(at)) throw new ValidationError('The AS issued several access tokens; this client asks for one', { code: 'invalid_grant_response' });
    if (!at || typeof at.value !== 'string' || !at.value) throw new ValidationError('The access token has no value', { code: 'invalid_grant_response' });
    if (at.key !== undefined) {
      throw new ValidationError('The access token is bound to a key other than this client\'s, which this client cannot prove', { code: 'invalid_grant_response' });
    }
    const flags = Array.isArray(at.flags) ? at.flags.filter((f) => typeof f === 'string') : [];
    const bearer = flags.includes('bearer');
    if (bearer && c.requireBoundTokens) {
      throw new ValidationError('The AS issued a bearer token, and this client requires key-bound tokens', { code: 'bearer_downgrade' });
    }
    if (at.expires_in !== undefined && !(Number.isFinite(Number(at.expires_in)) && Number(at.expires_in) >= 0)) {
      throw new ValidationError(`Invalid expires_in ${at.expires_in}`, { code: 'invalid_grant_response' });
    }
    let manage;
    if (at.manage !== undefined) {
      if (typeof at.manage?.uri !== 'string' || typeof at.manage.access_token?.value !== 'string') {
        throw new ValidationError('The access token\'s manage object is malformed', { code: 'invalid_grant_response' });
      }
      this.#checkSameOrigin(at.manage.uri, 'manage.uri');
      manage = { uri: at.manage.uri, access_token: { value: at.manage.access_token.value } };
    }
    const cont = answer.continue !== undefined ? this.#checkContinue(answer.continue) : previousContinue;
    const subject = answer.subject ?? previous?.subject;
    const claims = answer.subject !== undefined ? await this.#validateSubject(answer.subject) : previous?.claims;
    return new GrantSet({
      access_token: at.value,
      bearer,
      flags,
      ...(at.label !== undefined ? { label: String(at.label) } : {}),
      access: Array.isArray(at.access) ? at.access : previous?.access,
      manage,
      continue: cont,
      grant_id: grantIdOf(cont?.uri) ?? previous?.grant_id,
      instance_id: typeof answer.instance_id === 'string' ? answer.instance_id : previous?.instance_id,
      grant_endpoint: c.grantEndpoint,
      key_thumbprint: this.key.thumbprint,
      subject,
      ...(at.expires_in !== undefined ? { expires_in: Number(at.expires_in) } : {}),
    }, claims);
  }

  /**
   * Who the resource owner is (RFC 9635 section 3.4): an `iss_sub` identifier gives `iss` and `sub`; an
   * `opaque` one gives `sub`, with the grant endpoint as `iss`. An `id_token` assertion is verified when
   * `idToken` is configured, must be about the same subject, and adds its profile claims; otherwise it is
   * kept as received and never decoded.
   */
  async #validateSubject(subject) {
    if (subject === null || typeof subject !== 'object' || Array.isArray(subject)) {
      throw new ValidationError('The subject information is not an object', { code: 'invalid_subject' });
    }
    const subIds = subject.sub_ids ?? [];
    if (!Array.isArray(subIds) || subIds.some((s) => !s || typeof s !== 'object' || typeof s.format !== 'string')) {
      throw new ValidationError('subject.sub_ids must be an array of subject identifiers', { code: 'invalid_subject' });
    }
    const claims = {};
    const issSub = subIds.find((s) => s.format === 'iss_sub');
    const opaque = subIds.find((s) => s.format === 'opaque');
    if (issSub) {
      if (typeof issSub.iss !== 'string' || typeof issSub.sub !== 'string' || !issSub.sub) {
        throw new ValidationError('An iss_sub subject identifier needs iss and sub strings', { code: 'invalid_subject' });
      }
      claims.iss = issSub.iss;
      claims.sub = issSub.sub;
    } else if (opaque) {
      if (typeof opaque.id !== 'string' || !opaque.id) throw new ValidationError('An opaque subject identifier needs an id', { code: 'invalid_subject' });
      claims.iss = this.#config.grantEndpoint;
      claims.sub = opaque.id;
    }
    if (opaque?.id && typeof opaque.id === 'string') claims.opaque_id = opaque.id;
    // RFC 9493 `account` (RFC 7565 `acct:userpart@host`): the person's username at the AS. iya-sts writes
    // the directory uid as the user part, so it names the person where `sub` is an opaque identifier.
    const account = subIds.find((s) => s.format === 'account' && typeof s.uri === 'string');
    const acct = account && /^acct:([^@]+)@(.+)$/.exec(account.uri);
    if (acct) {
      let uid = acct[1];
      try {
        uid = decodeURIComponent(uid);
      } catch {
        // A user part that is not valid percent-encoding is kept as sent.
      }
      claims.uid = uid;
      claims.account = account.uri;
    }
    claims.sub_ids = subIds;

    const assertions = Array.isArray(subject.assertions) ? subject.assertions : [];
    const idToken = assertions.find((a) => a?.format === 'id_token' && typeof a.value === 'string');
    if (idToken && this.#jwks) {
      const cfg = this.#config.idToken;
      let verified;
      try {
        ({ payload: verified } = await jwtVerify(idToken.value, this.#jwks, {
          algorithms: cfg.algorithms ?? ASYMMETRIC_JWS_ALGS,
          issuer: cfg.issuer,
          ...(cfg.audience !== undefined ? { audience: cfg.audience } : {}),
          clockTolerance: this.#config.clockToleranceSec,
          requiredClaims: ['iss', 'sub', 'exp'],
        }));
      } catch (err) {
        const msg = err instanceof joseErrors.JOSEError ? err.message : String(err);
        throw new ValidationError(`The id_token assertion failed validation: ${msg}`, { code: 'invalid_assertion', cause: err });
      }
      // Section 3.4: every identifier and assertion in one subject names the same person.
      if (claims.sub !== undefined && issSub && verified.sub !== claims.sub) {
        throw new ValidationError('The id_token assertion is about somebody other than the subject identifier', { code: 'subject_mismatch' });
      }
      if (claims.sub === undefined || !issSub) {
        claims.iss = verified.iss;
        claims.sub = verified.sub;
      }
      for (const k of PROFILE_CLAIMS) if (verified[k] !== undefined && claims[k] === undefined) claims[k] = verified[k];
      claims.assertion_verified = true;
    }
    return claims.sub === undefined ? undefined : claims;
  }
}

/** RFC 9635 section 4.2.3: base64url(H(client nonce \n server nonce \n interact_ref \n grant endpoint)). */
export async function interactionHash(clientNonce, serverNonce, interactRef, grantEndpoint, method = 'sha-256') {
  const alg = HASH_METHODS[method];
  if (!alg) throw new ValidationError(`Unsupported interaction hash method ${method}`);
  const input = new TextEncoder().encode([clientNonce, serverNonce, interactRef, grantEndpoint].join('\n'));
  return base64url(new Uint8Array(await crypto.subtle.digest(alg, input)));
}

function grantIdOf(uri) {
  if (typeof uri !== 'string') return undefined;
  try {
    const last = new URL(uri).pathname.split('/').filter(Boolean).pop();
    return last ? decodeURIComponent(last) : undefined;
  } catch {
    return undefined;
  }
}

function toParams(input) {
  if (input instanceof URLSearchParams) return input;
  if (typeof input === 'string') {
    if (/^[a-z][a-z0-9+.-]*:/i.test(input) || input.startsWith('/')) {
      const u = new URL(input, 'http://localhost');
      const all = new URLSearchParams(u.search);
      if (u.hash.length > 1) for (const [k, v] of new URLSearchParams(u.hash.slice(1))) all.append(k, v);
      return all;
    }
    return new URLSearchParams(input.replace(/^[?#]/, ''));
  }
  return new URLSearchParams(Object.entries(input ?? {}).filter(([, v]) => typeof v === 'string'));
}
