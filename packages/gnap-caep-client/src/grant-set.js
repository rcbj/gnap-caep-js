const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * What a GNAP grant gave this client: one access token, how to manage it, how to continue the grant, and
 * who the resource owner is. Serializable with `toJSON()` / `GrantSet.from()`.
 *
 * The access token is bound to the client key (it is presented as `Authorization: GNAP <value>` with an
 * HTTP message signature) unless `bearer` is true.
 */
export class GrantSet {
  // Declared so TypeScript knows them; the constructor fills in whichever the response carried.
  /** The access token's value. @type {string} */
  access_token;
  /** Always "GNAP": the Authorization scheme the token is presented with. @type {string} */
  token_type;
  /** The token was issued with the `bearer` flag: no key proof is sent with it. @type {boolean|undefined} */
  bearer;
  /** The access token's flags (RFC 9635 section 3.2.1). @type {string[]|undefined} */
  flags;
  /** The token's label, when a multiple-token request named one. @type {string|undefined} */
  label;
  /** The access rights the token carries (RFC 9635 section 8). @type {Array<string|Record<string, any>>|undefined} */
  access;
  /** Token management (section 6): `{ uri, access_token: { value } }`. @type {{ uri: string, access_token: { value: string } }|undefined} */
  manage;
  /** Continuation (section 5): `{ uri, access_token: { value }, wait? }`. @type {{ uri: string, access_token: { value: string }, wait?: number }|undefined} */
  continue;
  /** The grant's id: the last path segment of the continuation URI. @type {string|undefined} */
  grant_id;
  /** The `instance_id` the AS handed this client instance (section 3.5), if any. @type {string|undefined} */
  instance_id;
  /** The grant endpoint that issued it. @type {string|undefined} */
  grant_endpoint;
  /** The thumbprint of the client key the token is bound to. @type {string|undefined} */
  key_thumbprint;
  /** The subject information as the AS returned it: `sub_ids`, `assertions`, `updated_at`. @type {Record<string, any>|undefined} */
  subject;
  /** Epoch seconds when the access token expires. @type {number|undefined} */
  expires_at;
  /** Epoch seconds when the access token was issued. @type {number|undefined} */
  issued_at;
  /**
   * Who the resource owner is, as this client validated it: `iss` and `sub` from an `iss_sub` subject
   * identifier (or an `opaque` one, with the grant endpoint as `iss`), `uid` (their username) and
   * `account` from an `account` one, and the profile claims of an `id_token` assertion when one was
   * verified. @type {Record<string, any>|undefined}
   */
  claims;

  /**
   * @param {Record<string, any>} fields  Snake-case fields, optionally with `expires_in` (seconds).
   * @param {Record<string, any>} [claims] The validated identity of the resource owner.
   */
  constructor(fields, claims) {
    const { expires_in, claims: _ignored, ...rest } = fields;
    // Field by field rather than Object.assign: a JSON "__proto__" member would otherwise replace this
    // object's prototype, and one named like a method would shadow it. `claims` comes only from the
    // second argument, which only the client's own validation fills.
    for (const [name, value] of Object.entries(rest)) {
      if (!UNSAFE_KEYS.has(name) && !(name in GrantSet.prototype)) this[name] = value;
    }
    this.token_type = 'GNAP';
    if (this.expires_at === undefined && expires_in !== undefined) {
      this.issued_at ??= Math.floor(Date.now() / 1000);
      this.expires_at = this.issued_at + Number(expires_in);
    }
    if (claims) this.claims = claims;
  }

  /** @returns {number|undefined} Seconds until the access token expires. */
  expiresIn() {
    if (this.expires_at === undefined) return undefined;
    return Math.max(0, this.expires_at - Math.floor(Date.now() / 1000));
  }

  /**
   * Skew to apply for early rotation, capped at half the token lifetime so short-lived tokens aren't
   * considered expired the moment they're issued.
   * @param {number} skewSec
   */
  effectiveSkew(skewSec) {
    if (this.issued_at === undefined || this.expires_at === undefined) return skewSec;
    return Math.min(skewSec, (this.expires_at - this.issued_at) / 2);
  }

  /** @param {number} [skewSec] Treat the token as expired this many seconds early (see effectiveSkew). */
  isExpired(skewSec = 0) {
    if (this.expires_at === undefined) return false;
    return this.expires_at - this.effectiveSkew(skewSec) <= Math.floor(Date.now() / 1000);
  }

  /** Whether the access token can be rotated (it carries a management URI). */
  canRotate() {
    return !!this.manage?.uri && !!this.manage?.access_token?.value;
  }

  /**
   * The session ids iya-sts names this grant by in a CAEP `session-revoked`: `gnap-grant:<grant id>`, and
   * `gnap-token:<jti>` when the access token is a JWT. The `jti` is read from the token without verifying
   * it; it is only ever compared with the session named in a SET whose signature was verified.
   * @returns {string[]}
   */
  sessionIds() {
    const out = [];
    if (this.grant_id) out.push(`gnap-grant:${this.grant_id}`);
    const jti = unverifiedJti(this.access_token);
    if (jti) out.push(`gnap-token:${jti}`);
    return out;
  }

  /** @returns {Record<string, any>} */
  toJSON() {
    return { ...this };
  }

  /**
   * @param {GrantSet|Record<string, any>} value  A GrantSet, or one as stored (`toJSON()`).
   * @returns {GrantSet}
   */
  static from(value) {
    if (!value || value instanceof GrantSet) return /** @type {GrantSet} */ (value);
    const { claims, ...fields } = value;
    return new GrantSet(fields, claims);
  }
}

function unverifiedJti(token) {
  const part = String(token ?? '').split('.');
  if (part.length !== 3) return undefined;
  try {
    const json = atob(part[1].replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(part[1].length / 4) * 4, '='));
    const jti = JSON.parse(json)?.jti;
    return typeof jti === 'string' && jti ? jti : undefined;
  } catch {
    return undefined;
  }
}
