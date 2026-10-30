// HTTP message signatures (RFC 9421) with an RFC 9530 Content-Digest, as RFC 9635 section 7.3.1 profiles
// them for GNAP's `httpsig` key proof. Web APIs only.
import { randomToken } from './util.js';

const encoder = new TextEncoder();

/** Standard base64 (with padding), as RFC 8941 byte sequences use. */
export function base64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

/**
 * RFC 9530 section 2: `sha-256=:<base64 of SHA-256 over the content>:`.
 * @param {string|Uint8Array} body
 * @returns {Promise<string>}
 */
export async function contentDigest(body) {
  const bytes = typeof body === 'string' ? encoder.encode(body) : body;
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return `sha-256=:${base64(d)}:`;
}

/** RFC 8941 section 4.1.6: a String. */
function sfString(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * The covered components and the `@signature-params` value for one signature.
 * @param {string[]} components  component identifiers without quotes, e.g. `@method`, `content-digest`
 * @param {{ created: number, nonce?: string, keyid: string, tag?: string }} params
 */
export function signatureParams(components, params) {
  let out = `(${components.map((c) => `"${c}"`).join(' ')})`;
  out += `;created=${params.created}`;
  if (params.nonce) out += `;nonce=${sfString(params.nonce)}`;
  out += `;keyid=${sfString(params.keyid)}`;
  if (params.tag) out += `;tag=${sfString(params.tag)}`;
  return out;
}

/**
 * The RFC 9421 section 2.5 signature base.
 * @param {string[]} components
 * @param {{ method: string, url: string, headers: Record<string, string> }} message  headers with lower-case names
 * @param {string} serialisedParams
 */
export function signatureBase(components, message, serialisedParams) {
  const lines = components.map((c) => {
    let value;
    if (c === '@method') value = message.method.toUpperCase();
    else if (c === '@target-uri') value = message.url;
    else if (c === '@authority') value = new URL(message.url).host.toLowerCase();
    else {
      value = message.headers[c];
      if (value === undefined) throw new TypeError(`Cannot sign "${c}": the request has no such header`);
      value = String(value).trim();
    }
    if (/[\r\n]/.test(value)) throw new TypeError(`Cannot sign "${c}": the value contains a line break`);
    return `"${c}": ${value}`;
  });
  lines.push(`"@signature-params": ${serialisedParams}`);
  return lines.join('\n');
}

/**
 * Signs a request for GNAP's `httpsig` proof (RFC 9635 section 7.3.1). The signature covers `@method`,
 * `@target-uri`, `content-digest` when there is content, and `authorization` when an access token is
 * presented, with `created`, a fresh `nonce`, the key's `keyid` and the `gnap` tag.
 *
 * @param {{ method: string, url: string, headers?: Record<string, string>, body?: string|Uint8Array,
 *   key: { thumbprint: string, sign(data: Uint8Array): Promise<Uint8Array> }, created?: number, nonce?: string, label?: string }} req
 * @returns {Promise<Record<string, string>>} the headers to add: `signature`, `signature-input`, and
 *   `content-digest` when there is content
 */
export async function signRequest({ method, url, headers = {}, body, key, created, nonce, label = 'sig1' }) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const added = {};
  const components = ['@method', '@target-uri'];
  const hasBody = body !== undefined && body !== null && (typeof body === 'string' ? body.length > 0 : body.byteLength > 0);
  if (hasBody) {
    added['content-digest'] = await contentDigest(body);
    lower['content-digest'] = added['content-digest'];
    components.push('content-digest');
  }
  if (lower.authorization) components.push('authorization');
  const params = signatureParams(components, {
    created: created ?? Math.floor(Date.now() / 1000),
    nonce: nonce ?? randomToken(16),
    keyid: key.thumbprint,
    tag: 'gnap',
  });
  const base = signatureBase(components, { method, url: new URL(url).href, headers: lower }, params);
  const signature = await key.sign(encoder.encode(base));
  added['signature-input'] = `${label}=${params}`;
  added.signature = `${label}=:${base64(signature)}:`;
  return added;
}
