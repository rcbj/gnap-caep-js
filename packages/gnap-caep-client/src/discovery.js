import { httpRequest, readJson } from './http.js';
import { ValidationError } from './errors.js';

const cache = new Map();

/**
 * `s` without its trailing slashes. A loop, not `replace(/\/+$/, '')`: that regex is retried at every
 * slash of a run that is not at the end, so a long run followed by any other character is quadratic.
 * @param {string} s
 */
function trimTrailingSlashes(s) {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x2f) end--;
  return s.slice(0, end);
}

/** Trailing slashes off, so `https://as/gnap` and `https://as/gnap/` compare equal. */
const norm = (u) => trimTrailingSlashes(String(u ?? ''));

/**
 * Builds the OpenID Connect Discovery 1.0 §4 URL: the well-known suffix is appended to the issuer.
 * Used to find the JWKS that verifies an `id_token` subject assertion.
 * @param {string} issuer
 */
export function oidcDiscoveryUrl(issuer) {
  return `${norm(issuer)}/.well-known/openid-configuration`;
}

/**
 * Builds RFC 8414 §3-style well-known URLs: the suffix is inserted between host and path.
 * Some deployments instead append it (OIDC style), so both are returned in preference order.
 * @param {string} issuer
 * @param {string} suffix e.g. "ssf-configuration"
 */
export function wellKnownUrls(issuer, suffix) {
  const u = new URL(issuer);
  const path = trimTrailingSlashes(u.pathname);
  const inserted = `${u.origin}/.well-known/${suffix}${path}`;
  const appended = `${u.origin}${path}/.well-known/${suffix}`;
  return inserted === appended ? [inserted] : [inserted, appended];
}

/**
 * Fetches metadata from the first URL that answers 2xx and checks that `check` accepts it.
 * @param {string[]} urls
 * @param {(metadata: Record<string, any>, url: string) => void} check
 * @param {{ timeoutMs?: number, fetch?: typeof fetch, cacheTtlMs?: number, method?: string }} [opts]
 */
async function fetchMetadata(urls, check, { cacheTtlMs = 60 * 60_000, method = 'GET', ...httpOpts } = {}) {
  const cacheKey = `${method} ${urls.join('|')}`;
  const hit = cache.get(cacheKey);
  if (hit && hit.expiresAt > Date.now()) return hit.metadata;

  let lastError;
  for (const url of urls) {
    const res = await httpRequest(url, { ...httpOpts, method, headers: { accept: 'application/json' } });
    if (res.status === 404 && url !== urls.at(-1)) {
      await res.body?.cancel();
      continue;
    }
    try {
      const metadata = await readJson(res);
      if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new ValidationError(`Metadata at ${url} is not a JSON object`);
      check(metadata, url);
      cache.set(cacheKey, { metadata, expiresAt: Date.now() + cacheTtlMs });
      return metadata;
    } catch (err) {
      lastError = err;
      break;
    }
  }
  throw lastError ?? new ValidationError(`No metadata found at ${urls.join(', ')}`);
}

/** Members of the RFC 9635 section 9 discovery document that are lists of strings. */
const LIST_MEMBERS = ['interaction_start_modes_supported', 'interaction_finish_methods_supported', 'key_proofs_supported',
  'sub_id_formats_supported', 'assertion_formats_supported'];

/**
 * Validates a GNAP authorization server discovery document (RFC 9635 section 9). `grant_request_endpoint`
 * is required and, when `expectedGrantEndpoint` is given, must be that endpoint: a document naming
 * another grant endpoint is a mix-up (section 11.12), as an OpenID Provider's `issuer` would be.
 * @param {Record<string, any>} metadata
 * @param {string} [expectedGrantEndpoint]
 * @returns {Record<string, any>} the same metadata
 */
export function validateGrantServerMetadata(metadata, expectedGrantEndpoint) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new ValidationError('GNAP discovery document must be a JSON object');
  }
  if (typeof metadata.grant_request_endpoint !== 'string') {
    throw new ValidationError('GNAP discovery document is missing grant_request_endpoint');
  }
  let url;
  try {
    url = new URL(metadata.grant_request_endpoint);
  } catch {
    throw new ValidationError('grant_request_endpoint is not a valid URL');
  }
  if (url.hash) throw new ValidationError('grant_request_endpoint must not contain a fragment');
  if (expectedGrantEndpoint !== undefined && norm(metadata.grant_request_endpoint) !== norm(expectedGrantEndpoint)) {
    throw new ValidationError(`Grant endpoint mismatch: expected "${expectedGrantEndpoint}", the discovery document names "${metadata.grant_request_endpoint}"`,
      { code: 'grant_endpoint_mismatch' });
  }
  for (const key of LIST_MEMBERS) {
    if (metadata[key] !== undefined && !(Array.isArray(metadata[key]) && metadata[key].every((v) => typeof v === 'string'))) {
      throw new ValidationError(`GNAP discovery member ${key} must be an array of strings`);
    }
  }
  return metadata;
}

/**
 * Discovers a GNAP authorization server: an HTTP OPTIONS request to its grant endpoint
 * (RFC 9635 section 9), validated with `validateGrantServerMetadata()`.
 * @param {string} grantEndpoint
 * @param {{ timeoutMs?: number, fetch?: typeof fetch, cacheTtlMs?: number }} [opts]
 * @returns {Promise<Record<string, any>>}
 */
export async function discoverGrantServer(grantEndpoint, opts) {
  return fetchMetadata([grantEndpoint], (m) => validateGrantServerMetadata(m, grantEndpoint), { ...opts, method: 'OPTIONS' });
}

/**
 * Retrieves OpenID Provider metadata, for the `jwks_uri` that verifies an `id_token` assertion.
 * @param {string} issuer
 * @param {{ timeoutMs?: number, fetch?: typeof fetch, cacheTtlMs?: number }} [opts]
 */
export async function discoverOpenIdProvider(issuer, opts) {
  return fetchMetadata([oidcDiscoveryUrl(issuer)], (m, url) => {
    if (m.issuer !== issuer) throw new ValidationError(`Issuer mismatch in ${url}: expected "${issuer}", got "${m.issuer}"`, { code: 'issuer_mismatch' });
    if (typeof m.jwks_uri !== 'string') throw new ValidationError(`OpenID Provider metadata at ${url} has no jwks_uri`);
  }, opts);
}

/**
 * Retrieves SSF 1.0 transmitter metadata from `/.well-known/ssf-configuration`
 * (RFC 8414-style path insertion first, then the appended form).
 * @param {string} issuer
 * @param {{ timeoutMs?: number, fetch?: typeof fetch, cacheTtlMs?: number }} [opts]
 */
export async function discoverSSFTransmitter(issuer, opts) {
  return fetchMetadata(wellKnownUrls(issuer, 'ssf-configuration'), (m, url) => {
    if (m.issuer !== issuer) throw new ValidationError(`Issuer mismatch in ${url}: expected "${issuer}", got "${m.issuer}"`, { code: 'issuer_mismatch' });
    if (!m.jwks_uri) throw new ValidationError('SSF transmitter metadata has no jwks_uri');
  }, opts);
}

/** Clears the in-process metadata cache (mostly useful in tests). */
export function clearDiscoveryCache() {
  cache.clear();
}
