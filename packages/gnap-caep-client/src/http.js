import { GNAPClientError, GNAPError } from './errors.js';

/**
 * Thin fetch wrapper with timeout and consistent error handling. Redirects are never followed: a GNAP
 * request is signed over its target URI, and a redirect would carry the signature somewhere else.
 * @param {string|URL} url
 * @param {RequestInit & { timeoutMs?: number, fetch?: typeof fetch }} [opts]
 */
export async function httpRequest(url, { timeoutMs = 10_000, fetch: fetchImpl = globalThis.fetch, ...init } = {}) {
  try {
    return await fetchImpl(url, { redirect: 'manual', ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    throw new GNAPClientError(`HTTP request to ${url} failed: ${err.message}`, { code: 'network_error', cause: err });
  }
}

/**
 * The GNAP error a parsed body carries, if any: RFC 9635 section 3.6's object form
 * `{ error: { code, description } }`, or the string form `{ error: "code" }`.
 * @param {any} body
 * @param {number} status
 * @returns {GNAPError|undefined}
 */
export function gnapErrorOf(body, status) {
  if (!body || typeof body !== 'object') return undefined;
  const e = body.error;
  if (typeof e === 'string') {
    return new GNAPError({ error: e, error_description: body.error_description, status, response: body, continue: body.continue });
  }
  if (e && typeof e === 'object' && typeof e.code === 'string') {
    return new GNAPError({ error: e.code, error_description: e.description, status, response: body, continue: body.continue });
  }
  return undefined;
}

/**
 * Reads a JSON body; turns GNAP error bodies and non-2xx responses into errors. A 204 or an empty
 * body answers undefined.
 * @param {Response} res
 * @param {typeof GNAPClientError} [ErrorClass]
 */
export async function readJson(res, ErrorClass = GNAPClientError) {
  const text = await res.text();
  let body;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      if (res.ok) throw new ErrorClass(`Expected JSON from ${res.url}, got: ${text.slice(0, 200)}`, { status: res.status });
    }
  }
  if (!res.ok) {
    const gnap = gnapErrorOf(body, res.status);
    if (gnap) throw gnap;
    throw new ErrorClass(`HTTP ${res.status} from ${res.url || 'the server'}${text ? `: ${text.slice(0, 200)}` : ''}`, {
      code: 'http_error',
      status: res.status,
      response: body ?? text,
    });
  }
  // RFC 9635 section 3.6 allows an error in a 200 answer too (an error beside `continue`).
  const gnap = gnapErrorOf(body, res.status);
  if (gnap) throw gnap;
  return body;
}
