import { GNAPClientError, GNAPError } from './errors.js';
import { GrantSet } from './grant-set.js';
import { MemoryTokenStore } from './stores.js';
import { Emitter, withLock } from './util.js';

const MAX_TIMEOUT_MS = 2 ** 31 - 1;

/** GNAP errors that say a token can never be rotated again: the grant is gone. */
const FATAL_ROTATION_ERRORS = ['invalid_rotation', 'invalid_continuation', 'invalid_client', 'request_denied'];

/**
 * Caches GrantSets per key (typically one per signed-in person) and keeps their access tokens fresh by
 * GNAP token rotation (RFC 9635 section 6.1).
 *
 * - `getTokenSet(key)` always returns a token valid for at least `refreshSkewSec`, rotating on demand.
 * - With `autoRefresh` (default), a timer rotates each token `refreshSkewSec` before it expires.
 * - Concurrent rotations for the same key are coalesced into one request; across tabs sharing a store, a
 *   rotation holds a Web Lock and reuses the token another tab has just obtained, so a management token
 *   is never presented twice.
 *
 * Events:
 *   "rotated"         (key, grantSet)  — a new access token obtained by rotation
 *   "rotation_error"  (key, error)     — rotation failed (tokens are dropped when the grant is gone)
 *   "expired"         (key)            — tokens for key could not be renewed and were removed
 *   "removed"         (key)            — tokens deleted via delete()
 */
export class TokenManager extends Emitter {
  #client;
  #store;
  #timers = new Map();
  #wanted = new Set();
  #inflight = new Map();
  #opts;

  /**
   * @param {import('./gnap-client.js').GNAPClient} client
   * @param {{ store?: import('./stores.js').TokenStore, refreshSkewSec?: number, autoRefresh?: boolean, minRefreshDelayMs?: number, retryDelayMs?: number }} [opts]
   */
  constructor(client, { store = new MemoryTokenStore(), refreshSkewSec = 60, autoRefresh = true, minRefreshDelayMs = 1000, retryDelayMs = 5000 } = {}) {
    super();
    this.#client = client;
    this.#store = store;
    this.#opts = { refreshSkewSec, autoRefresh, minRefreshDelayMs, retryDelayMs };
  }

  /**
   * Stores a grant for a key and (unless `schedule: false`) schedules its proactive rotation.
   * @param {string} key
   * @param {GrantSet|object} grantSet
   * @param {{ schedule?: boolean }} [opts]
   * @returns {Promise<GrantSet>}
   */
  async set(key, grantSet, { schedule = true } = {}) {
    const ts = GrantSet.from(grantSet);
    await this.#store.set(key, ts.toJSON());
    if (schedule) this.#wanted.add(key);
    else this.unschedule(key);
    this.#schedule(key, ts);
    return ts;
  }

  /**
   * Schedules the proactive rotation of the token already stored for key.
   * @param {string} key
   * @returns {Promise<void>}
   */
  async schedule(key) {
    this.#wanted.add(key);
    const ts = await this.get(key);
    if (ts) this.#schedule(key, ts);
  }

  /**
   * Stops rotating key's token in the background; it stays stored.
   * @param {string} key
   */
  unschedule(key) {
    this.#wanted.delete(key);
    clearTimeout(this.#timers.get(key));
    this.#timers.delete(key);
  }

  /**
   * @param {string} key
   * @returns {Promise<GrantSet|undefined>} The cached grant (possibly expired) for key.
   */
  async get(key) {
    const raw = await this.#store.get(key);
    return raw ? GrantSet.from(raw) : undefined;
  }

  /**
   * Rotates key's access token now. Concurrent calls share a single request.
   * @param {string} key
   * @returns {Promise<GrantSet>}
   */
  rotate(key) {
    const existing = this.#inflight.get(key);
    if (existing) return existing;
    const p = (async () => {
      const before = await this.get(key);
      if (!before) throw new GNAPClientError(`No tokens cached for ${key}`, { code: 'no_tokens' });
      try {
        return await withLock(rotationLock(key), async () => {
          // Another tab sharing the store may have rotated while this one waited for the lock.
          const current = await this.get(key);
          if (!current) throw new GNAPClientError(`Tokens for ${key} were removed`, { code: 'no_tokens' });
          if (current.access_token !== before.access_token && !current.isExpired(this.#opts.refreshSkewSec)) {
            this.#schedule(key, current);
            return current;
          }
          const next = await this.#client.rotate(current);
          // Deleted while the request was in flight (by another tab): the new token is revoked rather than
          // left valid at the AS.
          if (!(await this.#store.get(key))) {
            await this.#client.revokeToken(next).catch(() => {});
            throw new GNAPClientError(`Tokens for ${key} were removed during rotation`, { code: 'no_tokens' });
          }
          await this.set(key, next, { schedule: this.#wanted.has(key) });
          this.emit('rotated', key, next);
          return next;
        });
      } catch (err) {
        this.emit('rotation_error', key, err);
        if (err instanceof GNAPError && FATAL_ROTATION_ERRORS.includes(err.error)) await this.#drop(key, 'expired');
        throw err;
      }
    })().finally(() => this.#inflight.delete(key));
    this.#inflight.set(key, p);
    return p;
  }

  /**
   * Removes the grant for key, optionally revoking it at the AS: the whole grant (section 5.4), or with
   * `revoke: 'token'` only its access token (section 6.2).
   * @param {string} key
   * @param {{ revoke?: boolean|'grant'|'token' }} [opts]
   * @returns {Promise<GrantSet|undefined>}
   */
  async delete(key, { revoke = false } = {}) {
    // Under the rotation lock: a rotation in flight finishes first, so it can't write its token back.
    const ts = await withLock(rotationLock(key), async () => {
      const held = await this.get(key);
      await this.#drop(key, 'removed');
      return held;
    });
    if (revoke && ts) {
      if (revoke === 'token') await this.#client.revokeToken(ts).catch(() => {});
      else {
        const revoked = await this.#client.revokeGrant(ts).catch(() => false);
        if (!revoked) await this.#client.revokeToken(ts).catch(() => {});
      }
    }
    return ts;
  }

  /**
   * Returns the cached grant for key, rotating first if the access token is (nearly) expired.
   * @param {string} key
   * @param {{ forceRefresh?: boolean }} [opts]
   * @returns {Promise<GrantSet>}
   */
  async getTokenSet(key, { forceRefresh = false } = {}) {
    let ts = await this.get(key);
    if (!ts) throw new GNAPClientError(`No tokens cached for ${key}`, { code: 'no_tokens' });
    if (forceRefresh || ts.isExpired(this.#opts.refreshSkewSec)) {
      if (ts.canRotate()) {
        ts = await this.rotate(key);
      } else if (ts.isExpired()) {
        await this.#drop(key, 'expired');
        throw new GNAPClientError('Access token expired and cannot be rotated', { code: 'token_expired' });
      }
    }
    return ts;
  }

  /** Cancels all rotation timers (call on shutdown). */
  close() {
    for (const t of this.#timers.values()) clearTimeout(t);
    this.#timers.clear();
    this.#wanted.clear();
  }

  async #drop(key, event) {
    this.unschedule(key);
    await this.#store.delete(key);
    this.emit(event, key);
  }

  #schedule(key, ts) {
    clearTimeout(this.#timers.get(key));
    this.#timers.delete(key);
    if (!this.#opts.autoRefresh || !this.#wanted.has(key) || ts.expires_at === undefined || !ts.canRotate()) return;
    const dueMs = (ts.expires_at - ts.effectiveSkew(this.#opts.refreshSkewSec)) * 1000 - Date.now();
    const delay = Math.min(MAX_TIMEOUT_MS, Math.max(this.#opts.minRefreshDelayMs, dueMs));
    const timer = setTimeout(() => {
      this.#timers.delete(key);
      this.rotate(key).catch(() => this.#retry(key));
    }, delay);
    timer.unref?.();
    this.#timers.set(key, timer);
  }

  /** After a transient background-rotation failure (already surfaced via "rotation_error"), try again later. */
  async #retry(key) {
    const ts = await this.get(key);
    if (!ts || this.#timers.has(key) || !this.#wanted.has(key)) return;
    if (ts.isExpired()) {
      await this.#drop(key, 'expired');
      return;
    }
    const timer = setTimeout(() => {
      this.#timers.delete(key);
      this.rotate(key).catch(() => this.#retry(key));
    }, this.#opts.retryDelayMs);
    timer.unref?.();
    this.#timers.set(key, timer);
  }
}

/** The lock one key's rotations and deletes share, across this origin's tabs. */
function rotationLock(key) {
  return `gnap-caep-client:rotate:${key}`;
}
