import { subjectMatches } from './caep/subjects.js';
import { GNAPClientError } from './errors.js';
import { GrantSet } from './grant-set.js';
import { IndexedDBTokenStore, MemoryTokenStore, WebStorageTokenStore } from './stores.js';
import { TokenManager } from './token-manager.js';
import { base64url, digest, Emitter, withLock } from './util.js';

/** Identity claims an account record keeps, for display and for matching security events. No tokens. */
const PROFILE_CLAIMS = ['iss', 'sub', 'uid', 'account', 'name', 'given_name', 'family_name', 'preferred_username', 'email',
  'email_verified', 'phone_number', 'phone_number_verified', 'picture', 'acr', 'amr', 'auth_time'];

/**
 * @typedef {object} Account  One person signed in through this client in this browser. Holds no token.
 * @property {string} key          Stable id derived from `iss` and `sub`.
 * @property {string} iss
 * @property {string} sub
 * @property {string[]} [sessions] The session ids iya-sts names this account's grant by in a CAEP event:
 *           `gnap-grant:<id>` and `gnap-token:<jti>`.
 * @property {string} [grantId]
 * @property {string} [uid]        The person's username at the AS, from an `account` subject identifier.
 * @property {string} [name]
 * @property {string} [email]
 * @property {string} [preferred_username]
 * @property {'signed-in'|'tokens-missing'|'signed-out'|'ended'} status
 *           `signed-in`: its grant is in the cache. `tokens-missing`: not signed out, but its access token
 *           expired and could not be rotated; `reauthenticate()` asks for a new grant. `ended`: ended by
 *           the AS, a security event or a refused rotation; see `endedReason`.
 * @property {string} [endedReason]
 * @property {number} addedAt
 * @property {number} lastUsedAt
 * @property {number} [changedAt]  When the status last left `signed-in`.
 */

/**
 * @callback AccountHook
 * @param {Account} account
 * @param {{ getTokenSet: (opts?: { forceRefresh?: boolean }) => Promise<GrantSet> }} access
 *        Reaches this account's grant during the hook (and, for `onActivate`, for as long as it stays active).
 * @returns {unknown} Anything; a promise is awaited.
 */

/**
 * @typedef {object} AccountManagerOptions
 * @property {import('./stores.js').TokenStore} [store]  The cache shared by every tab: the account list and
 *           each account's grant. Default: IndexedDB (`IndexedDBTokenStore`) when tokens are key-bound
 *           (`requireBoundTokens`, the default), else memory.
 * @property {import('./stores.js').TokenStore} [tabStore]  Where this tab remembers its active account.
 *           Default: sessionStorage where it exists, else memory.
 * @property {string} [storeKey]                Default "accounts".
 * @property {number} [refreshSkewSec]          Default 60.
 * @property {number} [maxAccounts]             Default 10.
 * @property {number} [rememberSignedOutDays]   How long a signed-out account stays listed. Default 30.
 * @property {AccountHook} [onActivate]  Runs when an account is about to become this tab's active account,
 *           after its token is rotated if due and before "activated" is emitted — e.g. to poll its CAEP
 *           stream and act on the signals queued while it was dormant. Throwing aborts the activation.
 * @property {(account: Account) => void|Promise<void>} [onDeactivate]  Runs when an account stops being
 *           this tab's active account (e.g. to stop polling its stream).
 * @property {AccountHook} [onLeave]  Runs before an account's grant is dropped by `signOut()` or `end()`
 *           (e.g. to delete its CAEP stream while its token still works).
 * @property {boolean} [broadcast]  Tell this origin's other tabs about changes (BroadcastChannel). Default true.
 */

/**
 * Every person signed in through one GNAP client in this browser, with ONE active account per tab.
 *
 * - **One cache, shared by every tab.** Each account's grant (access token, management and continuation)
 *   is kept until the account is signed out or its grant ends, so any tab can make any signed-in account
 *   active with no trip to the AS.
 * - **One active account per tab.** Only its token is reachable (`getTokenSet()`), and only its token is
 *   rotated in the background. The others are dormant. `activate(key)` rotates a dormant account's token
 *   if due and runs `onActivate` before it becomes active.
 * - Rotations hold a lock shared by the tabs (Web Locks); sign-outs and ended grants are announced to the
 *   other tabs (BroadcastChannel).
 *
 * Signing in: `signIn()` / `addAccount()` start a grant the AS decides on (its account picker when several
 * people are signed in there). `reauthenticate(key)` names the person in the request's `user` and refuses
 * a grant approved by anybody else. `signOut(key)` revokes that account's grant at the AS.
 *
 * Events: "added" (account), "updated" (account), "activated" (account|undefined, previous|undefined),
 * "rotated" (account) for the active account, "signed-out" (account), "ended" (account, reason),
 * "forgotten" (account), "activation_error" (account, error), and "change" after any of them, including
 * changes made in another tab.
 */
export class AccountManager extends Emitter {
  #client;
  #tokens;
  #store;
  #tabStore;
  #storeKey;
  #opts;
  /** @type {Map<string, Account>} */
  #accounts = new Map();
  #active;
  #activating;
  #mutating;
  #channel;

  /**
   * @param {import('./gnap-client.js').GNAPClient} client
   * @param {AccountManagerOptions} [opts]
   */
  constructor(client, {
    store, tabStore, storeKey = 'accounts', refreshSkewSec = 60, maxAccounts = 10, rememberSignedOutDays = 30,
    onActivate, onDeactivate, onLeave, broadcast = true,
  } = {}) {
    super();
    this.#client = client;
    // Tokens at rest need a sender constraint. GNAP tokens are bound to the client key unless the AS issued
    // a bearer token, which `requireBoundTokens` (the default) refuses.
    const bound = client.config?.requireBoundTokens !== false;
    this.#store = store ?? (bound && typeof indexedDB !== 'undefined' ? new IndexedDBTokenStore() : new MemoryTokenStore());
    if (store && !bound && !(store instanceof MemoryTokenStore)) {
      console.warn('[gnap-caep-client] AccountManager: bearer tokens may be kept in persistent browser storage. '
        + 'Any script in the page can read them and use them anywhere; keep requireBoundTokens on or use MemoryTokenStore.');
    }
    this.#tabStore = tabStore ?? (globalThis.sessionStorage ? new WebStorageTokenStore({ prefix: 'gnap-caep-client:tab:' }) : new MemoryTokenStore());
    this.#storeKey = storeKey;
    this.#opts = { maxAccounts, rememberSignedOutDays, refreshSkewSec, onActivate, onDeactivate, onLeave };
    this.#tokens = new TokenManager(client, { store: this.#store, refreshSkewSec });
    this.#tokens.on('rotated', (key, ts) => { this.#onRotated(key, ts).catch(() => {}); });
    this.#tokens.on('expired', (key) => { this.end(key, 'Its access token could not be renewed.').catch(() => {}); });
    if (broadcast && typeof BroadcastChannel !== 'undefined') {
      this.#channel = new BroadcastChannel(`gnap-caep-client:${storeKey}`);
      this.#channel.onmessage = () => { this.#onRemoteChange().catch(() => {}); };
      this.#channel.unref?.();
    }
  }

  /**
   * Loads the shared account list and reactivates the account this tab had active. A failed reactivation
   * leaves the tab with no active account and is emitted as "activation_error".
   */
  async init() {
    const forgetBefore = Date.now() - this.#opts.rememberSignedOutDays * 86_400_000;
    await this.#mutate(() => {
      for (const a of [...this.#accounts.values()]) {
        if (a.status === 'signed-out' && (a.changedAt ?? 0) < forgetBefore) this.#accounts.delete(a.key);
      }
    });
    const remembered = await this.#tabStore.get(this.#tabKey());
    if (remembered && this.#accounts.has(remembered)) {
      try {
        await this.#activate(remembered);
      } catch (err) {
        this.emit('activation_error', this.get(remembered), err);
      }
    }
    return this;
  }

  /** @returns {Account[]} Every account in this browser, in the order added. */
  list() {
    return [...this.#accounts.values()].sort((a, b) => a.addedAt - b.addedAt).map((a) => ({ ...a }));
  }

  /** @param {string} key @returns {Account|undefined} */
  get(key) {
    const a = this.#accounts.get(key);
    return a && { ...a };
  }

  /** @returns {Account|undefined} This tab's active account (whatever its status). */
  get active() { return this.get(this.#active); }
  get activeKey() { return this.#active; }

  /**
   * The identity `subjectMatches()` compares a security event's subject with: `iss`, `sub`, the grant's
   * session ids as `sid`, and a verified email or phone number.
   * @param {string} key
   * @returns {{ iss: string, sub: string, sid?: string[], email?: string, email_verified?: boolean,
   *   phone_number?: string, phone_number_verified?: boolean }|undefined}
   */
  identity(key) {
    const a = this.#accounts.get(key);
    return a && { iss: a.iss, sub: a.sub, sid: a.sessions, email: a.email, email_verified: a.email_verified,
      phone_number: a.phone_number, phone_number_verified: a.phone_number_verified };
  }

  /**
   * The accounts a security event's subject (`sub_id`) is about. A subject naming a session (iya-sts:
   * `gnap-grant:<id>` or `gnap-token:<jti>`) matches only the account holding that grant or token.
   * @param {object} subId
   * @returns {Account[]}
   */
  accountsForSubject(subId) {
    return this.list().filter((a) => subjectMatches(subId, this.identity(a.key)));
  }

  // ---------------------------------------------------------------------------
  // The active account's grant: the only one reachable
  // ---------------------------------------------------------------------------

  /**
   * The active account's grant, its token rotated first when (nearly) expired.
   * @param {{ forceRefresh?: boolean }} [opts]
   * @returns {Promise<GrantSet>}
   */
  getTokenSet(opts) {
    return this.#tokensFor(this.#active, opts);
  }

  /**
   * Rotates the active account's access token now.
   * @returns {Promise<GrantSet>}
   */
  rotate() {
    return this.#tokensFor(this.#active, { forceRefresh: true });
  }

  async #tokensFor(key, opts) {
    if (!key || (key !== this.#active && key !== this.#activating)) {
      throw new GNAPClientError('Only the active account\'s tokens can be used; activate the account first', { code: 'not_active' });
    }
    if (this.#accounts.get(key)?.status !== 'signed-in') {
      throw new GNAPClientError('The active account is not signed in', { code: 'no_tokens' });
    }
    return this.#tokens.getTokenSet(key, opts);
  }

  // ---------------------------------------------------------------------------
  // Signing in
  // ---------------------------------------------------------------------------

  /**
   * Starts a grant the AS decides on. Resolves `{ url }` to send the browser to; or, when the AS issued
   * the grant with nobody asked, the signed-in account (`{ account, grantSet, intent, added }`).
   * @param {Parameters<import('./gnap-client.js').GNAPClient['createGrantRequest']>[0]} [opts]
   */
  signIn(opts = {}) {
    return this.#start({ ...opts, context: { intent: 'sign-in' } });
  }

  /**
   * Starts a grant for another person, added as a further account.
   * @param {Parameters<import('./gnap-client.js').GNAPClient['createGrantRequest']>[0]} [opts]
   */
  addAccount(opts = {}) {
    return this.#start({ ...opts, context: { intent: 'add' } });
  }

  /**
   * Starts a grant for this account's person again: the request names them in `user` (RFC 9635 section
   * 2.4), and a grant approved by anybody else is refused at the callback (`account_mismatch`).
   * @param {string} key
   * @param {Parameters<import('./gnap-client.js').GNAPClient['createGrantRequest']>[0]} [opts]
   */
  reauthenticate(key, opts = {}) {
    const a = this.#mustGet(key);
    return this.#start({
      user: { sub_ids: [{ format: 'iss_sub', iss: a.iss, sub: a.sub }] },
      ...opts,
      expectedSub: a.sub,
      context: { intent: 'reauth', key },
    });
  }

  async #start(opts) {
    const result = await this.#client.createGrantRequest(opts);
    if (result.grantSet) return this.#record(result.grantSet, opts.context);
    return { url: /** @type {string} */ (result.url) };
  }

  /**
   * Completes a grant from the finish redirect. The person it is about is added to the cache (or, when
   * already listed, signed in again) and becomes this tab's active account.
   *
   * An error is thrown with `err.context` (`{ intent, key? }`) and, for `reauth`, `err.account`.
   * @param {URLSearchParams|Record<string,string>|string} response
   * @returns {Promise<{ account: Account, grantSet: GrantSet, intent: string, added: boolean }>}
   */
  async handleCallback(response) {
    let result;
    try {
      result = await this.#client.completeGrant(response);
    } catch (err) {
      if (err.context?.key) {
        await this.#load();
        err.account = this.get(err.context.key);
      }
      throw err;
    }
    return this.#record(result.grantSet, result.context);
  }

  async #record(grantSet, context) {
    const claims = grantSet.claims;
    if (!claims?.sub) {
      await this.#client.revokeGrant(grantSet).catch(() => {});
      throw new GNAPClientError('The grant carries no subject information, so nobody can be signed in: ask for sub_id formats the AS supports',
        { code: 'no_subject' });
    }
    const key = await accountKey(claims.iss, claims.sub);
    let added = false;
    await this.#mutate(async () => {
      let account = this.#accounts.get(key);
      added = !account;
      if (added) {
        this.#makeRoom(grantSet);
        account = /** @type {Account} */ ({ key, addedAt: Date.now() });
        this.#accounts.set(key, account);
      }
      for (const c of PROFILE_CLAIMS) delete account[c];
      Object.assign(account, pick(claims, PROFILE_CLAIMS), {
        status: 'signed-in', lastUsedAt: Date.now(), sessions: grantSet.sessionIds(), grantId: grantSet.grant_id,
      });
      delete account.endedReason;
      delete account.changedAt;
      await this.#tokens.set(key, grantSet, { schedule: false });
    });
    this.emit(added ? 'added' : 'updated', this.get(key));
    await this.#activate(key);
    return { account: /** @type {Account} */ (this.get(key)), grantSet, intent: context?.intent ?? 'sign-in', added };
  }

  // ---------------------------------------------------------------------------
  // Activating
  // ---------------------------------------------------------------------------

  /**
   * Makes a listed account this tab's active account; the previous one becomes dormant. Nothing is sent to
   * the AS unless the account's token is due for rotation. When the rotation or `onActivate` fails, the
   * previously active account is reactivated and the error thrown.
   * @param {string} key
   * @returns {Promise<Account|undefined>}
   */
  async activate(key) {
    this.#mustGet(key);
    const previous = this.#active;
    try {
      await this.#activate(key);
    } catch (err) {
      if (previous && previous !== key && this.#active !== previous) await this.#activate(previous).catch(() => {});
      throw err;
    }
    return this.active;
  }

  async #activate(key) {
    await this.#load();
    const previous = this.#active;
    if (previous && previous !== key) await this.#deactivate();
    this.#mustGet(key);
    if (this.#accounts.get(key).status === 'signed-in') {
      let ts = await this.#tokens.get(key);
      if (ts?.isExpired(this.#opts.refreshSkewSec)) {
        ts = ts.canRotate() ? await this.#tokens.rotate(key) : (ts.isExpired() ? undefined : ts);
      }
      if (!ts) {
        await this.#tokens.delete(key).catch(() => {});
        await this.#mutate(() => this.#setStatus(key, 'tokens-missing'));
      } else if (this.#opts.onActivate) {
        this.#activating = key;
        try {
          await this.#opts.onActivate(this.get(key), { getTokenSet: (opts) => this.#tokensFor(key, opts) });
        } finally {
          this.#activating = undefined;
        }
        await this.#load(); // a signal acted on during onActivate may have ended the account
      }
    }
    this.#active = key;
    await this.#tabStore.set(this.#tabKey(), key);
    if (this.#accounts.get(key)?.status === 'signed-in') {
      await this.#mutate(() => { const a = this.#accounts.get(key); if (a) a.lastUsedAt = Date.now(); });
      await this.#tokens.schedule(key);
    }
    if (previous !== key) this.emit('activated', this.get(key), this.get(previous));
    this.emit('change');
  }

  async #deactivate() {
    const key = this.#active;
    if (!key) return;
    this.#tokens.unschedule(key);
    this.#active = undefined;
    await this.#tabStore.delete(this.#tabKey());
    const a = this.get(key);
    if (a) await Promise.resolve(this.#opts.onDeactivate?.(a)).catch(() => {});
  }

  // ---------------------------------------------------------------------------
  // Signing out, ending, forgetting
  // ---------------------------------------------------------------------------

  /**
   * Signs one account out of this browser: `onLeave` runs, its grant is revoked at the AS (with `revoke`,
   * the default) and removed from the cache, and it stays listed as `signed-out`. GNAP has no front-channel
   * logout: revoking the grant is what ends it, and iya-sts then sends CAEP `session-revoked` for it.
   * @param {string} [key]  Default: the active account.
   * @param {{ revoke?: boolean }} [opts]
   * @returns {Promise<Account|undefined>}
   */
  async signOut(key = this.#active, { revoke = true } = {}) {
    if (!key) return undefined;
    const { account } = await this.#leave(key, 'signed-out', { revoke });
    await this.#afterLeaving(key);
    this.emit('signed-out', account);
    this.emit('change');
    return this.get(key);
  }

  /**
   * Signs every account out of this browser, revoking each grant.
   * @param {{ revoke?: boolean }} [opts]
   */
  async signOutAll({ revoke = true } = {}) {
    await this.#load();
    const previous = this.active;
    for (const a of this.list().filter((x) => x.status === 'signed-in' || x.status === 'tokens-missing')) {
      const { account } = await this.#leave(a.key, 'signed-out', { revoke });
      this.emit('signed-out', account);
    }
    if (this.#active) await this.#deactivate();
    if (previous) this.emit('activated', undefined, this.get(previous.key));
    this.emit('change');
  }

  /**
   * Ends an account's session in this browser because the AS or a security event says its grant has
   * ended: `onLeave` runs, its grant is removed from the cache (not revoked: the AS already knows), and it
   * stays listed as `ended` with the reason. Does nothing for an account that is not signed in.
   * @param {string} key
   * @param {string} [reason]
   * @returns {Promise<Account|undefined>}
   */
  async end(key, reason) {
    await this.#load();
    const a = this.#accounts.get(key);
    if (!a || (a.status !== 'signed-in' && a.status !== 'tokens-missing')) return a && { ...a };
    const { account } = await this.#leave(key, 'ended', { revoke: false, reason });
    if (this.#activating !== key) await this.#afterLeaving(key);
    this.emit('ended', account, reason);
    this.emit('change');
    return this.get(key);
  }

  /**
   * Removes an account that is not signed in from the list.
   * @param {string} key
   * @returns {Promise<void>}
   */
  async forget(key) {
    let removed;
    await this.#mutate(() => {
      const a = this.#mustGet(key);
      if (a.status === 'signed-in') throw new GNAPClientError('Sign the account out before forgetting it', { code: 'account_signed_in' });
      this.#accounts.delete(key);
      removed = a;
    });
    await this.#tokens.delete(key).catch(() => {});
    if (this.#active === key) {
      this.#active = undefined;
      await this.#tabStore.delete(this.#tabKey());
      this.emit('activated', undefined, removed);
    }
    this.emit('forgotten', removed);
    this.emit('change');
  }

  /** Cancels rotation timers and stops listening to other tabs (call on shutdown). */
  close() {
    this.#tokens.close();
    this.#channel?.close();
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  #tabKey() { return `active:${this.#storeKey}`; }

  #mustGet(key) {
    const a = this.#accounts.get(key);
    if (!a) throw new GNAPClientError(`No account ${key}`, { code: 'no_account' });
    return a;
  }

  async #leave(key, status, { revoke, reason }) {
    await this.#load();
    const a = this.#mustGet(key);
    const cached = await this.#tokens.get(key);
    if (cached && this.#opts.onLeave) {
      await Promise.resolve(this.#opts.onLeave(this.get(key), { getTokenSet: (opts) => this.#tokens.getTokenSet(key, opts) })).catch(() => {});
    }
    await this.#tokens.delete(key, { revoke }).catch(() => {});
    await this.#mutate(() => {
      this.#setStatus(key, status);
      const x = this.#accounts.get(key);
      if (x && reason !== undefined) x.endedReason = reason;
    });
    return { account: this.get(key) ?? { ...a, status } };
  }

  async #afterLeaving(key) {
    if (this.#active !== key) return;
    await this.#deactivate();
    const next = [...this.#accounts.values()].filter((a) => a.status === 'signed-in').sort((a, b) => b.addedAt - a.addedAt)[0];
    if (next) {
      await this.#activate(next.key).catch((err) => this.emit('activation_error', this.get(next.key), err));
    } else {
      this.emit('activated', undefined, this.get(key));
    }
  }

  #setStatus(key, status) {
    const a = this.#accounts.get(key);
    if (!a) return;
    a.status = status;
    a.changedAt = Date.now();
    if (status !== 'ended') delete a.endedReason;
  }

  #makeRoom(grantSet) {
    if (this.#accounts.size < this.#opts.maxAccounts) return;
    const droppable = [...this.#accounts.values()].filter((a) => a.status !== 'signed-in')
      .sort((a, b) => (a.changedAt ?? a.lastUsedAt) - (b.changedAt ?? b.lastUsedAt));
    if (!droppable.length) {
      void this.#client.revokeGrant(grantSet).catch(() => {});
      throw new GNAPClientError(`${this.#opts.maxAccounts} accounts are signed in already; sign one out first`, { code: 'too_many_accounts' });
    }
    this.#accounts.delete(droppable[0].key);
    this.#tokens.delete(droppable[0].key).catch(() => {});
    this.emit('forgotten', droppable[0]);
  }

  async #onRotated(key, ts) {
    await this.#mutate(() => {
      const a = this.#accounts.get(key);
      if (a) a.sessions = GrantSet.from(ts).sessionIds();
    });
    if (key === this.#active) this.emit('rotated', this.get(key));
    this.emit('change');
  }

  async #onRemoteChange() {
    await this.#load();
    const key = this.#active;
    if (key && this.#accounts.get(key)?.status !== 'signed-in') this.#tokens.unschedule(key);
    if (key && !this.#accounts.has(key)) {
      this.#active = undefined;
      await this.#tabStore.delete(this.#tabKey());
      this.emit('activated', undefined, undefined);
    }
    this.emit('change');
  }

  /** Re-reads the shared list, after any change this tab is making. Never call it inside a #mutate callback. */
  async #load() {
    while (this.#mutating) await this.#mutating.catch(() => {});
    await this.#read();
  }

  async #read() {
    const saved = await this.#store.get(this.#storeKey);
    this.#accounts = new Map((saved?.accounts ?? []).map((a) => [a.key, a]));
  }

  /** Read-modify-write of the shared list, under a lock shared by the tabs; then tells the other tabs. */
  async #mutate(fn) {
    while (this.#mutating) await this.#mutating.catch(() => {});
    const run = withLock(`gnap-caep-client:${this.#storeKey}`, async () => {
      await this.#read();
      await fn();
      await this.#store.set(this.#storeKey, { accounts: [...this.#accounts.values()] });
    });
    this.#mutating = run;
    try {
      await run;
    } finally {
      if (this.#mutating === run) this.#mutating = undefined;
    }
    this.#channel?.postMessage({ type: 'change' });
  }
}

/**
 * The account key for an `iss` and `sub`: stable, opaque, and safe in a storage key or a URL.
 * @param {string} iss
 * @param {string} sub
 * @returns {Promise<string>}
 */
export async function accountKey(iss, sub) {
  return `acct-${base64url(await digest(`${iss}\n${sub}`)).slice(0, 22)}`;
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj[k] !== undefined) out[k] = obj[k];
  return out;
}
