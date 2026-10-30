import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK } from 'jose';

/** Client key algorithms this library can sign HTTP messages with, in preference order. */
export const CLIENT_KEY_ALGS = Object.freeze(['ES256', 'ES384', 'PS256', 'RS256']);

/** WebCrypto parameters for signing with each JWS algorithm (RFC 9421 section 3.3.7). */
const SIGN_PARAMS = {
  ES256: { name: 'ECDSA', hash: 'SHA-256' },
  ES384: { name: 'ECDSA', hash: 'SHA-384' },
  PS256: { name: 'RSA-PSS', saltLength: 32 },
  RS256: { name: 'RSASSA-PKCS1-v1_5' },
};

/**
 * Where the client key pair is kept between page loads. `extractable: true` says the store can only hold
 * an extractable key (Web Storage holds strings), so `ClientKey.loadOrCreate` generates one.
 * @typedef {object} KeyStore
 * @property {() => Promise<StoredKey|undefined>} get
 * @property {(value: StoredKey) => Promise<void>} set
 * @property {() => Promise<void>} delete
 * @property {boolean} [extractable]
 */

/**
 * @typedef {object} StoredKey
 * @property {string} alg
 * @property {CryptoKeyPair} keyPair
 */

/**
 * The client instance's key (RFC 9635 section 7.1). In GNAP the key IS the client: it is presented by
 * value in the first request, and every request after is signed with it, so each token the AS issues is
 * bound to it. This library proves it with HTTP message signatures (`httpsig`, RFC 9421).
 *
 * The private key is generated NON-EXTRACTABLE: script running in the page (including injected script)
 * can ask it to sign while the page is open, but can never read it out, so a stolen access token or
 * continuation token is useless anywhere else. `IndexedDBKeyStore` keeps that non-extractable key across
 * page loads. `WebStorageKeyStore` keeps an extractable copy in sessionStorage for this tab, which is what
 * Web Storage can hold.
 *
 * The JWK's `kid` is its RFC 7638 thumbprint, and is the `keyid` of every signature.
 */
export class ClientKey {
  #privateKey;
  /** The public JWK, with `alg` and `kid`. @type {Record<string, any>} */
  publicJwk;
  /** @type {string} */
  alg;
  /** RFC 7638 SHA-256 thumbprint of the public key; also its `kid`. @type {string} */
  thumbprint;
  /** @type {CryptoKeyPair|undefined} */
  keyPair;

  /**
   * Use `ClientKey.create()` or `ClientKey.loadOrCreate()` rather than this.
   * @param {string} alg
   * @param {CryptoKey} privateKey
   * @param {Record<string, any>} publicJwk
   * @param {string} thumbprint
   */
  constructor(alg, privateKey, publicJwk, thumbprint) {
    if (!SIGN_PARAMS[alg]) throw new TypeError(`Unsupported client key alg ${alg} (supported: ${CLIENT_KEY_ALGS.join(', ')})`);
    this.alg = alg;
    this.#privateKey = privateKey;
    this.publicJwk = publicJwk;
    this.thumbprint = thumbprint;
  }

  /**
   * Builds a key from a CryptoKeyPair, generating a new pair if none is given.
   * Generated keys are non-extractable unless `extractable` is set, which sessionStorage requires.
   * @param {{ alg?: string, keyPair?: CryptoKeyPair, extractable?: boolean }} [opts]
   * @returns {Promise<ClientKey>}
   */
  static async create({ alg = 'ES256', keyPair, extractable = false } = {}) {
    if (!SIGN_PARAMS[alg]) throw new TypeError(`Unsupported client key alg ${alg} (supported: ${CLIENT_KEY_ALGS.join(', ')})`);
    const pair = keyPair ?? await generateKeyPair(alg, { extractable });
    const { kty, crv, x, y, n, e } = await exportJWK(pair.publicKey);
    const bare = Object.fromEntries(Object.entries({ kty, crv, x, y, n, e }).filter(([, v]) => v !== undefined));
    const thumbprint = await calculateJwkThumbprint(bare, 'sha256');
    const key = new ClientKey(alg, pair.privateKey, { ...bare, alg, kid: thumbprint }, thumbprint);
    key.keyPair = pair;
    return key;
  }

  /**
   * Loads the key held in `store`, or creates one and stores it.
   * @param {KeyStore} store
   * @param {{ alg?: string }} [opts]
   * @returns {Promise<ClientKey>}
   */
  static async loadOrCreate(store, { alg = 'ES256' } = {}) {
    const held = await store.get();
    if (held?.keyPair && held.alg === alg) return ClientKey.create({ alg, keyPair: held.keyPair });
    const key = await ClientKey.create({ alg, extractable: store.extractable === true });
    await store.set({ alg, keyPair: /** @type {CryptoKeyPair} */ (key.keyPair) });
    return key;
  }

  /**
   * The key object a grant request carries by value (RFC 9635 section 7.1): the proof method and the
   * public JWK. Register exactly this on the AS (iya-sts: the application's `gnapKey`).
   * @returns {{ proof: string, jwk: Record<string, any> }}
   */
  keyObject() {
    return { proof: 'httpsig', jwk: { ...this.publicJwk } };
  }

  /**
   * Signs bytes with the private key, as RFC 9421 section 3.3.7 does for a JWS algorithm: ECDSA
   * signatures are the raw `r || s` concatenation, which is what WebCrypto produces.
   * @param {Uint8Array} data
   * @returns {Promise<Uint8Array>}
   */
  async sign(data) {
    return new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS[this.alg], this.#privateKey, data));
  }
}

/**
 * Keeps one client key pair in IndexedDB. CryptoKeys are stored as-is (structured clone), so a
 * non-extractable private key survives page loads without ever being exported.
 */
export class IndexedDBKeyStore {
  #name;
  #key;

  /** @param {{ database?: string, key?: string }} [opts] */
  constructor({ database = 'gnap-caep-client', key = 'client-key' } = {}) {
    this.#name = database;
    this.#key = key;
  }

  #open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.#name, 1);
      req.onupgradeneeded = () => req.result.createObjectStore('keys');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async #tx(mode, fn) {
    const db = await this.#open();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction('keys', mode);
        const req = fn(tx.objectStore('keys'));
        tx.oncomplete = () => resolve(req.result);
        tx.onerror = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  /** @returns {Promise<StoredKey|undefined>} */
  get() { return this.#tx('readonly', (s) => s.get(this.#key)); }
  /** @param {StoredKey} value @returns {Promise<void>} */
  set(value) { return this.#tx('readwrite', (s) => s.put(value, this.#key)); }
  /** @returns {Promise<void>} */
  delete() { return this.#tx('readwrite', (s) => s.delete(this.#key)); }
}

/**
 * Keeps one client key pair in Web Storage, sessionStorage by default. Storage holds strings, so the
 * private key is a JWK and therefore extractable. It survives a reload and the round trip to the
 * authorization server, and it is cleared when the tab closes.
 */
export class WebStorageKeyStore {
  #storage;
  #key;

  /** @param {{ storage?: Storage, key?: string }} [opts] */
  constructor({ storage = globalThis.sessionStorage, key = 'gnap-caep-client:client-key' } = {}) {
    if (!storage) throw new TypeError('Web Storage is not available here');
    this.extractable = true;
    this.#storage = storage;
    this.#key = key;
  }

  /** @returns {Promise<StoredKey|undefined>} */
  async get() {
    const raw = this.#storage.getItem(this.#key);
    if (!raw) return undefined;
    const saved = JSON.parse(raw);
    if (!saved?.alg || !saved.privateJwk || !saved.publicJwk) return undefined;
    const [privateKey, publicKey] = await Promise.all([
      importJWK(saved.privateJwk, saved.alg, { extractable: true }),
      importJWK(saved.publicJwk, saved.alg),
    ]);
    return { alg: saved.alg, keyPair: { privateKey: /** @type {CryptoKey} */ (privateKey), publicKey: /** @type {CryptoKey} */ (publicKey) } };
  }

  /** @param {StoredKey} value @returns {Promise<void>} */
  async set(value) {
    const privateKey = value?.keyPair?.privateKey;
    if (!privateKey?.extractable) throw new TypeError('WebStorageKeyStore can only store an extractable private key');
    const [privateJwk, publicJwk] = await Promise.all([exportJWK(privateKey), exportJWK(value.keyPair.publicKey)]);
    this.#storage.setItem(this.#key, JSON.stringify({ alg: value.alg, privateJwk, publicJwk }));
  }

  async delete() {
    this.#storage.removeItem(this.#key);
  }
}

/** Keeps a client key in memory only (a new key, so a new client instance, after every page load). */
export class MemoryKeyStore {
  #value;
  /** @returns {Promise<StoredKey|undefined>} */
  async get() { return this.#value; }
  /** @param {StoredKey} value */
  async set(value) { this.#value = value; }
  async delete() { this.#value = undefined; }
}
