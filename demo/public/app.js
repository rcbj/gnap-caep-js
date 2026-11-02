// GNAP + CAEP demo SPA. The GNAP client instance runs HERE, in the browser: its key is generated here
// (non-extractable, kept in IndexedDB), every request to the authorization server is signed with it
// (HTTP message signatures), the person approves the grant at the AS through a redirect interaction, and
// the grant's subject information says who they are. The access token is bound to the key.
//
// Several people can be signed in at once. Each tab has ONE active account: only its grant is used and
// rotated, and its token polls the application's CAEP stream. A GNAP web application's stream belongs to
// the APPLICATION and hears about every person who approved a grant to it, so each event is routed to the
// account it names — by person, or by the grant (`gnap-grant:<id>`) or token (`gnap-token:<jti>`) it ended.
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  AccountManager, CAEP, GNAPClient, IndexedDBKeyStore, MemoryKeyStore, MemoryTokenStore, SSFReceiver,
  WebStorageTokenStore,
} from 'gnap-caep-client';

const $ = (id) => document.getElementById(id);
const ORIGIN = location.origin;
const FINISH_URI = `${ORIGIN}/callback`;
const CAEP_EVENTS = Object.values(CAEP).map((uri) => uri.split('/').pop());
// Shared by the tabs (localStorage): the application's stream id, and the event types it asks for.
const STREAM_KEY = 'gnap-caep-demo.stream-id';
const EVENTS_KEY = 'gnap-caep-demo.caep-events';
// Per tab (sessionStorage): the signals this tab received, and the page tab shown.
const LOG_KEY = 'gnap-caep-demo.event-log';
const PAGE_TAB_KEY = 'gnap-caep-demo.page-tab';

/** @type {GNAPClient|undefined} */ let client;
/** @type {AccountManager|undefined} */ let accounts;
let config;
const ui = { error: undefined, notices: [], ended: new Map(), busy: undefined };
const perAccount = new Map();
let caep = { key: undefined, receiver: undefined, state: { status: 'waiting-for-user' } };

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const store = {
  get(key, storage = localStorage) {
    try { return JSON.parse(storage.getItem(key) ?? 'null'); } catch { return null; }
  },
  set(key, value, storage = localStorage) {
    try { storage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
  },
  del(key, storage = localStorage) {
    try { storage.removeItem(key); } catch { /* storage unavailable */ }
  },
};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  node.append(...children.filter((c) => c !== '' && c !== undefined && c !== null && c !== false));
  return node;
}

async function withBusy(button, fn) {
  button.disabled = true;
  try { await fn(); } finally { button.disabled = false; }
}

const describe = (err) => {
  const json = err?.response && typeof err.response === 'object' ? JSON.stringify(err.response) : '';
  const detail = json && !err.message.includes(json) ? ` ${json}` : '';
  const status = err?.status && !err.message.includes(String(err.status)) ? ` (HTTP ${err.status})` : '';
  const msg = /Failed to fetch|NetworkError|Load failed/i.test(err?.message ?? '')
    ? `${err.message}: the authorization server refused the request from this origin (CORS), or is unreachable`
    : err?.message ?? String(err);
  return `${msg}${status}${detail}`.slice(0, 600);
};

function labelOf(a) {
  if (!a) return '—';
  // The person's username: their uid, from the grant's `account` subject identifier. `sub` is an
  // opaque identifier (iya-sts: urn:uuid:…) and names nobody a person would recognise.
  const display = String(a.name || '').trim();
  const username = String(a.uid || a.preferred_username || '').trim();
  if (display && username && display !== username) return `${display} (${username})`;
  return display || username || a.email || a.sub || '—';
}
const initialOf = (a) => String(labelOf(a))[0]?.toUpperCase() ?? '?';
const stateOf = (key) => {
  if (!perAccount.has(key)) perAccount.set(key, { rotations: 0, lastRotation: undefined, stepUp: undefined });
  return perAccount.get(key);
};
const signedIn = () => (accounts?.active?.status === 'signed-in' ? accounts.active : undefined);

const STATUS = {
  'signed-in': ['ok', 'Signed in'],
  'tokens-missing': ['warn', 'Token expired'],
  'signed-out': ['', 'Signed out'],
  ended: ['danger', 'Grant ended'],
};

// ---------------------------------------------------------------------------
// Configuration → client
// ---------------------------------------------------------------------------

function parseConfig(doc) {
  if (!doc || typeof doc !== 'object') throw new Error('gnap.json is not a JSON object.');
  const grantEndpoint = String(doc.grantEndpoint ?? '').trim();
  if (!grantEndpoint) throw new Error('gnap.json needs grantEndpoint.');
  const access = Array.isArray(doc.access) ? doc.access : String(doc.access ?? '').split(/\s+/).filter(Boolean);
  if (!access.length) throw new Error('gnap.json needs access.');
  return {
    grantEndpoint,
    transmitterIssuer: String(doc.transmitterIssuer ?? '').trim() || new URL(grantEndpoint).origin,
    idTokenIssuer: String(doc.idTokenIssuer ?? '').trim() || undefined,
    application: String(doc.application ?? '').trim() || undefined,
    display: doc.display,
    access,
    signals: doc.signals,
    subIdFormats: doc.subIdFormats ?? ['iss_sub', 'account', 'opaque'],
    assertionFormats: doc.assertionFormats ?? [],
  };
}

async function applyConfig(cfg) {
  accounts?.close();
  // The key is kept in IndexedDB, non-extractable, so it is the same client instance in every tab and
  // after a restart. Nobody registers it: class_id names the application it is an instance of.
  const keyStore = typeof indexedDB !== 'undefined' ? new IndexedDBKeyStore({ database: 'gnap-caep-demo' }) : new MemoryKeyStore();
  client = await GNAPClient.discover({
    grantEndpoint: cfg.grantEndpoint,
    // GNAP discovery (RFC 9635 section 9): an OPTIONS request to the grant endpoint, which the browser
    // preflights. The AS's CORS answer must list OPTIONS in Access-Control-Allow-Methods.
    finishUri: FINISH_URI,
    access: cfg.access,
    signals: cfg.signals,
    display: { name: 'GNAP CAEP demo', uri: `${ORIGIN}/`, ...cfg.display },
    // The registered application this browser's key is an instance of: the AS accepts an unregistered key
    // when class_id names a registered client (iya-sts: gnap.unregisteredInstances, #1216).
    classId: cfg.application,
    subject: { subIdFormats: cfg.subIdFormats, assertionFormats: cfg.assertionFormats },
    keyStore,
    // Verify the id_token assertion when the AS sends one; its claims name the person.
    idToken: cfg.idTokenIssuer && cfg.assertionFormats.includes('id_token')
      ? { issuer: cfg.idTokenIssuer, ...(cfg.application ? { audience: cfg.application } : {}) }
      : undefined,
  }).catch(async (err) => {
    // An AS without a reachable OpenID configuration still signs people in by sub_id.
    if (!cfg.idTokenIssuer) throw err;
    console.warn('[demo] id_token verification is off:', err.message);
    return GNAPClient.discover({
      grantEndpoint: cfg.grantEndpoint, finishUri: FINISH_URI, access: cfg.access, signals: cfg.signals,
      display: { name: 'GNAP CAEP demo', uri: `${ORIGIN}/`, ...cfg.display },
      classId: cfg.application, subject: { subIdFormats: cfg.subIdFormats, assertionFormats: [] }, keyStore,
    });
  });
  config = cfg;

  // One token cache for this tab (sessionStorage); one active account in the tab.
  const tabStorage = globalThis.sessionStorage;
  accounts = new AccountManager(client, {
    store: tabStorage ? new WebStorageTokenStore({ prefix: 'gnap-caep-demo:tokens:' }) : new MemoryTokenStore(),
    storeKey: `accounts:${cfg.grantEndpoint}`,
    onActivate: (account, { getTokenSet }) => startCaep(account, getTokenSet),
    onDeactivate: (account) => stopCaep(account.key),
  });
  accounts.on('rotated', (a) => {
    const s = stateOf(a.key);
    s.rotations += 1;
    s.lastRotation = Date.now();
    render();
  });
  accounts.on('signed-out', (a) => clearLog(a.key));
  accounts.on('forgotten', (a) => clearLog(a.key));
  accounts.on('ended', (a, reason) => { ui.ended.set(a.key, reason); render(); });
  accounts.on('activation_error', (a, err) => { ui.error = `Could not make ${labelOf(a)} active: ${describe(err)}`; render(); });
  accounts.on('change', () => {
    if (caep.key && accounts.get(caep.key)?.status !== 'signed-in') stopCaep(caep.key);
    render();
  });
  await accounts.init();
}

// ---------------------------------------------------------------------------
// Sign-in, switching, callback, sign-out
// ---------------------------------------------------------------------------

/** Starts a grant; sends the browser to the AS, or (a trusted client) signs in at once. */
async function go(make, what = 'sign-in') {
  if (!accounts) return;
  try {
    const result = await make(accounts);
    if (result.url) location.assign(result.url);
    else { ui.notices.unshift({ level: 'info', text: `Signed in as ${labelOf(result.account)} with no interaction.` }); render(); }
  } catch (err) {
    ui.error = `Could not start the ${what}: ${describe(err)}`;
    render();
  }
}

const signIn = () => go((m) => m.signIn());
const addAccount = () => go((m) => m.addAccount());
const reauthenticate = (key) => go((m) => m.reauthenticate(key));

async function activate(key) {
  closeMenu();
  ui.busy = config.signals === false
    ? `Switching to ${labelOf(accounts.get(key))}…`
    : `Switching to ${labelOf(accounts.get(key))}: checking the signals queued for this application…`;
  render();
  try {
    await accounts.activate(key);
  } catch (err) {
    ui.error = `Could not switch to ${labelOf(accounts.get(key))}: ${describe(err)}`;
  } finally {
    ui.busy = undefined;
  }
  await render();
}

async function completeCallback() {
  try {
    const { account, added } = await accounts.handleCallback(location.href);
    perAccount.delete(account.key);
    ui.ended.delete(account.key);
    ui.notices.unshift({ level: 'info', text: added ? `${labelOf(account)} added. Your other accounts stay signed in, dormant until you switch to them.` : `Signed in as ${labelOf(account)}.` });
  } catch (err) {
    if (err.error === 'user_denied') ui.error = 'The grant was not approved at the authorization server.';
    else if (err.code === 'account_mismatch') ui.error = 'Somebody other than the account this page asked for approved the grant. It was revoked; nothing was changed.';
    else if (err.error === 'invalid_client') ui.error = `The authorization server would not accept this browser's key as an instance of "${config?.application}". Check that the application is registered with this page's finish URI (npm run configure-iya-sts). (${describe(err)})`;
    else ui.error = `Sign-in failed: ${describe(err)}`;
  } finally {
    history.replaceState(null, '', '/');
  }
}

/** Signs one account out of this browser: its grant is revoked at the AS. The others stay signed in. */
async function signOut(key = accounts.activeKey) {
  closeMenu();
  await accounts.signOut(key).catch((err) => { ui.error = `Sign-out failed: ${describe(err)}`; });
  ui.notices.unshift({ level: 'info', text: 'Signed out: the grant was revoked at the authorization server.' });
  render();
}

async function signOutAll() {
  closeMenu();
  await accounts.signOutAll().catch((err) => { ui.error = `Sign-out failed: ${describe(err)}`; });
  render();
}

// ---------------------------------------------------------------------------
// CAEP. A GNAP web application owns ONE stream (iya-sts scopes it to the people who approved a grant to
// it), so the tab polls it with the active account's token and routes each event to the account it names.
// ---------------------------------------------------------------------------

const selectedEvents = () => {
  const saved = store.get(EVENTS_KEY);
  return Array.isArray(saved) ? CAEP_EVENTS.filter((n) => saved.includes(n)) : CAEP_EVENTS;
};
const eventUris = (names) => names.map((n) => Object.values(CAEP).find((u) => u.endsWith(`/${n}`)));
const rightsOf = (grant) => (grant?.access ?? []).map((r) => (typeof r === 'string' ? r : r?.type)).filter(Boolean);
const canWrite = (grant) => rightsOf(grant).includes('ssf.manage');
const canRead = (grant) => canWrite(grant) || rightsOf(grant).includes('ssf.read');

function makeReceiver(getTokenSet, streamId) {
  if (config.signals === false) return undefined;
  return new SSFReceiver({
    transmitterIssuer: config.transmitterIssuer,
    streamId,
    // Every call carries the active account's GNAP token, signed with this browser's key.
    authorizationHeaders: async (req) => client.resourceHeaders(await getTokenSet(), req),
    eventsRequested: eventUris(selectedEvents()),
    description: `gnap-caep-client in-browser demo @ ${ORIGIN}`,
    pollIntervalMs: 5000,
    handlers: handlers(getTokenSet),
  });
}

async function startCaep(account, getTokenSet) {
  const key = account.key;
  // Off before the missing-rights note, which is only for a grant that was allowed to ask.
  if (config.signals === false) {
    caep = { key, receiver: undefined, state: { status: 'unavailable', note: 'CAEP and RISC are off, so this tab reads no stream.' } };
    render();
    return;
  }
  caep = { key, receiver: undefined, state: { status: 'connecting' } };
  render();
  try {
    const grant = await getTokenSet();
    if (!canRead(grant)) {
      caep.state = { status: 'unavailable', note: 'This grant carries neither ssf.read nor ssf.manage, so this tab reads no stream.' };
      return;
    }
    const write = canWrite(grant);
    const held = store.get(STREAM_KEY);
    let r;
    if (held) {
      r = makeReceiver(getTokenSet, held);
      try {
        await r.start({ catchUp: true });
      } catch {
        await r.stop().catch(() => {});
        r = undefined;
      }
    }
    if (!r) {
      if (!write) {
        const probe = makeReceiver(getTokenSet);
        await probe.discover();
        const id = (await probe.listStreams()).find((s) => s?.stream_id)?.stream_id;
        if (!id) {
          caep.state = { status: 'no-stream', note: 'No stream for this application, and ssf.read cannot create one.' };
          return;
        }
        r = makeReceiver(getTokenSet, id);
      } else {
        r = makeReceiver(getTokenSet);
      }
      await r.start({ catchUp: true });
    }
    if (caep.key !== key || accounts.get(key)?.status !== 'signed-in') {
      await r.stop();
      return;
    }
    caep.receiver = r;
    store.set(STREAM_KEY, r.stream.stream_id);
    if (write) {
      const want = eventUris(selectedEvents());
      const have = r.stream.events_requested ?? [];
      if (want.length !== have.length || want.some((u) => !have.includes(u))) {
        await r.updateStream({ events_requested: want }).catch((err) => log({ name: 'subscription', action: `Could not update the stream's event types: ${describe(err)}` }));
      }
      r.requestVerification({ timeoutMs: 30_000 }).catch(() => {});
    }
    caep.state = { status: 'connected', streamStatus: r.stream.status ?? 'enabled', write };
  } catch (err) {
    if (caep.key === key) caep.state = { status: 'error', error: `Could not read the stream: ${describe(err)}` };
  } finally {
    render();
  }
}

async function stopCaep(key) {
  if (caep.key !== key) return;
  const r = caep.receiver;
  caep = { key: undefined, receiver: undefined, state: { status: 'waiting-for-user' } };
  if (r) await r.stop().catch(() => {});
}

// --- The event log (this tab only) -------------------------------------------

const eventLog = () => store.get(LOG_KEY, sessionStorage) ?? [];
function clearLog(key) {
  store.set(LOG_KEY, eventLog().filter((e) => key && e.account !== key), sessionStorage);
  renderLog();
}
function log(entry) {
  const entries = eventLog();
  if (entry.jti && entries.some((e) => e.jti === entry.jti && e.account === entry.account)) return;
  const full = { at: Date.now(), account: accounts?.activeKey, ...entry };
  entries.unshift(full);
  entries.length = Math.min(entries.length, 300);
  store.set(LOG_KEY, entries, sessionStorage);
  renderLog(full.at);
}

/**
 * Wraps a policy: the event is acted on for each account it names (by person, or by grant or token),
 * the active one or a dormant one. An event naming nobody here is about the stream, or somebody else.
 */
function handle(policy, { bySignOnSession = false } = {}) {
  return async (evt) => {
    let targets = evt.subject ? accounts.accountsForSubject(evt.subject).filter((a) => a.status === 'signed-in') : [];
    if (!targets.length && bySignOnSession) targets = signOnSessionTargets(evt.subject);
    const aboutStream = !evt.subject || (evt.subject.format === 'opaque' && evt.subject.id === caep.receiver?.stream?.stream_id);
    let action;
    try {
      if (targets.length) {
        const done = [];
        for (const a of targets) done.push(`${labelOf(a)}: ${await policy(evt, a)}`);
        action = done.join(' ');
      } else {
        action = aboutStream ? await policy(evt, undefined) : 'Not about anybody signed in here; ignored.';
      }
    } catch (err) {
      action = `Handler failed: ${describe(err)}`;
    }
    log({ account: targets[0]?.key ?? accounts.activeKey, name: evt.name, type: evt.type, jti: evt.jti, subject: evt.subject, payload: evt.payload, action });
    render();
  };
}

/**
 * The accounts a session-revoked about the AS's own SIGN-ON session names. iya-sts names that session by
 * its sign-on session id, which this page never learns (the grant's subject information carries no session),
 * so `accountsForSubject()` cannot match its `session` member. The `user` member still names the person: the
 * grant was approved on a sign-on session of theirs that has now ended, so the person's signed-in accounts
 * here end too. A `gnap-grant:` or `gnap-token:` session is the library's own matching, never this.
 */
function signOnSessionTargets(subject) {
  if (subject?.format !== 'complex' || !subject.user || subject.session?.format !== 'opaque') return [];
  if (/^gnap-(grant|token):/.test(String(subject.session.id ?? ''))) return [];
  return accounts.accountsForSubject(subject.user).filter((a) => a.status === 'signed-in');
}

function handlers(getTokenSet) {
  // Ending an account stops its stream, and SSFReceiver.stop() waits for the poll in flight, which is the
  // one running this handler. Awaiting the end here would wait for itself: the event would never be logged
  // or acknowledged, polling would stop, and the account would stay signed in. So the end starts once the
  // handler has returned.
  const end = (a, reason) => {
    setTimeout(() => {
      accounts.end(a.key, reason).catch((err) => {
        ui.error = `Could not end ${labelOf(a)}: ${describe(err)}`;
        render();
      });
    }, 0);
  };
  return {
    sessionRevoked: handle(async (evt, a) => {
      if (!a) return 'No account named.';
      const session = evt.subject?.session?.id ?? '';
      end(a, evt.reasonUser?.en ?? (session.startsWith('gnap-grant:') ? 'The grant was revoked at the authorization server.' : 'The session was revoked.'));
      return 'Grant ended; its cached token discarded.';
    }, { bySignOnSession: true }),
    tokenClaimsChange: handle(async (evt, a) => {
      if (a?.key === accounts.activeKey) {
        await getTokenSet({ forceRefresh: true });
        return `Token rotated for the new access (${JSON.stringify(evt.payload.claims?.access ?? evt.payload.claims ?? {})}).`;
      }
      return 'Noted; the token is rotated when the account is next active.';
    }),
    credentialChange: handle(async (evt, a) => {
      const { credential_type: type = 'credential', change_type: change } = evt.payload;
      if (a && ['revoke', 'delete'].includes(change)) {
        end(a, `The ${type} was ${change}d; sign in again.`);
        return `Credential ${change}d: grant ended.`;
      }
      return 'User notified; grant kept.';
    }),
    assuranceLevelChange: handle((evt, a) => {
      if (a) stateOf(a.key).stepUp = evt.payload.change_direction === 'decrease' ? `Assurance dropped to ${evt.payload.current_level}.` : undefined;
      return evt.payload.change_direction === 'decrease' ? 'Step-up required.' : 'Step-up cleared.';
    }),
    deviceComplianceChange: handle(async (evt, a) => {
      if (a && evt.payload.current_status === 'not-compliant') {
        end(a, 'The device is no longer compliant with security policy.');
        return 'Device not compliant: grant ended.';
      }
      return 'Device compliant: no action.';
    }),
    riskLevelChange: handle(async (evt, a) => {
      const { current_level: level, risk_reason: why } = evt.payload;
      if (a && level === 'HIGH') {
        end(a, `High risk detected (${why ?? 'no reason given'}).`);
        return 'Risk HIGH: grant ended.';
      }
      if (a) stateOf(a.key).stepUp = level === 'MEDIUM' ? `Risk raised to MEDIUM (${why ?? 'no reason given'}).` : undefined;
      return `Risk ${level}.`;
    }),
    sessionEstablished: handle(() => 'Informational: a new session at the authorization server.'),
    sessionPresented: handle(() => 'Informational: a session presented to another service.'),
    verification: handle((evt) => `Stream verified (state=${evt.payload.state ?? 'none'}).`),
    streamUpdated: handle((evt) => {
      caep.state = { ...caep.state, streamStatus: evt.payload.status };
      return `Transmitter set the stream to "${evt.payload.status}".`;
    }),
    unhandled: handle((evt) => `No handler for ${evt.type}.`),
    error: (err, ctx) => {
      if (ctx.phase === 'poll') {
        caep.state = { ...caep.state, error: `Last poll failed at ${new Date().toLocaleTimeString()}: ${describe(err)}` };
        render();
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

async function render() {
  const me = signedIn();
  const list = accounts?.list() ?? [];
  renderWho(list);
  renderHero(list);
  renderKey();

  $('session-empty').hidden = !!me;
  $('claims').hidden = !me;
  $('btn-rotate').disabled = !me;
  $('btn-revoke-token').disabled = !me;
  if (me) {
    $('session-title').textContent = `Session · ${labelOf(me)}`;
    const shown = ['uid', 'sub', 'iss', 'account', 'name', 'email', 'email_verified', 'grantId', 'sessions'];
    $('claims').replaceChildren(...shown.filter((k) => me[k] !== undefined).flatMap((k) => [
      el('dt', {}, k), el('dd', {}, typeof me[k] === 'object' ? JSON.stringify(me[k]) : String(me[k])),
    ]));
    const { stepUp, rotations } = stateOf(me.key);
    $('session-pill').textContent = stepUp ? 'Step-up required' : 'Active';
    $('session-pill').className = `pill ${stepUp ? 'warn' : 'ok'}`;
    $('rotate-count').textContent = `${rotations} rotations`;
  } else {
    $('session-title').textContent = 'Session';
    $('claims').replaceChildren();
    $('session-pill').textContent = 'Signed out';
    $('session-pill').className = 'pill';
    $('rotate-count').textContent = '';
  }

  $('security-empty').hidden = !!client;
  $('security-list').hidden = !client;
  if (client) {
    const f = client.securityFeatures;
    const items = [
      ['The key is the client', `no client id, no secret: ${f.clientKey.alg} key, thumbprint ${f.clientKey.thumbprint.slice(0, 12)}…, ${f.clientKey.extractable ? 'extractable' : 'non-extractable'}`],
      ['Every request signed', f.keyProof],
      ['Key-bound access tokens', f.boundTokens],
      ['Interaction finish', `the redirect back carries no token; ${f.interactionHash}`],
      ['Finish nonce', f.finishNonce],
      ['Continuation', f.continuationOrigin],
      ['Who signed in', `subject information: ${f.subject}; id_token ${f.idTokenAssertion}`],
      ['TLS', f.tlsEnforced ? 'required for the AS and the finish URI (loopback excepted)' : 'not enforced'],
      ['Token cache', 'this tab\'s grants, in session storage; one active account per tab'],
      ['Sign-out', 'revokes the grant at the AS, which sends CAEP session-revoked for it'],
      ['Page', 'CSP (no inline script), Referrer-Policy no-referrer, framing denied'],
    ];
    $('security-list').replaceChildren(...items.map(([k, v]) => el('li', {}, el('strong', {}, k), el('span', { class: 'muted' }, ` ${v}`))));
  }
  renderStream();
  renderBanners();
  renderLog();
  tick();
  await renderGrant();
}

function renderKey() {
  if (!client) {
    $('key-pill').textContent = '…';
    $('key-info').replaceChildren();
    return;
  }
  const k = client.key;
  $('key-pill').textContent = k.alg;
  $('key-pill').className = 'pill ok';
  $('key-info').replaceChildren(...[
    ['thumbprint (kid)', k.thumbprint],
    ['proof', 'httpsig (RFC 9421)'],
    ['private key', k.keyPair?.privateKey?.extractable ? 'extractable' : 'non-extractable, kept in IndexedDB'],
    ['instance of', `${config.application ?? '(no class_id)'} (class_id)`],
    ['grant endpoint', client.grantEndpoint],
  ].flatMap(([a, b]) => [el('dt', {}, a), el('dd', {}, b)]));
}

function avatar(a) {
  return el('span', { class: 'avatar', 'aria-hidden': 'true' }, initialOf(a));
}
function closeMenu() {
  const menu = document.querySelector('.acct-menu');
  if (menu) menu.open = false;
}

function renderWho(list) {
  const who = $('who');
  if (!client) return who.replaceChildren();
  if (!list.length) return who.replaceChildren(el('button', { class: 'btn primary', onclick: () => signIn() }, 'Sign in'));
  const cur = accounts.active;
  const others = list.filter((a) => a.key !== cur?.key);
  const choices = cur && cur.status !== 'signed-in' ? [cur, ...others] : others;
  const wasOpen = document.querySelector('.acct-menu')?.open;
  const pick = (a) => (a.status === 'signed-in' ? activate(a.key) : (closeMenu(), reauthenticate(a.key)));
  const row = (a) => el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => pick(a) },
    avatar(a),
    el('span', { class: 'menu-who' }, el('span', { title: labelOf(a) }, labelOf(a)), a.email ? el('span', { class: 'muted small' }, a.email) : ''),
    a.status === 'signed-in' ? '' : el('span', { class: `pill ${STATUS[a.status][0]}` }, STATUS[a.status][1]));
  const menu = el('details', { class: 'acct-menu' },
    el('summary', { 'aria-label': 'Switch account' }, cur ? avatar(cur) : '',
      el('span', { class: 'menu-name' }, cur ? labelOf(cur) : 'Choose an account'), el('span', { class: 'caret', 'aria-hidden': 'true' }, '▾')),
    el('div', { class: 'menu', role: 'menu' },
      el('p', { class: 'menu-head' }, 'Switch account'),
      ...(choices.length ? choices.map(row) : [el('p', { class: 'muted small menu-note' }, 'No other account yet.')]),
      el('div', { class: 'menu-sep' }),
      el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => addAccount() }, el('span', { class: 'avatar plus', 'aria-hidden': 'true' }, '+'), 'Sign in with another account'),
      el('div', { class: 'menu-sep' }),
      cur?.status === 'signed-in' ? el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => signOut() }, `Sign out ${labelOf(cur)}`) : '',
      el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => signOutAll() }, 'Sign out of all accounts')));
  if (wasOpen) menu.open = true;
  who.replaceChildren(menu);
}

function renderHero(list) {
  const cur = accounts?.active;
  const actions = [];
  let title = 'Sign in';
  let text = 'Sign in through the GNAP authorization server: it asks you to approve this application\'s grant, then says who you are.';
  if (!client) {
    title = 'Authorization server';
    text = 'Loading the GNAP configuration.';
  } else if (cur?.status === 'signed-in') {
    title = `Signed in as ${labelOf(cur)}`;
    text = config.signals === false
      ? 'The grant and its token cache for this account are on this tab. CAEP and RISC are off.'
      : 'The grant, its token cache and the CAEP stream for this account are on this tab.';
  } else if (cur) {
    title = cur.status === 'ended' ? `${labelOf(cur)}'s grant was ended` : `${labelOf(cur)} is signed out`;
    text = `${cur.status === 'ended' && cur.endedReason ? `${cur.endedReason} ` : ''}Sign in again as ${labelOf(cur)}, or with another account.`;
    actions.push(el('button', { class: 'btn primary', onclick: () => reauthenticate(cur.key) }, `Sign in again as ${labelOf(cur)}`));
  } else if (list.some((a) => a.status === 'signed-in')) {
    title = 'Choose an account for this tab';
    text = 'These accounts are signed in in this tab. Pick one from the menu under your name.';
  }
  if (client) actions.push(el('button', { class: `btn ${actions.length ? 'ghost' : 'primary'}`, onclick: () => (list.length ? addAccount() : signIn()) }, list.length ? 'Sign in with another account' : 'Sign in'));
  $('hero-title').textContent = title;
  $('hero-text').textContent = text;
  $('hero-actions').replaceChildren(...actions);
}

function renderStream() {
  const me = signedIn();
  const st = me && caep.key === me.key ? caep.state : { status: ui.busy ? 'connecting' : 'waiting-for-user' };
  const status = st.status === 'connected' ? st.streamStatus ?? 'enabled' : st.status;
  $('ssf-pill').textContent = status;
  $('ssf-pill').className = `pill ${status === 'enabled' ? 'ok' : status === 'error' ? 'danger' : 'warn'}`;
  const r = caep.receiver;
  const s = r?.stream;
  $('ssf-info').replaceChildren(...[
    ['transmitter', config?.transmitterIssuer ?? '—'],
    ['owner', 'this application (a GNAP web application\'s stream hears about the people who approved it)'],
    ...(s ? [['stream_id', s.stream_id], ['delivery', 'poll (RFC 8936)'], ['SET audience', [].concat(s.aud ?? '—').join(', ')]] : []),
    ...(st.status === 'waiting-for-user' ? [['note', 'Sign in. This tab reads the stream with the active account\'s token.']] : []),
    ...(st.note ? [['note', st.note]] : []),
  ].flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]));
  $('ssf-events').replaceChildren(...(s?.events_delivered ?? []).map((e) => el('span', { class: 'chip', title: e }, e.split('/').pop())));
  const picked = pickedEvents();
  const saved = selectedEvents();
  const dirty = picked.length !== saved.length || picked.some((n) => !saved.includes(n));
  $('btn-events').disabled = !st.write || !picked.length || !dirty;
  $('events-note').textContent = config?.signals === false ? 'CAEP and RISC are off.'
    : !r ? 'Sign in to change the stream\'s event types.'
    : !st.write ? 'Changing the stream needs ssf.manage.' : dirty ? 'Not applied yet.' : 'The stream asks for these.';
  $('btn-verify').disabled = !s || !st.write;
  $('btn-reconnect').disabled = !me || config?.signals === false;
  $('ssf-error').hidden = !st.error;
  $('ssf-error').textContent = st.error ?? '';
  $('live').classList.toggle('on', !!r);
}

const pickedEvents = () => [...document.querySelectorAll('#event-options input:checked')].map((i) => i.value);
function drawEventOptions() {
  const saved = selectedEvents();
  $('event-options').replaceChildren(...CAEP_EVENTS.map((name) => el('label', { class: 'check' },
    el('input', { type: 'checkbox', value: name, ...(saved.includes(name) ? { checked: '' } : {}), onchange: () => renderStream() }),
    el('span', {}, name))));
}

function renderBanners() {
  const items = [];
  const banner = (level, title, text, ...actions) => el('div', { class: `banner ${level}`, role: level === 'danger' ? 'alert' : 'status' },
    el('div', {}, el('strong', {}, title), el('span', {}, text)), actions.length ? el('div', { class: 'banner-actions' }, ...actions) : '');
  const dismiss = (fn) => el('button', { class: 'btn', onclick: () => { fn(); render(); } }, 'Dismiss');
  if (ui.busy) items.push(banner('info', 'One moment', ui.busy));
  if (ui.error) items.push(banner('danger', 'Something went wrong', ui.error, dismiss(() => { ui.error = undefined; })));
  for (const [key, reason] of ui.ended) {
    const a = accounts?.get(key);
    if (!a || a.status !== 'ended' || key === accounts.activeKey) continue;
    items.push(banner('danger', `${labelOf(a)}'s grant was ended`, reason,
      el('button', { class: 'btn', onclick: () => reauthenticate(key) }, `Sign in again as ${labelOf(a)}`), dismiss(() => ui.ended.delete(key))));
  }
  const me = signedIn();
  if (me && stateOf(me.key).stepUp) {
    items.push(banner('warn', 'Step-up authentication required', stateOf(me.key).stepUp, el('button', { class: 'btn', onclick: () => reauthenticate(me.key) }, 'Sign in again')));
  }
  for (const n of ui.notices.slice(0, 3)) items.push(banner(n.level, 'Notice', n.text, dismiss(() => ui.notices.splice(ui.notices.indexOf(n), 1))));
  $('banners').replaceChildren(...items);
}

async function tick() {
  const me = signedIn();
  const t = me && await accounts.getTokenSet().catch(() => undefined);
  if (!t?.expires_at) {
    for (const id of ['expires-in', 'rotate-in', 'last-rotate']) $(id).textContent = '—';
    $('meter-fill').style.width = '0%';
    $('meter-skew').style.width = '0%';
    return;
  }
  const now = Date.now() / 1000;
  const lifetime = Math.max(1, t.expires_at - (t.issued_at ?? now));
  const left = Math.max(0, t.expires_at - now);
  const skew = Math.min(60, lifetime / 2);
  const fmt = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;
  const { lastRotation } = stateOf(me.key);
  $('expires-in').textContent = fmt(left);
  $('rotate-in').textContent = t.canRotate() ? fmt(Math.max(0, left - skew)) : 'n/a';
  $('last-rotate').textContent = lastRotation ? `${Math.round((Date.now() - lastRotation) / 1000)}s ago` : 'never';
  $('meter-fill').style.width = `${(left / lifetime) * 100}%`;
  $('meter-skew').style.width = `${(skew / lifetime) * 100}%`;
}
setInterval(tick, 1000);

const SEVERITY = {
  'session-revoked': 'danger', 'credential-change': 'warn', 'device-compliance-change': 'warn', 'risk-level-change': 'warn',
  'assurance-level-change': 'warn', 'token-claims-change': 'info', 'session-established': 'ok', 'session-presented': 'ok',
  verification: 'ok', 'stream-updated': 'info',
};

function renderLog(freshAt) {
  const shown = eventLog();
  $('log').replaceChildren(...shown.map((entry) => {
    const node = $('log-item').content.firstElementChild.cloneNode(true);
    const evt = node.querySelector('.evt');
    evt.textContent = entry.name;
    evt.className = `evt ${SEVERITY[entry.name] ?? 'info'}`;
    evt.title = entry.type ?? '';
    node.querySelector('time').textContent = new Date(entry.at).toLocaleTimeString();
    node.querySelector('.action').textContent = entry.action;
    node.querySelector('pre').textContent = JSON.stringify({ subject: entry.subject, payload: entry.payload, jti: entry.jti }, null, 2);
    if (entry.at === freshAt) node.classList.add('fresh');
    return node;
  }));
  $('btn-clear-log').disabled = shown.length === 0;
  $('log-empty').hidden = shown.length > 0;
  renderLiveStatus();
}

/** The account #live-status reports: this tab's active one, or the last one it had. */
let liveKey;

/**
 * What a test driving this page in a browser reads (scripts/live_iya_sts.py): whether this tab's active
 * account is signed in, the subject of the account it has (or last had) active, this tab's receiver
 * state, and the type URI and jti of each signal it received for that account. Never a token, a grant, an
 * assertion or a payload. An ended account stops being active, and what a test asks is what happened to
 * it, so the last active account is reported until another becomes active.
 */
function renderLiveStatus() {
  const node = $('live-status');
  if (!node) return;
  if (accounts?.activeKey) liveKey = accounts.activeKey;
  const key = liveKey;
  const account = key ? accounts?.get(key) : undefined;
  const events = key
    ? eventLog().filter((e) => e.account === key && e.type && e.jti).reverse().map((e) => ({ type: e.type, jti: e.jti }))
    : [];
  node.textContent = JSON.stringify({
    signedIn: !!signedIn(),
    subject: account?.sub ?? null,
    receiver: String(caep.state?.status ?? 'none'),
    receiverError: caep.state?.error ?? null,
    events,
  });
}
$('btn-clear-log').addEventListener('click', () => clearLog(undefined));

function decode(value) {
  try {
    return { jwt: true, header: decodeProtectedHeader(value), payload: decodeJwt(value) };
  } catch {
    return { jwt: false };
  }
}

async function renderGrant() {
  const me = signedIn();
  if (!me) {
    $('tokens-note').textContent = 'Nothing until someone is signed in on this tab.';
    $('tokens-body').replaceChildren();
    return;
  }
  const g = await accounts.getTokenSet().catch(() => undefined);
  if (!g) {
    $('tokens-body').replaceChildren(el('p', { class: 'muted small' }, 'Not available.'));
    return;
  }
  $('tokens-note').textContent = `As cached for ${labelOf(me)}, the active account.`;
  const tok = decode(g.access_token);
  const facts = [`GNAP ${g.bearer ? 'bearer' : 'key-bound'}`, g.expires_at && `expires ${new Date(g.expires_at * 1000).toLocaleTimeString()}`,
    `access ${JSON.stringify(g.access ?? [])}`].filter(Boolean).join(' · ');
  $('tokens-body').replaceChildren(
    el('div', { class: 'tok' },
      el('div', { class: 'tok-head' }, el('h3', {}, 'Access token', el('span', { class: `pill ${tok.jwt ? 'ok' : ''}` }, tok.jwt ? 'JWT' : 'opaque'),
        g.bearer ? '' : el('span', { class: 'pill warn' }, 'key-bound'))),
      el('p', { class: 'tok-meta' }, facts),
      el('pre', { class: 'tok-raw' }, g.access_token),
      ...(tok.jwt ? [Object.assign(el('details', {}, el('summary', { class: 'muted small' }, 'Decoded claims (not verified here)'), el('pre', {}, JSON.stringify(tok.payload, null, 2))), { open: true })] : [])),
    el('div', { class: 'tok' },
      el('div', { class: 'tok-head' }, el('h3', {}, 'Grant')),
      el('dl', { class: 'kv' }, ...[
        ['grant_id', g.grant_id], ['continue', g.continue?.uri], ['manage', g.manage?.uri],
        ['sessions (CAEP)', g.sessionIds().join(', ')], ['instance_id', g.instance_id],
      ].filter(([, v]) => v).flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]))),
    el('div', { class: 'tok' },
      el('div', { class: 'tok-head' }, el('h3', {}, 'Subject information')),
      el('pre', {}, JSON.stringify({ sub_ids: g.subject?.sub_ids, assertions: (g.subject?.assertions ?? []).map((a) => a.format), verified_claims: g.claims }, null, 2))),
  );
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

function showPageTab(which) {
  const name = which === 'caep' ? 'caep' : 'identity';
  store.set(PAGE_TAB_KEY, name, sessionStorage);
  for (const id of ['identity', 'caep']) {
    const on = id === name;
    $(`panel-${id}`).hidden = !on;
    $(`tab-${id}`).setAttribute('aria-selected', String(on));
    $(`tab-${id}`).tabIndex = on ? 0 : -1;
  }
}
for (const tab of document.querySelectorAll('.page-tab')) tab.addEventListener('click', () => showPageTab(tab.dataset.page));
showPageTab(store.get(PAGE_TAB_KEY, sessionStorage) === 'caep' ? 'caep' : 'identity');
document.addEventListener('click', (e) => {
  const menu = document.querySelector('.acct-menu');
  if (menu?.open && !menu.contains(e.target)) menu.open = false;
});
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });

async function copy(text, button) {
  const label = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Copy failed';
  }
  setTimeout(() => { button.textContent = label; }, 1500);
}
$('btn-copy-key').addEventListener('click', (e) => copy(JSON.stringify(client?.key.keyObject() ?? {}), e.currentTarget));

$('btn-rotate').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const out = $('token-out');
  out.hidden = false;
  try {
    const g = await accounts.rotate();
    out.textContent = `POST manage URI → new token, expires ${new Date(g.expires_at * 1000).toLocaleTimeString()}`;
  } catch (err) {
    out.textContent = `Rotation failed: ${describe(err)}`;
  }
}));
$('btn-revoke-token').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const out = $('token-out');
  out.hidden = false;
  try {
    const g = await accounts.getTokenSet();
    await client.revokeToken(g);
    out.textContent = 'DELETE manage URI → revoked. The AS sends CAEP session-revoked for gnap-token:<jti>; watch the event log.';
  } catch (err) {
    out.textContent = `Revocation failed: ${describe(err)}`;
  }
}));
$('btn-verify').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try {
    await caep.receiver.requestVerification({ timeoutMs: 15_000 });
  } catch (err) {
    caep.state = { ...caep.state, error: `Verification failed: ${describe(err)}` };
    render();
  }
}));
$('btn-events').addEventListener('click', async (e) => {
  e.currentTarget.disabled = true;
  store.set(EVENTS_KEY, pickedEvents());
  try {
    await caep.receiver?.updateStream({ events_requested: eventUris(selectedEvents()) });
    log({ name: 'subscription', action: `Stream now asks for: ${selectedEvents().join(', ')}.` });
  } catch (err) {
    caep.state = { ...caep.state, error: `Could not update the stream's event types: ${describe(err)}` };
  }
  render();
});
$('btn-reconnect').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const me = signedIn();
  await stopCaep(me.key);
  store.del(STREAM_KEY);
  await startCaep(me, (opts) => accounts.getTokenSet(opts));
}));

// ---------------------------------------------------------------------------
// Start-up
// ---------------------------------------------------------------------------

async function start() {
  drawEventOptions();
  try {
    const res = await fetch('/gnap.json', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status} reading /gnap.json`);
    await applyConfig(parseConfig(await res.json()));
  } catch (err) {
    ui.error = `The GNAP configuration could not be applied: ${describe(err)}`;
    client = undefined;
    accounts = undefined;
  }
  if (client && location.pathname === '/callback') await completeCallback();
  else if (location.pathname === '/callback') {
    ui.error = 'Returned from the authorization server, but this browser has no configuration for it.';
    history.replaceState(null, '', '/');
  }
  await render();
}

start();
