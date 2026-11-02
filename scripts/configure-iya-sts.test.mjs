// Tests for scripts/configure-iya-sts.mjs: what it would ask iya-sts to write, worked out offline.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  demoPort, parseArgs, planFor, publicUrlFor, readGnapFile, rootOnFirstUse, savePassword, trustAnchor,
} from './configure-iya-sts.mjs';

const SCRIPT = fileURLToPath(new URL('./configure-iya-sts.mjs', import.meta.url));
const DEMO_FILE = fileURLToPath(new URL('../demo/public/gnap.json', import.meta.url));

describe('configure-iya-sts', () => {
  it('writes a generated password to <user>.password, mode 0600, and never prints it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gnap-password-'));
    try {
      const path = savePassword('gnap-demo-user', 's3cret-value', join(dir, 'generated'));
      assert.equal(path, join(dir, 'generated', 'gnap-demo-user.password'));
      assert.equal(readFileSync(path, 'utf8'), 's3cret-value\n');
      assert.equal(statSync(path).mode & 0o777, 0o600);
      // An existing, wider file is narrowed.
      writeFileSync(path, 'old', { mode: 0o644 });
      savePassword('gnap-demo-user', 'again', join(dir, 'generated'));
      assert.equal(statSync(path).mode & 0o777, 0o600);
      assert.throws(() => savePassword('../x', 'p', dir), /cannot name a file/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    const source = readFileSync(SCRIPT, 'utf8');
    assert.doesNotMatch(source, /console\.\w+\([^)]*created\.body\.password\s*\}/);
  });

  it('reads the demo\'s file: the default realm, and the Shared Signals scopes its access names', () => {
    const file = readGnapFile(readFileSync(DEMO_FILE, 'utf8'));
    assert.equal(file.realmBase, 'https://localhost:8081');
    assert.deepEqual(file.scopes, ['ssf.read', 'ssf.manage']);
    assert.equal(file.application, 'gnap-caep-demo');
    const realm = readGnapFile(JSON.stringify({ grantEndpoint: 'https://sts.test/realm/r1/gnap', access: [{ type: 'ssf', actions: ['write'] }] }));
    assert.equal(realm.realmBase, 'https://sts.test/realm/r1');
    assert.deepEqual(realm.scopes, ['ssf.manage']);
    assert.throws(() => readGnapFile(JSON.stringify({ grantEndpoint: 'https://sts.test/oauth2/token' })), /grant endpoint/);
    assert.throws(() => readGnapFile(JSON.stringify({ grantEndpoint: 'https://sts.test/payments/gnap' })), /profile/);
    const off = readGnapFile(JSON.stringify({
      grantEndpoint: 'https://sts.test/gnap', signals: false,
      access: ['openid', 'ssf.read', 'ssf.manage', { type: 'ssf', actions: ['write'] }],
    }));
    assert.deepEqual(off.scopes, []);
    const plan = planFor({ file: off, identifier: 'x', publicUrl: 'http://localhost:3000', testUser: '' });
    assert.equal(plan.fields.oauthAllowedScope, undefined);
    assert.equal(plan.calls.some((c) => c.path === '/roles/add-member'), false);
  });

  it('plans the application, the SSF roles and the test user', () => {
    const file = readGnapFile(readFileSync(DEMO_FILE, 'utf8'));
    const { calls, fields, finishUri } = planFor({ file, identifier: 'gnap-caep-demo', publicUrl: 'http://localhost:3000', testUser: 'gnap-demo-user' });
    assert.equal(finishUri, 'http://localhost:3000/callback');
    assert.deepEqual(calls.map((c) => c.path), ['/applications/create', '/roles/add-member', '/roles/add-member', '/users/create']);
    assert.equal(calls[0].body.kind, 'gnap-client');
    assert.deepEqual(calls[0].body.protocols, ['gnap']);
    assert.deepEqual(fields.gnapFinishUri, ['http://localhost:3000/callback']);
    assert.deepEqual(fields.appCorsOrigin, ['http://localhost:3000']);
    assert.equal(fields.gnapInstanceId, 'gnap-caep-demo', 'the token\'s client_id, which iya-sts\'s CORS check resolves');
    assert.deepEqual(fields.oauthAllowedScope, ['ssf.read', 'ssf.manage']);
    assert.equal(fields.gnapKey, undefined, 'no key is registered: each browser\'s key is an instance, named by class_id');
    assert.deepEqual(calls.slice(1, 3).map((c) => c.body.role), ['SSF_READ', 'SSF_MANAGE']);
    const noUser = planFor({ file, identifier: 'x', publicUrl: 'https://demo.example', testUser: '' });
    assert.equal(noUser.calls.at(-1).path, '/roles/add-member');
  });

  it('parses its arguments', () => {
    const a = parseArgs(['--public-url', 'https://demo.example/', '--no-test-user', '--dry-run'], {});
    assert.equal(a.publicUrl, 'https://demo.example');
    assert.equal(a.publicUrlGiven, true);
    assert.equal(a.testUser, '');
    assert.equal(a.dryRun, true);
    assert.equal(parseArgs([], {}).publicUrlGiven, false);
    assert.equal(parseArgs([], { PUBLIC_URL: '' }).publicUrlGiven, false);
    const kept = parseArgs([], { PUBLIC_URL: 'https://edge.example/', PORT: '3001' });
    assert.equal(kept.publicUrlGiven, true);
    assert.equal(kept.publicUrl, 'https://edge.example');
    assert.throws(() => parseArgs(['--bogus'], {}), /Unknown argument/);
    assert.throws(() => parseArgs(['--key', '{}'], {}), /Unknown argument --key/);
    assert.throws(() => parseArgs(['--identifier'], {}), /needs a value/);
  });

  it('registers the finish URI on the port the demo listens on', () => {
    const file = readGnapFile(readFileSync(DEMO_FILE, 'utf8'));
    const onPort = publicUrlFor({ publicUrlGiven: false, envPort: '3001' });
    assert.equal(onPort, 'http://localhost:3001');
    const plan = planFor({ file, identifier: 'gnap-caep-demo', publicUrl: onPort, testUser: 'gnap-demo-user' });
    assert.equal(plan.finishUri, 'http://localhost:3001/callback');
    assert.equal(plan.fields.gnapDisplayUri, 'http://localhost:3001/');
    assert.deepEqual(plan.fields.gnapFinishUri, ['http://localhost:3001/callback']);
    assert.deepEqual(plan.fields.appCorsOrigin, ['http://localhost:3001']);

    const flagged = parseArgs(['--public-url', 'https://demo.example/'], { PORT: '3001' });
    assert.equal(publicUrlFor({ ...flagged, envPort: '3001', containerPort: '3009' }), 'https://demo.example');
    const fromEnv = parseArgs([], { PUBLIC_URL: 'http://demo.test:9/', PORT: '3001' });
    assert.equal(publicUrlFor({ ...fromEnv, envPort: '3001', containerPort: '3009' }), 'http://demo.test:9');

    assert.equal(demoPort('3000', '3001'), 3001);
    assert.equal(demoPort('3001', ''), 3001);
    assert.equal(demoPort('', undefined), undefined);
    assert.equal(demoPort('nope', undefined), undefined);
    const containerWins = publicUrlFor({ publicUrlGiven: false, envPort: '3000', containerPort: '3001' });
    assert.equal(containerWins, 'http://localhost:3001');
    const moved = planFor({ file, identifier: 'gnap-caep-demo', publicUrl: containerWins, testUser: '' });
    assert.equal(moved.finishUri, 'http://localhost:3001/callback');
    assert.equal(moved.fields.gnapDisplayUri, 'http://localhost:3001/');
    assert.equal(publicUrlFor({ publicUrlGiven: false }), 'http://localhost:3000');
  });

  it('--dry-run prints the calls and sends nothing', () => {
    const out = execFileSync(process.execPath, [SCRIPT, '--dry-run'], {
      encoding: 'utf8',
      env: { ...process.env, ADMIN_API_CLIENT_SECRET: '', PUBLIC_URL: 'http://localhost:3000' },
    });
    assert.match(out, /nothing is sent/);
    assert.match(out, /POST \/applications\/create/);
    assert.doesNotMatch(out, /"gnapKey"/);
  });

  it('a dry run with PORT and no public URL registers that port', () => {
    // PATH has no docker: the container lookup fails closed, and $PORT is the port.
    const out = execFileSync(process.execPath, [SCRIPT, '--dry-run'], {
      encoding: 'utf8',
      env: { PATH: '/nonexistent', PORT: '3001', ADMIN_API_CLIENT_SECRET: '' },
    });
    assert.match(out, /http:\/\/localhost:3001\/callback/);
    assert.match(out, /"gnapDisplayUri": "http:\/\/localhost:3001\/"/);
    assert.doesNotMatch(out, /localhost:3000/);
  });
});

describe('configure-iya-sts: TLS', () => {
  const work = mkdtempSync(join(tmpdir(), 'register-tls-'));
  const openssl = (...args) => execFileSync('openssl', args, { stdio: 'ignore' });
  const ext = join(work, 'ext.cnf');
  writeFileSync(ext, [
    '[ca]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign',
    '[leaf]', 'basicConstraints = critical, CA:FALSE', 'extendedKeyUsage = serverAuth',
    'subjectAltName = IP:127.0.0.1, DNS:localhost', '',
  ].join('\n'));
  const root = (name) => openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', `/CN=${name}`, '-keyout', join(work, `${name}.key`), '-out', join(work, `${name}.pem`),
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  root('sts-root');
  root('other-root');
  openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
    '-keyout', join(work, 'leaf.key'), '-out', join(work, 'leaf.csr'));
  openssl('x509', '-req', '-in', join(work, 'leaf.csr'), '-days', '1', '-set_serial', '7',
    '-CA', join(work, 'sts-root.pem'), '-CAkey', join(work, 'sts-root.key'),
    '-extfile', ext, '-extensions', 'leaf', '-out', join(work, 'leaf.pem'));
  const pem = (name) => readFileSync(join(work, `${name}.pem`), 'utf8');
  const cert = (name) => new X509Certificate(pem(name));
  let server;
  let origin = '';

  before(async () => {
    server = https.createServer({ key: readFileSync(join(work, 'leaf.key')), cert: `${pem('leaf')}${pem('sts-root')}` },
      (req, res) => {
        res.statusCode = req.url === '/tls/server-certificate' ? 200 : 404;
        res.end(req.url === '/tls/server-certificate' ? `${pem('leaf')}${pem('sts-root')}` : '');
      });
    await new Promise((done) => server.listen(0, '127.0.0.1', done));
    origin = `https://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await new Promise((done) => server.close(done));
  });

  it('without --ca, takes the presented root on first use', async () => {
    const anchor = await trustAnchor(origin, '');
    assert.equal(anchor.firstUse, true);
    assert.equal(anchor.root.fingerprint256, cert('sts-root').fingerprint256);
    assert.equal(new X509Certificate(anchor.pem).fingerprint256, cert('sts-root').fingerprint256);
  });

  it('without --ca, a server that does not publish its chain is refused', async () => {
    const bare = https.createServer({ key: readFileSync(join(work, 'leaf.key')), cert: pem('leaf') },
      (_req, res) => { res.statusCode = 404; res.end(); });
    await new Promise((done) => bare.listen(0, '127.0.0.1', done));
    try {
      await assert.rejects(trustAnchor(`https://127.0.0.1:${bare.address().port}`, ''), /answered 404/);
    } finally {
      await new Promise((done) => bare.close(done));
    }
  });

  it('with --ca, uses that file and fetches nothing', async () => {
    const anchor = await trustAnchor('https://127.0.0.1:1', join(work, 'sts-root.pem'));
    assert.equal(anchor.firstUse, false);
    assert.equal(anchor.pem, pem('sts-root'));
    await assert.rejects(trustAnchor(origin, join(work, 'ext.cnf')), /no PEM certificate/);
    assert.equal(parseArgs(['--ca', 'x.pem'], {}).ca, resolve('x.pem'));
    assert.equal(parseArgs([], { IYA_STS_CA: 'y.pem' }).ca, resolve('y.pem'));
  });

  it('first use checks the host name and every link, and needs a self-signed root', () => {
    const leaf = cert('leaf');
    assert.equal(rootOnFirstUse('127.0.0.1', [leaf, cert('sts-root')]).fingerprint256, cert('sts-root').fingerprint256);
    assert.throws(() => rootOnFirstUse('elsewhere.example', [leaf, cert('sts-root')]), /altnames|Hostname/);
    assert.throws(() => rootOnFirstUse('127.0.0.1', [leaf, cert('other-root')]), /not signed/);
    assert.throws(() => rootOnFirstUse('127.0.0.1', [leaf]), /self-signed root/);
    assert.throws(() => rootOnFirstUse('127.0.0.1', []), /no certificate/);
  });
});
