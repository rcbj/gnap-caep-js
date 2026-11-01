// Tests for scripts/configure-iya-sts.mjs: what it would ask iya-sts to write, worked out offline.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { demoPort, parseArgs, planFor, publicUrlFor, readGnapFile } from './configure-iya-sts.mjs';

const SCRIPT = fileURLToPath(new URL('./configure-iya-sts.mjs', import.meta.url));
const DEMO_FILE = fileURLToPath(new URL('../demo/public/gnap.json', import.meta.url));

describe('configure-iya-sts', () => {
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
