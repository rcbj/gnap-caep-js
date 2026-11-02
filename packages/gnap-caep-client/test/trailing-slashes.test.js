// Trailing slashes are trimmed in linear time (CodeQL js/polynomial-redos). `replace(/\/+$/, '')`
// retries at every slash of a run that is not at the end of the string, so an issuer or a grant
// endpoint (the grant server's own discovery document names one) with a long run of slashes followed
// by any other character took seconds; the loop takes microseconds.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { oidcDiscoveryUrl, validateGrantServerMetadata } from '../src/index.js';
import { wellKnownUrls } from '../src/discovery.js';

const RUN = '/'.repeat(100_000);
const BUDGET_MS = 500;

function timed(what, fn) {
  const started = performance.now();
  const result = fn();
  const took = performance.now() - started;
  assert.ok(took < BUDGET_MS, `${what} took ${Math.round(took)} ms`);
  return result;
}

describe('trailing slashes', () => {
  it('are trimmed and nothing else', () => {
    assert.equal(oidcDiscoveryUrl('https://as/'), 'https://as/.well-known/openid-configuration');
    assert.equal(oidcDiscoveryUrl('https://as/realm///'), 'https://as/realm/.well-known/openid-configuration');
    assert.equal(oidcDiscoveryUrl('https://as//a'), 'https://as//a/.well-known/openid-configuration');
    assert.deepEqual(wellKnownUrls('https://as/realm/a/', 'ssf-configuration'), [
      'https://as/.well-known/ssf-configuration/realm/a',
      'https://as/realm/a/.well-known/ssf-configuration',
    ]);
    const metadata = { grant_request_endpoint: 'https://as/gnap/' };
    assert.equal(validateGrantServerMetadata(metadata, 'https://as/gnap'), metadata);
    assert.throws(() => validateGrantServerMetadata(metadata, 'https://as/gnap/x'), /Grant endpoint mismatch/);
  });

  it('builds the discovery URL from a long run of slashes that is not at the end in linear time', () => {
    const issuer = `https://as${RUN}x`;
    assert.equal(timed('oidcDiscoveryUrl', () => oidcDiscoveryUrl(issuer)), `${issuer}/.well-known/openid-configuration`);
    assert.equal(timed('a run at the end', () => oidcDiscoveryUrl(`https://as${RUN}`)), 'https://as/.well-known/openid-configuration');
  });

  it('compares a grant endpoint named with such a run in linear time', () => {
    const metadata = { grant_request_endpoint: `https://as/gnap${RUN}x` };
    assert.throws(() => timed('validateGrantServerMetadata', () => validateGrantServerMetadata(metadata, 'https://as/gnap')),
      /Grant endpoint mismatch/);
    assert.equal(timed('validateGrantServerMetadata', () => validateGrantServerMetadata(metadata, `https://as/gnap${RUN}x/`)), metadata);
  });

  it('builds the well-known URLs from such an issuer path in linear time', () => {
    const urls = timed('wellKnownUrls', () => wellKnownUrls(`https://as${RUN}x`, 'ssf-configuration'));
    assert.equal(urls[0], `https://as/.well-known/ssf-configuration${RUN}x`);
  });
});
