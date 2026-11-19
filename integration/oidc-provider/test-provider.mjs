import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './provider.mjs';
import { advancedOptions, inspectRS256, peerCertificate } from './advanced-provider.mjs';
import { generateKeyPairSync, sign } from 'node:crypto';
import { resourceOptions } from './resource-provider.mjs';
import { createServer } from 'node:http';

const config = {
  issuer: 'https://localhost:30000', redirect_uri: 'https://localhost:30001/',
  run_id: 'a'.repeat(32), control_key: 'b'.repeat(64), client_id: 'local-public', client_auth_type: 'none',
};

test('fixture rejects external origins and unsupported registrations before startup', () => {
  for (const patch of [
    { issuer: 'http://localhost:30000' }, { issuer: 'https://example.com' },
    { redirect_uri: 'https://example.com/' }, { client_auth_type: 'client_secret_post' },
    { run_id: 'unsafe' }, { control_key: 'short' },
  ]) assert.throws(() => fixture({ ...config, ...patch }), /Invalid local fixture configuration/);
});

test('provider event collection excludes errors and credentials supplied by listeners', () => {
  const { provider, events } = fixture(config);
  provider.emit('grant.error', { oidc: { params: { client_id: config.client_id } } }, {
    error: 'DO_NOT_EXPORT', error_description: 'DO_NOT_EXPORT_SECRET', cause: 'DO_NOT_EXPORT_CAUSE',
  });
  assert.deepEqual(events, [{ sequence: 1, type: 'grant.error', error: 'other_error', client_matches: true, pkce_missing: true }]);
  assert.doesNotMatch(JSON.stringify(events), /DO_NOT_EXPORT/);
});

test('public client evidence distinguishes an unexpected authentication header', () => {
  const { provider, events } = fixture(config);
  provider.emit('grant.success', {
    oidc: { params: { client_id: config.client_id, grant_type: 'refresh_token' }, client: { clientId: config.client_id } },
    body: { access_token: 'DO_NOT_EXPORT_ACCESS', refresh_token: 'DO_NOT_EXPORT_REFRESH', id_token: 'DO_NOT_EXPORT_ID' },
    get: () => 'Basic DO_NOT_EXPORT_HEADER',
  });
  assert.equal(events[0].authentication_valid, false);
  assert.doesNotMatch(JSON.stringify(events), /DO_NOT_EXPORT/);
});

test('signature inspection verifies actual RS256 bytes independently of expiry policy', () => {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pub = pair.publicKey.export({ format: 'jwk' });
  const input = [Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url'),
    Buffer.from(JSON.stringify({ exp: 1, sub: 'DO_NOT_EXPORT' })).toString('base64url')].join('.');
  const jwt = `${input}.${sign('RSA-SHA256', Buffer.from(input), pair.privateKey).toString('base64url')}`;
  assert.equal(inspectRS256(jwt, pub).claims.exp, 1);
  assert.equal(inspectRS256(`${input}.${'A'.repeat(342)}`, pub), null);
  assert.equal(inspectRS256(jwt, generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' })), null);
});

test('advanced registration rejects private client material and retains native JAR validation', () => {
  const publicKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
  const selected = { ...config, advanced: { sender: 'dpop', par: true, jarm: false }, client_jwk: publicKey };
  const options = advancedOptions(selected);
  assert.equal(options.features.requestObjects.requireSignedRequestObject, true);
  assert.equal('assertJwtClaimsAndHeader' in options.features.requestObjects, false);
  assert.throws(() => advancedOptions({ ...selected, client_assertion_private_key: 'PRIVATE MATERIAL' }), /private material/);
  assert.throws(() => advancedOptions({ ...selected, client_jwk: { ...publicKey, d: 'PRIVATE MATERIAL' } }), /Invalid advanced/);
});

test('mTLS certificate collection uses the TLS peer rather than a forwarded header', () => {
  assert.equal(peerCertificate({ req: { socket: { getPeerCertificate: () => ({}) } }, get: () => 'FORGED CERTIFICATE' }), undefined);
});

test('resource configuration resolves exact audiences and rejects unknown indicators natively', () => {
  const options = resourceOptions({ ...config, resource_indicators: { target: 'a' } });
  const resolve = options.resourceIndicators.getResourceServerInfo;
  for (const target of ['a', 'b']) {
    const uri = `${config.issuer}/resource/${target}`;
    assert.equal(resolve(null, uri).audience, uri);
    assert.equal(resolve(null, uri).scope, 'api.read');
  }
  for (const uri of [`${config.issuer}/resource/unknown`, `${config.issuer}/resource/a/`]) {
    assert.throws(() => resolve(null, uri), error => error.error === 'invalid_target');
  }
  assert.equal(options.userinfo.enabled, false);
  assert.throws(() => resourceOptions({ ...config, resource_indicators: { target: 'a' }, advanced: {} }), /Invalid resource/);
});

test('rotation observation is opt-in and native JWKS retain their original headers and public keys', async () => {
  assert.throws(() => fixture({ ...config, jwks_rotation: 'true' }), /Invalid JWKS rotation selection/);
  const selected = fixture({ ...config, jwks_rotation: true });
  const second = fixture({ ...config, jwks_rotation: true });
  const evidence = async instance => {
    let body;
    await instance.handler({ url: '/fixture/evidence', method: 'GET', headers: { 'x-fixture-key': config.control_key } }, {
      setHeader() {}, end(value) { body = JSON.parse(value); },
    });
    return body;
  };
  assert.equal('jwks_rotation' in await evidence(fixture(config)), false);
  const first = (await evidence(selected)).jwks_rotation;
  const next = (await evidence(second)).jwks_rotation;
  assert.match(first.instance_id, /^[a-f0-9]{32}$/);
  assert.equal(first.issuer, config.issuer);
  assert.equal(next.issuer, first.issuer);
  assert.notEqual(first.instance_id, next.instance_id);
  assert.notEqual(first.active_kid, next.active_kid);
  const server = createServer((req, res) => Promise.resolve(selected.handler(req, res)).catch(error => {
    res.writeHead(500).end(); throw error;
  }));
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/jwks`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), null);
    assert.equal(response.headers.get('expires'), null);
    const jwks = await response.json();
    assert.deepEqual(jwks.keys.map(value => value.kid), [first.active_kid]);
    assert.equal(jwks.keys.every(value => !('d' in value) && !('p' in value)), true);
    assert.deepEqual(selected.events, [{ sequence: 1, type: 'jwks', status: 200,
      kids: [first.active_kid], cache_control: null, expires: null }]);
    assert.doesNotMatch(JSON.stringify(await evidence(selected)), /"control_key"|"client_secret"|"d"|"p"/);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
