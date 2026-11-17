import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './provider.mjs';

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
