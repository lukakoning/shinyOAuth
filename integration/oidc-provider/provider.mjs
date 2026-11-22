import { createServer } from 'node:https';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import Provider from 'oidc-provider';
import { advancedOptions, observeAdvanced, senderFacts } from './advanced-provider.mjs';
import { resourceOptions, resourceFacts, resourceResponse, observeResource } from './resource-provider.mjs';

const lock = JSON.parse(readFileSync(new URL('./provider-lock.json', import.meta.url)));
const version = JSON.parse(readFileSync(new URL('./node_modules/oidc-provider/package.json', import.meta.url))).version;
const digest = value => createHash('sha256').update(value).digest('base64url');

export function fixture(config) {
  if (process.version !== lock.node_version || version !== lock.provider_version) throw Error('Pinned runtime mismatch');
  const issuer = new URL(config.issuer);
  const redirect = new URL(config.redirect_uri);
  if (issuer.protocol !== 'https:' || issuer.hostname !== 'localhost' || issuer.pathname !== '/' ||
      redirect.protocol !== 'https:' || redirect.hostname !== 'localhost' || redirect.pathname !== '/' ||
      !['none', 'client_secret_basic'].includes(config.client_auth_type) ||
      !/^[a-f0-9]{32}$/.test(config.run_id) || !/^[a-f0-9]{64}$/.test(config.control_key)) throw Error('Invalid local fixture configuration');
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
  Object.assign(key, { kid: randomBytes(16).toString('hex'), alg: 'RS256', use: 'sig' });
  if (config.jwks_rotation !== undefined && config.jwks_rotation !== true) throw Error('Invalid JWKS rotation selection');
  const rotation = config.jwks_rotation ? { instance_id: randomBytes(16).toString('hex'), active_kid: key.kid, issuer: config.issuer } : undefined;
  const client = {
    client_id: config.client_id, redirect_uris: [config.redirect_uri],
    token_endpoint_auth_method: config.client_auth_type,
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
    id_token_signed_response_alg: 'RS256',
  };
  if (config.client_auth_type === 'client_secret_basic') client.client_secret = config.client_secret;
  const features = { devInteractions: { enabled: false }, userinfo: { enabled: true } };
  const advanced = advancedOptions(config);
  const resources = resourceOptions(config);
  if (resources) Object.assign(features, resources);
  if (advanced) {
    Object.assign(client, advanced.registration);
    Object.assign(features, advanced.features);
  }
  const provider = new Provider(config.issuer, {
    clients: [client], jwks: { keys: [key] }, features,
    ...(advanced ? { discovery: advanced.discovery } : {}),
    cookies: { keys: [randomBytes(32).toString('base64url')] },
    claims: { openid: ['sub'], profile: ['name'], email: ['email', 'email_verified'] },
    scopes: ['openid', 'profile', 'email', 'offline_access'], responseTypes: ['code'],
    pkce: { required: () => true },
    routes: { authorization: '/authorize', userinfo: '/userinfo' },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    rotateRefreshToken: true,
    findAccount: async (_ctx, id) => ({ accountId: id, claims: async () => ({
      sub: id, name: 'Local test account', email: 'fixture@example.invalid', email_verified: true,
    }) }),
  });
  const events = [];
  const record = (type, fields = {}) => events.push({ sequence: events.length + 1, type, ...fields });
  const observeAuthenticationTime = config.observe_authentication_time === true;
  const epochSeconds = () => Math.floor(Date.now() / 1000);
  let pushedAgeRequest;
  let pushedAgeChallenge;
  let challenge;
  let codeDigest;
  const issued = new Set();
  let currentAccess;
  let previousRefresh;
  const state = {};
  const errors = new Set(['invalid_request', 'invalid_client', 'invalid_grant', 'access_denied', 'invalid_token', 'invalid_dpop_proof', 'invalid_request_object', 'invalid_target']);
  for (const type of ['authorization.error', 'grant.error', 'userinfo.error', 'server_error', ...(advanced ? ['pushed_authorization_request.error', 'introspection.error', 'revocation.error'] : [])]) {
    provider.on(type, (ctx, error) => record(type, {
      error: errors.has(error?.error) ? error.error : 'other_error',
      client_matches: ctx.oidc?.params?.client_id === config.client_id || ctx.oidc?.client?.clientId === config.client_id,
      pkce_missing: !ctx.oidc?.params?.code_challenge,
      ...(advanced && type === 'userinfo.error' ? senderFacts(ctx, config, state) : {}),
      ...(resources ? resourceFacts(ctx, config) : {}),
    }));
  }
  if (observeAuthenticationTime) provider.on('pushed_authorization_request.success', (ctx, client) => {
    // Read the received form value before authorization normalizes max_age=0.
    const form = ctx.oidc.body;
    pushedAgeChallenge = form.code_challenge;
    pushedAgeRequest = {
      max_age: typeof form.max_age === 'string' ? form.max_age : null,
      client_matches: client.clientId === config.client_id,
    };
  });
  provider.on('authorization.accepted', ctx => {
    const params = ctx.oidc.params;
    challenge = params.code_challenge;
    record('authorization.accepted', {
      client_matches: params.client_id === config.client_id,
      code_flow: params.response_type === 'code', response_mode: params.response_mode ?? 'query',
      pkce_s256: params.code_challenge_method === 'S256' && /^[A-Za-z0-9_-]{43}$/.test(challenge),
      state_present: typeof params.state === 'string' && params.state.length >= 22,
      nonce_present: typeof params.nonce === 'string' && params.nonce.length >= 16,
      ...(observeAuthenticationTime ? { pushed_age_request: pushedAgeRequest ? {
        ...pushedAgeRequest,
        challenge_matches: typeof pushedAgeChallenge === 'string' && challenge === pushedAgeChallenge,
      } : null } : {}),
      ...(resources ? resourceFacts(ctx, config) : {}),
    });
  });
  provider.on('authorization.success', (_ctx, response) => {
    codeDigest = typeof response?.code === 'string' ? digest(response.code) : undefined;
    record('authorization.success', {
      code_issued: !!codeDigest,
      ...(observeAuthenticationTime ? { code_issued_at: epochSeconds() } : {}),
    });
  });
  provider.on('grant.success', ctx => {
    const params = ctx.oidc.params;
    const body = ctx.body;
    // Observe the claim in the provider's own issued token, without changing the response.
    const authenticationTime = observeAuthenticationTime && params.grant_type === 'authorization_code' &&
      typeof body.id_token === 'string'
      ? JSON.parse(Buffer.from(body.id_token.split('.')[1], 'base64url').toString('utf8')).auth_time
      : undefined;
    if (typeof body.access_token === 'string') issued.add(body.access_token);
    currentAccess = body.access_token;
    state.currentAccess = currentAccess;
    if (advanced) {
      state.dpopJkt = ctx.oidc.entities.AccessToken?.jkt;
      state.mtlsThumbprint = ctx.oidc.entities.AccessToken?.['x5t#S256'];
    }
    const authorization = ctx.get('authorization');
    const expected = `Basic ${Buffer.from(`${config.client_id}:${config.client_secret}`).toString('base64')}`;
    record('grant.success', {
      grant_type: params.grant_type,
      client_matches: ctx.oidc.client.clientId === config.client_id,
      authentication_valid: config.client_auth_type === 'none'
        ? !authorization && params.client_id === config.client_id && !params.client_secret
        : authorization === expected && !params.client_secret,
      pkce_verified: params.grant_type === 'authorization_code'
        ? typeof params.code_verifier === 'string' && digest(params.code_verifier) === challenge : null,
      code_matches: params.grant_type === 'authorization_code'
        ? typeof params.code === 'string' && digest(params.code) === codeDigest : null,
      access_token_present: typeof body.access_token === 'string',
      id_token_present: typeof body.id_token === 'string',
      ...(observeAuthenticationTime && params.grant_type === 'authorization_code'
        ? { auth_time: authenticationTime ?? null } : {}),
      refresh_token_present: typeof body.refresh_token === 'string',
      refresh_token_rotated: params.grant_type === 'refresh_token'
        ? params.refresh_token === previousRefresh && body.refresh_token !== previousRefresh : null,
      ...(resources ? { ...resourceFacts(ctx, config),
        audience_matches: ctx.oidc.entities.AccessToken?.aud === `${config.issuer}/resource/${config.resource_indicators.target}`,
        scope_matches: ctx.oidc.entities.AccessToken?.scope === 'api.read' } : {}),
      ...(advanced ? { sender_bound: config.advanced.sender === 'dpop' ? typeof state.dpopJkt === 'string' && state.dpopJkt === state.requestJkt
        : config.advanced.sender === 'mtls' ? typeof state.mtlsThumbprint === 'string' && state.mtlsThumbprint === config.mtls_thumbprint : true } : {}),
    });
    previousRefresh = body.refresh_token;
  });
  provider.use(async (ctx, next) => {
    await next();
    // Observe the native endpoint; do not supply keys or alter cache headers.
    if (rotation && ctx.path === '/jwks') record('jwks', {
      status: ctx.status, kids: (ctx.body?.keys ?? []).map(value => value.kid),
      cache_control: ctx.response.get('cache-control') || null,
      expires: ctx.response.get('expires') || null,
    });
    if (resources) observeResource(ctx, config, state, record);
    if (advanced) observeAdvanced(ctx, config, key, state, record);
    else if (ctx.path === '/userinfo') record('userinfo', {
      status: ctx.status, issued_token_used: issued.has(ctx.get('authorization').replace(/^Bearer /i, '')),
      current_token_used: ctx.get('authorization').replace(/^Bearer /i, '') === currentAccess,
      subject_present: typeof ctx.body?.sub === 'string',
    });
  });
  const callback = provider.callback();
  const handler = async (req, res) => {
    const path = new URL(req.url, config.issuer).pathname;
    if (path === '/api/server' && req.method === 'GET') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ provider: 'oidc-provider', version, node_version: process.version, ready: true }));
      return;
    }
    if (path === '/fixture/evidence' && req.method === 'GET') {
      res.setHeader('cache-control', 'no-store');
      if (req.headers['x-fixture-key'] !== config.control_key) { res.writeHead(403).end(); return; }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ run_id: config.run_id, provider_version: version, node_version: process.version,
        client_auth_type: config.client_auth_type, features: { dev_interactions: false, userinfo: !resources,
          pkce_required: true, refresh_rotation: true }, ...(advanced ? { advanced: config.advanced } : {}),
        ...(resources ? { resource_indicators: config.resource_indicators } : {}),
        ...(rotation ? { jwks_rotation: rotation } : {}), events }));
      return;
    }
    if (resources && await resourceResponse(req, res, provider, config, state, record)) return;
    if (/^\/interaction\/[A-Za-z0-9_-]+$/.test(path)) {
      const details = await provider.interactionDetails(req, res);
      const prompt = details.prompt.name;
      if (!['login', 'consent'].includes(prompt)) throw Error('Unexpected fixture prompt');
      if (req.method === 'GET') {
        res.setHeader('cache-control', 'no-store');
        res.setHeader('content-type', 'text/html; charset=utf-8');
        res.end(`<form method="post"><button id="fixture-${prompt}" type="submit">${prompt === 'login' ? 'Sign in with test account' : 'Allow test access'}</button></form>`);
        return;
      }
      if (req.method !== 'POST' || req.headers.origin !== config.issuer) { res.writeHead(400).end(); return; }
      record('interaction', {
        prompt,
        ...(observeAuthenticationTime && prompt === 'login' ? { login_started_at: epochSeconds() } : {}),
      });
      if (prompt === 'login') {
        await provider.interactionFinished(req, res, { login: { accountId: 'local-test-account' } }, { mergeWithLastSubmission: false });
      } else {
        const grant = details.grantId ? await provider.Grant.find(details.grantId)
          : new provider.Grant({ accountId: details.session.accountId, clientId: details.params.client_id });
        if (details.prompt.details.missingOIDCScope) grant.addOIDCScope(details.prompt.details.missingOIDCScope.join(' '));
        if (details.prompt.details.missingOIDCClaims) grant.addOIDCClaims(details.prompt.details.missingOIDCClaims);
        for (const [resource, scopes] of Object.entries(details.prompt.details.missingResourceScopes || {})) {
          grant.addResourceScope(resource, scopes.join(' '));
        }
        const grantId = await grant.save();
        await provider.interactionFinished(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
      }
      return;
    }
    callback(req, res);
  };
  return { provider, handler, events };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const config = JSON.parse(readFileSync(process.env.FIXTURE_CONFIG));
  const { handler } = fixture(config);
  const tls = { key: readFileSync(process.env.FIXTURE_TLS_KEY), cert: readFileSync(process.env.FIXTURE_TLS_CERT) };
  const serve = (req, res) => { Promise.resolve(handler(req, res)).catch(() => {
    if (!res.headersSent) res.writeHead(500);
    if (!res.writableEnded) res.end('Fixture failed');
  }); };
  const server = createServer(tls, serve);
  if (config.advanced?.sender === 'mtls') createServer({ ...tls, requestCert: true, rejectUnauthorized: false }, serve).listen(9444, '0.0.0.0');
  server.listen(9443, '0.0.0.0', () => console.log(JSON.stringify({ ready: true, version, node_version: process.version })));
}
