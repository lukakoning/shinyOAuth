import { createHash, createPublicKey, verify, X509Certificate } from 'node:crypto';

export function inspectRS256(value, jwk) {
  try {
    const parts = value.split('.');
    if (parts.length !== 3) return null;
    const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
    if (header.alg !== 'RS256' || !verify('RSA-SHA256', Buffer.from(parts.slice(0, 2).join('.')),
      createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'))) return null;
    return { header, claims };
  } catch { return null; }
}

const hash = value => createHash('sha256').update(value).digest('base64url');
export const peerCertificate = ctx => {
  const raw = ctx.req.socket.getPeerCertificate?.().raw;
  return raw ? new X509Certificate(raw).toString() : undefined;
};

export function advancedOptions(config) {
  const mode = config.advanced;
  if (!mode) return null;
  if (![null, 'dpop', 'mtls'].includes(mode.sender) || typeof mode.par !== 'boolean' ||
      typeof mode.jarm !== 'boolean' || (mode.sender === null && !mode.jarm) ||
      !config.client_jwk || config.client_jwk.kty !== 'RSA' || 'd' in config.client_jwk) throw Error('Invalid advanced fixture configuration');
  if (['client_assertion_private_key', 'dpop_private_key', 'mtls'].some(name => name in config)) throw Error('Client private material cannot enter provider configuration');
  return {
    registration: { jwks: { keys: [config.client_jwk] }, request_object_signing_alg: 'RS256', require_signed_request_object: true,
      userinfo_signed_response_alg: 'RS256',
      ...(mode.jarm ? { authorization_signed_response_alg: 'RS256' } : {}),
      ...(mode.sender === 'dpop' ? { dpop_bound_access_tokens: true } : {}),
      ...(mode.sender === 'mtls' ? { tls_client_certificate_bound_access_tokens: true, use_mtls_endpoint_aliases: true } : {}),
    },
    discovery: mode.sender === 'mtls' ? { mtls_endpoint_aliases: Object.fromEntries([
      ['token_endpoint', '/token'], ['userinfo_endpoint', '/userinfo'],
      ['introspection_endpoint', '/token/introspection'], ['revocation_endpoint', '/token/revocation'],
      ...(mode.par ? [['pushed_authorization_request_endpoint', '/request']] : []),
    ].map(([name, path]) => [name, `${config.mtls_origin}${path}`])) } : {},
    features: {
      jwtUserinfo: { enabled: true },
      requestObjects: { enabled: true, requireSignedRequestObject: true },
      pushedAuthorizationRequests: { enabled: mode.par, requirePushedAuthorizationRequests: mode.par },
      jwtResponseModes: { enabled: mode.jarm }, dPoP: { enabled: mode.sender === 'dpop', allowReplay: false, requireNonce: () => false },
      mTLS: { enabled: mode.sender === 'mtls', certificateBoundAccessTokens: mode.sender === 'mtls', getCertificate: peerCertificate },
      introspection: { enabled: true }, revocation: { enabled: true },
    },
  };
}

export function senderFacts(ctx, config, state) {
  const authorization = ctx.get('authorization').replace(/^(Bearer|DPoP) /i, '');
  let proof;
  try { proof = JSON.parse(Buffer.from(ctx.get('dpop').split('.')[0], 'base64url')); } catch { /* An absent proof is an expected attacker input. */ }
  const jwk = proof?.jwk;
  const thumbprint = jwk?.kty === 'EC' ? hash(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })) : undefined;
  const raw = ctx.req.socket.getPeerCertificate?.().raw;
  const peer = raw ? hash(raw) : undefined;
  return {
    probe: ['bearer', 'wrong_key', 'replay_valid', 'replay', 'missing_cert', 'wrong_cert', 'forged_header', 'revoked'].includes(ctx.get('x-fixture-probe')) ? ctx.get('x-fixture-probe') : null,
    current_token_used: authorization === state.currentAccess,
    dpop_key_matches: config.advanced.sender === 'dpop' ? !!thumbprint && thumbprint === state.dpopJkt : null,
    mtls_peer_present: !!raw,
    mtls_peer_matches: config.advanced.sender === 'mtls' ? !!peer && peer === state.mtlsThumbprint && peer === config.mtls_thumbprint : null,
  };
}

export function observeAdvanced(ctx, config, key, state, record) {
  const query = new URL(ctx.req.url, config.issuer).searchParams;
  const pushed = ctx.path === '/request' && ctx.method === 'POST';
  const direct = ctx.path === '/authorize' && query.has('request');
  if (pushed || direct) {
    const jar = pushed ? ctx.oidc.body?.request : query.get('request');
    const parsed = inspectRS256(jar, config.client_jwk);
    const claims = parsed?.claims;
    if (claims?.dpop_jkt) state.requestJkt = claims.dpop_jkt;
    record('request_object', {
      source: pushed ? 'par' : 'direct', status: ctx.status, signature_valid: !!parsed,
      issuer_matches: claims?.iss === config.client_id, audience_matches: claims?.aud === config.issuer,
      redirect_matches: claims?.redirect_uri === config.redirect_uri,
      code_flow: claims?.response_type === 'code', pkce_s256: claims?.code_challenge_method === 'S256',
      state_present: typeof claims?.state === 'string' && claims.state.length >= 22,
      nonce_present: typeof claims?.nonce === 'string' && claims.nonce.length >= 16,
      dpop_jkt_present: config.advanced.sender === 'dpop' ? typeof claims?.dpop_jkt === 'string' : null,
      par_reference_issued: pushed ? ctx.status === 201 && typeof ctx.body?.request_uri === 'string' : null,
    });
  }
  if (ctx.path === '/authorize') record('frontchannel', {
    pushed: query.has('request_uri'), signed: query.has('request'),
    par_only: config.advanced.par ? [...query.keys()].sort().join(',') === 'client_id,request_uri' : null,
  });
  const location = ctx.response.get('location') || '';
  if (config.advanced.jarm && location.startsWith(config.redirect_uri)) {
    const response = new URL(location);
    const parsed = inspectRS256(response.searchParams.get('response'), key);
    record('jarm', { signature_valid: !!parsed, issuer_matches: parsed?.claims.iss === config.issuer,
      audience_matches: parsed?.claims.aud === config.client_id, code_present: typeof parsed?.claims.code === 'string',
      expiry_valid: typeof parsed?.claims.exp === 'number' && parsed.claims.exp > Date.now() / 1000,
      query_only: [...response.searchParams.keys()].join(',') === 'response' });
  }
  if (ctx.path === '/userinfo') {
    const parsed = inspectRS256(ctx.body, key);
    record('userinfo', { status: ctx.status, signed_response_valid: !!parsed,
      issuer_matches: parsed?.claims.iss === config.issuer, audience_matches: parsed?.claims.aud === config.client_id,
      subject_present: typeof parsed?.claims.sub === 'string', ...senderFacts(ctx, config, state) });
  }
  if (['/token/introspection', '/token/revocation'].includes(ctx.path)) {
    record(ctx.path.endsWith('introspection') ? 'introspection' : 'revocation', {
      status: ctx.status, client_matches: ctx.oidc.client?.clientId === config.client_id,
      current_token_used: ctx.oidc.params?.token === state.currentAccess,
      active: ctx.path.endsWith('introspection') ? ctx.body?.active === true : null,
    });
  }
}
