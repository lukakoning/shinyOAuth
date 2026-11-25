import { errors } from 'oidc-provider';

export const resourceURI = (config, target) => `${config.issuer}/resource/${target}`;

export function resourceOptions(config) {
  if (!config.resource_indicators) return null;
  const { target, narrow_scope: narrowScope } = config.resource_indicators;
  if (config.advanced || !['a', 'b', 'unknown'].includes(target) ||
    (narrowScope !== undefined && typeof narrowScope !== 'boolean') || (narrowScope && target === 'unknown')) {
    throw Error('Invalid resource fixture configuration');
  }
  return {
    // An API-audience token cannot be used at native UserInfo. ID-token
    // processing remains enabled; this selection does not request UserInfo.
    userinfo: { enabled: false },
    pushedAuthorizationRequests: { enabled: false },
    introspection: { enabled: true },
    resourceIndicators: {
      enabled: true,
      getResourceServerInfo(_ctx, indicator) {
        if (!['a', 'b'].some(target => indicator === resourceURI(config, target))) {
          throw new errors.InvalidTarget();
        }
        return {
          scope: narrowScope ? 'api.read api.write' : 'api.read',
          audience: indicator, accessTokenFormat: 'opaque', accessTokenTTL: 300,
        };
      },
    },
  };
}

export function resourceFacts(ctx, config) {
  return {
    requested_resource_matches: ctx.oidc.params?.resource === resourceURI(config, config.resource_indicators.target),
    resource_known: ['a', 'b'].some(target => ctx.oidc.params?.resource === resourceURI(config, target)),
  };
}

function matchesScope(value, broad = false) {
  const expected = broad ? 'api.read api.write' : 'api.read';
  return typeof value === 'string' && value.split(' ').sort().join(' ') === expected;
}

export function resourceGrantFacts(ctx, config) {
  const narrowScope = config.resource_indicators.narrow_scope;
  const refresh = ctx.oidc.params.grant_type === 'refresh_token';
  const broad = narrowScope && !refresh;
  return {
    ...resourceFacts(ctx, config),
    audience_matches: ctx.oidc.entities.AccessToken?.aud === resourceURI(config, config.resource_indicators.target),
    scope_matches: matchesScope(ctx.oidc.entities.AccessToken?.scope, broad),
    ...(narrowScope ? { response_scope_matches: matchesScope(ctx.body?.scope, broad) } : {}),
    ...(narrowScope && refresh ? { refresh_scope_read_only: ctx.oidc.body?.scope === 'api.read' } : {}),
  };
}

// This is a fixture resource server using the provider's public model API.
// Resource indicator validation and audience issuance stay in native handlers.
export async function resourceResponse(req, res, provider, config, state, record) {
  const target = new URL(req.url, config.issuer).pathname.match(/^\/resource\/(a|b)$/)?.[1];
  const narrowScope = config.resource_indicators.narrow_scope;
  const write = narrowScope && req.method === 'POST';
  if (!target || (!write && req.method !== 'GET')) return false;
  const value = /^Bearer (\S+)$/i.exec(req.headers.authorization || '')?.[1];
  const token = value ? await provider.AccessToken.find(value) : undefined;
  const grant = token ? await provider.Grant.find(token.grantId) : undefined;
  const valid = !!token && !!grant && !grant.isExpired && token.clientId === config.client_id &&
    token.accountId === grant.accountId && grant.clientId === config.client_id;
  const audience = token?.aud === resourceURI(config, target);
  const required = write ? 'api.write' : 'api.read';
  const scope = narrowScope ? token?.scope?.split(' ').includes(required) === true : token?.scope === required;
  const error = !valid || !audience || (!narrowScope && !scope)
    ? 'invalid_token' : !scope ? 'insufficient_scope' : null;
  const status = error === 'invalid_token' ? 401 : error === 'insufficient_scope' ? 403 : 200;
  const tag = req.headers['x-fixture-probe'];
  record('resource', {
    status, target, probe: ['wrong_audience', 'missing', 'invalid'].includes(tag) ? tag : null,
    token_present: !!value, token_valid: valid, audience_matches: audience, scope_matches: scope,
    current_token_used: !!value && value === state.currentAccess,
    ...(write ? { operation: 'write', error } : {}),
  });
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
    ...(error ? { 'www-authenticate': `Bearer error="${error}"` } : {}) });
  res.end(JSON.stringify(error ? { error } : { ok: true, sub: token.accountId, audience: token.aud }));
  return true;
}

export function observeResource(ctx, config, state, record) {
  if (ctx.path === '/token/introspection') record('introspection', {
    status: ctx.status, active: ctx.body?.active === true,
    client_matches: ctx.oidc.client?.clientId === config.client_id,
    audience_matches: ctx.body?.aud === resourceURI(config, config.resource_indicators.target),
    scope_matches: ctx.body?.scope === 'api.read' ||
      (config.resource_indicators.narrow_scope === true && matchesScope(ctx.body?.scope, true)),
    current_token_used: ctx.oidc.params?.token === state.currentAccess,
  });
}
