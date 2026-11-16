# Discover an OAuth authorization server

Fetch RFC 8414 metadata for an OAuth authorization-code provider. The
metadata location inserts `/.well-known/oauth-authorization-server`
before the issuer's path. A terminal slash is removed for that request;
the returned issuer must still match the caller's issuer exactly,
including its terminal slash.

## Usage

``` r
oauth_provider_oauth_discover(
  issuer,
  name = NULL,
  use_pkce = TRUE,
  token_auth_style = NULL,
  allowed_token_types = "Bearer",
  ...
)
```

## Arguments

- issuer:

  Exact OAuth authorization-server issuer URL, including its scheme,
  path and any terminal slash. Supply the issuer identifier rather than
  a metadata-document URL.

- name:

  Optional friendly provider name. Defaults to the issuer hostname

- use_pkce:

  Logical, whether to use PKCE for this provider. Defaults to TRUE.
  Public clients require PKCE. Setting FALSE also prevents automatic
  selection of public-client authentication; a confidential-client
  method must be available or explicitly configured instead.

- token_auth_style:

  Authentication style for token requests: "header"
  (client_secret_basic), "body" (client_secret_post), or "public"
  (public client; send `client_id` only). The alias `"none"` is also
  accepted for `"public"`. If NULL (default), it is inferred
  conservatively from discovery: `"header"` (client_secret_basic) is
  preferred, followed by `"body"` (client_secret_post), then `"public"`
  if `none` is advertised and PKCE is enabled. Set
  `token_auth_style = "public"` explicitly for a public client
  registration. JWT methods (`"client_secret_jwt"`, `"private_key_jwt"`)
  and mTLS methods (`"tls_client_auth"`,
  `"self_signed_tls_client_auth"`) must be selected explicitly. See
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  for the supported methods and their credentials.

- allowed_token_types:

  Character vector of allowed token types for access tokens issued by
  this provider. Defaults to 'Bearer'

- ...:

  Additional
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  settings. OIDC settings and relaxed issuer matching are not accepted
  by this OAuth-only helper.

## Value

An
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
configured from the authorization-server metadata.

## Details

This helper requires support for the code flow and configures OAuth-only
behavior: no automatic `openid` scope, OIDC nonce, ID-token validation
or UserInfo request. It retains the discovery transport, endpoint, host,
PKCE, client authentication, PAR, DPoP and mTLS checks. JWKS is
optional; an advertised JWKS URL still undergoes the normal URL and host
checks.

Supply an issuer identifier, rather than a metadata-document URL. This
helper does not fall back to another discovery location and does not
verify signed metadata. Use
[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md)
for OpenID Connect.

## See also

[`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md),
[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md)
