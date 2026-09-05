# OAuthToken S7 class

An `OAuthToken` holds credentials and user information returned after
login. The Shiny module supplies it as `auth$token`, and
[`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
returns it for custom integrations. Pass it to
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
to call an API, or to the token helpers for refresh, introspection, and
revocation.

Read properties with `@`, for example `auth$token@userinfo`. Profile
fields depend on the provider. Keep access and refresh tokens out of the
UI and logs.

## Usage

``` r
OAuthToken(
  access_token = character(0),
  token_type = NA_character_,
  refresh_token = NA_character_,
  id_token = NA_character_,
  expires_at = Inf,
  userinfo = list(),
  cnf = list(),
  granted_scopes = character(0),
  granted_scopes_verified = FALSE,
  id_token_validated = FALSE
)
```

## Arguments

- access_token:

  Access token

- token_type:

  OAuth access token type (for example `Bearer` or `DPoP`)

- refresh_token:

  Refresh token (if provided by the provider)

- id_token:

  ID token (if provided by the provider; OpenID Connect)

- expires_at:

  Numeric timestamp (seconds since epoch) when the access token expires,
  `NA_real_` when the expiry is unknown, or `Inf` for a non-expiring
  token

- userinfo:

  List containing user information fetched from the provider's userinfo
  endpoint (if fetched)

- cnf:

  Optional confirmation claim set returned alongside a
  sender-constrained access token or observed on another token surface.
  For RFC 8705 certificate-bound tokens, this may contain `x5t#S256`
  with the SHA-256 thumbprint of the client certificate that must
  accompany later requests. For DPoP-bound tokens, this may contain
  `jkt` with the RFC 7638 thumbprint of the public JWK bound to the
  token. When `cnf` is learned by locally parsing a raw JWT access
  token, shinyOAuth is observing the token payload and is not
  independently verifying the access-token signature; introspection or
  another provider proof surface is stronger assurance.

- granted_scopes:

  Normalized scope tokens currently associated with the access token.
  When a provider omits `scope` in a token response, shinyOAuth carries
  forward the best-known scope set instead of dropping it.

- granted_scopes_verified:

  Logical flag indicating whether the current token response explicitly
  proved `granted_scopes`. `FALSE` means the scope set was assumed or
  carried forward because the provider omitted `scope`. For stronger
  proof, configure `introspect_elements = "scope"`.

- id_token_validated:

  Logical flag indicating whether the ID token was cryptographically
  validated (signature verified and standard claims checked) during the
  OAuth flow. Defaults to `FALSE`.

## Details

The `id_token_claims` property is a read-only computed property that
returns the decoded JWT payload of the ID token as a named list. This
surfaces all standard and optional OIDC claims (e.g., `sub`, `iss`,
`aud`, `acr`, `amr`, `auth_time`, `nonce`, `at_hash`, etc.) without
requiring manual JWT decoding. Returns an empty list when no ID token is
present or if the token cannot be decoded.

Note: `id_token_claims` always decodes the JWT payload regardless of
whether the ID token's signature was verified. Check the
`id_token_validated` property to determine whether the claims were
cryptographically validated.

## Examples

``` r
# Inside reactive server code, after a successful login:
# auth$token@userinfo
# auth$token@expires_at
# auth$token@id_token_validated
# auth$token@id_token_claims$sub
```
