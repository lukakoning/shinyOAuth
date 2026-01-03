# Revoke an OAuth 2.0 token

Attempts to revoke an access or refresh token using RFC 7009 when the
provider exposes a revocation endpoint.

Authentication mirrors the provider's `token_auth_style` (same as token
exchange and introspection).

Best-effort semantics:

- If the provider does not expose a revocation endpoint, returns
  `supported = FALSE`, `revoked = NA`, and
  `status = "revocation_unsupported"`.

- If the selected token value is missing, returns `supported = TRUE`,
  `revoked = NA`, and `status = "missing_token"`.

- If the endpoint returns a 2xx, returns `supported = TRUE`,
  `revoked = TRUE`, and `status = "ok"`.

- If the endpoint returns an HTTP error, returns `supported = TRUE`,
  `revoked = NA`, and `status = "http_<code>"`.

## Usage

``` r
revoke_token(
  oauth_client,
  oauth_token,
  which = c("refresh", "access"),
  async = FALSE,
  shiny_session = NULL
)
```

## Arguments

- oauth_client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object

- oauth_token:

  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object containing tokens to revoke

- which:

  Which token to revoke: "refresh" (default) or "access"

- async:

  Logical, default FALSE. If TRUE and promises is available, run in
  background and return a promise resolving to the result list

- shiny_session:

  Optional pre-captured Shiny session context (from
  `capture_shiny_session_context()`) to include in audit events. Used
  when calling from async workers that lack access to the reactive
  domain.

## Value

A list with fields: supported, revoked, status
