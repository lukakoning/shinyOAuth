# Introspect an OAuth 2.0 token

Introspects an access or refresh token using RFC 7662 when the provider
exposes an introspection endpoint. Returns a list including at least
`supported` (logical) and `active` (logical\|NA) and the parsed response
(if any) under `raw`.

Authentication to the introspection endpoint mirrors the provider's
`token_auth_style`:

- "header" (default): HTTP Basic with `client_id`/`client_secret`.

- "body": form fields `client_id` and (when available) `client_secret`.

- "client_secret_jwt" / "private_key_jwt": a signed JWT client assertion
  is generated (RFC 7523) and sent via `client_assertion_type` and
  `client_assertion`, with `aud` set to the provider's
  `introspection_url`.

## Usage

``` r
introspect_token(
  oauth_client,
  oauth_token,
  which = c("access", "refresh"),
  async = FALSE
)
```

## Arguments

- oauth_client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object

- oauth_token:

  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object to introspect

- which:

  Which token to introspect: "access" (default) or "refresh".

- async:

  Logical, default FALSE. If TRUE and promises is available, run in
  background and return a promise resolving to the result list

## Value

A list with fields: supported, active, raw, status

## Details

Best-effort semantics:

- If the provider does not expose an introspection endpoint, the
  function returns `supported = FALSE`, `active = NA`, and
  `status = "introspection_unsupported"`.

- If the endpoint responds with an HTTP error (e.g., 404/500) or the
  body cannot be parsed or does not include a usable `active` field, the
  function does not throw. It returns `supported = TRUE`, `active = NA`,
  and a descriptive `status` (for example, `"http_404"`,
  `"invalid_json"`, `"missing_active"`). In this context, `NA` means
  "unknown" and will not break flows unless your code explicitly
  requires a definitive result (i.e., `isTRUE(result$active)`).

- Providers vary in how they encode the RFC 7662 `active` field
  (logical, numeric, or character variants like "true"/"false", 1/0).
  These are normalized to logical `TRUE`/`FALSE` when possible;
  otherwise `active` is set to `NA`.

## Examples

``` r
# Please note: `get_userinfo()`, `introspect_token()`, and `refresh_token()`
# are typically not called by users of this package directly, but are called
# internally by `oauth_module_server()`. These functions are exported
# nonetheless for advanced use cases. Most users will not need to
# call these functions directly

# Example requires a real token from a completed OAuth flow
# (code is therefore not run; would error with placeholder values below)
if (FALSE) { # \dontrun{
# Define client
client <- oauth_client(
  provider = oauth_provider_github(),
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100"
)

# Have a valid OAuthToken object; fake example below
# (typically provided by `oauth_module_server()` or `handle_callback()`)
token <- handle_callback(client, "<code>", "<payload>", "<browser_token>")

# Get userinfo
user_info <- get_userinfo(client, token)

# Introspect token (if supported by provider)
introspection <- introspect_token(client, token)

# Refresh token
new_token <- refresh_token(client, token, introspect = TRUE)
} # }
```
