# Build and perform an authenticated httr2 request for a protected resource

Companion to
[`resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/resource_req.md)
for callers who want shinyOAuth to both build and perform the request.
For DPoP-bound access tokens, this helper reuses shinyOAuth's existing
nonce-challenge handling and retries one `use_dpop_nonce` response with
a fresh proof that includes the supplied `DPoP-Nonce`, as described by
RFC 9449.

## Usage

``` r
perform_resource_req(
  token,
  url,
  method = "GET",
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE,
  check_url = TRUE,
  oauth_client = NULL,
  token_type = NULL,
  dpop_nonce = NULL,
  idempotent = NULL
)
```

## Arguments

- token:

  Either an
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object or a raw access token string.

- url:

  The absolute URL to call.

- method:

  Optional HTTP method (character). Defaults to "GET". When the
  effective token type is `DPoP`, this must be the final request method
  because the proof is signed against it.

- headers:

  Optional named list or named character vector of extra headers to set
  on the request. Header names are case-insensitive. Any user-supplied
  `Authorization` or `DPoP` header is ignored to ensure the token
  authentication set by this function is not overridden.

- query:

  Optional named list of query parameters to append to the URL.

- follow_redirect:

  Logical. If `FALSE` (the default), HTTP redirects are disabled to
  prevent leaking the access token to unexpected hosts. Set to `TRUE`
  only if you trust all possible redirect targets and understand the
  security implications.

- check_url:

  Logical. If `TRUE` (the default), validates `url` against
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  before attaching the access token. This rejects relative URLs, plain
  HTTP to non-loopback hosts, and when
  `options(shinyOAuth.allowed_hosts)` is set, hosts outside the
  allowlist. Set to `FALSE` only if you have already validated the URL
  and understand the security implications.

- oauth_client:

  Optional
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md).
  Required when the effective token type is `DPoP`, because the client
  carries the configured DPoP proof key, and also when using
  sender-constrained mTLS / certificate-bound tokens so shinyOAuth can
  attach the configured client certificate and validate any `cnf`
  thumbprint from an
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  and observe any `cnf` thumbprint carried on a raw JWT access-token
  string.

- token_type:

  Optional override for the access token type when `token` is supplied
  as a raw string. Supported values are `Bearer` and `DPoP`. Invalid or
  multi-valued inputs are rejected. When omitted, shinyOAuth preserves
  `OAuthToken@token_type` and also infers `DPoP` from an observed raw
  JWT access token `cnf.jkt` binding when `oauth_client` carries a DPoP
  key. This local JWT parse does not independently verify the
  access-token signature.

- dpop_nonce:

  Optional DPoP nonce to embed in the proof for this request. This is
  primarily useful after a resource server challenges with `DPoP-Nonce`.

- idempotent:

  Optional logical controlling generic transport and transient-HTTP
  retries in `req_with_retry()`. When `NULL` (the default), shinyOAuth
  infers this from the final request method using standard HTTP
  idempotency semantics (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`,
  `DELETE`). DPoP nonce challenges are replayed once regardless, as
  required by RFC 9449.

## Value

An [httr2](https://httr2.r-lib.org/reference/httr2-package.html)
response object.

## Examples

``` r
# Make request using OAuthToken object
# (code is not run because it requires a real token from user interaction)
if (interactive()) {
  # Get an OAuthToken
  # (typically provided as reactive return value by `oauth_module_server()`)
  token <- OAuthToken()

  # Recommended for most callers: build + perform in one step.
  response <- perform_resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  # Advanced callers can still build first and perform later.
  request <- resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  response <- httr2::req_perform(request)
}
```
