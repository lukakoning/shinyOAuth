# Build and perform an authenticated httr2 request for a protected resource

This is a helper for calling downstream APIs with an access token. It
creates an
[`httr2::request()`](https://httr2.r-lib.org/reference/request.html) for
the given URL, attaches the right authorization header for the token
type, applies shinyOAuth's standard HTTP defaults, and performs the
request. You can also provide a prebuilt
[`httr2::request()`](https://httr2.r-lib.org/reference/request.html)
object as the `url` argument, in which case this helper will layer token
authentication and any explicit overrides on top of the provided request
before performing it.

Use
[`resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/resource_req.md)
if you want to only build the request (and perform it later).

Compared to
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html),
this helper adds shinyOAuth-specific handling for DPoP-bound tokens,
including retrying once with a fresh proof when a `DPoP-Nonce` challenge
is encountered. For non-DPoP tokens, this helper behaves similarly to
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html)
but with the package's standard defaults for retries and redirects.

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

  Either the absolute URL to call or an
  [`httr2::request()`](https://httr2.r-lib.org/reference/request.html)
  object to authorize and perform. When you pass a request object,
  shinyOAuth uses it as the base request, still applies token
  authentication and request defaults, and then layers any explicit
  `method`, `headers`, `query`, and `follow_redirect` overrides on top.

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
  `OAuthToken@token_type`, and may infer `DPoP` from explicit
  `OAuthToken@cnf$jkt` metadata. Raw access-token strings default to
  `Bearer` unless you pass `token_type = "DPoP"` explicitly.

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

  # Build only when you need to inspect the request yourself.
  request <- resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  httr2::req_dry_run(request)

  # Or start from your own httr2 request and still let shinyOAuth perform it
  # so DPoP nonce retries remain available.
  custom_request <- httr2::request("https://api.example.com/resource") |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_url_query(limit = 5)

  response <- perform_resource_req(token, custom_request)
}
```
