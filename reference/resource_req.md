# Build an authenticated httr2 request for a protected resource

Small helper for calling downstream APIs with an access token. It
creates an
[`httr2::request()`](https://httr2.r-lib.org/reference/request.html) for
the given URL, attaches the right authorization header for the token
type, and applies shinyOAuth's standard HTTP defaults. Use
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
when you want shinyOAuth to also perform the request and handle DPoP
nonce challenges for you.

Accepts either a raw access token string or an
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
object.

## Usage

``` r
resource_req(
  token,
  url,
  method = "GET",
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE,
  check_url = TRUE,
  oauth_client = NULL,
  token_type = NULL,
  dpop_nonce = NULL
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
  or raw JWT access token string.

- token_type:

  Optional override for the access token type when `token` is supplied
  as a raw string. Supported values are `Bearer` and `DPoP`. Invalid or
  multi-valued inputs are rejected. When omitted, shinyOAuth preserves
  `OAuthToken@token_type` and also infers `DPoP` from a raw JWT access
  token's `cnf.jkt` binding when `oauth_client` carries a DPoP key.

- dpop_nonce:

  Optional DPoP nonce to embed in the proof for this request. This is
  primarily useful after a resource server challenges with `DPoP-Nonce`.

## Value

An httr2 request object, ready to be performed with
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html).
Callers may still add headers or query parameters, but when the
effective token type is `DPoP` they must not change the request method
or base URL after calling `resource_req()` because the proof is already
bound to those values.

## Side effects

This function does not perform network I/O. It reads shinyOAuth package
options through
[`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
and HTTP-default helpers, may emit warnings when unsafe custom auth
headers are ignored, and may read configured mTLS certificate files when
validating certificate-bound access tokens.

## DPoP note

DPoP proofs bind the current HTTP method and target URI (without query
or fragment). Adding query parameters after `resource_req()` is fine,
but changing the method, scheme, host, or path invalidates the proof.

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
