# Alias for `perform_resource_req()`

**\[deprecated\]**

Deprecated alias for
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
to avoid a breaking change in the public API. Use
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
for Bearer, DPoP, and mTLS-protected resource requests instead.

## Usage

``` r
perform_client_bearer_req(
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

Same value as
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md).
