# Alias for `perform_resource_req()`

**\[deprecated\]**

Deprecated alias for
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md).
Use
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
  idempotent = NULL,
  resource_hosts = NULL
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
  Inherited httr2 authentication, caching, and retry policies, and curl
  authentication options are rejected. Authenticated response caching is
  unsupported. shinyOAuth owns retries; configure them with `idempotent`
  and the `shinyOAuth.retry_*` options.

- method:

  Optional HTTP method (character). Defaults to "GET". When the
  effective token type is `DPoP`, this must be the final request method
  because the proof is signed against it. `TRACE` and the nonstandard
  `TRACK` method are rejected because authenticated requests could be
  reflected by the server and disclose credentials.

- headers:

  Optional named list or named character vector of extra headers to set
  on the request. Header names are case-insensitive. Any user-supplied
  `Authorization` or `DPoP` header is ignored to ensure the token
  authentication set by this function is not overridden.

- query:

  Optional named list of query parameters to append to the URL.

- follow_redirect:

  Logical or `NULL`. `FALSE` (the default) disables HTTP redirects even
  when `shinyOAuth.allow_redirect` is enabled. `NULL` inherits that
  global option (disabled by default). Set to `TRUE` only if you trust
  all possible redirect targets and understand the security
  implications.

- check_url:

  Logical. If `TRUE` (the default), validates `url` against
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  before attaching the access token. This rejects relative URLs, plain
  HTTP to non-loopback hosts, and when
  `options(shinyOAuth.allowed_hosts)` is set, hosts outside the
  allowlist. Without an allowlist this performs HTTPS and URL-syntax
  validation only (with the configured non-HTTPS exceptions); any HTTPS
  host is accepted. Set to `FALSE` only if you have already validated
  the URL and understand the security implications.

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

  Whether ordinary network/HTTP failures may be retried safely. `NULL`
  (default) infers this from the final HTTP method: GET, HEAD, OPTIONS,
  PUT, and DELETE permit retries. Set it explicitly if your API has
  different guarantees. One DPoP nonce challenge retry is allowed
  independently of this setting.

- resource_hosts:

  Optional non-empty character vector of trusted resource host patterns,
  using
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  matching rules. This call-scoped allowlist adds to the global policy
  and is enforced even if `check_url` is `FALSE`. Use exact hostnames
  for URLs derived from lower-trust input. It constrains the initial
  URL, not redirect destinations or resolved IPs; retain
  `follow_redirect = FALSE`. `NULL` adds no resource-specific policy.

## Value

Same value as
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md).
