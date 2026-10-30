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
  client = NULL,
  token_type = NULL,
  dpop_nonce = NULL,
  idempotent = NULL,
  resource_hosts = NULL,
  oauth_client = NULL
)
```

## Arguments

- token:

  Either an
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object or a raw access token string.

- url:

  The absolute API URL, or a prepared
  [`httr2::request()`](https://httr2.r-lib.org/reference/request.html)
  object. The URL must be at most 8192 bytes before and after adding
  `query`. The helper adds current authentication and defaults to a
  prepared request, then applies explicit `method`, `headers`, `query`
  and redirect overrides. See Prepared requests for customization
  restrictions.

- method:

  Optional HTTP method (character). Defaults to "GET". When the
  effective token type is `DPoP`, this must be the final request method
  because the proof is signed against it. `TRACE` and the nonstandard
  `TRACK` method are rejected because authenticated requests could be
  reflected by the server and disclose credentials.

- headers:

  Optional named list or named character vector of extra headers to set
  on the request. Header names are case-insensitive. Names must be
  unique HTTP field-name tokens, and values must not contain prohibited
  control characters. DPoP requests reject `Host` overrides. This
  function manages the `Authorization` and `DPoP` headers and ignores
  user-supplied replacements.

- query:

  Optional named list of query parameters to append to the URL.

- follow_redirect:

  Logical or `NULL`. `FALSE` (the default) disables HTTP redirects even
  when `shinyOAuth.allow_redirect` is enabled. `NULL` inherits that
  global option (disabled by default). `TRUE` enables redirects. DPoP
  requests reject enabled redirects because each target needs a new
  proof.

- check_url:

  Logical. If `TRUE` (the default), validates `url` against
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  before attaching the access token. This rejects relative URLs, plain
  HTTP to non-loopback hosts, and when
  `options(shinyOAuth.allowed_hosts)` is set, hosts outside the
  allowlist. Without an allowlist this performs HTTPS and URL-syntax
  validation only (with the configured non-HTTPS exceptions); any HTTPS
  host is accepted. `FALSE` skips this policy check; URL length and
  resource-host restrictions still apply.

- client:

  Optional
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md);
  required for DPoP or mTLS-bound tokens so the request can use the
  matching signing key or certificate and check any token-binding
  information.

- token_type:

  Optional override for the access token type when `token` is supplied
  as a raw string. Supported values are `Bearer` and `DPoP`. Invalid or
  multi-valued inputs are rejected. When omitted, shinyOAuth preserves
  `OAuthToken@token_type`, and may infer `DPoP` from explicit
  `OAuthToken@cnf[["jkt"]]` metadata. Raw access-token strings default
  to `Bearer` unless you pass `token_type = "DPoP"` explicitly.

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
  and is enforced even if `check_url` is `FALSE`. It constrains the
  initial URL, not redirect destinations or resolved IPs. `NULL` adds no
  resource-specific policy.

- oauth_client:

  Compatibility alias for `client`. Supply only one spelling.

## Value

Same value as
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md).
