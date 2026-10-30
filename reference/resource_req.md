# Prepare an API request with an access token

Build an [httr2](https://httr2.r-lib.org/reference/httr2-package.html)
request that uses the user's access token. Use this when you want to
inspect or customize a request before sending it. To build and send in
one step, use
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md).

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
  client = NULL,
  token_type = NULL,
  dpop_nonce = NULL,
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

  The absolute URL to call. Resource URLs must not exceed 8192 bytes,
  including the query and fragment, both before and after applying
  `query`. This limit also applies when `check_url = FALSE`.

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

An [httr2](https://httr2.r-lib.org/reference/httr2-package.html) request
object, accepted by
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
for bounded response handling. A DPoP proof is bound to the method and
base URL at preparation time; later changes to either invalidate it.

## Details

The package applies its URL policy, timeouts and redirect defaults. It
supports Bearer authentication and tokens tied to a key (DPoP) or
certificate (mTLS). For DPoP or mTLS, `client` supplies the matching key
or certificate.

[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
sends the prepared request with the package's response-size limits.
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html)
uses httr2's transport settings.

## Advanced request restrictions

The helper rejects additional `access_token` credentials in ordinary URL
and form inputs. File, multipart and streaming bodies, and changes made
after preparation, are outside that check.

[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
limits both downloaded bytes and decoded gzip data. Direct httr2
execution does not provide shinyOAuth's decoded-response limit; its curl
limit depends on the installed libcurl version. Prepared requests can be
sent with `perform_resource_req(token, request, client = client)`.

## DPoP note

DPoP proofs bind the current HTTP method and target URI (without query
or fragment). Literal `.` and `..` path segments are removed before
signing and sending; percent-encoded path segments remain escaped. Use
the `query` argument to preserve encoded resource paths; external URL
modifiers can decode reserved path characters. Changing the method,
scheme, host, or path invalidates the proof. Automatic redirects are
unsupported; each target URL requires its own proof.

## Examples

``` r
# Make request using OAuthToken object
# (code is not run because it requires a real token from user interaction)
if (interactive()) {
  # Inside reactive server code, after login has succeeded:
  token <- auth[["token"]]

  # Build and send in one step.
  response <- perform_resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  # Prepare a request before sending it.
  request <- resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  # Sending the prepared request applies the same response-size limits.
  response <- perform_resource_req(token, request)

  # Or start from your own httr2 request and still let shinyOAuth perform it
  # so response limits and DPoP nonce retries remain available.
  custom_request <- httr2::request("https://api.example.com/resource") |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_url_query(limit = 5)

  response <- perform_resource_req(token, custom_request)

  # resource_hosts restricts this dynamic URL to api.example.com.
  response <- perform_resource_req(
    token,
    input[["resource_url"]],
    resource_hosts = "api.example.com",
    follow_redirect = FALSE
  )
}
```
