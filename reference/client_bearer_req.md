# Build an authorized httr2 request with an OAuth access token

Convenience helper to reduce boilerplate when calling downstream APIs.
It creates an
[`httr2::request()`](https://httr2.r-lib.org/reference/request.html) for
the given URL, attaches the appropriate `Authorization` header for the
supplied token type, and applies the package's standard HTTP defaults
(timeout and User-Agent).

Accepts either a raw access token string or an
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
object.

## Usage

``` r
client_bearer_req(
  token,
  url,
  method = "GET",
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE,
  check_url = TRUE,
  allowed_hosts = NULL,
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

  Optional HTTP method (character). Defaults to "GET".

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

  Logical. If `TRUE` (the default), validates `url` against an explicit
  protected-resource host policy before attaching the access token. The
  policy comes from `allowed_hosts`, `oauth_client@resource`, or
  `options(shinyOAuth.allowed_hosts)`. This rejects relative URLs, plain
  HTTP to non-loopback hosts, and hosts outside the resolved allowlist.
  Set to `FALSE` only if you have already validated the URL and
  understand the security implications.

- allowed_hosts:

  Optional character vector of allowed protected-resource hosts/domains
  for this request. Supports the same glob semantics as
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md).
  When omitted, shinyOAuth derives HTTP(S) hosts from
  `oauth_client@resource` if possible, then falls back to
  `options(shinyOAuth.allowed_hosts)`.

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
  as a raw string. Supported values are `Bearer` and `DPoP`.

- dpop_nonce:

  Optional DPoP nonce to embed in the proof for this request. This is
  primarily useful after a resource server challenges with `DPoP-Nonce`.

## Value

An httr2 request object, ready to be further customized or performed
with
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html).

## Examples

``` r
# Make request using OAuthToken object
# (code is not run because it requires a real token from user interaction)
if (FALSE) { # \dontrun{
# Get an OAuthToken
# (typically provided as reactive return value by `oauth_module_server()`)
token <- OAuthToken()

# Build request
request <- client_bearer_req(
  token, 
  "https://api.example.com/resource", 
  query = list(limit = 5),
  allowed_hosts = "api.example.com"
)

# Perform request
response <- httr2::req_perform(request)
} # }
```
