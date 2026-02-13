# Build an authorized httr2 request with Bearer token

Convenience helper to reduce boilerplate when calling downstream APIs.
It creates an
[`httr2::request()`](https://httr2.r-lib.org/reference/request.html) for
the given URL, attaches the `Authorization: Bearer <token>` header, and
applies the package's standard HTTP defaults (timeout and User-Agent).

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
  check_url = TRUE
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
  `Authorization` header is ignored to ensure the Bearer token set by
  this function is not overridden.

- query:

  Optional named list of query parameters to append to the URL.

- follow_redirect:

  Logical. If `FALSE` (the default), HTTP redirects are disabled to
  prevent leaking the Bearer token to unexpected hosts. Set to `TRUE`
  only if you trust all possible redirect targets and understand the
  security implications.

- check_url:

  Logical. If `TRUE` (the default), validates `url` against
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  before attaching the Bearer token. This rejects relative URLs, plain
  HTTP to non-loopback hosts, and – when
  `options(shinyOAuth.allowed_hosts)` is set – hosts outside the
  allowlist. Set to `FALSE` only if you have already validated the URL
  and understand the security implications.

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
  query = list(limit = 5)
)

# Perform request
response <- httr2::req_perform(request)
} # }
```
