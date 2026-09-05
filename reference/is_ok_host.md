# Check a URL against the package's host policy

Test whether a URL is allowed by shinyOAuth's ordinary scheme and host
rules. HTTPS is accepted by default. HTTP is limited to local
development hosts unless you change `allowed_non_https_hosts`. Supply
`allowed_hosts` to restrict which services your app may contact.

Call this when checking configured endpoint URLs or diagnosing a
URL-policy rejection. The provider and API request helpers apply these
checks internally; a direct call lets you inspect the result without
making a network request.

## Usage

``` r
is_ok_host(
  url,
  allowed_non_https_hosts = getOption("shinyOAuth.allowed_non_https_hosts", default =
    c("localhost", "127.0.0.1", "::1", "[::1]")),
  allowed_hosts = getOption("shinyOAuth.allowed_hosts", default = NULL)
)
```

## Arguments

- url:

  Single URL or vector of URLs (character; length 1 or more)

- allowed_non_https_hosts:

  Character vector of hostnames that are allowed to use HTTP instead of
  HTTPS. Defaults to localhost equivalents. Supports globs

- allowed_hosts:

  Optional allowlist of hosts/domains; if supplied (length \> 0), only
  these hosts are permitted. Supports globs

## Value

Logical indicator (TRUE if all URLs pass all checks; FALSE otherwise)

## Details

Both host lists support `*` (any characters), `?` (one character), and a
leading dot: `".example.com"` matches the domain and its subdomains.
`"*"` permits every host. If `allowed_hosts` is empty, only the scheme
rules apply. Missing values, empty strings, and malformed URLs return
`FALSE`.

If the scheme is absent, this helper tries HTTP, then HTTPS. Request
helpers can impose additional requirements, including an absolute URL.
OIDC discovery has a separate HTTPS policy and requires an explicit
loopback development opt-in; a `TRUE` result here does not override it.

Defaults come from `shinyOAuth.allowed_hosts` and
`shinyOAuth.allowed_non_https_hosts`.

## Examples

``` r
# HTTPS allowed by default
is_ok_host("https://example.com")
#> [1] TRUE

# HTTP allowed for localhost
is_ok_host("http://localhost:8100")
#> [1] TRUE

# Restrict to a specific domain (allowlist)
is_ok_host("https://api.example.com", allowed_hosts = c(".example.com"))
#> [1] TRUE

# Caution: a catch-all pattern disables host restrictions
# (only scheme rules remain). Avoid unless you truly intend it
is_ok_host("https://anywhere.example", allowed_hosts = c("*"))
#> [1] TRUE
```
