# Check if URL(s) are HTTPS and/or in allowed hosts lists

Returns TRUE if every input URL is either:

- a syntactically valid HTTPS URL, and (if set) whose host matches
  `allowed_hosts`, or

- an HTTP URL whose host matches `allowed_non_https_hosts` (e.g.
  localhost, 127.0.0.1, ::1), and (if set) also matches `allowed_hosts`.

If the input omits the scheme (e.g., "localhost:8080/cb"), this function
will first attempt to validate it as HTTP (useful for loopback
development), and if that fails, as HTTPS. This mirrors how helpers
normalize inputs for convenience while still enforcing the same host and
scheme policies.

`allowed_hosts` is thus an allowlist of hosts/domains that are
permitted, while `allowed_non_https_hosts` defines which hosts are
allowed to use HTTP instead of HTTPS. If `allowed_hosts` is NULL or
length 0, all hosts are allowed (subject to scheme rules), but HTTPS is
still required unless the host is in `allowed_non_https_hosts`.

Since `allowed_hosts` supports globs, a value like "\*" matches any host
and therefore effectively disables endpoint host restrictions. Only use
a catch‑all pattern when you truly intend to allow any host. In most
deployments you should pin to your expected domain(s), e.g.
`c(".example.com")` or a specific host name.

Wildcards: `allowed_hosts` and `allowed_non_https_hosts` support globs:
`*` = any chars, `?` = one char. A leading `.example.com` matches the
domain itself and any subdomain.

Any non-URLs, NAs, or empty strings cause a FALSE result.

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

This function is used internally to validate redirect URIs in OAuth
clients, but can be used elsewhere to test if URLs would be allowed.
Internally, it will always determine the default values for
`allowed_non_https_hosts` and `allowed_hosts` from the options
`shinyOAuth.allowed_non_https_hosts` and `shinyOAuth.allowed_hosts`,
respectively.

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
