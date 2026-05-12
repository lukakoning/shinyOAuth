# Build RFC 8705 mTLS registration metadata

Returns a JSON-ready list of client metadata for registering an
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
that uses RFC 8705 mutual TLS.

For `token_auth_style = "tls_client_auth"`, this helper returns
`token_endpoint_auth_method = "tls_client_auth"` plus exactly one RFC
8705 certificate identifier field: `tls_client_auth_subject_dn`,
`tls_client_auth_san_dns`, `tls_client_auth_san_uri`,
`tls_client_auth_san_ip`, or `tls_client_auth_san_email`.

For `token_auth_style = "self_signed_tls_client_auth"`, this helper
returns `token_endpoint_auth_method = "self_signed_tls_client_auth"`
plus either an inline `jwks` document built from the configured client
certificate and certificate chain (published via `x5c`), or a
caller-supplied `jwks_uri`.

This helper prepares metadata only. It does not make a registration HTTP
call.

## Usage

``` r
oauth_client_mtls_registration(
  oauth_client,
  tls_client_auth_type = c("subject_dn", "san_dns", "san_uri", "san_ip", "san_email"),
  tls_client_auth_value = NULL,
  jwks_uri = NULL
)
```

## Arguments

- oauth_client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  configured for `tls_client_auth` or `self_signed_tls_client_auth`.

- tls_client_auth_type:

  For `tls_client_auth`, which RFC 8705 certificate identifier field to
  emit. One of `"subject_dn"`, `"san_dns"`, `"san_uri"`, `"san_ip"`, or
  `"san_email"`.

- tls_client_auth_value:

  Optional explicit value for the selected `tls_client_auth_type`. When
  omitted, shinyOAuth derives the subject DN or, when possible, a unique
  matching SAN value from the configured client certificate. If the
  certificate exposes no unambiguous SAN for the chosen type, pass the
  exact registration value explicitly.

- jwks_uri:

  Optional absolute URL of a JWKS document to publish for
  `self_signed_tls_client_auth`. When omitted, the helper returns an
  inline `jwks` object with the configured client certificate chain in
  `x5c`.

## Value

A JSON-ready list of RFC 7591/RFC 8705 client metadata.
