# Prepare client-certificate registration settings (mTLS)

Build a list of settings to register a certificate-based client with
your provider using mutual TLS (mTLS). Use this when preparing metadata
for dynamic client registration or when your provider asks for
certificate identifiers, public keys, or certificate-bound token
settings. It derives those settings from an
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
already configured for mTLS.

The result is a metadata list, ready to include in a registration
request. Submit it through your provider's registration process; this
function does not register the client or upload the certificate.

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
  configured for RFC 8705 mutual TLS client authentication or for
  certificate-bound access tokens.

- tls_client_auth_type:

  For `tls_client_auth`, which RFC 8705 certificate identifier field to
  emit. One of `"subject_dn"`, `"san_dns"`, `"san_uri"`, `"san_ip"`, or
  `"san_email"`.

- tls_client_auth_value:

  Optional explicit value for the selected `tls_client_auth_type`. When
  omitted, shinyOAuth derives the subject DN or, when possible, a unique
  matching SAN value from the configured client certificate.
  Auto-derived IP SAN values are normalized to dotted-decimal IPv4 or
  RFC 5952 IPv6 text. If the certificate exposes no unambiguous SAN for
  the chosen type, pass the exact registration value explicitly.

- jwks_uri:

  Optional absolute URL of a JWKS document to publish for
  `self_signed_tls_client_auth`. When omitted, the helper returns an
  inline `jwks` object with the configured client certificate chain in
  `x5c`.

## Value

A JSON-ready list of RFC 7591/RFC 8705 client metadata.

## Details

For `tls_client_auth`, the result identifies the client certificate
using one selected subject or alternative-name field. For
`self_signed_tls_client_auth`, it contains an inline `jwks` with the
certificate chain (`x5c`), or the supplied `jwks_uri`.

For certificate-bound tokens without mTLS client authentication, the
result uses the corresponding registration authentication method (for
example, `public` becomes `none`) and sets
`tls_client_certificate_bound_access_tokens = TRUE`. See the [advanced
security
vignette](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.html)
for when these configurations are useful.
