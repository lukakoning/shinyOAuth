# Discover SMART on FHIR server metadata

Read and validate the SMART App Launch STU 2.2 discovery document for a
configured FHIR server. This returns server metadata for application
setup; it does not register an app, choose client credentials, or start
authorization.

## Usage

``` r
smart_discover(fhir_base, endpoint_hosts = NULL, allow_http_loopback = FALSE)
```

## Arguments

- fhir_base:

  Trusted FHIR base URL, including its complete path, for example
  `"https://ehr.example/fhir/R4"`.

- endpoint_hosts:

  Character vector of exact permitted hostnames for recognized metadata
  URLs. `NULL` defaults to the FHIR base hostname. An explicit vector
  replaces that default; include every permitted host. Hostnames are
  case-insensitive. Wildcards, URLs, and ports are not accepted.

- allow_http_loopback:

  Logical, default `FALSE`. Explicit development exception permitting
  HTTP only at `localhost`, `127.0.0.1`, or `::1`. This applies to the
  base and metadata URLs and does not change global options. It does not
  establish production TLS interoperability.

## Value

A plain named list with `fhir_base` (the supplied identifier),
`discovery_url` (the requested URL), `smart_version` (`"2.2.0"`, the
validation baseline, not a detected server version), `metadata` (the
parsed document, with JSON arrays as lists), `endpoint_hosts` (the
normalized policy), and `allow_http_loopback`. No client, token, or live
cache is stored in the result. Invalid input or endpoint policy raises a
`shinyOAuth_config_error`; malformed metadata raises a
`shinyOAuth_parse_error`; failed HTTP requests raise a
`shinyOAuth_http_error`.

## Details

Call once during application setup, outside `server()`. The request
appends `/.well-known/smart-configuration` to the full FHIR base,
removing its terminal slash first. The supplied base and returned
endpoint/issuer strings are retained exactly, so discovery does not
change protocol identifiers.

This is separate from
[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md).
OAuth-only SMART metadata need not contain OIDC issuer or signing-key
information. Advertised `sso-openid-connect` requires both `issuer` and
`jwks_uri`; their presence does not validate an identity or fetch OIDC
metadata or keys.

Required SMART fields, conditional launch/SSO fields, and advertised
asymmetric-authentication metadata are checked. S256 must be advertised
and plain PKCE is rejected. Client-specific capability, scope, key and
algorithm selection belongs to the application's registration
configuration. `scopes_supported` is informative, not an exhaustive
permission allowlist. Its array may be empty. An empty
`token_endpoint_auth_methods_supported` array permits public
registrations; confidential registrations still require their selected
method whenever that array is present.

## Network and trust policy

Supply a trusted, deployment-configured base, never an arbitrary browser
query parameter. The base must be an absolute HTTPS URL without
userinfo, query, fragment, or ambiguous path syntax. Discovered URLs
must be absolute; this reader does not repair relative URLs from legacy
servers.

`endpoint_hosts` applies to the issuer and these top-level URL fields
when present: `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
`registration_endpoint`, `management_endpoint`,
`introspection_endpoint`, `revocation_endpoint`, `userinfo_endpoint`,
`pushed_authorization_request_endpoint`, `smart_app_state_endpoint`, and
`user_access_brand_bundle`. Matching uses exact hostnames, independently
of port. This is a discovery policy; it does not authorize resource
requests. The generic `shinyOAuth.allowed_hosts` option can further
restrict these URLs.

The request carries no OAuth credentials. Redirects are refused even
when the generic redirect option is enabled. Existing package TLS,
timeout, response-size, and retry protections apply. JSON must be an
object with no duplicate members; arrays and recognized URL fields have
bounded validation. Errors do not include response bodies or returned
metadata values.

Unknown extensions, including `associated_endpoints`, are retained as
data only. Their URLs are not fetched or approved for credential use. No
automatic metadata cache is used: every call reads a new snapshot.
Applications should review metadata changes before replacing
configuration; do not rediscover endpoints during a pending
authorization or to reinterpret a retained grant.

## References

[SMART STU 2.2
discovery](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html)
and [asymmetric client
metadata](https://hl7.org/fhir/smart-app-launch/STU2.2/client-confidential-asymmetric.html).

## See also

[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md),
[`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md)

## Examples

``` r
if (FALSE) { # \dontrun{
site <- smart_discover(
  "https://ehr.example/fhir/R4",
  endpoint_hosts = c("ehr.example", "login.example")
)
site$metadata$token_endpoint
site$metadata$capabilities

} # }
```
