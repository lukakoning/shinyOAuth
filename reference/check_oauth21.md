# Assess an OAuth configuration against a pinned OAuth 2.1 draft

This function inspects a configured
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
and its
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
for compliance with the OAuth 2.1 draft 16 (ruleset `1.0.0`)
specification. It reports configuration gaps, unresolved external
prerequisites, and recommendations without changing the configuration or
making requests.

## Usage

``` r
check_oauth21(client, draft = "draft-ietf-oauth-v2-1-16", context = list())
```

## Arguments

- client:

  An
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  or
  [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md).
  Provider-only assessments are partial and cannot establish missing
  client settings.

- draft:

  Implemented target revision. Currently only
  `"draft-ietf-oauth-v2-1-16"` is supported (an Internet-Draft, not an
  RFC).

- context:

  Optional named list with `operations`, a character vector selecting
  additional `"userinfo"`, `"introspection"` or `"revocation"`
  operations, and `nonce_exception`, a scalar logical declaration.
  Setting `nonce_exception = TRUE` declares that the authorization
  server has the assurance required by draft section 7.5.1.1 for this
  confidential deployment and specific request's correct OIDC nonce use.
  It does not supply observed evidence or excuse missing local
  prerequisites. Prefer S256 PKCE.

## Value

A `shinyOAuth_oauth21_assessment` list with `configuration_compliant`,
`checks`, `draft`, `ruleset_version`, `package_version`, `assessed_at`,
`assessment_scope`, and `operations`. `checks` is a data frame with
stable `id`, `scope`, `status` (`pass`, `fail`, `unknown`,
`not_applicable`), `requirement` (`MUST`, `SHOULD`, `info`), `message`,
`remediation`, `reference`, `evidence_source`, and logical
`affects_verdict` columns. Only rows with `affects_verdict = TRUE` enter
aggregation; unknown external obligations remain visible separately.

## Details

Ruleset `1.0.0` covers code/refresh, enabled PAR, required UserInfo and
introspection, and the additional operations selected in `context`.
Signing key retrieval is included when applicable. Future resource URLs,
arbitrary request customization, browser/proxy TLS, registered redirect
matching, secret custody, and authorization/resource server behavior
require separate evidence. Optional DPoP, mTLS, PAR, JAR and JARM are
not required as a bundle.

`configuration_compliant` is `FALSE` if an applicable mandatory
configuration check fails; otherwise `NA` if a mandatory configuration
check is unresolved; otherwise `TRUE` when a nonempty set of applicable
mandatory checks passes. Recommendations and external unknowns do not
change that verdict. In particular, the legacy assertion type `JWT` is a
recommendation finding; the assertion audience is a separate mandatory
check for JWT authentication.

A positive verdict applies only to the recorded scope and ruleset, with
the current configuration, options, runtime and declared context. It is
not certification or a test of a live deployment. Rerun after policy
changes. Reports contain no client/provider objects, credentials, keys
or endpoint URLs. No caches or state stores are read or changed; their
method contracts are inspected without invoking them.

## References

<https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16>

<https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11>

<https://www.rfc-editor.org/rfc/rfc9207.html>

## Examples

``` r
provider <- oauth_provider(
  name = "Example",
  auth_url = "https://auth.example/authorize",
  token_url = "https://auth.example/token",
  token_auth_style = "public", use_pkce = TRUE, pkce_method = "S256"
)
client <- oauth_client(
  provider, client_id = "example-client",
  redirect_uri = "https://app.example/callback"
)
assessment <- check_oauth21(client)
assessment$checks[assessment$checks$status != "pass", ]
#>                              id         scope         status requirement
#> 5            jwt_audience.token configuration not_applicable        MUST
#> 6                 jwt_typ.token configuration not_applicable      SHOULD
#> 7                   tls.minimum configuration        unknown        MUST
#> 9               tls.connections      external        unknown        MUST
#> 12          identity.validation configuration not_applicable        MUST
#> 13               identity.nonce configuration not_applicable        MUST
#> 18         issuer.participation configuration not_applicable        MUST
#> 21        redirect.registration      external        unknown        MUST
#> 22             state.deployment      external        unknown        MUST
#> 23        client.secret_custody      external        unknown        MUST
#> 24                 issuer.trust      external        unknown        MUST
#> 26     resource.future_requests       request        unknown        MUST
#> 28    refresh.server_protection      external        unknown        MUST
#> 30    tokens.application_policy      external        unknown        MUST
#> 32 callback.deployment_capacity      external        unknown      SHOULD
#> 35              server.protocol      external        unknown        MUST
#>                                                                                                                                                           message
#> 5                                                                       JWT client authentication requires the sole audience to equal the trusted issuer exactly.
#> 6                                                                  Explicit client-authentication+jwt typing is recommended; legacy JWT typing remains supported.
#> 7                                                     A configured minimum of TLS 1.2 or later, or a known suitable libcurl default, is required by this ruleset.
#> 9                                                                         Negotiated connections, browser/proxy hops and trust-root deployment were not observed.
#> 12                                                                     Applicable OIDC identity use requires ID token validation without active signature bypass.
#> 13                                                                                  Configured nonce use is checked against the transaction's validated ID token.
#> 18                           RFC 9207 participation compares a present issuer and requires it when support is advertised; validated JARM supplies its own issuer.
#> 21                                                              Exact registered redirect matching and actual callback/proxy routing require deployment evidence.
#> 22                                                       Shared-store atomicity, session isolation and coordination across processes require deployment evidence.
#> 23                                                                     Configured credentials do not establish that a deployed client can keep them confidential.
#> 24                                                  Issuer/endpoint provenance and the declared authorization-server topology were not independently established.
#> 26                                                      Future resource URLs, opaque bodies and request mutations after construction are outside this assessment.
#> 28 Refresh-token binding, rotation, replay detection and sender-constraint enforcement remain server obligations, even with a configured DPoP key or certificate.
#> 30                          Applications must enforce required granted scopes and account for estimated expiry; resource servers validate tokens and permissions.
#> 32                                                                   Encoded callbacks, JARM envelopes and proxy/browser limits require interoperability testing.
#> 35                            Authorization-server PKCE enforcement, one-time codes, client registration and optional extension interoperability were not tested.
#>                                                                                                                    remediation
#> 5                                Set client_assertion_audience to the trusted issuer, including applicable endpoint overrides.
#> 6                                      Select client_assertion_typ = 'client-authentication+jwt' when supported by the server.
#> 7                                              Select shinyOAuth.tls_min_version = '1.2' or '1.3' on a supporting TLS backend.
#> 9                                                                                        Obtain deployment or server evidence.
#> 12                                           Require and validate ID tokens for OIDC identity; disable shinyOAuth.skip_id_sig.
#> 13                                                                              Retain nonce and ID token validation together.
#> 18 Require callback issuer presence for advertised RFC 9207 participation, or explicitly configure the applicable alternative.
#> 21                                                                                       Obtain deployment or server evidence.
#> 22                                                                                       Obtain deployment or server evidence.
#> 23                                                                                       Obtain deployment or server evidence.
#> 24                                                                                       Obtain deployment or server evidence.
#> 26                                                  Review the final request and use HTTPS without competing token transports.
#> 28                                                                                       Obtain deployment or server evidence.
#> 30                                                                                       Obtain deployment or server evidence.
#> 32                                                                                       Obtain deployment or server evidence.
#> 35                                                                                       Obtain deployment or server evidence.
#>                                                                         reference
#> 5  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4
#> 6  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4
#> 7                       https://www.rfc-editor.org/rfc/rfc9325.html#section-3.1.1
#> 9      https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-1.5
#> 12        https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
#> 13 https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.1.1
#> 18                        https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4
#> 21   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-2.3.1
#> 22   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-2.3.3
#> 23     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-2.1
#> 24   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-2.3.4
#> 26     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-5.1
#> 28   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.3.3
#> 30     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-5.2
#> 32   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-1.7.1
#> 35     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5
#>                       evidence_source affects_verdict
#> 5                       configuration            TRUE
#> 6                       configuration           FALSE
#> 7                     runtime_default            TRUE
#> 9                        not_observed           FALSE
#> 12                      configuration            TRUE
#> 13 configuration_and_package_contract            TRUE
#> 18                      configuration            TRUE
#> 21                       not_observed           FALSE
#> 22                       not_observed           FALSE
#> 23                       not_observed           FALSE
#> 24                       not_observed           FALSE
#> 26                       not_supplied           FALSE
#> 28                       not_observed           FALSE
#> 30                       not_observed           FALSE
#> 32                       not_observed           FALSE
#> 35                       not_observed           FALSE
```
