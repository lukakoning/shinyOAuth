# Assess an OAuth configuration against a pinned OAuth 2.1 draft

This function inspects a configured
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
and its
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
for compliance with the OAuth 2.1 draft 16 (ruleset `1.1.0`)
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
`remediation`, `reference`, `evidence_source`, `requirement_source`, and
logical `affects_verdict` columns. Only rows with
`affects_verdict = TRUE` enter aggregation; unknown external obligations
remain visible separately.

## Details

Ruleset `1.1.0` covers code/refresh, enabled PAR, required UserInfo and
introspection, and the additional operations selected in `context`.
Signing and encryption key retrieval is included when applicable. Future
resource URLs, arbitrary request customization, browser/proxy TLS,
registered redirect matching, secret custody, and authorization/resource
server behavior require separate evidence. Optional DPoP, mTLS, PAR, JAR
and JARM are not required as a bundle.

`configuration_compliant` is `FALSE` if an applicable mandatory
configuration check fails; otherwise `NA` if a mandatory configuration
check is unresolved; otherwise `TRUE` when a nonempty set of applicable
mandatory checks passes. Recommendations and external unknowns do not
change that verdict. In particular, the legacy assertion type `JWT` is a
recommendation finding; the assertion audience is a separate mandatory
check for JWT authentication. `requirement_source` distinguishes OAuth
core, OIDC, extension specifications, security guidance and local
package/application policy. Callback capacity thresholds are package
recommendations, not draft-defined numeric minima; complete encoded
requests still need deployment testing. OAuth 2.1 assessment is opt-in
and does not change existing OAuth 2.0 configuration or requests.

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
#>                                   id         scope         status requirement
#> 5       client_auth.asymmetric.token configuration not_applicable      SHOULD
#> 6                 jwt_audience.token configuration not_applicable        MUST
#> 7                      jwt_typ.token configuration not_applicable      SHOULD
#> 8                        tls.minimum configuration        unknown        MUST
#> 10                   tls.connections      external        unknown        MUST
#> 13               identity.validation configuration not_applicable        MUST
#> 14                    identity.nonce configuration not_applicable        MUST
#> 19 issuer.identification_recommended configuration not_applicable      SHOULD
#> 20         redirect.loopback_literal configuration not_applicable      SHOULD
#> 21              issuer.participation configuration not_applicable        MUST
#> 24             redirect.registration      external        unknown        MUST
#> 25                  state.deployment      external        unknown        MUST
#> 26             client.secret_custody      external        unknown        MUST
#> 27                      issuer.trust      external        unknown        MUST
#> 29          resource.future_requests       request        unknown        MUST
#> 31         refresh.server_protection      external        unknown        MUST
#> 32    refresh.scope_resource_binding      external        unknown        MUST
#> 33  refresh.public_client_protection      external        unknown        MUST
#> 35         tokens.application_policy      external        unknown        info
#> 36 tokens.resource_server_validation      external        unknown        MUST
#> 37         tokens.early_invalidation      external        unknown        MUST
#> 39      callback.deployment_capacity      external        unknown      SHOULD
#> 42                   server.protocol      external        unknown        MUST
#>                                                                                                                                                               message
#> 5                                                    Asymmetric client authentication is recommended where supported; secret-based authentication remains compatible.
#> 6                                                                           JWT client authentication requires the sole audience to equal the trusted issuer exactly.
#> 7                                                                      Explicit client-authentication+jwt typing is recommended; legacy JWT typing remains supported.
#> 8                                                         A configured minimum of TLS 1.2 or later, or a known suitable libcurl default, is required by this ruleset.
#> 10                                                                            Negotiated connections, browser/proxy hops and trust-root deployment were not observed.
#> 13                                                                         Applicable OIDC identity use requires ID token validation without active signature bypass.
#> 14                                                                                      Configured nonce use is checked against the transaction's validated ID token.
#> 19                                           Issuer identification is preferred for multi-server clients; distinct registered callback routes remain a valid defense.
#> 20                                                                   Loopback deployments should prefer an IP literal; existing localhost callbacks remain supported.
#> 21                               RFC 9207 participation compares a present issuer and requires it when support is advertised; validated JARM supplies its own issuer.
#> 24                                                                  Exact registered redirect matching and actual callback/proxy routing require deployment evidence.
#> 25                                                           Shared-store atomicity, session isolation and coordination across processes require deployment evidence.
#> 26                                                                         Configured credentials do not establish that a deployed client can keep them confidential.
#> 27                                                      Issuer/endpoint provenance and the declared authorization-server topology were not independently established.
#> 29                                                          Future resource URLs, opaque bodies and request mutations after construction are outside this assessment.
#> 31                                                                                The authorization server must maintain refresh-token binding to the issuing client.
#> 32                                                                                   Issued refresh tokens must remain bound to consented scope and resource servers.
#> 33 Refresh tokens issued to public clients require server-enforced rotation or sender constraints; configuring a local key or certificate does not prove enforcement.
#> 35                                                                     The application's required scopes and authorization decisions depend on its own access policy.
#> 36                                                                   Resource servers must validate token validity, scope and permission for each protected resource.
#> 37                              Clients must account for access tokens becoming invalid before their reported expiry; application recovery behavior was not observed.
#> 39                                                                       Encoded callbacks, JARM envelopes and proxy/browser limits require interoperability testing.
#> 42                                Authorization-server PKCE enforcement, one-time codes, client registration and optional extension interoperability were not tested.
#>                                                                                                                    remediation
#> 5                 Consider private_key_jwt or mTLS for this endpoint, subject to provider registration and deployment support.
#> 6                                Set client_assertion_audience to the trusted issuer, including applicable endpoint overrides.
#> 7                                      Select client_assertion_typ = 'client-authentication+jwt' when supported by the server.
#> 8                                              Select shinyOAuth.tls_min_version = '1.2' or '1.3' on a supporting TLS backend.
#> 10                                                                                       Obtain deployment or server evidence.
#> 13                                           Require and validate ID tokens for OIDC identity; disable shinyOAuth.skip_id_sig.
#> 14                                                                              Retain nonce and ID token validation together.
#> 19         Prefer RFC 9207 issuer identification or JARM when supported; document legacy-provider reasons for distinct routes.
#> 20                                   Register and use a matching 127.0.0.1 or [::1] callback where the deployment supports it.
#> 21 Require callback issuer presence for advertised RFC 9207 participation, or explicitly configure the applicable alternative.
#> 24                                                                                       Obtain deployment or server evidence.
#> 25                                                                                       Obtain deployment or server evidence.
#> 26                                                                                       Obtain deployment or server evidence.
#> 27                                                                                       Obtain deployment or server evidence.
#> 29                                                  Review the final request and use HTTPS without competing token transports.
#> 31                                                                                       Obtain deployment or server evidence.
#> 32                                                                                       Obtain deployment or server evidence.
#> 33         Obtain server evidence for refresh tokens issued to public clients, or establish that no refresh tokens are issued.
#> 35                            Define application-specific access rules and inspect granted scopes where those rules need them.
#> 36                                                                                       Obtain deployment or server evidence.
#> 37                                                                                       Obtain deployment or server evidence.
#> 39                                                                                       Obtain deployment or server evidence.
#> 42                                                                                       Obtain deployment or server evidence.
#>                                                                         reference
#> 5                         https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5
#> 6  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4
#> 7  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4
#> 8                       https://www.rfc-editor.org/rfc/rfc9325.html#section-3.1.1
#> 10     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-1.5
#> 13        https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
#> 14 https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.1.1
#> 19  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.15.2
#> 20   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-8.4.2
#> 21                        https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4
#> 24   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-2.3.1
#> 25   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-2.3.3
#> 26     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-2.1
#> 27   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-2.3.4
#> 29     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-5.1
#> 31     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.3
#> 32   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-3.2.3
#> 33   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.3.1
#> 35   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-1.4.1
#> 36     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-5.2
#> 37   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-3.2.3
#> 39   https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-1.7.1
#> 42     https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5
#>                       evidence_source        requirement_source affects_verdict
#> 5                       configuration        oauth_security_bcp           FALSE
#> 6                       configuration jwt_client_authentication            TRUE
#> 7                       configuration jwt_client_authentication           FALSE
#> 8                     runtime_default          tls_security_bcp            TRUE
#> 10                       not_observed                   oauth21           FALSE
#> 13                      configuration                      oidc            TRUE
#> 14 configuration_and_package_contract                   oauth21            TRUE
#> 19                      configuration                   oauth21           FALSE
#> 20                      configuration                   oauth21           FALSE
#> 21                      configuration     issuer_identification            TRUE
#> 24                       not_observed                   oauth21           FALSE
#> 25                       not_observed                   oauth21           FALSE
#> 26                       not_observed                   oauth21           FALSE
#> 27                       not_observed                   oauth21           FALSE
#> 29                       not_supplied                   oauth21           FALSE
#> 31                       not_observed                   oauth21           FALSE
#> 32                       not_observed                   oauth21           FALSE
#> 33                       not_observed                   oauth21           FALSE
#> 35                       not_observed        application_policy           FALSE
#> 36                       not_observed                   oauth21           FALSE
#> 37                       not_observed                   oauth21           FALSE
#> 39                       not_observed                   oauth21           FALSE
#> 42                       not_observed                   oauth21           FALSE
```
