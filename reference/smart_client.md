# Configure a SMART on FHIR app registration

Combine a reviewed
[`smart_discover()`](https://lukakoning.github.io/shinyOAuth/reference/smart_discover.md)
snapshot with an existing app registration. The result is an
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
for
[`oauth_connections()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections.md),
with the resource ID `"fhir"`. Discovery does not register the app or
grant access.

## Usage

``` r
smart_client(
  discovery,
  client_id,
  redirect_uri,
  scopes,
  required_scopes = scopes,
  token_auth_style = c("public", "header", "private_key_jwt"),
  client_secret = character(),
  client_assertion_private_key = NULL,
  client_assertion_private_key_kid = NULL,
  client_assertion_alg = "RS384",
  launch = c("standalone", "ehr"),
  identity = c("none", "openid", "fhirUser"),
  allow_v1 = FALSE,
  response_mode = NULL,
  authorization_server_mode = "single",
  authorization_server_redirect_uris = character(),
  state_store = cachem::cache_mem(max_age = 300),
  state_key = random_urlsafe(128),
  state_payload_max_age = 300,
  label = "FHIR server",
  authorization_method = "GET",
  initial_expires_in = NULL,
  online_access_policy = c("online_only", "allow_offline")
)
```

## Arguments

- discovery:

  A plain snapshot returned by
  [`smart_discover()`](https://lukakoning.github.io/shinyOAuth/reference/smart_discover.md).
  Its metadata and endpoint policy are revalidated locally; this
  performs no network calls.

- client_id, redirect_uri:

  App registration values. The callback must use HTTPS, except for the
  snapshot's explicit HTTP loopback development policy.

- scopes:

  Permissions to request, without automatic wildcard/offline access.
  Standalone patient scopes require `launch/patient`. EHR clients add
  `launch`. `online_access` requires EHR launch and `permission-online`;
  `offline_access` requires `permission-offline` in either launch mode.
  Each resource scope spelling must be advertised through
  `permission-v2` or, for v1 spellings, `permission-v1` with
  `allow_v1 = TRUE`. A SMART scope comparison supports at most 256
  distinct scopes on each side and 64 KiB (65,536 bytes) of combined
  scope text. Larger comparisons fail closed, including during token
  acceptance and refresh.

- required_scopes:

  Minimum permissions, defaulting to `scopes`. Pass a subset to accept
  reduced grants as limited connections. Identity scopes are always
  required when identity is enabled. Unsupported comparisons fail
  closed.

- token_auth_style:

  Registration type: `"public"`, `"header"` for a symmetric secret using
  HTTP Basic, or `"private_key_jwt"`. Selection must agree with
  advertised capabilities. Confidential methods must also agree with
  authentication metadata; public clients do not authenticate and need
  no `"none"` entry in that metadata. Later property edits must retain a
  supported SMART token authentication method. Asymmetric assertions
  require `typ = "JWT"`, a key ID, an explicit RS384/ES384 algorithm,
  and the token endpoint as their audience.

- client_secret:

  Secret for a symmetric registration; otherwise omit.

- client_assertion_private_key, client_assertion_private_key_kid:

  Private signing key and registered key ID for asymmetric
  authentication; see
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).
  Required for `"private_key_jwt"`.

- client_assertion_alg:

  `"RS384"` (default) or `"ES384"`; the key and server metadata must
  support the selected algorithm. Other styles omit assertions.

- launch:

  `"standalone"` or `"ehr"`, matching the registered app flow.

- identity:

  `"none"` (default), `"openid"` for a validated OIDC subject, or
  `"fhirUser"` to also require the user's FHIR reference. `"openid"`
  does not interpret a `fhirUser` claim or populate
  `smart_context()[["fhirUser"]]`. A validated `fhirUser` claim may be
  an absolute URL or a supported resource instance reference relative to
  this client's FHIR base, such as `"Practitioner/example"` or
  `"Practitioner/example/_history/2"`. Versioned references retain their
  version.

- allow_v1:

  Explicit compatibility flag enabling `.read`, `.write` and `.*`.
  Requesting these spellings requires `permission-v1`; requesting v2
  spellings requires `permission-v2`, including when this flag is
  enabled. Default `FALSE`.

- response_mode:

  `NULL`, `"query"`, or `"form_post"`. Advertised response modes, when
  present, must allow the selection.

- authorization_server_mode, authorization_server_redirect_uris:

  See
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).
  Multiple clients use distinct registered callback routes.

- state_store, state_key, state_payload_max_age:

  See
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

- label:

  Display label, default `"FHIR server"`; no credentials or context.

- authorization_method:

  `"GET"` (default) or `"POST"` for the outgoing browser request. POST
  requires the discovered `authorize-post` capability and uses the
  module's `request_login()` or
  [`prepare_authorization_request()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_authorization_request.md).
  POST supports longer browser requests but retains the scope comparison
  limits described under `scopes`.

- initial_expires_in:

  Optional positive lifetime in seconds, supplied by the authorization
  server out of band for initial access tokens. Used only when an
  initial response omits `expires_in`; an explicit response value takes
  precedence. Default `NULL` requires the response to include a
  lifetime. This does not apply to refresh responses or change ordinary
  OAuth defaults.

- online_access_policy:

  `"online_only"` (default) or `"allow_offline"`. SMART permits an
  `online_access` request to negotiate `offline_access`. Opt in to
  `"allow_offline"` to accept that longer-lived permission in place of
  required `online_access`. The default rejects this substitution, even
  when `online_access` is optional. Explicitly requesting
  `offline_access` also authorizes offline persistence. Granted scopes
  retain their actual spelling; refresh responses cannot escalate an
  existing online grant.

## Value

An
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md),
usable by the existing module or the separate connection manager.
`@resource_bases` contains the approved `fhir` base; `@required_scopes`
and `@label` use the ordinary client properties. `@smart` describes the
selected profile. The client contains registration settings, never a
user's token or launch context. Configure it outside `server()`.

## Details

This constructor selects SMART 2.2 scope rules, S256 PKCE and the exact
FHIR base as the authorization request's `aud`. Identity is opt-in:
`"openid"` requests and requires `openid`, signed ID-token validation
and nonce binding. `"fhirUser"` additionally requests and requires the
`fhirUser` scope and claim. `"none"` does not enable OIDC because an
issuer happens to be present. A patient in context is independent of the
authenticated user and local owner.

Only direct authorization requests and query/form POST callbacks are
currently supported. Claims requests (including `auth_time`), JAR, PAR,
JARM, DPoP, mTLS and remote freshness requirements need separate SMART
composition work; this constructor provides no overrides for those
features. EHR clients require a fresh registered launch transaction.
Configure standalone and EHR registrations as separate clients when both
are needed. No launch handle is stored in shared provider configuration.
Local usability policy requires a positive lifetime. An initial response
may omit `expires_in` only when `initial_expires_in` is configured
explicitly; refresh responses must include it. The generic assumed
lifetime is not used. SMART back-channel and resource requests require
TLS 1.2 or newer. A stronger configured TLS minimum is preserved;
ordinary clients keep their defaults.

## References

[SMART 2.2
launch](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html)
and [client
authentication](https://hl7.org/fhir/smart-app-launch/STU2.2/client-confidential-asymmetric.html).

## Examples

``` r
if (FALSE) { # \dontrun{
site <- smart_discover("https://ehr.example/fhir/R4")
client <- smart_client(site, "registered-app", "https://app.example/callback",
  scopes = c("launch/patient", "patient/Patient.r"),
  required_scopes = "patient/Patient.r", token_auth_style = "public")
client@smart[["launch"]]
} # }
```
