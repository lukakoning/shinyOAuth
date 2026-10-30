# Authentication flow

## Overview

shinyOAuth runs the OAuth 2.0 Authorization Code flow inside a Shiny
app. The browser visits the provider for login and consent, then returns
with an authorization code. shinyOAuth exchanges that code for tokens,
validates the response, and updates the module’s reactive authentication
state.

The provider object describes the service, the client object holds the
app’s registration and policy, and
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
manages each Shiny session. The UI wrapper handles the HTTP callback and
browser setup. With OpenID Connect (OIDC), the flow also validates
identity through a signed ID token. OAuth-only providers such as GitHub
and Spotify supply profile information through their own APIs.

The [usage
vignette](https://lukakoning.github.io/shinyOAuth/articles/usage.md)
contains the application setup. The sequence below describes the work
performed by the package after that setup.

## Starting login and binding it to the browser

With `auto_redirect = TRUE`, the module starts login for an
unauthenticated session. With `auto_redirect = FALSE`,
`auth[["request_login"]]()` initiates the same flow. Both paths wait for
browser setup before preparing the request.

For each login transaction, the module establishes a fresh random
browser binding. The browser holds the binding token in origin- and
tab-scoped session storage, with a separate temporary cookie marker. On
return, the module checks this binding against the pending transaction.
This connects the callback to the browser tab that started it, rather
than accepting state from any browser presenting the same callback URL.

The binding is separate from provider-issued access and ID tokens.
Browser storage and cookie setup happen through the UI dependency;
unavailable browser facilities produce a browser-setup error before
login proceeds.

## Preparing the authorization request

The authorization builder, also exposed through
[`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)
and
[`prepare_authorization_request()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_authorization_request.md),
combines the provider’s authorization endpoint with the client’s ID,
redirect URI, scopes and configured request parameters. The module
prepares the transaction values used during later validation:

| Value | How the package uses it |
|----|----|
| `state` | Carries authenticated, encrypted transaction data and links the callback to the pending login record. |
| PKCE verifier and challenge | The request carries the challenge; the later token exchange supplies the verifier, binding the exchange to this request. |
| OIDC nonce | The returned ID token is checked against the stored nonce when nonce validation is enabled. |

Generic OIDC helpers enable PKCE and nonce checks by default. Named
provider helpers select defaults appropriate to their service. S256 is
the default PKCE method when PKCE is enabled.

### Pending state and expiry

The client state store retains the browser binding, PKCE verifier, nonce
and transaction context needed for the return. The encrypted state and
stored context also record the client/provider policy used to start
login. A callback cannot continue under a changed validation policy.

`state_payload_max_age` limits the encrypted state’s age, while the
store’s retention determines how long the pending record remains
available. Both default to five minutes. State consumption is
single-use, so replaying a completed callback cannot exchange the code
again.

The default store belongs to one R process. A shared store and
`state_key` let another process continue the same transaction, with
atomic record consumption providing the single-use guarantee across
processes.

## Authorization at the provider

The module sends the browser to the prepared authorization URL, or
submits a browser form when the client selects POST authorization. The
provider handles credentials and consent. Existing provider sessions or
earlier consent may allow it to return without showing another prompt.

The authorization result contains a short-lived code or an error such as
`access_denied`, together with the transaction state. The provider sends
this result to the registered redirect URI. The code is exchanged by R;
it is not the access token used in later API calls.

## Receiving and validating the callback

[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
processes query callbacks before application HTML or scripts load. It
validates the callback address and response envelope, stores a sealed,
short-lived response, and redirects to a clean continuation URL carrying
a one-time handle.
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
provides the corresponding path for POST callbacks. The wrappers also
set no-store and no-referrer response headers.

The HTTP continuation separates callback data from application
rendering. It does not complete login by itself: the Shiny module still
checks the initiating browser and consumes the pending transaction
before code exchange.

### Transaction checks

The module checks that the state is authentic and within its lifetime,
that the stored client/provider policy still matches, and that the
browser binding agrees with the pending record. The callback route and
any required issuer identifier are checked against trusted client
configuration. Missing, expired, already-consumed or mismatched records
reject the callback.

A provider error response goes through state and browser validation too.
Only a valid response for this transaction can become the session’s
login error.

### Several authorization servers

For a configured client registry, the HTTP wrapper selects the client by
its registered callback route or issuer. Distinct-route mode checks the
callback address. Issuer mode uses the RFC 9207 `iss` or the JARM
response’s issuer as a routing hint; the selected client’s issuer,
signature, transaction and browser checks establish trust. The registry
does not treat an incoming issuer string as a new trusted provider.

## Exchanging the code for tokens

After callback validation, shinyOAuth sends the code to the token
endpoint, along with the PKCE verifier and the authentication required
by the app’s registration. `token_auth_style` selects that
authentication, such as a client secret, signed assertion or client
certificate.

The token response is still untrusted at this point. shinyOAuth parses
it, validates the access token and token type, calculates expiry, and
reconciles reported scopes with the requested permissions.
`scope_validation` determines whether a reduced grant produces a warning
or rejects login. The token records `granted_scopes` and whether the
response explicitly verified that grant in `granted_scopes_verified`.

For ordinary OAuth responses that omit `expires_in`, the package uses
`shinyOAuth.default_expires_in`, defaulting to 3,600 seconds. SMART
clients apply their separate lifetime policy.

Code exchange and refresh are not automatically retried after ordinary
network or HTTP failures, because the provider may already have consumed
the code or rotated a refresh credential. DPoP nonce challenges have
their own one-retry handling.

## Validating identity and profile information

### ID token checks

With OIDC validation enabled, shinyOAuth verifies the ID token using the
provider’s public signing keys. Key retrieval and caching follow the
provider’s configured issuer and JWKS policy. Decoding claims is
followed by signature and claim validation before the identity is
accepted.

| Check | What it establishes |
|----|----|
| Signature and allowed algorithm | The token was signed with an acceptable provider key. |
| `iss` | The token came from the configured issuer. |
| `aud` and, when present, `azp` | The token is intended for this client; additional audiences require explicit trust. |
| `sub` | The token identifies a subject within that issuer. |
| `exp`, `iat` and optional `nbf` | The token is within its validity window. |
| Nonce, when enabled | The ID token belongs to this login request. |
| `auth_time`, when freshness was requested | The provider login satisfies the requested maximum age. |
| `at_hash`, when present or required | The ID token agrees with the returned access token. |

Time checks allow the configured clock leeway, defaulting to 30 seconds.
The package also applies its configured maximum ID-token lifetime,
defaulting to 24 hours. Requested claim requirements follow
`claims_validation`, while `required_acr_values` checks the validated
authentication-context claim against the client’s accepted values.

### Introspection and UserInfo

With `introspect = TRUE`, shinyOAuth asks the provider whether the
access token is active. The response must report `active = TRUE` and
satisfy the configured `introspection_checks`. Introspection runs before
profile retrieval, allowing it to supply binding information for opaque
certificate- or DPoP-bound tokens. Checks involving the profile finish
after that profile becomes available.

When `userinfo_required = TRUE`, the package fetches the provider’s
UserInfo endpoint or profile API. A failed required fetch rejects login.
For OIDC, when both a validated ID token and UserInfo are available,
their `sub` values must match. The provider’s subject-binding policy can
also require a validated ID token to be present for the profile fetch.

UserInfo can be JSON or a signed JWT. Signed responses go through
signature and claim validation, and `userinfo_signed_jwt_required`
rejects ordinary JSON when the registration requires signing. OAuth-only
helpers obtain their profiles through the service’s API without creating
an OIDC identity assertion.

## Publishing authentication state

After all configured checks pass, the module publishes the `OAuthToken`
as `auth[["token"]]` and sets `auth[["authenticated"]]` to `TRUE`.
Reactive consumers then see the accepted token and available profile. A
rejected login instead populates `auth[["error"]]` and
`auth[["error_description"]]`.

The token holds the access and refresh credentials, expiry, granted
scopes, validated ID token claims and fetched profile. Additional
response parameters are available in `extra_fields`;
`initial_extra_fields` preserves the initial code-exchange values across
refreshes.

The module’s `connection()` method resolves the current credentials
through an `OAuthConnection`. Connection methods apply session
ownership, current access and configured permission checks when
obtaining tokens or making requests.

## Asynchronous execution

With `async = TRUE` and mirai workers or a non-sequential future plan,
the module dispatches network work to background R processes. The
validation sequence is the same, while the main process can continue
servicing Shiny. Authentication state is updated after the worker result
passes validation. The module checks that a result still belongs to the
current authorization, so work completing after logout or replacement
cannot restore the old login.

State-store access and hosted Request Object publication remain in the
main process. Signed-request preparation, PAR and query-JARM
verification can run in workers. Setup-time discovery and POST-wrapper
JARM verification remain synchronous. This describes the module’s work;
API calls made by application code have their own execution context.

## Refresh, reauthentication and logout

### Token refresh

The module watches token expiry. With `refresh_proactively = TRUE` and
an available refresh token, it schedules refresh before expiry.
Connection token acquisition can also trigger refresh on demand.
Overlapping asynchronous refreshes coordinate use of the same
credential.

A refresh response passes token validation, configured introspection and
any required profile fetch before replacing the current token. A rotated
refresh token replaces the previous one. If the provider omits a new ID
token, the stored identity token remains; a new ID token is checked for
continuity with the original subject, issuer and audience, plus nonce
and authentication time when applicable. Certificate-bound tokens
require fresh binding data.

Ordinary refresh requests preserve the retained scope limit. SMART
clients and API-specific token targets apply their corresponding scope
rules. Refresh updates credentials without establishing a new
interactive login.

### Expiry and maximum login age

By default, token expiry or refresh failure clears the local token and
makes `authenticated` false. An in-progress refresh has a grace period
before expiry clearing. `reauth_after_seconds` independently limits the
age of the interactive login; refresh does not restart that timer. With
automatic redirects enabled, the module starts authorization again when
appropriate.

For OIDC age-based reauthentication, the request includes `max_age = 0`
and the returned `auth_time` is checked. OAuth-only providers receive an
ordinary new authorization request, which may reuse their existing login
session.

`indefinite_session = TRUE` changes local clearing behavior: the module
retains login state after expiry or refresh failure, reports
`token_stale`, and ignores the maximum-login-age limit. This does not
extend token validity at the provider. With token targets, individual
API tokens can expire while the shared local authorization remains;
connection methods check the selected target before use.

### Logout and revocation

`auth[["logout"]]()` clears local credentials and resets the browser
binding. It also attempts token revocation when the provider supports
it. With `revoke_on_session_end = TRUE`, session termination and
automatic clearing also attempt revocation. These requests follow the
module’s sync or async mode; remote failure does not prevent local
cleanup.

Provider account sessions are separate, so local logout can be followed
by another authorization without a provider password prompt. Retained
connections have their own lifetime and ownership rules, described in
[Multiple
authorizations](https://lukakoning.github.io/shinyOAuth/articles/multiple-authorizations.md).

## Optional protocol extensions

Configured extensions fit into the same sequence rather than requiring a
separate application-managed flow:

| Extension | Package behavior |
|----|----|
| JAR | Signs the authorization parameters as a Request Object before browser navigation. Optional encryption hides the contents. |
| PAR | Sends the request directly to the provider first, then redirects the browser with the returned reference. |
| Form Post | Receives the authorization result by POST and bridges it into the Shiny session. |
| JARM | Verifies the signed authorization response before processing its callback fields; configured encryption adds decryption first. |
| mTLS | Presents the client certificate and uses configured endpoint aliases; certificate-bound token checks apply when enabled. |
| DPoP | Signs proofs and handles nonce challenges for token requests and resource requests made through the configured connection or request helpers. |

[Advanced
security](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.md)
describes these configurations. Detailed contracts are documented under
[oauth_client()](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.html),
[oauth_provider()](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.html),
[handle_callback()](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.html)
and
[refresh_token()](https://lukakoning.github.io/shinyOAuth/reference/refresh_token.html).

## Audit trail

The flow emits events for request preparation, callback checks, token
operations and authentication-state changes. Related events share a
`trace_id`, and failed checks include operation or phase context. The
configured audit hook receives these events; OpenTelemetry can export
the same events and operation timings. The [audit
logging](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md)
and
[OpenTelemetry](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.md)
vignettes describe those records.
