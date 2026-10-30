# Advanced security configuration

## Overview

Some login providers require extra proof that a request comes from your
app, or extra protection for the tokens they issue. Start with the
working app in
[Usage](https://lukakoning.github.io/shinyOAuth/articles/usage.md), then
configure the features your provider requires.

A signature lets the receiver check who sent a message and whether it
changed. Encryption hides its contents. A client certificate or signing
key can also tie an access token to your app, so the token alone is not
enough to use it.

The features below depend on support from the provider and, for token
binding, the API.

| Need | Feature |
|----|----|
| Prove the app’s identity with a signing key | [JWT client authentication](#jwt-client-authentication) |
| Present a registered certificate | [Mutual TLS](#mutual-tls-mtls) |
| Send request details directly to the provider | [PAR](#pushed-authorization-requests-par) |
| Sign the login request | [JAR](#jwt-secured-authorization-request-jar) |
| Return login results outside the URL or with a signature | [Form Post](#form-post-response-mode) or [JARM](#jwt-secured-authorization-response-mode-jarm) |
| Require a matching key when using a token | [DPoP](#demonstrating-proof-of-possession-dpop) |

The examples use placeholder addresses and key files for the app
registration.

## Provider metadata and OIDC discovery

Discovery reads the provider’s published settings so you do not have to
copy each endpoint and supported feature manually:

``` r

provider <- oauth_provider_oidc_discover(
  issuer = "https://id.example.com"
)
```

## JWT client authentication

With `private_key_jwt`, your app signs a short-lived JSON Web Token
(JWT) when requesting tokens instead of sending a shared secret.
Register the public key with the provider, then configure the matching
private key:

``` r

provider <- oauth_provider_oidc_discover(
  "https://id.example.com", token_auth_style = "private_key_jwt"
)
client <- oauth_client(
  provider = provider,
  client_id = "client-id",
  redirect_uri = "https://app.example.com",
  scopes = c("openid", "profile"),
  client_assertion_private_key = openssl::read_key("keys/client-key.pem"),
  client_assertion_private_key_kid = "registered-key-id"
)
```

The provider uses the public key to verify the app’s message. For
secret-based assertions, see
[oauth_client()](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.html).
See [endpoint-specific
authentication](#endpoint-specific-authentication) for credentials and
audience settings.

## Mutual TLS (mTLS)

mTLS lets your app present a certificate during the secure network
connection. It can identify the app to the provider. Separately, a
provider can issue certificate-bound tokens that an API accepts only
with the matching certificate. Configure the use agreed with your
provider:

``` r

provider <- oauth_provider(
  name = "example-mtls",
  # Exact OIDC issuer; enables nonce and ID-token validation
  issuer = "https://id.example.com",
  auth_url = "https://id.example.com/authorize",
  token_url = "https://id.example.com/token",
  jwks_uri = "https://id.example.com/jwks",
  userinfo_url = "https://id.example.com/userinfo",
  # Use RFC 8705 client-certificate auth at the token endpoint
  token_auth_style = "tls_client_auth",
  # Use mTLS-specific endpoints when the provider publishes them
  mtls_endpoint_aliases = list(
    token_endpoint = "https://mtls.id.example.com/token",
    userinfo_endpoint = "https://mtls.id.example.com/userinfo"
  ),
  # Expect certificate-bound access tokens from the provider
  mtls_client_certificate_bound_access_tokens = TRUE
)
```

``` r

client <- oauth_client(
  provider = provider,
  client_id = "client-id",
  redirect_uri = "https://app.example.com/auth/callback",
  scopes = c("openid", "profile"),
  # Certificate and key sent on mTLS requests
  mtls_client_cert_file = "certs/client.pem",
  mtls_client_key_file = "certs/client-key.pem",
  mtls_client_ca_file = "certs/ca.pem",
  # Require the matching certificate when access tokens are used
  mtls_certificate_bound_access_tokens = TRUE
)
```

By default, shinyOAuth requires visible confirmation of the token’s
certificate binding and verifies it. If your provider uses opaque
tokens, see the [certificate-binding details
below](#certificate-binding-and-platform-requirements).

On Windows, separate PEM certificate and key files require curl’s
OpenSSL backend. Follow the platform setup in that section before
testing mTLS.

## Pushed authorization requests (PAR)

PAR sends login-request details directly from your server to the
provider. The browser carries a short reference instead of the full
request, which keeps most details out of browser history and avoids very
long URLs.

``` r

provider <- oauth_provider(
  name = "example-par",
  issuer = "https://id.example.com",
  auth_url = "https://id.example.com/authorize",
  token_url = "https://id.example.com/token",
  # Enable pushed authorization requests
  par_url = "https://id.example.com/par",
  par_required = TRUE,
  # Keep the browser redirect down to client_id + PAR request_uri
  authorization_request_front_channel_mode = "minimal"
)

client <- oauth_client(
  provider = provider,
  client_id = "client-id",
  client_secret = "client-secret",
  redirect_uri = "https://app.example.com/auth/callback",
  scopes = c("openid", "profile")
)
```

## JWT-secured authorization request (JAR)

JAR signs the login request so the provider can detect changes to its
parameters. It can be combined with PAR. The app’s provider registration
holds the public signing key and the requirement for signed requests;
shinyOAuth’s local setting controls request construction.

``` r

provider <- oauth_provider(
  name = "example-jar",
  issuer = "https://id.example.com",
  auth_url = "https://id.example.com/authorize",
  token_url = "https://id.example.com/token",
  # The server registration must already require signed Request Objects
  signed_request_object_required = TRUE,
  request_parameter_supported = TRUE,
  request_object_signing_alg_values_supported = c("RS256")
)

client <- oauth_client(
  provider = provider,
  client_id = "client-id",
  client_secret = "client-secret",
  redirect_uri = "https://app.example.com/auth/callback",
  scopes = c("openid", "profile"),
  # Signing key for the Request Object
  client_assertion_private_key = openssl::read_key("keys/client-key.pem"),
  # Send the authorization request as a JWT in the request parameter
  request_object_mode = "request",
  request_object_signing_alg = "RS256"
)
```

The [unsigned-request example
below](#testing-signed-request-enforcement) illustrates the
provider-side enforcement check.

If your provider fetches signed requests from the app, see [Request
Objects published by the Shiny
app](#request-objects-published-by-the-shiny-app).

## Form Post response mode

Form Post returns the login result in an HTTP request body instead of
the browser URL, keeping callback values out of browser history. Signing
and encryption are separate features.

Set `response_mode = "form_post"` on the client, then use the matching
wrapper:

``` r

base_ui <- shiny::fluidPage(shiny::textOutput("status"))
ui <- oauth_form_post_ui(base_ui, id = "auth", client = client)

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client)
  output[["status"]] <- shiny::renderText({
    if (isTRUE(auth[["authenticated"]])) "Signed in" else "Waiting for login"
  })
}

app <- shiny::shinyApp(ui, server, uiPattern = ".*")
```

`uiPattern = ".*"` allows Shiny to serve the dedicated callback path.

If your proxy accepts HTTPS but forwards HTTP to Shiny, the wrapper
needs a trusted way to recover the public callback address. See the
[HTTPS proxy example below](#deployment-behind-an-https-proxy).

## JWT-secured authorization response mode (JARM)

JARM signs the returning login result. shinyOAuth verifies it before
accepting the callback fields, giving the app a way to check the
response’s sender and integrity. Select the mode and signing algorithm
supported by your registration:

``` r

provider <- oauth_provider(
  name = "example-jarm",
  issuer = "https://id.example.com",
  auth_url = "https://id.example.com/authorize",
  token_url = "https://id.example.com/token",
  # Advertise the JARM response modes and algorithms this provider supports
  response_modes_supported = c("query", "query.jwt", "form_post.jwt"),
  jarm_signing_alg_values_supported = c("RS256"),
  jarm_encryption_alg_values_supported = c("RSA-OAEP"),
  jarm_encryption_enc_values_supported = c("A128CBC-HS256")
)

client <- oauth_client(
  provider = provider,
  client_id = "client-id",
  client_secret = "client-secret",
  redirect_uri = "https://app.example.com/auth/callback",
  scopes = c("openid", "profile"),
  # Ask for a JWT-wrapped authorization response
  response_mode = "query.jwt",
  jarm_signed_response_alg = "RS256"
)
```

JARM uses
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
With `form_post.jwt`, also use
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).
Optional response encryption requires additional client settings and
support for local R subprocesses; see the [encrypted response example
below](#encrypted-authorization-responses).

## Demonstrating proof-of-possession (DPoP)

DPoP ties an access token to a signing key. Each request includes fresh
proof that the app holds that key, so an API enforcing DPoP cannot
accept a stolen token on its own. The provider and the API must both
support it.

``` r

provider <- oauth_provider(
  name = "example-dpop",
  issuer = "https://id.example.com",
  auth_url = "https://id.example.com/authorize",
  token_url = "https://id.example.com/token",
  # Optional metadata check for acceptable DPoP signing algorithms
  dpop_signing_alg_values_supported = c("ES256")
)

client <- oauth_client(
  provider = provider,
  client_id = "client-id",
  client_secret = "client-secret",
  redirect_uri = "https://app.example.com/auth/callback",
  scopes = c("openid", "profile", "api.read"),
  # Private key used to sign DPoP proofs
  dpop_private_key = openssl::read_key("keys/dpop-key.pem"),
  dpop_signing_alg = "ES256"
)
```

After login, let the request helper attach the proof and handle provider
nonce challenges:

``` r

resp <- perform_resource_req(
  auth[["token"]],
  "https://api.example.com/me",
  # Lets shinyOAuth attach the DPoP proof and handle nonce challenges
  client = client
)
```

The helper uses `client = client` to supply the matching key or
certificate. For DPoP tokens it rejects automatic redirects, since the
proof is tied to the request’s method and address.

## Browser binding and deployment boundary

The module links a pending login to browser session storage and a
temporary cookie. Callback validation checks both against the initiating
transaction; browser setup and binding rotation happen automatically
through the UI wrapper.

Session storage is scoped to the app’s origin and tab. Cookies are
shared across ports on a hostname, and scripts on the app’s origin can
access its storage.

With
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
or
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md),
callbacks are processed before application UI loads. Low-level
integrations built directly on
[`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)
and
[`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
supply their own browser-binding and HTTP handling.

## Endpoint-specific authentication

For the client assertion profile referenced by OAuth 2.1 draft 16, use
the trusted issuer as the audience and optionally select the recommended
type:

``` r

client@client_assertion_audience <- provider@issuer
client@client_assertion_typ <- "client-authentication+jwt"
```

[RFC7523bis draft 11 section
4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4)
describes these settings. They apply to client authentication
assertions, not JAR, JARM or ID token headers. Match them to your
provider’s registration.

PAR, introspection and revocation can each require different
authentication:

``` r

client@endpoint_auth <- list(
  introspection = list(
    token_auth_style = "header",
    client_id = "registered-inspector",
    client_secret = Sys.getenv("INTROSPECTION_SECRET"),
    extra_headers = c("X-App" = "registered-app")
  ),
  revocation = list(
    token_auth_style = "private_key_jwt",
    client_assertion_private_key = openssl::read_key("keys/revocation-key.pem"),
    client_assertion_alg = "RS256",
    client_assertion_audience = "https://id.example.com/revocation"
  )
)
```

Unspecified credentials inherit the client settings. Each endpoint has
its own authentication method and audience. `extra_token_headers`
applies only to exchange and refresh; `extra_headers` covers other
endpoints.

## Certificate binding and platform requirements

`mtls_certificate_bound_access_tokens = TRUE` enables certificate
presentation and mTLS endpoint selection, independently of the client
authentication method.

By default, `mtls_require_observed_cnf = TRUE` requires visible binding
data that matches the certificate. Some providers use opaque tokens
whose binding only their servers can check.
`mtls_require_observed_cnf = FALSE` permits missing local confirmation
for opaque tokens:

``` r

client <- oauth_client(
  provider = provider,
  client_id = "client-id",
  redirect_uri = "https://app.example.com/auth/callback",
  mtls_client_cert_file = "certs/client.pem",
  mtls_client_key_file = "certs/client-key.pem",
  mtls_certificate_bound_access_tokens = TRUE,
  mtls_require_observed_cnf = FALSE
)
```

Any observed certificate mismatch is rejected. The provider and API
enforce binding; see [RFC 8705 section
3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3).

On Windows, separate PEM certificate/key files require curl’s OpenSSL
backend. Set `CURL_SSL_BACKEND=openssl` in `.Renviron` and restart R
before loading curl, httr2 or shinyOAuth. Check the active backend with
`curl::curl_version()[["ssl_version"]]`; shinyOAuth rejects Schannel for
this configuration. See the [curl certificate
guide](https://curl.se/libcurl/c/CURLOPT_SSLCERT.html).

For dynamic registration,
[`oauth_client_mtls_registration()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client_mtls_registration.md)
builds the matching certificate registration metadata.

## Testing signed-request enforcement

This request uses the same client registration but omits the signed
Request Object:

``` r

unsigned <- httr2::request(provider@auth_url) |>
  httr2::req_url_query(
    client_id = client@client_id,
    redirect_uri = client@redirect_uri,
    response_type = "code", scope = "openid profile",
    state = "unsigned-policy-probe",
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method = "S256"
  ) |>
  httr2::req_options(followlocation = FALSE) |>
  httr2::req_error(is_error = function(resp) FALSE) |>
  httr2::req_perform()
httr2::resp_status(unsigned)
httr2::resp_headers(unsigned)
httr2::resp_body_string(unsigned)
```

Provider enforcement means this otherwise valid request is rejected for
the missing signature while a signed request succeeds. An HTTP error,
login page or `login_required` response alone leaves that result
unresolved.

To encrypt the signed request, select supported
`request_object_encryption_alg` and `request_object_encryption_enc`
values, and configure a provider encryption key. See
[oauth_client()](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.html)
and
[oauth_provider()](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.html).
PAR can also carry the signed object while keeping most details out of
the URL.

## Request Objects published by the Shiny app

With `request_object_mode = "request_uri"`, shinyOAuth publishes the
signed request at a short-lived URL for the provider to fetch. This
differs from PAR, where the provider issues the reference. Providers
requiring PAR cannot use app-hosted Request Objects in its place.

The provider must be able to reach the public HTTPS URL. Register it or
its prefix if your provider requires this:

``` r

request_uri_provider <- oauth_provider(
  name = "example-request-uri",
  issuer = "https://id.example.com",
  auth_url = "https://id.example.com/authorize",
  token_url = "https://id.example.com/token",
  request_uri_parameter_supported = TRUE,
  request_object_signing_alg_values_supported = "RS256"
)

client <- oauth_client(
  provider = request_uri_provider,
  client_id = "client-id",
  client_secret = "client-secret",
  redirect_uri = "https://app.example.com/auth/callback",
  scopes = c("openid", "profile"),
  client_assertion_private_key = openssl::read_key("keys/client-key.pem"),
  # Publish the Request Object by reference instead of sending it inline
  request_object_mode = "request_uri",
  request_object_signing_alg = "RS256"
)

# Inside server()
auth <- oauth_module_server(
  "auth",
  client,
  auto_redirect = TRUE,
  # Public HTTPS base URL of this Shiny app as seen by the provider
  request_uri_base_url = "https://shiny.yourdomain.com/myapp"
)
```

Use
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
or
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
with the same client and state store as the server. Multiple R processes
need a shared store with atomic `take()`; see
[custom_cache()](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.html).

A live retrieval handle permits one-time consumption of the object.
Signing leaves its claims readable; Request Object encryption supplies
confidentiality.

The `"minimal"` front-channel mode is for compatible PAR providers; it
is not available for OIDC inline or app-hosted signed requests.

## Deployment behind an HTTPS proxy

If your web server accepts HTTPS but forwards HTTP to Shiny, the wrapper
needs a trusted way to recover the public request address. Configure
`request_uri_resolver` for your own proxy. This example accepts one
proxy IP and a fixed public origin, including a mounted app path:

``` r

trusted_proxy_uri <- function(req) {
  if (!identical(req[["REMOTE_ADDR"]], "10.0.0.10") ||
      !identical(req[["HTTP_X_FORWARDED_PROTO"]], "https")) {
    return(NULL)
  }
  paste0("https://app.example.com", req[["SCRIPT_NAME"]], req[["PATH_INFO"]])
}

ui <- oauth_form_post_ui(
  base_ui, id = "auth", client = client,
  request_uri_resolver = trusted_proxy_uri
)
```

This resolver accepts forwarded metadata from the configured proxy
address. The wrapper checks the result against the registered redirect
origin and callback path.

## Encrypted authorization responses

For encrypted JARM, add the decryption settings:

``` r

client <- oauth_client(
  provider = provider,
  client_id = "client-id",
  client_secret = "client-secret",
  redirect_uri = "https://app.example.com/auth/callback",
  scopes = c("openid", "profile"),
  response_mode = "query.jwt",
  jarm_signed_response_alg = "RS256",
  # Optional: decrypt JARM before validating the signed payload
  jarm_encrypted_response_alg = "RSA-OAEP",
  jarm_encrypted_response_enc = "A128CBC-HS256",
  jarm_decryption_private_key = openssl::read_key("keys/jarm-decrypt.pem")
)
```

Use
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
and, for `form_post.jwt`,
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).
Encrypted callbacks use a temporary local R process, so hosting must
permit subprocesses and allow for startup time.

## Token binding requirements and validation

With a DPoP key configured, `dpop_require_access_token` defaults to
`TRUE`. The provider must return a DPoP token, and any visible key
binding must match. `dpop_require_observed_cnf = TRUE` also requires
local confirmation; opaque tokens may need introspection to provide it.

Certificate-bound tokens similarly need matching certificate data.
Refresh must provide fresh binding data; shinyOAuth does not reuse the
old certificate thumbprint when the new response omits it. Malformed
binding data is rejected.

Reading binding data from a JWT access token does not verify that
token’s signature. Introspection can confirm it with the provider. The
API must also enforce binding for a stolen token to be unusable without
its key or certificate.

### DPoP in API requests

[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
and
[`get_userinfo()`](https://lukakoning.github.io/shinyOAuth/reference/get_userinfo.md)
handle a nonce challenge with one fresh-proof retry. Proofs bind the
request’s method and address, and the helpers reject automatic
redirects. The `query` argument preserves the URL form used when
signing.

[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
also applies decoded response-size limits. Direct
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html)
uses httr2’s transport instead. If your provider issues unusually large
nonces, see `shinyOAuth.dpop_nonce_max_bytes` in [package
options](https://lukakoning.github.io/shinyOAuth/articles/package-options.md).

## Policy identity across callbacks and retained credentials

Pending logins and saved connections remember the client and provider
policies that created them. Policy changes invalidate those records.
After upgrades that change the policy encoding, users must sign in
again; update workers that share keys and storage together.

If a custom `userinfo_id_selector` depends on external settings, assign
a `userinfo_id_selector_policy_id` and change it when those settings or
helper behavior change. This identifies policy inputs outside the
function body. The Spotify helper tracks its `allow_legacy_id` setting
automatically.

## Issuer comparison and transport policy

`compare_callback_issuer = TRUE` compares `iss` exactly with the trusted
`provider@issuer`; `enforce_callback_issuer` also requires it to be
present. Providers advertising RFC 9207 support require the identifier,
while validated JARM supplies its own issuer. Apps using several
providers still need issuer identification or distinct callback routes.

For legacy providers that omit `iss`, comparison can remain enabled
while presence is optional. The flags control these checks separately;
see
[oauth_client()](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.html).

Package HTTPS requests require TLS 1.2 or later by default.
`options(shinyOAuth.tls_min_version = "1.3")` selects a higher minimum;
set it before discovery or login. Browser and proxy TLS need separate
configuration. See [package
options](https://lukakoning.github.io/shinyOAuth/articles/package-options.html#http-settings-timeout-retries-user-agent).

## Callback pages and application scripts

For query and query-JARM callbacks,
`oauth_ui(ui, id = "auth", client = client)` processes callbacks before
loading application UI and sets privacy headers. Its ID and client
identify the corresponding
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
instance.

Response headers control browser caching and referrers, independently of
upstream hosting and proxy logs. The standard UI wrappers isolate raw
callbacks from application scripts; custom
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
integrations provide their own HTTP callback handling.

The registered redirect URI declares fixed routing query parameters;
continuation discards unregistered inbound parameters. Behind an HTTPS
proxy, `request_uri_resolver` supplies the public address under the
trust policy described for
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).

## Provider key-set validation

shinyOAuth checks the entire provider key set before selecting a signing
key. A malformed entry can therefore interrupt login or signed responses
even if another key would work. Providers must publish valid entries
throughout key rotation; see [RFC 7517 section
5](https://www.rfc-editor.org/rfc/rfc7517.html#section-5) for the
standard’s less restrictive recommendation.

shinyOAuth rejects conflicting signing algorithms for one RSA key,
including when reused under different key IDs. Key rotation changes the
key and can require corresponding pin, policy and cache updates;
changing only `kid` does not change the key. See
[oauth_provider()](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.html)
for pinning and key-selection settings.

## Trusted ID-token audiences

ID tokens with multiple audiences remain rejected by default. If an
issuer legitimately includes another trusted audience, configure
`trusted_id_token_audiences = c("trusted-service")` on
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).
shinyOAuth still requires this client’s ID in `aud` and a matching `azp`
when present. Trusted multiple audiences do not require an `azp` claim
under [OIDC Core section
3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

## Signature and encryption support

The signing algorithm must be supported by both the provider and
shinyOAuth. Outgoing defaults depend on the key: RSA defaults to
`RS256`, with `client_assertion_alg = "RS384"` available for
registrations requiring RS384.

| Use | Supported algorithms |
|----|----|
| Private-key assertions, JAR and DPoP | `RS256`, `RS384`, `ES256`, `ES384`, `ES512`, and `EdDSA` or `Ed25519` with Ed25519 keys. |
| Secret-based assertions and JAR | `HS256`, `HS384`, `HS512`. |
| Request Object encryption and JARM decryption | `RSA-OAEP` with `A128CBC-HS256`, `A192CBC-HS384` or `A256CBC-HS512`. |

Outgoing RSA-PSS and Ed448 signatures are unsupported. For encryption,
`RSA-OAEP-256` and GCM JWE modes are unsupported, as are encrypted ID
tokens and encrypted UserInfo.

Incoming signature policies are separate. See
[oauth_provider()](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.html)
and the `jarm_*` settings in
[oauth_client()](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.html).
