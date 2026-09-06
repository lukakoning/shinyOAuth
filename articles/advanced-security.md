# Advanced security configuration

## Overview

This vignette documents the configuration of OAuth 2.0 and OpenID
Connect extensions supported by shinyOAuth: JWT client authentication,
mutual TLS (mTLS), signed authorization requests (JAR), pushed
authorization requests (PAR), Form Post responses, signed authorization
responses (JARM), and tokens bound to a private key (DPoP).

These features require corresponding support and configuration at the
provider. The examples extend the provider and client setup in the
[usage
vignette](https://lukakoning.github.io/shinyOAuth/articles/usage.md).
Replace placeholder domains, credentials, and key paths with your
registered values. Each example shows the settings for the feature being
discussed.

## Provider metadata and OIDC discovery

[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md)
reads provider metadata used by these features, including PAR support,
JARM and DPoP algorithms, and mTLS endpoint aliases:

``` r
provider <- oauth_provider_oidc_discover(
  issuer = "https://id.example.com"
)
```

The sections below show the extra settings you usually add on top of
your normal
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
setup.

## JWT client authentication

Some providers require your app to sign a short statement proving its
identity when requesting tokens. This **client assertion** is a JWT
(JSON Web Token). It identifies the app, rather than the user signing
in.

For a registered private key, select the method during provider setup
and supply the key when creating your client:

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

Register the corresponding public key with your provider. For
`client_secret_jwt`, select that method and supply a sufficiently strong
`client_secret` instead. `client_assertion_alg` has a key-compatible
default; `client_assertion_audience` overrides the expected recipient if
your provider requires a value other than the token request URL.

Authentication can differ at PAR, introspection, and revocation
endpoints. Discovery preserves their independent method and algorithm
metadata; configure credentials and audiences to match each endpoint’s
registration agreement:

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

Unspecified credentials inherit the client’s settings. Advertised
methods and JWT algorithms are checked per endpoint. Discovery defaults
omitted revocation methods to Basic authentication; omitted
introspection methods have no standard default, so confirm the
configured method with your provider. PAR inherits the token
authentication settings unless explicitly overridden.
`extra_token_headers` now applies only to exchange and refresh: opt in
through `extra_headers` at each other endpoint that should receive those
headers, even on the same origin.

## Mutual TLS (mTLS)

With mutual TLS (mTLS), the client presents a certificate during the TLS
connection. OAuth 2.0 uses this for certificate-based client
authentication and for certificate-bound access tokens (RFC 8705). With
certificate-bound tokens, the API requires the matching certificate when
accepting a token. The provider must support the selected use of mTLS.

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

`mtls_certificate_bound_access_tokens = TRUE` is a strict local
assurance policy: shinyOAuth must observe `cnf$x5t#S256` in the token
response, a JWT access token, or introspection and match it to the
configured certificate. An opaque bound token without observable binding
fails this policy. RFC 8705 also permits opaque tokens whose binding is
known only to the authorization and resource servers; it does not
require a client to inspect that binding.

For that deployment, configure the certificate and key and leave the
strict flag `FALSE`; the servers must enforce certificate binding.
Certificate configuration controls presenting the certificate, while the
strict flag requires locally observable proof. Configure the needed mTLS
endpoints explicitly when using this mode. Any binding shinyOAuth does
observe must still match. See [RFC 8705, Section
3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3).

On Windows, separate PEM certificate/key files require curl’s OpenSSL
backend. Set `CURL_SSL_BACKEND=openssl` in `.Renviron` and restart R, or
run `Sys.setenv(CURL_SSL_BACKEND = "openssl")` before loading curl,
httr2, or shinyOAuth in a fresh session. Check
`curl::curl_version()$ssl_version`: parenthesized backends are inactive
alternatives. If OpenSSL is unavailable, install a curl build that
provides it. shinyOAuth rejects an active Schannel backend for this PEM
configuration before sending the request. See the [libcurl certificate
documentation](https://curl.se/libcurl/c/CURLOPT_SSLCERT.html).

If your provider uses dynamic client registration,
[`oauth_client_mtls_registration()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client_mtls_registration.md)
can build the RFC 8705 registration metadata from the configured client.

## JWT-secured authorization request (JAR)

JAR protects authorization request parameters with a signature. The
client sends them in a JWT called a Request Object, which the provider
verifies before processing the request. Optional Request Object
encryption also protects the request contents. Both settings must match
the provider registration.

For enforced request integrity, configure the authorization server to
require signed Request Objects for this client, for example with the RFC
9101 client registration field `require_signed_request_object = true`,
and register its signing key and allowed algorithm. Confirm the server
actually enforces this policy. Setting
`signed_request_object_required = TRUE` below describes that server
policy and enforces local construction; it does not register or change
the client at the server. If unsigned requests remain accepted, signing
is optional and cannot prevent a downgrade to unsigned authorization
requests ([RFC 9101 section
10.5](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.5)).

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

Test the server policy before deployment: send an otherwise valid
authorization request for this same client without `request` or
`request_uri`. For example:

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

The negative test passes only when the server explicitly rejects the
request because the required signed Request Object is missing. Check its
documented error response or server audit event for that reason; a
generic HTTP error is insufficient. A login/consent page, authorization
code, or `login_required` response does not establish enforcement.
Repeat this probe in deployment tests alongside a successful signed
request. The Keycloak compatibility examples in the integration suite do
not certify server enforcement of all JAR claims.

Register the signing key with your provider. To encrypt the signed
request too, configure `request_object_encryption_alg = "RSA-OAEP"` and
`request_object_encryption_enc` to a supported AES-CBC-HMAC value such
as `"A128CBC-HS256"`. The provider must publish a suitable encryption
key or you must supply `request_object_encryption_jwk`. See
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.html)
for supported algorithms and key selection.

PAR, described below, keeps most request details out of the browser URL.
It can also carry a signed Request Object, combining PAR with JAR.

### Request Objects published by the Shiny app

If you set `request_object_mode = "request_uri"`, shinyOAuth still
builds a signed Request Object, but instead of putting that JWT directly
on the browser redirect as `request=...`, it publishes the Request
Object at a URL and sends the provider `request_uri=<that URL>`. The
provider then fetches that published Request Object itself.

[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
serves the Request Object at a short-lived URL under the Shiny app. The
provider must be able to request that URL directly.

This mode is separate from PAR and cannot be used when the provider
requires PAR. With PAR, the provider issues the reference; with this
mode, the provider fetches a URL published by your app.

Deployment requirements:

- the published URL must use HTTPS and be reachable from the provider,
  not just from the user’s browser
- if the provider requires pre-registered `request_uri` values, the
  public URL or wildcard prefix must already be registered there

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

Shiny’s published request URL contains session-routing path segments.
These can appear in provider or proxy logs; changing
`request_uri_base_url` changes the public origin, not that path. Use PAR
when you need a provider-issued opaque reference. OIDC signed requests
retain outer `client_id`, `response_type`, and `scope` parameters.
`authorization_request_front_channel_mode = "minimal"` is available for
compatible PAR providers, but is rejected for OIDC inline or
client-published signed requests.

## Pushed authorization requests (PAR)

PAR sends the authorization request from your server to the provider
first. The browser then gets redirected with a short `request_uri`
handle instead of the full request details.

PAR allows the provider to validate the request before the browser
redirect and avoids placing large requests in a URL. It also keeps most
request details out of browser history and logs of browser requests. Set
`par_required = TRUE` when the provider requires PAR.

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

## Form Post response mode

`response_mode = "form_post"` tells the provider to send the
authorization response back as an HTTP POST body instead of query
parameters on the URL. The body still contains normal OAuth fields such
as `code`, `state`, `error`, and `iss`.

Use `form_post` when required by the provider or to keep callback values
out of the browser URL, history, and logs of browser requests. It
changes the callback transport; it does not sign or encrypt the
response.

Keep your existing provider and credentials, set
`response_mode = "form_post"` on the client, then use this UI setup.
Here `client` has a registered `redirect_uri` such as
`https://app.example.com/callback`.

``` r
base_ui <- shiny::fluidPage(shiny::textOutput("status"))
ui <- oauth_form_post_ui(base_ui, id = "auth", client = client)

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client)
  output$status <- shiny::renderText({
    if (isTRUE(auth$authenticated)) "Signed in" else "Waiting for login"
  })
}

app <- shiny::shinyApp(ui, server, uiPattern = ".*")
```

The wrapper includes
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
setup. Its module ID and client must match the server’s. For a callback
path such as `/callback`, `uiPattern = ".*"` lets Shiny send the POST to
the wrapper. A callback at the app root also works. `callback_path`
defaults to the path in `redirect_uri`; keep both aligned.

### Deployment behind an HTTPS proxy

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

Use your deployment’s verified proxy address and public origin. The
result must still match the configured redirect origin and callback
path. Do not trust forwarded headers from arbitrary clients.

## JWT-secured authorization response mode (JARM)

JARM protects the authorization response with a signature. The provider
returns a JWT, and shinyOAuth verifies its signature, issuer, audience,
and expiry before processing the callback fields. If encryption is
configured, shinyOAuth decrypts the response before validating the
signed contents.

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

JARM is currently intended for
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
If you use `response_mode = "form_post.jwt"`, wrap your UI with
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).

## Demonstrating proof-of-possession (DPoP)

DPoP binds tokens to a client key. The client signs a proof for each
token or API request, and the receiving server verifies it against the
token binding. An API enforcing DPoP requires both the access token and
a proof from the matching private key. Configure it when supported by
the authorization server and the API.

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

After login, keep using the request helpers instead of adding
`Authorization` or `DPoP` headers manually:

``` r
resp <- perform_resource_req(
  auth$token,
  "https://api.example.com/me",
  # Lets shinyOAuth attach the DPoP proof and handle nonce challenges
  oauth_client = client
)
```

### Token binding requirements and validation

Supplying a DPoP key makes `dpop_require_access_token` default to
`TRUE`: the provider must return a DPoP access token. If binding data is
visible, its `cnf$jkt` key thumbprint must match. For opaque tokens with
no visible binding, enable `dpop_require_observed_cnf = TRUE` and
arrange introspection if your deployment needs to confirm that binding
locally.

For certificate-bound tokens, the corresponding field is `cnf$x5t#S256`.
The package checks it against the configured certificate before
protected API and userinfo calls. A refreshed token needs fresh binding
data from the new token or its introspection response; the old
certificate thumbprint is not carried forward when the response omits
it.

Binding data read from a JWT access token is observed payload data;
shinyOAuth does not independently verify that access token’s signature.
Introspection can provide confirmation from the provider. The API must
enforce the binding too for a stolen token to be unusable without its
key or certificate.

### DPoP in API requests

[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
and
[`get_userinfo()`](https://lukakoning.github.io/shinyOAuth/reference/get_userinfo.md)
handle a DPoP nonce challenge with one fresh-proof retry. Later requests
to the same resource server can reuse its nonce; token-server and
resource-server nonces are kept separate. Retries of eligible API
requests generate fresh proofs.

[`resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/resource_req.md)
only builds the request. A DPoP proof is tied to its HTTP method and
base URL, so do not change those after construction. Adding query
parameters is allowed. Use
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
to manage nonce retries.

## Signature and encryption support

For outgoing private-key client assertions, JAR, and DPoP, signing
supports `RS256`, `ES256`, `ES384`, and `ES512`. Secret-based assertions
and JAR support `HS256`, `HS384`, and `HS512`. RSA-PSS and EdDSA are not
supported for outgoing signatures. Incoming signature policies are
separate; see
[`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.html)
and the `jarm_*` arguments in
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.html).

Request Object encryption and JARM decryption support `RSA-OAEP` with
`A128CBC-HS256`, `A192CBC-HS384`, or `A256CBC-HS512`. This does not
imply support for encrypted ID tokens or encrypted userinfo, which are
rejected.
