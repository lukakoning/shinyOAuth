# Create generic [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)

Main helper for creating a validated
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
configuration before
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
starts login or callback handling.

## Usage

``` r
oauth_client(
  provider,
  client_id = Sys.getenv("OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("OAUTH_CLIENT_SECRET"),
  redirect_uri,
  enforce_callback_issuer = NULL,
  scopes = character(0),
  resource = character(0),
  claims = NULL,
  state_store = cachem::cache_mem(max_age = 300),
  state_payload_max_age = 300,
  state_entropy = 64,
  state_key = random_urlsafe(128),
  client_private_key = NULL,
  client_private_key_kid = NULL,
  client_assertion_alg = NULL,
  client_assertion_audience = NULL,
  tls_client_cert_file = NULL,
  tls_client_key_file = NULL,
  tls_client_key_password = NULL,
  tls_client_ca_file = NULL,
  mtls_request_certificate_bound_access_tokens = FALSE,
  authorization_request_mode = c("parameters", "request", "request_uri"),
  authorization_request_signing_alg = NULL,
  authorization_request_audience = NULL,
  authorization_request_encryption_alg = NULL,
  authorization_request_encryption_enc = NULL,
  authorization_request_encryption_kid = NULL,
  authorization_request_ttl = 45,
  authorization_request_nbf_skew = NULL,
  dpop_private_key = NULL,
  dpop_private_key_kid = NULL,
  dpop_signing_alg = NULL,
  dpop_require_access_token = NULL,
  scope_validation = c("strict", "warn", "none"),
  claims_validation = c("none", "warn", "strict"),
  userinfo_jwt_required_temporal_claims = character(0),
  required_acr_values = character(0),
  introspect = FALSE,
  introspect_elements = character(0)
)
```

## Arguments

- provider:

  [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
  object

- client_id:

  OAuth client ID

- client_secret:

  OAuth client secret.

  Validation rules:

  - Required (non-empty) when the provider authenticates the client with
    HTTP Basic auth at the token endpoint
    (`token_auth_style = "header"`, also known as
    `client_secret_basic`).

  - Optional when the provider uses form-body client authentication at
    the token endpoint (`token_auth_style = "body"`, also known as
    `client_secret_post`) and `use_pkce = TRUE`. In that configuration,
    the secret is omitted only when it is empty.

  - Ignored for token-endpoint authentication when the provider uses
    `token_auth_style = "public"` (or the alias `"none"`). Public auth
    sends `client_id` only and never sends `client_secret`, even if one
    is configured or picked up from `OAUTH_CLIENT_SECRET`.

  Note: If your provider issues HS256 ID tokens and
  `id_token_validation` is enabled, a non-empty `client_secret` is
  required for signature validation.

- redirect_uri:

  Redirect URI registered with provider

- enforce_callback_issuer:

  Logical or `NULL`. When `TRUE`, enforce that authorization responses
  handled through this client include an RFC 9207 `iss` parameter and
  reject callbacks unless it exactly matches `provider@issuer`. This is
  recommended when one callback URL can receive responses from more than
  one authorization server. Requires the provider to have a configured
  `issuer`.

  When `NULL` (the `oauth_client()` helper default), shinyOAuth
  auto-enables this check for providers that advertise
  `authorization_response_iss_parameter_supported = TRUE` and have a
  configured `issuer`, such as OIDC discovery providers that expose RFC
  9207 support. Set `FALSE` to opt out explicitly.

- scopes:

  Vector of scopes to request. For OIDC providers (those with an
  `issuer`), shinyOAuth automatically prepends `openid` when it is
  missing; that effective scope set is what gets sent in the
  authorization request and used for later state and token-scope
  validation.

- resource:

  Optional RFC 8707 resource indicator(s). Supply a character vector of
  absolute URIs to request audience-restricted tokens for one or more
  protected resources. Each value is sent as a repeated `resource`
  parameter on the authorization request, initial token exchange, and
  token refresh requests. Default is `character(0)`.

- claims:

  OIDC claims request parameter (OIDC Core §5.5). Allows requesting
  specific claims from the UserInfo Endpoint and/or in the ID Token. Can
  be:

  - `NULL` (default): no claims parameter is sent

  - A list: automatically JSON-encoded (via
    [`jsonlite::toJSON()`](https://jeroen.r-universe.dev/jsonlite/reference/fromJSON.html)
    with `auto_unbox = TRUE`) and URL-encoded into the authorization
    request. The list should have top-level members `userinfo` and/or
    `id_token`, each containing named lists of claims. Use `NULL` to
    request a claim without parameters (per spec). Example:
    `list(userinfo = list(email = NULL, given_name = list(essential = TRUE)), id_token = list(auth_time = list(essential = TRUE)))`

    Note on single-element arrays: because `auto_unbox = TRUE` is used,
    single-element R vectors are serialized as JSON scalars, not arrays.
    The OIDC spec defines `values` as an array. To force array encoding
    for a single-element vector, wrap it in
    [`I()`](https://rdrr.io/r/base/AsIs.html), e.g.,
    `acr = list(values = I("urn:mace:incommon:iap:silver"))` produces
    `{"values":["urn:mace:incommon:iap:silver"]}`. Multi-element vectors
    are always encoded as arrays.

  - A character string: pre-encoded JSON string (advanced use). Must be
    valid JSON. Use this when you need full control over JSON encoding.
    Note: The `claims` parameter is OPTIONAL per OIDC Core §5.5. Not all
    providers support it; consult your provider's documentation.

- state_store:

  State storage backend. Defaults to `cachem::cache_mem(max_age = 300)`.
  Alternative backends should use
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  with an atomic `$take()` method for replay-safe single-use state
  consumption. The backend must implement cachem-like methods
  `$get(key, missing)`, `$set(key, value)`, and `$remove(key)`;
  `$info()` is optional.

  Stored values must round-trip `browser_token` as a non-empty string.
  `pkce_code_verifier` and `nonce` are required only when the provider
  enables PKCE or nonce validation; otherwise backends may keep those
  fields as `NULL` or omit them.

  [`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)
  is a good default for a single Shiny process. For multi-process
  deployments, use
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  with an atomic `$take()` backed by a shared store (for example Redis
  `GETDEL` or SQL `DELETE ... RETURNING`). Plain
  [`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
  is **not safe** as a shared state store because its `$get()` +
  `$remove()` operations are not atomic.

  The client automatically generates, persists (in `state_store`), and
  validates the OAuth `state` parameter (and OIDC `nonce` when
  applicable) during the authorization code flow.

- state_payload_max_age:

  Positive number of seconds. Maximum allowed age for the decrypted
  state payload's `issued_at` timestamp during callback validation.

  This is the freshness window for the sealed `state` payload itself. It
  is separate from the `state_store` TTL, which controls how long the
  one-time server-side state entry can exist.

  Default is 300 seconds.

- state_entropy:

  Integer. The length (in characters) of the randomly generated state
  parameter. Higher values provide more entropy and better security
  against CSRF attacks. Must be between 22 and 128 (to align with
  `validate_state()`'s default minimum which targets ~128 bits for
  base64url‑like strings). Default is 64.

- state_key:

  Optional per-client secret used as the state sealing key for AES-GCM
  AEAD (authenticated encryption) of the state payload that travels via
  the `state` query parameter. This provides confidentiality and
  integrity (via authentication tag) for the embedded data used during
  callback verification. If you omit this argument, a random value is
  generated via `random_urlsafe(128)`. This key is distinct from the
  OAuth `client_secret` and may be used with public clients.

  Type: character string (\>= 32 bytes when encoded) or raw vector (\>=
  32 bytes). Raw keys enable direct use of high-entropy secrets from
  external stores. Both forms are normalized internally by cryptographic
  helpers.

  Multi-process deployments: if your app runs with multiple R workers or
  behind a non-sticky load balancer, configure a shared `state_store`
  and the same `state_key` across all workers. Otherwise callbacks that
  land on a different worker will fail state validation.

- client_private_key:

  Optional private key for `private_key_jwt` client authentication at
  the token endpoint. Can be an `openssl::key` or a PEM string
  containing a private key. Required when the provider's
  `token_auth_style = 'private_key_jwt'`. Ignored for other auth styles.
  Current outbound private-key JWT signing supports RSA and EC private
  keys. For RSA keys, outbound signing is currently limited to `RS256`;
  `RS384`, `RS512`, and RSA-PSS (`PS256`, `PS384`, `PS512`) are not
  supported. Ed25519/Ed448 keys are also not currently supported.

- client_private_key_kid:

  Optional key identifier (kid) to include in the JWT header for
  `private_key_jwt` assertions. Useful when the authorization server
  uses kid to select the correct verification key.

- client_assertion_alg:

  Optional JWT signing algorithm to use for client assertions. When
  omitted, defaults to `HS256` for `client_secret_jwt`. For
  `private_key_jwt`, a compatible default is selected based on the
  private key type/curve (e.g., `RS256` for RSA or
  `ES256`/`ES384`/`ES512` for EC P-256/384/521). If an explicit value is
  provided but incompatible with the key, validation fails early with a
  configuration error. When the provider advertises
  `token_endpoint_auth_signing_alg_values_supported`, both explicit
  values and inferred defaults must be included in that set. Supported
  values are `HS256`, `HS384`, `HS512` for client_secret_jwt and
  asymmetric algorithms supported for outbound signing (`RS256`,
  `ES256`, `ES384`, `ES512`) for private keys. `RS384`, `RS512`,
  `PS256`, `PS384`, `PS512`, and `EdDSA` are not currently supported for
  outbound client assertions.

- client_assertion_audience:

  Optional override for the `aud` claim used when building JWT client
  assertions (`client_secret_jwt` / `private_key_jwt`). By default,
  shinyOAuth uses the exact token endpoint request URL. Some identity
  providers require a different audience value; set this to the exact
  value your IdP expects.

- tls_client_cert_file:

  Optional path to the PEM-encoded client certificate (or certificate
  chain) used for RFC 8705 mutual TLS client authentication and
  certificate-bound protected-resource requests. Required when
  `provider@token_auth_style` is `"tls_client_auth"` or
  `"self_signed_tls_client_auth"`.

- tls_client_key_file:

  Optional path to the PEM-encoded private key used with
  `tls_client_cert_file`. Must be supplied together with
  `tls_client_cert_file`, and is required for RFC 8705 mTLS client
  authentication.

- tls_client_key_password:

  Optional password used to decrypt an encrypted PEM private key
  referenced by `tls_client_key_file`.

- tls_client_ca_file:

  Optional path to a PEM CA bundle used to validate the remote HTTPS
  server certificate when making mTLS requests. This is mainly useful
  for local or test environments that use self-signed server
  certificates.

- mtls_request_certificate_bound_access_tokens:

  Logical. Whether this client intends to request RFC 8705
  certificate-bound access tokens when the provider advertises that
  capability. Default is `FALSE`.

  Set this to `TRUE` for clients that should prefer discovered
  `mtls_endpoint_aliases` on authorization-server requests even when
  `token_auth_style` itself is not an mTLS auth style, and that should
  fail closed if the returned access token omits `cnf.x5t#S256`.

  Requires `tls_client_cert_file` and `tls_client_key_file`, and the
  provider must be configured with
  `tls_client_certificate_bound_access_tokens = TRUE`.

- authorization_request_mode:

  Controls how the authorization request is transported to the provider.

  - `"parameters"` (default): send OAuth parameters directly on the
    browser redirect URL.

  - `"request"`: send a signed JWT-secured authorization request (JAR;
    RFC 9101) via the `request` parameter.

  - `"request_uri"`: publish a signed Request Object by reference and
    send its URL via the `request_uri` parameter.

  Most users can keep the default. Request mode is an advanced option
  that requires signing material on the client. shinyOAuth prefers
  `client_private_key` when present; otherwise it falls back to HMAC
  signing with `client_secret`. When Request Object encryption is
  configured, shinyOAuth signs first and then wraps the signed Request
  Object in a JWE.

- authorization_request_signing_alg:

  Optional JWS algorithm override for signed authorization requests when
  `authorization_request_mode` uses a Request Object (`"request"` or
  `"request_uri"`). When omitted, shinyOAuth chooses `HS256` for
  HMAC-based signing or a compatible asymmetric default based on
  `client_private_key` (for example `RS256`, `ES256`, `ES384`, or
  `ES512`). `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, and `EdDSA` are
  not currently supported for outbound signed authorization requests.

- authorization_request_audience:

  Optional override for the `aud` claim used in signed authorization
  requests. By default, shinyOAuth uses the provider issuer when
  available. If the provider has no configured issuer, shinyOAuth omits
  the `aud` claim unless you supply an explicit override.

- authorization_request_encryption_alg:

  Optional JWE key-management algorithm override for encrypted Request
  Objects. Current outbound support is limited to `RSA-OAEP`. When set,
  you must also set `authorization_request_encryption_enc`.

- authorization_request_encryption_enc:

  Optional JWE content-encryption algorithm override for encrypted
  Request Objects. Current outbound support is limited to the
  AES-CBC-HMAC family (`A128CBC-HS256`, `A192CBC-HS384`,
  `A256CBC-HS512`). When set, you must also set
  `authorization_request_encryption_alg`.

- authorization_request_encryption_kid:

  Optional key identifier (`kid`) used to select one provider encryption
  key and emit the outer JWE `kid` header. This is mainly useful when
  the provider publishes more than one Request Object encryption key.

- authorization_request_ttl:

  Positive number of seconds to keep signed authorization request
  objects (`request` JWTs) valid. When
  `authorization_request_mode = "request_uri"`, shinyOAuth also uses
  this value as the default publication window for the referenced
  Request Object URI. Default is `45`.

- authorization_request_nbf_skew:

  Optional non-negative number of seconds. When provided, shinyOAuth
  adds an `nbf` claim set to `iat - authorization_request_nbf_skew` so
  deployments can tolerate small clock skew while still emitting bounded
  request-object validity windows. Leave `NULL` (the default) to omit
  `nbf`. Request-object `nbf` is reserved by shinyOAuth and cannot be
  supplied through extra authorization parameters.

- dpop_private_key:

  Optional private key used to generate DPoP proofs (RFC 9449). Can be
  an `openssl::key` or a PEM string containing an asymmetric private
  key. When provided, shinyOAuth can attach `DPoP` proofs to token
  endpoint requests and use DPoP-bound access tokens in downstream
  request helpers. In `oauth_client()`, configuring this key also makes
  `dpop_require_access_token` default to `TRUE`, so access-token
  responses reject `token_type = "Bearer"` unless you explicitly set
  `dpop_require_access_token = FALSE`. Current outbound DPoP signing
  supports RSA and EC private keys. For RSA keys, outbound signing is
  currently limited to `RS256`; `RS384`, `RS512`, and RSA-PSS (`PS256`,
  `PS384`, `PS512`) are not supported. Ed25519/Ed448 keys are also not
  currently supported. This is an advanced setting; most clients do not
  need DPoP unless their provider or resource server asks for it.

- dpop_private_key_kid:

  Optional key identifier (`kid`) to include in the JOSE header of DPoP
  proofs. Useful when the authorization or resource server expects a
  stable key identifier alongside the embedded public JWK.

- dpop_signing_alg:

  Optional JWT signing algorithm to use for DPoP proofs. When omitted, a
  compatible asymmetric default is selected based on the private key
  type/curve (for example `RS256`, `ES256`, `ES384`, or `ES512`).
  `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, and `EdDSA` are not
  currently supported for outbound DPoP proofs. If an explicit value is
  provided but incompatible with the key, validation fails early with a
  configuration error.

- dpop_require_access_token:

  Logical or `NULL`. When `TRUE` and `dpop_private_key` is configured,
  shinyOAuth requires the authorization server to return
  `token_type = "DPoP"` for access tokens and fails fast otherwise. In
  `oauth_client()`, the default `NULL` resolves to `TRUE` when
  `dpop_private_key` is configured and to `FALSE` otherwise. Set `FALSE`
  explicitly only when you intentionally want to allow Bearer access
  tokens, such as deployments where DPoP is used only to bind refresh
  tokens.

- scope_validation:

  Controls how scope discrepancies are handled when the authorization
  server grants fewer scopes than requested. RFC 6749 Section 3.3
  permits servers to issue tokens with reduced scope, and Section 5.1
  allows token responses to omit `scope` when it is unchanged from the
  requested scope.

  - `"strict"` (default): Throws an error if any requested scope is
    missing from the granted scopes. Omitted `scope` is treated as
    unchanged, not as an error.

  - `"warn"`: Emits a warning but continues authentication if scopes are
    missing.

  - `"none"`: Skips scope validation entirely.

- claims_validation:

  Controls validation of requested claims supplied via the `claims`
  parameter (OIDC Core §5.5). When `claims` includes entries with
  `essential = TRUE` for `id_token` or `userinfo`, or explicit `value` /
  `values` constraints for individual claims, this setting determines
  what happens if the returned ID token or userinfo response does not
  satisfy those requests.

  - `"none"` (default): Skips claims validation entirely. If you leave
    this default while requesting `essential`, `value`, or `values`
    constraints, `oauth_client()` warns because providers may still
    complete login without satisfying those claim requests.

  - `"warn"`: Emits a warning but continues authentication if requested
    essential claims are missing or requested claim values are not
    satisfied.

  - `"strict"`: Throws an error if any requested essential claims are
    missing or requested claim `value` / `values` constraints are not
    satisfied by the response.

  Enforceable requests under `claims$id_token` require a validated ID
  token. Configure the provider with `id_token_validation = TRUE` or
  `use_nonce = TRUE` so shinyOAuth validates the ID token before
  checking those claims.

- userinfo_jwt_required_temporal_claims:

  Optional character vector of temporal JWT claims that must be present
  when the UserInfo response is a signed JWT (`application/jwt`).
  Allowed values are `"exp"`, `"iat"`, and `"nbf"`.

  Default is `character(0)`, which means these claims are validated only
  when present. Set, for example,
  `userinfo_jwt_required_temporal_claims = "exp"` to require an expiry
  on signed UserInfo JWTs, or pass multiple values to require additional
  temporal claims. For security-sensitive deployments that accept signed
  UserInfo JWTs, prefer requiring at least `"exp"`.

- required_acr_values:

  Optional character vector of acceptable Authentication Context Class
  Reference values (OIDC Core §2, §3.1.2.1). When non-empty, the ID
  token returned by the provider must contain an `acr` claim whose value
  is one of the specified entries; otherwise the login fails with a
  `shinyOAuth_id_token_error`.

  Additionally, when non-empty, the authorization request automatically
  includes an `acr_values` query parameter (space-separated) as a
  voluntary hint to the provider (OIDC Core §3.1.2.1). Note that the
  provider is not required to honour this hint; the client-side
  validation is the authoritative enforcement.

  Requires an OIDC-capable provider with `id_token_validation = TRUE`
  and an `issuer` configured. Default is `character(0)` (no
  enforcement).

- introspect:

  If TRUE, the login flow will call the provider's token introspection
  endpoint (RFC 7662) to validate the access token. The login is not
  considered complete unless introspection succeeds and returns
  `active = TRUE`; otherwise the login fails and `authenticated` remains
  FALSE. When
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  later performs proactive refresh, it also forwards this setting so
  refreshed access tokens are introspected through the same client
  policy. Default is FALSE. Requires the provider to have an
  `introspection_url` configured.

- introspect_elements:

  Optional character vector of additional requirements to enforce on the
  introspection response when `introspect = TRUE`. Supported values:

  - `"sub"`: require the introspected `sub` to match the session subject
    (from a validated ID token `sub` when available, else from userinfo
    `sub`).

  - `"client_id"`: require the introspected `client_id` to match your
    OAuth client id.

  - `"scope"`: validate introspected `scope` against requested scopes
    (respects the client's `scope_validation` mode). Default is
    `character(0)`. (Note that not all providers may return each of
    these fields in introspection responses.)

## Value

[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
object

## Examples

``` r
if (
  # Example requires configured GitHub OAuth 2.0 app
  # (go to https://github.com/settings/developers to create one):
  nzchar(Sys.getenv("GITHUB_OAUTH_CLIENT_ID")) &&
    nzchar(Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET")) &&
    interactive()
) {
  library(shiny)
  library(shinyOAuth)

  # Define client
  client <- oauth_client(
    provider = oauth_provider_github(),
    client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
    client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
    redirect_uri = "http://127.0.0.1:8100"
  )

  # Choose which app you want to run
  app_to_run <- NULL
  while (!isTRUE(app_to_run %in% c(1:4))) {
    app_to_run <- readline(
      prompt = paste0(
        "Which example app do you want to run?\n",
        "  1: Auto-redirect login\n",
        "  2: Manual login button\n",
        "  3: Fetch additional resource with access token\n",
        "  4: No app (all will be defined but none run)\n",
        "Enter 1, 2, 3, or 4... "
      )
    )
  }

  if (app_to_run %in% c(1:3)) {
    cli::cli_alert_info(paste0(
      "Will run example app {app_to_run} on {.url http://127.0.0.1:8100}\n",
      "Open this URL in a regular browser (viewers in RStudio/Positron/etc. ",
      "cannot perform necessary redirects)"
    ))
  }

  # Example app with auto-redirect (1) -----------------------------------------

  ui_1 <- fluidPage(
    use_shinyOAuth(),
    uiOutput("login")
  )

  server_1 <- function(input, output, session) {
    # Auto-redirect (default):
    auth <- oauth_module_server(
      "auth",
      client,
      auto_redirect = TRUE
    )

    output$login <- renderUI({
      if (auth$authenticated) {
        user_info <- auth$token@userinfo
        tagList(
          tags$p("You are logged in!"),
          tags$pre(paste(capture.output(str(user_info)), collapse = "\n"))
        )
      } else {
        tags$p("You are not logged in.")
      }
    })
  }

  app_1 <- shinyApp(ui_1, server_1)
  if (app_to_run == "1") {
    runApp(
      app_1,
      port = 8100,
      launch.browser = FALSE
    )
  }

  # Example app with manual login button (2) -----------------------------------

  ui_2 <- fluidPage(
    use_shinyOAuth(),
    actionButton("login_btn", "Login"),
    uiOutput("login")
  )

  server_2 <- function(input, output, session) {
    auth <- oauth_module_server(
      "auth",
      client,
      auto_redirect = FALSE
    )

    observeEvent(input$login_btn, {
      auth$request_login()
    })

    output$login <- renderUI({
      if (auth$authenticated) {
        user_info <- auth$token@userinfo
        tagList(
          tags$p("You are logged in!"),
          tags$pre(paste(capture.output(str(user_info)), collapse = "\n"))
        )
      } else {
        tags$p("You are not logged in.")
      }
    })
  }

  app_2 <- shinyApp(ui_2, server_2)
  if (app_to_run == "2") {
    runApp(
      app_2,
      port = 8100,
      launch.browser = FALSE
    )
  }

  # Example app requesting additional resource with access token (3) -----------

  # Below app shows the authenticated username + their GitHub repositories,
  # fetched via GitHub API using the access token obtained during login

  ui_3 <- fluidPage(
    use_shinyOAuth(),
    uiOutput("ui")
  )

  server_3 <- function(input, output, session) {
    auth <- oauth_module_server(
      "auth",
      client,
      auto_redirect = TRUE
    )

    repositories <- reactiveVal(NULL)

    observe({
      req(auth$authenticated)

      # Example additional API request using the access token
      # (e.g., fetch user repositories from GitHub)
      resp <- perform_resource_req(
        auth$token,
        "https://api.github.com/user/repos"
      )

      if (httr2::resp_is_error(resp)) {
        repositories(NULL)
      } else {
        repos_data <- httr2::resp_body_json(resp, simplifyVector = TRUE)
        repositories(repos_data)
      }
    })

    # Render username + their repositories
    output$ui <- renderUI({
      if (isTRUE(auth$authenticated)) {
        user_info <- auth$token@userinfo
        repos <- repositories()

        return(tagList(
          tags$p(paste("You are logged in as:", user_info$login)),
          tags$h4("Your repositories:"),
          if (!is.null(repos)) {
            tags$ul(
              Map(
                function(url, name) {
                  tags$li(tags$a(href = url, target = "_blank", name))
                },
                repos$html_url,
                repos$full_name
              )
            )
          } else {
            tags$p("Loading repositories...")
          }
        ))
      }

      return(tags$p("You are not logged in."))
    })
  }

  app_3 <- shinyApp(ui_3, server_3)
  if (app_to_run == "3") {
    runApp(
      app_3,
      port = 8100,
      launch.browser = FALSE
    )
  }
}
```
