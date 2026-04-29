# OAuthClient S7 class

S7 class representing an OAuth 2.0 client configuration, including a
provider, client credentials, redirect URI, requested scopes, and state
management.

This is a low-level constructor intended for advanced use. Most users
should prefer the helper constructor
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

## Usage

``` r
OAuthClient(
  provider = NULL,
  client_id = character(0),
  client_secret = character(0),
  client_private_key = NULL,
  client_private_key_kid = NA_character_,
  client_assertion_alg = NA_character_,
  client_assertion_audience = NA_character_,
  tls_client_cert_file = NA_character_,
  tls_client_key_file = NA_character_,
  tls_client_key_password = NA_character_,
  tls_client_ca_file = NA_character_,
  authorization_request_mode = "parameters",
  authorization_request_signing_alg = NA_character_,
  authorization_request_audience = NA_character_,
  dpop_private_key = NULL,
  dpop_private_key_kid = NA_character_,
  dpop_signing_alg = NA_character_,
  dpop_require_access_token = FALSE,
  redirect_uri = character(0),
  enforce_callback_issuer = FALSE,
  scopes = character(0),
  resource = character(0),
  claims = NULL,
  state_store = cachem::cache_mem(max_age = 300),
  state_payload_max_age = 300,
  state_entropy = 64,
  state_key = random_urlsafe(n = 128),
  scope_validation = "strict",
  claims_validation = "none",
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

  - Optional for public PKCE-only clients when the provider is
    configured with `use_pkce = TRUE` and uses form-body client
    authentication at the token endpoint (`token_auth_style = "body"`,
    also known as `client_secret_post`). In this case, the secret is
    omitted from token requests.

  Note: If your provider issues HS256 ID tokens and
  `id_token_validation` is enabled, a non-empty `client_secret` is
  required for signature validation.

- client_private_key:

  Optional private key for `private_key_jwt` client authentication at
  the token endpoint. Can be an `openssl::key` or a PEM string
  containing a private key. Required when the provider's
  `token_auth_style = 'private_key_jwt'`. Ignored for other auth styles.
  Current outbound private-key JWT signing supports RSA and EC private
  keys; Ed25519/Ed448 keys are not currently supported for client-side
  signing.

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
  asymmetric algorithms supported for outbound signing (for example
  `RS256`, `PS256`, `ES256`, `ES384`, `ES512`) for private keys. EdDSA
  remains supported for inbound ID token verification, not outbound
  client assertions.

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

- authorization_request_mode:

  Controls how the authorization request is transported to the provider.

  - `"parameters"` (default): send OAuth parameters directly on the
    browser redirect URL.

  - `"request"`: send a signed JWT-secured authorization request (JAR;
    RFC 9101) via the `request` parameter.

  Request mode requires signing material on the client. shinyOAuth
  prefers `client_private_key` when present; otherwise it falls back to
  HMAC signing with `client_secret`.

- authorization_request_signing_alg:

  Optional JWS algorithm override for signed authorization requests when
  `authorization_request_mode = "request"`. When omitted, shinyOAuth
  chooses `HS256` for HMAC-based signing or a compatible asymmetric
  default based on `client_private_key` (for example `RS256`, `ES256`,
  `ES384`, or `ES512`). EdDSA is not currently supported for outbound
  signed authorization requests.

- authorization_request_audience:

  Optional override for the `aud` claim used in signed authorization
  requests. By default, shinyOAuth uses the provider issuer when
  available and otherwise falls back to the authorization endpoint URL.

- dpop_private_key:

  Optional private key used to generate DPoP proofs (RFC 9449). Can be
  an `openssl::key` or a PEM string containing an asymmetric private
  key. When provided, shinyOAuth can attach `DPoP` proofs to token
  endpoint requests and use DPoP-bound access tokens in downstream
  request helpers. Configuring this key alone does not require
  DPoP-bound access tokens; set `dpop_require_access_token = TRUE` if
  token responses must reject `token_type = "Bearer"`. Current outbound
  DPoP signing supports RSA and EC private keys; Ed25519/Ed448 keys are
  not currently supported for client-side signing.

- dpop_private_key_kid:

  Optional key identifier (`kid`) to include in the JOSE header of DPoP
  proofs. Useful when the authorization or resource server expects a
  stable key identifier alongside the embedded public JWK.

- dpop_signing_alg:

  Optional JWT signing algorithm to use for DPoP proofs. When omitted, a
  compatible asymmetric default is selected based on the private key
  type/curve (for example `RS256`, `ES256`, `ES384`, or `ES512`). EdDSA
  is not currently supported for outbound DPoP proofs. If an explicit
  value is provided but incompatible with the key, validation fails
  early with a configuration error.

- dpop_require_access_token:

  Logical. When `TRUE` and `dpop_private_key` is configured, shinyOAuth
  requires the authorization server to return `token_type = "DPoP"` for
  access tokens and fails fast otherwise. Leave at the default `FALSE`
  only when you intentionally want to allow Bearer access tokens, such
  as deployments where DPoP is used only to bind refresh tokens. When
  `dpop_private_key` is configured and this argument is left at its
  default,
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  warns because configured DPoP does not by itself guarantee
  sender-constrained access tokens.

- redirect_uri:

  Redirect URI registered with provider

- enforce_callback_issuer:

  Logical or `NULL`. When `TRUE`, enforce that authorization responses
  handled through this client include an RFC 9207 `iss` parameter and
  reject callbacks unless it exactly matches `provider@issuer`. This is
  recommended when one callback URL can receive responses from more than
  one authorization server. Requires the provider to have a configured
  `issuer`.

  When `NULL` (the
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  helper default), shinyOAuth auto-enables this check for providers that
  advertise `authorization_response_iss_parameter_supported = TRUE` and
  have a configured `issuer`, such as OIDC discovery providers that
  expose RFC 9207 support. Set `FALSE` to opt out explicitly.

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

  - A character string: pre-encoded JSON string (for advanced use). Must
    be valid JSON. Use this when you need full control over JSON
    encoding. Note: The `claims` parameter is OPTIONAL per OIDC Core
    §5.5. Not all providers support it; consult your provider's
    documentation.

- state_store:

  State storage backend. Defaults to `cachem::cache_mem(max_age = 300)`.
  Alternative backends should use
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  with an atomic `$take()` method for replay-safe single-use state
  consumption. The backend must implement cachem-like methods
  `$get(key, missing)`, `$set(key, value)`, and `$remove(key)`;
  `$info()` is optional.

  Trade-offs: `cache_mem` is in-memory and thus scoped to a single R
  process (good default for a single Shiny process). For multi-process
  deployments, use
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  with an atomic `$take()` backed by a shared store (e.g., Redis
  `GETDEL`, SQL `DELETE ... RETURNING`). Plain
  [`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
  is **not safe** as a shared state store because its `$get()` +
  `$remove()` operations are not atomic; use it only if wrapped in a
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  that provides `$take()`. See also
  [`vignette("usage", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/usage.md).

  The client automatically generates, persists (in `state_store`), and
  validates the OAuth `state` parameter (and OIDC `nonce` when
  applicable) during the authorization code flow

- state_payload_max_age:

  Positive number of seconds. Maximum allowed age for the decrypted
  state payload's `issued_at` timestamp during callback validation.

  This value is an independent freshness backstop against replay attacks
  on the encrypted `state` payload. It is intentionally decoupled from
  `state_store` TTL (which controls how long the single-use state entry
  can exist in the server-side cache, and also drives browser cookie
  max-age in
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)).

  Default is 300 seconds.

- state_entropy:

  Integer. The length (in characters) of the randomly generated state
  parameter. Higher values provide more entropy and better security
  against CSRF attacks. Must be between 22 and 128 (to align with
  `validate_state()`'s default minimum which targets ~128 bits for
  base64url‑like strings). Default is 64, which provides approximately
  384 bits of entropy

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
  behind a non-sticky load balancer, you must configure a shared
  `state_store` and the same `state_key` across all workers. Otherwise
  callbacks that land on a different worker will be unable to
  decrypt/validate the state envelope and authentication will fail. In
  such environments, do not rely on the random per-process default:
  provide an explicit, high-entropy key (for example via a secret store
  or environment variable). Prefer values with substantial entropy
  (e.g., 64–128 base64url characters or a raw 32+ byte key). Avoid
  human‑memorable passphrases. See also
  [`vignette("usage", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/usage.md).

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
    constraints,
    [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
    warns because providers may still complete login without satisfying
    those claim requests.

  - `"warn"`: Emits a warning but continues authentication if requested
    essential claims are missing or requested claim values are not
    satisfied.

  - `"strict"`: Throws an error if any requested essential claims are
    missing or requested claim `value` / `values` constraints are not
    satisfied by the response.

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
  FALSE. Default is FALSE. Requires the provider to have an
  `introspection_url` configured.

- introspect_elements:

  Optional character vector of additional requirements to enforce on the
  introspection response when `introspect = TRUE`. Supported values:

  - `"sub"`: require the introspected `sub` to match the session subject
    (from ID token `sub` when available, else from userinfo `sub`).

  - `"client_id"`: require the introspected `client_id` to match your
    OAuth client id.

  - `"scope"`: validate introspected `scope` against requested scopes
    (respects the client's `scope_validation` mode). Default is
    `character(0)`. (Note that not all providers may return each of
    these fields in introspection responses.)

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
      req <- client_bearer_req(auth$token, "https://api.github.com/user/repos")
      resp <- httr2::req_perform(req)

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
