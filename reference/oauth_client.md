# Create generic [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)

Create generic
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)

## Usage

``` r
oauth_client(
  provider,
  client_id = Sys.getenv("OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("OAUTH_CLIENT_SECRET"),
  redirect_uri,
  scopes = character(0),
  claims = NULL,
  state_store = cachem::cache_mem(max_age = 300),
  state_payload_max_age = 300,
  state_entropy = 64,
  state_key = random_urlsafe(128),
  client_private_key = NULL,
  client_private_key_kid = NULL,
  client_assertion_alg = NULL,
  client_assertion_audience = NULL,
  scope_validation = c("strict", "warn", "none"),
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

- redirect_uri:

  Redirect URI registered with provider

- scopes:

  Vector of scopes to request

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
  Alternative backends could include
  [`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
  or a custom implementation (which you can create with
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md).
  The backend must implement cachem-like methods `$get(key, missing)`,
  `$set(key, value)`, and `$remove(key)`; `$info()` is optional.

  Trade-offs: `cache_mem` is in-memory and thus scoped to a single R
  process (good default for a single Shiny process). `cache_disk`
  persists to disk and can be shared across multiple R processes (useful
  for multi-process deployments or when Shiny workers aren't sticky). A
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  backend could use a database or external store (e.g., Redis,
  Memcached). See also
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

- client_private_key:

  Optional private key for `private_key_jwt` client authentication at
  the token endpoint. Can be an `openssl::key` or a PEM string
  containing a private key. Required when the provider's
  `token_auth_style = 'private_key_jwt'`. Ignored for other auth styles.

- client_private_key_kid:

  Optional key identifier (kid) to include in the JWT header for
  `private_key_jwt` assertions. Useful when the authorization server
  uses kid to select the correct verification key.

- client_assertion_alg:

  Optional JWT signing algorithm to use for client assertions. When
  omitted, defaults to `HS256` for `client_secret_jwt`. For
  `private_key_jwt`, a compatible default is selected based on the
  private key type/curve (e.g., `RS256` for RSA, `ES256`/`ES384`/`ES512`
  for EC P-256/384/521, or `EdDSA` for Ed25519/Ed448). If an explicit
  value is provided but incompatible with the key, validation fails
  early with a configuration error. Supported values are `HS256`,
  `HS384`, `HS512` for client_secret_jwt and asymmetric algorithms
  supported by
  [`jose::jwt_encode_sig`](https://r-lib.r-universe.dev/jose/reference/jwt_encode.html)
  (e.g., `RS256`, `PS256`, `ES256`, `EdDSA`) for private keys.

- client_assertion_audience:

  Optional override for the `aud` claim used when building JWT client
  assertions (`client_secret_jwt` / `private_key_jwt`). By default,
  shinyOAuth uses the exact token endpoint request URL. Some identity
  providers require a different audience value; set this to the exact
  value your IdP expects.

- scope_validation:

  Controls how scope discrepancies are handled when the authorization
  server grants fewer scopes than requested. RFC 6749 Section 3.3
  permits servers to issue tokens with reduced scope.

  - `"strict"` (default): Throws an error if any requested scope is
    missing from the granted scopes.

  - `"warn"`: Emits a warning but continues authentication if scopes are
    missing.

  - `"none"`: Skips scope validation entirely.

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
