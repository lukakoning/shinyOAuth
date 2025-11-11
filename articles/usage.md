# Usage

## Overview

‘shinyOAuth’ implements provider‑agnostic OAuth 2.0 and OpenID Connect
(OIDC) authorization/authentication for Shiny apps, with modern S7
classes and secure defaults. It streamlines the full
authorization/authentication flow, including:

- Building authorization URLs and redirecting unauthenticated users
- State, nonce, and PKCE generation, sealing, and verification
- Authorization code exchange and token validation
- Optional userinfo retrieval & ID token signature/claims validation
- Proactive token refresh and re‑authentication triggers

For a full step-by-step protocol breakdown, see the separate vignette:
[`vignette("authentication-flow", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/authentication-flow.md).

For a detailed explanation of audit logging key events during the flow,
see:
[`vignette("audit-logging", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md).

## Minimal Shiny module example

Below is a minimal example using a GitHub’s OAuth 2.0 app (same as shown
in the README). Register an OAuth application at
<https://github.com/settings/developers> and set environment variables
`GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET`.

``` r
library(shiny)
library(shinyOAuth)

provider <- oauth_provider_github()

client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("read:user", "user:email")
)

ui <- fluidPage(
  # Include JavaScript dependency:
  use_shinyOAuth(),
  # Render login status & user info:
  uiOutput("login")
)

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client, auto_redirect = TRUE)
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

runApp(
  shinyApp(ui, server), port = 8100,
  # Ensure the app opens in an external browser window; 
  # RStudio's viewer cannot handle necesarry redirects properly:
  launch.browser = .rs.invokeShinyWindowExternal
)
```

Note that `ui` includes
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
to load the necessary JavaScript dependency. Always place
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
in your UI; otherwise, the module will not function. You may place it
near the top-level of your UI (e.g., inside
[`fluidPage()`](https://rdrr.io/pkg/shiny/man/fluidPage.html),
[`tagList()`](https://rstudio.github.io/htmltools/reference/tagList.html),
or
[`bslib::page()`](https://rstudio.github.io/bslib/reference/page.html)).

Note also that you must access the app in a regular browser window (not
RStudio’s viewer pane). This is because the necesarry redirects that the
browser must perform cannot be handled properly inside RStudio’s viewer.

## Manual login button variant

Below is an example where the user clicks a button to start the login
process instead of being redirected immediately on page load.

``` r
library(shiny)
library(shinyOAuth)

provider <- oauth_provider_github()

client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("read:user", "user:email")
)

ui <- fluidPage(
  use_shinyOAuth(),
  actionButton("login_btn", "Login"),
  uiOutput("login")
)

server <- function(input, output, session) {
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

runApp(
  shinyApp(ui, server), port = 8100,
  # Ensure the app opens in an external browser window; 
  # RStudio's viewer cannot handle necesarry redirects properly:
  launch.browser = .rs.invokeShinyWindowExternal
)
```

## Making authenticated API calls

Once authenticated, you may want to call an API on behalf of the user
using the access token. Use
[`client_bearer_req()`](https://lukakoning.github.io/shinyOAuth/reference/client_bearer_req.md)
to quickly build an authorized ‘httr2’ request with the correct Bearer
token. See the example app below; it calls the GitHub API to obtain the
user’s repositories.

``` r
library(shiny)
library(shinyOAuth)

provider <- oauth_provider_github()

client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("read:user", "user:email")
)

ui <- fluidPage(
  use_shinyOAuth(),
  uiOutput("ui")
)

server <- function(input, output, session) {
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
            Map(function(url, name) {
              tags$li(tags$a(href = url, target = "_blank", name))
            }, repos$html_url, repos$full_name)
          )
        } else {
          tags$p("Loading repositories...")
        }
      ))
    }
    
    return(tags$p("You are not logged in."))
  })
}

runApp(
  shinyApp(ui, server), port = 8100,
  # Ensure the app opens in an external browser window; 
  # RStudio's viewer cannot handle necesarry redirects properly:
  launch.browser = .rs.invokeShinyWindowExternal
)
```

For an example application which fetches data from the Spotify web API,
see:
[`vignette("example-spotify", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/example-spotify.md).

## Async mode to keep UI responsive

By default,
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
performs network operations (authorization code exchange, refresh,
userinfo) on the main R thread. During transient network errors the
package retries with backoff, and sleeping on the main thread can block
the Shiny event loop for the worker process.

To avoid blocking, enable async mode and configure a future backend:

``` r
future::plan(future::multisession)

server <- function(input, output, session) {
  auth <- oauth_module_server(
    "auth",
    client,
    auto_redirect = TRUE,
    async = TRUE # Run token exchange & refresh off the main thread
  )
  
  # ...
}
```

If you need to keep `async = FALSE`, you may consider reducing retry
behaviour to limit blocking during provider incidents. See ‘Global
options’ and then ‘HTTP timeout/retries’.

## Global options

The package provides several global options to customize behavior. Below
is a list of all available options.

### Observability/logging

- `options(shinyOAuth.print_errors = TRUE)` – concise error lines
  (interactive / tests only)
- `options(shinyOAuth.print_traceback = TRUE)` – include backtraces
  (interactive / tests only)
- `options(shinyOAuth.expose_error_body = TRUE)` – include sanitized
  HTTP bodies (may reveal details)
- `options(shinyOAuth.trace_hook = function(event){ ... })` – structured
  events (errors, http, etc.)
- `options(shinyOAuth.audit_hook = function(event){ ... })` – separate
  audit stream

See
[`vignette("audit-logging", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md)
for details about audit and trace hooks.

### Networking/security

- `options(shinyOAuth.leeway = 30)` – default ID token exp/iat leeway
  seconds
- `options(shinyOAuth.allowed_non_https_hosts = c("localhost", "127.0.0.1", "::1"))` -
  allows hosts to use `http://` scheme instead of `https://`
- `options(shinyOAuth.allowed_hosts = c())` – when non‑empty, restricts
  accepted hosts to this whitelist
- `options(shinyOAuth.allow_hs = TRUE)` – opt‑in HMAC validation for ID
  tokens (HS256/HS384/HS512). Requires a strictly server‑side
  `client_secret`
- `options(shinyOAuth.client_assertion_ttl = 300L)` – lifetime in
  seconds for JWT client assertions used with `client_secret_jwt` or
  `private_key_jwt` token endpoint authentication. Values below 60
  seconds are coerced up to a safe minimum; default is 300 seconds
- `options(shinyOAuth.state_fail_delay_ms = c(10, 30))` – adds a small
  randomized delay (in milliseconds) before any state validation failure
  (e.g., malformed token, IV/tag/ciphertext issues, or GCM
  authentication failure). This helps reduce timing side‑channels
  between different failure modes

Note on `allowed_hosts`: patterns support globs (`*`, `?`). Using a
catch‑all like `"*"` matches any host and effectively disables endpoint
host restrictions (scheme rules still apply). Avoid this unless you
truly intend to accept any host; prefer pinning to your domain(s), e.g.,
`c(".example.com")`.

### HTTP settings (timeout, retries, user agent)

- `options(shinyOAuth.timeout = 5)` – default HTTP timeout (seconds)
  applied to all outbound requests (discovery, JWKS, token exchange,
  userinfo). Increase if your provider/network is slow
- `options(shinyOAuth.retry_max_tries = 3L)` – maximum attempts for
  transient failures (network errors, 408, 429, 5xx)
- `options(shinyOAuth.retry_backoff_base = 0.5)` – base backoff in
  seconds used for exponential backoff with jitter
- `options(shinyOAuth.retry_backoff_cap = 5)` – per‑attempt cap on
  backoff seconds (before jitter)
- `options(shinyOAuth.retry_status = c(408L, 429L, 500:599))` – HTTP
  statuses considered transient and retried
- `options(shinyOAuth.user_agent = "shinyOAuth/<version> R/<version> httr2/<version>")`
  – override the default User‑Agent header applied to all outbound
  requests. By default this string is built dynamically from the
  installed package/runtime versions; set a custom string here if your
  organization requires a specific format

### Development softening

- `options(shinyOAuth.skip_browser_token = TRUE)` – skip browser cookie
  binding
- `options(shinyOAuth.skip_id_sig = TRUE)` – skip ID token signature
  verification

Don’t enable these in production. They disable key security checks and
are intended for local testing only. Use
[`error_on_softened()`](https://lukakoning.github.io/shinyOAuth/reference/error_on_softened.md)
at startup to fail fast if softening flags are enabled in an environment
where they should not be.

### State envelope size caps

- `options(shinyOAuth.state_max_token_chars = 8192)` – maximum allowed
  length of the base64url-encoded `state` query parameter
- `options(shinyOAuth.state_max_wrapper_bytes = 8192)` – maximum decoded
  byte size of the outer JSON wrapper (before parsing)
- `options(shinyOAuth.state_max_ct_b64_chars = 8192)` – maximum allowed
  length of the base64url-encoded ciphertext inside the wrapper
- `options(shinyOAuth.state_max_ct_bytes = 8192)` – maximum decoded byte
  size of the ciphertext before attempting AES-GCM decrypt

These prevent maliciously large state parameters from causing excessive
CPU or memory usage during decoding and decryption.

## Browser cookie & preventing XSS

[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
binds the browser and server session with a short‑lived cookie that must
be readable from client‑side JavaScript to bridge values into Shiny.

The cookie ensures that the same browser which initiated login is the
one receiving the callback. This specifically prevents an attack where
an attacker tricks a user into clicking a link which initiates login for
the attacker’s account, confusing the user into logging in as the
attacker (login confusion).

The cookie is set with the `HttpOnly` flag disabled so that it can be
read by JavaScript. This is necessary to bridge the cookie value into
Shiny. However, this means that if your app has XSS vulnerabilities, an
attacker could read the cookie too.

While this is a relatively limited attack vector, you should still take
care to prevent XSS vulnerabilities in your app. An important mitigation
is to sanitize user inputs before rendering them in the UI (e.g., using
[`htmltools::htmlEscape()`](https://rstudio.github.io/htmltools/reference/htmlEscape.html)).

## Multi‑process deployments: share state store & key

When you run multiple Shiny R processes (e.g., multiple workers, Shiny
Server Pro, RStudio Connect, Docker/Kubernetes replicas, or any
non‑sticky load balancer), you must ensure that:

- All workers share the same state store (e.g.,
  [`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
  pointing at a shared directory, or a custom cachem backend; the
  default
  [`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)
  is per‑process only and is then not shared)
- All workers share the same state key (e.g., read from environment
  variable; by default, a random key is generated per client instance
  which is then not shared)

This is because during the authorization code + PKCE flow, ‘shinyOAuth’
creates an encrypted “state envelope” which is stored in a cache (the
state_store) and echoed back via the `state` query parameter. The
envelope is sealed with AES‑GCM using your state_key. If the callback
lands on a different worker than the one that initiated login, that
worker must be able to both read the cached entry and decrypt the
envelope using the same key. If workers have different keys, decryption
will fail and the login flow will abort with a state error.

When providing a custom state key, please ensure it has high entropy
(minimum 32 characters or 32 raw bytes; recommended 64–128 characters)
to prevent offline guessing attacks against the encrypted state. Do not
use short or human‑memorable passphrases.

## Security checklist

Below is a checklist of things you may want to think about when bringing
your app to production:

- Use HTTPS everywhere in production
- Verify issuer used in your provider is correct
- In your `OAuthProvider`, set as many of the security options as
  possible; for instance, set
  `jwks_host_issuer_match`/`jwks_host_allow_only` (if your provider uses
  a different host for JWKS)
- Have your `OAuthClient` request the minimum scopes necessary; give
  your app registration only the permissions it needs
- Do not show `$error_description` to your users; never expose tokens in
  UI or logs
- Keep secrets safe in environment variables (e.g., `OAUTH_CLIENT_ID`,
  `OAUTH_CLIENT_SECRET`)
- Sanitize user inputs before rendering them in the UI (e.g., using
  [`htmltools::htmlEscape()`](https://rstudio.github.io/htmltools/reference/htmlEscape.html))
- Make use of audit logging (see
  [`vignette("audit-logging", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md))
  and monitor these logs
- Use a provider which enforces strong authentication (e.g.,
  multi-factor authentication)
- Set Content Security Policy (CSP) headers to restrict resource loading
  and mitigate XSS attacks; (requires middleware; can’t be done in
  Shiny)
- Log IP addresses of those accessing your app (requires middleware;
  can’t be done in Shiny)

While this R package has been developed with care and the OAuth 2.0/OIDC
protocols contain many security features, no guarantees can be made in
the realm of cybersecurity. For highly sensitive applications, consider
a layered (‘defense-in-depth’) approach to security (for example, adding
an IP whitelist as an additional safeguard).
