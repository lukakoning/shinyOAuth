# OAuth 2.0 & OIDC authentication module for Shiny applications

This function implements a Shiny module server that manages OAuth
2.0/OIDC authentication for Shiny applications. It handles the OAuth
2.0/OIDC flow, including redirecting users to the authorization
endpoint, securely processing the callback, exchanging authorization
codes for tokens, verifying tokens, and managing token refresh. It also
provides options for automatic or manual login flows, session expiry,
and proactive token refresh.

Note: when using this module, you must include
[`shinyOAuth::use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
in your UI definition to load the necessary JavaScript dependencies.

## Usage

``` r
oauth_module_server(
  id,
  client,
  auto_redirect = TRUE,
  async = FALSE,
  indefinite_session = FALSE,
  reauth_after_seconds = NULL,
  refresh_proactively = FALSE,
  refresh_lead_seconds = 60,
  refresh_check_interval = 10000,
  tab_title_cleaning = TRUE,
  tab_title_replacement = NULL,
  browser_cookie_path = NULL,
  browser_cookie_samesite = c("Strict", "Lax", "None")
)
```

## Arguments

- id:

  Shiny module id

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object

- auto_redirect:

  If TRUE (default), unauthenticated sessions will immediately initiate
  the OAuth flow by redirecting the browser to the authorization
  endpoint. If FALSE, the module will not auto-redirect; instead, the
  returned object exposes helpers for triggering login manually (use:
  `$request_login()`)

- async:

  If TRUE, performs token exchange and refresh in the background using
  the promises package (future_promise), and updates values when the
  promise resolves. Requires the
  [promises::promises](https://rstudio.github.io/promises/reference/promises-package.html)
  package and a suitable backend to be configured with
  [`future::plan()`](https://future.futureverse.org/reference/plan.html).
  If FALSE (default), token exchange and refresh are performed
  synchronously (which may block the Shiny event loop; it is thus
  strongly recommended to set `async = TRUE` in production apps)

- indefinite_session:

  If TRUE, the module will not automatically clear the token due to
  access-token expiry or the `reauth_after_seconds` window, and it will
  not trigger automatic reauthentication when a token expires or a
  refresh fails. This effectively makes sessions "indefinite" from the
  module's perspective once a user has logged in. Note that your API
  calls may still fail once the provider considers the token expired;
  this option only affects the module's automatic clearing/redirect
  behavior

- reauth_after_seconds:

  Optional maximum session age in seconds. If set, the module will
  remove the token (and thus set `authenticated` to FALSE) after this
  many seconds have elapsed since authentication started. By default
  this is `NULL` (no forced re-authentication). If a value is provided,
  the timer is reset after each successful refresh so the knob is opt-in
  and counts rolling session age

- refresh_proactively:

  If TRUE, will automatically refresh tokens before they expire (if
  refresh token is available). The refresh is scheduled adaptively so
  that it executes approximately at `expires_at - refresh_lead_seconds`
  rather than on a coarse polling loop

- refresh_lead_seconds:

  Number of seconds before expiry to attempt proactive refresh (default:
  60)

- refresh_check_interval:

  Fallback check interval in milliseconds for expiry/refresh (default:
  10000 ms). When expiry is known, the module uses adaptive scheduling
  to wake up exactly when needed; this interval is used as a safety net
  or when expiry is unknown/infinite

- tab_title_cleaning:

  If TRUE (default), removes any query string suffix from the browser
  tab title after the OAuth callback, so titles like
  "localhost:8100?code=...&state=..." become "localhost:8100"

- tab_title_replacement:

  Optional character string to explicitly set the browser tab title
  after the OAuth callback. If provided, it takes precedence over
  `tab_title_cleaning`

- browser_cookie_path:

  Optional cookie Path to scope the browser token cookie. By default
  (`NULL`), the path is fixed to "/" for reliable clearing across route
  changes. Provide an explicit path (e.g., "/app") to narrow the
  cookie's scope to a sub-route. Note: when the path is "/" and the page
  is served over HTTPS, the cookie name uses the `__Host-` prefix
  (Secure, Path=/) for additional hardening; when the path is not "/", a
  regular cookie name is used.

  For apps deployed under nested routes or where the OAuth callback may
  land on a different route than the initial page, keeping the default
  (root path) ensures the browser token cookie is available and
  clearable across app routes. If you deliberately scope the cookie to a
  sub-path, make sure all relevant routes share that prefix.

- browser_cookie_samesite:

  SameSite value for the browser-token cookie. One of "Strict", "Lax",
  or "None". Defaults to "Strict" for maximum protection against
  cross-site request forgery. Use "Lax" only when your deployment
  requires the cookie to accompany top-level cross-site navigations (for
  example, because of reverse-proxy flows), and document the associated
  risk. If set to "None", the cookie will be marked
  `SameSite=None; Secure` in the browser, and authentication will error
  on non-HTTPS origins because browsers reject `SameSite=None` cookies
  without the `Secure` attribute

## Value

A reactiveValues object with `token`, `error`, `error_description`, and
`authenticated`, plus additional fields used by the module.

The returned reactiveValues contains the following fields:

- `authenticated`: logical TRUE when there is no error and a token is
  present and valid (matching the verifications enabled in the client
  provider); FALSE otherwise.

- `token`:
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object, or NULL if not yet authenticated. This contains the access
  token, refresh token (if any), ID token (if any), and userinfo (if
  fetched). See
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  for details. Note that since
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  is a S7 object, you access its fields with `@`, e.g.,
  `token@userinfo`.

- `error`: error code string when the OAuth flow fails. Be careful with
  exposing this directly to users, as it may contain sensitive
  information which could aid an attacker.

- `error_description`: human-readable error detail when available. Be
  extra careful with exposing this directly to users, as it may contain
  even more sensitive information which could aid an attacker.

- `browser_token`: internal opaque browser cookie value; used for state
  double-submit protection; NULL if not yet set

- `pending_callback`: internal list(code, state); used to defer token
  exchange until `browser_token` is available; NULL otherwise.

- `pending_login`: internal logical; TRUE when a login was requested but
  must wait for `browser_token` to be set, FALSE otherwise.

- `auto_redirected`: internal logical; TRUE once the module has
  initiated an automatic redirect in this session to avoid duplicate
  redirects.

- `reauth_triggered`: internal logical; TRUE once a reauthentication
  attempt has been initiated (after expiry or failed refresh), to avoid
  loops.

- `auth_started_at`: internal numeric timestamp (as from
  [`Sys.time()`](https://rdrr.io/r/base/Sys.time.html)) when
  authentication started; NA if not yet authenticated. Used to enforce
  `reauth_after_seconds` if set.

- `token_stale`: logical; TRUE when the token was kept despite a refresh
  failure because `indefinite_session = TRUE`, or when the access token
  is past its expiry but `indefinite_session = TRUE` prevents automatic
  clearing. This lets UIs warn users or disable actions that require a
  fresh token. It resets to FALSE on successful login, refresh, or
  logout.

- `last_login_async_used`: internal logical; TRUE if the last login
  attempt used `async = TRUE`, FALSE if it was synchronous. This is only
  used for testing and diagnostics.

- `refresh_in_progress`: internal logical; TRUE while a token refresh is
  currently in flight (async or sync). Used to prevent concurrent
  refresh attempts when proactive refresh logic wakes up multiple times.

It also contains the following helper functions, mainly useful when
`auto_redirect = FALSE` and you want to implement a manual login flow
(e.g., with your own button):

- `request_login()`: initiates login by redirecting to the authorization
  endpoint, with cookie-ensure semantics: if `browser_token` is missing,
  the module sets the cookie and defers the redirect until
  `browser_token` is present, then redirects. This is the main entry
  point for login when `auto_redirect = FALSE` and you want to trigger
  login from your own UI

- `logout()`: clears the current token setting `authenticated` to FALSE,
  and clears the browser token cookie. You might call this when the user
  clicks a "logout" button

- `build_auth_url()`: internal; builds and returns the authorization
  URL, also storing the relevant state in the client's `state_store`
  (for validation during callback). Note that this requires
  `browser_token` to be present, so it will throw an error if called too
  early (verify with `has_browser_token()` first). Typically you would
  not call this directly, but use `request_login()` instead, which calls
  it internally.

- `set_browser_token()`: internal; injects JS to set the browser token
  cookie if missing. Normally called automatically on first load, but
  you can call it manually if needed. If a token is already present, it
  will return immediately without changing it (call
  `clear_browser_token()` if you want to force a reset). Typically you
  would not call this directly, but use `request_login()` instead, which
  calls it internally if needed.

- `clear_browser_token()`: internal; injects JS to clear the browser
  token cookie and clears `browser_token`. You might call this to reset
  the cookie if you suspect it's stale or compromised. Typically you
  would not call this directly.

- `has_browser_token()`: internal; returns TRUE if `browser_token` is
  present (non-NULL, non-empty), FALSE otherwise. Typically you would
  not call this directly

## Details

- Blocking vs. async behavior: when `async = FALSE` (the default),
  network operations like token exchange and refresh are performed on
  the main R thread. Transient errors are retried by the package's
  internal `req_with_retry()` helper, which currently uses
  [`Sys.sleep()`](https://rdrr.io/r/base/Sys.sleep.html) for backoff. In
  Shiny, [`Sys.sleep()`](https://rdrr.io/r/base/Sys.sleep.html) blocks
  the event loop for the entire worker process, potentially freezing UI
  updates for all sessions on that worker during slow provider responses
  or retry backoff. To keep the UI responsive: set `async = TRUE` so
  network calls run in a background future via the promises package
  (configure a multisession/multicore backend), or reduce/block retries
  (see
  [`vignette("usage", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/usage.md)).

- Browser requirements: the module relies on the browser's Web Crypto
  API to generate a secure, per-session browser token used for state
  double-submit protection. Specifically, the login flow requires
  `window.crypto.getRandomValues` to be available. If it is not present
  (for example, in some very old or highly locked-down browsers), the
  module will be unable to proceed with authentication. In that case a
  client-side error is emitted and surfaced to the server as
  `shinyOAuth_cookie_error` containing the message
  `"webcrypto_unavailable"`. Use a modern browser (or enable Web Crypto)
  to resolve this.

- Browser cookie lifetime: the opaque browser token cookie lifetime
  mirrors the client's `state_store` TTL. Internally, the module reads
  `client@state_store$info()$max_age` and uses that value for the
  cookie's `Max-Age`/`Expires`. When the cache does not expose a finite
  `max_age`, a conservative default of 5 minutes (300 seconds) is used
  to align with the built-in `cachem::cache_mem(max_age = 300)` default
  and the state payload's `issued_at` validation window.

- Watchdog for missing browser token: to catch misconfiguration early
  during development, the module includes a short watchdog. If the
  browser token cookie is not set within 1500ms of module
  initialization, a warning is emitted to the R console. This likely
  means you forgot to include
  [`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
  in your UI, but it may also indicate that a user of your app is using
  a browser with JavaScript disabled. The watchdog prints a warning only
  once per R session, but if you want to suppress it permanently, you
  can set `options(shinyOAuth.disable_watchdog_warning = TRUE)`.

## See also

[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)

## Examples

``` r
if (
  # Example requires configured GitHub OAuth 2.0 app
  # (go to https://github.com/settings/developers to create one):
  nzchar(Sys.getenv("GITHUB_OAUTH_CLIENT_ID")) 
  && nzchar(Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"))
  && interactive()
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
      app_1, port = 8100,
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
      app_2, port = 8100,
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
  
  app_3 <- shinyApp(ui_3, server_3)
  if (app_to_run == "3") {
    runApp(
      app_3, port = 8100,
      launch.browser = FALSE
    )
  }
}
```
