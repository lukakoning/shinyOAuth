# OAuth 2.0 authorization and OIDC authentication module for Shiny

Call `oauth_module_server()` inside your Shiny `server()` function to
manage login for each user. It sends users to the provider, checks their
return, and gives your app reactive login status and user information.
Create `client` with
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
outside `server()`, and wrap your complete UI with
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md).

This uses the OAuth 2.0 Authorization Code flow, with OpenID Connect
(OIDC) identity checks when configured for an OIDC provider.

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
  revoke_on_session_end = FALSE,
  tab_title_cleaning = TRUE,
  tab_title_replacement = NULL,
  request_uri_base_url = NULL,
  browser_cookie_path = NULL,
  browser_cookie_samesite = c("Strict", "Lax", "None")
)
```

## Arguments

- id:

  A name for this Shiny module, such as `"auth"`.

- client:

  The app configuration created with
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

- auto_redirect:

  If `TRUE` (default), start login automatically for unauthenticated
  sessions. If `FALSE`, call `auth$request_login()` to start it.

- async:

  If `TRUE`, run the module's network work through a background backend.
  Configure mirai daemons or a non-sequential future plan first; mirai
  takes priority when both are configured. Default `FALSE`.
  [`future::sequential()`](https://future.futureverse.org/reference/sequential.html)
  runs in the main process. See Asynchronous execution for operations
  that remain synchronous.

- indefinite_session:

  If TRUE, the module will not automatically clear the token due to
  access-token expiry or the `reauth_after_seconds` window, and it will
  not trigger automatic reauthentication when a token expires or a
  refresh fails. This effectively makes sessions "indefinite" from the
  module's perspective once a user has logged in. Note that your API
  calls may still fail once the provider considers the token expired;
  this option only affects the module's automatic clearing and redirect
  behavior.

- reauth_after_seconds:

  Optional maximum interactive-authentication age in seconds. If set,
  the module removes the token (and thus sets `authenticated` to FALSE)
  after this many seconds. Token refresh does not reset the timer. For
  OIDC providers, reauthentication requests send `max_age=0`; the
  returned ID token must contain a valid `auth_time`, which is used as
  the next authentication start. OAuth-only providers have no standard
  way to require active user authentication, so for them this is a hard
  local session lifetime followed by an ordinary authorization request.
  By default this is `NULL` (no forced reauthentication).

- refresh_proactively:

  If `TRUE`, obtain a replacement access token before expiry when a
  refresh token is available. Default `FALSE`. The module schedules
  refresh at approximately `expires_at - refresh_lead_seconds`.

- refresh_lead_seconds:

  Number of seconds before expiry to attempt proactive refresh (default:
  60)

- refresh_check_interval:

  Fallback interval in milliseconds for checking expiry and refresh
  (default 10000). Known expiry times are scheduled directly; this
  interval is used as a safety check or when expiry is unknown or
  infinite.

- revoke_on_session_end:

  If TRUE, automatically revokes provider tokens when the Shiny session
  ends (e.g., browser tab closed, session timeout). This is a
  best-effort operation. Revocation runs asynchronously only when the
  module is configured with `async = TRUE` (otherwise it runs
  synchronously). Requires the provider to have a `revocation_url`
  configured. Default is FALSE. Note that session-end revocation may not
  always succeed (e.g., network issues, provider unavailable), so
  combine with appropriate token lifetimes on the provider side.

- tab_title_cleaning:

  If TRUE (default), removes any query string suffix from the browser
  tab title after the OAuth callback, so titles like
  "localhost:8100?code=...&state=..." become "localhost:8100"

- tab_title_replacement:

  Optional character string to explicitly set the browser tab title
  after the OAuth callback. If provided, it takes precedence over
  `tab_title_cleaning`

- request_uri_base_url:

  Optional absolute base URL used when
  `request_object_mode = "request_uri"` publishes Request Objects
  through Shiny. By default (`NULL`), shinyOAuth derives the base URL
  from the current browser-visible app origin, but only when
  `options(shinyOAuth.allowed_hosts = ...)` pins the permitted public
  host. Set this when the authorization server must fetch the published
  Request Object through a different public host or proxy address than
  the browser uses, or when you prefer to declare the public origin
  explicitly. The value must use HTTPS and contain no query string or
  fragment. Caller-published Request Object URLs require HTTPS even when
  the ordinary
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  policy permits HTTP for that host (RFC 9101 Section 5.2).

- browser_cookie_path:

  URL path covered by the login cookie. Default `NULL` uses `"/"`,
  covering all app routes. An explicit path, such as `"/app"`, must
  cover both the starting page and callback, start with `/`, and contain
  no semicolons or control characters. On HTTPS the path is always `"/"`
  and the cookie always uses the `__Host-` prefix to prevent
  sibling-domain cookie injection. Module identifiers isolate cookie
  names. Custom paths apply only to HTTP development; HTTP cannot
  provide this protection.

- browser_cookie_samesite:

  Cookie setting controlling when the browser sends the login cookie on
  requests from other sites. One of `"Strict"` (default), `"Lax"`, or
  `"None"`. `"Lax"` allows the cookie on top-level cross-site
  navigations, which some proxy arrangements require. `"None"` also
  allows cross-site cookie use in other contexts; it requires HTTPS and
  sets the cookie's `Secure` attribute. Keep `"Strict"` unless the
  deployment needs these broader cookie-sending rules.

## Value

A
[`shiny::reactiveValues()`](https://rdrr.io/pkg/shiny/man/reactiveValues.html)
object. If you assign it to `auth`, its main fields are:

- `auth$authenticated`: `TRUE` when a token is present and the
  configured checks have passed, otherwise `FALSE`. With
  `indefinite_session = TRUE`, the flag stays true while a token is
  kept, including after refresh errors.

- `auth$token`: an
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md),
  or `NULL` before login or after clearing the session. Read properties
  with `@`, for example `auth$token@userinfo`.

- `auth$error`, `auth$error_description`: the error code and available
  diagnostic detail. Use your own user-facing message; these fields can
  include sensitive provider information.

- `auth$error_uri`: an optional provider help URL. Only absolute HTTPS
  URLs on provider or explicitly allowed hosts are surfaced. Treat it as
  untrusted navigation input. `NULL` means the provider omitted the URL
  or supplied a value that did not pass validation.

- `auth$token_stale`: `TRUE` when an indefinite session keeps an expired
  token or one whose refresh failed. Resets after successful login,
  refresh, or logout.

The object also supplies:

- `auth$request_login()`: start login. Waits for browser setup when
  needed and does nothing if the session is already authenticated.

- `auth$logout()`: clear the local login and attempt to revoke tokens
  when supported, following `async`. It does not sign out of the
  provider account.

- `auth$build_auth_url()`: advanced helper for a custom login link.
  Creates pending login state as well as the URL, so retain the result
  for the link instead of rebuilding it on every UI update. Refreshes
  and reads the browser cookie before creating state. Returns a promise
  resolving to the URL (or `NA` on failure or an obsolete result); use
  [`promises::then()`](https://rstudio.github.io/promises/reference/then.html).
  PAR URLs carry `shinyOAuth.par_request_uri`,
  `shinyOAuth.par_expires_in`, and `shinyOAuth.par_expires_at`
  attributes to help you decide when to regenerate the link.
  `request_login()` handles these details for button-based login. Inside
  [`observeEvent()`](https://rdrr.io/pkg/shiny/man/observeEvent.html),
  register the promise handler and then return `invisible(NULL)` so
  Shiny can process the browser acknowledgment. Do not return the
  pending promise from the observer itself.

- `auth$has_browser_token()`: reports whether the browser token is
  available. Use it before building a custom login URL; it does not
  report whether the user is authenticated.

- `auth$set_browser_token()`: asks the browser to create its token
  cookie when missing. The token becomes available after the browser
  reports it back to Shiny. An existing token is left unchanged.

- `auth$clear_browser_token()`: clears the cookie and its reactive
  value, for example when resetting browser setup in a custom
  integration. `request_login()` manages cookie setup automatically, and
  `logout()` handles cookie rotation when ending a session.

Other fields manage the module internally and are not needed in app
code.

## Details

Login starts automatically by default. Use `auto_redirect = FALSE` and
`auth$request_login()` to start it from a button. Read
`auth$authenticated` in reactive code, and use `req(auth$authenticated)`
before server operations that require login. Your app must also enforce
its own access rules.

See the [usage
vignette](https://lukakoning.github.io/shinyOAuth/articles/usage.html)
for a complete app and instructions for registration, API calls, and
deployment.

## Asynchronous execution

With `async = TRUE`, configure
[`mirai::daemons()`](https://mirai.r-lib.org/reference/daemons.html) or
a non-sequential
[`future::plan()`](https://future.futureverse.org/reference/plan.html)
before starting the app. Slow provider requests can then run outside the
main R process. Without this, network waits can delay all Shiny sessions
sharing that process.

Advanced operations sent to workers include PAR, signed Request Object
preparation, and query JARM verification. State-store operations and
Shiny Request Object publication stay in the main process. Discovery
during app setup, standalone
[`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md),
and JARM verification in
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
remain synchronous. Use timeouts on those network and storage
operations; see the [package options
reference](https://lukakoning.github.io/shinyOAuth/articles/package-options.html).

## Browser setup

Open the app at its registered return address in a regular browser with
cookies and Web Crypto enabled. Embedded IDE viewers may prevent login.
The temporary browser cookie follows the state store's `max_age`, with a
300-second fallback when that lifetime is unavailable. The separate
`state_payload_max_age` client setting limits the age of the login
request.

## See also

[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md),
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md),
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md),
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)

## Examples

``` r
# Register http://127.0.0.1:8100 as the GitHub OAuth App callback URL.
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
    redirect_uri = "http://127.0.0.1:8100",
    scopes = c("read:user", "user:email")
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

  ui_1 <- oauth_ui(fluidPage(
    uiOutput("login")
  ))

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

  ui_2 <- oauth_ui(fluidPage(
    actionButton("login_btn", "Login"),
    actionButton("logout_btn", "Logout"),
    uiOutput("login")
  ))

  server_2 <- function(input, output, session) {
    auth <- oauth_module_server(
      "auth",
      client,
      auto_redirect = FALSE
    )

    observeEvent(input$login_btn, {
      auth$request_login()
    })
    observeEvent(input$logout_btn, {
      auth$logout()
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

  ui_3 <- oauth_ui(fluidPage(
    uiOutput("ui")
  ))

  server_3 <- function(input, output, session) {
    auth <- oauth_module_server(
      "auth",
      client,
      auto_redirect = TRUE
    )

    repositories <- reactiveVal(NULL)
    repository_error <- reactiveVal(FALSE)

    observe({
      req(auth$authenticated)

      # Example additional API request using the access token
      # (e.g., fetch user repositories from GitHub)
      # This loads one page; use the API's pagination for further results.
      repos_data <- tryCatch({
        resp <- perform_resource_req(
          auth$token,
          "https://api.github.com/user/repos",
          query = list(per_page = 30)
        )
        httr2::resp_check_status(resp)
        httr2::resp_body_json(resp, simplifyVector = TRUE)
      }, error = function(e) NULL)

      repository_error(is.null(repos_data))
      repositories(repos_data)
    })

    # Render username + their repositories
    output$ui <- renderUI({
      if (isTRUE(auth$authenticated)) {
        user_info <- auth$token@userinfo
        repos <- repositories()

        return(tagList(
          tags$p(paste("You are logged in as:", user_info$login)),
          tags$h4("Your repositories:"),
          if (repository_error()) {
            tags$p("Could not load repositories.")
          } else if (!is.null(repos) && length(repos) == 0) {
            tags$p("No repositories returned.")
          } else if (!is.null(repos)) {
            tags$ul(
              Map(
                function(url, name) {
                  # Render names as text; accept only GitHub HTTPS links.
                  if (isTRUE(grepl("^https://github\\.com/", url))) {
                    tags$li(tags$a(
                      href = url, target = "_blank",
                      rel = "noopener noreferrer", name
                    ))
                  } else {
                    tags$li(name)
                  }
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
