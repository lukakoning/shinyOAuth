# This file contains the main Shiny module that runs the browser login session
# It keeps the login flow tied to one browser session from redirect to
# callback
# Used for managing redirects, callbacks, token refresh, and authenticated
# state inside a Shiny app

# 1 Shiny module entry point ---------------------------------------------------

#' @title
#' OAuth 2.0 authorization and OIDC authentication module for Shiny
#'
#' @description
#' Call `oauth_module_server()` inside your Shiny `server()` function to manage
#' login for each user. It sends users to the provider, checks their return,
#' and gives your app reactive login status and user information.
#' Create `client` with [oauth_client()] outside `server()`, and wrap your
#' complete UI with [oauth_ui()].
#'
#' This uses the OAuth 2.0 Authorization Code flow, with OpenID Connect (OIDC)
#' identity checks when configured for an OIDC provider.
#'
#' @details
#' Login starts automatically by default. Use `auto_redirect = FALSE` and
#' `auth$request_login()` to start it from a button. Read `auth$authenticated`
#' in reactive code, and use `req(auth$authenticated)` before server operations
#' that require login. Your app must also enforce its own access rules.
#'
#' See the [usage vignette](https://lukakoning.github.io/shinyOAuth/articles/usage.html) for a complete app and
#' instructions for registration, API calls, and deployment.
#'
#' @section Asynchronous execution:
#' With `async = TRUE`, configure [mirai::daemons()] or a non-sequential
#' [future::plan()] before starting the app. Slow provider requests can then
#' run outside the main R process. Without this, network waits can delay all
#' Shiny sessions sharing that process.
#'
#' Advanced operations sent to workers include PAR, signed Request Object
#' preparation, and query JARM verification. State-store operations and Shiny
#' Request Object publication stay in the main process. Discovery during app
#' setup, standalone [prepare_call()], and JARM verification in
#' [oauth_form_post_ui()] remain synchronous. Use timeouts on those network
#' and storage operations; see the [package options reference](https://lukakoning.github.io/shinyOAuth/articles/package-options.html).
#'
#' @section Browser setup:
#' Open the app at its registered return address in a regular browser with
#' cookies, local storage, and Web Crypto enabled. Embedded IDE viewers may
#' prevent login. The binding token stays in origin-scoped local storage; the
#' cookie contains an independent marker, which must match the stored record.
#' The temporary browser cookie follows the state store's `max_age`, with a
#' 300-second fallback when that lifetime is unavailable. The separate
#' `state_payload_max_age` client setting limits the age of the login request.
#' Each new login uses a fresh server-selected browser binding. Complete one
#' login at a time per module; starting another replaces the pending binding.
#' Private browser-binding inputs are excluded from Shiny bookmarks. Do not
#' copy `auth$browser_token` into custom bookmark values, URLs, or logs.
#' Treat the entire hostname as a trust boundary: cookies are shared across
#' ports, even with `__Host-`, `Secure`, or `HttpOnly`. Use a dedicated hostname
#' when other services are not trusted. The origin-scoped check prevents cookie
#' adoption across ports, but co-hosted services can still disrupt cookies.
#'
#' @param id A name for this Shiny module, such as `"auth"`.
#'
#' @param client The app configuration created with [oauth_client()].
#'
#' @param auto_redirect If `TRUE` (default), start login automatically for unauthenticated
#'   sessions. If `FALSE`, call `auth$request_login()` to start it.
#'
#' @param async If `TRUE`, run the module's network work through a background
#'   backend. Configure mirai daemons or a non-sequential future plan first;
#'   mirai takes priority when both are configured. Default `FALSE`.
#'   `future::sequential()` runs in the main process. See Asynchronous execution for
#'   operations that remain synchronous.
#'
#' @param indefinite_session If TRUE, the module will not automatically clear
#'   the token due to access-token expiry or the `reauth_after_seconds` window,
#'   and it will not trigger automatic reauthentication when a token expires or
#'   a refresh fails. This effectively makes sessions "indefinite" from the
#'   module's perspective once a user has logged in. Note that your API calls
#'   may still fail once the provider considers the token expired; this option
#'   only affects the module's automatic clearing and redirect behavior.
#'
#' @param reauth_after_seconds Optional maximum interactive-authentication age
#'  in seconds. If set, the module removes the token (and thus sets
#'  `authenticated` to FALSE) after this many seconds. Token refresh does not
#'  reset the timer. For OIDC providers, reauthentication requests send
#'  `max_age=0`; the returned ID token must contain a valid `auth_time`, which
#'  is used as the next authentication start. OAuth-only providers have no
#'  standard way to require active user authentication, so for them this is a
#'  hard local session lifetime followed by an ordinary authorization request.
#'  By default this is `NULL` (no forced reauthentication).
#'
#' @param refresh_proactively If `TRUE`, obtain a replacement access token before
#'   expiry when a refresh token is available. Default `FALSE`. The module
#'   schedules refresh at approximately `expires_at - refresh_lead_seconds`.
#'
#' @param refresh_lead_seconds Number of seconds before expiry to attempt
#'  proactive refresh (default: 60)
#' @param refresh_check_interval Fallback interval in milliseconds for checking
#'   expiry and refresh (default 10000). Known expiry times are scheduled
#'   directly; this interval is used as a safety check or when expiry is unknown
#'   or infinite.
#'
#' @param revoke_on_session_end If TRUE, automatically revokes provider tokens
#'   when the Shiny session ends (e.g., browser tab closed, session timeout).
#'   This is a best-effort operation. Revocation runs asynchronously only when
#'   the module is configured with `async = TRUE` (otherwise it runs
#'   synchronously).
#'   Requires the provider to have a `revocation_url` configured. Default is
#'   FALSE. Note that session-end revocation may not always succeed (e.g.,
#'   network issues, provider unavailable), so combine with appropriate token
#'   lifetimes on the provider side.
#'
#' @param tab_title_cleaning If TRUE (default), removes any query string suffix
#'   from the browser tab title after the OAuth callback, so titles like
#'   "localhost:8100?code=...&state=..." become "localhost:8100"
#' @param tab_title_replacement Optional character string to explicitly set the
#'   browser tab title after the OAuth callback. If provided, it takes
#'   precedence over `tab_title_cleaning`
#' @param request_uri_base_url Optional absolute base URL used when
#'   `request_object_mode = "request_uri"` publishes Request Objects
#'   through Shiny. By default (`NULL`), shinyOAuth derives the base URL from
#'   the current browser-visible app origin, but only when
#'   `options(shinyOAuth.allowed_hosts = ...)` pins the permitted public host.
#'   Set this when the authorization server must fetch the published Request
#'   Object through a different public host or proxy address than the browser
#'   uses, or when you prefer to declare the public origin explicitly. The
#'   value must use HTTPS and contain no query string or fragment.
#'   Caller-published Request Object URLs require HTTPS even when the ordinary
#'   [is_ok_host()] policy permits HTTP for that host (RFC 9101 Section 5.2).
#'
#' @param browser_cookie_path URL path covered by the login cookie. Default `NULL`
#'   uses `"/"`, covering all app routes. An explicit path, such as `"/app"`,
#'   must cover both the starting page and callback, start with `/`, and contain
#'   no semicolons or control characters. On HTTPS the path is always `"/"`
#'   and the cookie always uses the `__Host-` prefix to prevent sibling-domain
#'   cookie injection. Module identifiers isolate cookie names. Custom paths
#'   apply only to HTTP development; HTTP cannot provide this protection.
#'
#' @param browser_cookie_samesite Cookie setting controlling when the browser sends
#'   the login cookie on requests from other sites. One of `"Strict"` (default),
#'   `"Lax"`, or `"None"`. `"Lax"` allows the cookie on top-level cross-site
#'   navigations, which some proxy arrangements require. `"None"` also allows
#'   cross-site cookie use in other contexts; it requires HTTPS and sets the
#'   cookie's `Secure` attribute. Keep `"Strict"` unless the deployment needs
#'   these broader cookie-sending rules.
#'
#' @return A [shiny::reactiveValues()] object. If you assign it to `auth`,
#'   its main fields are:
#'
#'   - `auth$authenticated`: `TRUE` when a token is present and the configured
#'     checks have passed, otherwise `FALSE`. With `indefinite_session = TRUE`,
#'     the flag stays true while a token is kept, including after refresh errors.
#'   - `auth$token`: an [OAuthToken], or `NULL` before login or after clearing
#'     the session. Read properties with `@`, for example `auth$token@userinfo`.
#'   - `auth$error`, `auth$error_description`: the error code and available
#'     diagnostic detail. Use your own user-facing message; these fields can
#'     include sensitive provider information.
#'   - `auth$error_uri`: an optional provider help URL. Only absolute HTTPS
#'     URLs on provider or explicitly allowed hosts are surfaced. Treat it as
#'     untrusted navigation input. `NULL` means the provider omitted the URL or
#'     supplied a value that did not pass validation.
#'   - `auth$token_stale`: `TRUE` when an indefinite session keeps an expired
#'     token or one whose refresh failed. Resets after successful login,
#'     refresh, or logout.
#'
#'   The object also supplies:
#'
#'   - `auth$request_login()`: start login. Waits for browser setup when needed
#'     and does nothing if the session is already authenticated.
#'   - `auth$logout()`: clear the local login and attempt to revoke tokens when
#'     supported, following `async`. It does not sign out of the provider account.
#'   - `auth$build_auth_url()`: advanced helper for a custom login link.
#'     Creates pending login state as well as the URL, so retain the result for
#'     the link instead of rebuilding it on every UI update.
#'     Rotates and checks the browser binding before creating state. Returns a
#'     promise resolving to the URL (or `NA` on failure or an obsolete result);
#'     use `promises::then()`. PAR URLs carry `shinyOAuth.par_request_uri`,
#'     `shinyOAuth.par_expires_in`, and `shinyOAuth.par_expires_at` attributes
#'     to help you decide when to regenerate the link. `request_login()`
#'     handles these details for button-based login.
#'     Inside `observeEvent()`, register the promise handler and then return
#'     `invisible(NULL)` so Shiny can process the browser acknowledgment. Do not
#'     return the pending promise from the observer itself.
#'   - `auth$has_browser_token()`: reports whether the browser token is
#'     available. Use it before building a custom login URL; it does not report
#'     whether the user is authenticated.
#'   - `auth$set_browser_token()`: asks the browser to establish its binding
#'     when missing. The token becomes available after the browser reports it
#'     back to Shiny. An existing token is left unchanged.
#'   - `auth$clear_browser_token()`: clears the cookie, local record, and reactive value,
#'     for example when resetting browser setup in a custom integration.
#'     `request_login()` manages cookie setup automatically, and `logout()`
#'     handles cookie rotation when ending a session.
#'
#'   Other fields manage the module internally and are not needed in app code.
#'
#' @example inst/examples/oauth_module_server.R
#'
#' @export
#'
#' @seealso [oauth_ui()], [oauth_client()], [OAuthToken], [oauth_form_post_ui()]
oauth_module_server <- function(
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
) {
  # 1 Module setup -------------------------------------------------------------

  ## 1.1 Parameter validation --------------------------------------------------

  S7::check_is_S7(client, class = OAuthClient)

  if (!is_valid_string(id)) {
    err_input("{.arg id} must be a single non-empty string.")
  }
  if (
    !(is.logical(refresh_proactively) &&
      length(refresh_proactively) == 1 &&
      !is.na(refresh_proactively))
  ) {
    err_input("{.arg refresh_proactively} must be a single non-NA logical.")
  }
  if (
    !(is.numeric(refresh_lead_seconds) &&
      length(refresh_lead_seconds) == 1 &&
      is.finite(refresh_lead_seconds) &&
      refresh_lead_seconds >= 0)
  ) {
    err_input(
      "{.arg refresh_lead_seconds} must be a single non-negative number."
    )
  }
  if (
    !(is.numeric(refresh_check_interval) &&
      length(refresh_check_interval) == 1 &&
      is.finite(refresh_check_interval) &&
      refresh_check_interval >= 100)
  ) {
    err_input(
      "{.arg refresh_check_interval} must be a single number >= 100."
    )
  }
  if (!(is.logical(async) && length(async) == 1 && !is.na(async))) {
    err_input("{.arg async} must be a single non-NA logical.")
  }
  if (
    !(is.logical(tab_title_cleaning) &&
      length(tab_title_cleaning) == 1 &&
      !is.na(tab_title_cleaning))
  ) {
    err_input("{.arg tab_title_cleaning} must be a single non-NA logical.")
  }
  if (
    !(is.null(tab_title_replacement) ||
      is_valid_string(tab_title_replacement))
  ) {
    err_input(
      "{.arg tab_title_replacement} must be NULL or a non-empty string."
    )
  }
  if (
    !(is.null(request_uri_base_url) ||
      is_valid_string(request_uri_base_url))
  ) {
    err_input(
      "{.arg request_uri_base_url} must be NULL or a non-empty string."
    )
  }
  if (
    !(is.logical(auto_redirect) &&
      length(auto_redirect) == 1 &&
      !is.na(auto_redirect))
  ) {
    err_input("{.arg auto_redirect} must be a single non-NA logical.")
  }
  if (
    !(is.null(reauth_after_seconds) ||
      (is.numeric(reauth_after_seconds) &&
        length(reauth_after_seconds) == 1 &&
        is.finite(reauth_after_seconds) &&
        reauth_after_seconds > 0))
  ) {
    err_input(
      "{.arg reauth_after_seconds} must be NULL or a single positive number."
    )
  }
  if (
    !(is.logical(indefinite_session) &&
      length(indefinite_session) == 1 &&
      !is.na(indefinite_session))
  ) {
    err_input("{.arg indefinite_session} must be a single non-NA logical.")
  }
  if (
    !(is.null(browser_cookie_path) ||
      is_valid_cookie_path(browser_cookie_path))
  ) {
    err_input(
      paste(
        "{.arg browser_cookie_path} must be NULL or a cookie path that starts",
        "with '/' and contains no semicolons or control characters."
      )
    )
  }
  if (
    !(is.logical(revoke_on_session_end) &&
      length(revoke_on_session_end) == 1 &&
      !is.na(revoke_on_session_end))
  ) {
    err_input("{.arg revoke_on_session_end} must be a single non-NA logical.")
  }

  request_uri_base_url <- normalize_request_uri_base_url(
    request_uri_base_url,
    arg = "request_uri_base_url"
  )

  allowed_hosts <- getOption("shinyOAuth.allowed_hosts", default = NULL)
  has_request_uri_host_policy <-
    is.character(allowed_hosts) &&
    length(allowed_hosts) > 0L &&
    any(vapply(allowed_hosts, is_valid_string, logical(1)))

  if (
    identical(
      client@request_object_mode %||% "parameters",
      "request_uri"
    ) &&
      is.null(request_uri_base_url) &&
      !isTRUE(has_request_uri_host_policy)
  ) {
    err_config(c(
      paste(
        "oauth_module_server() with request_object_mode =",
        "'request_uri' requires either request_uri_base_url or",
        "options(shinyOAuth.allowed_hosts = ...) so the published",
        "Request Object origin is pinned explicitly."
      ),
      "i" = paste(
        "Set request_uri_base_url to the public HTTPS origin that the",
        "authorization server should fetch."
      ),
      "i" = paste(
        "Or configure shinyOAuth.allowed_hosts so the browser-derived origin",
        "must match your deployment policy."
      )
    ))
  }

  ## 1.2 Browser and async prerequisites ---------------------------------------

  # Fail fast: revoke_on_session_end requires a revocation URL

  if (isTRUE(revoke_on_session_end)) {
    provider_name <- client@provider@name %||% "(unnamed)"
    revocation_url <- client@provider@revocation_url %||% NA_character_
    if (!is_valid_string(revocation_url)) {
      err_config(
        c(
          "{.arg revoke_on_session_end} = {.val TRUE} requires\nthe provider to have a {.arg revocation_url} configured.",
          "x" = paste0(
            "Provider ",
            provider_name,
            " does not expose a revocation endpoint."
          ),
          "i" = "Set {.arg revoke_on_session_end} = {.val FALSE} or\nconfigure the provider with a valid {.arg revocation_url}."
        )
      )
    }
  }

  if (!.is_test()) {
    warn_pkg(
      "Open your Shiny app in a regular browser",
      c(
        "!" = "{.code oauth_module_server()} was called; view your app in a standard web browser (e.g., Chrome, Firefox, Safari)",
        "i" = "Viewers in RStudio/Positron/etc. cannot perform necessary redirects for OAuth 2.0 flows"
      ),
      .frequency = "once",
      .frequency_id = "oauth_module_server_remind_browser"
    )
  }

  warn_about_missing_js_dependency()
  warn_about_missing_form_post_ui(id, client)

  browser_cookie_samesite <- match.arg(browser_cookie_samesite)
  if (identical(browser_cookie_samesite, "Lax")) {
    warn_pkg(
      "Verify browser token cookie settings",
      c(
        "!" = "`browser_cookie_samesite = \"Lax\"` relaxes cross-site protections for the session-binding cookie",
        "i" = "Ensure this mode is strictly required for your deployment"
      )
    )
  }
  if (identical(browser_cookie_samesite, "None")) {
    inform_pkg(
      "Enforcing Secure for SameSite=None cookie",
      c(
        "i" = "`browser_cookie_samesite = \"None\"` requires HTTPS. The browser cookie writer will force `Secure` and error on non-HTTPS origins"
      )
    )
  }

  # Validate async settings
  if (!isTRUE(async)) {
    if (!.is_test()) {
      warn_pkg(
        "Consider using `async = TRUE` for responsive UIs",
        c(
          "!" = "{.code oauth_module_server(async = FALSE)} may block the Shiny event loop during network calls, potentially freezing the UI",
          "i" = "Consider setting `async = TRUE` and configuring {.pkg mirai} daemons (e.g., {.code mirai::daemons(2)})"
        ),
        .frequency = "once",
        .frequency_id = "oauth_module_server_no_async"
      )
    }
  } else {
    # Ensure at least one async backend is available
    # Prefer mirai, but also support future for backwards compatibility
    backend <- async_backend_available()

    if (is.null(backend)) {
      # No backend available - check what's missing to provide helpful message
      if (rlang::is_installed("mirai")) {
        warn_pkg(
          "No async backend configured",
          c(
            "!" = "{.code oauth_module_server(async = TRUE)} but no {.pkg mirai} daemons are connected",
            "i" = "Set up daemons: {.code mirai::daemons(2)} at the top of your app",
            "i" = "Or configure a future plan: {.code future::plan(future::multisession)}"
          )
        )
      } else if (
        rlang::is_installed("future") && rlang::is_installed("promises")
      ) {
        warn_pkg(
          "No async backend configured",
          c(
            "!" = "{.code oauth_module_server(async = TRUE)} but no {.pkg future} plan is set",
            "i" = "Set up a future plan: {.code future::plan(future::multisession)}",
            "i" = "Or use mirai (preferred): {.code mirai::daemons(2)}"
          )
        )
      } else {
        rlang::check_installed(
          "mirai",
          reason = "to use `async = TRUE` in `oauth_module_server()`. Alternatively, install `promises` and `future`."
        )
      }
    } else if (backend == "mirai") {
      # mirai is available - check if we have enough daemons
      n_connections <- mirai_connection_count()
      if (n_connections == 1 && !.is_test()) {
        warn_pkg(
          "Consider using multiple mirai daemons for concurrency",
          c(
            "!" = "{.code oauth_module_server(async = TRUE)} but with a single mirai daemon",
            "i" = "Tasks are offloaded but concurrent jobs may queue. Consider using more daemons"
          )
        )
      }
    } else if (backend == "future" && !.is_test()) {
      # future is available - inform user that mirai is preferred
      inform_pkg(
        "Using {.pkg future} async backend",
        c(
          "i" = "Consider migrating to {.pkg mirai} for lower overhead and non-blocking dispatch",
          "i" = "See {.url https://github.com/shikokuchuo/mirai} for migration guide"
        ),
        .frequency = "once",
        .frequency_id = "oauth_module_server_future_backend"
      )
    }

    if (!.is_test()) {
      warn_about_async_otel_workers()
    }
  }

  # 2 Shiny module -------------------------------------------------------------

  shiny::moduleServer(id, function(input, output, session) {
    exclude_oauth_module_bookmarks(session)
    ## 2.1 Reactive values -----------------------------------------------------

    # Set browser token initial value to "__SKIPPED__" in test mode
    browser_token_initial <- NULL
    if (isTRUE(allow_skip_browser_token())) {
      browser_token_initial <- "__SKIPPED__"
    }

    # Core reactive values
    values <- shiny::reactiveValues(
      token = NULL,
      error = NULL,
      error_description = NULL,
      error_uri = NULL,
      authenticated = FALSE,
      token_stale = FALSE,
      browser_token = browser_token_initial,
      pending_callback = NULL,
      pending_login = FALSE,
      auto_redirected = FALSE,
      reauth_triggered = FALSE,
      auth_started_at = NA_real_,
      last_login_async_used = FALSE,
      refresh_in_progress = FALSE,
      refresh_last_attempt_at = NA_real_,
      refresh_last_success_at = NA_real_,
      refresh_next_attempt_at = 0,
      refresh_success_generation = 0L,
      refresh_failure_count = 0L
    )

    # Authentication work can outlive the state that launched it. Keep a
    # non-reactive lifecycle epoch and per-operation owner IDs so late promise
    # callbacks cannot install credentials or overwrite newer state.
    auth_operations <- new.env(parent = emptyenv())
    auth_operations$epoch <- 0
    auth_operations$next_id <- 0
    auth_operations$active_login_id <- NULL
    auth_operations$active_refresh_id <- NULL
    auth_operations$session_active <- TRUE
    auth_operations$force_oidc_reauth <- FALSE

    .advance_auth_epoch <- function() {
      auth_operations$epoch <- auth_operations$epoch + 1
      auth_operations$active_login_id <- NULL
      auth_operations$active_refresh_id <- NULL
      values$refresh_in_progress <- FALSE
      values$refresh_next_attempt_at <- 0
      values$refresh_failure_count <- 0L
      invisible(auth_operations$epoch)
    }

    .begin_auth_operation <- function(kind, source_token, new_epoch = FALSE) {
      if (isTRUE(new_epoch)) {
        .advance_auth_epoch()
      }

      auth_operations$next_id <- auth_operations$next_id + 1
      operation <- list(
        epoch = auth_operations$epoch,
        id = auth_operations$next_id,
        source_token = source_token
      )
      auth_operations[[paste0("active_", kind, "_id")]] <- operation$id
      if (identical(kind, "refresh")) {
        values$refresh_in_progress <- TRUE
      }
      operation
    }

    .auth_operation_is_owner <- function(operation, kind) {
      isTRUE(auth_operations$session_active) &&
        identical(auth_operations$epoch, operation$epoch) &&
        identical(
          auth_operations[[paste0("active_", kind, "_id")]],
          operation$id
        )
    }

    .auth_operation_can_apply <- function(operation, kind) {
      .auth_operation_is_owner(operation, kind) &&
        identical(values$token, operation$source_token)
    }

    .finish_auth_operation <- function(operation, kind) {
      if (!isTRUE(.auth_operation_is_owner(operation, kind))) {
        return(invisible(FALSE))
      }

      auth_operations[[paste0("active_", kind, "_id")]] <- NULL
      if (identical(kind, "refresh")) {
        values$refresh_in_progress <- FALSE
      }
      invisible(TRUE)
    }

    .revoke_stale_credentials <- function(tok, shiny_session = NULL) {
      if (!S7::S7_inherits(tok, OAuthToken)) {
        return(invisible(NULL))
      }

      use_async_revocation <- isTRUE(async)
      try(
        revoke_token(
          client,
          tok,
          which = "refresh",
          async = use_async_revocation,
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
      try(
        revoke_token(
          client,
          tok,
          which = "access",
          async = use_async_revocation,
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
      invisible(NULL)
    }

    .interactive_auth_started_at <- function(tok) {
      now <- as.numeric(Sys.time())
      if (
        !S7::S7_inherits(tok, OAuthToken) ||
          !isTRUE(tok@id_token_validated)
      ) {
        return(now)
      }

      auth_time <- suppressWarnings(as.numeric(
        tok@id_token_claims[["auth_time"]] %||% NA_real_
      ))
      if (length(auth_time) != 1L || !is.finite(auth_time)) {
        return(now)
      }
      min(auth_time, now)
    }

    form_post_module_registry <- tryCatch(
      session$userData$shinyOAuth_form_post_module_registry,
      error = function(...) NULL
    )
    if (!is.environment(form_post_module_registry)) {
      form_post_module_registry <- new.env(parent = emptyenv())
      session$userData$shinyOAuth_form_post_module_registry <-
        form_post_module_registry
    }
    assign(id, TRUE, envir = form_post_module_registry)

    .form_post_module_registered <- function(module_id) {
      if (!is_valid_string(module_id)) {
        return(FALSE)
      }

      isTRUE(get0(
        module_id,
        envir = form_post_module_registry,
        inherits = FALSE,
        ifnotfound = FALSE
      ))
    }

    .mark_unclaimed_form_post_query <- function(query_string) {
      raw_query <- query_string %||% ""
      last_query <- tryCatch(
        session$userData$shinyOAuth_last_unclaimed_form_post_query,
        error = function(...) NULL
      )
      if (identical(last_query, raw_query)) {
        return(FALSE)
      }

      session$userData$shinyOAuth_last_unclaimed_form_post_query <- raw_query
      TRUE
    }

    # Export for tests
    shiny::exportTestValues(
      token = values$token,
      error = values$error,
      error_description = values$error_description,
      error_uri = values$error_uri,
      authenticated = values$authenticated,
      browser_token = values$browser_token,
      pending_callback = values$pending_callback,
      pending_login = values$pending_login,
      auto_redirected = values$auto_redirected,
      reauth_triggered = values$reauth_triggered,
      auth_started_at = values$auth_started_at,
      token_stale = values$token_stale,
      last_login_async_used = values$last_login_async_used,
      refresh_in_progress = values$refresh_in_progress,
      refresh_last_attempt_at = values$refresh_last_attempt_at,
      refresh_last_success_at = values$refresh_last_success_at,
      refresh_next_attempt_at = values$refresh_next_attempt_at,
      refresh_success_generation = values$refresh_success_generation,
      refresh_failure_count = values$refresh_failure_count
    )

    with_otel_span(
      "shinyOAuth.module.init",
      {
        try(
          audit_event(
            "session_started",
            context = list(
              module_id = id,
              ns_prefix = tryCatch(session$ns(""), error = function(...) {
                NA_character_
              }),
              client_provider = client@provider@name %||% NA_character_,
              client_issuer = client@provider@issuer %||% NA_character_,
              client_id_digest = string_digest(client@client_id)
            )
          ),
          silent = TRUE
        )
      },
      attributes = otel_client_attributes(
        client = client,
        module_id = id,
        phase = "module.init",
        extra = list(
          oauth.auto_redirect = isTRUE(auto_redirect),
          oauth.refresh_proactively = isTRUE(refresh_proactively),
          oauth.revoke_on_session_end = isTRUE(revoke_on_session_end),
          oauth.indefinite_session = isTRUE(indefinite_session),
          oauth.reauth_after_seconds = reauth_after_seconds %||% NULL,
          oauth.refresh_lead_seconds = refresh_lead_seconds,
          oauth.browser_cookie_samesite = browser_cookie_samesite,
          oauth.browser_cookie_path_root = otel_browser_cookie_path_root(
            browser_cookie_path
          )
        )
      ),
      parent = NA
    )

    ## 2.2 Session-end hooks ---------------------------------------------------

    # Capture session context now while we still have it (it won't be
    # available in onSessionEnded callback). Keep separate sync/async variants
    # so main-thread lifecycle events are not mislabeled as async workers.
    captured_session_end_context <- capture_shiny_session_context(
      is_async = FALSE
    )
    captured_session_end_async_context <- capture_shiny_session_context(
      is_async = TRUE
    )

    # Always log session end, regardless of revoke_on_session_end setting
    session$onSessionEnded(function() {
      auth_operations$session_active <- FALSE
      .advance_auth_epoch()

      # Capture authentication state at session end
      was_authenticated <- tryCatch(
        isTRUE(shiny::isolate(values$authenticated)),
        error = function(...) FALSE
      )

      # Audit: session ended (always emitted)
      try(
        audit_event(
          "session_ended",
          context = list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            was_authenticated = was_authenticated
          ),
          shiny_session = captured_session_end_context
        ),
        silent = TRUE
      )
    })

    # Session-end revocation: revoke tokens if configured
    if (isTRUE(revoke_on_session_end)) {
      session$onSessionEnded(function() {
        # Capture token at session end; may be NULL if never authenticated
        tok <- shiny::isolate(values$token)
        if (!is.null(tok)) {
          with_trace_id(
            NULL,
            with_otel_span(
              "shinyOAuth.session.end.revoke",
              {
                # Audit: session ending with revocation attempt
                try(
                  audit_event(
                    "session_ended_revoke",
                    context = list(
                      provider = client@provider@name %||% NA_character_,
                      issuer = client@provider@issuer %||% NA_character_,
                      client_id_digest = string_digest(client@client_id)
                    ),
                    shiny_session = captured_session_end_context
                  ),
                  silent = TRUE
                )
                # Best-effort revocation: async only when module async = TRUE
                use_async_revocation <- isTRUE(async)
                try(revoke_token(
                  client,
                  tok,
                  which = "refresh",
                  async = use_async_revocation,
                  shiny_session = if (isTRUE(use_async_revocation)) {
                    captured_session_end_async_context
                  } else {
                    captured_session_end_context
                  }
                ))
                try(revoke_token(
                  client,
                  tok,
                  which = "access",
                  async = use_async_revocation,
                  shiny_session = if (isTRUE(use_async_revocation)) {
                    captured_session_end_async_context
                  } else {
                    captured_session_end_context
                  }
                ))
              },
              attributes = otel_client_attributes(
                client = client,
                module_id = id,
                shiny_session = captured_session_end_context,
                phase = "session.end.revoke"
              ),
              parent = NA
            )
          )
        }
      })
    }

    ## 2.3 Error handling helpers ----------------------------------------------

    # Internal helper: write the module's exposed error fields.
    # Used throughout `oauth_module_server()` whenever login, callback, or
    # refresh work fails, so reactive error state stays consistent.
    # @param code Stable module error code.
    # @param e Optional condition to format.
    # @param phase Optional phase label passed to `oauth_module_compose_error()`.
    # @param description Optional explicit user-facing description.
    # @return No return value; mutates `values$error`,
    #   `values$error_description`, and `values$error_uri`.
    .set_error <- function(code, e = NULL, phase = NULL, description = NULL) {
      values$error <- code
      values$error_description <- description %||%
        if (!is.null(e)) oauth_module_compose_error(e, phase) else NULL
      # Internal errors never carry error_uri; clear any stale provider value.
      values$error_uri <- NULL
    }

    ## 2.4 Browser token cookie ------------------------------------------------

    # Manage a first-party cookie marker plus an origin-scoped binding record.
    # Only the binding token is mirrored into input$shinyOAuth_sid; the marker
    # alone cannot restore the binding on another origin.
    shiny::observeEvent(
      TRUE,
      {
        .set_browser_token()
      },
      once = TRUE
    )

    # Mirror input to values$browser_token with validation and auto-repair
    shiny::observeEvent(
      input$shinyOAuth_sid,
      {
        if (!isTRUE(browser_ack$accept_input)) {
          return(invisible(NULL))
        }
        tok <- tryCatch(
          as.character(input$shinyOAuth_sid)[1],
          error = function(...) NULL
        )
        # In test/interactive mode when skip_browser_token is enabled, keep the
        # synthetic sentinel and do not clobber it on initial NULL input.
        if (isTRUE(allow_skip_browser_token()) && !is_valid_string(tok)) {
          return(invisible(NULL))
        }
        # Validate incoming token; if invalid, request regeneration and audit
        is_valid <- FALSE
        if (!is.null(tok)) {
          is_valid <- tryCatch(
            {
              validate_browser_token(tok)
              TRUE
            },
            error = function(e) FALSE
          )
        }
        if (is_valid) {
          values$browser_token <- tok
        } else {
          # Do not accept invalid tokens; attempt regeneration via JS and audit once
          values$browser_token <- NULL
          # Emit an audit trail entry for visibility (no sensitive values)
          len <- tryCatch(nchar(tok, type = "bytes"), error = function(...) {
            NA_integer_
          })
          try(
            audit_event(
              "invalid_browser_token",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                reason = "validation_failed",
                length = len
              )
            ),
            silent = TRUE
          )
          # Ask browser to (re)issue a proper cookie
          .set_browser_token()
        }
      },
      ignoreInit = FALSE
    )

    # Observe cookie/WebCrypto errors reported by the injected JS. If cookies
    # are blocked or WebCrypto is unavailable, authentication can't proceed.
    shiny::observeEvent(
      input$shinyOAuth_cookie_error,
      {
        reason <- input$shinyOAuth_cookie_error
        if (
          !is.character(reason) ||
            length(reason) != 1L ||
            is.na(reason) ||
            !reason %in%
              c(
                "webcrypto_unavailable",
                "samesite_none_requires_https",
                "cookie_unavailable",
                "storage_unavailable"
              )
        ) {
          reason <- "unknown"
        }

        # Surface a stable machine code and a concise description (do not show
        # description directly to end users; app authors can decide how to render).
        values$error <- "browser_cookie_error"
        values$error_description <- sprintf(
          "Browser cookie/storage/WebCrypto error: %s. Cookies, local storage, and Web Crypto must be available; authentication cannot proceed.",
          reason %||% "unknown"
        )

        # Stop any pending login loop to avoid repeated redirects while the
        # browser cannot store/read the cookie.
        values$pending_login <- FALSE
        if (!is.null(browser_ack$reject)) {
          browser_ack$reject(simpleError("Browser cookie unavailable"))
          browser_ack$reject <- NULL
          browser_ack$resolve <- NULL
        }

        # Emit an audit event with safe context
        proto <- tryCatch(
          session$clientData$url_protocol %||% NA_character_,
          error = function(...) NA_character_
        )
        try(
          audit_event(
            "browser_cookie_error",
            context = list(
              provider = client@provider@name %||% NA_character_,
              issuer = client@provider@issuer %||% NA_character_,
              client_id_digest = string_digest(client@client_id),
              reason = reason %||% NA_character_,
              url_protocol = proto
            )
          ),
          silent = TRUE
        )
      },
      ignoreInit = TRUE,
      once = TRUE
    )

    # Internal helper: compute browser-token cookie settings and ask the
    # browser to set the token. Used on first load, before login, and after
    # logout.
    # @return No return value; computes cookie settings and asks the browser to
    #   set the token.
    .set_browser_token <- function(request_id = NULL, token = NULL) {
      browser_ack$accept_input <- TRUE
      # Max age (sec); defaults to 300s (5 min) if state_store TTL is unavailable
      max_age_sec <- client_state_store_max_age(client)
      instance <- build_oauth_module_browser_token_instance(session, id)

      send_oauth_module_set_browser_token(
        session = session,
        instance = instance,
        max_age_ms = max_age_sec * 1000,
        same_site = browser_cookie_samesite,
        path = if (is.null(browser_cookie_path)) NULL else browser_cookie_path,
        request_id = request_id,
        token = token
      )
    }

    # Select the binding on the server for every new login. A request identifier
    # alone does not prevent a client from adopting a disclosed browser token.
    # The acknowledgment confirms delivery; it is not cookie-possession proof.
    browser_ack <- new.env(parent = emptyenv())
    browser_ack$generation <- 0L
    browser_ack$accept_input <- TRUE
    .with_fresh_browser_token <- function(body) {
      if (isTRUE(allow_skip_browser_token())) {
        return(body())
      }
      if (!is.null(browser_ack$reject)) {
        browser_ack$reject(simpleError("Browser cookie request superseded"))
      }
      request_id <- random_urlsafe(32)
      token <- paste(format(openssl::rand_bytes(64)), collapse = "")
      epoch <- auth_operations$epoch
      generation <- browser_ack$generation
      promise <- promises::promise(function(resolve, reject) {
        browser_ack$id <- request_id
        browser_ack$token <- token
        browser_ack$resolve <- resolve
        browser_ack$reject <- reject
        .set_browser_token(request_id, token)
        later::later(
          function() {
            if (
              identical(browser_ack$id, request_id) &&
                !is.null(browser_ack$reject)
            ) {
              browser_ack$reject(simpleError(
                "Browser cookie acknowledgment timed out"
              ))
              browser_ack$resolve <- NULL
              browser_ack$reject <- NULL
            }
          },
          delay = 10
        )
      })
      promises::then(promise, function(token) {
        if (
          !isTRUE(auth_operations$session_active) ||
            !identical(epoch, auth_operations$epoch) ||
            !identical(generation, browser_ack$generation) ||
            !identical(browser_ack$id, request_id)
        ) {
          return(NA_character_)
        }
        values$browser_token <- token
        values$pending_login <- FALSE
        body()
      }) |>
        promises::catch(function(e) {
          if (
            identical(browser_ack$id, request_id) &&
              identical(epoch, auth_operations$epoch) &&
              isTRUE(auth_operations$session_active)
          ) {
            values$pending_login <- FALSE
            .set_error("browser_cookie_error", e, phase = "browser_cookie_ack")
          }
          NA_character_
        })
    }
    shiny::observeEvent(
      input$shinyOAuth_cookie_ack,
      {
        ack <- input$shinyOAuth_cookie_ack
        if (
          is.list(ack) &&
            identical(ack$requestId, browser_ack$id) &&
            !is.null(browser_ack$resolve)
        ) {
          valid <- tryCatch(
            {
              validate_browser_token(input$shinyOAuth_sid)
              constant_time_compare(input$shinyOAuth_sid, browser_ack$token)
            },
            error = function(e) FALSE
          )
          if (valid) {
            browser_ack$resolve(browser_ack$token)
            browser_ack$resolve <- NULL
            browser_ack$reject <- NULL
          }
        }
      },
      ignoreInit = TRUE
    )

    # Internal helper: clear the browser token cookie and reset matching
    # server-side state. Used after successful login, during logout, and when
    # the session binding must be reset.
    # @return No return value; clears the browser cookie and resets related
    #   module state.
    .clear_browser_token <- function() {
      # Invalidate both pending acknowledgments and already-queued promise
      # continuations before clearing the browser or reactive state.
      reject <- browser_ack$reject
      browser_ack$generation <- browser_ack$generation + 1L
      browser_ack$accept_input <- FALSE
      browser_ack$id <- NULL
      browser_ack$token <- NULL
      browser_ack$resolve <- NULL
      browser_ack$reject <- NULL
      if (!is.null(reject)) {
        reject(simpleError("Browser binding cleared"))
      }
      instance <- build_oauth_module_browser_token_instance(session, id)

      send_oauth_module_clear_browser_token(
        session = session,
        instance = instance,
        same_site = browser_cookie_samesite,
        path = if (is.null(browser_cookie_path)) NULL else browser_cookie_path
      )
      values$browser_token <- NULL
      # Reset redirect guard after a successful round-trip so future
      # logins/reauths that need to reissue the cookie won't stall.
      values$auto_redirected <- FALSE
      # Clear any pending login request; a fresh request will be set if needed
      values$pending_login <- FALSE
    }

    # Internal helper: check whether the module currently has a usable browser
    # token. Used before login and callback work that depends on
    # browser-session binding.
    # @return `TRUE` when `values$browser_token` is usable, otherwise `FALSE`.
    .has_browser_token <- function() {
      # Check if we have a browser token
      if (is_valid_string(values$browser_token)) {
        return(TRUE)
      }
      return(FALSE)
    }

    ## 2.5 Authentication state ------------------------------------------------

    # Internal helper: compute whether the current module state counts as
    # authenticated. Used by `.is_authenticated_now()` and the authenticated
    # observer.
    # @return `TRUE` when the current token or session state should count as
    #   authenticated.
    .compute_authenticated <- function() {
      # In indefinite_session mode we ignore module error flags when computing
      # authenticated; otherwise, any error flips authenticated to FALSE
      no_error <- if (isTRUE(indefinite_session)) {
        TRUE
      } else {
        is.null(values$error) && is.null(values$error_description)
      }
      tok <- values$token
      if (is.null(tok) || !no_error) {
        return(FALSE)
      }

      now <- as.numeric(Sys.time())

      # Optional maximum interactive-authentication age (reauth window).
      # Ignored when indefinite_session = TRUE
      if (!isTRUE(indefinite_session) && !is.null(reauth_after_seconds)) {
        started <- tryCatch(values$auth_started_at, error = function(...) {
          NA_real_
        })
        if (is.finite(started) && !is.na(started)) {
          if ((now - started) >= reauth_after_seconds) {
            return(FALSE)
          }
        }
      }

      # Expiry-aware check that tolerates Inf or NA. Ignored when
      # indefinite_session = TRUE
      if (!isTRUE(indefinite_session)) {
        exp <- tryCatch(tok@expires_at, error = function(...) NA_real_)
        if (is.finite(exp) && !is.na(exp)) {
          if (now >= exp) {
            return(FALSE)
          }
        }
      }
      # If exp is NA or Inf, treat as not expired here.
      TRUE
    }

    # Internal helper: read the latest authenticated state immediately.
    # Used by login helpers during redirect decisions without waiting for the
    # observer to flush `values$authenticated`.
    # @return Latest authentication boolean computed from current module state.
    .is_authenticated_now <- function() {
      # Refresh failures can clear token/error and immediately request reauth
      # before the authenticated observer has flushed its cached flag.
      isTRUE(.compute_authenticated())
    }

    # Keep authenticated in sync like other values; store a plain logical
    # Also emit audit event when authenticated state changes
    .previous_authenticated <- FALSE
    shiny::observe({
      # depend on these so we recalc when any changes
      values$token
      values$error
      values$error_description
      values$browser_token
      new_authenticated <- .compute_authenticated()

      # Schedule a timer to re-evaluate at the next relevant expiry boundary
      # so that authenticated flips promptly even without other reactive changes.
      # This addresses the gap where .compute_authenticated() uses Sys.time()
      # but the observer only recalculates on reactive dependency changes.
      if (isTRUE(new_authenticated) && !isTRUE(indefinite_session)) {
        tok <- values$token
        now <- as.numeric(Sys.time())
        next_boundary <- Inf

        # Check token expiry boundary
        if (!is.null(tok)) {
          exp <- tryCatch(tok@expires_at, error = function(...) NA_real_)
          if (is.finite(exp) && !is.na(exp) && exp > now) {
            next_boundary <- min(next_boundary, exp - now)
          }
        }

        # Check reauth_after_seconds boundary
        if (!is.null(reauth_after_seconds)) {
          started <- tryCatch(values$auth_started_at, error = function(...) {
            NA_real_
          })
          if (is.finite(started) && !is.na(started)) {
            reauth_at <- started + reauth_after_seconds
            if (reauth_at > now) {
              next_boundary <- min(next_boundary, reauth_at - now)
            }
          }
        }

        # Schedule wakeup at boundary + small buffer to ensure we're past it
        if (is.finite(next_boundary) && next_boundary > 0) {
          wake_ms <- shiny_timer_delay_ms(
            next_boundary,
            buffer_seconds = 0.05
          )
          shiny::invalidateLater(wake_ms, session)
        }
      }

      # Emit audit event if authenticated state changed
      if (!identical(new_authenticated, .previous_authenticated)) {
        # Derive reason from current state
        reason <- if (isTRUE(new_authenticated)) {
          "login"
        } else if (!is.null(values$error)) {
          values$error
        } else if (is.null(values$token)) {
          "token_cleared"
        } else {
          "unknown"
        }

        try(
          audit_event(
            "authenticated_changed",
            context = list(
              provider = client@provider@name %||% NA_character_,
              issuer = client@provider@issuer %||% NA_character_,
              client_id_digest = string_digest(client@client_id),
              authenticated = new_authenticated,
              previous_authenticated = .previous_authenticated,
              reason = reason
            )
          ),
          silent = TRUE
        )
        .previous_authenticated <<- new_authenticated
      }

      values$authenticated <- new_authenticated
    })

    # Keep token_stale consistent when the token changes directly
    # If a fresh (non-expired) token is set, or the token is cleared,
    # reset the stale flag to FALSE. This covers unit tests and manual
    # flows that assign values$token without going through login/refresh
    # helpers where we also reset the flag.
    shiny::observeEvent(
      values$token,
      {
        tok <- values$token
        if (is.null(tok)) {
          values$token_stale <- FALSE
        } else {
          exp <- tryCatch(tok@expires_at, error = function(...) NA_real_)
          now <- as.numeric(Sys.time())
          # If expiry is unknown (NA/Inf) or in the future, this token isn't stale
          if (!is.finite(exp) || is.na(exp) || now < exp) {
            values$token_stale <- FALSE
          }
        }
      },
      ignoreInit = FALSE
    )

    ## 2.6 Authorization URL and redirection helpers ---------------------------

    # Internal helper: warn when code tries to start a new login while already
    # authenticated.
    # @param action Helper name that attempted to start login.
    # @return Invisibly returns `FALSE` after emitting a warning.
    .warn_about_authenticated_login_request <- function(action) {
      warn_pkg(
        "Ignoring OAuth login request while already authenticated",
        c(
          "i" = paste0(
            "`",
            action,
            "()` does not start a new OAuth flow when `authenticated` is TRUE."
          ),
          "i" = "Call `logout()` first if you need to start a fresh authorization flow."
        ),
        class = "shinyOAuth_authenticated_login_request",
        .frequency = "once",
        .frequency_id = paste0(
          "shinyOAuth-authenticated-login-request-",
          action
        )
      )

      invisible(FALSE)
    }

    # Internal helper: build the next login URL and convert failures into
    # module error state. Used by `.initiate_login()` and the public
    # `values$build_auth_url()` helper.
    # @return Authorization URL string, or `NA_character_` after recording a
    #   module error.
    .build_auth_url <- function() {
      if (.is_authenticated_now()) {
        .warn_about_authenticated_login_request("build_auth_url")
        return(NA_character_)
      }

      # If no browser token yet, defer URL building (return NA) so callers can
      # render a button/link reactively once the cookie arrives
      if (!.has_browser_token()) {
        abort_pkg(
          "No browser token available",
          c(
            "i" = paste(
              "Call `has_browser_token()` to check and `set_browser_token()`",
              "to set one before calling `build_auth_url()`"
            )
          ),
          class = c("shinyOAuth_state_error", "shinyOAuth_error"),
          call = rlang::current_env()
        )
      }

      publisher <- function(
        request_object,
        request_handle_id,
        expires_at,
        oauth_client
      ) {
        publish_shiny_request_object(
          session,
          request_object,
          request_handle_id,
          expires_at,
          base_url = request_uri_base_url
        )
      }
      requested_max_age <- if (
        isTRUE(auth_operations$force_oidc_reauth) &&
          provider_uses_oidc(client@provider)
      ) {
        0
      } else {
        NULL
      }
      provider_work <- is_valid_string(client@provider@par_url) ||
        !identical(client@request_object_mode, "parameters")
      if (!isTRUE(async) || !provider_work) {
        return(tryCatch(
          prepare_call(
            client,
            values$browser_token,
            publisher,
            requested_max_age
          ),
          error = function(e) {
            .set_error("auth_url_error", e, phase = "build_auth_url")
            NA_character_
          }
        ))
      }

      operation <- .begin_auth_operation(
        "authorization",
        source_token = values$token,
        new_epoch = TRUE
      )
      browser <- values$browser_token
      prepared <- NULL
      cleanup <- function() {
        if (!is.null(prepared)) {
          try(client@state_store$remove(prepared$state_key), silent = TRUE)
        }
      }
      fail <- function(e) {
        cleanup()
        if (.auth_operation_can_apply(operation, "authorization")) {
          .set_error("auth_url_error", e, phase = "build_auth_url")
          .finish_auth_operation(operation, "authorization")
        }
        NA_character_
      }
      tryCatch(
        {
          prepared <- prepare_call(
            client,
            browser,
            .requested_max_age = requested_max_age,
            .defer_build = TRUE
          )
          worker <- prepare_client_for_worker(client)
          if (is.null(worker)) {
            err_config(
              "Authorization client cannot be serialized for async work"
            )
          }
          async_dispatch(
            quote({
              .ns <- asNamespace("shinyOAuth")
              .ns$with_async_options(captured_options, {
                .ns$with_async_session_context(
                  captured_session,
                  .ns$build_prepared_authorization(worker, prepared)
                )
              })
            }),
            args = list(
              worker = worker,
              prepared = prepared,
              captured_options = capture_async_options(),
              captured_session = capture_shiny_session_context()
            ),
            otel_context = list(
              headers = prepared$otel_headers,
              worker_span_name = "shinyOAuth.login.request.worker",
              shiny_session = capture_shiny_session_context(),
              attributes = otel_client_attributes(
                client,
                module_id = id,
                async = TRUE,
                phase = "login.request.worker"
              )
            )
          ) |>
            promises::then(function(raw) {
              if (
                !.auth_operation_can_apply(operation, "authorization") ||
                  !identical(values$browser_token, browser)
              ) {
                cleanup()
                return(NA_character_)
              }
              result <- replay_async_conditions(raw)
              url <- finish_prepared_authorization(
                result,
                client,
                prepared,
                publisher
              )
              .finish_auth_operation(operation, "authorization")
              url
            }) |>
            promises::catch(fail)
        },
        error = fail
      )
    }

    # Internal helper: redirect the browser if there is a usable URL. Used by
    # `.initiate_login()` after `.build_auth_url()` succeeds.
    # @param url Candidate authorization URL.
    # @return Invisibly returns `TRUE` when a redirect was sent, otherwise
    #   `FALSE`.
    .redirect_to <- function(url) {
      if (is.na(url)) {
        return(invisible(FALSE))
      }
      send_oauth_module_redirect(session, url)
      invisible(TRUE)
    }

    # Internal helper: start the browser redirect for a login request. Used by
    # `.request_login()` and pending-login resume logic.
    # @return No return value; may redirect the browser and set
    #   `values$auto_redirected`.
    .initiate_login <- function(cookie_acknowledged = FALSE) {
      if (!cookie_acknowledged) {
        return(.with_fresh_browser_token(function() .initiate_login(TRUE)))
      }
      values$pending_login <- FALSE
      url <- .build_auth_url()
      epoch <- auth_operations$epoch
      redirect <- function(url) {
        if (
          !isTRUE(auth_operations$session_active) ||
            !identical(epoch, auth_operations$epoch) ||
            .is_authenticated_now()
        ) {
          return(invisible(FALSE))
        }
        if (isTRUE(.redirect_to(url))) {
          values$auto_redirected <- TRUE
        }
        invisible(NULL)
      }
      if (inherits(url, "promise")) {
        promises::then(url, redirect)
      } else {
        redirect(url)
      }
    }

    # Internal helper: request a login, ensuring the browser token exists
    # first. Used by auto-redirect, manual login, and reauthentication.
    # @return Invisibly returns `FALSE` only when the request is rejected
    #   because the session is already authenticated.
    .request_login <- function() {
      if (.is_authenticated_now()) {
        .warn_about_authenticated_login_request("request_login")
        return(invisible(FALSE))
      }

      values$pending_login <- TRUE
      if (isTRUE(allow_skip_browser_token()) && !.has_browser_token()) {
        .set_browser_token()
      } else {
        .initiate_login()
      }
      invisible(TRUE)
    }

    # Expose helpers for manual login flows when `auto_redirect = FALSE`.

    # Module value helper: set or refresh the browser token cookie.
    # Used by app code when manual login flows need to prepare the browser
    # session before building an authorization URL.
    # @return No return value; sends a browser-token message.
    values$set_browser_token <- function() {
      .set_browser_token()
    }

    # Module value helper: clear the browser token cookie.
    # Used by app code when it needs to reset the browser-session binding
    # outside the built-in logout flow.
    # @return No return value; clears browser and server token state.
    values$clear_browser_token <- function() {
      .clear_browser_token()
    }

    # Module value helper: report browser-token availability.
    # Used by app code to decide whether an auth URL can be built yet.
    # @return `TRUE` when a browser token is available, otherwise `FALSE`.
    values$has_browser_token <- function() {
      .has_browser_token()
    }

    # Module value helper: build the next authorization URL.
    # Used by app code in manual login flows when it wants to render a link or
    # button target instead of redirecting immediately.
    # @return Authorization URL string, or `NA_character_` after recording a
    #   module error.
    values$build_auth_url <- function() {
      .with_fresh_browser_token(.build_auth_url)
    }

    # Module value helper: request a login redirect.
    # Used by app code in manual login flows when a click or other event should
    # start authentication.
    # @return Invisibly returns `FALSE` only when the request is rejected
    #   because the session is already authenticated.
    values$request_login <- function() {
      .request_login()
    }

    # Internal helper: expose a logout helper that revokes tokens best-effort
    # and clears session state. Used by app code through `values$logout()`.
    # @param reason Optional logout reason string for audit trails.
    # @return No return value; clears module auth state, rotates the browser
    #   token, and emits logout side effects.
    values$logout <- function(reason = "manual_logout") {
      logout_shiny_session <- capture_shiny_session_context(is_async = FALSE)
      logout_async_shiny_session <- if (isTRUE(async)) {
        capture_shiny_session_context(is_async = TRUE)
      } else {
        NULL
      }
      with_trace_id(
        NULL,
        with_otel_span(
          "shinyOAuth.logout",
          {
            # Best-effort: revoke provider tokens asynchronously if supported.
            # Fire-and-forget so logout returns immediately.
            tok <- values$token
            .advance_auth_epoch()
            auth_operations$force_oidc_reauth <- FALSE
            if (!is.null(tok)) {
              # Async revocation follows module async setting
              use_async_revocation <- isTRUE(async)
              try(revoke_token(
                client,
                tok,
                which = "refresh",
                async = use_async_revocation,
                shiny_session = if (isTRUE(use_async_revocation)) {
                  logout_async_shiny_session
                } else {
                  NULL
                }
              ))
              try(revoke_token(
                client,
                tok,
                which = "access",
                async = use_async_revocation,
                shiny_session = if (isTRUE(use_async_revocation)) {
                  logout_async_shiny_session
                } else {
                  NULL
                }
              ))
            }

            # Clear token and browser cookie, emit audit trail
            try(
              audit_event(
                "logout",
                context = list(
                  provider = client@provider@name %||% NA_character_,
                  issuer = client@provider@issuer %||% NA_character_,
                  client_id_digest = string_digest(client@client_id),
                  reason = reason
                ),
                shiny_session = logout_shiny_session
              )
            )
            values$token <- NULL
            values$error <- "logged_out"
            values$error_description <- NULL
            values$error_uri <- NULL
            values$token_stale <- FALSE
            .clear_browser_token()
            # Proactively re-issue a fresh browser token so that a subsequent
            # manual login can redirect immediately without a preparatory click.
            # This maintains session binding without authenticating the user.
            .set_browser_token()
          },
          attributes = otel_client_attributes(
            client = client,
            module_id = id,
            phase = "logout"
          ),
          parent = NA
        )
      )
    }

    ## 2.7 Callback handling and auto-redirect ---------------------------------

    # Handle OAuth flow by listening to clientData$url_search
    shiny::observeEvent(
      session$clientData$url_search,
      {
        .process_query(
          shiny::isolate(session$clientData$url_search) %||% "",
          current_uri = shiny::isolate(
            oauth_shiny_session_callback_uri(session)
          ) %||%
            NA_character_
        )
      },
      priority = 100
    )

    # Internal helper: query-based JARM reserves `response` on the configured
    # callback path, even when the value is not a compact JWT.
    .query_response_is_reserved_callback <- function(
      query_string,
      query_jarm_client = FALSE,
      current_path = NULL,
      current_uri = NULL
    ) {
      if (!isTRUE(query_jarm_client)) {
        return(FALSE)
      }

      if (!length(oauth_module_query_raw_values(query_string, "response"))) {
        return(FALSE)
      }

      .callback_route_matches(
        current_uri = current_uri,
        current_path = current_path
      )
    }

    # Internal helper: compare the browser-visible scheme, authority, and path
    # to this client's configured redirect URI. The current path-only argument
    # remains available for internal tests; live observers always pass the
    # complete browser URI.
    .callback_route_matches <- function(
      current_uri = NULL,
      current_path = NULL
    ) {
      if (!is.null(current_uri)) {
        if (!is_valid_string(current_uri)) {
          return(FALSE)
        }
        return(isTRUE(oauth_callback_route_matches(
          current_uri,
          client@redirect_uri
        )))
      }

      callback_path <- tryCatch(
        normalize_oauth_form_post_callback_path(
          httr2::url_parse(client@redirect_uri)[["path"]] %||% "/"
        ),
        error = function(...) "/"
      )
      if (!is.null(current_path)) {
        normalized_path <- tryCatch(
          normalize_oauth_form_post_callback_path(as.character(current_path)),
          error = function(...) NA_character_
        )
        return(identical(normalized_path, callback_path))
      }

      # Direct calls to the internal test hook historically supplied only the
      # query string. Treat those as the configured route. The live observer
      # above never takes this fallback because it supplies `current_uri`.
      TRUE
    }

    # Internal helper: decide whether an already-authenticated module should
    # clear callback-like query params immediately. Foreign registered
    # form_post handles must remain in the URL so the owning module can bridge
    # or reject them.
    # @param query_string Current browser query string.
    # @return `TRUE` when this module should clear the callback query now.
    .should_clear_authenticated_callback_query <- function(
      query_string,
      current_path = NULL,
      current_uri = NULL
    ) {
      configured_jarm_transport <- resolve_jarm_callback_transport(client)
      query_jarm_client <- identical(
        configured_jarm_transport$transport %||% NULL,
        "query"
      )
      response_is_callback <- .query_response_is_reserved_callback(
        query_string,
        query_jarm_client = query_jarm_client,
        current_path = current_path,
        current_uri = current_uri
      )

      if (
        !isTRUE(oauth_module_query_has_callback_keys(
          query_string,
          query_jarm_client = query_jarm_client,
          response_is_callback = response_is_callback
        ))
      ) {
        return(FALSE)
      }

      parsed <- tryCatch(
        shiny::parseQueryString(query_string %||% ""),
        error = function(...) list()
      )
      form_post_handle <- parsed[[oauth_form_post_handle_param]] %||% NULL
      if (is.null(form_post_handle)) {
        return(TRUE)
      }

      form_post_id <- parsed[[oauth_form_post_id_param]] %||% NULL
      if (identical(form_post_id, id)) {
        return(TRUE)
      }
      if (!is_valid_string(form_post_id)) {
        return(TRUE)
      }

      !isTRUE(.form_post_module_registered(form_post_id))
    }

    # Internal helper: surface callback-query validation failures before any
    # state or token handling runs.
    .reject_callback_query <- function(
      description,
      reason = NULL,
      drop_response = FALSE,
      error_code = "invalid_callback_query"
    ) {
      clear_oauth_module_callback_query(
        session,
        tab_title_replacement,
        tab_title_cleaning,
        drop_response = drop_response
      )
      .set_error(
        error_code,
        NULL,
        phase = "callback_query_validation",
        description = description
      )
      try(
        audit_event(
          "callback_query_rejected",
          context = compact_list(list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            error_class = error_code,
            phase = "callback_query_validation",
            reason = reason %||% NULL
          ))
        ),
        silent = TRUE
      )

      invisible(NULL)
    }

    # Internal helper: process the current URL query string. Decides whether
    # to log in, handle a callback, or surface an error. Used by the
    # `url_search` observer and test hooks.
    # @param query_string Current browser query string.
    # @return No return value; updates module state, clears query params, or
    #   triggers login or callback handling.
    .process_query <- function(
      query_string,
      current_path = NULL,
      current_uri = NULL
    ) {
      # Defensive: cap untrusted callback query sizes to reduce DoS surface.
      # Apply a pre-parse guard on the raw query string so that
      # shiny::parseQueryString() doesn't have to process arbitrarily long
      # input.  This MUST run before any code path that parses the query,
      # including the "already authenticated" early-return branch.
      limits <- oauth_callback_limits()
      configured_jarm_transport <- resolve_jarm_callback_transport(client)
      jarm_client <- !is.null(configured_jarm_transport)
      query_jarm_client <- identical(
        configured_jarm_transport[["transport"]] %||% NULL,
        "query"
      )

      # Validate raw query size before any parsing (including the
      # already-authenticated branch that checks for OAuth callback keys).
      query_size_ok <- tryCatch(
        {
          validate_untrusted_query_string(
            query_string %||% "",
            max_bytes = limits[["query"]]
          )
          TRUE
        },
        error = function(e) {
          clear_oauth_module_callback_query(
            session,
            tab_title_replacement,
            tab_title_cleaning,
            drop_response = query_jarm_client
          )
          .set_error(
            "invalid_callback_query",
            e,
            phase = "callback_query_validation"
          )
          try(
            audit_event(
              "callback_query_rejected",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                error_class = paste(class(e), collapse = ", ")
              )
            ),
            silent = TRUE
          )
          FALSE
        }
      )

      if (!isTRUE(query_size_ok)) {
        return(invisible(NULL))
      }

      # Route callback-looking queries before parsing any parameter values or
      # touching sealed/single-use state. Every module observes the same Shiny
      # URL, so this boundary prevents a module for one authorization server
      # from consuming a response delivered to another server's redirect URI.
      callback_keys_present <- oauth_module_query_has_callback_keys(
        query_string,
        query_jarm_client = query_jarm_client,
        response_is_callback = isTRUE(query_jarm_client) &&
          length(oauth_module_query_raw_values(query_string, "response")) > 0L
      )
      if (
        isTRUE(callback_keys_present) &&
          !isTRUE(.callback_route_matches(
            current_uri = current_uri,
            current_path = current_path
          ))
      ) {
        return(invisible(NULL))
      }

      response_is_reserved_for_query_jarm <-
        .query_response_is_reserved_callback(
          query_string,
          query_jarm_client = query_jarm_client,
          current_path = current_path,
          current_uri = current_uri
        )

      if (!is.null(values$token)) {
        if (
          isTRUE(.should_clear_authenticated_callback_query(
            query_string,
            current_path = current_path,
            current_uri = current_uri
          ))
        ) {
          clear_oauth_module_callback_query(
            session,
            tab_title_replacement,
            tab_title_cleaning,
            drop_response = response_is_reserved_for_query_jarm
          )
        }
        return(invisible(NULL))
      }

      qs <- NULL
      query_response <- NULL
      query_code <- NULL
      query_state <- NULL
      query_error <- NULL
      query_error_description <- NULL
      query_error_uri <- NULL
      query_iss <- NULL
      query_form_post_handle <- NULL
      query_form_post_id <- NULL
      ok <- tryCatch(
        {
          reject_duplicate_oauth_module_callback_query(
            query_string %||% "",
            query_jarm_client = query_jarm_client,
            response_is_callback = response_is_reserved_for_query_jarm
          )
          qs <- shiny::parseQueryString(query_string %||% "")
          query_response <- qs[["response"]]
          query_code <- qs[["code"]]
          query_state <- qs[["state"]]
          query_error <- qs[["error"]]
          query_error_description <- qs[["error_description"]]
          query_error_uri <- qs[["error_uri"]]
          query_iss <- qs[["iss"]]
          query_form_post_handle <- qs[[
            oauth_form_post_handle_param,
            exact = TRUE
          ]]
          query_form_post_id <- qs[[oauth_form_post_id_param]]

          validate_untrusted_query_param(
            "code",
            query_code,
            max_bytes = limits[["code"]]
          )
          if (!is.null(query_response)) {
            validate_untrusted_query_param(
              "response",
              query_response,
              max_bytes = limits[["query"]]
            )
          }
          validate_untrusted_query_param(
            "state",
            query_state,
            max_bytes = limits[["state"]]
          )
          validate_untrusted_query_param(
            "error",
            query_error,
            max_bytes = limits[["error"]]
          )
          validate_untrusted_query_param(
            "error_description",
            query_error_description,
            max_bytes = limits[["error_description"]],
            allow_empty = TRUE
          )
          validate_untrusted_query_param(
            "error_uri",
            query_error_uri,
            max_bytes = limits[["error_uri"]],
            allow_empty = TRUE
          )
          validate_untrusted_query_param(
            "iss",
            query_iss,
            max_bytes = limits[["iss"]]
          )
          validate_untrusted_query_param(
            oauth_form_post_handle_param,
            query_form_post_handle,
            max_bytes = limits[["form_post_handle"]]
          )
          validate_untrusted_query_param(
            oauth_form_post_id_param,
            query_form_post_id,
            max_bytes = limits[["form_post_id"]]
          )
          TRUE
        },
        error = function(e) {
          clear_oauth_module_callback_query(
            session,
            tab_title_replacement,
            tab_title_cleaning,
            drop_response = response_is_reserved_for_query_jarm
          )
          .set_error(
            "invalid_callback_query",
            e,
            phase = "callback_query_validation"
          )
          try(
            audit_event(
              "callback_query_rejected",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                error_class = paste(class(e), collapse = ", ")
              )
            ),
            silent = TRUE
          )
          FALSE
        }
      )
      if (!isTRUE(ok)) {
        return(invisible(NULL))
      }

      form_post_handle <- query_form_post_handle
      if (!is.null(form_post_handle)) {
        form_post_id <- query_form_post_id
        if (is.null(form_post_id)) {
          clear_oauth_module_callback_query(
            session,
            tab_title_replacement,
            tab_title_cleaning,
            drop_response = response_is_reserved_for_query_jarm
          )
          .set_error(
            "invalid_callback_query",
            NULL,
            phase = "form_post_callback_query",
            description = "form_post callback handle is missing module id"
          )
          try(
            audit_event(
              "callback_query_rejected",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                handle_digest = string_digest(form_post_handle),
                error_class = "invalid_callback_query",
                phase = "form_post_callback_query",
                reason = "missing_form_post_id"
              )
            ),
            silent = TRUE
          )
          return(invisible(NULL))
        }
        if (!identical(form_post_id, id)) {
          if (
            !isTRUE(.form_post_module_registered(form_post_id)) &&
              isTRUE(.mark_unclaimed_form_post_query(query_string))
          ) {
            clear_oauth_module_callback_query(
              session,
              tab_title_replacement,
              tab_title_cleaning,
              drop_response = response_is_reserved_for_query_jarm
            )
            .set_error(
              "invalid_callback_query",
              NULL,
              phase = "form_post_callback_query",
              description = "form_post callback handle references unknown module id"
            )
            try(
              audit_event(
                "callback_query_rejected",
                context = list(
                  provider = client@provider@name %||% NA_character_,
                  issuer = client@provider@issuer %||% NA_character_,
                  client_id_digest = string_digest(client@client_id),
                  handle_digest = string_digest(form_post_handle),
                  target_module_id = form_post_id,
                  error_class = "invalid_callback_query",
                  phase = "form_post_callback_query",
                  reason = "unknown_form_post_id"
                )
              ),
              silent = TRUE
            )
          }
          return(invisible(NULL))
        }
        response_param <- query_response
        code_param <- query_code
        error_param <- query_error
        state_param <- query_state
        response_param_conflicts <- isTRUE(
          oauth_module_query_has_jarm_response(response_param)
        )
        if (
          isTRUE(response_param_conflicts) ||
            !is.null(code_param) ||
            !is.null(error_param) ||
            !is.null(state_param)
        ) {
          clear_oauth_module_callback_query(
            session,
            tab_title_replacement,
            tab_title_cleaning,
            drop_response = !is.null(response_param)
          )
          .set_error(
            "invalid_callback_query",
            NULL,
            phase = "form_post_callback_query",
            description = paste(
              "form_post callback handles must not be combined with direct",
              "OAuth callback parameters"
            )
          )
          try(
            audit_event(
              "callback_query_rejected",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                handle_digest = string_digest(form_post_handle),
                error_class = "invalid_callback_query",
                phase = "form_post_callback_query",
                reason = "mixed_form_post_and_direct_callback_params"
              )
            ),
            silent = TRUE
          )
          return(invisible(NULL))
        }

        form_post_payload <- tryCatch(
          with_otel_span(
            "shinyOAuth.form_post.bridge",
            {
              oauth_form_post_store_take(client, id, form_post_handle)
            },
            attributes = otel_client_attributes(
              client = client,
              module_id = id,
              phase = "form_post.callback_lookup",
              extra = list(
                oauth.form_post.handle_digest = string_digest(
                  form_post_handle
                )
              )
            ),
            parent = NA
          ),
          error = function(e) {
            clear_oauth_module_callback_query(
              session,
              tab_title_replacement,
              tab_title_cleaning,
              drop_response = response_is_reserved_for_query_jarm
            )
            .set_error(
              oauth_module_callback_failure_error_code(e),
              e,
              phase = "form_post_callback_lookup"
            )
            try(
              audit_event(
                "callback_validation_failed",
                context = list(
                  provider = client@provider@name %||% NA_character_,
                  issuer = client@provider@issuer %||% NA_character_,
                  client_id_digest = string_digest(client@client_id),
                  state_digest = NA_character_,
                  handle_digest = string_digest(form_post_handle),
                  error_class = paste(class(e), collapse = ", "),
                  phase = "form_post_callback_lookup"
                )
              ),
              silent = TRUE
            )
            NULL
          }
        )
        if (is.null(form_post_payload)) {
          return(invisible(NULL))
        }

        if (identical(form_post_payload[["type"]], "response")) {
          normalized_response <- form_post_payload[[
            "normalized_response",
            exact = TRUE
          ]] %||%
            NULL
          if (
            is.list(normalized_response) && length(normalized_response) > 0L
          ) {
            .resume_cached_jarm_response(
              normalized_response = normalized_response,
              decrypted_payload = form_post_payload[[
                "state_payload",
                exact = TRUE
              ]] %||%
                NULL,
              phase = "form_post_callback_validation"
            )
            return(invisible(NULL))
          }

          .handle_jarm_response(
            response = form_post_payload[["response"]],
            transport = form_post_payload[["transport"]] %||% "form_post",
            decrypted_payload = form_post_payload[[
              "state_payload",
              exact = TRUE
            ]] %||%
              NULL,
            phase = "form_post_callback_validation"
          )
          return(invisible(NULL))
        }

        form_post_state_payload <- form_post_payload[[
          "state_payload",
          exact = TRUE
        ]] %||%
          NULL
        # The bridge handle is single-use, but logical state belongs to the
        # initiating browser. Shared callback handlers check browser binding
        # before consuming it, including deferred and async callbacks.
        form_post_state_store_values <- NULL

        if (identical(form_post_payload[["type"]], "error")) {
          clear_oauth_module_callback_query(
            session,
            tab_title_replacement,
            tab_title_cleaning
          )
          .handle_error_response(
            error = form_post_payload[["error"]],
            error_description = form_post_payload[[
              "error_description",
              exact = TRUE
            ]],
            error_uri = form_post_payload[["error_uri"]],
            state = form_post_payload[["state"]],
            iss = form_post_payload[["iss"]] %||% NULL,
            decrypted_payload = form_post_payload[[
              "state_payload",
              exact = TRUE
            ]] %||%
              NULL,
            state_store_values = form_post_state_store_values
          )
          return(invisible(NULL))
        }

        .handle_callback(
          code = form_post_payload[["code"]],
          state = form_post_payload[["state"]],
          iss = form_post_payload[["iss"]] %||% NULL,
          decrypted_payload = form_post_payload[[
            "state_payload",
            exact = TRUE
          ]] %||%
            NULL,
          state_store_values = form_post_state_store_values
        )
        return(invisible(NULL))
      }

      response <- query_response
      outer_iss <- query_iss %||% NULL
      direct_callback_params_present <- !all(vapply(
        list(
          query_code,
          query_state,
          query_error,
          query_error_description,
          query_error_uri
        ),
        is.null,
        logical(1)
      ))
      configured_jarm_transport <- resolve_jarm_callback_transport(client)
      response_looks_like_jarm <-
        isTRUE(oauth_module_query_has_jarm_response(response))
      response_is_jarm <-
        isTRUE(response_is_reserved_for_query_jarm) &&
        isTRUE(response_looks_like_jarm)
      response_is_invalid_query_jarm <-
        isTRUE(response_is_reserved_for_query_jarm) &&
        !isTRUE(response_is_jarm)

      if (
        isTRUE(response_looks_like_jarm) &&
          isTRUE(jarm_client) &&
          !isTRUE(query_jarm_client)
      ) {
        .reject_callback_query(
          description = paste(
            "JARM clients configured for",
            configured_jarm_transport$mode,
            "must not receive compact query response parameters; resume from",
            "the validated form_post callback handle instead."
          ),
          reason = "wrong_jarm_callback_transport",
          drop_response = TRUE
        )
        return(invisible(NULL))
      }

      if (isTRUE(response_is_jarm)) {
        if (isTRUE(direct_callback_params_present)) {
          .reject_callback_query(
            description = paste(
              "JARM response must not be combined with direct OAuth callback",
              "parameters"
            ),
            reason = "mixed_jarm_and_direct_callback_params",
            drop_response = TRUE
          )
          return(invisible(NULL))
        }

        .handle_jarm_response(
          response,
          transport = "query",
          outer_iss = outer_iss
        )
        return(invisible(NULL))
      }

      if (isTRUE(response_is_invalid_query_jarm)) {
        .reject_callback_query(
          description = paste(
            "Query-based JARM callbacks must carry a compact JWT in the",
            "response parameter."
          ),
          reason = "invalid_query_jarm_response",
          drop_response = TRUE
        )
        return(invisible(NULL))
      }

      if (isTRUE(jarm_client) && isTRUE(direct_callback_params_present)) {
        .reject_callback_query(
          description = if (isTRUE(query_jarm_client)) {
            paste(
              "JARM clients must receive the callback in the response",
              "parameter; direct OAuth callback parameters are not accepted."
            )
          } else {
            paste(
              "JARM clients must resume from the validated form_post",
              "callback handle; direct OAuth callback parameters are not",
              "accepted."
            )
          },
          reason = "direct_callback_params_for_jarm_client"
        )
        return(invisible(NULL))
      }

      # Validate the complete direct response shape before error handling or
      # code exchange can validate and consume the single-use state entry.
      if (isTRUE(direct_callback_params_present)) {
        shape_error <- tryCatch(
          {
            validate_oauth_callback_shape(
              code = query_code,
              state = query_state,
              error = query_error,
              context = "OAuth query callback"
            )
            NULL
          },
          error = identity
        )
        if (!is.null(shape_error)) {
          has_exactly_one_response <- xor(
            !is.null(query_code),
            !is.null(query_error)
          )
          missing_state <- !is_valid_string(query_state)
          missing_response_state <- isTRUE(has_exactly_one_response) &&
            isTRUE(missing_state)
          .reject_callback_query(
            description = conditionMessage(shape_error),
            reason = if (missing_response_state) {
              "missing_direct_callback_state"
            } else {
              "invalid_direct_callback_shape"
            },
            error_code = if (missing_response_state) {
              "invalid_state"
            } else {
              "invalid_callback_query"
            }
          )
          return(invisible(NULL))
        }
      }

      # If provider returned an OAuth error response, surface it and abort.
      # Per RFC 6749 section 4.1.2.1 the authorization server may include
      # error and error_description parameters instead of a code.
      if (!is.null(query_error)) {
        # Clear sensitive callback params even on failure paths to reduce
        # leak risk via referrers, browser history, or logs.
        clear_oauth_module_callback_query(
          session,
          tab_title_replacement,
          tab_title_cleaning
        )
        .handle_error_response(
          error = query_error,
          error_description = query_error_description,
          error_uri = query_error_uri,
          state = query_state,
          iss = query_iss %||% NULL
        )
        return(invisible(NULL))
      }

      # If we're on the callback step, handle immediately and stop here
      if (!is.null(query_code)) {
        .handle_callback(
          code = query_code,
          state = query_state,
          iss = query_iss %||% NULL
        )
        return(invisible(NULL))
      }

      # Otherwise, initiate authentication via automatic redirect.
      # Skip if an error has already been surfaced (e.g. access_denied,
      # consent_required) to avoid a redirect loop: clearing the URL after
      # an error re-triggers this observer but we must not re-initiate login.
      if (
        isTRUE(auto_redirect) &&
          is.null(values$pending_callback) &&
          is.null(values$error)
      ) {
        .request_login()
      }

      return(invisible(NULL))
    }

    # Internal helper: run callback issuer enforcement and convert failures
    # into module error state. Used by `.handle_callback()` and
    # `.handle_error_response()`.
    # @param iss Optional issuer returned on the callback.
    # @return `TRUE` when issuer validation succeeds, otherwise `FALSE` after
    #   recording module error state.
    .enforce_callback_issuer_or_set_error <- function(iss = NULL) {
      tryCatch(
        {
          enforce_callback_issuer(
            oauth_client = client,
            iss = iss
          )
          TRUE
        },
        error = function(e) {
          error_context <- tryCatch(e[["context"]], error = function(...) {
            NULL
          })
          callback_error <- error_context[["callback_error"]] %||%
            "callback_iss_validation_error"
          expected_issuer <- client@provider@issuer %||% NA_character_

          .set_error(
            callback_error,
            e,
            phase = "callback_iss_validation"
          )

          audit_name <- switch(
            callback_error,
            issuer_missing = "callback_iss_missing",
            issuer_mismatch = "callback_iss_mismatch",
            "callback_iss_validation_failed"
          )
          try(
            audit_event(
              audit_name,
              context = compact_list(list(
                provider = client@provider@name %||% NA_character_,
                expected_issuer = expected_issuer,
                callback_issuer = iss %||% NULL,
                client_id_digest = string_digest(client@client_id),
                error_class = paste(class(e), collapse = ", ")
              ))
            ),
            silent = TRUE
          )
          FALSE
        }
      )
    }

    # Internal helper: recheck a cached normalized JARM response before it is
    # resumed from the POST bridge or a pending callback wait.
    .resume_cached_jarm_response <- function(
      normalized_response,
      decrypted_payload = NULL,
      phase = "callback_response_validation",
      drop_response = FALSE
    ) {
      normalized <- tryCatch(
        revalidate_cached_jarm_response(client, normalized_response),
        error = function(e) {
          clear_oauth_module_callback_query(
            session,
            tab_title_replacement,
            tab_title_cleaning,
            drop_response = drop_response
          )
          .set_error(
            oauth_module_callback_failure_error_code(e),
            e,
            phase = phase
          )
          try(
            audit_event(
              "callback_validation_failed",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                state_digest = NA_character_,
                error_class = paste(class(e), collapse = ", "),
                phase = phase
              )
            ),
            silent = TRUE
          )
          NULL
        }
      )
      if (is.null(normalized)) {
        return(invisible(NULL))
      }

      if (!is_valid_string(values$browser_token)) {
        clear_oauth_module_callback_query(
          session,
          tab_title_replacement,
          tab_title_cleaning,
          drop_response = drop_response
        )
        values$pending_callback <- list(
          type = "jarm",
          normalized_response = normalized,
          decrypted_payload = decrypted_payload,
          drop_response = drop_response
        )
        return(invisible(NULL))
      }

      if (identical(normalized[["type"]], "error")) {
        clear_oauth_module_callback_query(
          session,
          tab_title_replacement,
          tab_title_cleaning,
          drop_response = drop_response
        )
        .handle_error_response(
          error = normalized[["error"]],
          error_description = normalized[["error_description"]],
          error_uri = normalized[["error_uri"]],
          state = normalized[["state"]],
          iss = normalized[["iss"]] %||% NULL,
          decrypted_payload = decrypted_payload
        )
        return(invisible(NULL))
      }

      .handle_callback(
        code = normalized[["code"]],
        state = normalized[["state"]],
        iss = normalized[["iss"]] %||% NULL,
        decrypted_payload = decrypted_payload,
        drop_response = drop_response,
        callback_validated = TRUE
      )
      invisible(NULL)
    }

    # Internal helper: validate one JARM callback response and dispatch the
    # normalized result into the existing error or code callback path.
    # @param response Raw compact JARM JWT from the callback transport.
    # @param phase Phase label used for module error reporting and auditing.
    # @return No return value; updates module state or delegates to existing
    #   callback handlers.
    .handle_jarm_response <- function(
      response,
      transport = c("query", "form_post"),
      outer_iss = NULL,
      decrypted_payload = NULL,
      phase = "callback_response_validation",
      drop_response = FALSE
    ) {
      transport <- match.arg(transport)
      drop_response <- isTRUE(drop_response) || identical(transport, "query")

      authenticated_state_payload <- decrypted_payload
      authenticate_jarm_state <- function(state) {
        authenticated_state_payload <<- if (is.null(decrypted_payload)) {
          state_payload_decrypt_validate(
            client,
            state,
            audit_success = FALSE
          )
        } else {
          state_payload_revalidate(
            client,
            decrypted_payload,
            audit_success = FALSE
          )
        }
        authenticated_state_payload
      }

      operation <- NULL
      fail <- function(e) {
        clear_oauth_module_callback_query(
          session,
          tab_title_replacement,
          tab_title_cleaning,
          drop_response = drop_response
        )
        .set_error(
          oauth_module_callback_failure_error_code(e),
          e,
          phase = phase
        )
        try(
          audit_event(
            "callback_validation_failed",
            context = list(
              provider = client@provider@name %||% NA_character_,
              issuer = client@provider@issuer %||% NA_character_,
              client_id_digest = string_digest(client@client_id),
              state_digest = NA_character_,
              error_class = paste(class(e), collapse = ", "),
              phase = phase
            )
          ),
          silent = TRUE
        )
        NULL
      }
      report_failure <- function(e) {
        if (
          is.null(operation) || .auth_operation_can_apply(operation, "jarm")
        ) {
          fail(e)
          if (!is.null(operation)) .finish_auth_operation(operation, "jarm")
        }
        invisible(NULL)
      }
      normalized <- tryCatch(
        validate_jarm_response(
          client,
          response,
          transport = transport,
          outer_iss = outer_iss,
          authenticate_state = authenticate_jarm_state,
          .defer_signature = isTRUE(async)
        ),
        error = report_failure
      )
      if (is.null(normalized)) {
        return(invisible(NULL))
      }
      if (isTRUE(async)) {
        # Local shape/issuer/state checks have passed. Only signature/key work
        # crosses the worker boundary; logical state remains browser-bound.
        operation <- .begin_auth_operation(
          "jarm",
          source_token = values$token,
          new_epoch = TRUE
        )
        return(tryCatch(
          {
            worker <- prepare_client_for_worker(client)
            if (is.null(worker)) {
              err_config("JARM client cannot be serialized for async work")
            }
            async_dispatch(
              quote({
                .ns <- asNamespace("shinyOAuth")
                .ns$with_async_options(captured_options, {
                  .ns$with_async_session_context(captured_session, {
                    .ns$verify_jarm_signature(
                      worker,
                      preflight$jwt_str,
                      preflight$alg,
                      preflight$kid
                    )
                    .ns$validate_jarm_claims(
                      worker,
                      preflight$claims,
                      prechecked = preflight$prechecked
                    )
                  })
                })
              }),
              args = list(
                worker = worker,
                preflight = normalized,
                captured_options = capture_async_options(),
                captured_session = capture_shiny_session_context()
              )
            ) |>
              promises::then(function(raw) {
                if (!.auth_operation_can_apply(operation, "jarm")) {
                  return(invisible(NULL))
                }
                result <- replay_async_conditions(raw)
                .finish_auth_operation(operation, "jarm")
                .resume_cached_jarm_response(
                  result,
                  authenticated_state_payload,
                  phase = phase,
                  drop_response = drop_response
                )
              }) |>
              promises::catch(report_failure)
          },
          error = report_failure
        ))
      }
      .resume_cached_jarm_response(
        normalized,
        authenticated_state_payload,
        phase = phase,
        drop_response = drop_response
      )
      invisible(NULL)
    }

    # Internal helper: handle a provider-supplied error callback after state
    # validation. Used by `.process_query()` for `?error=...` callback URLs.
    # @param error Provider-supplied OAuth error code.
    # @param error_description Optional provider-supplied description.
    # @param error_uri Optional provider-supplied documentation URL.
    # @param state Callback state value.
    # @param iss Optional callback issuer.
    # @return No return value; either records module error state or stages
    #   pending callback work.
    .handle_error_response <- function(
      error,
      error_description,
      error_uri,
      state,
      iss = NULL,
      decrypted_payload = NULL,
      state_store_values = NULL
    ) {
      if (!isTRUE(.enforce_callback_issuer_or_set_error(iss))) {
        return(invisible(NULL))
      }

      # Mirror the code-callback path: wait for the browser token before
      # consuming state or surfacing provider-controlled error text.
      if (!is_valid_string(values$browser_token)) {
        values$pending_callback <- list(
          type = "error",
          error = error,
          error_description = error_description,
          error_uri = error_uri,
          state = state,
          iss = iss,
          decrypted_payload = decrypted_payload,
          state_store_values = state_store_values
        )
        return(invisible(NULL))
      }

      # Security: treat provider error callbacks as valid only when state is
      # present and can be successfully validated/consumed.
      state_ok <- tryCatch(
        {
          if (!is_valid_string(state)) {
            err_invalid_state("Callback missing state payload")
          }
          # strict = TRUE makes validation failures propagate so we can reject
          # the callback instead of surfacing an unbound provider error.
          state_was_preconsumed <- !is.null(decrypted_payload) &&
            !is.null(state_store_values)
          consumed_state <- if (
            !is.null(decrypted_payload) && !is.null(state_store_values)
          ) {
            cached_payload <- state_payload_revalidate(
              client,
              decrypted_payload,
              audit_success = FALSE
            )
            with_trace_id(
              cached_payload[["trace_id"]] %||% NULL,
              try(
                audit_event(
                  "error_state_consumed",
                  context = list(
                    provider = client@provider@name %||% NA_character_,
                    issuer = client@provider@issuer %||% NA_character_,
                    client_id_digest = string_digest(client@client_id),
                    state_digest = string_digest(cached_payload[[
                      "state",
                      exact = TRUE
                    ]])
                  )
                ),
                silent = TRUE
              )
            )
            list(
              payload = cached_payload,
              state_store_values = state_store_values
            )
          } else {
            .consume_error_state(
              state,
              strict = TRUE,
              decrypted_payload = decrypted_payload,
              consume = FALSE
            )
          }
          .validate_error_response_browser_token(consumed_state)
          if (!isTRUE(state_was_preconsumed)) {
            consumed_state <- .consume_error_state(
              state,
              strict = TRUE,
              decrypted_payload = consumed_state[["payload"]],
              consume = TRUE
            )
          }
          TRUE
        },
        error = function(e) {
          .set_error(
            "invalid_state",
            e,
            phase = "error_response_state_validation"
          )
          FALSE
        }
      )

      if (!isTRUE(state_ok)) {
        return(invisible(NULL))
      }

      # State validated and consumed: now surface provider error.
      # Keep the raw value in deferred state so replay/resume paths preserve
      # provider error context, but sanitize before surfacing it to callers.
      error_uri <- sanitize_callback_error_uri(error_uri, client@provider)
      values$error <- error
      values$error_description <- if (allow_expose_error_body()) {
        sanitize_diagnostic_text(error_description)
      } else {
        NULL
      }
      values$error_uri <- error_uri %||% NULL
      invisible(NULL)
    }

    # Internal helper: decrypt, validate, and consume state for an error
    # callback. Used by `.handle_error_response()` so provider error text is
    # only trusted after state binding succeeds.
    # @param state Encrypted callback state payload.
    # @param strict Whether failures should be rethrown instead of converted to
    #   `FALSE`.
    # @param decrypted_payload Optional pre-decrypted state payload.
    # @param consume Whether to consume the state-store entry. Use `FALSE` for
    #   the pre-browser-token lookup and `TRUE` after browser binding succeeds.
    # @return Consumed state bundle on success, otherwise `FALSE` when
    #   `strict` is `FALSE`.
    .consume_error_state <- function(
      state,
      strict = FALSE,
      decrypted_payload = NULL,
      consume = TRUE
    ) {
      payload <- NULL
      state_store_values <- NULL
      consumed <- tryCatch(
        {
          # Decrypt and validate the state payload
          payload <- if (is.null(decrypted_payload)) {
            state_payload_decrypt_validate(
              client,
              state,
              audit_success = FALSE
            )
          } else {
            state_payload_revalidate(
              client,
              decrypted_payload,
              audit_success = FALSE
            )
          }
          with_trace_id(
            payload[["trace_id"]] %||% NULL,
            {
              if (isTRUE(consume)) {
                # Consume the state store entry (single-use enforcement)
                state_store_values <- state_store_get_remove(
                  client,
                  payload[["state"]]
                )

                # Audit success using the logical state digest for correlation.
                try(
                  audit_event(
                    "error_state_consumed",
                    context = list(
                      provider = client@provider@name %||% NA_character_,
                      issuer = client@provider@issuer %||% NA_character_,
                      client_id_digest = string_digest(client@client_id),
                      state_digest = string_digest(payload[[
                        "state",
                        exact = TRUE
                      ]])
                    )
                  ),
                  silent = TRUE
                )
              } else {
                state_store_values <- state_store_get(
                  client,
                  payload[["state"]]
                )
              }
            }
          )

          list(
            payload = payload,
            state_store_values = state_store_values
          )
        },
        error = function(e) {
          event_trace_id <- if (!is.null(payload)) {
            payload[["trace_id"]] %||% NULL
          } else {
            tryCatch(
              e[["trace_id"]],
              error = function(...) NULL
            )
          }
          state_digest <- if (
            !is.null(payload) &&
              is_valid_string(payload[["state"]])
          ) {
            string_digest(payload[["state"]])
          } else {
            string_digest(state %||% NA_character_)
          }

          # State consumption failed; always emit audit.
          try(
            with_trace_id(
              event_trace_id,
              audit_event(
                "error_state_consumption_failed",
                context = list(
                  provider = client@provider@name %||% NA_character_,
                  issuer = client@provider@issuer %||% NA_character_,
                  client_id_digest = string_digest(client@client_id),
                  state_digest = state_digest,
                  error_class = paste(class(e), collapse = ", "),
                  error_message = conditionMessage(e)
                )
              )
            ),
            silent = TRUE
          )

          if (isTRUE(strict)) {
            rlang::abort(message = conditionMessage(e), parent = e)
          }

          FALSE
        }
      )

      invisible(consumed)
    }

    # Internal helper: validate that the browser token for an error callback
    # matches stored state. Used by `.handle_error_response()` after state has
    # been consumed.
    # @param consumed_state State payload or store bundle returned by
    #   `.consume_error_state()`.
    # @return `TRUE` when browser-token validation succeeds; otherwise this
    #   helper signals invalid state.
    .validate_error_response_browser_token <- function(consumed_state) {
      payload <- consumed_state[["payload"]]
      state_store_values <- consumed_state[["state_store_values"]]

      validated <- tryCatch(
        {
          with_trace_id(
            payload[["trace_id"]] %||% NULL,
            {
              tryCatch(
                validate_browser_token(values$browser_token),
                error = function(e) {
                  err_invalid_state(
                    "Invalid browser token",
                    context = list(
                      original_error_class = paste(class(e), collapse = ", ")
                    )
                  )
                }
              )

              if (
                !constant_time_compare(
                  state_store_values[["browser_token"]],
                  values$browser_token
                )
              ) {
                err_invalid_state("Browser token mismatch")
              }

              TRUE
            }
          )
        },
        error = function(e) {
          try(
            with_trace_id(
              payload[["trace_id"]] %||% NULL,
              audit_event(
                "callback_validation_failed",
                context = list(
                  provider = client@provider@name %||% NA_character_,
                  issuer = client@provider@issuer %||% NA_character_,
                  client_id_digest = string_digest(client@client_id),
                  state_digest = string_digest(
                    payload[["state"]] %||% NA_character_
                  ),
                  browser_token_digest = string_digest(
                    values$browser_token %||% NA_character_
                  ),
                  error_class = paste(class(e), collapse = ", "),
                  phase = "browser_token_validation"
                )
              )
            ),
            silent = TRUE
          )
          rethrow_with_context(e)
        }
      )

      invisible(validated)
    }

    # Internal helper: handle an authorization-code callback from the
    # provider. Used by `.process_query()` directly and by pending-callback
    # resume logic.
    # @param code Authorization code from the callback.
    # @param state Encrypted callback state value.
    # @param iss Optional callback issuer.
    # @param callback_validated Whether the callback transport and outer
    #   callback shape were already validated on an internal path such as JARM.
    # @return No return value; completes or defers callback handling and
    #   updates module state.
    .handle_callback <- function(
      code,
      state,
      iss = NULL,
      decrypted_payload = NULL,
      state_store_values = NULL,
      drop_response = FALSE,
      callback_validated = FALSE
    ) {
      callback_parent <- NULL
      callback_hint <- otel_callback_parent_hint(client, state)
      # Always clear callback params once we've parsed them (success or failure)
      on.exit(
        {
          try(
            clear_oauth_module_callback_query(
              session,
              tab_title_replacement,
              tab_title_cleaning,
              drop_response = drop_response
            ),
            silent = TRUE
          )
        },
        add = TRUE
      )

      if (!isTRUE(.enforce_callback_issuer_or_set_error(iss))) {
        return(invisible(NULL))
      }

      # If browser token isn't here yet, defer (set as pending) and wait for browser token
      if (!is_valid_string(values$browser_token)) {
        values$pending_callback <- list(
          type = "code",
          code = code,
          state = state,
          iss = iss,
          decrypted_payload = decrypted_payload,
          state_store_values = state_store_values,
          drop_response = drop_response,
          callback_validated = callback_validated
        )
        return(invisible(NULL))
      }

      login_operation <- .begin_auth_operation(
        "login",
        source_token = values$token,
        new_epoch = TRUE
      )

      tryCatch(
        {
          with_trace_id(
            callback_hint[["trace_id"]] %||% NULL,
            {
              async_fallback <- FALSE
              res <- if (isTRUE(async)) {
                # Use mirai to move work off the main thread. To avoid
                # cross-process cache visibility issues with client@state_store,
                # pre-decrypt the payload and prefetch+remove the state_store entry on the
                # main thread, and pass these to handle_callback.

                # Capture Shiny session context on the main thread for audit events
                # emitted from the async worker (which lacks reactive domain access)
                captured_shiny_session <- capture_shiny_session_context()
                parent_shiny_session <- normalize_shiny_session_context(
                  captured_shiny_session
                )
                callback_parent <- otel_start_async_parent(
                  "shinyOAuth.callback",
                  attributes = otel_client_attributes(
                    client = client,
                    module_id = id,
                    shiny_session = parent_shiny_session,
                    async = TRUE,
                    phase = "callback",
                    extra = list(
                      oauth.introspect = isTRUE(client@introspect),
                      oauth.introspect_elements_count = otel_count_items(
                        client@introspect_elements %||% character(0)
                      ),
                      oauth.userinfo.required = isTRUE(
                        client@provider@userinfo_required
                      ),
                      oauth.userinfo.id_token_match_required = isTRUE(
                        client@provider@userinfo_id_token_match
                      ),
                      oauth.id_token.validation_enabled = isTRUE(
                        client@provider@id_token_validation
                      )
                    )
                  ),
                  parent = callback_hint[["parent"]] %||% NA
                )

                otel_with_active_span(
                  callback_parent$span,
                  {
                    # Capture shinyOAuth.* options for propagation to the async worker.
                    # This ensures audit hooks, HTTP settings, and other options are
                    # available in the worker process.
                    captured_async_options <- capture_async_options()

                    pre_payload <- decrypted_payload
                    if (is.null(pre_payload)) {
                      pre_payload <- tryCatch(
                        with_otel_span(
                          "shinyOAuth.callback.validate",
                          {
                            payload <- state_payload_decrypt_validate(
                              client,
                              state,
                              shiny_session = captured_shiny_session,
                              audit_success = FALSE
                            )
                            if (
                              !is_valid_string(
                                callback_hint[["trace_id"]] %||%
                                  NA_character_
                              )
                            ) {
                              otel_set_span_attributes(
                                attributes = list(
                                  shinyoauth.trace_id = payload[[
                                    "trace_id",
                                    exact = TRUE
                                  ]] %||%
                                    NULL
                                )
                              )
                            }
                            payload
                          },
                          attributes = otel_client_attributes(
                            client = client,
                            module_id = id,
                            shiny_session = captured_shiny_session,
                            async = TRUE,
                            phase = "callback.state_payload"
                          )
                        ),
                        error = function(e) {
                          .set_error(
                            oauth_module_callback_failure_error_code(e),
                            e,
                            phase = "async_payload_validation"
                          )
                          rethrow_with_context(
                            e,
                            phase = "async_payload_validation"
                          )
                        }
                      )
                    }

                    captured_trace_id <- pre_payload[[
                      "trace_id",
                      exact = TRUE
                    ]] %||%
                      resolve_trace_id()

                    with_trace_id(
                      captured_trace_id,
                      {
                        if (
                          !is_valid_string(
                            callback_hint[["trace_id"]] %||%
                              NA_character_
                          )
                        ) {
                          otel_set_span_attributes(
                            span = callback_parent$span,
                            attributes = list(
                              shinyoauth.trace_id = captured_trace_id
                            )
                          )
                        }

                        # Capture the browser token value on the main thread to avoid
                        # touching reactive values inside the worker.
                        captured_browser_token <- tryCatch(
                          shiny::isolate(values$browser_token),
                          error = function(...) values$browser_token
                        )

                        pre_state <- state_store_values
                        if (is.null(pre_state)) {
                          pre_state <- tryCatch(
                            with_otel_span(
                              "shinyOAuth.callback.validate",
                              {
                                state_store_get(
                                  client,
                                  pre_payload[["state"]],
                                  shiny_session = captured_shiny_session
                                )
                              },
                              attributes = otel_client_attributes(
                                client = client,
                                module_id = id,
                                shiny_session = captured_shiny_session,
                                async = TRUE,
                                phase = "callback.state_store_lookup"
                              )
                            ),
                            error = function(e) {
                              .set_error(
                                oauth_module_callback_failure_error_code(e),
                                e,
                                phase = "async_state_store_lookup"
                              )
                              rethrow_with_context(
                                e,
                                phase = "async_state_store_lookup"
                              )
                            }
                          )

                          tryCatch(
                            with_otel_span(
                              "shinyOAuth.callback.validate",
                              {
                                tryCatch(
                                  validate_browser_token(
                                    captured_browser_token
                                  ),
                                  error = function(e) {
                                    err_invalid_state(
                                      "Invalid browser token",
                                      context = list(
                                        original_error_class = paste(
                                          class(e),
                                          collapse = ", "
                                        )
                                      )
                                    )
                                  }
                                )
                                if (
                                  !constant_time_compare(
                                    pre_state[["browser_token"]],
                                    captured_browser_token
                                  )
                                ) {
                                  err_invalid_state("Browser token mismatch")
                                }
                              },
                              attributes = otel_client_attributes(
                                client = client,
                                module_id = id,
                                shiny_session = captured_shiny_session,
                                async = TRUE,
                                phase = "callback.browser_token_validation"
                              )
                            ),
                            error = function(e) {
                              try(
                                audit_event(
                                  "callback_validation_failed",
                                  context = list(
                                    provider = client@provider@name %||%
                                      NA_character_,
                                    issuer = client@provider@issuer %||%
                                      NA_character_,
                                    client_id_digest = string_digest(
                                      client@client_id
                                    ),
                                    state_digest = string_digest(
                                      pre_payload[["state"]] %||%
                                        NA_character_
                                    ),
                                    browser_token_digest = string_digest(
                                      captured_browser_token %||%
                                        NA_character_
                                    ),
                                    error_class = paste(
                                      class(e),
                                      collapse = ", "
                                    ),
                                    phase = "browser_token_validation"
                                  ),
                                  shiny_session = captured_shiny_session
                                ),
                                silent = TRUE
                              )
                              .set_error(
                                oauth_module_callback_failure_error_code(e),
                                e,
                                phase = "browser_token_validation"
                              )
                              rethrow_with_context(
                                e,
                                phase = "browser_token_validation"
                              )
                            }
                          )

                          pre_state <- tryCatch(
                            with_otel_span(
                              "shinyOAuth.callback.validate",
                              {
                                state_store_get_remove(
                                  client,
                                  pre_payload[["state"]],
                                  shiny_session = captured_shiny_session
                                )
                              },
                              attributes = otel_client_attributes(
                                client = client,
                                module_id = id,
                                shiny_session = captured_shiny_session,
                                async = TRUE,
                                phase = "callback.state_store_consume"
                              )
                            ),
                            error = function(e) {
                              .set_error(
                                oauth_module_callback_failure_error_code(e),
                                e,
                                phase = "async_state_store_lookup"
                              )
                              rethrow_with_context(
                                e,
                                phase = "async_state_store_lookup"
                              )
                            }
                          )
                        }
                        # Build a serialization-safe client for the worker.
                        # The state_store is already consumed on the main thread, so
                        # prepare_client_for_worker() replaces it with a lightweight
                        # serializable dummy and verifies overall serializability.
                        client_for_worker <- prepare_client_for_worker(client)
                        async_fallback <- is.null(client_for_worker)

                        if (async_fallback) {
                          warn_pkg(
                            "Async callback fell back to synchronous execution",
                            c(
                              "!" = "Client object contains non-serializable components, so async callback dispatch could not proceed.",
                              "i" = "Falling back to synchronous callback execution",
                              "i" = "Custom state_store or JWKS cache backends must be serializable for async mode",
                              "i" = "Consider using cachem::cache_mem() or cachem::cache_disk() for async compatibility"
                            ),
                            class = "shinyOAuth_async_serialization_fallback",
                            .frequency = "once",
                            .frequency_id = "shinyOAuth-async-serialization-fallback"
                          )
                          # Fall back to synchronous execution using pre-computed values
                          # (state_store was already consumed above, so we must use
                          # handle_callback_internal with the pre-fetched data)
                          handle_callback_internal(
                            oauth_client = client,
                            code = code,
                            payload = state,
                            browser_token = captured_browser_token,
                            decrypted_payload = pre_payload,
                            state_store_values = pre_state,
                            shiny_session = captured_shiny_session
                          )
                        } else {
                          # Use namespace-qualified calls to avoid passing function closures to mirai
                          # (functions carry their enclosing environments, causing serialization overhead)
                          async_dispatch(
                            expr = quote({
                              .ns <- asNamespace("shinyOAuth")
                              # Restore shinyOAuth.* options in the async worker
                              .ns$with_trace_id(captured_trace_id, {
                                .ns$with_async_options(captured_async_options, {
                                  # Set async context so errors include session info with is_async = TRUE
                                  .ns$with_async_session_context(
                                    captured_shiny_session,
                                    {
                                      .ns$handle_callback_internal(
                                        oauth_client = client_for_worker,
                                        code = code,
                                        payload = state,
                                        browser_token = captured_browser_token,
                                        decrypted_payload = pre_payload,
                                        state_store_values = pre_state,
                                        shiny_session = captured_shiny_session
                                      )
                                    }
                                  )
                                })
                              })
                            }),
                            args = list(
                              captured_trace_id = captured_trace_id,
                              captured_async_options = captured_async_options,
                              captured_shiny_session = captured_shiny_session,
                              client_for_worker = client_for_worker,
                              code = code,
                              state = state,
                              captured_browser_token = captured_browser_token,
                              pre_payload = pre_payload,
                              pre_state = pre_state
                            ),
                            otel_context = list(
                              headers = callback_parent$headers,
                              worker_span_name = "shinyOAuth.callback.worker",
                              shiny_session = captured_shiny_session,
                              attributes = otel_client_attributes(
                                client = client,
                                module_id = id,
                                shiny_session = captured_shiny_session,
                                async = TRUE,
                                phase = "callback.worker"
                              )
                            )
                          )
                        }
                      }
                    )
                  }
                )
              } else {
                if (
                  isTRUE(callback_validated) ||
                    identical(
                      client@authorization_server_mode,
                      "multi_redirect_uri"
                    ) ||
                    !is.null(decrypted_payload) ||
                    !is.null(state_store_values)
                ) {
                  handle_callback_internal(
                    oauth_client = client,
                    code = code,
                    payload = state,
                    browser_token = values$browser_token,
                    decrypted_payload = decrypted_payload,
                    state_store_values = state_store_values
                  )
                } else {
                  handle_callback(
                    oauth_client = client,
                    code = code,
                    payload = state,
                    browser_token = values$browser_token,
                    iss = iss
                  )
                }
              }

              # Handle async/sync
              if (isTRUE(async) && !isTRUE(async_fallback)) {
                # Mark that we exercised the async pathway (testing aid)
                values$last_login_async_used <- TRUE

                res |>
                  promises::then(function(raw) {
                    if (!is.null(callback_parent)) {
                      otel_end_async_parent(callback_parent, status = "ok")
                    }
                    tok <- replay_async_conditions(raw)
                    if (
                      !isTRUE(.auth_operation_can_apply(
                        login_operation,
                        "login"
                      ))
                    ) {
                      .finish_auth_operation(login_operation, "login")
                      .revoke_stale_credentials(
                        tok,
                        shiny_session = captured_shiny_session
                      )
                      return(invisible(NULL))
                    }
                    .finish_auth_operation(login_operation, "login")
                    validate_token_acceptance_deadline(tok)
                    values$token <- tok
                    values$error <- NULL
                    values$error_description <- NULL
                    values$error_uri <- NULL
                    values$auth_started_at <- .interactive_auth_started_at(tok)
                    values$token_stale <- FALSE
                    .clear_browser_token()
                    # Immediately re-issue a fresh browser token so that
                    # subsequent manual logins can redirect on the first click.
                    .set_browser_token()
                    # A successful login completes any prior reauth cycle
                    values$reauth_triggered <- FALSE
                    auth_operations$force_oidc_reauth <- FALSE
                  }) |>
                  promises::catch(function(e) {
                    failure_phase <- tryCatch(
                      e[["phase"]],
                      error = function(...) NULL
                    ) %||%
                      "async_token_exchange"
                    if (!is.null(callback_parent)) {
                      otel_end_async_parent(
                        callback_parent,
                        status = "error",
                        error = e
                      )
                    }
                    if (
                      !isTRUE(.auth_operation_can_apply(
                        login_operation,
                        "login"
                      ))
                    ) {
                      .finish_auth_operation(login_operation, "login")
                      return(invisible(NULL))
                    }
                    .set_error(
                      oauth_module_callback_failure_error_code(e),
                      e,
                      phase = failure_phase
                    )
                    try(
                      audit_event(
                        "login_failed",
                        context = list(
                          provider = client@provider@name %||% NA_character_,
                          issuer = client@provider@issuer %||% NA_character_,
                          client_id_digest = string_digest(client@client_id),
                          phase = failure_phase,
                          error_class = paste(class(e), collapse = ", "),
                          mirai_error_type = classify_mirai_error(e) %||%
                            NA_character_
                        ),
                        shiny_session = captured_shiny_session
                      ),
                      silent = TRUE
                    )
                    .finish_auth_operation(login_operation, "login")
                    if (isTRUE(getOption("shinyOAuth.debug", FALSE))) {
                      rlang::abort(message = conditionMessage(e), parent = e)
                    }
                  })
              } else {
                if (
                  !isTRUE(.auth_operation_can_apply(
                    login_operation,
                    "login"
                  ))
                ) {
                  .finish_auth_operation(login_operation, "login")
                  .revoke_stale_credentials(res)
                  return(invisible(NULL))
                }
                .finish_auth_operation(login_operation, "login")
                validate_token_acceptance_deadline(res)
                values$token <- res
                values$error <- NULL
                values$error_description <- NULL
                values$error_uri <- NULL
                values$auth_started_at <- .interactive_auth_started_at(res)
                values$token_stale <- FALSE
                .clear_browser_token()
                # Immediately re-issue a fresh browser token so that
                # subsequent manual logins can redirect on the first click.
                .set_browser_token()
                # Reset reauth guard on successful sync login
                values$reauth_triggered <- FALSE
                auth_operations$force_oidc_reauth <- FALSE
                if (!is.null(callback_parent)) {
                  otel_end_async_parent(callback_parent, status = "ok")
                }
              }
            }
          )
        },
        error = function(e) {
          failure_phase <- tryCatch(
            e[["phase"]],
            error = function(...) NULL
          ) %||%
            "sync_token_exchange"
          if (!is.null(callback_parent)) {
            otel_end_async_parent(callback_parent, status = "error", error = e)
          }
          if (!isTRUE(.auth_operation_can_apply(login_operation, "login"))) {
            .finish_auth_operation(login_operation, "login")
            return(invisible(NULL))
          }
          .set_error(
            oauth_module_callback_failure_error_code(e),
            e,
            phase = failure_phase
          )
          try(
            audit_event(
              "login_failed",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                phase = failure_phase,
                error_class = paste(class(e), collapse = ", ")
              )
            ),
            silent = TRUE
          )
          .finish_auth_operation(login_operation, "login")
          if (isTRUE(getOption("shinyOAuth.debug", FALSE))) {
            rlang::abort(message = conditionMessage(e), parent = e)
          }
        }
      )

      invisible(NULL)
    }

    # Resume the deferred callback once the JS cookie has populated the input
    shiny::observeEvent(
      values$browser_token,
      {
        pc <- shiny::isolate(values$pending_callback)
        if (!is.null(pc) && .has_browser_token()) {
          values$pending_callback <- NULL
          pending_type <- pc[["type"]] %||%
            if (!is.null(pc[["normalized_response"]])) {
              "jarm"
            } else if (!is.null(pc[["code"]])) {
              "code"
            } else if (!is.null(pc[["error"]])) {
              "error"
            } else {
              NULL
            }

          if (identical(pending_type, "jarm")) {
            .resume_cached_jarm_response(
              normalized_response = pc[["normalized_response"]] %||% NULL,
              decrypted_payload = pc[["decrypted_payload"]] %||% NULL,
              phase = "callback_response_resume",
              drop_response = isTRUE(pc[["drop_response"]] %||% FALSE)
            )
          } else if (identical(pending_type, "error")) {
            .handle_error_response(
              error = pc[["error"]],
              error_description = pc[["error_description"]],
              error_uri = pc[["error_uri"]],
              state = pc[["state"]],
              iss = pc[["iss"]] %||% NULL,
              decrypted_payload = pc[["decrypted_payload"]] %||% NULL,
              state_store_values = pc[["state_store_values"]] %||% NULL
            )
          } else {
            .handle_callback(
              pc[["code"]],
              pc[["state"]],
              pc[["iss"]] %||% NULL,
              decrypted_payload = pc[["decrypted_payload"]] %||% NULL,
              state_store_values = pc[["state_store_values"]] %||% NULL,
              drop_response = isTRUE(pc[["drop_response"]] %||% FALSE),
              callback_validated = isTRUE(
                pc[["callback_validated"]] %||% FALSE
              )
            )
          }
        }
      },
      ignoreInit = FALSE
    )

    # If a login was requested while no cookie was present, proceed once it is.
    shiny::observeEvent(
      values$browser_token,
      {
        if (
          isTRUE(allow_skip_browser_token()) &&
            isTRUE(shiny::isolate(values$pending_login)) &&
            .has_browser_token()
        ) {
          # Guard against running during callback processing
          qs <- tryCatch(
            shiny::parseQueryString(session$clientData$url_search %||% ""),
            error = function(...) list()
          )
          if (
            is.null(qs[["code"]]) &&
              is.null(qs[["error"]]) &&
              is.null(shiny::isolate(values$pending_callback)) &&
              !isTRUE(shiny::isolate(values$auto_redirected))
          ) {
            values$pending_login <- FALSE
            .initiate_login()
          }
        }
      },
      ignoreInit = FALSE
    )

    # Track whether we've already auto-redirected to avoid repeated attempts

    # Testing hooks: expose helpers for unit tests
    values$.process_query <- .process_query
    values$.strip_oauth_query <- strip_oauth_module_callback_query

    ## 2.8 Proactive refresh ---------------------------------------------------

    # Expiry management and optional proactive refresh logic
    if (isTRUE(refresh_proactively)) {
      # Record proactive refresh pacing state for success and failure paths.
      .record_refresh_result <- function(
        operation,
        token = NULL,
        condition = NULL
      ) {
        if (!isTRUE(.auth_operation_can_apply(operation, "refresh"))) {
          .finish_auth_operation(operation, "refresh")
          return(FALSE)
        }

        now <- as.numeric(Sys.time())
        .finish_auth_operation(operation, "refresh")

        if (!is.null(token)) {
          values$refresh_failure_count <- 0L
          values$refresh_last_success_at <- now
          values$refresh_success_generation <-
            values$refresh_success_generation + 1L
          delay <- proactive_refresh_success_delay(
            token,
            now,
            refresh_lead_seconds
          )
        } else {
          values$refresh_failure_count <- values$refresh_failure_count + 1L
          delay <- proactive_refresh_failure_delay(
            values$refresh_failure_count,
            refresh_condition_retry_after(condition)
          )
        }

        values$refresh_next_attempt_at <- now + delay
        TRUE
      }

      shiny::observe({
        tok <- values$token

        # Default: wake up on a coarse interval when token missing/unknown
        wake_ms <- refresh_check_interval

        if (!is.null(tok)) {
          exp <- tryCatch(tok@expires_at, error = function(...) NA_real_)
          now <- as.numeric(Sys.time())

          if (is.finite(exp) && !is.na(exp)) {
            remaining <- exp - now
            # compute time to refresh: remaining - lead
            to_refresh <- remaining - refresh_lead_seconds
            # add small jitter 0..1s to avoid herd
            jitter <- stats::runif(1, min = 0, max = 1)
            if (!is.na(to_refresh) && to_refresh > 0) {
              wake_ms <- shiny_timer_delay_ms(
                to_refresh,
                buffer_seconds = jitter
              )
            } else {
              # We are within the lead window or past it. Respect pacing from a
              # recent short-lived success or failed attempt before retrying.
              next_attempt_at <- values$refresh_next_attempt_at
              if (is.finite(next_attempt_at) && next_attempt_at > now) {
                wake_ms <- shiny_timer_delay_ms(next_attempt_at - now)
              } else {
                wake_ms <- 250L
              }
              # Avoid concurrent refresh attempts: if one is already running,
              # skip starting another and try again shortly.
              if (
                isTRUE(values$refresh_in_progress) ||
                  !is.null(auth_operations$active_login_id) ||
                  (is.finite(next_attempt_at) && next_attempt_at > now)
              ) {
                # Keep wake_ms short and bail out of starting a new refresh
                # The enclosing observe will schedule the next wake.
              } else {
                # Capture Shiny session context on the main thread for audit events
                # emitted from the async worker (which lacks reactive domain access)
                captured_shiny_session_refresh <- if (isTRUE(async)) {
                  capture_shiny_session_context(is_async = TRUE)
                } else {
                  NULL
                }

                # Delegate to refresh_token with async and handle promise if returned
                refresh_operation <- NULL
                tryCatch(
                  {
                    # Claim ownership until this exact refresh resolves.
                    refresh_operation <- .begin_auth_operation(
                      "refresh",
                      source_token = tok
                    )
                    values$refresh_last_attempt_at <- as.numeric(Sys.time())
                    res <- refresh_token(
                      client,
                      tok,
                      async = async,
                      introspect = isTRUE(client@introspect),
                      shiny_session = captured_shiny_session_refresh
                    )

                    # Handle async path (wait for promise to resolve; then set values)
                    if (isTRUE(async)) {
                      res |>
                        promises::then(function(raw) {
                          res_resolved <- replay_async_conditions(raw)
                          if (
                            !isTRUE(.record_refresh_result(
                              refresh_operation,
                              token = res_resolved
                            ))
                          ) {
                            .revoke_stale_credentials(
                              res_resolved,
                              shiny_session = captured_shiny_session_refresh
                            )
                            return(invisible(NULL))
                          }
                          validate_token_acceptance_deadline(res_resolved)
                          values$token <- res_resolved
                          values$error <- NULL
                          values$error_description <- NULL
                          values$error_uri <- NULL
                          values$token_stale <- FALSE
                          # Successful refresh should allow future reauth cycles
                          values$reauth_triggered <- FALSE
                        }) |>
                        promises::catch(function(e) {
                          if (
                            !isTRUE(.record_refresh_result(
                              refresh_operation,
                              condition = e
                            ))
                          ) {
                            return(invisible(NULL))
                          }
                          mirai_err_type <- classify_mirai_error(e)
                          try(log_condition(
                            e,
                            context = list(
                              phase = "async_token_refresh",
                              mirai_error_type = mirai_err_type
                            )
                          ))

                          # On failure, either keep token (indefinite_session)
                          # or clear it (default behavior)
                          if (!isTRUE(indefinite_session)) {
                            values$token <- NULL
                            values$token_stale <- FALSE
                          }

                          .set_error(
                            "token_refresh_error",
                            e,
                            phase = "async_token_refresh"
                          )
                          # Mark token stale when we kept it due to indefinite_session
                          if (isTRUE(indefinite_session)) {
                            values$token_stale <- TRUE
                          }
                          if (isTRUE(indefinite_session)) {
                            try(
                              audit_event(
                                "refresh_failed_but_kept_session",
                                context = list(
                                  provider = client@provider@name %||%
                                    NA_character_,
                                  issuer = client@provider@issuer %||%
                                    NA_character_,
                                  client_id_digest = string_digest(
                                    client@client_id
                                  ),
                                  reason = "refresh_failed_async",
                                  kept_token = TRUE,
                                  error_class = paste(
                                    class(e),
                                    collapse = ", "
                                  ),
                                  mirai_error_type = mirai_err_type %||%
                                    NA_character_
                                ),
                                shiny_session = captured_shiny_session_refresh
                              ),
                              silent = TRUE
                            )
                          } else {
                            try(
                              audit_event(
                                "session_cleared",
                                context = list(
                                  provider = client@provider@name %||%
                                    NA_character_,
                                  issuer = client@provider@issuer %||%
                                    NA_character_,
                                  client_id_digest = string_digest(
                                    client@client_id
                                  ),
                                  reason = "refresh_failed_async",
                                  error_class = paste(
                                    class(e),
                                    collapse = ", "
                                  ),
                                  mirai_error_type = mirai_err_type %||%
                                    NA_character_
                                ),
                                shiny_session = captured_shiny_session_refresh
                              ),
                              silent = TRUE
                            )
                          }

                          if (!isTRUE(indefinite_session)) {
                            if (
                              isTRUE(auto_redirect) &&
                                !isTRUE(values$reauth_triggered)
                            ) {
                              values$reauth_triggered <- TRUE
                              try(values$request_login())
                            }
                          }
                        })
                    } else {
                      # Sync path; directly set values
                      new_tok <- res
                      if (
                        !isTRUE(.record_refresh_result(
                          refresh_operation,
                          token = new_tok
                        ))
                      ) {
                        .revoke_stale_credentials(new_tok)
                        return(invisible(NULL))
                      }
                      validate_token_acceptance_deadline(new_tok)
                      values$token <- new_tok
                      values$error <- NULL
                      values$error_description <- NULL
                      values$error_uri <- NULL
                      values$token_stale <- FALSE
                      # Successful sync refresh resets reauth guard as well
                      values$reauth_triggered <- FALSE
                    }
                  },
                  error = function(e) {
                    if (
                      is.null(refresh_operation) ||
                        !isTRUE(.record_refresh_result(
                          refresh_operation,
                          condition = e
                        ))
                    ) {
                      return(invisible(NULL))
                    }
                    # Set error; clear token unless indefinite_session
                    if (!isTRUE(indefinite_session)) {
                      values$token <- NULL
                      values$token_stale <- FALSE
                    }
                    .set_error(
                      "token_refresh_error",
                      e,
                      phase = "sync_token_refresh"
                    )
                    # Mark token stale when we kept it due to indefinite_session
                    if (isTRUE(indefinite_session)) {
                      values$token_stale <- TRUE
                    }
                    if (isTRUE(indefinite_session)) {
                      try(
                        audit_event(
                          "refresh_failed_but_kept_session",
                          context = list(
                            provider = client@provider@name %||% NA_character_,
                            issuer = client@provider@issuer %||% NA_character_,
                            client_id_digest = string_digest(client@client_id),
                            reason = "refresh_failed_sync",
                            kept_token = TRUE,
                            error_class = paste(class(e), collapse = ", ")
                          )
                        ),
                        silent = TRUE
                      )
                    } else {
                      try(
                        audit_event(
                          "session_cleared",
                          context = list(
                            provider = client@provider@name %||% NA_character_,
                            issuer = client@provider@issuer %||% NA_character_,
                            client_id_digest = string_digest(client@client_id),
                            reason = "refresh_failed_sync",
                            error_class = paste(class(e), collapse = ", ")
                          )
                        ),
                        silent = TRUE
                      )
                    }

                    # If refresh failed and we want to reauth, attempt a redirect
                    if (!isTRUE(indefinite_session)) {
                      if (
                        isTRUE(auto_redirect) &&
                          !isTRUE(values$reauth_triggered)
                      ) {
                        values$reauth_triggered <- TRUE
                        try(values$request_login())
                      }
                    }
                  }
                )
              } # end if not refresh_in_progress
            }
          }
        }

        # schedule next wake
        shiny::invalidateLater(wake_ms, session)
      })
    }

    ## 2.9 Expiry watch --------------------------------------------------------

    # Always-on expiry watcher to clear expired tokens and optionally reauth
    shiny::observe({
      tok <- values$token

      # default wake
      wake_ms <- refresh_check_interval

      if (!is.null(tok)) {
        now <- as.numeric(Sys.time())

        # Reauth-after window (max session age); ignored when indefinite_session
        if (!isTRUE(indefinite_session) && !is.null(reauth_after_seconds)) {
          started <- tryCatch(values$auth_started_at, error = function(...) {
            NA_real_
          })
          if (is.finite(started) && !is.na(started)) {
            until_reauth <- reauth_after_seconds - (now - started)
            if (
              is.finite(until_reauth) &&
                !is.na(until_reauth) &&
                until_reauth > 0
            ) {
              wake_ms <- min(
                wake_ms,
                shiny_timer_delay_ms(until_reauth)
              )
            } else if ((now - started) >= reauth_after_seconds) {
              # Default behavior clears token and triggers reauth; skip when indefinite_session
              if (!isTRUE(indefinite_session)) {
                .advance_auth_epoch()
                auth_operations$force_oidc_reauth <-
                  provider_uses_oidc(client@provider)
                values$token <- NULL
                values$error <- "reauth_required"
                values$error_description <- sprintf(
                  "Reauthentication required after %d seconds",
                  as.integer(reauth_after_seconds)
                )
                try(
                  audit_event(
                    "session_cleared",
                    context = list(
                      provider = client@provider@name %||% NA_character_,
                      issuer = client@provider@issuer %||% NA_character_,
                      client_id_digest = string_digest(client@client_id),
                      reason = "reauth_window"
                    )
                  ),
                  silent = TRUE
                )
                if (
                  isTRUE(auto_redirect) &&
                    !isTRUE(values$reauth_triggered)
                ) {
                  values$reauth_triggered <- TRUE
                  try(values$request_login())
                }
                # schedule soon to continue flow
                shiny::invalidateLater(250L, session)
                return()
              }
            }
          }
        }

        # Standard expiry check; ignored when indefinite_session
        if (!isTRUE(indefinite_session)) {
          exp <- tryCatch(tok@expires_at, error = function(...) NA_real_)
          if (is.finite(exp) && !is.na(exp)) {
            remaining <- exp - now

            # Grace window: if proactive refresh is enabled and a refresh is
            # in progress, or we're still within the lead window plus a small
            # buffer, defer clearing/reauth to allow the refresh to complete.
            # This avoids a race where the expiry watcher triggers reauth
            # while an async refresh is in flight under a slow IdP/network.
            refresh_grace_seconds <- if (isTRUE(refresh_proactively)) {
              refresh_lead_seconds + 5
            } else {
              0
            }
            in_grace_window <- (remaining > -refresh_grace_seconds)

            if (!is.na(remaining) && remaining <= 0) {
              # Skip clearing if a refresh is in progress and we're within grace
              if (isTRUE(values$refresh_in_progress) && in_grace_window) {
                # Defer: wake soon and check again after refresh completes
                shiny::invalidateLater(500L, session)
                return()
              }
              .advance_auth_epoch()
              auth_operations$force_oidc_reauth <- FALSE
              values$token <- NULL
              values$error <- "token_expired"
              values$error_description <- "Access token expired"
              try(
                audit_event(
                  "session_cleared",
                  context = list(
                    provider = client@provider@name %||% NA_character_,
                    issuer = client@provider@issuer %||% NA_character_,
                    client_id_digest = string_digest(client@client_id),
                    reason = "token_expired"
                  )
                ),
                silent = TRUE
              )
              if (
                isTRUE(auto_redirect) &&
                  !isTRUE(values$reauth_triggered)
              ) {
                values$reauth_triggered <- TRUE
                try(values$request_login())
              }
              shiny::invalidateLater(250L, session)
              return()
            }
            # schedule to wake right at expiry as a safeguard
            wake_ms <- min(wake_ms, shiny_timer_delay_ms(remaining))
          }
        } else {
          # When indefinite_session = TRUE, flag a past-expiry token as stale
          exp <- tryCatch(tok@expires_at, error = function(...) NA_real_)
          if (is.finite(exp) && !is.na(exp)) {
            if (now >= exp) {
              values$token_stale <- TRUE
            }
          }
        }
      }

      shiny::invalidateLater(wake_ms, session)
    })

    ## 2.10 Return reactive values ---------------------------------------------

    return(values)
  })
}

# 2 Browser client helpers -----------------------------------------------------

## 2.1 Browser-token message helpers -------------------------------------------

# Exclude private inputs in module scope. Shiny's module onBookmark callbacks
# receive a separate save-state object, so the defense-in-depth hook must update
# the root save state's exclusions, which both URL and disk serializers use.
exclude_oauth_module_bookmarks <- function(session) {
  private_inputs <- c(
    "shinyOAuth_sid",
    "shinyOAuth_cookie_ack",
    "shinyOAuth_cookie_error"
  )
  shiny::setBookmarkExclude(
    union(session$getBookmarkExclude(), private_inputs),
    session = session
  )
  private_names <- session$ns(private_inputs)
  shiny::onBookmark(
    function(state) {
      state$exclude <- union(state$exclude, private_names)
    },
    session = session$rootScope()
  )
  invisible(NULL)
}

# Helpers in this section send messages to handlers defined in
# `inst/www/shinyOAuth.js`, which applications load with `use_shinyOAuth()`.

#' Build a browser-token cookie instance name
#'
#' Used by [oauth_module_server()] when asking the browser to set or clear the
#' first-party browser-token cookie. The returned suffix is derived from the
#' Shiny namespace and includes a short hash so sanitized namespace collisions
#' remain unlikely.
#'
#' @param session Shiny session object for the module instance.
#' @param id Module id used as a fallback when the session namespace cannot be
#'   read.
#' @return A single safe instance string containing only letters, numbers,
#'   underscores, and hyphens.
#' @keywords internal
#' @noRd
build_oauth_module_browser_token_instance <- function(session, id) {
  ns_prefix <- tryCatch(session$ns(""), error = function(...) id %||% "")
  instance <- sub("-$", "", ns_prefix)
  ns_hash <- substr(as.character(openssl::sha256(ns_prefix)), 1, 8)
  instance <- gsub("[^A-Za-z0-9_\\-]", "-", instance)
  paste0(instance, "-", ns_hash)
}

#' Ask the browser to set the browser-token cookie
#'
#' Used by [oauth_module_server()] after the server resolves cookie lifetime,
#' path, and SameSite policy for the current module instance.
#'
#' @param session Shiny session object for the module instance.
#' @param instance Browser-token cookie instance suffix.
#' @param max_age_ms Cookie lifetime in milliseconds.
#' @param request_id Optional identifier for a fresh cookie acknowledgment.
#' @param token Optional server-selected binding for a new authorization request.
#' @param same_site SameSite policy string.
#' @param path Cookie path, or `NULL` to let the JavaScript handler use its
#'   default.
#' @return Invisibly returns `NULL`.
#'
#' @keywords internal
#' @noRd
send_oauth_module_set_browser_token <- function(
  session,
  instance,
  max_age_ms,
  same_site,
  path,
  request_id = NULL,
  token = NULL
) {
  session$sendCustomMessage(
    type = "shinyOAuth:setBrowserToken",
    message = list(
      instance = instance,
      maxAgeMs = max_age_ms,
      sameSite = same_site,
      path = path,
      inputId = session$ns("shinyOAuth_sid"),
      requestId = request_id,
      token = token,
      ackInputId = session$ns("shinyOAuth_cookie_ack"),
      errorInputId = session$ns("shinyOAuth_cookie_error")
    )
  )

  invisible(NULL)
}

#' Ask the browser to clear the browser-token cookie
#'
#' Used by [oauth_module_server()] when logout, successful callback handling,
#' or browser-token repair needs to reset the session binding.
#'
#' @param session Shiny session object for the module instance.
#' @param instance Browser-token cookie instance suffix.
#' @param same_site SameSite policy string.
#' @param path Cookie path, or `NULL` to let the JavaScript handler use its
#'   default.
#' @return Invisibly returns `NULL`.
#'
#' @keywords internal
#' @noRd
send_oauth_module_clear_browser_token <- function(
  session,
  instance,
  same_site,
  path
) {
  session$sendCustomMessage(
    type = "shinyOAuth:clearBrowserToken",
    message = list(
      instance = instance,
      sameSite = same_site,
      path = path,
      # Let the client also clear the mirrored Shiny input so a subsequent
      # cookie reissue will always propagate a changed value back to the server.
      inputId = session$ns("shinyOAuth_sid")
    )
  )

  invisible(NULL)
}

## 2.2 Browser navigation helpers ----------------------------------------------

#' Ask the browser to redirect
#'
#' Used by [oauth_module_server()] after an authorization URL has been built
#' and the module is ready to send the user to the provider.
#'
#' @param session Shiny session object for the module instance.
#' @param url Absolute URL to open in the browser.
#' @return Invisibly returns `NULL`.
#'
#' @keywords internal
#' @noRd
send_oauth_module_redirect <- function(session, url) {
  session$sendCustomMessage(
    type = "shinyOAuth:redirect",
    message = list(url = url)
  )

  invisible(NULL)
}

#' Clear OAuth callback parameters in the browser
#'
#' Used by [oauth_module_server()] after callback handling, provider error
#' handling, and callback-query validation failures. It removes OAuth callback
#' parameters from the address bar and optionally restores the tab title.
#'
#' @param session Shiny session object for the module instance.
#' @param title_replacement Optional title to restore.
#' @param clean_title Whether the browser should normalize the title text.
#' @param drop_response Whether the browser should always remove the
#'   `response` query parameter.
#' @return Invisibly returns `NULL`.
#'
#' @keywords internal
#' @noRd
clear_oauth_module_callback_query <- function(
  session,
  title_replacement,
  clean_title,
  drop_response = FALSE
) {
  session$sendCustomMessage(
    type = "shinyOAuth:clearQueryAndFixTitle",
    message = list(
      titleReplacement = if (!is.null(title_replacement)) {
        title_replacement
      } else {
        NULL
      },
      cleanTitle = isTRUE(clean_title),
      dropResponse = isTRUE(drop_response)
    )
  )

  invisible(NULL)
}

# 3 Callback query helpers -----------------------------------------------------

## 3.1 Callback query detection and cleanup ------------------------------------

#' Canonicalize an OAuth callback route
#'
#' Reduces an absolute URI to the browser-routing components that identify an
#' OAuth callback endpoint: scheme, authority, and path. Query and fragment
#' components are deliberately excluded. Scheme and host are case-normalized,
#' and explicit default ports are normalized away.
#'
#' @param uri Absolute callback URI.
#' @return A named list containing `scheme`, `hostname`, `port`, and `path`, or
#'   `NULL` when `uri` is not a usable absolute callback URI.
#' @keywords internal
#' @noRd
oauth_callback_route <- function(uri) {
  if (!is_valid_string(uri)) {
    return(NULL)
  }

  parsed <- tryCatch(httr2::url_parse(uri), error = function(...) NULL)
  if (is.null(parsed)) {
    return(NULL)
  }

  scalar_component <- function(value) {
    value <- as.character(value %||% "")
    if (length(value) != 1L || is.na(value)) "" else value
  }
  scheme <- tolower(scalar_component(parsed[["scheme"]]))
  hostname <- tolower(scalar_component(parsed[["hostname"]]))
  port <- scalar_component(parsed[["port"]])
  path <- scalar_component(parsed[["path"]])
  if (!nzchar(scheme) || !nzchar(hostname)) {
    return(NULL)
  }
  if (!nzchar(path)) {
    path <- "/"
  }
  if (
    (identical(scheme, "http") && identical(port, "80")) ||
      (identical(scheme, "https") && identical(port, "443"))
  ) {
    port <- ""
  }

  list(
    scheme = scheme,
    hostname = hostname,
    port = port,
    path = path
  )
}

#' Compare OAuth callback routes
#'
#' @param current_uri Browser-visible absolute URI receiving the callback.
#' @param redirect_uri Configured OAuth redirect URI.
#' @return `TRUE` only when canonical scheme, authority, path, and registered
#'   fixed query values match.
#' @keywords internal
#' @noRd
oauth_callback_route_matches <- function(current_uri, redirect_uri) {
  current <- oauth_callback_route(current_uri)
  expected <- oauth_callback_route(redirect_uri)
  !is.null(current) &&
    !is.null(expected) &&
    identical(current, expected) &&
    oauth_callback_fixed_query_matches(
      oauth_callback_uri_query(current_uri),
      oauth_callback_uri_query(redirect_uri)
    )
}

oauth_callback_uri_query <- function(uri) {
  uri <- sub("#.*$", "", uri)
  if (!grepl("?", uri, fixed = TRUE)) {
    return("")
  }
  sub("^[^?]*\\?", "", uri)
}

# Compare each registered name as a multiset, retaining duplicate values.
# Additional OAuth fields and application parameters do not change the fixed
# context, but an extra value for a registered name does.
oauth_callback_fixed_query_matches <- function(current, registered) {
  pairs <- function(query) {
    query <- sub("^\\?", "", query %||% "")
    parts <- strsplit(query, "&", fixed = TRUE)[[1L]]
    parts <- parts[nzchar(parts)]
    decode <- function(value) {
      if (grepl("(?i)%00|%(?![0-9a-f]{2})", value, perl = TRUE)) {
        stop("Invalid query encoding")
      }
      value <- utils::URLdecode(gsub("+", " ", value, fixed = TRUE))
      if (!validUTF8(value)) {
        stop("Invalid query encoding")
      }
      value
    }
    keys <- vapply(parts, function(part) decode(sub("=.*$", "", part)), "")
    values <- vapply(
      parts,
      function(part) {
        decode(
          if (grepl("=", part, fixed = TRUE)) sub("^[^=]*=", "", part) else ""
        )
      },
      ""
    )
    split(unname(values), keys)
  }
  if (!nzchar(registered)) {
    return(TRUE)
  }
  tryCatch(
    {
      expected <- pairs(registered)
      actual <- pairs(current)
      all(vapply(
        names(expected),
        function(name) {
          identical(sort(actual[[name]]), sort(expected[[name]]))
        },
        logical(1)
      ))
    },
    error = function(...) FALSE,
    warning = function(...) FALSE
  )
}

#' Read the browser-visible callback URI from a Shiny session
#'
#' @param session Active Shiny session.
#' @return Absolute browser URI including its query, without fragment, or `NULL` when the
#'   necessary client data is unavailable.
#' @keywords internal
#' @noRd
oauth_shiny_session_callback_uri <- function(session) {
  component <- function(name) {
    tryCatch(
      as.character(session$clientData[[name]] %||% NA_character_),
      error = function(...) NA_character_
    )
  }

  protocol <- component("url_protocol")
  hostname <- component("url_hostname")
  port <- component("url_port")
  pathname <- component("url_pathname")
  if (
    !is_valid_string(protocol) ||
      !grepl("^[A-Za-z][A-Za-z0-9+.-]*:$", protocol) ||
      !is_valid_string(hostname) ||
      !is_valid_string(pathname) ||
      !startsWith(pathname, "/")
  ) {
    return(NULL)
  }

  # Bracket raw IPv6 hostnames before constructing an absolute URI.
  if (grepl(":", hostname, fixed = TRUE) && !startsWith(hostname, "[")) {
    hostname <- paste0("[", hostname, "]")
  }
  port_suffix <- if (is_valid_string(port)) paste0(":", port) else ""
  search <- component("url_search")
  if (!is_valid_string(search)) {
    search <- ""
  }
  paste0(protocol, "//", hostname, port_suffix, pathname, search)
}

# OAuth/OIDC callback parameters that should be recognized and removed from the
# browser URL after callback handling. This keeps provider data out of browser
# history while preserving unrelated application query parameters. The JARM
# `response` parameter is handled separately so ordinary app queries like
# `?response=ok` are not treated as OAuth callbacks.
oauth_module_callback_query_keys <- c(
  "code",
  "state",
  "session_state",
  "id_token",
  "access_token",
  "token_type",
  "expires_in",
  "error",
  "error_description",
  "error_uri",
  "iss",
  "shinyOAuth_form_post",
  "shinyOAuth_form_post_id"
)

#' Check whether a query response value looks like compact JARM
#'
#' Used by callback-query helpers so ordinary app parameters named `response`
#' are ignored unless they look like a compact JWS/JWE.
#'
#' @param response Query parameter value.
#' @return `TRUE` when `response` looks like a compact JWS/JWE; otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
oauth_module_query_has_jarm_response <- function(response) {
  if (!is_valid_string(response)) {
    return(FALSE)
  }

  parts <- strsplit(response, ".", fixed = TRUE)[[1]]
  if (!length(parts) %in% c(3L, 5L)) {
    return(FALSE)
  }

  all(vapply(
    parts,
    function(part) {
      is.character(part) &&
        length(part) == 1L &&
        nzchar(part) &&
        grepl("^[A-Za-z0-9_-]+$", part)
    },
    logical(1)
  ))
}

#' Collect repeated raw query parameter values
#'
#' Used by callback-query helpers that must inspect repeated parameters before
#' `shiny::parseQueryString()` can collapse them to a single value.
#'
#' @param query_string Raw query string, with or without a leading `?`.
#' @param key Parameter name to collect.
#' @return Character vector of decoded values for matching parameters.
#' @keywords internal
#' @noRd
oauth_module_query_raw_values <- function(query_string, key) {
  raw <- sub("^\\?", "", query_string %||% "")
  if (!nzchar(raw) || !is_valid_string(key)) {
    return(character())
  }

  parts <- strsplit(raw, "&", fixed = TRUE)[[1]]
  parts <- parts[nzchar(parts)]
  if (!length(parts)) {
    return(character())
  }

  values <- character(0)
  for (part in parts) {
    raw_key <- sub("=.*$", "", part)
    decoded_key <- tryCatch(
      utils::URLdecode(gsub("\\+", " ", raw_key)),
      error = function(...) raw_key,
      warning = function(...) raw_key
    )
    if (!identical(decoded_key, key)) {
      next
    }

    raw_value <- if (grepl("=", part, fixed = TRUE)) {
      sub("^[^=]*=", "", part)
    } else {
      ""
    }
    decoded_value <- tryCatch(
      utils::URLdecode(gsub("\\+", " ", raw_value)),
      error = function(...) raw_value,
      warning = function(...) raw_value
    )
    values <- c(values, decoded_value)
  }

  values
}

#' Check whether any raw response value looks like compact JARM
#'
#' Used by callback-query helpers so repeated `response` parameters are treated
#' as callback data whenever any individual value looks like compact JWS/JWE.
#'
#' @param query_string Raw query string, with or without a leading `?`.
#' @return `TRUE` when any raw `response` value looks like compact JARM.
#' @keywords internal
#' @noRd
oauth_module_query_has_raw_jarm_response <- function(query_string) {
  response_values <- oauth_module_query_raw_values(query_string, "response")
  if (!length(response_values)) {
    return(FALSE)
  }

  any(vapply(
    response_values,
    oauth_module_query_has_jarm_response,
    logical(1)
  ))
}

#' Check whether a query string contains OAuth callback keys
#'
#' Used by [oauth_module_server()] to decide whether URL cleanup is needed when
#' a callback-like query reaches a session that is already authenticated.
#'
#' @param query_string Raw query string, with or without a leading `?`.
#' @param query_jarm_client Logical. Whether a compact-looking `response`
#'   parameter should be treated as a query JARM callback.
#' @param response_is_callback Logical. Whether the caller has already decided
#'   that `response` is reserved callback data for the current route.
#' @return `TRUE` when OAuth callback keys are present; otherwise `FALSE`.
#' @keywords internal
#' @noRd
oauth_module_query_has_callback_keys <- function(
  query_string,
  query_jarm_client = FALSE,
  response_is_callback = FALSE
) {
  raw <- sub("^\\?", "", query_string %||% "")
  if (!nzchar(raw)) {
    return(FALSE)
  }

  parts <- strsplit(raw, "&", fixed = TRUE)[[1]]
  parts <- parts[nzchar(parts)]
  if (!length(parts)) {
    return(FALSE)
  }

  raw_names <- vapply(parts, function(part) sub("=.*$", "", part), "")
  decoded_names <- vapply(
    raw_names,
    function(name) {
      tryCatch(
        utils::URLdecode(gsub("\\+", " ", name)),
        error = function(...) name,
        warning = function(...) name
      )
    },
    ""
  )

  any(decoded_names %in% oauth_module_callback_query_keys) ||
    isTRUE(response_is_callback) ||
    (isTRUE(query_jarm_client) &&
      isTRUE(oauth_module_query_has_raw_jarm_response(query_string)))
}

#' Reject duplicate OAuth callback query parameters
#'
#' Used before parsing callback query strings so repeated OAuth parameters
#' cannot be smuggled through parser-specific first/last-value behavior.
#'
#' @param query_string Raw query string, with or without a leading `?`.
#' @param query_jarm_client Logical. Whether a compact-looking `response`
#'   parameter should be treated as a query JARM callback.
#' @param response_is_callback Logical. Whether the caller has already decided
#'   that `response` is reserved callback data for the current route.
#' @return Invisibly returns `NULL` on success.
#' @keywords internal
#' @noRd
reject_duplicate_oauth_module_callback_query <- function(
  query_string,
  query_jarm_client = FALSE,
  response_is_callback = FALSE
) {
  raw <- sub("^\\?", "", query_string %||% "")
  if (!nzchar(raw)) {
    return(invisible(NULL))
  }

  parts <- strsplit(raw, "&", fixed = TRUE)[[1]]
  parts <- parts[nzchar(parts)]
  if (!length(parts)) {
    return(invisible(NULL))
  }

  seen <- character(0)
  response_is_callback_key <-
    isTRUE(response_is_callback) ||
    (isTRUE(query_jarm_client) &&
      isTRUE(oauth_module_query_has_raw_jarm_response(query_string)))
  for (part in parts) {
    key <- sub("=.*$", "", part)
    if (grepl("(?i)%00|%(?![0-9a-f]{2})", key, perl = TRUE)) {
      err_invalid_state(
        "Callback query contains malformed percent-encoded parameter name",
        context = list(component = "query_string")
      )
    }
    key <- tryCatch(
      utils::URLdecode(key),
      warning = function(e) {
        err_invalid_state(
          "Callback query contains malformed percent-encoded parameter name",
          context = list(component = "query_string")
        )
      },
      error = function(e) {
        err_invalid_state(
          "Callback query contains malformed percent-encoded parameter name",
          context = list(component = "query_string")
        )
      }
    )

    is_callback_key <- key %in% oauth_module_callback_query_keys
    if (identical(key, "response")) {
      is_callback_key <- isTRUE(response_is_callback_key)
    }

    if (isTRUE(is_callback_key)) {
      if (key %in% seen) {
        err_invalid_state(
          paste0("Callback query contains duplicate OAuth parameter: ", key),
          context = list(
            component = "query_string",
            parameter = key
          )
        )
      }
      seen <- c(seen, key)
    }
  }

  invisible(NULL)
}

#' Strip OAuth callback parameters from a query string
#'
#' Used by [oauth_module_server()] and tests after callback processing. The
#' helper removes provider callback data from the query string while preserving
#' unrelated application parameters.
#'
#' @param query_string Raw query string, with or without a leading `?`.
#' @param query_jarm_client Logical. Whether a compact-looking `response`
#'   parameter should be treated as a query JARM callback.
#' @return Cleaned query string beginning with `?`, or `""` when no non-OAuth
#'   parameters remain.
#' @keywords internal
#' @noRd
strip_oauth_module_callback_query <- function(
  query_string,
  query_jarm_client = FALSE
) {
  raw <- sub("^\\?", "", query_string %||% "")
  if (!nzchar(raw)) {
    return("")
  }

  # `shiny::parseQueryString()` returns character vectors, preserving repeated
  # keys as vectors. Rebuild through httr2 so kept parameters are encoded.
  parsed <- tryCatch(
    shiny::parseQueryString(paste0("?", raw)),
    error = function(...) list()
  )
  if (!length(parsed)) {
    return("")
  }

  drop_names <- oauth_module_callback_query_keys
  if (
    isTRUE(query_jarm_client) &&
      isTRUE(oauth_module_query_has_raw_jarm_response(query_string))
  ) {
    drop_names <- c(drop_names, "response")
  }

  keep <- parsed[setdiff(names(parsed), drop_names)]
  if (!length(keep)) {
    return("")
  }

  q <- tryCatch(httr2::url_query_build(keep), error = function(...) "")
  if (!nzchar(q)) {
    return("")
  }

  paste0("?", q)
}

# 4 Module error helpers -------------------------------------------------------

## 4.1 Condition inspection and formatting -------------------------------------

#' Internal: extract a trace id from a condition-like object
#'
#' Used by `oauth_module_compose_error()` so module error messages can surface a
#' trace id without relying on partial matching.
#'
#' @param e Condition or error-like object.
#' @return Trace id string or `NULL`.
#' @keywords internal
#' @noRd
oauth_module_extract_trace_id <- function(e) {
  tid <- tryCatch(e[["trace_id"]], error = function(...) NULL)
  if (!is.null(tid) && length(tid) && nzchar(as.character(tid)[1])) {
    return(as.character(tid)[1])
  }
  for (nm in c("traceId", "trace", "stack")) {
    value <- tryCatch(e[[nm]], error = function(...) NULL)
    if (!is.null(value) && length(value) && nzchar(as.character(value)[1])) {
      return(as.character(value)[1])
    }
  }
  NULL
}

#' Internal: compose a readable module error string
#'
#' Used by [oauth_module_server()] before internal conditions are stored in the
#' module's exposed reactive error state.
#'
#' @param e Caught condition.
#' @param phase Optional phase label for logging context.
#' @return Single display string, optionally suffixed with the trace id.
#' @keywords internal
#' @noRd
oauth_module_compose_error <- function(e, phase = NULL) {
  if (!is.null(phase)) {
    try(log_condition(e, context = list(phase = phase)))
  }
  msg <- tryCatch(
    if (allow_expose_error_body()) {
      sanitize_diagnostic_text(conditionMessage(e))
    } else {
      short_desc_for_class(class(e))
    },
    error = function(...) {
      "Unknown error"
    }
  )
  tid <- oauth_module_extract_trace_id(e)
  if (!is.null(tid)) sprintf("%s (trace %s)", msg, tid) else msg
}

#' Internal: test whether a condition chain inherits from a class
#'
#' Used by `oauth_module_callback_failure_error_code()` so callback failures can
#' distinguish invalid-state errors from token-exchange failures.
#'
#' @param e Condition to inspect.
#' @param class_name Condition class to look for.
#' @return `TRUE` when the condition chain inherits from `class_name`, otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
oauth_module_condition_inherits <- function(e, class_name) {
  cur <- e

  while (!is.null(cur)) {
    if (inherits(cur, class_name)) {
      return(TRUE)
    }

    cur <- tryCatch(
      cur[["parent"]],
      error = function(...) NULL
    )
  }

  FALSE
}

#' Internal: map a callback failure to a module error code
#'
#' Used by [oauth_module_server()] after callback handling fails in sync or
#' async paths.
#'
#' @param e Callback-handling condition.
#' @return Module error code string.
#' @keywords internal
#' @noRd
oauth_module_callback_failure_error_code <- function(e) {
  if (oauth_module_condition_inherits(e, "shinyOAuth_state_error")) {
    return("invalid_state")
  }

  "token_exchange_error"
}
