#' @title
#' OAuth 2.0 & OIDC authentication module for Shiny applications
#'
#' @description
#' This function implements a Shiny module server that manages OAuth 2.0/OIDC
#' authentication for Shiny applications. It handles the OAuth 2.0/OIDC flow,
#' including redirecting users to the authorization endpoint, securely processing the
#' callback, exchanging authorization codes for tokens, verifying tokens,
#' and managing token refresh. It also provides options for automatic or
#' manual login flows, session expiry, and proactive token refresh.
#'
#' Note: when using this module, you must include
#' `shinyOAuth::use_shinyOAuth()` in your UI definition to load the
#' necessary JavaScript dependencies.
#'
#' @details
#' - Blocking vs. async behavior: when `async = FALSE` (the default), network
#'   operations like token exchange and refresh are performed on the main R
#'   thread. Transient errors are retried by the package's internal
#'   `req_with_retry()` helper, which currently uses `Sys.sleep()` for backoff.
#'   In Shiny, `Sys.sleep()` blocks the event loop for the entire worker
#'   process, potentially freezing UI updates for all sessions on that worker
#'   during slow provider responses or retry backoff. To keep the UI
#'   responsive: set `async = TRUE` so network calls run in a background future
#'   via the promises package (configure a multisession/multicore backend), or
#'   reduce/block retries (see `vignette("usage", package = "shinyOAuth")`).
#'
#' - Browser requirements: the module relies on the browser's Web Crypto API to
#'   generate a secure, per-session browser token used for state double-submit
#'   protection. Specifically, the login flow requires
#'   `window.crypto.getRandomValues` to be available. If it is not present (for
#'   example, in some very old or highly locked-down browsers), the module will
#'   be unable to proceed with authentication. In that case a client-side error
#'   is emitted and surfaced to the server as `shinyOAuth_cookie_error`
#'   containing the message `"webcrypto_unavailable"`. Use a modern browser (or
#'   enable Web Crypto) to resolve this.
#'
#' - Browser cookie lifetime: the opaque browser token cookie lifetime mirrors the
#'   client's `state_store` TTL. Internally, the module reads
#'   `client@state_store$info()$max_age` and uses that value for the cookie's
#'   `Max-Age`/`Expires`. When the cache does not expose a finite `max_age`, a
#'   conservative default of 5 minutes (300 seconds) is used to align with the
#'   built-in `cachem::cache_mem(max_age = 300)` default. Separately, the state
#'   payload `issued_at` freshness window is controlled by the client's
#'   `state_payload_max_age` (default 300 seconds).
#'
#' - Watchdog for missing browser token: to catch misconfiguration early during
#'   development, the module includes a short watchdog. If the browser token
#'   cookie is not set within 1500ms of module initialization, a warning
#'   is emitted to the R console. This likely means you forgot to include
#'   `use_shinyOAuth()` in your UI, but it may also indicate that a user
#'   of your app is using a browser with JavaScript disabled. The watchdog
#'   prints a warning only once per R session, but if you want to suppress it
#'   permanently, you can set `options(shinyOAuth.disable_watchdog_warning = TRUE)`.
#'
#' @param id Shiny module id
#' @param client [OAuthClient] object
#'
#' @param auto_redirect If TRUE (default), unauthenticated sessions will
#'   immediately initiate the OAuth flow by redirecting the browser to the
#'   authorization endpoint. If FALSE, the module will not auto-redirect;
#'   instead, the returned object exposes helpers for triggering login
#'   manually (use: `$request_login()`)
#'
#' @param async If TRUE, performs token exchange and refresh in the background
#'   using the promises package (future_promise), and updates values when the
#'   promise resolves. Requires the [promises] package and a suitable
#'   backend to be configured with [future::plan()].
#'   If FALSE (default), token exchange and refresh are performed synchronously
#'   (which may block the Shiny event loop; it is thus strongly recommended to set
#'   `async = TRUE` in production apps)
#'
#' @param indefinite_session If TRUE, the module will not automatically clear
#'   the token due to access-token expiry or the `reauth_after_seconds` window,
#'   and it will not trigger automatic reauthentication when a token expires or
#'   a refresh fails. This effectively makes sessions "indefinite" from the
#'   module's perspective once a user has logged in. Note that your API calls
#'   may still fail once the provider considers the token expired; this option
#'   only affects the module's automatic clearing/redirect behavior
#'
#' @param reauth_after_seconds Optional maximum session age in seconds. If set,
#'  the module will remove the token (and thus set `authenticated` to FALSE)
#'  after this many seconds have elapsed since authentication started. By
#'  default this is `NULL` (no forced re-authentication). If a value is
#'  provided, the timer is reset after each successful refresh so the knob is
#'  opt-in and counts rolling session age
#'
#' @param refresh_proactively If TRUE, will automatically refresh tokens
#'  before they expire (if refresh token is available). The refresh is
#'  scheduled adaptively so that it executes approximately at
#'  `expires_at - refresh_lead_seconds` rather than on a coarse polling loop
#' @param refresh_lead_seconds Number of seconds before expiry to attempt
#'  proactive refresh (default: 60)
#' @param refresh_check_interval Fallback check interval in milliseconds for
#'  expiry/refresh (default: 10000 ms). When expiry is known, the module uses
#'  adaptive scheduling to wake up exactly when needed; this interval is used
#'  as a safety net or when expiry is unknown/infinite
#'
#' @param tab_title_cleaning If TRUE (default), removes any query string suffix
#'   from the browser tab title after the OAuth callback, so titles like
#'   "localhost:8100?code=...&state=..." become "localhost:8100"
#' @param tab_title_replacement Optional character string to explicitly set the
#'   browser tab title after the OAuth callback. If provided, it takes
#'   precedence over `tab_title_cleaning`
#'
#' @param browser_cookie_path Optional cookie Path to scope the browser token
#'   cookie. By default (`NULL`), the path is fixed to "/" for reliable
#'   clearing across route changes. Provide an explicit path (e.g., "/app")
#'   to narrow the cookie's scope to a sub-route. Note: when the path is "/"
#'   and the page is served over HTTPS, the cookie name uses the `__Host-`
#'   prefix (Secure, Path=/) for additional hardening; when the path is not
#'   "/", a regular cookie name is used.
#'
#'   For apps deployed under nested routes or where the OAuth callback may land
#'   on a different route than the initial page, keeping the default (root path)
#'   ensures the browser token cookie is available and clearable across app
#'   routes. If you deliberately scope the cookie to a sub-path, make sure all
#'   relevant routes share that prefix.
#' @param browser_cookie_samesite SameSite value for the browser-token cookie.
#'   One of "Strict", "Lax", or "None". Defaults to "Strict" for maximum
#'   protection against cross-site request forgery. Use "Lax" only when your
#'   deployment requires the cookie to accompany top-level cross-site
#'   navigations (for example, because of reverse-proxy flows), and document the
#'   associated risk. If set to "None", the cookie will be marked
#'   `SameSite=None; Secure` in the browser, and authentication will error on
#'   non-HTTPS origins because browsers reject `SameSite=None` cookies without
#'   the `Secure` attribute
#'
#' @return A reactiveValues object with `token`, `error`, `error_description`,
#'   and `authenticated`, plus additional fields used by the module.
#'
#'   The returned reactiveValues contains the following fields:
#'
#'   \itemize{
#'    \item `authenticated`: logical TRUE when there is no error and a token is
#'    present and valid (matching the verifications enabled in the client provider);
#'    FALSE otherwise.
#'    \item `token`: [OAuthToken] object, or NULL if not yet authenticated.
#'    This contains the access token, refresh token (if any), ID token (if
#'    any), and userinfo (if fetched). See [OAuthToken] for details.
#'    Note that since [OAuthToken] is a S7 object, you access its fields
#'    with `@`, e.g., `token@userinfo`.
#'    \item `error`: error code string when the OAuth flow fails.
#'    Be careful with exposing this directly to users, as it may
#'    contain sensitive information which could aid an attacker.
#'    \item `error_description`: human-readable error detail when available.
#'    Be extra careful with exposing this directly to users, as it may
#'    contain even more sensitive information which could aid an attacker.
#'    \item `browser_token`: internal opaque browser cookie value; used for state
#'    double-submit protection; NULL if not yet set
#'    \item `pending_callback`: internal list(code, state); used to defer token
#'    exchange until `browser_token` is available; NULL otherwise.
#'    \item `pending_error`: internal list(error, error_description, state); used to
#'    defer error-response state consumption until `browser_token` is available;
#'    NULL otherwise.
#'    \item `pending_login`: internal logical; TRUE when a login was requested but must
#'    wait for `browser_token` to be set, FALSE otherwise.
#'    \item `auto_redirected`: internal logical; TRUE once the module has initiated an
#'    automatic redirect in this session to avoid duplicate redirects.
#'    \item `reauth_triggered`: internal logical; TRUE once a reauthentication attempt
#'    has been initiated (after expiry or failed refresh), to avoid loops.
#'    \item `auth_started_at`: internal numeric timestamp (as from `Sys.time()`) when
#'    authentication started; NA if not yet authenticated. Used to enforce
#'    `reauth_after_seconds` if set.
#'    \item `token_stale`: logical; TRUE when the token was kept despite a refresh
#'    failure because `indefinite_session = TRUE`, or when the access token is past
#'    its expiry but `indefinite_session = TRUE` prevents automatic clearing. This
#'    lets UIs warn users or disable actions that require a fresh token. It resets
#'    to FALSE on successful login, refresh, or logout.
#'    \item `last_login_async_used`: internal logical; TRUE if the last login attempt
#'    used `async = TRUE`, FALSE if it was synchronous. This is only used for
#'    testing and diagnostics.
#'    \item `refresh_in_progress`: internal logical; TRUE while a token refresh
#'    is currently in flight (async or sync). Used to prevent concurrent refresh
#'    attempts when proactive refresh logic wakes up multiple times.
#'   }
#'
#'   It also contains the following helper functions, mainly useful when
#'   `auto_redirect = FALSE` and you want to implement a manual login flow
#'   (e.g., with your own button):
#'
#'   \itemize{
#'    \item `request_login()`: initiates login by redirecting to the
#'    authorization endpoint, with cookie-ensure semantics: if
#'    `browser_token` is missing, the module sets the cookie and defers
#'    the redirect until `browser_token` is present, then redirects.
#'    This is the main entry point for login when `auto_redirect = FALSE`
#'    and you want to trigger login from your own UI
#'    \item `logout()`: clears the current token setting `authenticated` to FALSE,
#'    and clears the browser token cookie. You might call this when the user
#'    clicks a "logout" button
#'    \item `build_auth_url()`: internal; builds and returns the authorization URL,
#'    also storing the relevant state in the client's `state_store` (for
#'    validation during callback). Note that this requires `browser_token` to
#'    be present, so it will throw an error if called too early
#'    (verify with `has_browser_token()` first). Typically you would not call
#'    this directly, but use `request_login()` instead, which calls it internally.
#'    \item `set_browser_token()`: internal; injects JS to set the browser token
#'    cookie if missing. Normally called automatically on first load,
#'    but you can call it manually if needed. If a token is already present,
#'    it will return immediately without changing it (call `clear_browser_token()`
#'    if you want to force a reset). Typically you would not call this directly,
#'    but use `request_login()` instead, which calls it internally if needed.
#'    \item `clear_browser_token()`: internal; injects JS to clear the browser token
#'    cookie and clears `browser_token`. You might call this to reset the
#'    cookie if you suspect it's stale or compromised. Typically you would
#'    not call this directly.
#'    \item `has_browser_token()`: internal; returns TRUE if `browser_token` is
#'    present (non-NULL, non-empty), FALSE otherwise. Typically
#'    you would not call this directly
#'   }
#'
#' @example inst/examples/oauth_module_server.R
#'
#' @export
#'
#' @seealso [use_shinyOAuth()]
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

  tab_title_cleaning = TRUE,
  tab_title_replacement = NULL,

  browser_cookie_path = NULL,
  browser_cookie_samesite = c("Strict", "Lax", "None")
) {
  # Validate parameters ------------------------------------------------------

  S7::check_is_S7(client, class = OAuthClient)

  stopifnot(
    is_valid_string(id),
    is.logical(refresh_proactively) &
      length(refresh_proactively) == 1 &
      !is.na(refresh_proactively),
    is.numeric(refresh_lead_seconds) &
      length(refresh_lead_seconds) == 1 &
      !is.na(refresh_lead_seconds) &
      refresh_lead_seconds >= 0,
    is.numeric(refresh_check_interval) &
      length(refresh_check_interval) == 1 &
      !is.na(refresh_check_interval) &
      refresh_check_interval >= 100,
    is.logical(async) & length(async) == 1 & !is.na(async),
    is.logical(tab_title_cleaning) &
      length(tab_title_cleaning) == 1 &
      !is.na(tab_title_cleaning),
    is.null(tab_title_replacement) || is_valid_string(tab_title_replacement),
    is.logical(auto_redirect) &
      length(auto_redirect) == 1 &
      !is.na(auto_redirect),
    is.null(reauth_after_seconds) ||
      (is.numeric(reauth_after_seconds) &
        length(reauth_after_seconds) == 1 &
        !is.na(reauth_after_seconds) &
        reauth_after_seconds > 0),
    is.logical(indefinite_session) &
      length(indefinite_session) == 1 &
      !is.na(indefinite_session),
    is.null(browser_cookie_path) || is_valid_string(browser_cookie_path)
  )

  if (!.is_test()) {
    rlang::warn(
      c(
        "[{.pkg shinyOAuth}] - {.strong Open your Shiny app in a regular browser}",
        "!" = "{.code oauth_module_server()} was called; view your app in a standard web browser (e.g., Chrome, Firefox, Safari)",
        "i" = "Viewers in RStudio/Positron/etc. cannot perform necesarry redirects for OAuth 2.0 flows"
      ),
      .frequency = "once",
      .frequency_id = "oauth_module_server_remind_browser"
    )
  }

  warn_about_missing_js_dependency()

  browser_cookie_samesite <- match.arg(browser_cookie_samesite)
  if (identical(browser_cookie_samesite, "Lax")) {
    rlang::warn(c(
      "[{.pkg shinyOAuth}] - {.strong Verify browser token cookie settings}",
      "!" = "`browser_cookie_samesite = \"Lax\"` relaxes cross-site protections for the session-binding cookie",
      "i" = "Ensure this mode is strictly required for your deployment"
    ))
  }
  if (identical(browser_cookie_samesite, "None")) {
    rlang::inform(c(
      "[{.pkg shinyOAuth}] - {.strong Enforcing Secure for SameSite=None cookie}",
      "i" = "`browser_cookie_samesite = \"None\"` requires HTTPS. The browser cookie writer will force `Secure` and error on non-HTTPS origins"
    ))
  }

  # Validate async settings
  if (!isTRUE(async)) {
    if (!.is_test()) {
      rlang::warn(
        c(
          "[{.pkg shinyOAuth}] - {.strong Consider using `async = TRUE` for responsive UIs}",
          "!" = "{.code oauth_module_server(async = FALSE)} may block the Shiny event loop during network calls, potentially freezing the UI",
          "i" = "Consider setting `async = TRUE` and configuring a {.pkg future} backend (e.g., {.code future::plan(future::multisession)})"
        ),
        .frequency = "once",
        .frequency_id = "oauth_module_server_no_async"
      )
    }
  } else {
    # Ensure dependencies are available
    rlang::check_installed(
      c("promises", "future"),
      reason = "to use `async = TRUE` in `oauth_module_server()`"
    )

    # Verify a future plan with workers is set; otherwise warn
    n_workers <- tryCatch(future::nbrOfWorkers(), error = function(...) {
      NA_integer_
    })
    if (!is.finite(n_workers) || is.na(n_workers) || n_workers < 1) {
      rlang::warn(c(
        "[{.pkg shinyOAuth}] - {.strong No future workers available for async operations}",
        "!" = "{.code oauth_module_server(async = TRUE)} but no {.pkg future} workers are available ({.code future::nbrOfWorkers()} < 1); calls will run synchronously",
        "i" = "Set a plan with at least one worker, e.g., {.code future::plan(multisession, workers = 2)}"
      ))
    } else if (n_workers == 1 && !.is_test()) {
      rlang::warn(c(
        "[{.pkg shinyOAuth}] - {.strong Consider using multiple future workers for concurrency}",
        "!" = "{.code oauth_module_server(async = TRUE)} but with a single future worker ({.code future::nbrOfWorkers()} == 1)",
        "i" = "Tasks are offloaded but concurrent jobs may queue. Consider using more workers"
      ))
    }
  }

  # Shiny module ---------------------------------------------------------------

  shiny::moduleServer(id, function(input, output, session) {
    # Reactive values ----------------------------------------------------------

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
      authenticated = FALSE,
      token_stale = FALSE,
      browser_token = browser_token_initial,
      pending_callback = NULL,
      pending_error = NULL,
      pending_login = FALSE,
      auto_redirected = FALSE,
      reauth_triggered = FALSE,
      auth_started_at = NA_real_,
      last_login_async_used = FALSE,
      refresh_in_progress = FALSE
    )

    # Export for tests
    shiny::exportTestValues(
      token = values$token,
      error = values$error,
      error_description = values$error_description,
      authenticated = values$authenticated,
      browser_token = values$browser_token,
      pending_callback = values$pending_callback,
      pending_error = values$pending_error,
      pending_login = values$pending_login,
      auto_redirected = values$auto_redirected,
      reauth_triggered = values$reauth_triggered,
      auth_started_at = values$auth_started_at,
      token_stale = values$token_stale,
      last_login_async_used = values$last_login_async_used,
      refresh_in_progress = values$refresh_in_progress
    )

    # Audit: new Shiny session started (module launched)
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

    # Error handling helpers --------------------------------------------------

    # Safe, exact extraction of a trace identifier from an error-like object
    .get_trace_id <- function(e) {
      # prefer exact indexing, avoid `$` partial matching
      tid <- tryCatch(e[["trace_id", exact = TRUE]], error = function(...) NULL)
      if (!is.null(tid) && length(tid) && nzchar(as.character(tid)[1])) {
        return(as.character(tid)[1])
      }
      # fall back to a few common alternates seen in async/promise/future errors
      for (nm in c("traceId", "trace", "stack")) {
        v <- tryCatch(e[[nm]], error = function(...) NULL)
        if (!is.null(v) && length(v) && nzchar(as.character(v)[1])) {
          return(as.character(v)[1])
        }
      }
      NULL
    }

    # Compose a friendly error message (optionally logs with phase context)
    .compose_error <- function(e, phase = NULL) {
      if (!is.null(phase)) {
        # best-effort logging, never throw
        try(log_condition(e, context = list(phase = phase)))
      }
      msg <- tryCatch(conditionMessage(e), error = function(...) {
        "Unknown error"
      })
      tid <- .get_trace_id(e)
      if (!is.null(tid)) sprintf("%s (trace %s)", msg, tid) else msg
    }

    # Convenience setter for the module's reactive error state
    .set_error <- function(code, e = NULL, phase = NULL, description = NULL) {
      values$error <- code
      values$error_description <- description %||%
        if (!is.null(e)) .compose_error(e, phase) else NULL
    }

    # Client-side actions (CSP-friendly via custom messages) ------------------

    # These helpers communicate with handlers defined in inst/www/shinyOAuth.js,
    # which you load in UI with `use_shinyOAuth()`
    .client_set_browser_token <- function(
      instance,
      max_age_ms,
      same_site,
      path
    ) {
      session$sendCustomMessage(
        type = "shinyOAuth:setBrowserToken",
        message = list(
          instance = instance,
          maxAgeMs = max_age_ms,
          sameSite = same_site,
          path = path,
          inputId = session$ns("shinyOAuth_sid"),
          errorInputId = session$ns("shinyOAuth_cookie_error")
        )
      )
    }

    .client_clear_browser_token <- function(instance, same_site, path) {
      session$sendCustomMessage(
        type = "shinyOAuth:clearBrowserToken",
        message = list(
          instance = instance,
          sameSite = same_site,
          path = path,
          # Let the client also clear the mirrored Shiny input so a subsequent
          # cookie reissue will always propagate a changed value back to the server
          inputId = session$ns("shinyOAuth_sid")
        )
      )
    }

    .client_redirect <- function(url) {
      session$sendCustomMessage(
        type = "shinyOAuth:redirect",
        message = list(url = url)
      )
    }

    .client_clear_query_and_fix_title <- function(
      title_replacement,
      clean_title
    ) {
      session$sendCustomMessage(
        type = "shinyOAuth:clearQueryAndFixTitle",
        message = list(
          titleReplacement = title_replacement,
          cleanTitle = isTRUE(clean_title)
        )
      )
    }

    # Helper: build a filtered query string that removes only OAuth parameters
    # from a raw query string that may start with '?' (returns string starting
    # with '?' or empty string when no params remain). Exposed to tests below.
    .strip_oauth_query <- function(query_string) {
      raw <- sub("^\\?", "", query_string %||% "")
      if (!nzchar(raw)) {
        return("")
      }
      # Parse query to a named list; shiny::parseQueryString returns character
      # vectors, preserving repeated keys as vectors.
      parsed <- tryCatch(
        shiny::parseQueryString(paste0("?", raw)),
        error = function(...) list()
      )
      if (!length(parsed)) {
        return("")
      }
      # Known OAuth/OIDC callback params to drop
      drop_keys <- c(
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
        "iss"
      )
      keep <- parsed[setdiff(names(parsed), drop_keys)]
      if (!length(keep)) {
        return("")
      }
      # Build query with proper encoding
      q <- tryCatch(httr2::url_query_build(keep), error = function(...) "")
      if (!nzchar(q)) {
        return("")
      }
      paste0("?", q)
    }

    # Helper: clear only OAuth params from URL and optionally adjust the title
    .clear_query_and_fix_title <- function() {
      .client_clear_query_and_fix_title(
        title_replacement = if (!is.null(tab_title_replacement)) {
          tab_title_replacement
        } else {
          NULL
        },
        clean_title = isTRUE(tab_title_cleaning)
      )
    }

    # Browser token cookie -----------------------------------------------------

    # Install a small JS snippet to manage a first-party cookie (SameSite configurable)
    # and mirror its value into input$shinyOAuth_sid. We set it once if missing
    # and then keep input in sync on every page load.
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
        reason <- tryCatch(
          as.character(input$shinyOAuth_cookie_error)[1],
          error = function(...) "unknown"
        )

        # Surface a stable machine code and a concise description (do not show
        # description directly to end users; app authors can decide how to render).
        values$error <- "browser_cookie_error"
        values$error_description <- sprintf(
          "Browser cookie/WebCrypto error: %s. Cookies may be blocked or the WebCrypto API is unavailable; authentication cannot proceed.",
          reason %||% "unknown"
        )

        # Stop any pending login loop to avoid repeated redirects while the
        # browser cannot store/read the cookie.
        values$pending_login <- FALSE

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

    .set_browser_token <- function() {
      # Max age (sec), default 1 hour
      max_age_sec <- client_state_store_max_age(client)

      # Build a safe instance suffix from this module's namespace/id
      ns_prefix <- tryCatch(session$ns(""), error = function(...) id %||% "")
      # strip trailing "-" that Shiny adds, then keep only [A-Za-z0-9_-]
      instance <- sub("-$", "", ns_prefix)

      # Calculate hash of the original namespace to ensure uniqueness
      # even if sanitization causes collisions
      ns_hash <- substr(as.character(openssl::md5(ns_prefix)), 1, 8)

      instance <- gsub("[^A-Za-z0-9_\\-]", "-", instance)
      instance <- paste0(instance, "-", ns_hash)

      # Compute configured path once per session (NULL means derive in JS)
      # Delegate to custom JS handler
      .client_set_browser_token(
        instance = instance,
        max_age_ms = max_age_sec * 1000,
        same_site = browser_cookie_samesite,
        path = if (is.null(browser_cookie_path)) NULL else browser_cookie_path
      )
    }

    .clear_browser_token <- function() {
      # Compute configured path once per session (NULL means derive in JS)

      # Delegate to custom JS handler
      # Build a safe instance suffix from this module's namespace/id (match setter)
      ns_prefix <- tryCatch(session$ns(""), error = function(...) id %||% "")
      # strip trailing "-" that Shiny adds, then keep only [A-Za-z0-9_-]
      instance <- sub("-$", "", ns_prefix)

      # Calculate hash of the original namespace to ensure uniqueness
      # even if sanitization causes collisions
      ns_hash <- substr(as.character(openssl::md5(ns_prefix)), 1, 8)

      instance <- gsub("[^A-Za-z0-9_\\-]", "-", instance)
      instance <- paste0(instance, "-", ns_hash)
      .client_clear_browser_token(
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

    .has_browser_token <- function() {
      # Check if we have a browser token
      if (is_valid_string(values$browser_token)) {
        return(TRUE)
      }
      return(FALSE)
    }

    # Track authentication status ----------------------------------------------

    # Helper: compute authentication status
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

      # Optional max session age (reauth window). Refresh does not reset this.
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
          if (now >= exp) return(FALSE)
        }
      }
      # If exp is NA or Inf, treat as not expired here.
      TRUE
    }

    # Keep authenticated in sync like other values; store a plain logical
    shiny::observe({
      # depend on these so we recalc when any changes
      values$token
      values$error
      values$error_description
      values$browser_token
      values$authenticated <- .compute_authenticated()
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

    # Auth URL & redirection helpers -------------------------------------------

    .build_auth_url <- function() {
      # If no browser token yet, defer URL building (return NA) so callers can
      # render a button/link reactively once the cookie arrives
      if (!.has_browser_token()) {
        rlang::abort(
          c(
            "No browser token available",
            "i" = "Call `has_browser_token()` to check and `set_browser_token()` to set one before calling `build_auth_url()`"
          ),
          class = c("shinyOAuth_state_error", "shinyOAuth_error"),
          call = rlang::current_env()
        )
      }

      # Build the auth URL (and set module errors on failure)
      tryCatch(
        prepare_call(
          client,
          browser_token = values$browser_token
        ),
        error = function(e) {
          .set_error("auth_url_error", e, phase = "build_auth_url")
          NA_character_
        }
      )
    }

    .redirect_to <- function(url) {
      if (is.na(url)) {
        return(invisible(FALSE))
      }
      .client_redirect(url)
      invisible(TRUE)
    }

    .initiate_login <- function() {
      # Build URL first; only mark redirected if we successfully issued a redirect
      url <- .build_auth_url()
      ok <- .redirect_to(url)
      if (isTRUE(ok)) {
        values$auto_redirected <- TRUE
      }
    }

    # Request a login, ensuring a browser cookie exists first. This is the
    # single entry point used by auto-redirect, manual login, and reauth.
    .request_login <- function() {
      if (.has_browser_token()) {
        .initiate_login()
      } else {
        .set_browser_token()
        values$pending_login <- TRUE
      }
    }

    # Expose helpers for manual login flows when `auto_redirect = FALSE`:
    values$set_browser_token <- function() .set_browser_token()
    values$clear_browser_token <- function() .clear_browser_token()
    values$has_browser_token <- function() .has_browser_token()
    values$build_auth_url <- function() .build_auth_url()
    values$request_login <- function() .request_login()
    values$logout <- function(reason = "manual_logout") {
      # Clear token and browser cookie, emit audit trail
      try(
        audit_event(
          "logout",
          context = list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            reason = reason
          )
        ),
        silent = TRUE
      )
      values$token <- NULL
      values$error <- "logged_out"
      values$error_description <- NULL
      values$token_stale <- FALSE
      .clear_browser_token()
      # Proactively re-issue a fresh browser token so that a subsequent
      # manual login can redirect immediately without a preparatory click.
      # This maintains session binding without authenticating the user.
      .set_browser_token()
    }

    # Handle callback + auto-redirect ------------------------------------------

    # Handle OAuth flow by listening to clientData$url_search
    shiny::observeEvent(
      session$clientData$url_search,
      {
        .process_query(shiny::isolate(session$clientData$url_search) %||% "")
      },
      priority = 100
    )

    # Function to process query string
    .process_query <- function(query_string) {
      if (!is.null(values$token)) {
        return(invisible(NULL))
      }

      qs <- shiny::parseQueryString(query_string %||% "")

      # Defensive: cap untrusted callback params to avoid memory/log amplification
      # and middleware edge cases with extremely long URLs.
      ok <- tryCatch(
        {
          validate_untrusted_query_param("code", qs$code, max_bytes = 4096)
          validate_untrusted_query_param("state", qs$state, max_bytes = 8192)
          validate_untrusted_query_param("error", qs$error, max_bytes = 256)
          validate_untrusted_query_param(
            "error_description",
            qs$error_description,
            max_bytes = 4096,
            allow_empty = TRUE
          )
          TRUE
        },
        error = function(e) {
          .clear_query_and_fix_title()
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

      # If provider returned an OAuth error response, surface it and abort.
      # Per RFC 6749 section 4.1.2.1 the authorization server may include
      # error and error_description parameters instead of a code.
      if (!is.null(qs$error)) {
        # Clear sensitive callback params even on failure paths to reduce
        # leak risk via referrers, browser history, or logs.
        .clear_query_and_fix_title()
        .handle_error_response(
          error = qs$error,
          error_description = qs$error_description,
          state = qs$state
        )
        return(invisible(NULL))
      }

      # If we're on the callback step, handle immediately and stop here
      if (!is.null(qs$code)) {
        .handle_callback(code = qs$code, state = qs$state)
        return(invisible(NULL))
      }

      # Otherwise, initiate authentication via automatic redirect
      if (isTRUE(auto_redirect) && is.null(values$pending_callback)) {
        .request_login()
      }

      return(invisible(NULL))
    }

    # Function to handle OAuth error responses and consume state if present
    .handle_error_response <- function(error, error_description, state) {
      # Surface the error to the module's reactive state immediately.
      # Even if we can't consume state yet, callers should see the provider error.
      values$error <- error
      values$error_description <- error_description %||% NULL

      # If state is present, we should consume it from the state store to:
      #   1. Reduce stale entries in the cache
      #   2. Align with "always validate state when returned" guidance
      # If the browser token isn't available yet, defer the cleanup until it is.
      if (!is.null(state) && is_valid_string(state)) {
        if (!is_valid_string(values$browser_token)) {
          # Defer until browser_token is available
          values$pending_error <- list(
            error = error,
            error_description = error_description,
            state = state
          )
          return(invisible(NULL))
        }
        # Attempt to validate and consume the state; failures are logged but
        # do not override the original OAuth error from the provider.
        .consume_error_state(state)
      }
      invisible(NULL)
    }

    # Helper to consume (validate/remove) state from an error response
    .consume_error_state <- function(state) {
      tryCatch(
        {
          # Decrypt and validate the state payload
          payload <- state_payload_decrypt_validate(client, state)
          # Consume the state store entry (single-use enforcement)
          state_store_get_remove(client, payload$state)
          # Audit success
          try(
            audit_event(
              "error_state_consumed",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                state_digest = string_digest(state)
              )
            ),
            silent = TRUE
          )
        },
        error = function(e) {
          # State consumption failed; log but don't override original error.
          # This can happen if the state was already consumed, expired, or
          # was tampered with. Not a critical failure for error responses.
          try(
            audit_event(
              "error_state_consumption_failed",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                state_digest = string_digest(state),
                error_class = paste(class(e), collapse = ", "),
                error_message = conditionMessage(e)
              )
            ),
            silent = TRUE
          )
        }
      )
      invisible(NULL)
    }

    # Function to handle code & state once received in query string
    .handle_callback <- function(code, state) {
      # Always clear callback params once we've parsed them (success or failure)
      on.exit(
        {
          try(.clear_query_and_fix_title(), silent = TRUE)
        },
        add = TRUE
      )

      # If browser token isn't here yet, defer (set as pending) and wait for browser token
      if (!is_valid_string(values$browser_token)) {
        values$pending_callback <- list(code = code, state = state)
        return(invisible(NULL))
      }

      tryCatch(
        {
          res <- if (isTRUE(async)) {
            # Use future_promise to move work off the main thread. To avoid
            # cross-process cache visibility issues with client@state_store,
            # pre-decrypt the payload and prefetch+remove the state_store entry on the
            # main thread, and pass these to handle_callback.
            pre_payload <- tryCatch(
              state_payload_decrypt_validate(client, state),
              error = function(e) {
                .set_error(
                  "token_exchange_error",
                  e,
                  phase = "async_payload_validation"
                )
                rlang::abort(message = conditionMessage(e), parent = e)
              }
            )

            pre_state <- tryCatch(
              state_store_get_remove(client, pre_payload$state),
              error = function(e) {
                .set_error(
                  "token_exchange_error",
                  e,
                  phase = "async_state_store_lookup"
                )
                rlang::abort(message = conditionMessage(e), parent = e)
              }
            )

            # Capture the browser token value on the main thread to avoid
            # touching reactive values inside the worker
            captured_browser_token <- tryCatch(
              shiny::isolate(values$browser_token),
              error = function(...) values$browser_token
            )
            # Build a client clone for the worker; reuse existing state_store (already consumed)
            client_for_worker <- client

            promises::future_promise({
              handle_callback(
                oauth_client = client_for_worker,
                code = code,
                payload = state,
                browser_token = captured_browser_token,
                decrypted_payload = pre_payload,
                state_store_values = pre_state
              )
            })
          } else {
            handle_callback(
              client,
              code = code,
              payload = state,
              browser_token = values$browser_token
            )
          }

          # Handle async/sync
          if (isTRUE(async)) {
            # Mark that we exercised the async pathway (testing aid)
            values$last_login_async_used <- TRUE

            res |>
              promises::then(function(tok) {
                values$token <- tok
                values$error <- NULL
                values$error_description <- NULL
                values$auth_started_at <- as.numeric(Sys.time())
                values$token_stale <- FALSE
                .clear_browser_token()
                # Immediately re-issue a fresh browser token so that
                # subsequent manual logins can redirect on the first click.
                .set_browser_token()
                # A successful login completes any prior reauth cycle
                values$reauth_triggered <- FALSE
              }) |>
              promises::catch(function(e) {
                .set_error(
                  "token_exchange_error",
                  e,
                  phase = "async_token_exchange"
                )
                try(
                  audit_event(
                    "login_failed",
                    context = list(
                      provider = client@provider@name %||% NA_character_,
                      issuer = client@provider@issuer %||% NA_character_,
                      client_id_digest = string_digest(client@client_id),
                      phase = "async_token_exchange",
                      error_class = paste(class(e), collapse = ", ")
                    )
                  ),
                  silent = TRUE
                )
                if (isTRUE(getOption("shinyOAuth.debug", FALSE))) {
                  rlang::abort(message = conditionMessage(e), parent = e)
                }
              })
          } else {
            values$token <- res
            values$error <- NULL
            values$error_description <- NULL
            values$auth_started_at <- as.numeric(Sys.time())
            values$token_stale <- FALSE
            .clear_browser_token()
            # Immediately re-issue a fresh browser token so that
            # subsequent manual logins can redirect on the first click.
            .set_browser_token()
            # Reset reauth guard on successful sync login
            values$reauth_triggered <- FALSE
          }
        },
        error = function(e) {
          .set_error("token_exchange_error", e, phase = "sync_token_exchange")
          try(
            audit_event(
              "login_failed",
              context = list(
                provider = client@provider@name %||% NA_character_,
                issuer = client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(client@client_id),
                phase = "sync_token_exchange",
                error_class = paste(class(e), collapse = ", ")
              )
            ),
            silent = TRUE
          )
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
          .handle_callback(pc$code, pc$state)
        }
      },
      ignoreInit = FALSE
    )

    # Resume deferred error-response state consumption once browser_token is available
    shiny::observeEvent(
      values$browser_token,
      {
        pe <- shiny::isolate(values$pending_error)
        if (!is.null(pe) && .has_browser_token()) {
          values$pending_error <- NULL
          # Attempt to consume the state (best-effort, failures logged)
          if (!is.null(pe$state) && is_valid_string(pe$state)) {
            .consume_error_state(pe$state)
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
          isTRUE(shiny::isolate(values$pending_login)) && .has_browser_token()
        ) {
          # Guard against running during callback processing
          qs <- tryCatch(
            shiny::parseQueryString(session$clientData$url_search %||% ""),
            error = function(...) list()
          )
          if (
            is.null(qs$code) &&
              is.null(qs$error) &&
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
    values$.strip_oauth_query <- .strip_oauth_query

    # Proactive refresh -------------------------------------------------------

    # Expiry management and optional proactive refresh logic
    if (isTRUE(refresh_proactively)) {
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
              wake_ms <- max(100, as.integer((to_refresh + jitter) * 1000))
            } else {
              # We are within the lead window or past it: attempt refresh now
              wake_ms <- 250L
              # Avoid concurrent refresh attempts: if one is already running,
              # skip starting another and try again shortly.
              if (isTRUE(values$refresh_in_progress)) {
                # Keep wake_ms short and bail out of starting a new refresh
                # The enclosing observe will schedule the next wake.
              } else {
                # Delegate to refresh_token with async and handle promise if returned
                tryCatch(
                  {
                    # Mark refresh as in-progress until we resolve success/error
                    values$refresh_in_progress <- TRUE
                    res <- refresh_token(
                      client,
                      tok,
                      async = async
                    )

                    # Handle async path (wait for promise to resolve; then set values)
                    if (isTRUE(async)) {
                      res |>
                        promises::then(function(res_resolved) {
                          values$refresh_in_progress <- FALSE
                          values$token <- res_resolved
                          values$error <- NULL
                          values$error_description <- NULL
                          # Reset rolling session start on successful refresh
                          values$auth_started_at <- as.numeric(Sys.time())
                          values$token_stale <- FALSE
                          # Successful refresh should allow future reauth cycles
                          values$reauth_triggered <- FALSE
                        }) |>
                        promises::catch(function(e) {
                          values$refresh_in_progress <- FALSE
                          try(log_condition(
                            e,
                            context = list(phase = "async_token_refresh")
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
                                  provider = client@provider@name %||%
                                    NA_character_,
                                  issuer = client@provider@issuer %||%
                                    NA_character_,
                                  client_id_digest = string_digest(
                                    client@client_id
                                  ),
                                  reason = "refresh_failed_async",
                                  error_class = paste(class(e), collapse = ", ")
                                )
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
                      values$refresh_in_progress <- FALSE
                      values$token <- new_tok
                      values$error <- NULL
                      values$error_description <- NULL
                      # Reset rolling session start on successful refresh
                      values$auth_started_at <- as.numeric(Sys.time())
                      values$token_stale <- FALSE
                      # Successful sync refresh resets reauth guard as well
                      values$reauth_triggered <- FALSE
                    }
                  },
                  error = function(e) {
                    # Always clear the in-progress flag on error
                    values$refresh_in_progress <- FALSE
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

    # Expiry watch -------------------------------------------------------------

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
              wake_ms <- min(wake_ms, max(100, as.integer(until_reauth * 1000)))
            } else if ((now - started) >= reauth_after_seconds) {
              # Default behavior clears token and triggers reauth; skip when indefinite_session
              if (!isTRUE(indefinite_session)) {
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
            if (!is.na(remaining) && remaining <= 0) {
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
            wake_ms <- min(wake_ms, max(100, as.integer(remaining * 1000)))
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

    # Return reactive values --------------------------------------------------

    return(values)
  })
}
