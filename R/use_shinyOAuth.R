# This file contains the UI-side helpers for the browser JavaScript dependency
# That browser code handles redirects and keeps the login flow tied to the
# current browser session
# Used for adding the shinyOAuth JavaScript dependency to a Shiny UI

# 1 UI dependency helper -------------------------------------------------------

## 1.1 Add the browser dependency to the UI ------------------------------------

#' Add JavaScript dependency to the UI of a Shiny app
#'
#' @description
#' Adds shinyOAuth's client-side JavaScript dependency to your Shiny UI.
#' This is required so the module can handle redirects and manage its
#' browser-side session token.
#'
#' Without this call in the UI, [oauth_module_server()] will not work unless
#' your app UI is wrapped with [oauth_form_post_ui()], which injects this
#' dependency automatically for form_post flows.
#'
#' @details
#' Place this near the top-level of your UI (e.g., inside `fluidPage()` or
#' `tagList()`), similar to how you would use `shinyjs::useShinyjs()`. If you
#' wrap the app UI with [oauth_form_post_ui()], you usually do not need a
#' separate call here because that wrapper injects this dependency for you.
#'
#' @param inject_referrer_meta If TRUE (default), injects a
#'   `<meta name="referrer" content="no-referrer">` tag into the document
#'   head. This reduces the risk of leaking OAuth callback query parameters
#'   (like `code` and `state`) via the `Referer` header to third-party
#'   subresources during the initial callback page load.
#'
#' @return A `tagList` that loads the `inst/www/shinyOAuth.js` dependency once.
#'
#' @export
#'
#' @examples
#' ui <- shiny::fluidPage(
#'   use_shinyOAuth(),
#'   # ...
#' )
#'
#' @seealso [oauth_module_server()]
use_shinyOAuth <- function(inject_referrer_meta = TRUE) {
  assign(".called_js_dependency", TRUE, envir = .watchdog_environment)

  if (
    !(isTRUE(inject_referrer_meta) || identical(inject_referrer_meta, FALSE))
  ) {
    err_input(
      "{.arg inject_referrer_meta} must be {.val TRUE} or {.val FALSE}."
    )
  }

  # Resolve a safe version string for the dependency. In dev contexts
  # (e.g., load_all), packageVersion() may not always be available; fall back
  # to "dev" to avoid erroring during UI rendering.
  ver <- tryCatch(
    as.character(utils::packageVersion("shinyOAuth")),
    error = function(...) NULL
  )
  if (!is_valid_string(ver)) {
    ver <- "dev"
  }

  dep <- htmltools::htmlDependency(
    name = "shinyOAuth",
    version = ver,
    src = "www",
    package = "shinyOAuth",
    script = "shinyOAuth.js"
  )

  referrer_meta <- NULL
  if (isTRUE(inject_referrer_meta)) {
    referrer_meta <- htmltools::tags$head(
      htmltools::tags$meta(name = "referrer", content = "no-referrer")
    )
  }

  htmltools::tagList(
    referrer_meta,
    dep
  )
}

# 2 Missing dependency watchdog ------------------------------------------------

## 2.1 Warn when the UI dependency is missing ----------------------------------

#' Warn when the UI dependency is missing
#'
#' Emits a once-per-session warning when server code uses the browser-side
#' helpers before [use_shinyOAuth()] has loaded the JavaScript dependency. Used
#' by [oauth_module_server()] so missing UI setup is easier to diagnose.
#'
#' @return Invisibly returns `TRUE` when a warning is emitted; otherwise
#'   invisibly returns `NULL`.
#' @keywords internal
#' @noRd
warn_about_missing_js_dependency <- function() {
  if (.is_test()) {
    return(invisible(NULL))
  }
  if (
    get0(
      ".called_js_dependency",
      envir = .watchdog_environment,
      inherits = FALSE,
      ifnotfound = FALSE
    )
  ) {
    return(invisible(NULL))
  }

  warn_pkg(
    "JavaScript dependency not called",
    c(
      "!" = "{.code oauth_module_server()} was called, but no previous call to {.code use_shinyOAuth()} was detected",
      "i" = paste0(
        "You must add {.code use_shinyOAuth()} to your UI (e.g., inside {.code fluidPage()}) ",
        "to ensure the module functions correctly"
      )
    ),
    .frequency = "once",
    .frequency_id = "js_dependency_warning"
  )

  invisible(TRUE)
}

#' Build a watchdog key for form_post UI reminders
#'
#' Produces a stable key so shinyOAuth can remember whether a specific module
#' and client pair was wrapped with `oauth_form_post_ui()` before
#' `oauth_module_server()` starts.
#'
#' @param id Shiny module id.
#' @param client [OAuthClient] object.
#'
#' @return A single character string suitable for watchdog lookups.
#' @keywords internal
#' @noRd
form_post_watchdog_key <- function(id, client) {
  provider_identity <- client@provider@issuer %||%
    client@provider@authorization_url %||%
    client@provider@name %||%
    ""

  paste(
    id,
    client@client_id %||% "",
    client@redirect_uri %||% "",
    provider_identity,
    sep = " :: "
  )
}

#' Mark a form_post UI wrapper as configured
#'
#' Records that `oauth_form_post_ui()` was called for a given module/client
#' pair so `oauth_module_server()` can avoid emitting a reminder later.
#'
#' @param id Shiny module id.
#' @param client [OAuthClient] object.
#'
#' @return Invisibly returns `TRUE`.
#' @keywords internal
#' @noRd
mark_form_post_ui_called <- function(id, client) {
  assign(
    paste0(".called_form_post_ui::", form_post_watchdog_key(id, client)),
    TRUE,
    envir = .watchdog_environment
  )

  invisible(TRUE)
}

#' Warn when the form_post UI wrapper is missing
#'
#' Emits a once-per-module reminder when `oauth_module_server()` is used with
#' a client that resolves to `response_mode = "form_post"` but no prior call
#' to `oauth_form_post_ui()` was detected for the same module/client pair.
#'
#' @param id Shiny module id.
#' @param client [OAuthClient] object.
#'
#' @return Invisibly returns `TRUE` when a warning is emitted; otherwise
#'   invisibly returns `NULL`.
#' @keywords internal
#' @noRd
warn_about_missing_form_post_ui <- function(id, client) {
  if (.is_test()) {
    return(invisible(NULL))
  }

  response_mode_info <- resolve_oauth_client_response_mode(client)
  if (
    !is.null(response_mode_info$error) ||
      !identical(response_mode_info$mode, "form_post")
  ) {
    return(invisible(NULL))
  }

  watchdog_key <- form_post_watchdog_key(id, client)
  if (
    get0(
      paste0(".called_form_post_ui::", watchdog_key),
      envir = .watchdog_environment,
      inherits = FALSE,
      ifnotfound = FALSE
    )
  ) {
    return(invisible(NULL))
  }

  warn_pkg(
    "form_post UI wrapper not detected",
    c(
      "!" = paste0(
        "{.code oauth_module_server()} was called with a client that resolves to ",
        "{.code response_mode = \"form_post\"}, but no previous call to ",
        "{.code oauth_form_post_ui()} was detected for this module"
      ),
      "i" = paste0(
        "Wrap your app UI with {.code oauth_form_post_ui(..., id = ",
        deparse(id),
        ", client = client)} so POST callbacks reach shinyOAuth before the ",
        "Shiny session starts"
      ),
      "i" = paste0(
        "If you already wrap the UI indirectly and this reminder fires before ",
        "that call is made, you can ignore it"
      )
    ),
    .frequency = "once",
    .frequency_id = paste0("form_post_ui_warning::", watchdog_key)
  )

  invisible(TRUE)
}

## 2.2 Store file-local watchdog state -----------------------------------------

# Here we track if the dependency has likely been added to UI;
# if this flag is FALSE, and `oauth_module_server()` is called,
# a warning is emitted to remind the developer to add it (once per session)

.watchdog_environment <- new.env(parent = emptyenv())
assign(".called_js_dependency", FALSE, envir = .watchdog_environment)
