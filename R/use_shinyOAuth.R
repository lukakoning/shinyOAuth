#' Add JavaScript dependency to the UI of a Shiny app
#'
#' @description
#' Adds the package's client-side JavaScript helpers as an htmlDependency to
#' your Shiny UI. This enables features such as redirection and setting
#' the browser cookie token.
#'
#' Without adding this to the UI of your app,  the `oauth_module_server()` will not function.
#'
#' @details
#' Place this near the top-level of your UI (e.g., inside `fluidPage()` or
#' `tagList()`), similar to how you would use `shinyjs::useShinyjs()`.
#'
#' @return A tagList containing a singleton dependency tag that ensures the JS
#'   file `inst/www/shinyOAuth.js` is loaded
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
use_shinyOAuth <- function() {
  .set_flag(".called_js_dependency", TRUE)

  # Resolve a safe version string for the dependency. In dev contexts
  # (e.g., load_all), packageVersion() may not always be available; fall back
  # to "dev" to avoid erroring during UI rendering.
  ver <- tryCatch(
    as.character(utils::packageVersion("shinyOAuth")),
    error = function(...) NULL
  )
  if (is.null(ver) || !nzchar(ver)) {
    ver <- "dev"
  }

  dep <- htmltools::htmlDependency(
    name = "shinyOAuth",
    version = ver,
    src = "www",
    package = "shinyOAuth",
    script = "shinyOAuth.js"
  )

  htmltools::tagList(
    dep
  )
}

# Warn about non-usage ----------------------------------------------------

# Here we track if the dependency has likely been added to UI;
# if this flag is FALSE, and `oauth_module_server()` is called,
# a warning is emitted to remind the developer to add it (once per session)

.watchdog_environment <- new.env(parent = emptyenv())
assign(".called_js_dependency", FALSE, envir = .watchdog_environment)

.get_flag <- function(name, default = FALSE) {
  get0(
    name,
    envir = .watchdog_environment,
    inherits = FALSE,
    ifnotfound = default
  )
}
.set_flag <- function(name, value) {
  assign(name, value, envir = .watchdog_environment)
  invisible(TRUE)
}

# call this from your UI helper that injects the JS dependency
mark_js_dependency_called <- function() {
  .set_flag(".called_js_dependency", TRUE)
}

warn_about_missing_js_dependency <- function() {
  if (.get_flag(".called_js_dependency")) {
    return(invisible(NULL))
  }

  rlang::warn(
    c(
      "[{.pkg shinyOAuth}] - {.strong JavaScript dependency not called}",
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
