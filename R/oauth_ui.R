#' Set up a Shiny UI for shinyOAuth
#'
#' @description
#' Use `oauth_ui()` around your app's UI when setting up login with
#' [oauth_module_server()]. It adds the browser code needed for login and
#' helps keep login details private when users return to your app.
#'
#' This is the recommended UI helper for most apps. It includes everything
#' provided by [use_shinyOAuth()], so you do not need to call both.
#'
#' @details
#' Build your UI as usual with `fluidPage()`, `tagList()`, or another Shiny
#' page function, then wrap the complete UI in `oauth_ui()`. Pass the result
#' as the `ui` argument to [shiny::shinyApp()]. If you already have a `ui`
#' object, you can use `ui <- oauth_ui(ui)` and remove the separate
#' `use_shinyOAuth()` call from your UI.
#'
#' For apps using `response_mode = "form_post"` or `"form_post.jwt"`, use
#' [oauth_form_post_ui()] instead. It includes this setup and also handles
#' the provider's POST response.
#'
#' For browser privacy, `oauth_ui()` sets the HTTP header
#' `Referrer-Policy: no-referrer` on HTML pages. This prevents the browser
#' from sharing the current page's URL when it requests scripts, images, or
#' other resources. After login, that URL can contain an authorization code
#' and state value. Setting the policy in the response header protects these
#' values before any page resources load. You can also configure the same
#' header at your web server.
#'
#' Existing UI functions are supported too, including functions that accept
#' the Shiny request as their argument.
#'
#' @param base_ui Your app's complete UI, such as a `fluidPage()` or `tagList()`.
#'   Can also be a UI function, optionally accepting the Shiny request.
#' @return A UI function to use as the `ui` argument to [shiny::shinyApp()].
#' @seealso [oauth_module_server()], [oauth_form_post_ui()], [use_shinyOAuth()]
#' @export
#' @examples
#' ui <- oauth_ui(
#'   shiny::fluidPage(
#'     shiny::h2("My app"),
#'     shiny::uiOutput("login")
#'   )
#' )
#'
#' # Use this UI with your app's server function:
#' # shiny::shinyApp(ui = ui, server = server)
oauth_ui <- function(base_ui) {
  force(base_ui)
  methods <- attr(base_ui, "http_methods_supported", exact = TRUE) %||% "GET"
  render_ui <- function(req) {
    value <- if (is.function(base_ui)) {
      if (length(formals(base_ui))) base_ui(req) else base_ui()
    } else base_ui
    if (is.null(value)) return(NULL)
    oauth_form_post_ensure_ui_dependency(value)
  }
  attr(render_ui, "http_methods_supported") <- methods
  # Reuse Shiny's normal rendering through its public app constructor. This
  # preserves custom documents, dependencies, request UIs, and test mode.
  handler <- shiny::shinyApp(render_ui, server = function(...) {}, uiPattern = ".*")$httpHandler
  ui <- function(req) {
    response <- handler(req)
    if (!is.null(response) && grepl("^text/html", response$content_type, ignore.case = TRUE)) {
      headers <- response$headers
      headers <- headers[tolower(names(headers)) != "referrer-policy"]
      headers[["Referrer-Policy"]] <- "no-referrer"
      response$headers <- headers
    }
    response
  }
  attr(ui, "http_methods_supported") <- methods
  ui
}
