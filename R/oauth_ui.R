#' Set up a Shiny UI for shinyOAuth
#'
#' @description
#' Wrap your complete UI in `oauth_ui()` when using [oauth_module_server()].
#' It adds the browser code needed for login and a privacy header that keeps
#' the returning callback address out of requests to other sites.
#'
#' @details
#' Build the page as usual, for example with `fluidPage()`, then use
#' `ui <- oauth_ui(ui)`. Pass the result to [shiny::shinyApp()]. UI functions
#' are supported too, including functions accepting the Shiny request.
#' This wrapper includes [use_shinyOAuth()] setup.
#'
#' For `response_mode = "form_post"` or `"form_post.jwt"`, use
#' [oauth_form_post_ui()] instead; it includes this setup and accepts POST
#' callbacks.
#'
#' The privacy header is `Referrer-Policy: no-referrer`. The browser reads it
#' before loading page resources. The meta tag from [use_shinyOAuth()] takes
#' effect only once the browser reads that tag, so it may miss early resource
#' requests. You can also set the same HTTP header at your web server.
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
    } else {
      base_ui
    }
    if (is.null(value)) {
      return(NULL)
    }
    oauth_form_post_ensure_ui_dependency(value)
  }
  attr(render_ui, "http_methods_supported") <- methods
  # Reuse Shiny's normal rendering through its public app constructor. This
  # preserves custom documents, dependencies, request UIs, and test mode.
  handler <- shiny::shinyApp(
    render_ui,
    server = function(...) {},
    uiPattern = ".*"
  )$httpHandler
  ui <- function(req) {
    response <- handler(req)
    if (
      !is.null(response) &&
        grepl("^text/html", response$content_type, ignore.case = TRUE)
    ) {
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
