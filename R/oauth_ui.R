#' Protect OAuth callback pages before browser subresources load
#'
#' Wrap the complete Shiny UI to set `Referrer-Policy: no-referrer` on HTML
#' responses, including the initial OAuth callback page. This prevents callback
#' query parameters from appearing in subresource Referer headers. The wrapper
#' also includes [use_shinyOAuth()] automatically.
#'
#' A meta tag alone is insufficient: Shiny serializes dependency scripts before
#' UI head tags. Use this wrapper, or set the same HTTP header at your web server.
#' [oauth_form_post_ui()] applies this wrapper automatically.
#'
#' @param base_ui A Shiny UI object or UI function accepting a request.
#' @return A UI function to pass to [shiny::shinyApp()].
#' @export
#' @examples
#' ui <- oauth_ui(shiny::fluidPage(shiny::h2("My app")))
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
