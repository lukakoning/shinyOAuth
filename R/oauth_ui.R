#' Set up a Shiny UI for shinyOAuth
#'
#' @description
#' Wrap your complete UI in `oauth_ui()` when using [oauth_module_server()].
#' It adds the browser code needed for login and protects callback responses
#' from caching and referrer disclosure. Supply `id` and `client` to accept
#' query callbacks before rendering any application UI or scripts.
#'
#' @details
#' Build the page as usual, for example with `fluidPage()`, then use
#' `ui <- oauth_ui(ui, id = "auth", client = client)`, using the same module
#' ID and client as the server. Pass the result to [shiny::shinyApp()]. UI functions
#' are supported too, including functions accepting the Shiny request.
#' This wrapper includes [use_shinyOAuth()] setup.
#'
#' For `response_mode = "form_post"` or `"form_post.jwt"`, use
#' [oauth_form_post_ui()] instead; it includes this setup and accepts POST
#' callbacks.
#'
#' GET callbacks are validated and sealed into short-lived, single-use bridge
#' handles in the client's state store, then redirected to a clean URL before
#' application HTML is rendered. Logical state is consumed only after the
#' Shiny module verifies browser binding. The storage requirements and quotas
#' are the same as [oauth_form_post_ui()]. Register any fixed application query
#' parameters in `client@redirect_uri`; other inbound parameters are discarded.
#' For non-root callback paths use `uiPattern = ".*"` in [shiny::shinyApp()].
#'
#' Without `id` and `client`, ordinary pages still render, but raw OAuth GET
#' callbacks fail closed with a setup error. Earlier `oauth_ui(ui)` query-flow
#' applications must add those arguments. When integrating [use_shinyOAuth()]
#' directly, provide an equivalent dedicated callback endpoint: third-party or
#' application scripts must not execute on an unsanitized callback page.
#'
#' HTML responses include `Cache-Control: no-store`, `Pragma: no-cache`, and
#' `Referrer-Policy: no-referrer`. The browser reads these headers
#' before loading page resources. The meta tag from [use_shinyOAuth()] takes
#' effect only once the browser reads that tag, so it may miss early resource
#' requests. You can also set the same HTTP header at your web server.
#'
#' @param base_ui Your app's complete UI, such as a `fluidPage()` or `tagList()`.
#'   Can also be a UI function, optionally accepting the Shiny request.
#' @param id Shiny module ID, required with `client` for GET callbacks.
#' @param client [OAuthClient] used by the server module, required with `id`.
#' @param request_uri_resolver Optional trusted public request URI resolver;
#'   see [oauth_form_post_ui()] for proxy requirements.
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
#' # After creating your OAuth client, enable the callback bridge:
#' # ui <- oauth_ui(ui, id = "auth", client = client)
#' # Use this UI with your app's server function:
#' # shiny::shinyApp(ui = ui, server = server)
oauth_ui <- function(
  base_ui,
  id = NULL,
  client = NULL,
  request_uri_resolver = NULL
) {
  if (!is.null(id) || !is.null(client)) {
    S7::check_is_S7(client, class = OAuthClient)
    if (!is_valid_string(id)) {
      err_input("{.arg id} must be a single non-empty string.")
    }
  }
  if (is.null(request_uri_resolver)) {
    request_uri_resolver <- oauth_form_post_request_uri
  }
  if (!is.function(request_uri_resolver)) {
    err_input("{.arg request_uri_resolver} must be NULL or a function.")
  }
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
    if (
      identical(req[["REQUEST_METHOD"]], "GET") &&
        oauth_get_query_is_callback(req[["QUERY_STRING"]] %||% "", client)
    ) {
      if (is.null(client)) {
        return(oauth_get_setup_error(
          "OAuth GET callback requires oauth_ui() with the module id and client."
        ))
      }
      uri <- tryCatch(request_uri_resolver(req), error = function(...) NULL)
      if (
        !is_valid_string(uri) ||
          !oauth_callback_route_matches(
            paste0(sub("[?#].*$", "", uri), "?", req[["QUERY_STRING"]] %||% ""),
            client@redirect_uri
          )
      ) {
        return(oauth_get_setup_error(
          "OAuth callback route does not match the registered redirect URI."
        ))
      }
      mode <- resolve_oauth_client_response_mode(client)[["mode"]]
      if (!mode %in% c("query", "query.jwt")) {
        return(oauth_get_setup_error(
          "OAuth callback used an unexpected response transport."
        ))
      }
      return(oauth_form_post_handle_request(
        req,
        id,
        client,
        transport = "query"
      ))
    }
    response <- handler(req)
    if (
      !is.null(response) &&
        grepl("^text/html", response$content_type, ignore.case = TRUE)
    ) {
      headers <- response$headers
      headers <- headers[
        !tolower(names(headers)) %in%
          c("referrer-policy", "cache-control", "pragma")
      ]
      headers[["Referrer-Policy"]] <- "no-referrer"
      headers[["Cache-Control"]] <- "no-store"
      headers[["Pragma"]] <- "no-cache"
      response$headers <- headers
    }
    response
  }
  attr(ui, "http_methods_supported") <- methods
  ui
}

oauth_get_query_is_callback <- function(query, client = NULL) {
  keys <- setdiff(
    oauth_module_callback_query_keys,
    c(oauth_form_post_handle_param, oauth_form_post_id_param)
  )
  any(vapply(
    keys,
    function(key) length(oauth_module_query_raw_values(query, key)) > 0L,
    logical(1)
  )) ||
    oauth_module_query_has_raw_jarm_response(query) ||
    (!is.null(client) &&
      !is.null(resolve_jarm_callback_transport(client)) &&
      length(oauth_module_query_raw_values(query, "response")) > 0L)
}

oauth_get_setup_error <- function(message) {
  shiny::httpResponse(
    400L,
    "text/plain; charset=UTF-8",
    message,
    headers = list(
      "Cache-Control" = "no-store",
      "Pragma" = "no-cache",
      "Referrer-Policy" = "no-referrer"
    )
  )
}

oauth_get_parse_query <- function(query, limits, client) {
  reject_duplicate_oauth_module_callback_query(
    query,
    query_jarm_client = TRUE,
    response_is_callback = !is.null(resolve_jarm_callback_transport(client))
  )
  parsed <- shiny::parseQueryString(paste0("?", query))
  keys <- c("code", "state", "error", "error_description", "error_uri", "iss")
  if (
    !is.null(resolve_jarm_callback_transport(client)) ||
      oauth_module_query_has_raw_jarm_response(query)
  ) {
    keys <- c(keys, "response")
  }
  payload <- compact_list(parsed[intersect(keys, names(parsed))])
  oauth_form_post_validate_payload(payload, limits, client = client)
}
