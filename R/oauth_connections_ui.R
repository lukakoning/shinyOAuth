#' Handle callbacks and establish the connection owner's browser session
#'
#' Wrap the application's UI with the same manager and module ID used by
#' [oauth_connections_server()]. Browser retention establishes its HttpOnly
#' owner cookie on an ordinary page request before Shiny starts. OAuth callbacks
#' use the existing validated callback bridge and clean continuation.
#'
#' @param base_ui A Shiny UI object or request-dependent UI function.
#' @param id Module ID shared with [oauth_connections_server()].
#' @param manager Configuration from [oauth_connections()].
#' @param request_uri_resolver Optional trusted function mapping a Rook request to
#'   its public absolute URI. Required when a trusted reverse proxy changes the
#'   apparent scheme/host. Do not trust arbitrary forwarded headers. The resolved
#'   origin must match the manager's configured origin.
#' @param app_base_path Public path at which the Shiny application is hosted,
#'   default `"/"`. Must begin and end with `/`. The wrapper inserts a document
#'   base before scripts so Shiny dependencies load from the app root even on
#'   nested callback pages. Do not supply a separate HTML `base` element.
#' @param launch_routes List of [smart_launch_route()] configurations, empty by
#'   default. EHR entry requires browser retention and top-level navigation.
#' @return A request UI function for `shinyApp(..., uiPattern = ".*")`.
#' @details
#' Raw GET and form POST callbacks never create or rotate an owner. A POST may
#' lack a SameSite owner cookie; its clean continuation must carry a still-valid
#' owner before credentials can be exchanged. An invalid cookie on an ordinary
#' page is cleared using an HTTP response and a same-origin redirect; the next
#' request establishes a new empty browser owner.
#'
#' The cookie is scoped to its host. Separate applications on that host must be
#' trusted; different ports or paths do not isolate their cookies. The wrapper
#' adds no owner cookie for session-only or account retention.
#' @seealso [oauth_browser_owner()], [oauth_ui()]
#' @export
oauth_connections_ui <- function(
  base_ui,
  id,
  manager,
  request_uri_resolver = NULL,
  app_base_path = "/",
  launch_routes = list()
) {
  connection_manager_bind(manager, id)
  if (
    !is_valid_string(app_base_path) ||
      !startsWith(app_base_path, "/") ||
      !endsWith(app_base_path, "/") ||
      grepl("[?#]", app_base_path)
  ) {
    err_config("app_base_path must be an absolute application directory path")
  }
  app_base <- resource_binding_components(
    paste0(manager$app_origin, app_base_path),
    base = TRUE
  )$url
  app_base <- paste0(sub("/$", "", app_base), "/")
  if (
    !all(vapply(
      manager$clients,
      function(client) {
        startsWith(
          resource_binding_components(client@redirect_uri)$path,
          app_base_path
        )
      },
      logical(1)
    ))
  ) {
    err_config("All managed callbacks must be inside app_base_path")
  }
  resolver <- request_uri_resolver %||% oauth_form_post_request_uri
  if (!is.function(resolver)) {
    err_config("A request URI resolver must be a function")
  }
  clients <- manager$clients
  names(clients) <- shiny::NS(id)(names(clients))
  callback_handler <- oauth_ui_impl(
    base_ui,
    clients = clients,
    request_uri_resolver = resolver,
    allow_shared_issuer = identical(manager$callback_policy, "shared_routes"),
    select_client = if (identical(manager$callback_policy, "shared_routes")) {
      function(candidates, payload) connection_router_select(manager, candidates, payload)
    } else NULL
  )
  handler <- function(req) {
    connection_manager_document_base(callback_handler(req), app_base)
  }
  state <- manager$state
  smart_launch_routes_validate(launch_routes, manager, app_base_path)
  state$ui_bound <- TRUE
  ui <- function(req) {
    connection_manager_check(manager)
    uri <- tryCatch(resolver(req), error = function(...) NULL)
    if (!connection_manager_same_origin(uri, manager$app_origin)) {
      return(oauth_get_setup_error(
        "Request does not match the configured application origin."
      ))
    }
    launch_response <- smart_launch_http(req, uri, manager, launch_routes, app_base, handler)
    if (!is.null(launch_response)) return(launch_response)
    rejected <- oauth_http_query_guard(req)
    if (!is.null(rejected)) return(rejected)
    query <- req[["QUERY_STRING"]] %||% ""
    raw_callback <- oauth_get_query_is_callback(query)
    if (
      !identical(manager$retention, "browser") ||
        !identical(req[["REQUEST_METHOD"]], "GET") ||
        raw_callback
    ) {
      return(handler(req))
    }
    supplied_origin <- req[["HTTP_ORIGIN"]]
    if (
      !is.null(supplied_origin) &&
        (!is_valid_string(supplied_origin) ||
          !identical(supplied_origin, manager$app_origin))
    ) {
      return(oauth_get_setup_error(
        "Cross-origin owner requests are not accepted."
      ))
    }
    tryCatch(
      {
        owners <- manager$state$owners
        cookie <- connection_owner_cookie_read(req, owners$cookie_name)
        owner <- owners$resolve(cookie)
        continuation <- length(oauth_module_query_raw_values(
          query,
          oauth_form_post_handle_param
        )) >
          0L
        if (is.null(owner) && continuation) {
          return(oauth_get_setup_error(
            "The local owner session ended; start a new connection from the application."
          ))
        }
        if (is.null(owner) && !is.null(cookie)) {
          return(shiny::httpResponse(
            303L,
            "text/plain",
            "",
            headers = list(
              Location = sub("[?#].*$", "", uri),
              "Set-Cookie" = connection_owner_cookie_header(
                owners$cookie_name,
                NULL,
                manager$app_origin,
                manager$owner,
                clear = TRUE
              ),
              "Cache-Control" = "no-store",
              "Referrer-Policy" = "no-referrer"
            )
          ))
        }
        response <- handler(req)
        if (
          is.null(owner) &&
            !is.null(response) &&
            isTRUE(response$status == 200L) &&
            grepl("^text/html", response$content_type, ignore.case = TRUE)
        ) {
          created <- owners$create()
          # Preserve independent Set-Cookie headers from a request-dependent UI.
          response$headers <- c(
            response$headers,
            list(
              "Set-Cookie" = connection_owner_cookie_header(
                owners$cookie_name,
                created$cookie,
                manager$app_origin,
                manager$owner
              )
            )
          )
        }
        response
      },
      error = function(...) {
        oauth_get_setup_error("The local owner session is unavailable.")
      }
    )
  }
  attr(ui, "http_methods_supported") <- attr(
    callback_handler,
    "http_methods_supported"
  )
  ui
}

connection_manager_document_base <- function(response, app_base) {
  if (
    is.null(response) ||
      !isTRUE(response$status == 200L) ||
      !grepl("^text/html", response$content_type, ignore.case = TRUE)
  ) {
    return(response)
  }
  html <- response$content
  if (
    !is.character(html) ||
      length(html) != 1L ||
      !grepl("<head\\b[^>]*>", html, perl = TRUE, ignore.case = TRUE) ||
      grepl("<base\\b", html, perl = TRUE, ignore.case = TRUE)
  ) {
    err_config("Managed HTML must have a head and no separate base element")
  }
  response$content <- sub(
    "(<head\\b[^>]*>)",
    paste0(
      "\\1<base href=\"",
      htmltools::htmlEscape(app_base, attribute = TRUE),
      "\">"
    ),
    html,
    perl = TRUE,
    ignore.case = TRUE
  )
  # A request-dependent UI can supply response headers. Body metadata from the
  # original HTML no longer describes the document after adding the base tag.
  response$headers <- response$headers[
    !tolower(names(response$headers)) %in%
      c("content-length", "etag", "content-md5")
  ]
  response
}
