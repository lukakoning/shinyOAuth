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
  request_uri_resolver = NULL
) {
  connection_manager_bind(manager, id)
  resolver <- request_uri_resolver %||% oauth_form_post_request_uri
  if (!is.function(resolver)) {
    err_config("A request URI resolver must be a function")
  }
  clients <- lapply(manager$targets, function(target) target$client)
  names(clients) <- shiny::NS(id)(names(clients))
  handler <- oauth_ui(
    base_ui,
    clients = clients,
    request_uri_resolver = resolver
  )
  state <- manager$state
  state$ui_bound <- TRUE
  ui <- function(req) {
    connection_manager_check(manager)
    rejected <- oauth_http_query_guard(req)
    if (!is.null(rejected)) {
      return(rejected)
    }
    uri <- tryCatch(resolver(req), error = function(...) NULL)
    if (!connection_manager_same_origin(uri, manager$app_origin)) {
      return(oauth_get_setup_error(
        "Request does not match the configured application origin."
      ))
    }
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
  attr(ui, "http_methods_supported") <- attr(handler, "http_methods_supported")
  ui
}
