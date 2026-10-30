#' Handle callbacks and establish the connection owner's browser session
#'
#' Handles login returns and restores the user's saved connections. The wrapper
#' and [oauth_connections_server()] share the same manager and module ID.
#' Browser setup from [use_shinyOAuth()] is included.
#'
#' @param base_ui A Shiny UI object or request-dependent UI function.
#' @param id Module ID shared with [oauth_connections_server()].
#' @param manager Configuration from [oauth_connections()].
#' @param request_uri_resolver Optional trusted function mapping a Rook request to
#'   its public absolute URI. Required when a trusted reverse proxy changes the
#'   apparent scheme/host. The custom resolver defines which proxy headers are
#'   trusted; the wrapper checks the resolved origin against the manager's origin.
#' @param app_base_path Public path at which the Shiny application is hosted,
#'   default `"/"`. Must begin and end with `/`. The wrapper inserts a document
#'   base before scripts so Shiny dependencies load from the app root even on
#'   nested callback pages. The wrapper manages the page's HTML `base` element.
#'   Managed JAR Request Object URLs are also published beneath this path.
#' @param launch_routes List of [smart_launch_route()] configurations, empty by
#'   default. EHR entry requires browser retention and top-level navigation.
#' @param additional_clients Optional named list of ordinary OAuth/OIDC clients
#'   used by separate [oauth_module_server()] modules. Names are their full module
#'   IDs. These clients keep their existing login lifecycle and are not managed
#'   connections. This wrapper dispatches their callbacks alongside managed ones.
#'   Their callback routes must be distinct from managed callbacks and SMART
#'   launch routes, on this app's
#'   origin and inside `app_base_path`. All clients must select an appropriate
#'   multi-server authorization mode, even when the manager contains one client.
#' @return A request UI function for `shinyApp(..., uiPattern = ".*")`.
#' @details
#' With `shinyApp(..., uiPattern = ".*")`, callback paths reach the wrapper.
#' With browser retention, a cookie lets the returning browser
#' find its saved connections; tokens remain on the server. Account and session-only
#' retention do not add that owner cookie.
#'
#' @section Advanced browser and proxy requirements:
#' With Strict cookies, returning from another site may briefly show an intermediate
#' page before Shiny starts. This lets the browser send its existing cookie; it
#' does not create a new owner or exchange credentials. Proxies must preserve
#' same-origin Fetch Metadata, `Referer` or `Origin` information for recovery.
#' The `shinyOAuth_owner_recovery` query parameter is reserved for this flow.
#'
#' A managed login return must still belong to a valid local owner. An ordinary
#' entry or an independently validated `additional_clients` callback can create
#' an empty browser owner, but cannot recover someone else's connections.
#' Invalid cookies are cleared before a fresh owner is created.
#'
#' Cookies are shared across ports and paths on the same hostname. Services on
#' that hostname share the owner cookie's trust boundary.
#'
#' @seealso [oauth_browser_owner()], [oauth_ui()]
#' @example inst/examples/oauth_connections.R
#' @export
oauth_connections_ui <- function(
  base_ui,
  id,
  manager,
  request_uri_resolver = NULL,
  app_base_path = "/",
  launch_routes = list(),
  additional_clients = list()
) {
  connection_manager_bind(manager, id)
  clients <- manager[["clients"]]
  names(clients) <- shiny::NS(id)(names(clients))
  if (!is.list(additional_clients) || length(additional_clients) > 64L) {
    err_config(
      "additional_clients must be a named list of at most 64 ordinary clients"
    )
  }
  if (length(additional_clients)) {
    additional_clients <- oauth_callback_registry(
      additional_clients,
      mark_ui = FALSE
    )
    for (client in additional_clients) {
      if (
        !connection_manager_same_origin(
          client@redirect_uri,
          manager[["app_origin"]]
        )
      ) {
        err_config(
          "Additional callbacks must use the configured application origin"
        )
      }
      if (
        any(vapply(
          clients,
          function(managed) {
            identical(
              oauth_callback_route(client@redirect_uri),
              oauth_callback_route(managed@redirect_uri)
            )
          },
          logical(1)
        ))
      ) {
        err_config(
          "Additional clients require callback routes distinct from managed clients"
        )
      }
    }
    clients <- c(clients, additional_clients)
  }
  if (
    !is_valid_string(app_base_path) ||
      !startsWith(app_base_path, "/") ||
      !endsWith(app_base_path, "/") ||
      grepl("[?#]", app_base_path)
  ) {
    err_config("app_base_path must be an absolute application directory path")
  }
  app_base <- resource_binding_components(
    paste0(manager[["app_origin"]], app_base_path),
    base = TRUE
  )[["url"]]
  app_base <- paste0(sub("/$", "", app_base), "/")
  if (
    !all(vapply(
      clients,
      function(client) {
        startsWith(
          resource_binding_components(client@redirect_uri)[["path"]],
          app_base_path
        )
      },
      logical(1)
    ))
  ) {
    err_config("All callbacks must be inside app_base_path")
  }
  resolver <- request_uri_resolver %||% oauth_form_post_request_uri
  if (!is.function(resolver)) {
    err_config("A request URI resolver must be a function")
  }
  smart_launch_routes_validate(launch_routes, manager, app_base_path, clients)
  callback_handler <- oauth_ui_impl(
    base_ui,
    clients = clients,
    request_uri_resolver = resolver,
    allow_shared_issuer = identical(
      manager[["callback_policy"]],
      "shared_routes"
    ),
    select_client = if (
      identical(manager[["callback_policy"]], "shared_routes")
    ) {
      function(candidates, payload) {
        connection_router_select(manager, candidates, payload)
      }
    } else {
      NULL
    }
  )
  handler <- function(req) {
    connection_manager_document_base(callback_handler(req), app_base)
  }
  state <- manager[["state"]]
  state[["app_base"]] <- app_base
  state[["ui_bound"]] <- TRUE
  ui <- function(req) {
    connection_manager_check(manager)
    # Bound queries before URI resolution and SMART request classification.
    rejected <- oauth_http_query_guard(req)
    if (!is.null(rejected)) {
      return(rejected)
    }
    uri <- tryCatch(resolver(req), error = function(...) NULL)
    if (!connection_manager_same_origin(uri, manager[["app_origin"]])) {
      return(oauth_get_setup_error(
        "Request does not match the configured application origin."
      ))
    }
    launch_response <- smart_launch_http(
      req,
      uri,
      manager,
      launch_routes,
      app_base,
      handler
    )
    if (!is.null(launch_response)) {
      return(launch_response)
    }
    query <- req[["QUERY_STRING"]] %||% ""
    raw_callback <- oauth_get_query_is_callback(query)
    if (
      !identical(manager[["retention"]], "browser") ||
        !identical(req[["REQUEST_METHOD"]], "GET") ||
        raw_callback
    ) {
      response <- handler(req)
      if (
        identical(manager[["retention"]], "browser") &&
          identical(manager[["owner"]][["same_site"]], "Strict")
      ) {
        response <- connection_manager_callback_document(
          response,
          uri,
          manager[["app_origin"]]
        )
      }
      return(response)
    }
    supplied_origin <- req[["HTTP_ORIGIN"]]
    if (
      !is.null(supplied_origin) &&
        (!is_valid_string(supplied_origin) ||
          !identical(supplied_origin, manager[["app_origin"]]))
    ) {
      return(oauth_get_setup_error(
        "Cross-origin owner requests are not accepted."
      ))
    }
    tryCatch(
      {
        owners <- manager[["state"]][["owners"]]
        cookie <- connection_owner_cookie_read(req, owners[["cookie_name"]])
        owner <- owners[["resolve"]](cookie)
        continuation <- length(oauth_module_query_raw_values(
          query,
          oauth_form_post_handle_param
        )) >
          0L
        ordinary_continuation <- is.null(owner) &&
          continuation &&
          connection_ordinary_continuation(query, uri, additional_clients)
        if (is.null(owner) && continuation && !ordinary_continuation) {
          return(oauth_get_setup_error(
            "The local owner session ended; start a new connection from the application."
          ))
        }
        if (is.null(owner) && !is.null(cookie) && !ordinary_continuation) {
          return(shiny::httpResponse(
            303L,
            "text/plain",
            "",
            headers = list(
              Location = sub("[?#].*$", "", uri),
              "Set-Cookie" = connection_owner_cookie_header(
                owners[["cookie_name"]],
                NULL,
                manager[["app_origin"]],
                manager[["owner"]],
                clear = TRUE
              ),
              "Cache-Control" = "no-store",
              "Referrer-Policy" = "no-referrer"
            )
          ))
        }
        if (identical(manager[["owner"]][["same_site"]], "Strict")) {
          recovery <- connection_manager_owner_recovery(
            req, uri, owner, cookie, manager[["app_origin"]]
          )
          if (!is.null(recovery)) {
            return(recovery)
          }
        }
        response <- handler(req)
        if (
          is.null(owner) &&
            !is.null(response) &&
            isTRUE(response[["status"]] == 200L) &&
            grepl("^text/html", response[["content_type"]], ignore.case = TRUE)
        ) {
          created <- owners[["create"]](provisional = TRUE)
          # Preserve independent Set-Cookie headers from a request-dependent UI.
          response[["headers"]] <- c(
            response[["headers"]],
            list(
              "Set-Cookie" = connection_owner_cookie_header(
                owners[["cookie_name"]],
                created[["cookie"]],
                manager[["app_origin"]],
                manager[["owner"]]
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
    "http_methods_supported",
    exact = TRUE
  )
  ui
}

# A missing Strict cookie on an external entry is ambiguous: the browser may
# already hold one. Commit an inert document and recheck it on a same-origin
# navigation. The query flag only bounds recovery; it never proves ownership.
connection_owner_recovery_param <- "shinyOAuth_owner_recovery"

connection_manager_owner_recovery <- function(req, uri, owner, cookie, origin) {
  query <- sub("^\\?", "", req[["QUERY_STRING"]] %||% "")
  fields <- decode_form_pairs(query, "Owner recovery")
  marked <- names(fields) == connection_owner_recovery_param
  site <- req[["HTTP_SEC_FETCH_SITE"]]
  same_origin <- if (!is.null(site)) {
    identical(site, "same-origin")
  } else {
    connection_manager_same_origin(req[["HTTP_REFERER"]], origin) ||
      identical(req[["HTTP_ORIGIN"]], origin)
  }
  if (any(marked)) {
    if (
      sum(marked) != 1L || !identical(unname(fields[marked]), list("1")) ||
        !same_origin
    ) {
      return(oauth_get_setup_error("The browser owner recovery request is invalid."))
    }
    # Preserve every application query byte, including repeated parameters.
    parts <- utils::head(
      strsplit(paste0(query, "&sentinel"), "&", fixed = TRUE)[[1L]], -1L
    )
    marked_parts <- rep(FALSE, length(parts))
    marked_parts[nzchar(parts)] <- marked
    clean <- paste(parts[!marked_parts], collapse = "&")
    location <- paste0(
      sub("[?#].*$", "", uri), if (nzchar(clean)) paste0("?", clean) else ""
    )
    return(shiny::httpResponse(
      303L, "text/plain", "",
      headers = list(
        Location = location, "Cache-Control" = "no-store",
        "Referrer-Policy" = "origin"
      )
    ))
  }
  if (!is.null(owner) || !is.null(cookie) || same_origin) {
    return(NULL)
  }
  location <- paste0(
    sub("[?#].*$", "", uri), "?", query, if (nzchar(query)) "&",
    connection_owner_recovery_param, "=1"
  )
  location <- htmltools::htmlEscape(location, attribute = TRUE)
  shiny::httpResponse(
    200L, "text/html; charset=UTF-8",
    paste0(
      '<!doctype html><html><head><meta name="referrer" content="origin">',
      '<meta http-equiv="refresh" content="0;url=', location, '">',
      '<title>Continue to application</title></head><body>',
      '<a href="', location, '">Continue</a></body></html>'
    ),
    headers = list(
      "Cache-Control" = "no-store", "Pragma" = "no-cache",
      "Referrer-Policy" = "origin",
      "Content-Security-Policy" = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
  )
}

# A cross-site HTTP redirect chain withholds Strict cookies even on its final
# same-origin hop. Commit a document before navigating to the bridge's opaque
# continuation; the next request still has to prove the existing live owner.
connection_manager_callback_document <- function(response, uri, origin) {
  location <- response[["headers"]][["Location"]]
  if (is_valid_string(location) && startsWith(location, "?")) {
    location <- paste0(sub("[?#].*$", "", uri), location)
  }
  if (
    is.null(response) ||
      !isTRUE(response[["status"]] == 303L) ||
      !connection_manager_same_origin(location, origin) ||
      length(oauth_module_query_raw_values(
        url_raw_query(location),
        oauth_form_post_handle_param
      )) !=
        1L
  ) {
    return(response)
  }
  location <- htmltools::htmlEscape(location, attribute = TRUE)
  shiny::httpResponse(
    200L,
    "text/html; charset=UTF-8",
    paste0(
      '<!doctype html><html><head><meta name="referrer" content="no-referrer">',
      '<meta http-equiv="refresh" content="0;url=',
      location,
      '">',
      '<title>Continue authorization</title></head><body>',
      '<a href="',
      location,
      '">Continue</a></body></html>'
    ),
    headers = list(
      "Cache-Control" = "no-store",
      "Pragma" = "no-cache",
      "Referrer-Policy" = "no-referrer",
      "Content-Security-Policy" = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
  )
}

# Establish only whether this clean continuation belongs to an independent
# configured module. Read and validate its candidate without consuming it;
# the module must still prove its browser binding and consume state once.
connection_ordinary_continuation <- function(query, uri, clients) {
  if (!length(clients)) {
    return(FALSE)
  }
  tryCatch(
    {
      fields <- decode_form_pairs(query, "Connection continuation")
      selected <- fields[
        names(fields) %in%
          c(oauth_form_post_id_param, oauth_form_post_handle_param)
      ]
      if (length(selected) != 2L || anyDuplicated(names(selected))) {
        return(FALSE)
      }
      id <- selected[[oauth_form_post_id_param]]
      handle <- selected[[oauth_form_post_handle_param]]
      if (!is_valid_string(id) || !id %in% names(clients)) {
        return(FALSE)
      }
      client <- clients[[id]]
      if (
        !oauth_callback_route_matches(
          paste0(sub("[?#].*$", "", uri), "?", query),
          client@redirect_uri
        )
      ) {
        return(FALSE)
      }
      key <- oauth_form_post_cache_key(id, handle, client)
      sealed <- state_store_backend_call(
        client@state_store[["get"]](key, missing = NULL),
        "form_post_store_get"
      )
      payload <- oauth_form_post_unseal_payload(client, id, handle, sealed)
      oauth_form_post_validate_handle_freshness(client, payload)
      payload <- oauth_form_post_validate_payload(payload, client = client)
      state <- payload[["state"]] %||%
        payload[["normalized_response"]][["state"]]
      validated <- state_payload_decrypt_validate(
        client,
        state,
        audit_success = FALSE
      )
      if (!is.null(validated[["transaction_context_digest"]])) {
        return(FALSE)
      }
      record <- state_store_get(client, validated[["state"]])
      state_record_verify_authorization_context(record, NULL)
      TRUE
    },
    error = function(...) FALSE
  )
}

connection_manager_document_base <- function(response, app_base) {
  if (
    is.null(response) ||
      !isTRUE(response[["status"]] == 200L) ||
      !grepl("^text/html", response[["content_type"]], ignore.case = TRUE)
  ) {
    return(response)
  }
  html <- response[["content"]]
  if (
    !is.character(html) ||
      length(html) != 1L ||
      !grepl("<head\\b[^>]*>", html, perl = TRUE, ignore.case = TRUE) ||
      grepl("<base\\b", html, perl = TRUE, ignore.case = TRUE)
  ) {
    err_config("Managed HTML must have a head and no separate base element")
  }
  response[["content"]] <- sub(
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
  response[["headers"]] <- response[["headers"]][
    !tolower(names(response[["headers"]])) %in%
      c("content-length", "etag", "content-md5")
  ]
  response
}
