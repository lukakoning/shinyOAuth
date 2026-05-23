# This file contains the Shiny UI wrapper needed for OAuth/OIDC fragment
# callbacks. The initial GET arrives before a Shiny session exists, so the
# wrapper serves a minimal bridge page that converts the URL fragment into a
# form POST. The POST then reuses the existing pre-session opaque-handle flow.

# 1 Public UI wrapper -----------------------------------------------------------

#' @title
#' Wrap a Shiny UI to enable OAuth 2.0/OIDC fragment callbacks
#'
#' @description
#' `oauth_fragment_ui()` enables plain OAuth 2.0/OIDC
#' `response_mode = "fragment"` callbacks for apps that use
#' [oauth_module_server()]. It wraps your existing Shiny UI so a provider can
#' redirect the browser to a dedicated callback page whose URL fragment contains
#' authorization response parameters.
#'
#' The wrapper serves a minimal bridge page on the callback path. That page
#' parses the fragment in the browser, POSTs the resulting parameters back to
#' the same callback path, and then shinyOAuth stores the callback server-side
#' under a short-lived one-time handle before redirecting the browser back to
#' the normal app page with only that opaque handle in the query string.
#'
#' This helper supports the plain fragment response mode for authorization-code
#' callbacks, where the fragment contains parameters such as `code`, `state`,
#' `error`, and `iss`. It does not decode JWT Secured Authorization Response
#' Mode (JARM) values such as `response_mode = "fragment.jwt"`.
#'
#' @details
#' Fragment callbacks for server-rendered Shiny apps require a browser bridge,
#' because URL fragments are visible to the browser but are never sent in the
#' initial HTTP request. To keep this bridge deterministic and avoid Shiny
#' bootstrap races, `oauth_fragment_ui()` requires a dedicated callback path;
#' it must not be the app root path.
#'
#' When this wrapper is used, it also injects [use_shinyOAuth()] automatically
#' for the wrapped GET UI, so you do not need a separate top-level
#' `use_shinyOAuth()` call.
#'
#' The server-side callback handle is single-use and is rejected if it is older
#' than the smaller of `client@state_payload_max_age` and the configured
#' `state_store` TTL. The bridge page and follow-up POST also apply the same
#' query/body bounds and issuer/state validation used by
#' [oauth_form_post_ui()].
#'
#' @param base_ui Existing Shiny UI object, or a UI function accepting `req`.
#' @param id Shiny module id used by [oauth_module_server()]. This must match
#'   the `id` argument passed to the server module.
#' @param client [OAuthClient] object used by [oauth_module_server()].
#' @param callback_path Optional URL path to accept fragment callbacks on.
#'   Defaults to the path component of `client@redirect_uri`.
#'
#' @return
#' A Shiny UI function. Pass it to [shiny::shinyApp()] and use
#' `uiPattern = ".*"` so Shiny routes the dedicated callback path to this UI
#' function.
#'
#' @export
oauth_fragment_ui <- function(
  base_ui,
  id,
  client,
  callback_path = NULL
) {
  S7::check_is_S7(client, class = OAuthClient)

  if (!is_valid_string(id)) {
    err_input("{.arg id} must be a single non-empty string.")
  }

  callback_path <- normalize_oauth_fragment_callback_path(
    callback_path %||% oauth_fragment_redirect_path(client)
  )

  mark_fragment_ui_called(id, client)

  force(base_ui)
  force(id)
  force(client)
  force(callback_path)

  ensure_dependency <- oauth_form_post_ensure_ui_dependency

  ui <- function(req) {
    if (oauth_fragment_request_matches(req, callback_path)) {
      if (identical(req$REQUEST_METHOD, "GET")) {
        if (oauth_fragment_get_needs_bridge(req)) {
          return(oauth_fragment_bridge_response())
        }
      } else {
        return(oauth_form_post_handle_request(
          req,
          id = id,
          client = client,
          block_fragment = TRUE
        ))
      }
    }

    if (is.function(base_ui)) {
      out <- base_ui(req)
      if (identical(req$REQUEST_METHOD, "GET")) {
        return(ensure_dependency(out))
      }

      return(out)
    }

    if (identical(req$REQUEST_METHOD, "GET")) {
      return(ensure_dependency(base_ui))
    }

    NULL
  }

  supported <- attr(base_ui, "http_methods_supported", exact = TRUE)
  supported <- unique(c(supported %||% "GET", "GET", "POST"))
  attr(ui, "http_methods_supported") <- supported

  ui
}

# 2 Fragment bridge helpers ----------------------------------------------------

#' Internal: derive the callback path for fragment response mode
#'
#' Uses the path component of `client@redirect_uri` and normalizes it for the
#' fragment callback bridge.
#'
#' @param client [OAuthClient] object.
#'
#' @return A normalized callback path.
#' @keywords internal
#' @noRd
oauth_fragment_redirect_path <- function(client) {
  parsed <- httr2::url_parse(client@redirect_uri)
  normalize_oauth_fragment_callback_path(parsed$path %||% "/")
}

#' Internal: normalize and validate a fragment callback path
#'
#' Fragment callbacks require a dedicated callback route so the browser bridge
#' can run before the main Shiny app bootstraps.
#'
#' @param path Candidate callback path.
#'
#' @return A normalized callback path string.
#' @keywords internal
#' @noRd
normalize_oauth_fragment_callback_path <- function(path) {
  path <- normalize_oauth_form_post_callback_path(path)

  if (identical(path, "/")) {
    err_input(
      paste(
        "{.arg callback_path} for {.fn oauth_fragment_ui} must be a dedicated",
        "non-root path such as {.val /callback}."
      )
    )
  }

  path
}

#' Internal: match fragment bridge callback requests
#'
#' Checks whether a request targets the dedicated callback path used by the
#' fragment bridge.
#'
#' @param req Shiny request object.
#' @param callback_path Expected callback path.
#'
#' @return `TRUE` when the request targets the fragment callback path.
#' @keywords internal
#' @noRd
oauth_fragment_request_matches <- function(req, callback_path) {
  identical(oauth_form_post_request_path(req), callback_path) &&
    req$REQUEST_METHOD %in% c("GET", "POST")
}

#' Internal: decide whether a callback GET still needs the fragment bridge
#'
#' The initial fragment callback GET needs the bridge page, but the follow-up
#' GET carrying the opaque `shinyOAuth_form_post*` handle must fall through to
#' the wrapped app UI so `oauth_module_server()` can consume it.
#'
#' @param req Shiny request object.
#'
#' @return `TRUE` when the request should still render the bridge page.
#' @keywords internal
#' @noRd
oauth_fragment_get_needs_bridge <- function(req) {
  if (!identical(req$REQUEST_METHOD, "GET")) {
    return(FALSE)
  }

  query_string <- req$QUERY_STRING %||% ""
  if (!is.character(query_string) || length(query_string) != 1L) {
    return(TRUE)
  }

  !grepl(
    paste0(
      "(^|&)(",
      oauth_form_post_handle_param,
      "|",
      oauth_form_post_id_param,
      ")="
    ),
    query_string
  )
}

#' Internal: build the standalone bridge script URL for the current callback
#'
#' @return An absolute path on the current app origin that serves
#'   `shinyOAuth.js`.
#' @keywords internal
#' @noRd
oauth_fragment_bridge_script_url <- function() {
  ver <- tryCatch(
    as.character(utils::packageVersion("shinyOAuth")),
    error = function(...) NULL
  )
  if (!is_valid_string(ver)) {
    ver <- "dev"
  }

  paste0("shinyOAuth-", ver, "/shinyOAuth.js")
}

#' Internal: build the standalone fragment bridge page
#'
#' Returns the minimal HTML page that parses the fragment in the browser and
#' POSTs it back to the same callback path.
#' @return A `httpResponse` containing the bridge page.
#' @keywords internal
#' @noRd
oauth_fragment_bridge_response <- function() {
  script_url <- oauth_fragment_bridge_script_url()
  body_tags <- htmltools::renderTags(
    htmltools::tags$main(
      id = "shinyOAuth-fragment-bridge",
      `data-shinyoauth-bridge` = "fragment",
      htmltools::tags$p(
        id = "shinyOAuth-fragment-bridge-status",
        "Processing sign-in response..."
      ),
      htmltools::tags$noscript(
        htmltools::tags$p(
          paste(
            "This OAuth fragment callback requires JavaScript to continue.",
            "Open the app in a regular browser with JavaScript enabled."
          )
        )
      )
    )
  )

  shiny::httpResponse(
    status = 200L,
    content_type = "text/html; charset=UTF-8",
    content = paste0(
      "<!doctype html><html lang=\"en\"><head>",
      "<meta charset=\"utf-8\"/>",
      "<title>Processing sign-in response</title>",
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>",
      "<meta name=\"referrer\" content=\"no-referrer\"/>",
      "<script src=\"",
      htmltools::htmlEscape(script_url, attribute = TRUE),
      "\"></script>",
      "</head><body>",
      body_tags$html,
      "</body></html>"
    ),
    headers = stats::setNames(
      as.list(c("no-store", "no-cache", "no-referrer")),
      c("Cache-Control", "Pragma", "Referrer-Policy")
    )
  )
}
