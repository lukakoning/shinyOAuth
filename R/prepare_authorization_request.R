#' Prepare a browser authorization request using GET or POST
#'
#' Creates the same one-use state, PKCE and nonce as [prepare_call()], returning
#' a plain list describing how to send the request. Use this for applications
#' that handle their own browser navigation and [handle_callback()]. In Shiny,
#' the module's `request_login()` sends the request automatically.
#'
#' For GET, navigate the browser to `url`. For POST, create a form with `url` as
#' its action, method POST, and `application/x-www-form-urlencoded` encoding.
#' Add one hidden input per `fields` entry, assigning its `name` and `value`
#' through DOM properties or an HTML escaping library, then submit the form in
#' the current browser window. Repeated names (such as OAuth `resource`) must
#' remain repeated inputs. Do not send the authorization request from R: the
#' provider needs to interact with the user's browser and login cookies.
#'
#' The client selects `authorization_method = "POST"` explicitly. Ordinary
#' OAuth providers may not support POST; confirm their documentation first.
#' [smart_client()] additionally requires the `authorize-post` capability.
#' The outgoing method is independent of the callback `response_mode`.
#' Configured PAR and Request Object requirements still apply. Each result
#' belongs to one login attempt; do not cache it or reuse it after logout.
#'
#' POST preserves the authorization endpoint's fixed query and sends newly
#' composed fields in the body. It permits up to 256 fields and 128 KiB of
#' encoded form data; CR/LF and the browser-reserved `_charset_` field are
#' rejected to prevent the browser changing field values. Existing state and
#' callback size limits also apply. Configure
#' your app's Content Security Policy `form-action` to allow the authorization
#' endpoint. Custom callers must preserve browser binding and callback handling.
#'
#' @inheritParams prepare_call
#' @return A list with `method` (`"GET"` or `"POST"`), `url` and `fields`.
#'   `fields` is empty for GET; for POST it is a list of lists, each with scalar
#'   character `name` and `value`. PAR expiry attributes are preserved as
#'   documented in [prepare_call()]. The result contains transient authorization
#'   data: do not log it or expose it to other browser sessions.
#' @export
prepare_authorization_request <- function(oauth_client, browser_token,
  request_uri_publisher = NULL) {
  result <- prepare_call(oauth_client, browser_token, request_uri_publisher,
    .authorization_request = TRUE)
  if (is.list(result)) return(result)
  request <- list(method = "GET", url = as.character(result), fields = list())
  for (name in names(attributes(result))) attr(request, name) <- attr(result, name)
  request
}

# Serialize only after the common authorization builder has selected direct
# parameters, a Request Object or a PAR reference. Never round-trip a long URL.
authorization_front_channel <- function(client, url, params) {
  if (identical(client@authorization_method, "GET")) {
    return(authorization_url_append(url, params))
  }
  resolved <- authorization_query_resolution(url, params)
  if (!is.null(resolved$problem)) err_config(resolved$problem)
  params <- resolved$params
  fields <- list()
  for (i in seq_along(params)) {
    for (value in as.character(params[[i]])) {
      fields[[length(fields) + 1L]] <- list(name = names(params)[[i]], value = value)
    }
  }
  text <- unlist(fields, use.names = FALSE)
  # WHATWG form serialization differs from R's URI encoder for characters
  # such as '~'. Count UTF-8 bytes with the browser's exact escape set so the
  # main process cannot accept a form that the browser's size check rejects.
  bytes <- as.integer(charToRaw(enc2utf8(paste(text, collapse = ""))))
  unescaped <- c(32L, 42L, 45L, 46L, 48:57, 65:90, 95L, 97:122)
  form_size <- sum(ifelse(bytes %in% unescaped, 1L, 3L)) + max(0L, 2L * length(fields) - 1L)
  if (length(fields) > 256L || anyNA(text) || any(grepl("[\r\n]", text)) ||
      "_charset_" %in% names(params) ||
      form_size > 131072L) {
    err_config("Authorization POST exceeds form limits or contains newline characters")
  }
  list(method = "POST", url = url, fields = fields)
}
