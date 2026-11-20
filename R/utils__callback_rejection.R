# Rejected callbacks never resume authorization. Their short-lived locators
# carry only an approved public diagnosis, independently of logical state and
# accepted callback handles. Another worker or an evicted entry fails closed.
oauth_callback_rejection_param <- "shinyOAuth_callback_error"

oauth_callback_rejection_cache <- function() {
  cachem::cache_mem(max_age = 120, max_n = 128, max_size = 1024^2)
}

oauth_callback_rejection_key <- function(handle) {
  string_digest(paste0("callback-rejection:", handle), key = NULL)
}

oauth_callback_rejection_mark <- function(response, message) {
  attr(response, "shinyOAuth.callback_rejection") <- TRUE
  attr(response, "shinyOAuth.callback_rejection_message") <- message
  response
}

oauth_callback_rejection_message <- function(e, status) {
  # Conditions can contain opt-in diagnostics and untrusted claim values.
  # Retain only these literal classifications, never the condition or suffix.
  messages <- c(
    "JARM payload missing required iss claim",
    "JARM issuer does not match provider issuer",
    "JARM aud claim is invalid",
    "JARM aud claim does not include client_id",
    "JARM payload missing required exp claim",
    "JARM payload expired",
    "JARM signature is invalid",
    "JARM HMAC signature is invalid",
    "JARM alg=none is not allowed",
    "JARM payload missing required state",
    "State store entry is missing or malformed",
    "JARM signing alg mismatch",
    "JARM outer iss does not match signed issuer",
    "Outer iss parameter does not match JARM iss claim",
    "JARM header could not be parsed",
    "JARM payload could not be parsed",
    "JARM payload must not contain both code and error",
    "JARM payload missing code or error",
    "JARM response must be a single non-empty compact JWT",
    "JARM payload issued in the future",
    "JARM payload is not yet valid",
    "Encrypted JARM response could not be parsed",
    "Encrypted JARM response could not be decrypted",
    "Encrypted JARM alg mismatch",
    "Encrypted JARM enc mismatch",
    "Encrypted JARM kid mismatch",
    "Callback missing required iss parameter (RFC 9207)",
    "Callback iss parameter does not match expected issuer (RFC 9207)",
    "Callback query contains duplicate OAuth parameter",
    "Callback query contains malformed percent-encoded parameter name",
    "OAuth error text must use the RFC 6749 printable ASCII character set",
    "OAuth callback used an unexpected response transport.",
    "OAuth form_post callback must use application/x-www-form-urlencoded.",
    "OAuth form_post callback body exceeded maximum length.",
    "OAuth form_post callback body contains malformed percent-encoded parameter name",
    "OAuth form_post callback body contains malformed percent-encoded parameter value",
    "OAuth form_post callback must not contain both code and error.",
    "OAuth form_post callback missing code or error.",
    "OAuth form_post callback missing state.",
    "OAuth form_post JARM callback must include the response parameter; direct OAuth callback parameters are not accepted.",
    "OAuth form_post JARM callback must not contain both response and direct OAuth callback parameters.",
    "State payload decryption or validation failed"
  )
  headers <- paste0("[shinyOAuth] - ", messages)
  conditions <- list(e)
  for (depth in seq_len(8L)) {
    parent <- tryCatch(e[["parent"]], error = function(...) NULL)
    if (!inherits(parent, "condition")) {
      break
    }
    conditions[[length(conditions) + 1L]] <- parent
    e <- parent
  }
  for (condition in rev(conditions)) {
    lines <- strsplit(
      cli::ansi_strip(conditionMessage(condition)),
      "\n",
      fixed = TRUE
    )[[1L]]
    # Some typed errors use their approved classification as the header title.
    # Exact equality avoids trusting diagnostic values or a suffixed title.
    header <- match(trimws(lines[[1L]]), headers)
    if (!is.na(header)) {
      return(messages[[header]])
    }
    # Only the primary bullet may select a classification. Opt-in received
    # values and other diagnostic suffixes remain outside this allowlist.
    index <- if (
      length(lines) >= 2L && startsWith(trimws(lines[[1L]]), "[shinyOAuth]")
    ) {
      2L
    } else {
      1L
    }
    primary <- trimws(sub(
      "^[[:space:]]*[!x\u2716\u00d7][[:space:]]*",
      "",
      lines[[index]]
    ))
    # Plain errors and bullets can both wrap. Continue only along an exact
    # approved literal, stopping before diagnostic, received or blank lines.
    # The reconstructed text only selects an existing literal; it is not output.
    approved <- c(messages, headers)
    while (index < length(lines) && !any(startsWith(primary, approved))) {
      candidates <- approved[startsWith(approved, primary)]
      continuation <- trimws(lines[[index + 1L]])
      if (!nzchar(primary) || !length(candidates) || !nzchar(continuation)) {
        break
      }
      joined <- paste(primary, continuation)
      if (!any(startsWith(candidates, joined))) {
        break
      }
      primary <- joined
      index <- index + 1L
    }
    # State-store errors can retain that namespace header as the primary
    # bullet of a typed wrapper. Inspect only that selected primary, never an
    # informational or received-value bullet elsewhere in the condition.
    header <- match(primary, headers)
    if (!is.na(header)) {
      return(messages[[header]])
    }
    matched <- startsWith(primary, messages)
    if (any(matched)) return(messages[[which(matched)[[1L]]]])
  }
  if (status >= 500L) {
    "OAuth callback failed."
  } else {
    "OAuth callback could not be processed."
  }
}

oauth_callback_rejection_terminal <- function(status = 400L, message = NULL) {
  shiny::httpResponse(
    status = status,
    content_type = "text/plain; charset=UTF-8",
    content = message %||%
      "OAuth callback rejection is unavailable or already consumed.",
    headers = list(
      "Cache-Control" = "no-store",
      "Pragma" = "no-cache",
      "Referrer-Policy" = "no-referrer"
    )
  )
}

oauth_callback_rejection_wrap <- function(handler, cache = NULL) {
  cache <- cache %||% oauth_callback_rejection_cache()
  path_digest <- function(req) {
    tryCatch(
      string_digest(oauth_form_post_request_path(req)),
      error = function(...) NULL
    )
  }
  redirect <- function(req, response) {
    handle <- paste0("ce1_", random_urlsafe(43))
    message <- attr(
      response,
      "shinyOAuth.callback_rejection_message",
      exact = TRUE
    )
    if (!is_valid_string(message) || nchar(message, type = "bytes") > 512L) {
      message <- "OAuth callback could not be processed."
    }
    tryCatch(
      cache[["set"]](
        oauth_callback_rejection_key(handle),
        list(
          status = as.integer(response[["status"]]),
          message = message,
          path_digest = path_digest(req),
          stored_at = as.numeric(Sys.time())
        )
      ),
      error = function(...) NULL
    )
    # An explicit empty fragment prevents a browser inheriting a fragment from
    # the rejected URL. No request origin, path or query value enters Location.
    shiny::httpResponse(
      303L,
      "text/plain; charset=UTF-8",
      "",
      headers = list(
        Location = paste0(
          "?",
          oauth_callback_rejection_param,
          "=",
          handle,
          "#"
        ),
        "Cache-Control" = "no-store",
        "Pragma" = "no-cache",
        "Referrer-Policy" = "no-referrer"
      )
    )
  }
  wrapped <- function(req) {
    query <- req[["QUERY_STRING"]] %||% ""
    method <- req[["REQUEST_METHOD"]] %||% "GET"
    # Recognize only this fixed-size internal locator before the external query
    # budget. Even a callback budget smaller than this URL must not cause loops.
    exact <- is_valid_string(query) &&
      nchar(query, type = "bytes") <= 96L &&
      grepl("^\\??shinyOAuth_callback_error=ce1_[A-Za-z0-9_-]{43}$", query)
    if (exact && identical(method, "GET")) {
      handle <- sub("^\\??shinyOAuth_callback_error=", "", query)
      key <- oauth_callback_rejection_key(handle)
      entry <- tryCatch(
        cache[["get"]](key, missing = NULL),
        error = function(...) NULL
      )
      path <- path_digest(req)
      if (
        !is.null(entry) &&
          !is.null(path) &&
          identical(entry[["path_digest"]], path)
      ) {
        tryCatch(cache[["remove"]](key), error = function(...) NULL)
        remaining <- tryCatch(
          cache[["get"]](key, missing = NULL),
          error = function(...) TRUE
        )
        age <- as.numeric(Sys.time()) - entry[["stored_at"]]
        if (
          is.null(remaining) &&
            length(age) == 1L &&
            is.finite(age) &&
            age >= 0 &&
            age <= 120
        ) {
          return(oauth_callback_rejection_terminal(
            entry[["status"]],
            entry[["message"]]
          ))
        }
      }
      return(oauth_callback_rejection_terminal())
    }
    rejected <- oauth_http_query_guard(req)
    if (!is.null(rejected)) {
      if (method %in% c("GET", "POST")) {
        return(redirect(req, rejected))
      }
      return(rejected)
    }
    if (
      length(oauth_module_query_raw_values(
        query,
        oauth_callback_rejection_param
      ))
    ) {
      rejected <- oauth_get_setup_error(
        "Invalid OAuth callback rejection continuation."
      )
      if (method %in% c("GET", "POST")) {
        return(redirect(req, rejected))
      }
      if (identical(method, "HEAD")) {
        rejected[["content"]] <- ""
      }
      return(rejected)
    }
    response <- handler(req)
    if (isTRUE(attr(response, "shinyOAuth.callback_rejection", exact = TRUE))) {
      if (method %in% c("GET", "POST")) {
        return(redirect(req, response))
      }
      if (identical(method, "HEAD")) response[["content"]] <- ""
    }
    response
  }
  attr(wrapped, "http_methods_supported") <- attr(
    handler,
    "http_methods_supported",
    exact = TRUE
  )
  wrapped
}
