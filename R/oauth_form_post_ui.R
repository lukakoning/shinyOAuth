# This file contains the Shiny UI wrapper needed for OAuth/OIDC form_post
# callbacks. The POST request arrives before a Shiny session exists, so the
# wrapper stores the callback body under a one-time handle and redirects the
# browser back to the normal Shiny app page.

# 1 Public UI wrapper -----------------------------------------------------------

#' @title
#' Wrap a Shiny UI to enable OAuth 2.0/OIDC form_post callbacks
#'
#' @description
#' `oauth_form_post_ui()` enables the OpenID Foundation OAuth 2.0 Form Post
#' Response Mode for apps that use [oauth_module_server()]. It wraps your
#' existing Shiny UI so a provider can POST an authorization response to the
#' app's redirect URI. The POST body is stored server-side under a short-lived
#' one-time handle, and the browser is redirected back to the app with only
#' that opaque handle in the query string.
#'
#' For most apps, this helper is not needed because the default transport for
#' authorization responses is the query string, which works without this UI wrapper.
#' You only need to use this helper if your provider requires or strongly recommends
#' form_post response mode.
#'
#' To request form_post response mode from the provider, wrap your UI with this
#' helper, configure your [OAuthClient] with `response_mode = "form_post"`, and
#' ensure the `redirect_uri` is set to a URL that routes to this UI wrapper
#' (e.g., the app's root URL or a specific callback path).
#' This helper handles the plain form_post response mode, where the POST body
#' contains authorization response parameters such as `code`, `state`, `error`,
#' and `iss`. When `response_mode = "form_post.jwt"`, the helper validates the
#' inbound JARM `response`, decrypts and validates the enclosed state, and then
#' stores the accepted callback payload under the same one-time handle so the
#' main callback flow can resume from a prevalidated POST boundary.
#'
#' @details
#' When this wrapper is used, it also injects [use_shinyOAuth()] automatically
#' for the wrapped GET UI, so you do not need a separate top-level
#' `use_shinyOAuth()` call.
#'
#' The server-side callback handle is single-use and is rejected if it is older
#' than the smaller of `client@state_payload_max_age` and the configured
#' `state_store` TTL. The raw POST body and transient handle query parameters
#' are also bounded by the `shinyOAuth.callback_max_form_post_*` options
#' described in the usage vignette.
#'
#' @param base_ui
#' Existing Shiny UI object, or a UI function accepting `req`.
#' @param id
#' Shiny module id used by [oauth_module_server()]. This must match
#' the `id` argument passed to the server module.
#' @param client
#' [OAuthClient] object used by [oauth_module_server()].
#' @param callback_path
#' Optional URL path to accept POST callbacks on. Defaults
#' to the path component of `client@redirect_uri`.
#'
#' @return
#' A Shiny UI function. Pass it to [shiny::shinyApp()] and, for non-root
#' callback paths, use `uiPattern = ".*"` so Shiny routes the callback path to
#' this UI function.
#'
#' @export
#'
#' @example inst/examples/oauth_form_post_ui.R
oauth_form_post_ui <- function(
  base_ui,
  id,
  client,
  callback_path = NULL
) {
  S7::check_is_S7(client, class = OAuthClient)

  if (!is_valid_string(id)) {
    err_input("{.arg id} must be a single non-empty string.")
  }

  callback_path <- normalize_oauth_form_post_callback_path(
    callback_path %||% oauth_form_post_redirect_path(client)
  )

  mark_form_post_ui_called(id, client)

  force(base_ui)
  force(id)
  force(client)
  force(callback_path)

  request_matches <- oauth_form_post_request_matches
  handle_request <- oauth_form_post_handle_request
  ensure_dependency <- oauth_form_post_ensure_ui_dependency

  ui <- function(req) {
    if (request_matches(req, callback_path)) {
      return(handle_request(req, id = id, client = client))
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

#' Internal: ensure shinyOAuth UI dependency is present
#'
#' Adds [use_shinyOAuth()] to wrapped GET UIs when it is not already present.
#' Used by [oauth_form_post_ui()] so form_post setups always get the required
#' browser dependency without needing an extra top-level UI helper call.
#'
#' @param ui Wrapped UI value.
#'
#' @return UI value with the shinyOAuth dependency available.
#' @keywords internal
#' @noRd
oauth_form_post_ensure_ui_dependency <- function(ui) {
  assign(".called_js_dependency", TRUE, envir = .watchdog_environment)

  if (inherits(ui, "httpResponse")) {
    return(ui)
  }

  deps <- tryCatch(
    htmltools::resolveDependencies(htmltools::findDependencies(ui)),
    error = function(...) list()
  )
  has_dependency <- any(vapply(
    deps,
    function(dep) identical(dep$name %||% NA_character_, "shinyOAuth"),
    logical(1)
  ))

  if (has_dependency) {
    return(ui)
  }

  htmltools::tagList(use_shinyOAuth(), ui)
}

oauth_form_post_handle_param <- "shinyOAuth_form_post"
oauth_form_post_id_param <- "shinyOAuth_form_post_id"

# 2 Request handling ------------------------------------------------------------

oauth_form_post_redirect_path <- function(client) {
  parsed <- httr2::url_parse(client@redirect_uri)
  normalize_oauth_form_post_callback_path(parsed$path %||% "/")
}

normalize_oauth_form_post_callback_path <- function(path) {
  if (!is.character(path) || length(path) != 1L || is.na(path)) {
    err_input(
      "{.arg callback_path} must be NULL or a single non-empty path string."
    )
  }

  path <- trimws(path)
  if (!nzchar(path)) {
    path <- "/"
  }
  if (grepl("[?#]", path)) {
    err_input("{.arg callback_path} must not contain query or fragment parts.")
  }
  if (grepl("[[:cntrl:]]", path)) {
    err_input("{.arg callback_path} must not contain control characters.")
  }
  if (!startsWith(path, "/")) {
    path <- paste0("/", path)
  }
  if (startsWith(path, "//")) {
    err_input(
      "{.arg callback_path} must not start with {.val //}."
    )
  }

  path
}

oauth_form_post_request_path <- function(req) {
  path <- tryCatch(req$PATH_INFO %||% "/", error = function(...) "/")
  normalize_oauth_form_post_callback_path(path)
}

oauth_form_post_request_matches <- function(req, callback_path) {
  identical(req$REQUEST_METHOD, "POST") &&
    identical(oauth_form_post_request_path(req), callback_path)
}

oauth_form_post_handle_request <- function(req, id, client) {
  tryCatch(
    with_otel_span(
      "shinyOAuth.form_post",
      {
        oauth_form_post_validate_content_type(req)
        limits <- oauth_callback_limits()
        validate_untrusted_query_string(
          req$QUERY_STRING %||% "",
          max_bytes = limits$query
        )
        body <- oauth_form_post_read_body(req, limits$form_post_body)
        payload <- oauth_form_post_parse_body(body, limits, client = client)
        if (identical(payload[["type", exact = TRUE]], "response")) {
          normalized <- validate_jarm_response(
            client,
            payload[["response", exact = TRUE]],
            transport = "form_post"
          )
          # Persist the normalized JARM callback so the module can resume from
          # this prevalidated result without depending on a second JWKS fetch.
          payload$normalized_response <- normalized
          state_payload <- state_payload_decrypt_validate(
            client,
            normalized$state %||% NA_character_,
            audit_success = FALSE
          )
          otel_set_span_attributes(
            attributes = list(
              shinyoauth.trace_id = state_payload$trace_id %||% NULL
            )
          )
          payload$state_payload <- state_payload
        } else {
          # Reject invalid state/issuer before persisting any pre-session
          # form_post handle. Do not consume the logical state here: the Shiny
          # session still needs to prove possession of the browser-bound token.
          state_payload <- state_payload_decrypt_validate(
            client,
            payload[["state", exact = TRUE]],
            audit_success = FALSE
          )
          otel_set_span_attributes(
            attributes = list(
              shinyoauth.trace_id = state_payload$trace_id %||% NULL
            )
          )
          tryCatch(
            enforce_callback_issuer(
              oauth_client = client,
              iss = payload[["iss", exact = TRUE]] %||% NULL
            ),
            error = function(e) {
              error_context <- tryCatch(e[["context"]], error = function(...) {
                NULL
              })
              callback_error <- error_context$callback_error %||%
                "callback_iss_validation_error"
              audit_name <- switch(
                callback_error,
                issuer_missing = "callback_iss_missing",
                issuer_mismatch = "callback_iss_mismatch",
                "callback_iss_validation_failed"
              )
              try(
                audit_event(
                  audit_name,
                  context = compact_list(list(
                    provider = client@provider@name %||% NA_character_,
                    expected_issuer = client@provider@issuer %||% NA_character_,
                    callback_issuer = payload[["iss", exact = TRUE]] %||% NULL,
                    client_id_digest = string_digest(client@client_id),
                    error_class = paste(class(e), collapse = ", ")
                  ))
                ),
                silent = TRUE
              )
              stop(e)
            }
          )
          payload$state_payload <- state_payload
        }
        handle <- oauth_form_post_store_set(client, id, payload)
        location <- oauth_form_post_redirect_location(req, id, handle)

        shiny::httpResponse(
          status = 303L,
          content_type = "text/html; charset=UTF-8",
          content = paste0(
            "<!doctype html><html><head><meta name=\"referrer\" ",
            "content=\"no-referrer\"></head><body>",
            "<a href=\"",
            htmltools::htmlEscape(location, attribute = TRUE),
            "\">Continue</a>",
            "</body></html>"
          ),
          headers = stats::setNames(
            as.list(c(
              location,
              "no-store",
              "no-cache",
              "no-referrer"
            )),
            c("Location", "Cache-Control", "Pragma", "Referrer-Policy")
          )
        )
      },
      attributes = otel_client_attributes(
        client = client,
        module_id = id,
        phase = "form_post.post",
        extra = list(oauth.response_mode = "form_post")
      ),
      parent = NA
    ),
    shinyOAuth_form_post_http_error = function(e) {
      try(
        audit_event(
          "callback_validation_failed",
          context = list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            state_digest = NA_character_,
            error_class = paste(class(e), collapse = ", "),
            phase = "form_post_request_validation"
          )
        ),
        silent = TRUE
      )
      oauth_form_post_error_response(e)
    },
    shinyOAuth_state_error = function(e) {
      configured_jarm_transport <- tryCatch(
        resolve_jarm_callback_transport(client),
        error = function(...) NULL
      )
      if (
        identical(configured_jarm_transport$transport %||% NULL, "form_post")
      ) {
        try(
          audit_event(
            "callback_validation_failed",
            context = list(
              provider = client@provider@name %||% NA_character_,
              issuer = client@provider@issuer %||% NA_character_,
              client_id_digest = string_digest(client@client_id),
              state_digest = NA_character_,
              error_class = paste(class(e), collapse = ", "),
              phase = "form_post_request_validation"
            )
          ),
          silent = TRUE
        )
      }
      oauth_form_post_error_response(e, fallback_status = 400L)
    },
    error = function(e) {
      oauth_form_post_error_response(e, fallback_status = 500L)
    }
  )
}

oauth_form_post_validate_content_type <- function(req) {
  content_type <- req$CONTENT_TYPE %||% req$HTTP_CONTENT_TYPE %||% ""
  content_type <- tolower(trimws(strsplit(
    content_type,
    ";",
    fixed = TRUE
  )[[1]][1]))

  if (!identical(content_type, "application/x-www-form-urlencoded")) {
    err_form_post_http(
      "OAuth form_post callback must use application/x-www-form-urlencoded.",
      status = 415L
    )
  }

  invisible(NULL)
}

oauth_form_post_read_body <- function(req, max_bytes) {
  max_bytes <- suppressWarnings(as.numeric(max_bytes))
  if (
    !is.numeric(max_bytes) ||
      length(max_bytes) != 1L ||
      is.na(max_bytes) ||
      !is.finite(max_bytes) ||
      max_bytes <= 0
  ) {
    err_form_post_http(
      "OAuth form_post callback body limit is invalid.",
      status = 500L
    )
  }
  read_bytes <- max_bytes + 1
  if (read_bytes > .Machine$integer.max) {
    err_form_post_http(
      "OAuth form_post callback body limit is invalid.",
      status = 500L
    )
  }

  content_length <- suppressWarnings(as.numeric(
    req$CONTENT_LENGTH %||% req$HTTP_CONTENT_LENGTH %||% NA_real_
  ))
  if (
    length(content_length) == 1L &&
      is.finite(content_length) &&
      !is.na(content_length) &&
      content_length > max_bytes
  ) {
    err_form_post_http(
      "OAuth form_post callback body exceeded maximum length.",
      status = 413L
    )
  }

  input <- req$rook.input
  if (is.null(input) || !is.function(input$read)) {
    err_form_post_http("OAuth form_post callback body is unavailable.")
  }

  body_raw <- input$read(as.integer(read_bytes))
  if (!is.raw(body_raw)) {
    err_form_post_http("OAuth form_post callback body was not raw bytes.")
  }
  if (length(body_raw) > max_bytes) {
    err_form_post_http(
      "OAuth form_post callback body exceeded maximum length.",
      status = 413L
    )
  }

  tryCatch(
    rawToChar(body_raw),
    error = function(e) {
      err_form_post_http("OAuth form_post callback body could not be decoded.")
    }
  )
}

oauth_form_post_parse_body <- function(
  body,
  limits = oauth_callback_limits(),
  client = NULL
) {
  if (!is.character(body) || length(body) != 1L || is.na(body)) {
    err_form_post_http("OAuth form_post callback body must be a single string.")
  }

  actual_bytes <- nchar(body, type = "bytes")
  if (!is.finite(actual_bytes) || is.na(actual_bytes)) {
    err_form_post_http("OAuth form_post callback body had invalid length.")
  }
  if (actual_bytes > limits$form_post_body) {
    err_form_post_http(
      "OAuth form_post callback body exceeded maximum length.",
      status = 413L
    )
  }

  tryCatch(
    reject_duplicate_form_encoded_members(
      body,
      "OAuth form_post callback body"
    ),
    shinyOAuth_parse_error = function(e) {
      err_form_post_http(conditionMessage(e))
    }
  )

  parsed <- tryCatch(
    shiny::parseQueryString(paste0("?", body)),
    error = function(e) {
      err_form_post_http("OAuth form_post callback body could not be parsed.")
    }
  )

  payload <- compact_list(list(
    response = parsed$response,
    code = parsed$code,
    state = parsed$state,
    error = parsed$error,
    error_description = parsed$error_description,
    error_uri = parsed$error_uri,
    iss = parsed$iss
  ))

  oauth_form_post_validate_payload(payload, limits, client = client)
}

oauth_form_post_validate_payload <- function(
  payload,
  limits = oauth_callback_limits(),
  client = NULL
) {
  if (!is.list(payload)) {
    err_form_post_http("OAuth form_post callback payload must be a list.")
  }
  if (!is.null(client)) {
    S7::check_is_S7(client, class = OAuthClient)
  }

  jarm_transport <- if (is.null(client)) {
    NULL
  } else {
    resolve_jarm_callback_transport(client)
  }
  jarm_client <- !is.null(jarm_transport)

  # Use exact indexing so helper-added fields like `state_payload` cannot
  # partially match OAuth parameter names during revalidation.
  response <- payload[["response", exact = TRUE]]
  code <- payload[["code", exact = TRUE]]
  state <- payload[["state", exact = TRUE]]
  error <- payload[["error", exact = TRUE]]
  error_description <- payload[["error_description", exact = TRUE]]
  error_uri <- payload[["error_uri", exact = TRUE]]
  iss <- payload[["iss", exact = TRUE]]

  validate_untrusted_query_param(
    "response",
    response,
    max_bytes = max(limits$query, limits$form_post_body)
  )
  validate_untrusted_query_param("code", code, limits$code)
  validate_untrusted_query_param("state", state, limits$state)
  validate_untrusted_query_param("error", error, limits$error)
  validate_untrusted_query_param(
    "error_description",
    error_description,
    max_bytes = limits$error_description,
    allow_empty = TRUE
  )
  validate_untrusted_query_param(
    "error_uri",
    error_uri,
    max_bytes = limits$error_uri,
    allow_empty = TRUE
  )
  validate_untrusted_query_param("iss", iss, limits$iss)

  if (!is.null(response)) {
    if (
      !all(vapply(
        list(code, state, error, error_description, error_uri, iss),
        is.null,
        logical(1)
      ))
    ) {
      err_form_post_http(
        paste(
          "OAuth form_post JARM callback must not contain both response and",
          "direct OAuth callback parameters."
        )
      )
    }
    payload$type <- "response"
    return(payload)
  }

  if (isTRUE(jarm_client)) {
    err_form_post_http(
      paste(
        "OAuth form_post JARM callback must include the response",
        "parameter; direct OAuth callback parameters are not accepted."
      )
    )
  }

  if (is.null(state)) {
    err_form_post_http("OAuth form_post callback missing state.")
  }
  if (!is.null(code) && !is.null(error)) {
    err_form_post_http(
      "OAuth form_post callback must not contain both code and error."
    )
  }
  if (is.null(code) && is.null(error)) {
    err_form_post_http("OAuth form_post callback missing code or error.")
  }

  payload$type <- if (!is.null(error)) "error" else "code"
  payload
}

oauth_form_post_redirect_location <- function(req, id, handle) {
  clean_query <- strip_oauth_module_callback_query(req$QUERY_STRING %||% "")
  clean_query <- sub("^\\?", "", clean_query)
  handle_query <- httr2::url_query_build(stats::setNames(
    list(handle, id),
    c(oauth_form_post_handle_param, oauth_form_post_id_param)
  ))
  query <- paste(
    c(clean_query, handle_query)[nzchar(c(
      clean_query,
      handle_query
    ))],
    collapse = "&"
  )

  paste0("?", query)
}

# 3 One-time form_post callback storage ----------------------------------------

oauth_form_post_cache_key <- function(id, handle) {
  if (!is_valid_string(id) || !is_valid_string(handle)) {
    err_invalid_state("Invalid form_post callback handle")
  }

  paste0(
    "formpost",
    raw_to_hex_lower(openssl::sha256(charToRaw(paste(id, handle, sep = "\n"))))
  )
}

oauth_form_post_store_set <- function(client, id, payload) {
  S7::check_is_S7(client, class = OAuthClient)
  if (!is_valid_string(id)) {
    err_invalid_state("Invalid form_post module id")
  }

  payload <- oauth_form_post_validate_payload(payload, client = client)
  handle <- random_urlsafe(32)
  key <- oauth_form_post_cache_key(id, handle)
  payload$module_id <- id
  payload$stored_at <- as.numeric(Sys.time())

  tryCatch(
    client@state_store$set(key, payload),
    error = function(e) {
      err_invalid_state(
        sprintf(
          "Failed to persist form_post callback payload: %s",
          conditionMessage(e)
        ),
        context = list(phase = "form_post_store_set")
      )
    }
  )

  handle
}

oauth_form_post_store_take <- function(client, id, handle) {
  S7::check_is_S7(client, class = OAuthClient)
  if (!is_valid_string(id)) {
    err_invalid_state("Invalid form_post module id")
  }

  limits <- oauth_callback_limits()
  validate_untrusted_query_param(
    oauth_form_post_handle_param,
    handle,
    max_bytes = limits$form_post_handle
  )

  key <- oauth_form_post_cache_key(id, handle)
  store <- client@state_store

  has_take <- !is.null(store$take) && is.function(store$take)
  payload <- NULL
  if (has_take) {
    payload <- tryCatch(
      store$take(key, missing = NULL),
      error = function(e) {
        err_invalid_state(
          sprintf(
            "Failed to consume form_post callback handle: %s",
            conditionMessage(e)
          ),
          context = list(phase = "form_post_store_take")
        )
      }
    )
  } else {
    if (!inherits(store, "cache_mem")) {
      if (!isTRUE(getOption("shinyOAuth.allow_non_atomic_state_store"))) {
        err_config(c(
          "form_post callback store requires atomic `$take(key, missing)` method",
          "i" = paste0(
            "The POST callback handle is single-use. Provide an atomic ",
            "`$take()` via `custom_cache(take = ...)` or use ",
            "`cachem::cache_mem()` for single-process deployments."
          )
        ))
      }
    }

    payload <- tryCatch(
      store$get(key, missing = NULL),
      error = function(e) {
        err_invalid_state(
          sprintf(
            "Failed to read form_post callback handle: %s",
            conditionMessage(e)
          ),
          context = list(phase = "form_post_store_get")
        )
      }
    )
    remove_succeeded <- FALSE
    missing_sentinel <- new.env(parent = emptyenv())
    tryCatch(
      {
        store$remove(key)
        post <- store$get(key, missing = missing_sentinel)
        remove_succeeded <- identical(post, missing_sentinel)
      },
      error = function(e) {
        err_invalid_state(
          sprintf(
            "Failed to remove form_post callback handle: %s",
            conditionMessage(e)
          ),
          context = list(phase = "form_post_store_remove")
        )
      }
    )
    if (!isTRUE(remove_succeeded)) {
      err_invalid_state(
        "Failed to remove form_post callback handle",
        context = list(phase = "form_post_store_remove")
      )
    }
  }

  if (is.null(payload)) {
    err_invalid_state(
      "form_post callback handle is missing or already consumed",
      context = list(phase = "form_post_store_take")
    )
  }
  if (!identical(payload$module_id %||% NULL, id)) {
    err_invalid_state(
      "form_post callback handle module mismatch",
      context = list(phase = "form_post_store_take")
    )
  }

  oauth_form_post_validate_handle_freshness(client, payload)
  oauth_form_post_validate_payload(payload, client = client)
}

oauth_form_post_validate_handle_freshness <- function(client, payload) {
  S7::check_is_S7(client, class = OAuthClient)
  if (!is.list(payload)) {
    err_invalid_state(
      "form_post callback handle payload is malformed",
      context = list(phase = "form_post_store_take")
    )
  }

  stored_at <- payload$stored_at
  if (
    !is.numeric(stored_at) ||
      length(stored_at) != 1L ||
      is.na(stored_at) ||
      !is.finite(stored_at)
  ) {
    err_invalid_state(
      "form_post callback handle is missing a valid stored_at timestamp",
      context = list(phase = "form_post_store_take")
    )
  }

  max_age <- min(
    client_state_payload_max_age(client),
    client_state_store_max_age(client)
  )
  now <- as.numeric(Sys.time())
  if (!is.finite(now) || is.na(now)) {
    err_invalid_state(
      "form_post callback handle freshness could not be evaluated",
      context = list(phase = "form_post_store_take")
    )
  }

  if (stored_at > now + (client@provider@leeway %||% 30)) {
    err_invalid_state(
      "form_post callback handle timestamp is in the future",
      context = list(phase = "form_post_store_take")
    )
  }

  if ((now - stored_at) > max_age) {
    err_invalid_state(
      "form_post callback handle expired",
      context = list(
        phase = "form_post_store_take",
        max_age = max_age
      )
    )
  }

  invisible(TRUE)
}

# 4 HTTP errors ----------------------------------------------------------------

err_form_post_http <- function(message, status = 400L) {
  rlang::abort(
    message,
    class = "shinyOAuth_form_post_http_error",
    status = as.integer(status)
  )
}

oauth_form_post_error_response <- function(
  e,
  fallback_status = 400L,
  expose_message = inherits(e, "shinyOAuth_form_post_http_error")
) {
  status <- tryCatch(e$status, error = function(...) NULL)
  if (
    !is.numeric(status) ||
      length(status) != 1L ||
      is.na(status) ||
      status < 400L
  ) {
    status <- fallback_status
  }

  content <- if (isTRUE(expose_message)) {
    conditionMessage(e)
  } else if (status >= 500L) {
    "OAuth form_post callback failed."
  } else {
    "OAuth form_post callback could not be processed."
  }

  shiny::httpResponse(
    status = as.integer(status),
    content_type = "text/plain; charset=UTF-8",
    content = content,
    headers = stats::setNames(
      as.list(c("no-store", "no-cache", "no-referrer")),
      c("Cache-Control", "Pragma", "Referrer-Policy")
    )
  )
}
