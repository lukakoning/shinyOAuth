# This file contains error-constructor helpers for shinyOAuth
# Used for creating package-specific errors with consistent messages, classes,
# trace ids, and structured context

# 1 Error constructors ---------------------------------------------------------

## 1.1 Generic constructors and formatting -------------------------------------

# Functions in this subsection create the base package condition and prepare
# the small formatting helpers it needs.

#' Abort with a typed shinyOAuth error
#'
#' Builds a typed shinyOAuth condition, emits the matching trace event, and
#' aborts with a resolved trace id. Used by all specialized `err_*()` wrappers.
#'
#' @param msg Error message or rlang-style bullet vector.
#' @param class Condition class or class vector to add to the error.
#' @param context Named list of structured context fields.
#' @param trace_id Optional trace id to reuse for the error.
#' @return No return value. This function always aborts.
#' @keywords internal
#' @noRd
err_abort <- function(
  msg,
  class = "shinyOAuth_error",
  context = list(),
  trace_id = NULL
) {
  trace_id <- resolve_trace_id(trace_id)
  emit_trace_event(c(
    list(type = "error", trace_id = trace_id, message = msg),
    context
  ))
  primary <- short_desc_for_class(c(class, "shinyOAuth_error"))
  message <- format_condition_message(
    primary,
    msg,
    footer = c("i" = paste0("Trace ID: ", trace_id))
  )
  rlang::abort(
    message = message,
    class = c(class, "shinyOAuth_error"),
    trace_id = trace_id,
    context = context
  )
}

#' Format the standard shinyOAuth condition header
#'
#' Used by errors, warnings, and informs that present a concise shinyOAuth
#' title line before their bullet details.
#'
#' @param short Short description shown in the condition header.
#' @param strong Whether to render `short` in bold via cli markup.
#' @return A formatted header string.
#' @keywords internal
#' @noRd
format_header <- function(short, strong = TRUE) {
  short <- as.character(short %||% "")

  if (isTRUE(strong)) {
    return(paste0("[{.pkg shinyOAuth}] - {.strong ", short, "}"))
  }

  paste0("[{.pkg shinyOAuth}] - ", short)
}

#' Build a standard shinyOAuth condition message
#'
#' Combines the package header, normalized bullet body, and any footer bullets
#' into the character vector expected by `rlang` condition helpers.
#'
#' @param short Short description shown in the condition header.
#' @param msg Condition body as a string, bullet vector, or one-level list.
#' @param default_type Bullet type assigned to unnamed body entries.
#' @param footer Optional footer bullets appended after the main body.
#' @param strong Whether to render `short` in bold via cli markup.
#' @return A named character vector suitable for `rlang::abort()`/
#'   `rlang::warn()`/`rlang::inform()`.
#' @keywords internal
#' @noRd
format_condition_message <- function(
  short,
  msg = NULL,
  default_type = "!",
  footer = NULL,
  strong = TRUE
) {
  c(
    format_header(short, strong = strong),
    normalize_bullets(msg, default_type = default_type),
    normalize_bullets(footer, default_type = "i")
  )
}

#' Abort with standard shinyOAuth formatting
#'
#' Used by package helpers that need a custom error title while keeping the same
#' header and bullet structure used by other shinyOAuth conditions.
#'
#' @param short Short description shown in the condition header.
#' @param msg Error body as a string, bullet vector, or one-level list.
#' @param ... Additional arguments forwarded to [rlang::abort()].
#' @param default_type Bullet type assigned to unnamed body entries.
#' @param footer Optional footer bullets appended after the main body.
#' @param strong Whether to render `short` in bold via cli markup.
#' @return No return value. This function always aborts.
#' @keywords internal
#' @noRd
abort_pkg <- function(
  short,
  msg = NULL,
  ...,
  default_type = "!",
  footer = NULL,
  strong = TRUE
) {
  rlang::abort(
    format_condition_message(
      short,
      msg,
      default_type = default_type,
      footer = footer,
      strong = strong
    ),
    ...
  )
}

#' Warn with standard shinyOAuth formatting
#'
#' Used by package helpers that emit advisory warnings with the same header and
#' bullet structure used by shinyOAuth errors.
#'
#' @param short Short description shown in the condition header.
#' @param msg Warning body as a string, bullet vector, or one-level list.
#' @param ... Additional arguments forwarded to [rlang::warn()].
#' @param default_type Bullet type assigned to unnamed body entries.
#' @param footer Optional footer bullets appended after the main body.
#' @param strong Whether to render `short` in bold via cli markup.
#' @return No meaningful return value; emits a warning side effect.
#' @keywords internal
#' @noRd
warn_pkg <- function(
  short,
  msg = NULL,
  ...,
  default_type = "!",
  footer = NULL,
  strong = TRUE
) {
  rlang::warn(
    format_condition_message(
      short,
      msg,
      default_type = default_type,
      footer = footer,
      strong = strong
    ),
    ...
  )
}

#' Inform with standard shinyOAuth formatting
#'
#' Used by package helpers that emit non-error operational notices while
#' keeping the same header structure as other shinyOAuth conditions.
#'
#' @param short Short description shown in the condition header.
#' @param msg Inform body as a string, bullet vector, or one-level list.
#' @param ... Additional arguments forwarded to [rlang::inform()].
#' @param default_type Bullet type assigned to unnamed body entries.
#' @param footer Optional footer bullets appended after the main body.
#' @param strong Whether to render `short` in bold via cli markup.
#' @return No meaningful return value; emits an inform side effect.
#' @keywords internal
#' @noRd
inform_pkg <- function(
  short,
  msg = NULL,
  ...,
  default_type = "i",
  footer = NULL,
  strong = TRUE
) {
  rlang::inform(
    format_condition_message(
      short,
      msg,
      default_type = default_type,
      footer = footer,
      strong = strong
    ),
    ...
  )
}

#' Warn about a deprecated shinyOAuth API with standard formatting
#'
#' Uses lifecycle's deprecation machinery to honor verbosity and once-per-id
#' behavior, then re-emits the warning with shinyOAuth's standard header.
#'
#' @param when Package version where the deprecation started.
#' @param what Deprecated API description.
#' @param with Optional replacement API description.
#' @param details Optional extra details as a string, bullet vector, or list.
#' @param id Optional lifecycle deprecation id.
#' @param env Environment forwarded to [lifecycle::deprecate_warn()].
#' @param user_env User environment forwarded to [lifecycle::deprecate_warn()].
#' @return No meaningful return value; emits a warning side effect when the
#'   deprecation is active under current lifecycle verbosity settings.
#' @keywords internal
#' @noRd
deprecate_warn_pkg <- function(
  when,
  what,
  with = NULL,
  details = NULL,
  id = NULL,
  env = rlang::caller_env(),
  user_env = rlang::caller_env()
) {
  deprecated_cnd <- NULL

  withCallingHandlers(
    lifecycle::deprecate_warn(
      when = when,
      what = what,
      with = with,
      details = details,
      id = id,
      env = env,
      user_env = user_env
    ),
    warning = function(w) {
      if (!inherits(w, "lifecycle_warning_deprecated")) {
        return(invisible(NULL))
      }

      deprecated_cnd <<- w
      tryInvokeRestart("muffleWarning")
      invisible(NULL)
    }
  )

  if (is.null(deprecated_cnd)) {
    return(invisible(NULL))
  }

  what_label <- as.character(what %||% "")
  with_label <- as.character(with %||% "")
  if (nzchar(what_label) && !grepl("`", what_label, fixed = TRUE)) {
    what_label <- paste0("`", what_label, "`")
  }
  if (nzchar(with_label) && !grepl("`", with_label, fixed = TRUE)) {
    with_label <- paste0("`", with_label, "`")
  }

  bullets <- c(
    "!" = paste0(what_label, " was deprecated in shinyOAuth ", when, "."),
    if (nzchar(with_label)) {
      stats::setNames(paste0("Please use ", with_label, " instead."), "i")
    } else {
      character()
    },
    normalize_bullets(details, default_type = "i")
  )

  warn_pkg(
    "Deprecated API",
    bullets,
    class = "lifecycle_warning_deprecated"
  )
}

#' Resolve deprecated constructor argument aliases
#'
#' Used by exported helper constructors to accept renamed arguments through
#' `...` during a deprecation window.
#'
#' @param dots Named list collected from `...`.
#' @param arg_map Named character vector mapping deprecated argument names to
#'   current argument names.
#' @param fn_name Constructor name used in warnings and errors.
#' @param provided_new Named logical vector indicating which current argument
#'   names were already supplied directly.
#' @param when Package version where the deprecation started.
#' @param env Environment forwarded to `deprecate_warn_pkg()`.
#' @param user_env User environment forwarded to `deprecate_warn_pkg()`.
#' @return Named list of remapped current argument names and values.
#' @keywords internal
#' @noRd
resolve_deprecated_constructor_args <- function(
  dots,
  arg_map,
  fn_name,
  provided_new = setNames(logical(0), character(0)),
  when = "0.5.0.9000",
  env = rlang::caller_env(),
  user_env = rlang::caller_env()
) {
  if (length(dots) == 0) {
    return(list())
  }

  dot_names <- names(dots) %||% character(length(dots))
  if (!all(nzchar(dot_names))) {
    err_input(paste0(fn_name, "() does not accept unnamed arguments in ..."))
  }

  unknown <- setdiff(dot_names, names(arg_map))
  if (length(unknown) > 0) {
    err_input(paste0(
      fn_name,
      "(): unknown argument(s) in ...: ",
      paste(sQuote(unknown), collapse = ", ")
    ))
  }

  resolved <- list()
  for (old_name in dot_names) {
    new_name <- unname(arg_map[[old_name]])

    if (isTRUE(provided_new[[new_name]]) || new_name %in% names(resolved)) {
      err_input(paste0(
        fn_name,
        "(): cannot supply both deprecated argument `",
        old_name,
        "` and current argument `",
        new_name,
        "`."
      ))
    }

    deprecate_warn_pkg(
      when = when,
      what = paste0(fn_name, "() argument `", old_name, "`"),
      with = paste0(fn_name, "() argument `", new_name, "`"),
      details = paste(
        "Backward-compatible forwarding via ... is temporary and will be",
        "removed in a future release."
      ),
      id = paste0(
        gsub("[^a-z0-9]+", "-", tolower(fn_name)),
        "-",
        old_name,
        "-arg"
      ),
      env = env,
      user_env = user_env
    )

    resolved[[new_name]] <- dots[[old_name]]
  }

  resolved
}

#' Resolve an error header description from condition classes
#'
#' Used by `err_abort()` to pick the short description shown in the header.
#'
#' @param class_vec Condition class vector.
#' @return A short description string used in the error header.
#' @keywords internal
#' @noRd
short_desc_for_class <- function(class_vec) {
  known <- c(
    shinyOAuth_http_error = "HTTP request failed",
    shinyOAuth_transport_error = "Transport failure",
    shinyOAuth_dpop_nonce_error = "DPoP nonce challenge",
    shinyOAuth_state_error = "Invalid OAuth state",
    shinyOAuth_pkce_error = "PKCE validation failed",
    shinyOAuth_oidc_nonce_error = "OIDC nonce validation failed",
    shinyOAuth_token_error = "Token error",
    shinyOAuth_id_token_error = "ID token error",
    shinyOAuth_userinfo_error = "Userinfo request failed",
    shinyOAuth_userinfo_mismatch = "Userinfo does not match ID token",
    shinyOAuth_config_error = "Configuration error",
    shinyOAuth_input_error = "Invalid input",
    shinyOAuth_parse_error = "Parse error",
    shinyOAuth_error = "Error"
  )

  # Find first matching known class
  hit <- intersect(names(known), class_vec)

  # Return known description or generic fallback
  if (length(hit)) known[[hit[[1]]]] else "Miscellaneous error"
}

#' Normalize rlang error bullets
#'
#' Converts a message vector or list into the named character format expected
#' by [rlang::abort()]. Used by the error constructors in this file.
#'
#' @param msg Message vector or list.
#' @param default_type Bullet type assigned to unnamed entries.
#' @return A named character vector of bullets.
#' @keywords internal
#' @noRd
normalize_bullets <- function(msg, default_type = "!") {
  if (is.null(msg)) {
    return(character())
  }
  # Flatten one level if someone supplied list() of strings
  if (is.list(msg)) {
    msg <- unlist(msg, recursive = FALSE, use.names = TRUE)
  }
  # Preserve names across coercion to character (as.character() drops names)
  nm <- names(msg)
  if (!is.character(msg)) {
    msg <- as.character(msg)
    # Restore names if they were present prior to coercion
    if (!is.null(nm) && length(nm) == length(msg)) {
      names(msg) <- nm
    }
  }
  # Prepare names vector for bullet types
  nm <- names(msg)
  if (is.null(nm)) {
    nm <- rep_len("", length(msg))
  }
  # Fill empty or NA names with default bullet type
  nm[is.na(nm) | nm == ""] <- default_type
  stats::setNames(as.character(msg), nm)
}

# 2 Specialized error constructors ---------------------------------------------

## 2.1 HTTP and transport failures ---------------------------------------------

#' Abort with a typed HTTP error
#'
#' Builds an HTTP-flavored shinyOAuth condition from an httr2 response, extracts
#' safe structured details, emits the corresponding trace event, and aborts.
#' Used when a remote endpoint responds but the response still represents a
#' failure.
#'
#' @param msg Error message or rlang-style bullet vector.
#' @param resp Optional httr2 response object.
#' @param context Named list of structured context fields.
#' @param trace_id Optional trace id to reuse for the error.
#' @return No return value. This function always aborts.
#' @keywords internal
#' @noRd
err_http <- function(msg, resp = NULL, context = list(), trace_id = NULL) {
  trace_id <- resolve_trace_id(trace_id)
  expose <- isTRUE(allow_expose_error_body())
  status <- NA_integer_
  desc <- NULL
  url <- NULL
  transport_error <- NULL
  issuer <- NULL
  body_snippet <- NULL

  if (is_valid_string(context[["transport_error"]])) {
    transport_error <- as.character(context[["transport_error"]])
  }
  if (is_valid_string(context[["issuer"]])) {
    issuer <- as.character(context[["issuer"]])
  }
  if (is_valid_string(context[["url"]])) {
    url <- otel_http_url_full(context[["url"]])
  } else if (is_valid_string(context[["request_url"]])) {
    url <- otel_http_url_full(context[["request_url"]])
  } else if (is_valid_string(context[["discovery_url"]])) {
    url <- otel_http_url_full(context[["discovery_url"]])
  }

  if (inherits(url, "try-error")) {
    url <- NULL
  }

  if (!is.null(resp) && inherits(resp, "httr2_response")) {
    st <- try(httr2::resp_status(resp), silent = TRUE)
    status <- if (!inherits(st, "try-error") && length(st) == 1) {
      st
    } else {
      NA_integer_
    }
    desc <- try(httr2::resp_status_desc(resp), silent = TRUE)
    if (inherits(desc, "try-error")) {
      desc <- NULL
    }
    urlv <- try(httr2::resp_url(resp), silent = TRUE)
    url <- if (!inherits(urlv, "try-error") && length(urlv) == 1) {
      otel_http_url_full(urlv)
    } else {
      NULL
    }
    if (inherits(url, "try-error")) {
      url <- NULL
    }
    # Some callers reach err_http() before their usual parse-time body guard.
    check_resp_body_size(
      resp,
      context = if (is_valid_string(context[["phase"]])) {
        context[["phase"]]
      } else {
        "error response"
      }
    )
    if (expose) {
      body_snippet <- try(httr2::resp_body_string(resp), silent = TRUE)
      if (!inherits(body_snippet, "try-error")) {
        body_snippet <- sanitize_body(body_snippet)
      } else {
        body_snippet <- NULL
      }
    }
  }
  # Compute non-sensitive body digest for debugging if available
  # and extract RFC 6749 §5.2 structured error fields when present
  body_digest <- NULL
  oauth_error <- NULL
  oauth_error_description <- NULL
  oauth_error_uri <- NULL
  if (!is.null(resp) && inherits(resp, "httr2_response")) {
    bs <- try(httr2::resp_body_string(resp), silent = TRUE)
    if (!inherits(bs, "try-error")) {
      dig <- try(openssl::sha256(charToRaw(bs)), silent = TRUE)
      if (!inherits(dig, "try-error")) {
        body_digest <- paste0(sprintf("%02x", as.integer(dig)), collapse = "")
      }
      # RFC 6749 §5.2: try to extract structured error fields from JSON body
      parsed <- try(
        jsonlite::fromJSON(bs, simplifyVector = TRUE),
        silent = TRUE
      )
      if (!inherits(parsed, "try-error") && is.list(parsed)) {
        if (is_valid_string(parsed[["error"]])) {
          oauth_error <- parsed[["error"]]
        }
        if (is_valid_string(parsed[["error_description"]])) {
          oauth_error_description <- parsed[["error_description"]]
        }
        if (is_valid_string(parsed[["error_uri"]])) {
          oauth_error_uri <- otel_http_url_full(parsed[["error_uri"]])
        }
      }
    }
  }

  event_oauth_error_description <- if (isTRUE(expose)) {
    oauth_error_description
  } else {
    NULL
  }

  event <- c(
    list(
      type = "http_error",
      trace_id = trace_id,
      message = msg,
      status = status,
      url = url,
      body_digest = body_digest,
      oauth_error = oauth_error,
      oauth_error_description = event_oauth_error_description,
      oauth_error_uri = oauth_error_uri
    ),
    context
  )
  emit_trace_event(event)

  status_msg <- if (length(status) == 1 && !is.na(status)) {
    if (is_valid_string(desc)) {
      stats::setNames(paste0("Status ", status, ": ", desc, "."), "x")
    } else {
      stats::setNames(paste0("Status ", status, "."), "x")
    }
  } else {
    character()
  }
  # RFC 6749 §5.2: surface structured error fields from token endpoint
  oauth_error_msg <- if (!is.null(oauth_error)) {
    reason <- oauth_error
    if (!is.null(oauth_error_description)) {
      reason <- paste0(reason, ": ", oauth_error_description)
    }
    stats::setNames(paste0("OAuth error: ", reason), "x")
  } else {
    character()
  }
  oauth_error_uri_msg <- if (!is.null(oauth_error_uri)) {
    stats::setNames(paste0("Error URI: ", oauth_error_uri), "i")
  } else {
    character()
  }
  transport_msg <- if (is_valid_string(transport_error)) {
    stats::setNames(paste0("Transport error: ", transport_error), "x")
  } else {
    character()
  }
  url_msg <- if (!is.null(url)) {
    stats::setNames(paste0("URL: ", url), "i")
  } else {
    character()
  }
  issuer_msg <- if (is_valid_string(issuer)) {
    stats::setNames(paste0("Issuer: ", issuer), "i")
  } else {
    character()
  }
  trace_msg <- c("i" = paste0("Trace ID: ", trace_id))
  body_msg <- if (expose && !is.null(body_snippet)) {
    stats::setNames(paste0("Body: ", body_snippet), "i")
  } else {
    character()
  }
  message <- format_condition_message(
    "HTTP request failed",
    c(
      msg,
      status_msg,
      oauth_error_msg,
      oauth_error_uri_msg,
      transport_msg,
      url_msg,
      issuer_msg
    ),
    footer = c(trace_msg, body_msg)
  )

  rlang::abort(
    message = message,
    class = c("shinyOAuth_http_error", "shinyOAuth_error"),
    trace_id = trace_id,
    status = status,
    url = url,
    body_digest = body_digest,
    oauth_error = oauth_error,
    oauth_error_description = oauth_error_description,
    oauth_error_uri = oauth_error_uri,
    context = context
  )
}

#' Abort with a typed transport error
#'
#' Builds a transport-flavored shinyOAuth condition for request failures that
#' did not produce an HTTP response. Used for network failures and timeouts.
#'
#' @param msg Error message or rlang-style bullet vector.
#' @param context Named list of structured context fields.
#' @param parent Optional parent condition.
#' @param trace_id Optional trace id to reuse for the error.
#' @return No return value. This function always aborts.
#' @keywords internal
#' @noRd
err_transport <- function(
  msg,
  context = list(),
  parent = NULL,
  trace_id = NULL
) {
  trace_id <- resolve_trace_id(trace_id)
  emit_trace_event(c(
    list(type = "transport_error", trace_id = trace_id, message = msg),
    context
  ))
  message <- format_condition_message(
    "Transport failure",
    c(msg, "x" = "No HTTP response was received."),
    footer = c("i" = paste0("Trace ID: ", trace_id))
  )
  rlang::abort(
    message = message,
    class = c("shinyOAuth_transport_error", "shinyOAuth_error"),
    trace_id = trace_id,
    context = context,
    parent = parent
  )
}

## 2.2 Typed wrapper constructors ----------------------------------------------

# Thin typed wrappers around err_abort() for the package's common error classes.
# Used throughout login, token, JWT, state, and HTTP helpers.

#' Raise an invalid state error
#'
#' Wraps `err_abort()` with the package state-error class. Used when stored or
#' returned OAuth state data is missing, expired, malformed, or does not match
#' the browser session.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_invalid_state <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_state_error", context = context)
}

#' Raise a PKCE error
#'
#' Wraps `err_abort()` with the package PKCE-error class. Used when the code
#' verifier or challenge values required for the OAuth login flow are invalid.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_pkce <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_pkce_error", context = context)
}

#' Raise an OIDC nonce error
#'
#' Wraps `err_abort()` with the package OIDC nonce-error class. Used when an
#' OpenID Connect nonce is missing or malformed.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_oidc_nonce <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_oidc_nonce_error", context = context)
}

#' Raise a token error
#'
#' Wraps `err_abort()` with the package token-error class. Used by token
#' exchange, refresh, revocation, introspection, and token response validation.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_token <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_token_error", context = context)
}

#' Raise an ID token error
#'
#' Wraps `err_abort()` with the package ID-token-error class. Used when an OIDC
#' ID token is missing, cannot be decoded, or fails claim or signature checks.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_id_token <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_id_token_error", context = context)
}

#' Raise a UserInfo error
#'
#' Wraps `err_abort()` with the package UserInfo-error class. Used when loading,
#' parsing, or validating a UserInfo response fails.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_userinfo <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_userinfo_error", context = context)
}

#' Raise a UserInfo subject mismatch error
#'
#' Wraps `err_abort()` with classes for a UserInfo response whose subject does
#' not match the ID token subject. Used after signed or plain UserInfo responses
#' are decoded.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_userinfo_mismatch <- function(
  msg = "userinfo subject mismatch",
  context = list()
) {
  err_abort(
    msg,
    class = c("shinyOAuth_userinfo_mismatch", "shinyOAuth_userinfo_error"),
    context = context
  )
}

#' Raise a configuration error
#'
#' Wraps `err_abort()` with the package configuration-error class. Used when
#' caller settings, provider metadata, or package options are inconsistent.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_config <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_config_error", context = context)
}

#' Raise an input error
#'
#' Wraps `err_abort()` with the package input-error class. Used when a public
#' function receives an argument value that cannot be accepted.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_input <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_input_error", context = context)
}

#' Raise a parse error
#'
#' Wraps `err_abort()` with the package parse-error class. Used when JSON, JWT,
#' JWKS, form, or other structured data cannot be decoded safely.
#'
#' @param msg Error message or cli-style bullet vector.
#' @param context Named list of diagnostic fields attached to the condition.
#' @return This function does not return; it raises a condition.
#' @keywords internal
#' @noRd
err_parse <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_parse_error", context = context)
}

## 2.3 Other helpers -----------------------------------------------------------

#' Sanitize an HTTP response body preview
#'
#' Used by `err_http()` when body exposure is enabled for development.
#'
#' @param body Response body text to sanitize.
#' @param max_chars Maximum number of bytes to keep before truncation.
#' @return A sanitized preview string.
#' @keywords internal
#' @noRd
sanitize_body <- function(body, max_chars = 200) {
  if (is.null(body) || is.na(body)) {
    return("")
  }
  body <- as.character(body)
  body <- gsub("\n|\r", " ", body)
  if (nchar(body, type = "bytes") > max_chars) {
    paste0(substr(body, 1, max_chars), "... [truncated]")
  } else {
    body
  }
}
