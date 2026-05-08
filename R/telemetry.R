# This file contains the helpers that connect shinyOAuth code to OpenTelemetry.
# Use them when login, token, module, or async code needs spans or logs without
# repeating the same value-cleaning and attribute-building rules each time.

# 1 Telemetry setup --------------------------------------------------------

## 1.1 Switches and warnings ----------------------------------------------

# Keep one stable instrumentation name so OTEL groups shinyOAuth spans and
# logs under the same scope.
otel_tracer_name <- "io.github.lukakoning.shinyOAuth" # nolint

#' Warn about OpenTelemetry setup failures
#'
#' Used by span and log helpers.
#'
#' @param context Short label for the failing OpenTelemetry operation.
#' @param error Caught condition describing the failure.
#' @return No meaningful return value; emits a warning side effect.
#' @keywords internal
#' @noRd
otel_telemetry_warning <- function(context, error) {
  rlang::warn(
    paste0(
      "[shinyOAuth] OpenTelemetry ",
      context,
      " disabled for this operation: ",
      conditionMessage(error)
    )
  )
}

#' Check whether tracing is enabled
#'
#' Reads the `shinyOAuth.otel_tracing_enabled` option before spans are started.
#'
#' @return `TRUE` when `getOption("shinyOAuth.otel_tracing_enabled", TRUE)` is
#'   enabled; otherwise `FALSE`.
#' @keywords internal
#' @noRd
otel_tracing_enabled <- function() {
  isTRUE(getOption("shinyOAuth.otel_tracing_enabled", TRUE))
}

#' Check whether OTEL logging is enabled
#'
#' Reads the `shinyOAuth.otel_logging_enabled` option before OTEL log records
#' are emitted.
#'
#' @return `TRUE` when `getOption("shinyOAuth.otel_logging_enabled", TRUE)` is
#'   enabled; otherwise `FALSE`.
#' @keywords internal
#' @noRd
otel_logging_enabled <- function() {
  isTRUE(getOption("shinyOAuth.otel_logging_enabled", TRUE))
}

#' Warn about async OTEL worker configuration
#'
#' Warns once when async OAuth work may emit telemetry from worker processes in
#' addition to the main R process. Used by async module setup.
#'
#' @return Invisibly returns `TRUE` when a warning is emitted; otherwise
#'   invisibly returns `FALSE`.
#' @keywords internal
#' @noRd
warn_about_async_otel_workers <- function() {
  otel_active <-
    (otel_tracing_enabled() && isTRUE(otel::is_tracing_enabled())) ||
    (otel_logging_enabled() && isTRUE(otel::is_logging_enabled()))

  if (!isTRUE(otel_active)) {
    return(invisible(FALSE))
  }

  rlang::warn(
    c(
      "[{.pkg shinyOAuth}] - {.strong Verify OpenTelemetry is configured in async workers}",
      "!" = paste(
        "{.code oauth_module_server(async = TRUE)} will emit telemetry from",
        "background worker processes as well as the main R process"
      ),
      "i" = paste(
        "When OTEL is configured via environment variables, shinyOAuth",
        "captures the current OTEL_* values for each async task and",
        "reapplies them inside the worker before running OAuth logic"
      ),
      "i" = paste(
        "You can enable or disable exporters after workers start, but do so",
        "before dispatching the async work that should use the new settings"
      ),
      "i" = paste(
        "If OTEL is configured from R code instead of environment variables,",
        "run the same setup in each worker or recreate workers after",
        "changing it"
      )
    ),
    .frequency = "once",
    .frequency_id = "oauth_module_server_async_otel_workers"
  )

  invisible(TRUE)
}

# 2 Value normalization ----------------------------------------------------

## 2.1 Scalar and list helpers --------------------------------------------

#' Normalize one OTEL scalar attribute value
#'
#' Used by attribute builders throughout the package.
#'
#' @param value Candidate attribute value.
#' @return A single OTEL-safe scalar value, or `NULL` when `value` should be
#'   skipped.
#' @keywords internal
#' @noRd
otel_scalar_attribute <- function(value) {
  if (is.null(value) || length(value) == 0) {
    return(NULL)
  }

  if (inherits(value, "POSIXt")) {
    return(as.character(value[[1]]))
  }

  if (is.list(value)) {
    return(NULL)
  }

  value <- value[[1]]

  if (is.character(value)) {
    if (length(value) != 1L || is.na(value) || !nzchar(value)) {
      return(NULL)
    }
    return(value)
  }

  if (is.logical(value)) {
    if (length(value) != 1L || is.na(value)) {
      return(NULL)
    }
    return(value)
  }

  if (is.integer(value)) {
    if (length(value) != 1L || is.na(value)) {
      return(NULL)
    }
    return(value)
  }

  if (is.numeric(value)) {
    if (length(value) != 1L || is.na(value) || !is.finite(value)) {
      return(NULL)
    }
    return(as.numeric(value))
  }

  out <- tryCatch(as.character(value), error = function(...) NULL)
  if (
    is.null(out) || length(out) == 0L || is.na(out[[1]]) || !nzchar(out[[1]])
  ) {
    return(NULL)
  }

  out[[1]]
}

#' Build an OTEL attributes object
#'
#' Used by span and log helpers.
#'
#' @param x Named list of candidate attributes.
#' @return An `otel::as_attributes(...)` object, or `NULL` when no usable
#'   attributes remain.
#' @keywords internal
#' @noRd
otel_attributes <- function(x) {
  if (is.null(x) || !length(x)) {
    return(NULL)
  }

  attrs <- list()
  for (nm in names(x)) {
    if (!is_valid_string(nm)) {
      next
    }
    value <- otel_scalar_attribute(x[[nm]])
    if (!is.null(value)) {
      attrs[[nm]] <- value
    }
  }

  attrs <- compact_list(attrs)
  if (!length(attrs)) {
    return(NULL)
  }

  otel::as_attributes(attrs)
}

#' Extract an HTTP host for telemetry
#'
#' Used by HTTP attribute builders.
#'
#' @param url URL string to inspect.
#' @return Hostname string, or `NULL` when the URL cannot be parsed.
#' @keywords internal
#' @noRd
otel_http_host <- function(url) {
  if (!is_valid_string(url)) {
    return(NULL)
  }

  parsed <- tryCatch(httr2::url_parse(url), error = function(...) NULL)
  if (is.null(parsed)) {
    return(NULL)
  }

  host <- parsed$hostname %||% NULL
  if (!is_valid_string(host)) {
    return(NULL)
  }

  host
}

#' Count telemetry items
#'
#' Used by telemetry summary helpers.
#'
#' @param x Vector-like value or list to count.
#' @return Integer item count.
#' @keywords internal
#' @noRd
otel_count_items <- function(x) {
  if (is.null(x)) {
    return(0L)
  }

  if (is.list(x)) {
    return(as.integer(length(x)))
  }

  x <- tryCatch(as.vector(x), error = function(...) x)
  x <- x[!is.na(x)]
  as.integer(length(x))
}

otel_join_values <- function(x, sep = " ", sort_values = TRUE) {
  if (is.null(x)) {
    return(NULL)
  }

  if (is.list(x)) {
    x <- unlist(x, recursive = TRUE, use.names = FALSE)
  }

  x <- tryCatch(as.vector(x), error = function(...) x)
  x <- as.character(x)
  x <- x[!is.na(x)]
  x <- trimws(x)
  x <- unique(x[nzchar(x)])

  if (!length(x)) {
    return(NULL)
  }

  if (isTRUE(sort_values)) {
    x <- sort(x)
  }

  paste(x, collapse = sep)
}

# 3 OAuth value summaries --------------------------------------------------

## 3.1 Scopes, claims, and response fields --------------------------------

#' Normalize scope tokens for telemetry
#'
#' Used by login and token telemetry helpers.
#'
#' @param scopes Raw scope input.
#' @param provider Optional provider object used when deciding whether to force
#'   `openid`.
#' @param ensure_openid Whether `openid` should be prepended when appropriate.
#' @param allow_commas Whether one comma-delimited string should be split.
#' @return A character vector of normalized scope tokens.
#' @keywords internal
#' @noRd
otel_scope_tokens <- function(
  scopes,
  provider = NULL,
  ensure_openid = FALSE,
  allow_commas = FALSE
) {
  if (is.null(scopes)) {
    tokens <- character()
  } else if (
    isTRUE(allow_commas) &&
      length(scopes) == 1L &&
      is_valid_string(as.character(scopes)[[1]]) &&
      grepl(",", as.character(scopes)[[1]], fixed = TRUE) &&
      !grepl(" ", as.character(scopes)[[1]], fixed = TRUE)
  ) {
    tokens <- unlist(
      strsplit(as.character(scopes)[[1]], ",", fixed = TRUE),
      use.names = FALSE
    )
  } else {
    tokens <- as_scope_tokens(scopes)
  }

  tokens <- as.character(tokens)
  tokens <- tokens[!is.na(tokens)]
  tokens <- trimws(tokens)
  tokens <- unique(tokens[nzchar(tokens)])

  if (
    isTRUE(ensure_openid) &&
      !is.null(provider) &&
      is_valid_string(provider@issuer) &&
      !("openid" %in% tokens)
  ) {
    tokens <- c("openid", tokens)
  }

  tokens
}

#' Join scope tokens for telemetry
#'
#' Used by telemetry attribute builders.
#'
#' @param scopes Raw scope input.
#' @param provider Optional provider object used when deciding whether to force
#'   `openid`.
#' @param ensure_openid Whether `openid` should be prepended when appropriate.
#' @param allow_commas Whether one comma-delimited string should be split.
#' @return A single space-delimited scope string, or `NULL` when no scopes
#'   survive normalization.
#' @keywords internal
#' @noRd
otel_scope_string <- function(
  scopes,
  provider = NULL,
  ensure_openid = FALSE,
  allow_commas = FALSE
) {
  otel_join_values(
    otel_scope_tokens(
      scopes = scopes,
      provider = provider,
      ensure_openid = ensure_openid,
      allow_commas = allow_commas
    ),
    sep = " ",
    sort_values = FALSE
  )
}

#' Count normalized scope tokens
#'
#' Used by telemetry summaries.
#'
#' @param scopes Raw scope input.
#' @param provider Optional provider object used when deciding whether to force
#'   `openid`.
#' @param ensure_openid Whether `openid` should be prepended when appropriate.
#' @param allow_commas Whether one comma-delimited string should be split.
#' @return Integer count of normalized scope tokens.
#' @keywords internal
#' @noRd
otel_scope_count <- function(
  scopes,
  provider = NULL,
  ensure_openid = FALSE,
  allow_commas = FALSE
) {
  as.integer(length(otel_scope_tokens(
    scopes = scopes,
    provider = provider,
    ensure_openid = ensure_openid,
    allow_commas = allow_commas
  )))
}

#' Check whether claims were requested
#'
#' Used by login telemetry helpers.
#'
#' @param claims Claims value from the client configuration.
#' @return `TRUE` when claims appear to be present; otherwise `FALSE`.
#' @keywords internal
#' @noRd
otel_claims_requested <- function(claims) {
  if (is.null(claims)) {
    return(FALSE)
  }

  if (is.list(claims)) {
    return(length(claims) > 0L)
  }

  is_valid_string(tryCatch(as.character(claims)[[1]], error = function(...) {
    NA_character_
  }))
}

#' Summarize requested claim targets
#'
#' Used by login telemetry helpers.
#'
#' @param claims Claims value as a list or JSON string.
#' @return Comma-separated top-level claim target names, or `NULL` when they
#'   cannot be determined.
#' @keywords internal
#' @noRd
otel_claim_targets <- function(claims) {
  if (is.null(claims)) {
    return(NULL)
  }

  if (is.character(claims)) {
    parsed <- tryCatch(
      jsonlite::fromJSON(claims, simplifyVector = FALSE),
      error = function(...) NULL
    )
    if (is.null(parsed)) {
      return(NULL)
    }
    claims <- parsed
  }

  if (!is.list(claims) || !length(claims)) {
    return(NULL)
  }

  otel_join_values(names(claims), sep = ",", sort_values = TRUE)
}

#' Read a provider max_age value for telemetry
#'
#' Used by login telemetry helpers.
#'
#' @param provider Provider object whose `extra_auth_params` are inspected.
#' @return Non-negative numeric `max_age`, or `NULL` when absent or invalid.
#' @keywords internal
#' @noRd
otel_requested_max_age <- function(provider) {
  if (is.null(provider)) {
    return(NULL)
  }

  max_age <- provider@extra_auth_params[["max_age"]] %||% NULL
  if (is.null(max_age)) {
    return(NULL)
  }

  max_age <- suppressWarnings(as.numeric(max_age[[1]]))
  if (
    length(max_age) != 1L ||
      is.na(max_age) ||
      !is.finite(max_age) ||
      max_age < 0
  ) {
    return(NULL)
  }

  as.numeric(max_age)
}

#' Read the client auth style for telemetry
#'
#' Used by login and token telemetry helpers.
#'
#' @param client OAuth client object.
#' @return Normalized auth-style string, or `NULL` when no client is supplied.
#' @keywords internal
#' @noRd
otel_client_auth_style <- function(client) {
  if (is.null(client)) {
    return(NULL)
  }

  normalize_token_auth_style(client@provider@token_auth_style %||% "header")
}

#' Check whether the browser cookie path is rooted
#'
#' Used by module telemetry helpers.
#'
#' @param browser_cookie_path Configured cookie path.
#' @return `TRUE` when the cookie path is rooted at `/`, `FALSE` when it is a
#'   valid non-root path, or `NULL` when the value is invalid.
#' @keywords internal
#' @noRd
otel_browser_cookie_path_root <- function(browser_cookie_path) {
  if (is.null(browser_cookie_path)) {
    return(TRUE)
  }

  if (!is_valid_string(browser_cookie_path)) {
    return(NULL)
  }

  identical(browser_cookie_path, "/")
}

#' Normalize an HTTP content type for telemetry
#'
#' Used by HTTP and span helpers.
#'
#' @param content_type Optional explicit content type string.
#' @param resp Optional httr2 response used when `content_type` is missing.
#' @return Lowercase media type without parameters, or `NULL`.
#' @keywords internal
#' @noRd
otel_http_content_type <- function(content_type = NULL, resp = NULL) {
  if (!is.null(resp) && inherits(resp, "httr2_response")) {
    content_type <- content_type %||%
      tryCatch(
        httr2::resp_header(resp, "content-type"),
        error = function(...) NULL
      )
  }

  if (!is_valid_string(content_type)) {
    return(NULL)
  }

  content_type <- tolower(trimws(as.character(content_type)[[1]]))
  content_type <- trimws(strsplit(content_type, ";", fixed = TRUE)[[1]][1])
  if (!nzchar(content_type)) {
    return(NULL)
  }

  content_type
}

#' Join required ACR values for telemetry
#'
#' Used by login telemetry helpers.
#'
#' @param values Character vector of ACR values.
#' @return A single joined string, or `NULL` when no usable values remain.
#' @keywords internal
#' @noRd
otel_required_acr_values <- function(values) {
  otel_join_values(values, sep = " ", sort_values = FALSE)
}

#' Join introspection elements for telemetry
#'
#' Used by token and login telemetry helpers.
#'
#' @param values Character vector of introspection checks.
#' @return A single joined string, or `NULL` when no usable values remain.
#' @keywords internal
#' @noRd
otel_introspect_elements <- function(values) {
  otel_join_values(values, sep = ",", sort_values = TRUE)
}

#' Build token response telemetry attributes
#'
#' Used after token exchange and refresh work completes.
#'
#' @param token_set Token response list returned by token exchange or refresh
#'   code.
#' @return A compact named list of OTEL-safe token response attributes.
#' @keywords internal
#' @noRd
otel_token_response_attributes <- function(token_set) {
  if (!is.list(token_set) || !length(token_set)) {
    return(list())
  }

  scope_tokens <- otel_scope_tokens(
    token_set$scope %||% NULL,
    allow_commas = TRUE
  )
  expires_in_present <- !is.null(token_set$expires_in)

  compact_list(list(
    oauth.token_type = otel_scalar_attribute(token_set$token_type %||% NULL),
    oauth.received_id_token = isTRUE(is_valid_string(token_set$id_token)),
    oauth.received_refresh_token = isTRUE(is_valid_string(
      token_set$refresh_token
    )),
    oauth.expires_in_present = isTRUE(expires_in_present),
    oauth.expires_in_synthesized = !isTRUE(expires_in_present),
    oauth.scope.present = length(scope_tokens) > 0L,
    oauth.scopes.granted = otel_scope_string(
      token_set$scope %||% NULL,
      allow_commas = TRUE
    )
  ))
}

# 4 Request and session attributes ----------------------------------------

## 4.1 Shiny and HTTP context builders ------------------------------------

#' Capture the current Shiny session context for telemetry
#'
#' Used when callers do not pass session context explicitly.
#'
#' @return Session-context list, or `NULL` when no usable context is available.
#' @keywords internal
#' @noRd
otel_current_shiny_session <- function() {
  event <- tryCatch(augment_with_shiny_context(list()), error = function(...) {
    list()
  })
  event$shiny_session %||% NULL
}

#' Build Shiny session telemetry attributes
#'
#' Used by client, event, and span helpers.
#'
#' @param shiny_session Optional precomputed session context. When omitted, the
#'   current session is inspected.
#' @return A named list of session-related telemetry attributes.
#' @keywords internal
#' @noRd
otel_shiny_attributes <- function(shiny_session = NULL) {
  shiny_session <- shiny_session %||% otel_current_shiny_session()
  shiny_session <- normalize_shiny_session_context(shiny_session)
  if (is.null(shiny_session)) {
    return(list())
  }

  http <- shiny_session$http %||% NULL
  server_address <- NULL
  http_method <- NULL
  if (is.list(http)) {
    server_address <- http$host %||% NULL
    http_method <- http$method %||% NULL
  }

  compact_list(list(
    shiny.session_token_digest = string_digest(shiny_session$token %||% NULL),
    shiny.session.is_async = isTRUE(shiny_session$is_async),
    shiny.session.main_process_id = as.integer(
      shiny_session$main_process_id %||% NA_integer_
    ),
    shiny.session.process_id = as.integer(
      shiny_session$process_id %||% NA_integer_
    ),
    http.request.method = http_method,
    server.address = server_address
  ))
}

#' Ensure a trace id attribute is present
#'
#' Used by span and log builders.
#'
#' @param attributes Existing attribute list.
#' @param trace_id Optional explicit trace id override.
#' @return The original or augmented attribute list.
#' @keywords internal
#' @noRd
otel_with_trace_attribute <- function(attributes = NULL, trace_id = NULL) {
  attrs <- attributes %||% list()
  trace_id <- otel_scalar_attribute(trace_id %||% get_current_trace_id())
  if (is.null(trace_id)) {
    return(attrs)
  }
  if (!("shinyoauth.trace_id" %in% names(attrs))) {
    attrs[["shinyoauth.trace_id"]] <- trace_id
  }
  attrs
}

#' Build common client telemetry attributes
#'
#' Used by login, token, and module code.
#'
#' @param client Optional OAuth client object.
#' @param module_id Optional Shiny module id.
#' @param shiny_session Optional Shiny session context.
#' @param async Optional async execution flag.
#' @param phase Optional operation phase label.
#' @param extra Named list of extra attributes to merge in.
#' @return A named list of OTEL-safe attributes.
#' @keywords internal
#' @noRd
otel_client_attributes <- function(
  client = NULL,
  module_id = NULL,
  shiny_session = NULL,
  async = NULL,
  phase = NULL,
  extra = list()
) {
  provider <- NULL
  issuer <- NULL
  client_id_digest <- NULL
  if (!is.null(client)) {
    provider <- client@provider@name %||% NULL
    issuer <- client@provider@issuer %||% NULL
    client_id_digest <- string_digest(client@client_id)
  }

  compact_list(c(
    list(
      oauth.provider.name = provider,
      oauth.provider.issuer = issuer,
      oauth.client_id_digest = client_id_digest,
      shiny.module_id = module_id,
      oauth.async = async,
      oauth.phase = phase
    ),
    otel_shiny_attributes(shiny_session = shiny_session),
    extra
  ))
}

#' Replace stale Shiny telemetry attributes
#'
#' Used when async work resumes in a worker process.
#'
#' @param attributes Existing attribute list.
#' @param shiny_session Fresh Shiny session context.
#' @return Updated attribute list.
#' @keywords internal
#' @noRd
otel_replace_shiny_attributes <- function(
  attributes = NULL,
  shiny_session = NULL
) {
  attrs <- attributes %||% list()
  if (is.null(shiny_session)) {
    return(attrs)
  }

  if (length(attrs)) {
    shiny_attr_names <- names(attrs) %in%
      "shiny.session_token_digest" |
      startsWith(names(attrs), "shiny.session.")
    attrs <- attrs[!shiny_attr_names]
  }

  compact_list(c(
    attrs,
    otel_shiny_attributes(shiny_session = shiny_session)
  ))
}

#' Build HTTP telemetry attributes
#'
#' Used by HTTP span helpers.
#'
#' @param method Optional HTTP method.
#' @param url Optional request or response URL.
#' @param resp Optional httr2 response.
#' @param status_code Optional explicit status code.
#' @param content_type Optional explicit content type.
#' @param extra Named list of additional attributes to merge in.
#' @return A named list of HTTP telemetry attributes.
#' @keywords internal
#' @noRd
otel_http_attributes <- function(
  method = NULL,
  url = NULL,
  resp = NULL,
  status_code = NULL,
  content_type = NULL,
  extra = list()
) {
  if (!is.null(resp) && inherits(resp, "httr2_response")) {
    status_code <- status_code %||%
      tryCatch(
        httr2::resp_status(resp),
        error = function(...) NULL
      )
    url <- url %||% tryCatch(httr2::resp_url(resp), error = function(...) NULL)
    content_type <- content_type %||% otel_http_content_type(resp = resp)
  }

  compact_list(c(
    list(
      http.request.method = method,
      http.response.status_code = as.integer(status_code %||% NA_integer_),
      http.response.content_type = otel_http_content_type(
        content_type = content_type
      ),
      server.address = otel_http_host(url)
    ),
    extra
  ))
}

# 5 Span helpers -----------------------------------------------------------

## 5.1 Span lifecycle ------------------------------------------------------

#' Set span attributes
#'
#' Used by HTTP and error helpers.
#'
#' @param span Target span, defaulting to the active span.
#' @param attributes Named list of candidate attributes.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
otel_set_span_attributes <- function(span = NULL, attributes = list()) {
  if (!otel_tracing_enabled()) {
    return(invisible(NULL))
  }

  attributes <- compact_list(attributes)
  if (!length(attributes)) {
    return(invisible(NULL))
  }

  span <- span %||% otel::get_active_span()
  for (nm in names(attributes)) {
    value <- otel_scalar_attribute(attributes[[nm]])
    if (!is.null(value)) {
      try(span$set_attribute(nm, value), silent = TRUE)
    }
  }

  invisible(NULL)
}

#' Mark a span as successful
#'
#' Used when an instrumented operation completes without error.
#'
#' @param span Target span, defaulting to the active span.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
otel_mark_span_ok <- function(span = NULL) {
  if (!otel_tracing_enabled()) {
    return(invisible(NULL))
  }

  span <- span %||% otel::get_active_span()
  try(span$set_status("ok"), silent = TRUE)
  invisible(NULL)
}

#' Record an error on a span
#'
#' Used when an instrumented operation fails.
#'
#' @param error Condition object to record.
#' @param span Target span, defaulting to the active span.
#' @param attributes Named list of extra error-related attributes.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
otel_note_error <- function(error, span = NULL, attributes = list()) {
  if (!otel_tracing_enabled()) {
    return(invisible(NULL))
  }

  span <- span %||% otel::get_active_span()
  if (is.null(error)) {
    return(invisible(NULL))
  }

  err_attrs <- compact_list(c(
    list(
      error.type = paste(class(error), collapse = ", "),
      error.message = conditionMessage(error)
    ),
    attributes
  ))

  otel_set_span_attributes(span = span, attributes = err_attrs)
  try(
    span$add_event(
      "exception",
      attributes = otel_attributes(err_attrs)
    ),
    silent = TRUE
  )
  try(
    span$set_status(
      "error",
      description = conditionMessage(error)
    ),
    silent = TRUE
  )

  invisible(NULL)
}

#' Record an HTTP result on a span
#'
#' Used after outbound requests complete.
#'
#' @param resp httr2 response to inspect.
#' @param span Target span, defaulting to the active span.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
otel_record_http_result <- function(resp, span = NULL) {
  if (!otel_tracing_enabled()) {
    return(invisible(NULL))
  }

  if (is.null(resp) || !inherits(resp, "httr2_response")) {
    return(invisible(NULL))
  }

  span <- span %||% otel::get_active_span()
  otel_set_span_attributes(
    span = span,
    attributes = otel_http_attributes(resp = resp)
  )

  status_code <- tryCatch(httr2::resp_status(resp), error = function(...) NULL)
  if (
    !is.numeric(status_code) || length(status_code) != 1L || is.na(status_code)
  ) {
    return(invisible(NULL))
  }

  if (status_code < 300L) {
    try(span$set_status("ok"), silent = TRUE)
  } else {
    try(
      span$set_status("error", description = paste0("HTTP ", status_code)),
      silent = TRUE
    )
  }

  invisible(NULL)
}

#' Run code inside a local active OTEL span
#'
#' Used around login, token, and module operations.
#'
#' @param name Span name.
#' @param code Unevaluated code block to run.
#' @param attributes Optional named attribute list.
#' @param options Optional span options list.
#' @param mark_ok Whether successful completion should set span status to `ok`.
#' @param parent Optional explicit parent context.
#' @return The evaluated result of `code`.
#' @keywords internal
#' @noRd
with_otel_span <- function(
  name,
  code,
  attributes = NULL,
  options = NULL,
  mark_ok = TRUE,
  parent = NULL
) {
  code <- substitute(code)
  if (!otel_tracing_enabled()) {
    return(eval(code, envir = parent.frame()))
  }

  span_options <- options %||% list()
  if (!is.null(parent) || (length(parent) == 1L && is.na(parent))) {
    span_options$parent <- parent
  }

  span_started <- FALSE
  tryCatch(
    {
      otel::start_local_active_span(
        name = name,
        attributes = otel_attributes(otel_with_trace_attribute(attributes)),
        options = span_options,
        activation_scope = environment()
      )
      span_started <- TRUE
    },
    error = function(e) {
      otel_telemetry_warning("span", e)
    }
  )
  ok <- FALSE
  err <- NULL

  on.exit(
    {
      if (isTRUE(span_started)) {
        if (isTRUE(ok) && isTRUE(mark_ok)) {
          otel_mark_span_ok()
        } else if (!is.null(err)) {
          otel_note_error(err)
        }
      }
    },
    add = TRUE
  )

  tryCatch(
    {
      result <- eval(code, envir = parent.frame())
      ok <- TRUE
      result
    },
    error = function(e) {
      err <<- e
      stop(e)
    }
  )
}

#' Run code with an existing active span
#'
#' Used when helper code needs to continue inside an already-created span.
#'
#' @param span Existing span to activate.
#' @param code Unevaluated code block to run.
#' @return The evaluated result of `code`.
#' @keywords internal
#' @noRd
otel_with_active_span <- function(span, code) {
  code <- substitute(code)
  if (!otel_tracing_enabled() || is.null(span)) {
    return(eval(code, envir = parent.frame()))
  }

  tryCatch(
    otel::local_active_span(
      span,
      end_on_exit = FALSE,
      activation_scope = environment()
    ),
    error = function(e) {
      otel_telemetry_warning("span activation", e)
    }
  )

  eval(code, envir = parent.frame())
}

#' Capture OTEL propagation headers
#'
#' Used before async work is dispatched to a worker.
#'
#' @param span Optional explicit span whose context should be serialized.
#' @return Header list for OTEL propagation, or `NULL` when no valid context is
#'   available.
#' @keywords internal
#' @noRd
otel_capture_context <- function(span = NULL) {
  if (!otel_tracing_enabled()) {
    return(NULL)
  }

  headers <- tryCatch(
    {
      if (!is.null(span)) {
        span$get_context()$to_http_headers()
      } else {
        otel::pack_http_context()
      }
    },
    error = function(...) NULL
  )
  if (is.null(headers) || !length(headers)) {
    return(NULL)
  }

  traceparent <- unname(headers[["traceparent"]] %||% NA_character_)
  if (
    isTRUE(
      identical(
        traceparent,
        "00-00000000000000000000000000000000-0000000000000000-00"
      )
    )
  ) {
    return(NULL)
  }

  headers
}

# 6 Async context handoff --------------------------------------------------

## 6.1 Parent context propagation -----------------------------------------

#' Rebuild an OTEL parent context from headers
#'
#' Used by async worker setup.
#'
#' @param otel_headers Header list or character value containing propagated OTEL
#'   context.
#' @return OTEL context object, or `NULL` when extraction fails.
#' @keywords internal
#' @noRd
otel_span_context_from_headers <- function(otel_headers) {
  if (is.null(otel_headers) || !length(otel_headers)) {
    return(NULL)
  }

  if (is.character(otel_headers)) {
    if (
      length(otel_headers) == 1L &&
        is_valid_string(as.character(otel_headers)[[1]])
    ) {
      header_name <- (names(otel_headers) %||% "traceparent")[[1]]
      otel_headers <- stats::setNames(
        list(as.character(otel_headers)[[1]]),
        header_name
      )
    } else {
      otel_headers <- as.list(otel_headers)
    }
  }

  parent_ctx <- tryCatch(
    otel::extract_http_context(otel_headers),
    error = function(...) NULL
  )
  if (is.null(parent_ctx)) {
    return(NULL)
  }

  if (!isTRUE(tryCatch(parent_ctx$is_valid(), error = function(...) FALSE))) {
    return(NULL)
  }

  parent_ctx
}

#' Start an async parent span
#'
#' Used by async login and module code before work is handed off to a worker.
#'
#' @param name Span name.
#' @param attributes Optional named attribute list.
#' @param parent Optional explicit parent context passed to `otel::start_span()`.
#' @return A list with `span` and `headers` elements.
#' @keywords internal
#' @noRd
otel_start_async_parent <- function(
  name,
  attributes = NULL,
  parent = NA
) {
  if (!otel_tracing_enabled()) {
    return(list(span = NULL, headers = NULL))
  }

  span <- tryCatch(
    {
      otel::start_span(
        name = name,
        attributes = otel_attributes(otel_with_trace_attribute(attributes)),
        options = list(parent = parent)
      )
    },
    error = function(e) {
      otel_telemetry_warning("async parent span", e)
      NULL
    }
  )

  list(
    span = span,
    headers = if (is.null(span)) {
      NULL
    } else {
      otel_capture_context(span)
    }
  )
}

#' Restore an async parent context in a worker
#'
#' Used by worker-side async code.
#'
#' @param otel_headers Propagated header bundle.
#' @param name Child span name.
#' @param attributes Optional named attribute list.
#' @param shiny_session Optional fresh session context.
#' @return Started span object, or `NULL` when a child span cannot be created.
#' @keywords internal
#' @noRd
otel_restore_parent_in_worker <- function(
  otel_headers,
  name,
  attributes = NULL,
  shiny_session = NULL
) {
  if (!otel_tracing_enabled()) {
    return(NULL)
  }

  if (is.null(otel_headers) || !length(otel_headers)) {
    return(NULL)
  }

  parent_ctx <- otel_span_context_from_headers(otel_headers)
  if (is.null(parent_ctx)) {
    return(NULL)
  }

  attributes <- otel_replace_shiny_attributes(
    attributes = attributes,
    shiny_session = shiny_session
  )

  span <- tryCatch(
    {
      otel::start_span(
        name = name,
        attributes = otel_attributes(otel_with_trace_attribute(attributes)),
        options = list(parent = parent_ctx)
      )
    },
    error = function(e) {
      otel_telemetry_warning("worker span", e)
      NULL
    }
  )

  span
}

#' End an async parent span
#'
#' Used when async work returns to the caller.
#'
#' @param parent Parent-span bundle returned by `otel_start_async_parent()`.
#' @param status Outcome status to record.
#' @param error Optional condition to record for error outcomes.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
otel_end_async_parent <- function(
  parent,
  status = c("ok", "error"),
  error = NULL
) {
  if (is.null(parent) || is.null(parent$span)) {
    return(invisible(NULL))
  }

  status <- match.arg(status)
  if (identical(status, "ok")) {
    otel_mark_span_ok(parent$span)
  } else {
    otel_note_error(error, span = parent$span)
  }

  try(otel::end_span(parent$span), silent = TRUE)
  invisible(NULL)
}

# 7 Event logging ----------------------------------------------------------

## 7.1 Audit and log shaping ----------------------------------------------

#' Choose a log severity for an event
#'
#' Used by OTEL log emission helpers.
#'
#' @param type Event type key.
#' @param status Optional event status.
#' @param reason Optional event reason.
#' @return Severity string such as `"info"`, `"warn"`, or `"error"`.
#' @keywords internal
#' @noRd
otel_event_severity <- function(type, status = NULL, reason = NULL) {
  if (!is_valid_string(type)) {
    return("info")
  }

  status <- otel_scalar_attribute(status)
  reason <- otel_scalar_attribute(reason)
  if (identical(type, "audit_userinfo")) {
    return(if (identical(status, "ok")) "info" else "error")
  }

  if (identical(type, "audit_token_revocation")) {
    if (is_valid_string(status) && grepl("^http_", status)) {
      return("warn")
    }
    return("info")
  }

  if (identical(type, "audit_token_introspection")) {
    if (
      identical(status, "ok") ||
        identical(status, "introspection_unsupported") ||
        identical(status, "missing_token")
    ) {
      return("info")
    }
    if (is_valid_string(status)) {
      return("warn")
    }
  }

  if (identical(type, "audit_session_cleared")) {
    if (reason %in% c("refresh_failed_async", "refresh_failed_sync")) {
      return("error")
    }
    return("info")
  }

  if (
    type %in%
      c(
        "audit_callback_validation_failed",
        "audit_invalid_browser_token",
        "audit_browser_cookie_error",
        "audit_callback_iss_missing",
        "audit_callback_iss_mismatch",
        "audit_callback_query_rejected",
        "audit_refresh_failed_but_kept_session",
        "audit_state_parse_failure",
        "audit_state_store_lookup_failed",
        "audit_state_store_removal_failed",
        "audit_error_state_consumption_failed"
      )
  ) {
    return("warn")
  }

  if (
    type %in%
      c(
        "error",
        "http_error",
        "transport_error",
        "audit_token_exchange_error",
        "audit_login_failed"
      )
  ) {
    return("error")
  }

  # Catch-all: treat any unrecognised type containing "_error" or "_failed"
  # as a warning so that new failure events are never silently logged at info.
  if (grepl("_error$|_failed$", type)) {
    return("warn")
  }

  "info"
}

#' Translate an event field name to an OTEL key
#'
#' Used when OTEL log records are built.
#'
#' @param name Event field name.
#' @return Mapped OTEL attribute key, the original name when no mapping is
#'   needed, or `NULL` for invalid input.
#' @keywords internal
#' @noRd
otel_translate_event_key <- function(name) {
  if (!is_valid_string(name)) {
    return(NULL)
  }

  switch(
    name,
    provider = "oauth.provider.name",
    client_provider = "oauth.provider.name",
    issuer = "oauth.provider.issuer",
    client_issuer = "oauth.provider.issuer",
    client_id_digest = "oauth.client_id_digest",
    module_id = "shiny.module_id",
    phase = "oauth.phase",
    trace_id = "shinyoauth.trace_id",
    type = "event.type",
    status = "oauth.status",
    name
  )
}

#' Build OTEL-safe event attributes
#'
#' Used by OTEL log emission helpers.
#'
#' @param event Audit or trace event list.
#' @return Named list of OTEL-safe log attributes, or `NULL` for invalid or
#'   empty input.
#' @keywords internal
#' @noRd
otel_event_attributes <- function(event) {
  if (!is.list(event) || !length(event)) {
    return(NULL)
  }

  sensitive_names <- c(
    "access_token",
    "refresh_token",
    "id_token",
    "code",
    "state",
    "browser_token"
  )

  attrs <- list()
  for (nm in names(event)) {
    if (!is_valid_string(nm) || nm %in% c("timestamp", "shiny_session")) {
      next
    }
    if (nm %in% sensitive_names) {
      next
    }
    if (is.list(event[[nm]])) {
      next
    }
    key <- otel_translate_event_key(nm)
    if (!is_valid_string(key)) {
      next
    }
    value <- otel_scalar_attribute(event[[nm]])
    if (!is.null(value)) {
      attrs[[key]] <- value
    }
  }

  c(attrs, otel_shiny_attributes(event$shiny_session %||% NULL))
}

#' Emit an OTEL log record
#'
#' Used by audit hooks and telemetry emitters.
#'
#' @param event Audit or trace event list.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
otel_emit_log <- function(event) {
  if (!otel_logging_enabled()) {
    return(invisible(NULL))
  }

  if (!is.list(event) || !length(event)) {
    return(invisible(NULL))
  }

  severity <- otel_event_severity(
    event$type %||% NULL,
    status = event$status %||% NULL,
    reason = event$reason %||% NULL
  )
  msg <- otel_scalar_attribute(event$message %||% NULL) %||%
    otel_scalar_attribute(event$type %||% NULL) %||%
    "shinyOAuth"
  otel::log(
    msg = msg,
    severity = severity,
    attributes = otel_attributes(otel_event_attributes(event))
  )

  invisible(NULL)
}
