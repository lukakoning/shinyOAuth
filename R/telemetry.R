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

otel_option_enabled <- function(name, default = TRUE) {
  value <- getOption(name, default)
  is.logical(value) && length(value) == 1L && !is.na(value) && isTRUE(value)
}

otel_tracing_enabled <- function() {
  otel_option_enabled("shinyOAuth.otel_tracing_enabled", default = TRUE)
}

otel_logging_enabled <- function() {
  otel_option_enabled("shinyOAuth.otel_logging_enabled", default = TRUE)
}

otel_runtime_enabled <- function() {
  tracing_active <- isTRUE(otel_tracing_enabled()) &&
    isTRUE(tryCatch(
      otel::is_tracing_enabled(),
      error = function(...) FALSE
    ))
  logging_active <- isTRUE(otel_logging_enabled()) &&
    isTRUE(tryCatch(
      otel::is_logging_enabled(),
      error = function(...) FALSE
    ))

  tracing_active || logging_active
}

warn_about_async_otel_workers <- function() {
  if (!isTRUE(otel_runtime_enabled())) {
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
        "If OTEL is configured via environment variables, set them before",
        "starting workers (e.g., before {.code mirai::daemons()})"
      ),
      "i" = paste(
        "If OTEL is configured from R code, run the same setup in each",
        "worker or recreate workers after configuring it"
      )
    ),
    .frequency = "once",
    .frequency_id = "oauth_module_server_async_otel_workers"
  )

  invisible(TRUE)
}

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

otel_current_shiny_session <- function() {
  event <- tryCatch(augment_with_shiny_context(list()), error = function(...) {
    list()
  })
  event$shiny_session %||% NULL
}

otel_shiny_attributes <- function(shiny_session = NULL) {
  shiny_session <- shiny_session %||% otel_current_shiny_session()
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

otel_http_attributes <- function(
  method = NULL,
  url = NULL,
  resp = NULL,
  status_code = NULL,
  extra = list()
) {
  if (!is.null(resp) && inherits(resp, "httr2_response")) {
    status_code <- status_code %||%
      tryCatch(
        httr2::resp_status(resp),
        error = function(...) NULL
      )
    url <- url %||% tryCatch(httr2::resp_url(resp), error = function(...) NULL)
  }

  compact_list(c(
    list(
      http.request.method = method,
      http.response.status_code = as.integer(status_code %||% NA_integer_),
      server.address = otel_http_host(url)
    ),
    extra
  ))
}

otel_set_span_attributes <- function(span = NULL, attributes = list()) {
  if (!isTRUE(otel_tracing_enabled())) {
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

otel_mark_span_ok <- function(span = NULL) {
  if (!isTRUE(otel_tracing_enabled())) {
    return(invisible(NULL))
  }

  span <- span %||% otel::get_active_span()
  try(span$set_status("ok"), silent = TRUE)
  invisible(NULL)
}

otel_note_error <- function(error, span = NULL, attributes = list()) {
  if (!isTRUE(otel_tracing_enabled())) {
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

with_otel_span <- function(
  name,
  code,
  attributes = NULL,
  options = NULL
) {
  code <- substitute(code)
  if (!isTRUE(otel_tracing_enabled())) {
    return(eval(code, envir = parent.frame()))
  }

  span_started <- FALSE
  tryCatch(
    {
      otel::start_local_active_span(
        name = name,
        attributes = otel_attributes(attributes),
        options = options
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
        if (isTRUE(ok)) {
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

otel_with_active_span <- function(span, code) {
  code <- substitute(code)
  if (!isTRUE(otel_tracing_enabled()) || is.null(span)) {
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

otel_capture_context <- function(span = NULL) {
  if (!isTRUE(otel_tracing_enabled())) {
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

otel_start_async_parent <- function(
  name,
  attributes = NULL
) {
  if (!isTRUE(otel_tracing_enabled())) {
    return(list(span = NULL, headers = NULL))
  }

  span <- tryCatch(
    {
      otel::start_span(
        name = name,
        attributes = otel_attributes(attributes)
      )
    },
    error = function(e) {
      otel_telemetry_warning("async parent span", e)
      NULL
    }
  )

  list(
    span = span,
    headers = otel_capture_context(span)
  )
}

otel_restore_parent_in_worker <- function(
  otel_headers,
  name,
  attributes = NULL
) {
  if (!isTRUE(otel_tracing_enabled())) {
    return(NULL)
  }

  if (is.null(otel_headers) || !length(otel_headers)) {
    return(NULL)
  }

  parent_ctx <- tryCatch(
    otel::extract_http_context(otel_headers),
    error = function(...) NULL
  )
  if (is.null(parent_ctx)) {
    return(NULL)
  }

  span <- tryCatch(
    {
      otel::start_span(
        name = name,
        attributes = otel_attributes(attributes),
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

otel_event_severity <- function(type) {
  if (!is_valid_string(type)) {
    return("info")
  }

  if (
    type %in%
      c(
        "audit_callback_validation_failed",
        "audit_invalid_browser_token",
        "audit_browser_cookie_error",
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

otel_emit_log <- function(event) {
  if (!isTRUE(otel_logging_enabled())) {
    return(invisible(NULL))
  }

  if (!is.list(event) || !length(event)) {
    return(invisible(NULL))
  }

  severity <- otel_event_severity(event$type %||% NULL)
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
