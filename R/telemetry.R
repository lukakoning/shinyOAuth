otel_tracer_name <- "io.github.lukakoning.shinyOAuth"

otel_telemetry_warning <- function(context, error) {
  warning(
    "[shinyOAuth] OpenTelemetry ",
    context,
    " disabled for this operation: ",
    conditionMessage(error),
    call. = FALSE
  )
}

otel_metric_names <- list(
  sessions_active = "shinyoauth.sessions.active",
  sessions_authenticated = "shinyoauth.sessions.authenticated",
  login_attempts = "shinyoauth.login.attempts",
  login_success = "shinyoauth.login.success",
  login_failure = "shinyoauth.login.failure",
  refresh_success = "shinyoauth.refresh.success",
  refresh_failure = "shinyoauth.refresh.failure",
  logout_total = "shinyoauth.logout.total",
  token_revocation_attempts = "shinyoauth.token.revocation.attempts",
  token_revocation_success = "shinyoauth.token.revocation.success",
  browser_cookie_error_total = "shinyoauth.browser_cookie_error.total",
  callback_duration = "shinyoauth.callback.duration_s",
  token_exchange_duration = "shinyoauth.token_exchange.duration_s",
  refresh_duration = "shinyoauth.refresh.duration_s",
  userinfo_duration = "shinyoauth.userinfo.duration_s"
)

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
  if (is.null(out) || length(out) == 0L || is.na(out[[1]]) || !nzchar(out[[1]])) {
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
    status_code <- status_code %||% tryCatch(
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
  span <- span %||% otel::get_active_span()
  try(span$set_status("ok"), silent = TRUE)
  invisible(NULL)
}

otel_note_error <- function(error, span = NULL, attributes = list()) {
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
  options = NULL,
  metric_name = NULL,
  metric_attributes = NULL
) {
  code <- substitute(code)
  start_time <- proc.time()[["elapsed"]]
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
      if (!is.null(metric_name)) {
        try(
          otel::histogram_record(
            metric_name,
            max(0, proc.time()[["elapsed"]] - start_time),
            attributes = otel_attributes(metric_attributes)
          ),
          silent = TRUE
        )
      }
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

otel_capture_context <- function(span = NULL) {
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
  attributes = NULL,
  metric_name = NULL,
  metric_attributes = NULL
) {
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
    headers = otel_capture_context(span),
    metric_name = metric_name,
    metric_attributes = metric_attributes,
    started_at = proc.time()[["elapsed"]]
  )
}

otel_restore_parent_in_worker <- function(
  otel_headers,
  name,
  attributes = NULL
) {
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
      spn <- otel::start_span(
        name = name,
        attributes = otel_attributes(attributes),
        options = list(parent = parent_ctx)
      )
      otel::local_active_span(
        spn,
        end_on_exit = FALSE,
        activation_scope = parent.frame()
      )
      spn
    },
    error = function(e) {
      otel_telemetry_warning("worker span", e)
      NULL
    }
  )

  span
}

otel_end_async_parent <- function(parent, status = c("ok", "error"), error = NULL) {
  if (is.null(parent) || is.null(parent$span)) {
    return(invisible(NULL))
  }

  status <- match.arg(status)
  if (identical(status, "ok")) {
    otel_mark_span_ok(parent$span)
  } else {
    otel_note_error(error, span = parent$span)
  }

  if (!is.null(parent$metric_name)) {
    try(
      otel::histogram_record(
        parent$metric_name,
        max(0, proc.time()[["elapsed"]] - (parent$started_at %||% proc.time()[["elapsed"]])),
        attributes = otel_attributes(parent$metric_attributes)
      ),
      silent = TRUE
    )
  }

  try(otel::end_span(parent$span), silent = TRUE)
  invisible(NULL)
}

otel_event_severity <- function(type) {
  if (!is_valid_string(type)) {
    return("info")
  }

  if (type %in% c(
    "audit_callback_validation_failed",
    "audit_invalid_browser_token",
    "audit_browser_cookie_error",
    "audit_callback_iss_mismatch",
    "audit_callback_query_rejected",
    "audit_refresh_failed_but_kept_session"
  )) {
    return("warn")
  }

  if (type %in% c("error", "http_error", "transport_error")) {
    return("error")
  }

  if (identical(type, "audit_token_exchange_error")) {
    return("error")
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

otel_metric_attributes <- function(
  provider = NULL,
  async = NULL,
  outcome = NULL
) {
  compact_list(list(
    oauth.provider.name = provider,
    oauth.async = async,
    outcome = outcome
  ))
}

otel_metric_attributes_from_event <- function(event, outcome = NULL) {
  provider <- event$provider %||% event$client_provider %||% NULL
  async <- tryCatch(
    isTRUE(event$shiny_session$is_async),
    error = function(...) NULL
  )

  otel_metric_attributes(provider = provider, async = async, outcome = outcome)
}

otel_emit_metrics <- function(event) {
  if (!isTRUE(getOption("shinyOAuth.otel_metrics_enabled", FALSE))) {
    return(invisible(NULL))
  }

  if (!is.list(event) || !is_valid_string(event$type)) {
    return(invisible(NULL))
  }

  attrs <- otel_attributes(otel_metric_attributes_from_event(event))
  type <- event$type

  if (identical(type, "audit_session_started")) {
    otel::up_down_counter_add(
      otel_metric_names$sessions_active,
      1L,
      attributes = attrs
    )
  } else if (identical(type, "audit_session_ended")) {
    otel::up_down_counter_add(
      otel_metric_names$sessions_active,
      -1L,
      attributes = attrs
    )
    if (isTRUE(event$was_authenticated)) {
      otel::up_down_counter_add(
        otel_metric_names$sessions_authenticated,
        -1L,
        attributes = attrs
      )
    }
  } else if (identical(type, "audit_authenticated_changed")) {
    delta <- if (isTRUE(event$authenticated)) 1L else -1L
    otel::up_down_counter_add(
      otel_metric_names$sessions_authenticated,
      delta,
      attributes = attrs
    )
  } else if (identical(type, "audit_redirect_issued")) {
    otel::counter_add(
      otel_metric_names$login_attempts,
      1L,
      attributes = attrs
    )
  } else if (identical(type, "audit_login_success")) {
    otel::counter_add(
      otel_metric_names$login_success,
      1L,
      attributes = attrs
    )
  } else if (type %in% c(
    "audit_login_failed",
    "audit_token_exchange_error",
    "audit_callback_validation_failed",
    "audit_callback_query_rejected",
    "audit_callback_iss_mismatch"
  )) {
    otel::counter_add(
      otel_metric_names$login_failure,
      1L,
      attributes = attrs
    )
  } else if (identical(type, "audit_token_refresh")) {
    otel::counter_add(
      otel_metric_names$refresh_success,
      1L,
      attributes = attrs
    )
  } else if (type %in% c("audit_refresh_failed_but_kept_session")) {
    otel::counter_add(
      otel_metric_names$refresh_failure,
      1L,
      attributes = attrs
    )
  } else if (
    identical(type, "audit_session_cleared") &&
      is_valid_string(event$reason %||% NULL) &&
      grepl("^refresh_failed", event$reason)
  ) {
    otel::counter_add(
      otel_metric_names$refresh_failure,
      1L,
      attributes = attrs
    )
  } else if (identical(type, "audit_logout")) {
    otel::counter_add(
      otel_metric_names$logout_total,
      1L,
      attributes = attrs
    )
  } else if (identical(type, "audit_token_revocation")) {
    otel::counter_add(
      otel_metric_names$token_revocation_attempts,
      1L,
      attributes = attrs
    )
    if (identical(event$status %||% NULL, "ok")) {
      otel::counter_add(
        otel_metric_names$token_revocation_success,
        1L,
        attributes = attrs
      )
    }
  } else if (identical(type, "audit_browser_cookie_error")) {
    otel::counter_add(
      otel_metric_names$browser_cookie_error_total,
      1L,
      attributes = attrs
    )
  }

  invisible(NULL)
}
