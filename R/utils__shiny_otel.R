# This file contains the helpers that propagate shinyOAuth and OpenTelemetry
# configuration into reused async workers
# Used for giving async workers the same package options, digest keys, and
# telemetry setup as the main Shiny process

# 1 Async option and OTEL propagation ------------------------------------------

## 1.1 Capture and apply configuration -----------------------------------------

#' Capture shinyOAuth options for async workers
#'
#' Captures the shinyOAuth-specific options and related internal metadata that
#' worker code needs to behave like the main Shiny process. Only
#' `shinyOAuth.*` options are copied so async payloads stay small and do not
#' serialize unrelated closures. Used before login or token work is handed off
#' to `mirai` or `future` workers.
#'
#' @return Named list of captured shinyOAuth options and async propagation
#'   metadata.
#' @keywords internal
#' @noRd
capture_async_options <- function() {
  all_opts <- options()
  # Filter to only shinyOAuth.* options
  shinyoauth_names <- grep("^shinyOAuth\\.", names(all_opts), value = TRUE)
  opts <- all_opts[shinyoauth_names]
  # Capture relevant OpenTelemetry env vars as internal metadata so async
  # workers inherit the parent session's telemetry configuration rather than
  # the ambient shell environment.
  opts[[".shinyOAuth.otel_envvars"]] <- capture_async_otel_envvars()
  # Propagate the effective digest key so worker-emitted digests remain
  # comparable even when the operator relies on the default auto-keying.
  opts[[".shinyOAuth.audit_digest_key_cache"]] <- get_audit_digest_key()
  # Also capture the originating process ID for audit event context
  opts[[".shinyOAuth.main_process_id"]] <- Sys.getpid()
  opts
}

#' Capture effective shinyOAuth OTEL option gates
#'
#' Reads the effective tracing and logging gates, including their default
#' values, so reused workers do not keep stale option state from earlier tasks.
#' Used by async worker setup.
#'
#' @return Named list of OTEL gate options and their effective logical values.
#' @keywords internal
#' @noRd
capture_async_otel_option_gates <- function() {
  list(
    shinyOAuth.otel_tracing_enabled = otel_tracing_enabled(),
    shinyOAuth.otel_logging_enabled = otel_logging_enabled()
  )
}

#' Apply captured shinyOAuth OTEL option gates
#'
#' Temporarily applies the main process' effective OTEL gate values before a
#' worker restores spans or emits telemetry. This prevents reused workers from
#' keeping stale `FALSE` option values from earlier tasks.
#'
#' @param captured_gates Named list returned by
#'   `capture_async_otel_option_gates()`.
#' @return List containing `old_options`, suitable for later restoration.
#' @keywords internal
#' @noRd
apply_async_otel_option_gates <- function(captured_gates) {
  if (is.null(captured_gates) || length(captured_gates) == 0) {
    return(list(old_options = list()))
  }

  list(old_options = do.call(options, captured_gates))
}

#' Restore worker-local shinyOAuth OTEL option gates
#'
#' Restores the option values replaced by
#' `apply_async_otel_option_gates()` when async worker setup is unwound.
#'
#' @param old_options Named list of prior option values.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
restore_async_otel_option_gates <- function(old_options) {
  if (is.null(old_options) || length(old_options) == 0) {
    return(invisible(NULL))
  }

  do.call(options, old_options)
  invisible(NULL)
}

#' Capture relevant OpenTelemetry envvar names
#'
#' Finds the OTEL-related environment variables that can influence exporter
#' selection or endpoint routing for async work.
#'
#' @return Character vector of OTEL environment-variable names.
#' @keywords internal
#' @noRd
current_async_otel_envvar_names <- function() {
  grep("^OTEL(_R)?_", names(Sys.getenv()), value = TRUE)
}

#' Capture OpenTelemetry envvars for async workers
#'
#' Records OTEL environment variables from the main process so worker code can
#' recreate the same exporter configuration. Values set to `NA` mean the
#' variable should be unset in the worker.
#'
#' @return Named character vector of OTEL environment variables.
#' @keywords internal
#' @noRd
capture_async_otel_envvars <- function() {
  otel_names <- unique(c(
    current_async_otel_envvar_names(),
    "OTEL_R_TRACES_EXPORTER",
    "OTEL_R_LOGS_EXPORTER",
    "OTEL_R_METRICS_EXPORTER",
    "OTEL_TRACES_EXPORTER",
    "OTEL_LOGS_EXPORTER",
    "OTEL_METRICS_EXPORTER",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
  ))
  if (!length(otel_names)) {
    return(stats::setNames(character(0), character(0)))
  }
  Sys.getenv(otel_names, unset = NA_character_)
}

## 1.2 OTEL cache reset warnings and env restoration ---------------------------

#' Resolve the available OTEL cache reset hook
#'
#' Detects whether the installed otel package exposes a cache reset helper that
#' shinyOAuth can call after OTEL environment changes in reused workers.
#'
#' @return List with `reset`, `source`, and `name` entries describing the
#'   available cache reset hook.
#' @keywords internal
#' @noRd
resolve_async_otel_cache_reset <- function() {
  if (!requireNamespace("otel", quietly = TRUE)) {
    return(list(
      reset = NULL,
      source = "missing",
      name = NA_character_
    ))
  }

  exported_names <- tryCatch(
    getNamespaceExports("otel"),
    error = function(...) character()
  )
  for (candidate in c(
    "otel_clean_cache",
    "reset_otel_cache",
    "reset_provider_cache"
  )) {
    if (!(candidate %in% exported_names)) {
      next
    }

    reset <- tryCatch(
      getExportedValue("otel", candidate),
      error = function(...) NULL
    )
    if (is.function(reset)) {
      return(list(
        reset = reset,
        source = "exported",
        name = candidate
      ))
    }
  }

  otel_ns <- asNamespace("otel")
  for (candidate in c("otel_clean_cache")) {
    reset <- tryCatch(
      get(candidate, envir = otel_ns, inherits = FALSE),
      error = function(...) NULL
    )
    if (is.function(reset)) {
      return(list(
        reset = reset,
        source = "private",
        name = candidate
      ))
    }
  }

  list(
    reset = NULL,
    source = "missing",
    name = NA_character_
  )
}

#' Warn when OTEL exporter changes may not take effect in a reused worker
#'
#' Used when OTEL environment changes but shinyOAuth cannot reset or rebuild the
#' otel provider cache reliably.
#'
#' @param reason Reason for the warning.
#' @param name Optional otel cache-reset helper name.
#' @param error Optional condition from a failed reset attempt.
#' @return Invisibly returns `FALSE`.
#' @keywords internal
#' @noRd
warn_about_async_otel_cache_reset <- function(
  reason = c("missing", "failed"),
  name = NA_character_,
  error = NULL
) {
  reason <- match.arg(reason)

  detail <- if (identical(reason, "failed")) {
    paste0(
      "shinyOAuth changed OTEL_* environment variables in a reused async ",
      "worker, but the otel cache reset hook",
      if (is_valid_string(name)) paste0(" '", name, "'") else "",
      " failed: ",
      conditionMessage(error %||% simpleError("unknown error"))
    )
  } else {
    paste(
      "shinyOAuth changed OTEL_* environment variables in a reused async",
      "worker, but the installed otel package does not expose a cache",
      "reset hook shinyOAuth can call."
    )
  }

  rlang::warn(
    c(
      "[{.pkg shinyOAuth}] - {.strong Async OpenTelemetry exporter changes may not take effect in reused workers}",
      "!" = detail,
      "i" = paste(
        "Reused Mirai workers may keep stale tracer, logger, or exporter",
        "providers until they are recreated."
      ),
      "i" = paste(
        "shinyOAuth feature-tests otel's cache reset hook and uses the",
        "internal otel_clean_cache helper when it is available."
      )
    ),
    .frequency = "once",
    .frequency_id = paste0("async_otel_cache_reset_", reason)
  )

  invisible(FALSE)
}

#' Reset OTEL provider caches after async env changes
#'
#' Used when reused workers temporarily adopt a different OTEL exporter
#' configuration.
#'
#' @return Invisibly returns `TRUE` on success or `FALSE` when only a warning
#'   could be emitted.
#' @keywords internal
#' @noRd
reset_async_otel_cache <- function() {
  cache_reset <- resolve_async_otel_cache_reset()
  if (!is.function(cache_reset$reset)) {
    return(warn_about_async_otel_cache_reset("missing"))
  }

  tryCatch(
    {
      cache_reset$reset()
      invisible(TRUE)
    },
    error = function(e) {
      warn_about_async_otel_cache_reset(
        "failed",
        name = cache_reset$name,
        error = e
      )
    }
  )
}

#' Apply captured OTEL environment variables in a worker
#'
#' Treats the captured OTEL environment as authoritative, applying new values,
#' unsetting missing ones, and resetting OTEL caches when the effective worker
#' configuration changes.
#'
#' @param captured_envvars Named character vector of OTEL environment values.
#' @return List with `changed` and `old_envvars` entries for later restoration.
#' @keywords internal
#' @noRd
apply_async_otel_envvars <- function(captured_envvars) {
  if (is.null(captured_envvars) || length(captured_envvars) == 0) {
    return(list(
      changed = FALSE,
      old_envvars = stats::setNames(character(0), character(0))
    ))
  }

  # Reused workers may still carry OTEL_* values that were not explicitly
  # captured by the parent because they were unset there. Treat the captured
  # state as authoritative and clear any extra OTEL vars currently living in
  # the worker, while preserving them for restore on exit.
  env_names <- unique(c(
    names(captured_envvars),
    current_async_otel_envvar_names()
  ))
  old_envvars <- Sys.getenv(env_names, unset = NA_character_)
  desired_envvars <- stats::setNames(
    rep(NA_character_, length(env_names)),
    env_names
  )
  desired_envvars[names(captured_envvars)] <- captured_envvars
  otel_envvars_changed <- !identical(old_envvars, desired_envvars)
  if (!isTRUE(otel_envvars_changed)) {
    return(list(changed = FALSE, old_envvars = old_envvars))
  }

  new_values <- desired_envvars[!is.na(desired_envvars)]
  vars_to_unset <- names(desired_envvars)[is.na(desired_envvars)]
  if (length(new_values)) {
    do.call(Sys.setenv, as.list(new_values))
  }
  if (length(vars_to_unset)) {
    Sys.unsetenv(vars_to_unset)
  }

  # OTEL_* env vars only affect provider setup at initialization time, so
  # reused async workers must rebuild cached providers after any env change,
  # including transitions from an enabled exporter back to "none".
  reset_async_otel_cache()

  list(changed = TRUE, old_envvars = old_envvars)
}

#' Restore OTEL environment variables after async worker propagation
#'
#' @param old_envvars Previously saved OTEL environment values.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
restore_async_otel_envvars <- function(old_envvars) {
  if (is.null(old_envvars) || length(old_envvars) == 0) {
    return(invisible(NULL))
  }

  restore_values <- old_envvars[!is.na(old_envvars)]
  restore_unset <- names(old_envvars)[is.na(old_envvars)]
  if (length(restore_values)) {
    do.call(Sys.setenv, as.list(restore_values))
  }
  if (length(restore_unset)) {
    Sys.unsetenv(restore_unset)
  }

  reset_async_otel_cache()

  invisible(NULL)
}

## 1.3 Run worker code with captured options -----------------------------------

#' Run code with captured async options restored
#'
#' Restores the main process' shinyOAuth options and OTEL environment while
#' evaluating worker code inside `async_dispatch()`.
#'
#' @param captured_opts Named list returned by `capture_async_options()`.
#' @param code Code to evaluate with the captured settings restored.
#' @return The value produced by `code`.
#' @keywords internal
#' @noRd
with_async_options <- function(captured_opts, code) {
  if (is.null(captured_opts) || length(captured_opts) == 0) {
    return(force(code))
  }
  old_async_worker <- set_async_worker_context(is_async_worker(captured_opts))
  on.exit(set_async_worker_context(old_async_worker), add = TRUE)
  captured_envvars <- captured_opts[[".shinyOAuth.otel_envvars"]]
  captured_digest_key <- captured_opts[[".shinyOAuth.audit_digest_key_cache"]]
  # Filter out internal markers (start with ".")
  opts_to_set <- captured_opts[
    !startsWith(names(captured_opts), ".")
  ]
  if (!is.null(captured_envvars) && length(captured_envvars) > 0) {
    otel_env_state <- apply_async_otel_envvars(captured_envvars)
    if (isTRUE(otel_env_state$changed)) {
      on.exit(
        restore_async_otel_envvars(otel_env_state$old_envvars),
        add = TRUE
      )
    }
  }

  if (".shinyOAuth.audit_digest_key_cache" %in% names(captured_opts)) {
    old_digest_key <- audit_digest_key_env$key
    audit_digest_key_env$key <- captured_digest_key
    on.exit(
      {
        audit_digest_key_env$key <- old_digest_key
      },
      add = TRUE
    )
  }

  if (length(opts_to_set) == 0) {
    return(force(code))
  }
  # Temporarily set options and restore on exit
  old_opts <- do.call(options, opts_to_set)
  on.exit(do.call(options, old_opts), add = TRUE)
  force(code)
}

#' Get the main process id from captured async options
#'
#' @param captured_opts Async option bundle produced by
#'   `capture_async_options()`.
#' @return Main-process pid as an integer, or `NA_integer_` when it is not
#'   available.
#' @keywords internal
#' @noRd
get_main_process_id <- function(captured_opts) {
  if (is.null(captured_opts)) {
    return(NA_integer_)
  }
  pid <- captured_opts[[".shinyOAuth.main_process_id"]]
  if (is.null(pid)) NA_integer_ else as.integer(pid)
}

#' Check whether code is running in an async worker
#'
#' Compares the current pid against the main-process pid captured by
#' `capture_async_options()`.
#'
#' @param captured_opts Async option bundle produced by
#'   `capture_async_options()`.
#' @return `TRUE` when running in a worker process, `FALSE` when running in the
#'   original process, or `NA` when the comparison cannot be made.
#' @keywords internal
#' @noRd
is_async_worker <- function(captured_opts) {
  main_pid <- get_main_process_id(captured_opts)
  if (is.na(main_pid)) {
    return(NA)
  }
  Sys.getpid() != main_pid
}
