# This file contains the helpers that propagate shinyOAuth and OpenTelemetry
# configuration into reused async workers.
# Use them when async work should see the same package options, digest keys,
# and OTEL exporter setup as the main Shiny process.

# 1 Async option and OTEL propagation -------------------------------------

## 1.1 Capture and apply configuration ------------------------------------

# Internal: capture shinyOAuth-specific options from the main process for
# propagation to async workers. Call this on the main thread before spawning
# a mirai or future. Only captures options starting with "shinyOAuth." to:
# 1. Reduce serialization overhead
# 2. Avoid serializing closures that may reference other package namespaces
#    (which can cause R serialization warnings)
# 3. Focus on package-specific behavior (audit hooks, HTTP settings, etc.)
# Returns a named list of shinyOAuth option values.
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

# Internal: capture the effective shinyOAuth OTel option gates, including
# default values when the options are currently unset in the main process.
capture_async_otel_option_gates <- function() {
  list(
    shinyOAuth.otel_tracing_enabled = otel_tracing_enabled(),
    shinyOAuth.otel_logging_enabled = otel_logging_enabled()
  )
}

# Internal: apply captured shinyOAuth OTel option gates before restoring worker
# spans. This keeps reused workers from reusing stale FALSE option values from
# previous tasks when the main process expects tracing/logging to be enabled.
apply_async_otel_option_gates <- function(captured_gates) {
  if (is.null(captured_gates) || length(captured_gates) == 0) {
    return(list(old_options = list()))
  }

  list(old_options = do.call(options, captured_gates))
}

# Internal: restore worker-local shinyOAuth OTel option gates after temporary
# async propagation.
restore_async_otel_option_gates <- function(old_options) {
  if (is.null(old_options) || length(old_options) == 0) {
    return(invisible(NULL))
  }

  do.call(options, old_options)
  invisible(NULL)
}

# Internal: capture the OpenTelemetry env vars that influence exporter
# selection and OTLP endpoints. Values set to NA indicate the variable should
# be unset in the async worker.
current_async_otel_envvar_names <- function() {
  grep("^OTEL(_R)?_", names(Sys.getenv()), value = TRUE)
}

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

## 1.2 OTEL cache reset warnings and env restoration ----------------------

# Internal: apply captured OTEL env vars in the current process and rebuild
# cached providers whenever the effective OTEL configuration changes.
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

# Internal: restore OTEL env vars after temporary async worker propagation.
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

## 1.3 Run worker code with captured options ------------------------------

# Internal: run worker code with the main process' shinyOAuth options and OTEL
# environment temporarily restored. Used inside async_dispatch() worker
# closures so login/token/userinfo code sees the same package configuration it
# would have seen on the main Shiny process.
#
# Input: the named list returned by capture_async_options(), plus the code to
# run.
# Output: the value produced by `code`, after temporary options/env setup has
# been restored on exit.
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

# Internal: get the main process ID from captured async options.
# Returns NA_integer_ if not available.
get_main_process_id <- function(captured_opts) {
  if (is.null(captured_opts)) {
    return(NA_integer_)
  }
  pid <- captured_opts[[".shinyOAuth.main_process_id"]]
  if (is.null(pid)) NA_integer_ else as.integer(pid)
}

# Internal: check if currently running in an async worker (different process).
# Compares current PID against the captured main process PID.
is_async_worker <- function(captured_opts) {
  main_pid <- get_main_process_id(captured_opts)
  if (is.na(main_pid)) {
    return(NA)
  }
  Sys.getpid() != main_pid
}
