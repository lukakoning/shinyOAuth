reset_test_otel_cache <- function() {
  # Keep tests hermetic even when the developer shell has ambient OTLP exporters
  # configured. Package tests only need local in-process recording.
  Sys.setenv(
    OTEL_R_TRACES_EXPORTER = "none",
    OTEL_R_LOGS_EXPORTER = "none",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_TRACES_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none"
  )
  Sys.unsetenv(c(
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
  ))

  # Default package telemetry to off for tests. Individual OTel-focused tests
  # enable what they need explicitly.
  options(
    shinyOAuth.otel_tracing_enabled = FALSE,
    shinyOAuth.otel_logging_enabled = FALSE
  )

  if (!requireNamespace("otel", quietly = TRUE)) {
    return(invisible(NULL))
  }

  # Replace any initialized providers without calling shutdown(). For test
  # isolation we want to drop exporter state, not flush buffered data to
  # whatever OTLP endpoint happened to be configured earlier in the process.
  otel_test_cache <- get("otel_save_cache", envir = asNamespace("otel"))()
  otel_test_cache[["tracer_provider"]] <- otel::tracer_provider_noop$new()
  otel_test_cache[["logger_provider"]] <- otel::logger_provider_noop$new()
  otel_test_cache[["meter_provider"]] <- otel::meter_provider_noop$new()
  otel_test_cache[["tracer_app"]] <- NULL
  otel_test_cache[["instruments"]] <- NULL
  get("otel_restore_cache", envir = asNamespace("otel"))(otel_test_cache)

  if (requireNamespace("mirai", quietly = TRUE)) {
    mirai_otel_env <- environment(
      get("otel_cache_tracer", envir = asNamespace("mirai"))
    )
    assign("otel_is_tracing", FALSE, envir = mirai_otel_env)
    assign("otel_tracer", NULL, envir = mirai_otel_env)
  }

  invisible(NULL)
}

capture_test_otel_state <- function() {
  otel_env_names <- c(
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
  )

  state <- list(
    envvars = Sys.getenv(otel_env_names, unset = NA_character_),
    options = list(
      shinyOAuth.otel_tracing_enabled = getOption(
        "shinyOAuth.otel_tracing_enabled"
      ),
      shinyOAuth.otel_logging_enabled = getOption(
        "shinyOAuth.otel_logging_enabled"
      )
    ),
    otel_cache = NULL,
    mirai_cache = NULL
  )

  if (requireNamespace("otel", quietly = TRUE)) {
    state$otel_cache <- get("otel_save_cache", envir = asNamespace("otel"))()
  }

  if (requireNamespace("mirai", quietly = TRUE)) {
    mirai_otel_env <- environment(
      get("otel_cache_tracer", envir = asNamespace("mirai"))
    )
    state$mirai_cache <- list(
      env = mirai_otel_env,
      otel_is_tracing = get("otel_is_tracing", envir = mirai_otel_env),
      otel_tracer = get("otel_tracer", envir = mirai_otel_env)
    )
  }

  state
}

restore_test_otel_state <- function(state) {
  if (is.null(state) || !is.list(state)) {
    return(invisible(NULL))
  }

  envvars <- state$envvars %||% character()
  if (length(envvars)) {
    restore_values <- envvars[!is.na(envvars)]
    restore_unset <- names(envvars)[is.na(envvars)]
    if (length(restore_values)) {
      do.call(Sys.setenv, as.list(restore_values))
    }
    if (length(restore_unset)) {
      Sys.unsetenv(restore_unset)
    }
  }

  do.call(options, state$options %||% list())

  if (!is.null(state$otel_cache) && requireNamespace("otel", quietly = TRUE)) {
    get("otel_restore_cache", envir = asNamespace("otel"))(state$otel_cache)
  }

  if (
    !is.null(state$mirai_cache) && requireNamespace("mirai", quietly = TRUE)
  ) {
    assign(
      "otel_is_tracing",
      state$mirai_cache$otel_is_tracing,
      envir = state$mirai_cache$env
    )
    assign(
      "otel_tracer",
      state$mirai_cache$otel_tracer,
      envir = state$mirai_cache$env
    )
  }

  invisible(NULL)
}

# Keep `devtools::load_all()`/`pkgload::load_all()` sessions usable for manual
# OTel verification. testthat sets `TESTTHAT=true` for real test execution,
# but load_all's helper sourcing does not.
if (identical(Sys.getenv("TESTTHAT"), "true")) {
  old_otel_state <- capture_test_otel_state()
  reg.finalizer(
    parent.frame(),
    function(...) restore_test_otel_state(old_otel_state),
    onexit = TRUE
  )
  reset_test_otel_cache()
}
