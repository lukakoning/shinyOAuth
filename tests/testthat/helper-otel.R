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

# Also override any already-initialized ambient providers in this R session.
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
