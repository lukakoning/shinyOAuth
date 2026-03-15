# This file is part of the standard devtools workflow.
# See `?devtools::test()` for more information.

Sys.setenv(
  OTEL_TRACES_EXPORTER = "none",
  OTEL_LOGS_EXPORTER = "none",
  OTEL_METRICS_EXPORTER = "none"
)

library(testthat)
library(shiny)
library(shinyOAuth)

if (requireNamespace("otel", quietly = TRUE)) {
  otel_cache <- new.env(parent = emptyenv())
  otel_cache$tracer_provider <- getFromNamespace(
    "tracer_provider_noop",
    "otel"
  )$new()
  otel_cache$logger_provider <- getFromNamespace(
    "logger_provider_noop",
    "otel"
  )$new()
  otel_cache$meter_provider <- getFromNamespace(
    "meter_provider_noop",
    "otel"
  )$new()
  otel_cache$tracer_app <- NULL
  otel_cache$instruments <- NULL
  getFromNamespace("otel_restore_cache", "otel")(otel_cache)
}

test_check("shinyOAuth")
