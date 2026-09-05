# This file is part of the standard devtools workflow.
# See `?devtools::test()` for more information.

# The mTLS request fixtures use separate PEM certificate/key files. Select the
# backend before loading curl through Shiny/httr2. test-mtls-backend separately
# checks the fresh Windows default. Keep this out of the package-check process
# so curl's backend startup diagnostic does not create a check NOTE.
if (.Platform$OS.type == "windows" && !nzchar(Sys.getenv("CURL_SSL_BACKEND"))) {
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
}

library(testthat)
library(shiny)
library(shinyOAuth)
helper_otel <- file.path("testthat", "helper-otel.R")
if (file.exists(helper_otel)) {
  source(helper_otel, local = TRUE)
}

test_check("shinyOAuth")
