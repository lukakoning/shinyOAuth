# This file is part of the standard devtools workflow.
# See `?devtools::test()` for more information.

library(testthat)
library(shiny)
library(shinyOAuth)
helper_otel <- file.path("testthat", "helper-otel.R")
if (file.exists(helper_otel)) {
  source(helper_otel, local = TRUE)
}

test_check("shinyOAuth")
