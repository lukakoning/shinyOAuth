pkgload::load_all(".")

results <- testthat::test_dir(
  "integration/keycloak",
  stop_on_failure = TRUE
)

skip_budget_text <- Sys.getenv("SHINYOAUTH_INT_MAX_SKIPS", unset = "0")
skip_budget <- suppressWarnings(as.integer(skip_budget_text))
if (
  is.na(skip_budget) ||
    skip_budget < 0L ||
    !identical(as.character(skip_budget), skip_budget_text)
) {
  stop(
    "SHINYOAUTH_INT_MAX_SKIPS must be a non-negative integer",
    call. = FALSE
  )
}

summary <- as.data.frame(results)
skip_count <- sum(summary$skipped)
message(
  "[run-integration] Skip budget: ",
  skip_count,
  "/",
  skip_budget
)
if (skip_count > skip_budget) {
  skipped_tests <- summary$test[summary$skipped]
  stop(
    paste0(
      "Integration skip budget exceeded (",
      skip_count,
      "/",
      skip_budget,
      "): ",
      paste(skipped_tests, collapse = "; ")
    ),
    call. = FALSE
  )
}
