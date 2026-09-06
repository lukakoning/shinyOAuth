test_that("wrapped module errors preserve safe categories and callback codes", {
  withr::local_options(shinyOAuth.expose_error_body = FALSE)
  descriptions <- c(
    shinyOAuth_state_error = "Invalid OAuth state",
    shinyOAuth_id_token_error = "ID token error",
    shinyOAuth_http_error = "HTTP request failed",
    shinyOAuth_transport_error = "Transport failure"
  )
  for (class in names(descriptions)) {
    error <- rlang::error_cnd(class = class, message = "private inner detail")
    for (depth in 1:2) {
      error <- rlang::error_cnd(
        message = "private wrapper detail",
        parent = error
      )
      expect_identical(oauth_module_compose_error(error), descriptions[[class]])
      expect_identical(
        oauth_module_callback_failure_error_code(error),
        if (class == "shinyOAuth_state_error") {
          "invalid_state"
        } else {
          "token_exchange_error"
        }
      )
    }
  }
})

test_that("module error categories respect typed wrappers and generic fallbacks", {
  withr::local_options(shinyOAuth.expose_error_body = FALSE)
  inner <- rlang::error_cnd(
    class = "shinyOAuth_http_error",
    message = "private HTTP detail"
  )
  outer <- rlang::error_cnd(
    class = "shinyOAuth_config_error",
    message = "private configuration",
    parent = inner
  )
  expect_identical(oauth_module_compose_error(outer), "Configuration error")
  expect_identical(
    oauth_module_compose_error(simpleError("private unknown error")),
    "Miscellaneous error"
  )
})
