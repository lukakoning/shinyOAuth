integration_authorization_helpers <- function() {
  path <- test_path("..", "..", "integration", "keycloak", "helper-keycloak.R")
  skip_if_not(file.exists(path), "Integration helpers unavailable")
  env <- new.env(parent = environment())
  sys.source(path, envir = env)
  env
}

test_that("negative authorization assertions propagate infrastructure errors", {
  integration <- integration_authorization_helpers()
  for (message in c("Connection unavailable", "Login form missing", "Parser failed")) {
    error <- simpleError(message)
    integration$perform_login_form <- function(...) stop(error)
    observed <- tryCatch(integration$expect_no_authorization_code(
      "https://example.test/auth?state=test-state", "https://example.test/callback"
    ), error = identity)
    expect_identical(observed, error)
  }
})

test_that("negative authorization assertions require specific protocol evidence", {
  integration <- integration_authorization_helpers()
  auth <- "https://example.test/auth?state=test-state"
  redirect <- "https://example.test/callback"
  callback <- paste0(redirect, "?error=invalid_request&state=test-state&",
                     "error_description=Missing%20parameter%3A%20code_challenge")
  response <- list(code = NA_character_, callback_url = callback)
  integration$perform_login_form <- function(...) response
  expect_true(integration$expect_no_authorization_code(auth, redirect))
  response$callback_url <- paste0(
    redirect, "?error=invalid_request&state=test-state&",
    "error_description=Invalid+parameter%3A+code+challenge+method+is+not+matching+the+configured+one"
  )
  expect_true(integration$expect_no_authorization_code(auth, redirect))
  for (url in c(
    redirect,
    sub("invalid_request", "server_error", callback),
    sub("test-state", "unrelated-state", callback),
    sub("code_challenge", "redirect_uri", callback),
    paste0(callback, "&code=unexpected"),
    sub("/callback", "/elsewhere", callback)
  )) {
    response$callback_url <- url
    expect_failure(integration$expect_no_authorization_code(auth, redirect))
  }
})
