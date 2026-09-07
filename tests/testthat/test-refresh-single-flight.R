test_that("concurrent exported refreshes share one dispatch and rotated result", {
  skip_if_not_installed("promises")
  skip_if_not_installed("later")
  client <- make_test_client(use_nonce = FALSE)
  token <- OAuthToken(access_token = "old", refresh_token = "refresh-original")
  finish <- NULL
  calls <- 0L
  local_mocked_bindings(dispatch_token_async = function(...) {
    calls <<- calls + 1L
    promises::promise(function(resolve, reject) finish <<- resolve)
  }, .package = "shinyOAuth")
  first <- refresh_token(client, token, async = TRUE)
  second <- refresh_token(client, token, async = TRUE)
  expect_identical(first, second)
  expect_equal(calls, 1L)
  expect_error(refresh_token(client, token), "already in progress")
  expect_error(refresh_token(client, token, async = TRUE, introspect = TRUE),
               "different token or validation settings")
  values <- list()
  promises::then(first, function(value) values[[1L]] <<- value)
  promises::then(second, function(value) values[[2L]] <<- value)
  rotated <- OAuthToken(access_token = "new", refresh_token = "refresh-rotated")
  finish(rotated)
  deadline <- Sys.time() + 3
  while (length(values) < 2L && Sys.time() < deadline) later::run_now(0.01)
  expect_length(values, 2L)
  expect_identical(values[[1L]], rotated)
  expect_identical(values[[2L]], rotated)
  expect_identical(token@refresh_token, "refresh-original")
  expect_length(ls(shinyOAuth:::refresh_flights$active), 0L)
})

test_that("failed refreshes release locks and separate clients do not collide", {
  skip_if_not_installed("promises")
  skip_if_not_installed("later")
  client <- make_test_client(use_nonce = FALSE)
  token <- OAuthToken(access_token = "old", refresh_token = "refresh-original")
  rejectors <- list()
  local_mocked_bindings(dispatch_token_async = function(...) {
    promises::promise(function(resolve, reject) {
      rejectors[[length(rejectors) + 1L]] <<- reject
    })
  }, .package = "shinyOAuth")
  other <- client
  other@client_id <- "another-client"
  errors <- list()
  for (c in list(client, other)) {
    promises::catch(refresh_token(c, token, async = TRUE), function(error) {
      errors[[length(errors) + 1L]] <<- conditionMessage(error)
      NULL
    })
  }
  expect_length(rejectors, 2L)
  for (reject in rejectors) reject(simpleError("refresh failed"))
  deadline <- Sys.time() + 3
  while (length(errors) < 2L && Sys.time() < deadline) later::run_now(0.01)
  expect_length(errors, 2L)
  expect_length(ls(shinyOAuth:::refresh_flights$active), 0L)
  local_mocked_bindings(refresh_token_impl = function(...) stop("dispatch failed"),
                        .package = "shinyOAuth")
  expect_error(refresh_token(client, token), "dispatch failed")
  expect_length(ls(shinyOAuth:::refresh_flights$active), 0L)
})
