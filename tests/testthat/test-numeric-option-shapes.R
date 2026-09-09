test_that("malformed retry options use defaults without base R errors", {
  attempts <- 0L
  local_mocked_bindings(
    req_perform_bounded = function(req) {
      attempts <<- attempts + 1L
      httr2::response(status = if (attempts < 3L) 503L else 200L)
    },
    retry_backoff_delay = function(attempt, base, cap) {
      expect_equal(base, 0.5)
      expect_equal(cap, 5)
      0
    },
    .package = "shinyOAuth"
  )
  invalid <- list(numeric(), c(1, 2), list(1), new.env(), TRUE, NA, Inf, 1i, "bad")
  for (value in invalid) {
    withr::local_options(stats::setNames(rep(list(value), 4L), c(
      "shinyOAuth.retry_max_tries", "shinyOAuth.retry_backoff_base",
      "shinyOAuth.retry_backoff_cap", "shinyOAuth.retry_after_cap"
    )))
    attempts <- 0L
    expect_equal(httr2::resp_status(req_with_retry(httr2::request("https://example.com"))), 200L)
    expect_identical(attempts, 3L)
  }
})

test_that("malformed assertion TTL options fall back to two minutes", {
  client <- make_test_client()
  client@client_secret <- strrep("s", 32)
  client@provider@token_auth_style <- "client_secret_jwt"
  for (value in list(numeric(), c(1, 2), list(1), new.env(), TRUE, NA, Inf, 1i, "bad")) {
    withr::local_options(shinyOAuth.client_assertion_ttl = value)
    jwt <- build_client_assertion(client, client@provider@token_url)
    claims <- parse_jwt_payload(jwt)
    expect_equal(claims$exp - claims$iat, 120)
  }
})
