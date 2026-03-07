# Tests verifying that token exchange and refresh do NOT retry, preventing
# single-use credential replay (authorization codes, rotatable refresh tokens).

# ---- req_with_retry(idempotent = FALSE) unit tests ----

test_that("req_with_retry(idempotent = FALSE) does not retry on transport error", {
  req <- httr2::request("https://example.com/token")
  attempts <- 0
  testthat::local_mocked_bindings(
    req_perform = function(request) {
      attempts <<- attempts + 1
      stop("connection reset")
    },
    .package = "httr2"
  )
  expect_error(
    shinyOAuth:::req_with_retry(req, idempotent = FALSE),
    class = "shinyOAuth_transport_error"
  )
  # Must have attempted exactly once — no retry

  expect_equal(attempts, 1)
})

test_that("req_with_retry(idempotent = FALSE) returns 500 without retrying", {
  req <- httr2::request("https://example.com/token")
  attempts <- 0
  testthat::local_mocked_bindings(
    req_perform = function(request) {
      attempts <<- attempts + 1
      httr2::response(
        url = request$url,
        status = 500,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"error":"server_error"}')
      )
    },
    .package = "httr2"
  )
  resp <- shinyOAuth:::req_with_retry(req, idempotent = FALSE)
  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 500)
  # 500 is in the default retry_status but must NOT be retried
  expect_equal(attempts, 1)
})

test_that("req_with_retry(idempotent = FALSE) returns success on first attempt", {
  req <- httr2::request("https://example.com/token")
  attempts <- 0
  testthat::local_mocked_bindings(
    req_perform = function(request) {
      attempts <<- attempts + 1
      httr2::response(
        url = request$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"access_token":"tok"}')
      )
    },
    .package = "httr2"
  )
  resp <- shinyOAuth:::req_with_retry(req, idempotent = FALSE)
  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 200)
  expect_equal(attempts, 1)
})

test_that("req_with_retry(idempotent = TRUE) still retries (default behavior)", {
  req <- httr2::request("https://example.com/userinfo")
  attempts <- 0
  sleeps <- numeric()
  testthat::local_mocked_bindings(
    req_perform = function(request) {
      attempts <<- attempts + 1
      if (attempts < 2) {
        stop("timeout")
      }
      httr2::response(
        url = request$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"sub":"user1"}')
      )
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    Sys.sleep = function(time) {
      sleeps <<- c(sleeps, time)
      invisible(NULL)
    },
    .package = "base"
  )
  resp <- shinyOAuth:::req_with_retry(req, idempotent = TRUE)
  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 200)
  expect_equal(attempts, 2) # retried once
})

# ---- Regression: token exchange does not retry ----

test_that("swap_code_for_token_set does not retry: server committed, response lost", {
  client <- make_test_client(use_pkce = TRUE)
  attempts <- 0

  testthat::with_mocked_bindings(
    req_with_retry = function(req, idempotent = TRUE) {
      attempts <<- attempts + 1
      # Verify the call site passes idempotent = FALSE
      expect_false(idempotent)
      httr2::response(
        url = "https://example.com/token",
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "at_123",
            token_type = "bearer",
            expires_in = 3600
          ),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth",
    {
      result <- shinyOAuth:::swap_code_for_token_set(
        client = client,
        code = "auth_code_abc",
        code_verifier = "test_verifier_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      )
    }
  )
  expect_equal(attempts, 1)
  expect_equal(result$access_token, "at_123")
})

# ---- Regression: refresh_token does not retry ----

test_that("refresh_token does not retry: server rotated token, response lost", {
  client <- make_test_client(use_pkce = TRUE)
  token <- shinyOAuth::OAuthToken(
    access_token = "old_at",
    refresh_token = "old_rt",
    expires_at = as.numeric(Sys.time()) + 3600
  )
  attempts <- 0

  testthat::with_mocked_bindings(
    req_with_retry = function(req, idempotent = TRUE) {
      attempts <<- attempts + 1
      # Verify the call site passes idempotent = FALSE
      expect_false(idempotent)
      httr2::response(
        url = "https://example.com/token",
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "new_at",
            token_type = "bearer",
            expires_in = 3600,
            refresh_token = "new_rt"
          ),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth",
    {
      result <- shinyOAuth::refresh_token(
        oauth_client = client,
        token = token
      )
    }
  )
  expect_equal(attempts, 1)
  expect_equal(result@access_token, "new_at")
  expect_equal(result@refresh_token, "new_rt")
})

# ---- Webfakes integration: token exchange single-attempt ----

test_that("token exchange hits server exactly once (webfakes)", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()

  app <- webfakes::new_app()
  app$locals$attempts <- 0
  # First request succeeds but simulates a slow 500 to show no retry
  app$post("/token", function(req, res) {
    req$app$locals$attempts <- req$app$locals$attempts + 1
    # Always return 500 — a retrying client would hit this twice
    res$set_status(500)
    res$set_type("application/json")
    res$send('{"error":"server_error"}')
  })
  app$get("/attempts", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(attempts = req$app$locals$attempts),
      auto_unbox = TRUE
    ))
  })

  srv <- webfakes::local_app_process(app)
  token_url <- paste0(srv$url(), "/token")
  attempts_url <- paste0(srv$url(), "/attempts")

  withr::local_options(list(
    shinyOAuth.retry_max_tries = 3L,
    shinyOAuth.retry_backoff_base = 0.01,
    shinyOAuth.retry_backoff_cap = 0.02
  ))

  req <- httr2::request(token_url) |>
    shinyOAuth:::add_req_defaults() |>
    httr2::req_body_form(
      grant_type = "authorization_code",
      code = "test_code"
    )

  resp <- shinyOAuth:::req_with_retry(req, idempotent = FALSE)
  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 500)

  # Verify only one attempt was made, even though 500 is normally retried
  att_resp <- httr2::request(attempts_url) |> httr2::req_perform()
  att <- jsonlite::fromJSON(httr2::resp_body_string(att_resp))$attempts
  expect_equal(att, 1)
})

test_that("idempotent request retries 500 as before (webfakes control)", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()

  app <- webfakes::new_app()
  app$locals$attempts <- 0
  app$get("/flaky", function(req, res) {
    req$app$locals$attempts <- req$app$locals$attempts + 1
    res$set_status(500)
    res$set_type("text/plain")
    res$send("error")
  })
  app$get("/attempts", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(attempts = req$app$locals$attempts),
      auto_unbox = TRUE
    ))
  })

  srv <- webfakes::local_app_process(app)

  withr::local_options(list(
    shinyOAuth.retry_max_tries = 2L,
    shinyOAuth.retry_backoff_base = 0.01,
    shinyOAuth.retry_backoff_cap = 0.02
  ))

  req <- httr2::request(paste0(srv$url(), "/flaky")) |>
    shinyOAuth:::add_req_defaults()

  # idempotent = TRUE (default) — should retry

  resp <- shinyOAuth:::req_with_retry(req, idempotent = TRUE)
  expect_equal(httr2::resp_status(resp), 500)

  att_resp <- httr2::request(paste0(srv$url(), "/attempts")) |>
    httr2::req_perform()
  att <- jsonlite::fromJSON(httr2::resp_body_string(att_resp))$attempts
  expect_equal(att, 2) # Retried once
})
