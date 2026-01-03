test_that("add_req_defaults skips non-httr2 objects", {
  not_req <- list(a = 1)
  expect_identical(shinyOAuth:::add_req_defaults(not_req), not_req)
})

test_that("add_req_defaults applies timeout and user agent options", {
  req <- httr2::request("https://example.com")
  withr::local_options(list(
    shinyOAuth.timeout = 4,
    shinyOAuth.user_agent = "ua-test"
  ))
  req2 <- shinyOAuth:::add_req_defaults(req)
  expect_equal(req2$options$timeout_ms, 4000)
  expect_equal(req2$options$useragent, "ua-test")
})

test_that("add_req_defaults falls back to default timeout when invalid", {
  req <- httr2::request("https://example.com")
  withr::local_options(list(
    shinyOAuth.timeout = "-2"
  ))
  req2 <- shinyOAuth:::add_req_defaults(req)
  expect_equal(req2$options$timeout_ms, 10000)
})

test_that("req_with_retry passes through non-httr2 requests", {
  fake_req <- structure(list(id = "fake"), class = "fake_request")
  called <- FALSE
  testthat::local_mocked_bindings(
    req_perform = function(req) {
      called <<- TRUE
      expect_identical(req, fake_req)
      "ok"
    },
    .package = "httr2"
  )
  expect_identical(shinyOAuth:::req_with_retry(fake_req), "ok")
  expect_true(called)
})

test_that("req_with_retry retries on transient errors then succeeds", {
  req <- httr2::request("https://example.com")
  attempts <- 0
  sleeps <- numeric()
  testthat::local_mocked_bindings(
    req_perform = function(request) {
      attempts <<- attempts + 1
      if (attempts < 2) {
        stop("boom")
      }
      httr2::response(
        url = request$url,
        status = 200,
        headers = list("content-type" = "text/plain"),
        body = charToRaw("ok")
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
  resp <- shinyOAuth:::req_with_retry(req)
  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 200)
  expect_equal(attempts, 2)
  expect_true(all(sleeps >= 0))
})

test_that("req_with_retry honours Retry-After header and returns last response", {
  req <- httr2::request("https://example.org")
  withr::local_options(list(shinyOAuth.retry_max_tries = 2L))
  sleeps <- numeric()
  attempts <- 0
  testthat::local_mocked_bindings(
    req_perform = function(request) {
      attempts <<- attempts + 1
      httr2::response(
        url = request$url,
        status = 503,
        headers = list(
          "content-type" = "text/plain",
          "retry-after" = "2"
        ),
        body = charToRaw("oops")
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
  resp <- shinyOAuth:::req_with_retry(req)
  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 503)
  expect_equal(attempts, 2)
  expect_true(any(abs(sleeps - 2) < 1e-6))
})

test_that("parse_token_response parses json and form encoded bodies", {
  json_resp <- httr2::response(
    url = "https://example.com/token",
    status = 200,
    headers = list("content-type" = "application/json"),
    body = charToRaw('{"access_token":"abc"}')
  )
  form_resp <- httr2::response(
    url = "https://example.com/token",
    status = 200,
    headers = list("content-type" = "application/x-www-form-urlencoded"),
    body = charToRaw("access_token=abc&scope=read")
  )
  expect_equal(shinyOAuth:::parse_token_response(json_resp)$access_token, "abc")
  expect_equal(shinyOAuth:::parse_token_response(form_resp)$scope, "read")
})

test_that("parse_token_response falls back to form parsing", {
  plain_resp <- httr2::response(
    url = "https://example.com/token",
    status = 200,
    headers = list("content-type" = "text/plain"),
    body = charToRaw("token_type=bearer&expires_in=3600")
  )
  parsed <- shinyOAuth:::parse_token_response(plain_resp)
  expect_equal(parsed$token_type, "bearer")
  expect_equal(parsed$expires_in, "3600")
})

test_that("parse_token_response signals parse error for invalid json", {
  bad_resp <- httr2::response(
    url = "https://example.com/token",
    status = 200,
    headers = list("content-type" = "application/json"),
    body = charToRaw("not json")
  )
  expect_error(
    shinyOAuth:::parse_token_response(bad_resp),
    class = "shinyOAuth_parse_error"
  )
})

# Tests using webfakes to verify real httr2 semantics ----------------------------
# Note: webfakes runs the app in a subprocess, so we use shared state
# via environment stored in the app locals.

test_that("req_with_retry returns 400 response immediately (no retry)", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$locals$attempts <- 0
  app$get("/badrequest", function(req, res) {
    app <- req$app
    app$locals$attempts <- app$locals$attempts + 1
    res$set_status(400)
    res$set_type("application/json")
    res$send('{"error":"bad_request"}')
  })
  app$get("/attempts", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(attempts = req$app$locals$attempts),
      auto_unbox = TRUE
    ))
  })

  srv <- webfakes::local_app_process(app)
  url <- paste0(srv$url(), "/badrequest")

  req <- httr2::request(url) |> shinyOAuth:::add_req_defaults()
  resp <- shinyOAuth:::req_with_retry(req)

  # Should return the response, not throw
  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 400)

  # Check attempt count via API

  attempts_resp <- httr2::request(paste0(srv$url(), "/attempts")) |>
    httr2::req_perform()
  attempts <- jsonlite::fromJSON(httr2::resp_body_string(
    attempts_resp
  ))$attempts
  # Should NOT have retried a 400 (not in retry_status)
  expect_equal(attempts, 1)
})

test_that("req_with_retry returns 401 response immediately (no retry)", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$locals$attempts <- 0
  app$get("/unauthorized", function(req, res) {
    req$app$locals$attempts <- req$app$locals$attempts + 1
    res$set_status(401)
    res$set_type("text/plain")
    res$send("Unauthorized")
  })
  app$get("/attempts", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(attempts = req$app$locals$attempts),
      auto_unbox = TRUE
    ))
  })

  srv <- webfakes::local_app_process(app)
  url <- paste0(srv$url(), "/unauthorized")

  req <- httr2::request(url) |> shinyOAuth:::add_req_defaults()
  resp <- shinyOAuth:::req_with_retry(req)

  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 401)

  attempts_resp <- httr2::request(paste0(srv$url(), "/attempts")) |>
    httr2::req_perform()
  attempts <- jsonlite::fromJSON(httr2::resp_body_string(
    attempts_resp
  ))$attempts
  expect_equal(attempts, 1)
})

test_that("req_with_retry retries 503 and returns last response", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$locals$attempts <- 0
  app$get("/unavailable", function(req, res) {
    req$app$locals$attempts <- req$app$locals$attempts + 1
    res$set_status(503)
    res$set_type("text/plain")
    res$send("Service Unavailable")
  })
  app$get("/attempts", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(attempts = req$app$locals$attempts),
      auto_unbox = TRUE
    ))
  })

  srv <- webfakes::local_app_process(app)
  url <- paste0(srv$url(), "/unavailable")

  withr::local_options(list(
    shinyOAuth.retry_max_tries = 2L,
    shinyOAuth.retry_backoff_base = 0.01,
    shinyOAuth.retry_backoff_cap = 0.02
  ))

  req <- httr2::request(url) |> shinyOAuth:::add_req_defaults()
  resp <- shinyOAuth:::req_with_retry(req)

  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 503)

  attempts_resp <- httr2::request(paste0(srv$url(), "/attempts")) |>
    httr2::req_perform()
  attempts <- jsonlite::fromJSON(httr2::resp_body_string(
    attempts_resp
  ))$attempts
  # Should have retried (503 is in retry_status by default)
  expect_equal(attempts, 2)
})

test_that("req_with_retry succeeds on retry after transient 500", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$locals$attempts <- 0
  app$get("/flaky", function(req, res) {
    req$app$locals$attempts <- req$app$locals$attempts + 1
    if (req$app$locals$attempts < 2) {
      res$set_status(500)
      res$set_type("text/plain")
      res$send("Internal Server Error")
    } else {
      res$set_status(200)
      res$set_type("application/json")
      res$send('{"status":"ok"}')
    }
  })
  app$get("/attempts", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(attempts = req$app$locals$attempts),
      auto_unbox = TRUE
    ))
  })

  srv <- webfakes::local_app_process(app)
  url <- paste0(srv$url(), "/flaky")

  withr::local_options(list(
    shinyOAuth.retry_max_tries = 3L,
    shinyOAuth.retry_backoff_base = 0.01,
    shinyOAuth.retry_backoff_cap = 0.02
  ))

  req <- httr2::request(url) |> shinyOAuth:::add_req_defaults()
  resp <- shinyOAuth:::req_with_retry(req)

  expect_s3_class(resp, "httr2_response")
  expect_equal(httr2::resp_status(resp), 200)

  attempts_resp <- httr2::request(paste0(srv$url(), "/attempts")) |>
    httr2::req_perform()
  attempts <- jsonlite::fromJSON(httr2::resp_body_string(
    attempts_resp
  ))$attempts
  expect_equal(attempts, 2)
})
