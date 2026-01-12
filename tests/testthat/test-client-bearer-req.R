test_that("client_bearer_req builds request metadata without network", {
  req <- client_bearer_req(
    token = "tok",
    url = "https://example.com/base",
    method = "post",
    headers = list(`X-Test` = "1"),
    query = list(a = 1, b = NULL)
  )

  expect_s3_class(req, "httr2_request")
  expect_equal(req$method, "POST")
  expect_equal(req$url, "https://example.com/base?a=1")

  dry <- httr2::req_dry_run(req, redact_headers = FALSE)
  expect_equal(dry$headers$authorization, "Bearer tok")
  expect_equal(dry$headers$`x-test`, "1")
})

test_that("client_bearer_req builds authorized request from string", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$get("/v1/items", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(
        method = req$method,
        path = req$path,
        auth = req$get_header("authorization"),
        ua = req$get_header("user-agent")
      ),
      auto_unbox = TRUE
    ))
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  req <- client_bearer_req(
    "tok",
    paste0(base, "/v1/items"),
    query = list(limit = 5)
  )
  expect_s3_class(req, "httr2_request")

  resp <- httr2::req_perform(req)
  expect_false(httr2::resp_is_error(resp))
  j <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  expect_identical(tolower(j$method), "get")
  expect_identical(j$path, "/v1/items")
  expect_true(grepl("^Bearer ", j$auth, ignore.case = TRUE))
  expect_true(nzchar(j$ua))
})

test_that("client_bearer_req accepts OAuthToken and sets headers/query/method", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$post("/resource", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(
        method = req$method,
        path = req$path,
        auth = req$get_header("authorization"),
        xt = req$get_header("x-test")
      ),
      auto_unbox = TRUE
    ))
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  tok <- OAuthToken(access_token = "abc", userinfo = list())
  req <- client_bearer_req(
    tok,
    paste0(base, "/resource"),
    method = "post",
    headers = list(`X-Test` = "1"),
    query = list(a = 1, b = NA)
  )

  expect_s3_class(req, "httr2_request")

  resp <- httr2::req_perform(req)
  expect_false(httr2::resp_is_error(resp))
  j <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  expect_identical(tolower(j$method), "post")
  expect_identical(j$path, "/resource")
  expect_true(grepl("^Bearer ", j$auth, ignore.case = TRUE))
  expect_identical(j$xt, "1")
})

test_that("custom Authorization header is ignored and warned", {
  expect_warning(
    req <- client_bearer_req(
      token = "tok",
      url = "https://example.com/base",
      headers = list(Authorization = "Basic xyz", `X-Other` = "ok")
    ),
    regexp = "Ignoring custom 'Authorization' header",
    fixed = TRUE
  )

  # Use dry run to force header computation without network
  dry <- httr2::req_dry_run(req, redact_headers = FALSE)

  expect_equal(dry$headers$authorization, "Bearer tok")
  expect_equal(dry$headers$`x-other`, "ok")
})

test_that("client_bearer_req disables redirects by default", {
  req <- client_bearer_req(
    token = "tok",
    url = "https://example.com/resource"
  )
  # Check that followlocation is set to FALSE via req_no_redirect()
  expect_false(req$options$followlocation)
})

test_that("client_bearer_req allows redirects when follow_redirect = TRUE", {
  req <- client_bearer_req(
    token = "tok",
    url = "https://example.com/resource",
    follow_redirect = TRUE
  )
  # When follow_redirect is TRUE, followlocation should not be set to FALSE
  expect_null(req$options$followlocation)
})

test_that("client_bearer_req does not follow redirects by default (token leak prevention)", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  # Endpoint that issues a redirect

  app$get("/redirect-me", function(req, res) {
    res$set_status(302)
    res$set_header("Location", "/final")
    res$send("")
  })
  # Final endpoint that would receive the token if redirect was followed
  app$get("/final", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(reached = TRUE, auth = req$get_header("authorization")),
      auto_unbox = TRUE
    ))
  })
  srv <- webfakes::local_app_process(app)

  req <- client_bearer_req(
    token = "secret-token",
    url = paste0(srv$url(), "/redirect-me")
  )

  # With redirects disabled, we should get the 302 response directly
  resp <- httr2::req_perform(req)
  expect_equal(httr2::resp_status(resp), 302L)
  expect_equal(httr2::resp_header(resp, "location"), "/final")
})

test_that("client_bearer_req follows redirects when follow_redirect = TRUE", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$get("/redirect-me", function(req, res) {
    res$set_status(302)
    res$set_header("Location", "/final")
    res$send("")
  })
  app$get("/final", function(req, res) {
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(reached = TRUE, auth = req$get_header("authorization")),
      auto_unbox = TRUE
    ))
  })
  srv <- webfakes::local_app_process(app)

  req <- client_bearer_req(
    token = "secret-token",
    url = paste0(srv$url(), "/redirect-me"),
    follow_redirect = TRUE
  )

  # With redirects enabled, we should reach the final endpoint
  resp <- httr2::req_perform(req)
  expect_equal(httr2::resp_status(resp), 200L)
  j <- httr2::resp_body_json(resp)
  expect_true(j$reached)
})
