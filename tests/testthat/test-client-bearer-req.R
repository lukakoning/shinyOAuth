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
