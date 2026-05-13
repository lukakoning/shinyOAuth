make_resource_req_dpop_client <- function() {
  oauth_client(
    provider = make_test_provider(use_pkce = TRUE, use_nonce = FALSE),
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    dpop_private_key = openssl::rsa_keygen()
  )
}

test_that("resource_req builds request metadata without network", {
  req <- resource_req(
    token = "tok",
    url = "https://example.com/base",
    method = "post",
    headers = list(`X-Test` = "1"),
    query = list(a = 1, b = NULL)
  )

  expect_s3_class(req, "httr2_request")
  expect_equal(req$method, "POST")
  expect_equal(req$url, "https://example.com/base?a=1")

  dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
  expect_equal(dry$headers$authorization, "Bearer tok")
  expect_equal(dry$headers$`x-test`, "1")
})

test_that("resource_req builds authorized request from string", {
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

  req <- resource_req(
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

test_that("resource_req accepts OAuthToken and sets headers/query/method", {
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
  req <- resource_req(
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

test_that("client_bearer_req is a deprecated alias for resource_req", {
  withr::local_options(lifecycle_verbosity = "warning")

  expect_warning(
    req <- client_bearer_req(
      token = "tok",
      url = "https://example.com/base",
      query = list(a = 1)
    ),
    class = "lifecycle_warning_deprecated"
  )

  expect_s3_class(req, "httr2_request")
  expect_equal(req$url, "https://example.com/base?a=1")
})

test_that("custom Authorization header is ignored and warned", {
  expect_warning(
    req <- resource_req(
      token = "tok",
      url = "https://example.com/base",
      headers = list(Authorization = "Basic xyz", `X-Other` = "ok")
    ),
    regexp = "Ignoring custom 'Authorization' header",
    fixed = TRUE
  )

  dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)

  expect_equal(dry$headers$authorization, "Bearer tok")
  expect_equal(dry$headers$`x-other`, "ok")
})

test_that("resource_req rejects non-scalar token_type overrides", {
  expect_error(
    resource_req(
      token = "tok",
      url = "https://example.com/base",
      token_type = c("DPoP", "Bearer")
    ),
    class = "shinyOAuth_input_error",
    regexp = "token_type"
  )
})

test_that("resource_req disables redirects by default", {
  req <- resource_req(
    token = "tok",
    url = "https://example.com/resource"
  )
  # Check that followlocation is set to FALSE via req_no_redirect()
  expect_false(req$options$followlocation)
})

test_that("resource_req allows redirects when follow_redirect = TRUE", {
  req <- resource_req(
    token = "tok",
    url = "https://example.com/resource",
    follow_redirect = TRUE
  )
  # When follow_redirect is TRUE, followlocation should not be set to FALSE
  expect_null(req$options$followlocation)
})

test_that("resource_req does not follow redirects by default (token leak prevention)", {
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

  req <- resource_req(
    token = "secret-token",
    url = paste0(srv$url(), "/redirect-me")
  )

  # With redirects disabled, we should get the 302 response directly
  resp <- httr2::req_perform(req)
  expect_equal(httr2::resp_status(resp), 302L)
  expect_equal(httr2::resp_header(resp, "location"), "/final")
})

test_that("resource_req follows redirects when follow_redirect = TRUE", {
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

  req <- resource_req(
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

test_that("perform_resource_req infers idempotency from method", {
  run_case <- function(method = "GET", idempotent = NULL) {
    seen <- new.env(parent = emptyenv())
    seen$idempotent <- NULL

    testthat::local_mocked_bindings(
      req_with_retry = function(req, idempotent = TRUE) {
        seen$idempotent <- idempotent
        httr2::response(
          url = as.character(req$url),
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw("{}")
        )
      },
      req_with_dpop_retry = function(...) {
        testthat::fail("DPoP retry helper should not be called for Bearer")
      },
      .package = "shinyOAuth"
    )

    resp <- perform_resource_req(
      token = "tok",
      url = "https://example.com/base",
      method = method,
      idempotent = idempotent
    )

    list(resp = resp, idempotent = seen$idempotent)
  }

  expect_s3_class(run_case()$resp, "httr2_response")
  expect_identical(run_case()$idempotent, TRUE)
  expect_identical(run_case(method = "POST")$idempotent, FALSE)
  expect_identical(run_case(method = "DELETE")$idempotent, TRUE)
  expect_identical(
    run_case(method = "POST", idempotent = TRUE)$idempotent,
    TRUE
  )

  expect_error(
    perform_resource_req(
      token = "tok",
      url = "https://example.com/base",
      idempotent = NA
    ),
    class = "shinyOAuth_input_error",
    regexp = "idempotent"
  )
})

test_that("perform_client_bearer_req is a deprecated alias for perform_resource_req", {
  withr::local_options(lifecycle_verbosity = "warning")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, idempotent = TRUE) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw("{}")
      )
    },
    req_with_dpop_retry = function(...) {
      testthat::fail("DPoP retry helper should not be called for Bearer")
    },
    .package = "shinyOAuth"
  )

  expect_warning(
    resp <- perform_client_bearer_req(
      token = "tok",
      url = "https://example.com/base"
    ),
    class = "lifecycle_warning_deprecated"
  )

  expect_s3_class(resp, "httr2_response")
})

test_that("perform_resource_req uses DPoP retry helper for DPoP tokens", {
  cli <- make_resource_req_dpop_client()
  seen <- new.env(parent = emptyenv())
  seen$client <- NULL
  seen$access_token <- NULL
  seen$idempotent <- NULL
  seen$nonce <- NULL
  seen$authorization <- NULL

  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(
      req,
      client,
      access_token = NULL,
      idempotent = TRUE,
      nonce = NULL
    ) {
      dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
      seen$client <- client
      seen$access_token <- access_token
      seen$idempotent <- idempotent
      seen$nonce <- nonce
      seen$authorization <- dry$headers$authorization
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw("{}")
      )
    },
    req_with_retry = function(...) {
      testthat::fail("Bearer retry helper should not be called for DPoP")
    },
    .package = "shinyOAuth"
  )

  resp <- perform_resource_req(
    token = "at-1",
    url = "https://resource.example.com/api",
    oauth_client = cli,
    token_type = "DPoP",
    dpop_nonce = "resource-nonce-1"
  )

  expect_s3_class(resp, "httr2_response")
  expect_true(S7::S7_inherits(seen$client, OAuthClient))
  expect_identical(seen$access_token, "at-1")
  expect_identical(seen$idempotent, TRUE)
  expect_identical(seen$nonce, "resource-nonce-1")
  expect_identical(seen$authorization, "DPoP at-1")
})
