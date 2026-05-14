make_request_uri_test_session <- function(
  protocol = "https:",
  hostname = "app.example.com",
  port = "",
  pathname = "/app/"
) {
  session <- new.env(parent = emptyenv())
  captured <- new.env(parent = emptyenv())

  session$token <- "session-token"
  session$clientData <- list(
    url_protocol = protocol,
    url_hostname = hostname,
    url_port = port,
    url_pathname = pathname
  )
  session$registerDataObj <- function(name, data, filterFunc) {
    captured$name <- name
    captured$data <- data
    captured$filterFunc <- filterFunc
    sprintf(
      "session/%s/dataobj/%s?w=worker-1&nonce=testnonce",
      utils::URLencode(session$token, reserved = TRUE),
      utils::URLencode(name, reserved = TRUE)
    )
  }

  list(session = session, captured = captured)
}


# 1. shiny request_uri publishing ---------------------------------------------

test_that("publish_shiny_request_object returns an absolute same-origin URL", {
  fixture <- make_request_uri_test_session()

  url <- shinyOAuth:::publish_shiny_request_object(
    session = fixture$session,
    request_object = "header.payload.signature",
    request_handle_id = "deadbeef",
    expires_at = Sys.time() + 60
  )

  expect_identical(
    url,
    paste0(
      "https://app.example.com/app/session/session-token/dataobj/",
      "oauth-request-deadbeef?w=worker-1&nonce=testnonce"
    )
  )
  expect_identical(fixture$captured$name, "oauth-request-deadbeef")
})

test_that("publish_shiny_request_object uses an explicit public base URL", {
  fixture <- make_request_uri_test_session()

  url <- shinyOAuth:::publish_shiny_request_object(
    session = fixture$session,
    request_object = "header.payload.signature",
    request_handle_id = "deadbeef",
    expires_at = Sys.time() + 60,
    base_url = "https://public.example.net/proxy/app/"
  )

  expect_identical(
    url,
    paste0(
      "https://public.example.net/proxy/app/session/session-token/dataobj/",
      "oauth-request-deadbeef?w=worker-1&nonce=testnonce"
    )
  )
})

test_that("request_uri base URL overrides reject query strings and fragments", {
  expect_error(
    shinyOAuth:::normalize_request_uri_base_url(
      "https://public.example.net/app?bad=1",
      arg = "request_uri_base_url"
    ),
    regexp = "must not include a query string or fragment"
  )

  expect_error(
    shinyOAuth:::normalize_request_uri_base_url(
      "https://public.example.net/app#frag",
      arg = "request_uri_base_url"
    ),
    regexp = "must not include a query string or fragment"
  )
})

test_that("serve_shiny_request_object serves JWT bodies and expiry responses", {
  usage_state <- new.env(parent = emptyenv())
  usage_state$consumed <- FALSE

  fresh <- shinyOAuth:::serve_shiny_request_object(
    data = list(
      request_object = "header.payload.signature",
      expires_at = Sys.time() + 60,
      usage_state = usage_state
    ),
    req = list(REQUEST_METHOD = "GET")
  )

  expect_identical(fresh$status, 200L)
  expect_identical(
    fresh$headers[["Content-Type"]],
    "application/oauth-authz-req+jwt"
  )
  expect_identical(fresh$body, "header.payload.signature")

  replay <- shinyOAuth:::serve_shiny_request_object(
    data = list(
      request_object = "header.payload.signature",
      expires_at = Sys.time() + 60,
      usage_state = usage_state
    ),
    req = list(REQUEST_METHOD = "GET")
  )

  expect_identical(replay$status, 410L)
  expect_match(replay$body, "already used", ignore.case = TRUE)

  expired <- shinyOAuth:::serve_shiny_request_object(
    data = list(
      request_object = "header.payload.signature",
      expires_at = Sys.time() - 60
    ),
    req = list(REQUEST_METHOD = "GET")
  )

  expect_identical(expired$status, 410L)
  expect_match(expired$body, "expired", ignore.case = TRUE)

  method_not_allowed <- shinyOAuth:::serve_shiny_request_object(
    data = list(
      request_object = "header.payload.signature",
      expires_at = Sys.time() + 60
    ),
    req = list(REQUEST_METHOD = "POST")
  )

  expect_identical(method_not_allowed$status, 405L)
  expect_identical(method_not_allowed$headers[["Allow"]], "GET, HEAD")
})
