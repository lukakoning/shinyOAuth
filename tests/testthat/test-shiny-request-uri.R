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
    stop("Request Objects must not use session data-object registration")
  }

  list(session = session, captured = captured, client = make_test_client())
}


# 1. shiny request_uri publishing ---------------------------------------------

test_that("app handlers serve independent handles once without rendering UI", {
  fixture <- make_request_uri_test_session()
  client <- fixture$client
  publish <- function(...) {
    publish_shiny_request_object(
      fixture$session,
      "header.payload.signature",
      request_handle_id = "same-state",
      oauth_client = client,
      ...
    )
  }
  request <- function(url, method = "GET") {
    list(
      REQUEST_METHOD = method,
      PATH_INFO = "/",
      QUERY_STRING = oauth_callback_uri_query(url)
    )
  }
  ui <- oauth_ui(function(...) stop("must not render UI"), "auth", client)
  handler <- shiny::shinyApp(ui, function(...) {})$httpHandler
  url <- publish()
  expect_false(identical(url, publish()))
  for (method in c("POST", "OPTIONS")) {
    denied <- handler(request(url, method))
    expect_identical(denied$status, 405L)
    expect_identical(denied$headers$Allow, "GET, HEAD")
  }
  head <- handler(request(url, "HEAD"))
  expect_identical(head$status, 200L)
  expect_identical(head$content, "")
  first <- handler(request(url))
  expect_identical(first$status, 200L)
  expect_identical(first$content, "header.payload.signature")
  expect_identical(first$content_type, "application/oauth-authz-req+jwt")
  expect_identical(first$headers[["Cache-Control"]], "no-store")
  expect_identical(first$headers[["Referrer-Policy"]], "no-referrer")
  expect_identical(handler(request(url))$status, 410L)
  expect_identical(handler(request(url, "HEAD"))$content, "")

  expired <- publish(expires_at = Sys.time() - 1)
  expect_identical(handler(request(expired))$status, 410L)
  future <- publish(expires_at = Sys.time() + 600)
  handle <- oauth_module_query_raw_values(
    request(future)$QUERY_STRING,
    shiny_request_object_param
  )
  data <- client@state_store$get(shiny_request_object_key(client, handle))
  expect_lte(
    as.numeric(difftime(data$expires_at, Sys.time(), units = "secs")),
    120
  )
  bad <- request(future)
  bad$QUERY_STRING <- paste(bad$QUERY_STRING, bad$QUERY_STRING, sep = "&")
  expect_identical(handler(bad)$status, 400L)
  other <- client
  other@client_id <- "other-client"
  expect_identical(
    shiny_request_object_http_handler(request(future), other)$status,
    410L
  )
  expect_identical(handler(request(future))$status, 200L)
  expect_error(
    client@redirect_uri <- "https://example.com/?shinyOAuth_request_object=x",
    "callback-reserved"
  )
})

test_that("shared Request Object stores require and use atomic take", {
  fixture <- make_request_uri_test_session()
  memory <- cachem::cache_mem(max_age = 600)
  takes <- 0L
  store <- list(
    get = memory$get,
    set = memory$set,
    remove = memory$remove,
    info = memory$info,
    take = function(key, missing = NULL) {
      takes <<- takes + 1L
      value <- memory$get(key, missing = missing)
      memory$remove(key)
      value
    }
  )
  client <- fixture$client
  client@state_store <- store
  url <- publish_shiny_request_object(
    fixture$session,
    "fixture",
    oauth_client = client
  )
  req <- list(
    REQUEST_METHOD = "HEAD",
    QUERY_STRING = oauth_callback_uri_query(url)
  )
  expect_identical(shiny_request_object_http_handler(req, client)$status, 200L)
  expect_identical(takes, 0L)
  req$REQUEST_METHOD <- "GET"
  expect_identical(
    shiny_request_object_http_handler(req, client)$content,
    "fixture"
  )
  expect_identical(shiny_request_object_http_handler(req, client)$status, 410L)
  expect_identical(takes, 2L)
  store$take <- NULL
  client@state_store <- store
  withr::local_options(shinyOAuth.allow_non_atomic_state_store = TRUE)
  expect_error(
    publish_shiny_request_object(
      fixture$session,
      "fixture",
      oauth_client = client
    ),
    "requires atomic"
  )
})

test_that("form-post UI also serves Request Objects", {
  fixture <- make_request_uri_test_session()
  client <- fixture$client
  client@response_mode <- "form_post"
  ui <- oauth_form_post_ui(shiny::fluidPage(), "auth", client)
  url <- publish_shiny_request_object(
    fixture$session,
    "fixture",
    oauth_client = client
  )
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/",
    QUERY_STRING = oauth_callback_uri_query(url)
  )
  expect_identical(ui(req)$content, "fixture")
})

test_that("publish_shiny_request_object returns an absolute same-origin URL", {
  fixture <- make_request_uri_test_session()

  url <- shinyOAuth:::publish_shiny_request_object(
    session = fixture$session,
    oauth_client = fixture$client,
    request_object = "header.payload.signature",
    request_handle_id = "deadbeef",
    expires_at = Sys.time() + 60
  )

  expect_match(
    url,
    "^https://app[.]example[.]com/app/\\?shinyOAuth_request_object=[A-Za-z0-9_-]{43}$"
  )
  expect_false(grepl("session-token|deadbeef|session/", url))
  handle <- httr2::url_parse(url)$query[[shiny_request_object_param]]
  keys <- fixture$client@state_store$keys()
  expect_identical(keys, shiny_request_object_key(fixture$client, handle))
  expect_false(grepl(handle, keys, fixed = TRUE))
  stored <- fixture$client@state_store$get(keys)
  expect_named(stored, c("request_object", "expires_at"))
  expect_identical(stored$request_object, "header.payload.signature")
})

test_that("publish_shiny_request_object uses an explicit public base URL", {
  fixture <- make_request_uri_test_session()

  url <- shinyOAuth:::publish_shiny_request_object(
    session = fixture$session,
    oauth_client = fixture$client,
    request_object = "header.payload.signature",
    request_handle_id = "deadbeef",
    expires_at = Sys.time() + 60,
    base_url = "https://public.example.net/proxy/app/"
  )

  expect_match(
    url,
    "^https://public[.]example[.]net/proxy/app/\\?shinyOAuth_request_object="
  )
})

test_that("publish_shiny_request_object rejects non-HTTPS request_uri URLs", {
  fixture <- make_request_uri_test_session(
    protocol = "http:",
    hostname = "localhost"
  )

  expect_error(
    shinyOAuth:::publish_shiny_request_object(
      session = fixture$session,
      oauth_client = fixture$client,
      request_object = "header.payload.signature",
      request_handle_id = "deadbeef",
      expires_at = Sys.time() + 60
    ),
    class = "shinyOAuth_config_error",
    regexp = "must use HTTPS"
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

test_that("serve_shiny_request_object ignores partial matches in request method keys", {
  fresh <- shinyOAuth:::serve_shiny_request_object(
    data = list(
      request_object = "header.payload.signature",
      expires_at = Sys.time() + 60
    ),
    req = list(REQUEST_METHOD_OVERRIDE = "POST")
  )

  expect_identical(fresh$status, 200L)
  expect_identical(fresh$body, "header.payload.signature")
})
