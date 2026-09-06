test_that("callback routes enforce the registered query multiset", {
  registered <- "https://app.example/callback?tenant=one&tag=a&tag=b&empty=&label=hello+world"
  valid <- "label=hello%20world&tag=b&empty&tenant=one&tag=a"
  for (response in c(
    "code=ok&state=s",
    "error=access_denied&state=s",
    "response=a.b.c",
    "shinyOAuth_form_post=handle&shinyOAuth_form_post_id=auth"
  )) {
    expect_true(oauth_callback_route_matches(
      paste0("https://app.example/callback?", valid, "&", response),
      registered
    ))
  }
  for (query in c(
    "",
    "tenant=two&tag=a&tag=b&empty=&label=hello+world",
    sub("&tag=a", "", valid, fixed = TRUE),
    paste0(valid, "&tenant=two"),
    paste0(valid, "&tag=a"),
    sub("tenant=one", "tenant=on%ZZ", valid, fixed = TRUE)
  )) {
    expect_false(oauth_callback_route_matches(
      paste0("https://app.example/callback?", query, "&code=ok"),
      registered
    ))
  }
  expect_false(oauth_callback_route_matches(
    "https://app.example/callback",
    "https://app.example/callback?registered=1"
  ))
})

test_that("the live Shiny callback URI includes fixed query context", {
  session <- list(
    clientData = list(
      url_protocol = "https:",
      url_hostname = "app.example",
      url_port = "",
      url_pathname = "/callback",
      url_search = "?tenant=one&code=ok"
    )
  )
  expect_identical(
    oauth_shiny_session_callback_uri(session),
    "https://app.example/callback?tenant=one&code=ok"
  )
})

test_that("form-post routing checks fixed parameters even with a trusted proxy resolver", {
  req <- new.env(parent = emptyenv())
  req$REQUEST_METHOD <- "POST"
  req$QUERY_STRING <- "tenant=two"
  matches <- function() {
    oauth_form_post_request_matches(
      req,
      "/callback",
      "https://app.example/callback?tenant=one",
      oauth_callback_route,
      request_uri_resolver = function(req) "https://app.example/callback"
    )
  }
  expect_false(matches())
  req$QUERY_STRING <- "tenant=one&extra=discard"
  expect_true(matches())
  location <- oauth_form_post_redirect_location(
    req,
    "auth",
    "handle",
    "https://app.example/callback?tenant=one&tag=a&tag=b"
  )
  expect_identical(
    location,
    "?tenant=one&tag=a&tag=b&shinyOAuth_form_post=handle&shinyOAuth_form_post_id=auth"
  )
  expect_false(grepl("extra|discard", location))
})

test_that("a mismatched fixed query cannot dispatch a callback", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  client <- make_test_client()
  client@redirect_uri <- "https://app.example/callback?tenant=one"
  server <- function(input, output, session) {
    auth <- oauth_module_server("auth", client, auto_redirect = FALSE)
  }
  shiny::testServer(server, {
    auth$.process_query(
      "?tenant=two&code=synthetic&state=unparsed",
      current_uri = "https://app.example/callback?tenant=two&code=synthetic&state=unparsed"
    )
    session$flushReact()
    expect_null(auth$error)
    expect_null(auth$token)
  })
})
