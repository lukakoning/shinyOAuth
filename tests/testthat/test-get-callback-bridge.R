make_get_bridge_case <- function(kind) {
  client <- make_test_client()
  client@redirect_uri <- "http://localhost:8100/?tenant=one&tag=a&tag=b"
  if (kind == "jarm") {
    client@scopes <- "openid"
    client@provider@issuer <- "https://issuer.example.com"
    client@client_secret <- strrep("a", 64)
    client@response_mode <- "query.jwt"
    client@jarm_signed_response_alg <- "HS256"
  }
  browser <- valid_browser_token()
  state <- parse_query_param(
    prepare_call(client, browser),
    "state",
    decode = TRUE
  )
  fields <- if (kind == "jarm") {
    claims <- jose::jwt_claim(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = as.numeric(Sys.time()) + 60,
      state = state,
      code = "SYNTHETIC_CODE"
    )
    list(response = jose::jwt_encode_hmac(claims, client@client_secret))
  } else if (kind == "error") {
    list(
      error = "access_denied",
      error_description = "SYNTHETIC_DETAILS",
      state = state
    )
  } else {
    list(code = "SYNTHETIC_CODE", state = state)
  }
  query <- paste0(
    "tenant=one&tag=b&tag=a&unregistered=discard&",
    httr2::url_query_build(fields)
  )
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/",
    QUERY_STRING = query,
    rook.url_scheme = "http",
    HTTP_HOST = "localhost:8100"
  )
  list(
    client = client,
    browser = browser,
    state = state,
    req = req,
    kind = kind
  )
}

test_that("GET code, error and JARM callbacks redirect before application rendering", {
  for (kind in c("code", "error", "jarm")) {
    case <- make_get_bridge_case(kind)
    rendered <- 0L
    ui <- oauth_ui(
      function(req) {
        rendered <<- rendered + 1L
        shiny::fluidPage(shiny::tags$script(
          "window.appSaw = window.location.search;"
        ))
      },
      "auth",
      case$client
    )
    response <- ui(case$req)
    expect_identical(response$status, 303L, info = response$content)
    expect_identical(rendered, 0L)
    expect_identical(response$headers[["Cache-Control"]], "no-store")
    expect_identical(response$headers[["Pragma"]], "no-cache")
    expect_identical(response$headers[["Referrer-Policy"]], "no-referrer")
    location <- response$headers[["Location"]]
    expect_match(location, "^\\?tenant=one&tag=a&tag=b&shinyOAuth_form_post=")
    expect_false(grepl(
      "SYNTHETIC|response=|code=|state=|error=|unregistered",
      paste(location, response$content)
    ))
    clean <- case$req
    clean$QUERY_STRING <- sub("^\\?", "", location)
    expect_equal(ui(clean)$status, 200L)
    expect_identical(rendered, 1L)
    handle <- parse_query_param(location, "shinyOAuth_form_post", decode = TRUE)
    payload <- oauth_form_post_store_take(case$client, "auth", handle)
    expect_identical(payload$transport, "query")
    expect_identical(payload$type, if (kind == "jarm") "response" else kind)
    expect_error(
      oauth_form_post_store_take(case$client, "auth", handle),
      class = "shinyOAuth_state_error"
    )
    state_payload <- state_payload_decrypt_validate(case$client, case$state)
    expect_true(is.list(state_store_get(case$client, state_payload$state)))
  }
})

test_that("GET bridge handles resume through browser-bound module validation", {
  for (kind in c("code", "error", "jarm")) {
    case <- make_get_bridge_case(kind)
    response <- oauth_ui(shiny::fluidPage(), "auth", case$client)(case$req)
    local_mocked_bindings(
      swap_code_for_token_set = function(...) {
        list(
          access_token = "synthetic",
          token_type = "Bearer",
          expires_in = 3600
        )
      },
      .package = "shinyOAuth"
    )
    server <- function(input, output, session) {
      auth <- oauth_module_server(
        "auth",
        case$client,
        auto_redirect = FALSE,
        async = FALSE,
        indefinite_session = TRUE
      )
    }
    shiny::testServer(server, {
      session$setInputs(`auth-shinyOAuth_sid` = case$browser)
      query <- response$headers[["Location"]]
      auth$.process_query(
        query,
        current_uri = paste0("http://localhost:8100/", query)
      )
      session$flushReact()
      if (case$kind == "error") {
        expect_identical(auth$error, "access_denied")
        expect_null(auth$error_description)
      } else {
        expect_true(auth$authenticated, info = auth$error)
      }
    })
  }
})

test_that("GET bridge callbacks retain the browser-binding check", {
  withr::local_options(list(shinyOAuth.skip_browser_token = FALSE))
  case <- make_get_bridge_case("code")
  response <- oauth_ui(shiny::fluidPage(), "auth", case$client)(case$req)
  local_mocked_bindings(
    swap_code_for_token_set = function(...) stop("must not exchange"),
    .package = "shinyOAuth"
  )
  server <- function(input, output, session) {
    auth <- oauth_module_server(
      "auth",
      case$client,
      auto_redirect = FALSE,
      async = FALSE
    )
  }
  shiny::testServer(server, {
    session$setInputs(`auth-shinyOAuth_sid` = strrep("cd", 64))
    auth$.process_query(response$headers[["Location"]])
    session$flushReact()
    expect_false(auth$authenticated)
    expect_identical(auth$error, "invalid_state")
  })
  payload <- state_payload_decrypt_validate(case$client, case$state)
  expect_true(is.list(state_store_get(case$client, payload$state)))
})

test_that("unconfigured, invalid and wrong-route GET callbacks never render the app", {
  render <- function(req) stop("application must not render")
  for (query in c(
    "code=synthetic&state=synthetic",
    "error=access_denied&state=synthetic",
    "response=a.b.c"
  )) {
    expect_identical(
      oauth_ui(render)(list(
        REQUEST_METHOD = "GET",
        QUERY_STRING = query
      ))$status,
      400L
    )
  }
  case <- make_get_bridge_case("code")
  ui <- oauth_ui(render, "auth", case$client)
  req <- case$req
  req$QUERY_STRING <- sub("tenant=one", "tenant=two", req$QUERY_STRING)
  expect_identical(ui(req)$status, 400L)
  req <- case$req
  req$QUERY_STRING <- paste0(req$QUERY_STRING, "&code=duplicate")
  expect_identical(ui(req)$status, 400L)
  req <- case$req
  req$QUERY_STRING <- "tenant=one&tag=a&tag=b&code=synthetic&state=invalid"
  expect_identical(ui(req)$status, 400L)
  req <- case$req
  req$HTTP_HOST <- "other.example"
  expect_identical(ui(req)$status, 400L)
})

test_that("application scripts observe only clean GET bridge URLs in a browser", {
  skip_if_not_installed("chromote")
  skip_if_not_installed("webfakes")
  skip_if(Sys.getenv("SHINYOAUTH_BROWSER_TESTS") != "true")
  for (kind in c("code", "error", "jarm")) {
    case <- make_get_bridge_case(kind)
    ui <- oauth_ui(
      shiny::fluidPage(shiny::tags$script(
        "window.appSaw = window.location.search;"
      )),
      "auth",
      case$client
    )
    bridge <- ui(case$req)
    req <- case$req
    req$QUERY_STRING <- sub("^\\?", "", bridge$headers[["Location"]])
    rendered <- ui(req)
    app <- webfakes::new_app()
    app$locals$bridge <- bridge
    app$locals$rendered <- rendered
    app$get("/", function(req, res) {
      response <- if (!is.null(req$query$shinyOAuth_form_post)) {
        app$locals$rendered
      } else {
        app$locals$bridge
      }
      for (header in names(response$headers)) {
        res$set_header(header, response$headers[[header]])
      }
      res$set_status(response$status)$set_type(response$content_type)$send(
        response$content
      )
    })
    srv <- webfakes::local_app_process(app)
    browser <- chromote::ChromoteSession$new()
    withr::defer(browser$close(), envir = environment())
    loaded <- browser$Page$loadEventFired(wait_ = FALSE)
    browser$Page$navigate(srv$url(paste0("/?", case$req$QUERY_STRING)))
    browser$wait_for(loaded)
    observed <- browser$Runtime$evaluate("window.appSaw")$result$value
    expect_identical(observed, bridge$headers[["Location"]])
    expect_false(grepl(
      "SYNTHETIC|response=|code=|state=|error=|unregistered",
      observed
    ))
    raw_response <- httr2::request(srv$url(paste0(
      "/?",
      case$req$QUERY_STRING
    ))) |>
      httr2::req_options(followlocation = FALSE) |>
      httr2::req_perform()
    expect_identical(httr2::resp_status(raw_response), 303L)
    expect_identical(
      httr2::resp_header(raw_response, "cache-control"),
      "no-store"
    )
    expect_identical(httr2::resp_header(raw_response, "pragma"), "no-cache")
    browser$close()
    srv$stop()
  }
})
# shinyOAuth-browser-suite
