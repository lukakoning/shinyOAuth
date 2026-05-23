make_fragment_get_req <- function(path = "/callback", query = "") {
  req <- new.env(parent = emptyenv())
  req$REQUEST_METHOD <- "GET"
  req$PATH_INFO <- path
  req$QUERY_STRING <- query
  req
}

make_fragment_post_req <- function(
  path = "/callback",
  query = "",
  body = "",
  content_type = "application/x-www-form-urlencoded"
) {
  req <- new.env(parent = emptyenv())
  req$REQUEST_METHOD <- "POST"
  req$PATH_INFO <- path
  req$QUERY_STRING <- query
  req$CONTENT_TYPE <- content_type
  req$CONTENT_LENGTH <- as.character(nchar(body, type = "bytes"))
  req$rook.input <- list(read = function(n) charToRaw(body))
  req
}

make_fragment_test_client <- function(
  use_pkce = TRUE,
  use_nonce = FALSE,
  state_max_age = 600,
  state_payload_max_age = 300
) {
  prov <- make_test_provider(use_pkce = use_pkce, use_nonce = use_nonce)
  prov@response_modes_supported <- c("query", "fragment", "form_post")

  oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    response_mode = "fragment",
    state_store = cachem::cache_mem(max_age = state_max_age),
    state_payload_max_age = state_payload_max_age,
    state_entropy = 64,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

test_that("fragment reminder warns when oauth_fragment_ui was not called", {
  cli <- make_fragment_test_client(use_pkce = TRUE, use_nonce = FALSE)
  id <- "auth_fragment_watchdog_missing"

  warning_cnd <- testthat::with_mocked_bindings(
    .package = "shinyOAuth",
    .is_test = function() FALSE,
    rlang::catch_cnd(
      shinyOAuth:::warn_about_missing_fragment_ui(id, cli),
      classes = "warning"
    )
  )

  testthat::expect_s3_class(warning_cnd, "warning")
  testthat::expect_match(
    conditionMessage(warning_cnd),
    "oauth_fragment_ui",
    fixed = TRUE
  )
  testthat::expect_match(
    conditionMessage(warning_cnd),
    "response_mode = \"fragment\"",
    fixed = TRUE
  )
})

test_that("fragment reminder stays quiet once oauth_fragment_ui was called", {
  cli <- make_fragment_test_client(use_pkce = TRUE, use_nonce = FALSE)
  id <- "auth_fragment_watchdog_seen"

  oauth_fragment_ui(shiny::fluidPage(), id = id, client = cli)

  warning_cnd <- testthat::with_mocked_bindings(
    .package = "shinyOAuth",
    .is_test = function() FALSE,
    rlang::catch_cnd(
      shinyOAuth:::warn_about_missing_fragment_ui(id, cli),
      classes = "warning"
    )
  )

  testthat::expect_null(warning_cnd)
})

test_that("oauth_fragment_ui requires a dedicated non-root callback path", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    response_mode = "fragment"
  )

  expect_error(
    oauth_fragment_ui(shiny::fluidPage(), id = "auth", client = cli),
    class = "shinyOAuth_input_error",
    regexp = "dedicated non-root path"
  )

  expect_error(
    shinyOAuth:::normalize_oauth_fragment_callback_path("/"),
    class = "shinyOAuth_input_error",
    regexp = "dedicated non-root path"
  )
})

test_that("oauth_fragment_ui can install bridge before response_mode is set", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@redirect_uri <- "http://localhost:8100/callback"

  expect_silent(
    oauth_fragment_ui(shiny::fluidPage(), id = "auth", client = cli)
  )
})

test_that("oauth_fragment_ui serves a standalone bridge page on callback GET", {
  cli <- make_fragment_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_fragment_ui(shiny::fluidPage(), id = "auth", client = cli)

  resp <- ui(make_fragment_get_req())

  expect_identical(resp$status, 200L)
  expect_match(resp$content, "shinyOAuth-fragment-bridge", fixed = TRUE)
  expect_match(resp$content, 'shinyOAuth-[^\"]+/shinyOAuth\\.js')
  expect_identical(resp$headers[["Cache-Control"]], "no-store")
  expect_identical(resp$headers[["Pragma"]], "no-cache")
  expect_identical(resp$headers[["Referrer-Policy"]], "no-referrer")
})

test_that("oauth_fragment_ui lets callback handle GETs reach the wrapped app", {
  cli <- make_fragment_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_fragment_ui(
    function(req) {
      shiny::fluidPage(
        shiny::div(id = "base-ui", req$QUERY_STRING %||% "")
      )
    },
    id = "auth",
    client = cli
  )

  rendered <- ui(make_fragment_get_req(
    query = paste0(
      "shinyOAuth_form_post=handle&",
      "shinyOAuth_form_post_id=auth"
    )
  ))
  rt <- htmltools::renderTags(rendered)

  expect_match(rt$html, "base-ui", fixed = TRUE)
  expect_match(rt$html, "shinyOAuth_form_post=handle", fixed = TRUE)
  expect_no_match(rt$html, "shinyOAuth-fragment-bridge", fixed = TRUE)
})

test_that("oauth_fragment_ui stores POST callback and blocks fragment inheritance", {
  cli <- make_fragment_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_fragment_ui(shiny::fluidPage(), id = "auth", client = cli)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")
  decoded_state <- shiny::parseQueryString(paste0("?state=", enc_state))$state

  resp <- ui(make_fragment_post_req(
    query = "return_to=dashboard",
    body = paste0(
      "code=ok&state=",
      enc_state,
      "&iss=https%3A%2F%2Fissuer"
    )
  ))

  expect_identical(resp$status, 303L)
  expect_match(resp$headers$Location, "^\\?return_to=dashboard&")
  expect_match(resp$headers$Location, "shinyOAuth_form_post=")
  expect_match(resp$headers$Location, "shinyOAuth_form_post_id=auth")
  expect_true(endsWith(resp$headers$Location, "#_"))
  expect_false(grepl("code=ok", resp$headers$Location, fixed = TRUE))

  handle <- parse_query_param(
    sub("#_$", "", resp$headers$Location),
    "shinyOAuth_form_post",
    decode = TRUE
  )
  payload <- shinyOAuth:::oauth_form_post_store_take(cli, "auth", handle)
  expect_identical(payload$type, "code")
  expect_identical(payload$code, "ok")
  expect_identical(payload$state, decoded_state)
  expect_identical(payload$iss, "https://issuer")
})
