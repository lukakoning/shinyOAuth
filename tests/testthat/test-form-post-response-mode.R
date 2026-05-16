make_form_post_req <- function(
  path = "/",
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

form_post_query <- function(handle, id = "auth") {
  paste0(
    "?",
    httr2::url_query_build(stats::setNames(
      list(handle, id),
      c("shinyOAuth_form_post", "shinyOAuth_form_post_id")
    ))
  )
}

test_that("oauth_form_post_ui stores POST callback and redirects with handle", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")
  decoded_state <- shiny::parseQueryString(paste0("?state=", enc_state))$state

  req <- make_form_post_req(
    body = paste0("code=ok&state=", enc_state, "&iss=https%3A%2F%2Fissuer")
  )
  resp <- ui(req)

  expect_identical(resp$status, 303L)
  expect_match(resp$headers$Location, "shinyOAuth_form_post=")
  expect_match(resp$headers$Location, "shinyOAuth_form_post_id=auth")
  expect_false(grepl("code=ok", resp$headers$Location, fixed = TRUE))
  expect_false(grepl(
    "state=",
    sub("shinyOAuth_form_post=[^&]+", "", resp$headers$Location)
  ))

  handle <- parse_query_param(
    resp$headers$Location,
    "shinyOAuth_form_post",
    decode = TRUE
  )
  payload <- shinyOAuth:::oauth_form_post_store_take(cli, "auth", handle)
  expect_identical(payload$type, "code")
  expect_identical(payload$code, "ok")
  expect_identical(payload$state, decoded_state)
  expect_identical(payload$iss, "https://issuer")
})

test_that("oauth_form_post_ui rejects invalid callback POST bodies", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")

  bad_type <- ui(make_form_post_req(
    body = paste0("code=ok&state=", enc_state),
    content_type = "application/json"
  ))
  expect_identical(bad_type$status, 415L)

  duplicate <- ui(make_form_post_req(
    body = paste0("code=ok&code=again&state=", enc_state)
  ))
  expect_identical(duplicate$status, 400L)

  missing_state <- ui(make_form_post_req(body = "code=ok"))
  expect_identical(missing_state$status, 400L)
})

test_that("oauth_module_server consumes form_post callback handles", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc_state <- parse_query_param(url, "state")
      decoded_state <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state
      ))$state
      handle <- shinyOAuth:::oauth_form_post_store_set(
        cli,
        "auth",
        list(code = "ok", state = decoded_state)
      )

      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          testthat::expect_identical(code, "ok")
          list(access_token = "t", token_type = "Bearer", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(form_post_query(handle, "auth"))
          session$flushReact()
          values$token
        }
      )

      expect_false(is.null(token))
      expect_true(isTRUE(values$authenticated))
      expect_null(values$error)
    }
  )
})

test_that("oauth_module_server consumes form_post error callbacks", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc_state <- parse_query_param(url, "state")
      decoded_state <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state
      ))$state
      handle <- shinyOAuth:::oauth_form_post_store_set(
        cli,
        "auth",
        list(
          error = "access_denied",
          error_description = "Denied",
          state = decoded_state
        )
      )

      values$.process_query(form_post_query(handle, "auth"))
      session$flushReact()

      expect_identical(values$error, "access_denied")
      expect_identical(values$error_description, "Denied")
      expect_false(isTRUE(values$authenticated))
    }
  )
})
