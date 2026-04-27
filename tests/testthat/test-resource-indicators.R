count_fixed_matches <- function(text, pattern) {
  matches <- gregexpr(pattern, text, fixed = TRUE)[[1]]
  sum(matches > 0L)
}

request_body_text <- function(req) {
  body <- req$body %||% NULL
  if (is.null(body)) {
    return(NA_character_)
  }
  if (identical(body$type, "raw")) {
    return(rawToChar(body$data))
  }
  if (identical(body$type, "form")) {
    data <- body$data %||% list()
    if (!length(data)) {
      return("")
    }

    parts <- unlist(
      lapply(seq_along(data), function(i) {
        nm <- names(data)[[i]]
        paste0(
          nm,
          "=",
          utils::URLencode(as.character(data[[i]])[[1]], reserved = TRUE)
        )
      }),
      use.names = FALSE
    )
    return(paste(parts, collapse = "&"))
  }

  NA_character_
}

test_that("oauth_client rejects non-absolute resource indicators", {
  expect_error(
    oauth_client(
      provider = make_test_provider(),
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      resource = "api.example.com"
    ),
    regexp = "resource.*absolute URI"
  )
})

test_that("prepare_call includes repeated RFC 8707 resource indicators", {
  cli <- make_test_client(
    resource = c(
      "https://api.example.com",
      "urn:example:ledger"
    )
  )

  auth_url <- prepare_call(cli, valid_browser_token())

  expect_identical(count_fixed_matches(auth_url, "resource="), 2L)
  expect_match(auth_url, "resource=https%3A%2F%2Fapi\\.example\\.com")
  expect_match(auth_url, "resource=urn%3Aexample%3Aledger")
})

test_that("swap_code_for_token_set sends resource indicators in token body", {
  cli <- make_test_client(
    resource = c(
      "https://api.example.com",
      "urn:example:ledger"
    )
  )
  body_text <- NULL

  testthat::with_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_text <<- request_body_text(req)
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","refresh_token":"rt","expires_in":3600}'
        )
      )
    },
    .package = "shinyOAuth",
    {
      token_set <- shinyOAuth:::swap_code_for_token_set(
        client = cli,
        code = "test_code",
        code_verifier = "test_verifier_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      )
    }
  )

  expect_identical(token_set$access_token, "at")
  expect_identical(count_fixed_matches(body_text, "resource="), 2L)
  expect_match(body_text, "resource=https%3A%2F%2Fapi\\.example\\.com")
  expect_match(body_text, "resource=urn%3Aexample%3Aledger")
})

test_that("refresh_token sends resource indicators in refresh body", {
  cli <- make_test_client(
    resource = c(
      "https://api.example.com",
      "urn:example:ledger"
    )
  )
  body_text <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_text <<- request_body_text(req)
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new_at","refresh_token":"new_rt","expires_in":60}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  tok <- OAuthToken(
    access_token = "old_at",
    refresh_token = "old_rt",
    expires_at = as.numeric(Sys.time()) + 60
  )

  refreshed <- refresh_token(cli, tok, async = FALSE, introspect = FALSE)

  expect_identical(refreshed@access_token, "new_at")
  expect_identical(count_fixed_matches(body_text, "resource="), 2L)
  expect_match(body_text, "grant_type=refresh_token")
  expect_match(body_text, "resource=https%3A%2F%2Fapi\\.example\\.com")
  expect_match(body_text, "resource=urn%3Aexample%3Aledger")
})
