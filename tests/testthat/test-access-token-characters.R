test_that("malformed access tokens never reach resource or UserInfo transport", {
  client <- make_test_client()
  client@provider@userinfo_url <- "https://example.com/userinfo"
  calls <- 0L
  local_mocked_bindings(req_with_retry = function(...) {
    calls <<- calls + 1L
    stop("unexpected transport")
  })
  for (value in c(
    "access\r\nX-Injected: secret",
    "access\n",
    "access\r",
    "access\t",
    "access\001",
    "access\177",
    "acc\u00e8ss",
    "access token",
    "access=token"
  )) {
    expect_error(OAuthToken(access_token = value), "access_token")
    for (scheme in c("Bearer", "DPoP")) {
      expect_error(
        build_client_bearer_authorized_request(
          "https://example.com/resource",
          method = "GET",
          token = value,
          access_token = value,
          token_type = scheme,
          oauth_client = client
        ),
        "invalid characters",
        class = "shinyOAuth_input_error"
      )
    }
    expect_error(
      perform_resource_req(value, "https://example.com/resource"),
      "invalid characters"
    )
    expect_error(get_userinfo(client, value), "invalid characters")
  }
  expect_identical(calls, 0L)
  value <- "AZaz09-._~+/=="
  expect_s3_class(
    resource_req(value, "https://example.com/resource"),
    "httr2_request"
  )
  expect_identical(OAuthToken(access_token = value)@access_token, value)
})

test_that("exchange and refresh reject injected tokens without changing credentials", {
  client <- make_test_client()
  token <- OAuthToken(
    access_token = "old-access",
    refresh_token = "old-refresh"
  )
  value <- "access\r\nX-Injected: secret"
  for (media_type in c(
    "application/json",
    "application/x-www-form-urlencoded"
  )) {
    body <- if (media_type == "application/json") {
      jsonlite::toJSON(
        list(access_token = value, token_type = "Bearer", expires_in = 60),
        auto_unbox = TRUE
      )
    } else {
      paste0(
        "access_token=",
        utils::URLencode(value, reserved = TRUE),
        "&token_type=Bearer&expires_in=60"
      )
    }
    local_mocked_bindings(req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status_code = 200L,
        headers = list("content-type" = media_type),
        body = charToRaw(body)
      )
    })
    expect_error(
      swap_code_for_token_set(client, "code", "verifier"),
      "invalid characters",
      class = "shinyOAuth_token_error"
    )
    expect_error(
      refresh_token(client, token),
      "invalid characters",
      class = "shinyOAuth_token_error"
    )
    expect_identical(token@access_token, "old-access")
    expect_identical(token@refresh_token, "old-refresh")
  }
})
