test_that("protocol parsers never dereference JSON input as URLs or files", {
  skip_if_not_installed("webfakes")
  app <- webfakes::new_app()
  app[["locals"]][["hits"]] <- 0L
  app[["get"]]("/payload", function(req, res) {
    req[["app"]][["locals"]][["hits"]] <- req[["app"]][["locals"]][["hits"]] +
      1L
    res[["send_json"]](list(
      access_token = "indirect",
      token_type = "Bearer",
      active = TRUE,
      error = "use_dpop_nonce"
    ))
  })
  app[["get"]]("/count", function(req, res) {
    res[["send_json"]](list(hits = req[["app"]][["locals"]][["hits"]]))
  })
  server <- webfakes::new_app_process(app)
  on.exit(server[["stop"]](), add = TRUE)
  path <- tempfile(fileext = ".json")
  on.exit(unlink(path), add = TRUE)
  writeLines('{"access_token":"indirect","error":"use_dpop_nonce"}', path)
  client <- make_test_client(use_nonce = FALSE)
  client@provider@introspection_url <- "https://example.com/introspect"
  response <- function(text, status = 200L) {
    httr2::response(
      status_code = status,
      headers = list(
        "Content-Type" = "application/json",
        "DPoP-Nonce" = "nonce"
      ),
      body = charToRaw(text)
    )
  }
  for (input in c(server[["url"]]("/payload"), path)) {
    expect_error(
      parse_token_response(response(input)),
      class = "shinyOAuth_parse_error"
    )
    expect_false(try_parse_token_response_json(input)[["ok"]])
    expect_false(resp_is_dpop_nonce_challenge(response(input, 400L)))
    introspection <- testthat::with_mocked_bindings(
      introspect_token(client, OAuthToken(access_token = "synthetic")),
      req_with_retry = function(...) response(input),
      .package = "shinyOAuth"
    )
    expect_identical(introspection[["status"]], "invalid_json")
    # This envelope is processed before any AEAD authentication can take place.
    state <- base64url_encode(charToRaw(input))
    expect_error(state_decrypt_gcm(state, client@state_key))
  }
  count <- curl::curl_fetch_memory(server[["url"]]("/count"))
  expect_equal(
    jsonlite::parse_json(rawToChar(count[["content"]]), simplifyVector = TRUE)[[
      "hits"
    ]],
    0L
  )
  expect_identical(
    parse_token_response(response(
      '{"access_token":"literal","token_type":"Bearer"}'
    ))[["access_token"]],
    "literal"
  )
  expect_true(resp_is_dpop_nonce_challenge(response(
    '{"error":"use_dpop_nonce"}',
    400L
  )))
})
