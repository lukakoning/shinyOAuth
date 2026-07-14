test_that("client_secret_basic form-encodes credentials on the wire", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$send(req$get_header("authorization"))
  })
  server <- webfakes::local_app_process(app)

  provider <- oauth_provider(
    name = "basic-auth-test",
    auth_url = "https://example.com/authorize",
    token_url = paste0(server$url(), "/token"),
    token_auth_style = "header"
  )
  client <- oauth_client(
    provider = provider,
    client_id = "client:id + café%",
    client_secret = "s:e% c+ret",
    redirect_uri = "https://client.example/callback"
  )
  prepared <- shinyOAuth:::apply_direct_client_auth(
    httr2::request(provider@token_url),
    list(grant_type = "authorization_code"),
    client,
    "token_exchange"
  )
  response <- prepared[["req"]] |>
    httr2::req_method("POST") |>
    httr2::req_perform()
  authorization <- httr2::resp_body_string(response)
  encoded <- sub("^Basic ", "", authorization)
  credentials <- rawToChar(openssl::base64_decode(encoded))

  expect_identical(
    credentials,
    paste0(
      "client%3Aid+%2B+caf%C3%A9%25",
      ":",
      "s%3Ae%25+c%2Bret"
    )
  )
})

test_that("client_secret_basic encoding preserves its single separator", {
  client_id <- shinyOAuth:::encode_client_secret_basic_credential("a:b")
  client_secret <- shinyOAuth:::encode_client_secret_basic_credential("c:d")

  expect_identical(client_id, "a%3Ab")
  expect_identical(client_secret, "c%3Ad")
  expect_identical(paste0(client_id, ":", client_secret), "a%3Ab:c%3Ad")
})