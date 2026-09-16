test_that("authenticated Apple claims remain normalized through login and policy", {
  provider <- oauth_provider(
    name = "apple",
    issuer = "https://appleid.apple.com",
    auth_url = "https://appleid.apple.com/auth/authorize",
    token_url = "https://appleid.apple.com/auth/token",
    token_auth_style = "body",
    use_nonce = TRUE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE
  )
  client <- oauth_client(
    provider,
    client_id = "com.example.app",
    client_secret = "secret",
    redirect_uri = "https://app.example/callback",
    scopes = "openid email",
    claims = list(
      id_token = list(
        email_verified = list(essential = TRUE, value = TRUE)
      )
    ),
    claims_validation = "strict"
  )
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  jwk[["alg"]] <- "RS256"
  local_mocked_bindings(fetch_jwks = function(...) list(keys = list(jwk)))
  jwt <- NULL
  local_mocked_bindings(swap_code_for_token_set = function(...) {
    list(
      access_token = "access",
      token_type = "Bearer",
      id_token = jwt,
      scope = "openid email",
      expires_in = 120
    )
  })
  login <- function(value, signing_key = key) {
    browser <- valid_browser_token()
    url <- prepare_call(client, browser_token = browser)
    now <- floor(as.numeric(Sys.time()))
    jwt <<- jose::jwt_encode_sig(
      jose::jwt_claim(
        iss = provider@issuer,
        aud = client@client_id,
        sub = "apple-user",
        iat = now,
        exp = now + 120,
        nonce = parse_query_param(url, "nonce", decode = TRUE),
        email_verified = value
      ),
      key = signing_key
    )
    handle_callback(
      client,
      code = "code",
      state = parse_query_param(url, "state"),
      browser_token = browser
    )
  }
  for (value in list(TRUE, "true")) {
    token <- login(value)
    expect_true(token@id_token_validated)
    expect_true(token@id_token_claims[["email_verified"]])
    expect_identical(token@id_token, jwt)
    expect_identical(
      parse_jwt_payload(token@id_token)[["email_verified"]],
      value
    )
  }
  for (value in list(FALSE, "false")) {
    expect_error(login(value), class = "shinyOAuth_id_token_error")
  }
  expect_error(
    login("true", openssl::rsa_keygen(2048)),
    class = "shinyOAuth_id_token_error"
  )

  client@claims_validation <- "none"
  for (value in c("true", "false")) {
    token <- login(value)
    expect_identical(
      token@id_token_claims[["email_verified"]],
      identical(value, "true")
    )
    token@id_token_validated <- FALSE
    expect_identical(token@id_token_claims[["email_verified"]], value)
  }
})
