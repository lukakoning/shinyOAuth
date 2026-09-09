test_that("ID tokens and both UserInfo formats preserve standard claim types", {
  client <- oauth_client(
    oauth_provider(
      name = "claims",
      issuer = "https://example.test",
      auth_url = "https://example.test/auth",
      token_url = "https://example.test/token",
      userinfo_url = "https://example.test/userinfo",
      use_nonce = FALSE,
      userinfo_id_token_match = FALSE
    ),
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = "openid"
  )
  key <- openssl::rsa_keygen()
  jwk <- jsonlite::fromJSON(write_test_jwk(key$pubkey), simplifyVector = FALSE)
  local_mocked_bindings(fetch_jwks = function(...) list(keys = list(jwk)))
  response <- NULL
  local_mocked_bindings(req_with_retry = function(...) response)
  base <- as.character(jsonlite::toJSON(
    list(
      iss = client@provider@issuer,
      aud = client@client_id,
      sub = "user-1",
      iat = floor(as.numeric(Sys.time())) - 10,
      exp = floor(as.numeric(Sys.time())) + 300
    ),
    auto_unbox = TRUE
  ))
  # Sign exact JSON to retain scalar/array/object/null distinctions on the wire.
  sign_json <- function(json) {
    input <- paste(
      base64url_encode(charToRaw('{"alg":"RS256"}')),
      base64url_encode(charToRaw(json)),
      sep = "."
    )
    signature <- openssl::signature_create(
      charToRaw(input),
      openssl::sha256,
      key
    )
    paste(input, base64url_encode(signature), sep = ".")
  }
  check <- function(json, channel) {
    jwt <- sign_json(json)
    if (channel == "id_token") {
      return(validate_id_token(client, jwt))
    }
    signed <- channel == "userinfo_jwt"
    response <<- httr2::response(
      status = 200,
      headers = list(
        "content-type" = if (signed) "application/jwt" else "application/json"
      ),
      body = charToRaw(if (signed) jwt else json)
    )
    get_userinfo(client, token = "test-access")
  }
  invalid <- list(
    email_verified = c('"true"', '1', 'null', '[true]', '{}'),
    phone_number_verified = c('"false"', '0', 'null', '[false]', '{}'),
    acr = c('true', '1', 'null', '["mfa"]', '{}'),
    amr = c(
      '"pwd"',
      'true',
      'null',
      '{}',
      '{"method":"pwd"}',
      '["pwd",1]',
      '[["pwd"]]',
      '[null]'
    )
  )
  valid <- c(
    '',
    ',"email_verified":true,"phone_number_verified":false,"acr":"mfa","amr":["pwd","otp"]',
    ',"email_verified":false,"phone_number_verified":true,"acr":"","amr":[]',
    ',"amr":["pwd"]'
  )
  for (channel in c("id_token", "userinfo_json", "userinfo_jwt")) {
    for (extra in valid) {
      json <- paste0(substr(base, 1L, nchar(base) - 1L), extra, "}")
      expect_silent(check(json, channel))
    }
    for (field in names(invalid)) {
      for (value in invalid[[field]]) {
        json <- paste0(
          substr(base, 1L, nchar(base) - 1L),
          ',"',
          field,
          '":',
          value,
          '}'
        )
        expect_error(
          check(json, channel),
          field,
          class = if (channel == "id_token") {
            "shinyOAuth_id_token_error"
          } else {
            "shinyOAuth_userinfo_error"
          }
        )
      }
    }
  }
})
