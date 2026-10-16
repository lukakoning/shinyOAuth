test_that("ID token nonce types are checked even when nonce use is disabled", {
  client <- oauth_client(
    oauth_provider(
      name = "nonce-types",
      issuer = "https://example.test",
      auth_url = "https://example.test/auth",
      token_url = "https://example.test/token",
      use_nonce = FALSE,
      userinfo_required = FALSE
    ),
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = "openid"
  )
  key <- openssl::rsa_keygen()
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]), simplifyVector = FALSE
  )
  local_mocked_bindings(fetch_jwks = function(...) list(keys = list(jwk)))
  now <- floor(as.numeric(Sys.time()))
  sign <- function(nonce, include = TRUE) {
    claims <- list(
      iss = client@provider@issuer, aud = client@client_id, sub = "user-1",
      iat = now, exp = now + 300
    )
    if (include) claims["nonce"] <- list(nonce)
    input <- paste(
      base64url_encode(charToRaw('{"alg":"RS256"}')),
      base64url_encode(charToRaw(jsonlite::toJSON(
        claims, auto_unbox = TRUE, null = "null"
      ))),
      sep = "."
    )
    paste(input, base64url_encode(openssl::signature_create(
      charToRaw(input), openssl::sha256, key
    )), sep = ".")
  }

  absent <- sign(NULL, include = FALSE)
  matching <- sign("transaction-nonce")
  expect_true(attr(validate_id_token(client, absent), "signature_verified"))
  expect_true(attr(validate_id_token(client, matching), "signature_verified"))
  expect_true(attr(
    validate_id_token(client, matching, expected_nonce = "transaction-nonce"),
    "signature_verified"
  ))
  expect_error(
    validate_id_token(client, absent, expected_nonce = "transaction-nonce"),
    "missing nonce", class = "shinyOAuth_id_token_error"
  )
  expect_error(
    validate_id_token(client, matching, expected_nonce = "other-nonce"),
    "nonce mismatch", class = "shinyOAuth_id_token_error"
  )

  for (nonce in list(
    NULL, 123, TRUE, FALSE, list(), list("transaction-nonce"),
    list("first", "second"), list(value = "transaction-nonce")
  )) {
    jwt <- sign(nonce)
    expect_true("nonce" %in% names(parse_jwt_payload(jwt)))
    for (expected in list(NULL, "transaction-nonce")) {
      expect_error(
        validate_id_token(client, jwt, expected_nonce = expected),
        "nonce claim must be a JSON string",
        class = "shinyOAuth_id_token_error"
      )
    }
    expect_error(
      verify_token_set(
        client,
        list(
          access_token = "token", token_type = "Bearer", scope = "openid",
          id_token = jwt
        ),
        nonce = NULL
      ),
      "nonce claim must be a JSON string",
      class = "shinyOAuth_id_token_error"
    )
  }
})

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
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
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
  for (field in c(
    "name", "given_name", "family_name", "middle_name", "nickname",
    "preferred_username", "profile", "picture", "website", "email", "gender",
    "birthdate", "zoneinfo", "locale", "phone_number"
  )) {
    invalid[[field]] <- c('1', 'true', 'null', '["text"]', '{}')
  }
  invalid[["updated_at"]] <- c('"yesterday"', 'true', 'null', '[1700000000]', '{}', '1e999')
  invalid[["address"]] <- c(
    '"line"', 'true', 'null', '[]', '["line"]',
    '{"country":1}', '{"country":["country"]}', '{"formatted":null}'
  )
  valid <- c(
    '',
    ',"email_verified":true,"phone_number_verified":false,"acr":"mfa","amr":["pwd","otp"]',
    ',"email_verified":false,"phone_number_verified":true,"acr":"","amr":[]',
    ',"amr":["pwd"]',
    ',"name":"Example User","email":"user@example.com","updated_at":1700000000',
    ',"address":{}',
    ',"address":{"formatted":"Line 1\\nLine 2","country":"NL","extension":123}',
    ',"groups":["staff"],"custom":{"key":[123]}'
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
