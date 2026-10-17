test_that("token verification rejects malformed supplied ID token values", {
  client <- make_test_client(use_nonce = FALSE)
  for (refresh in c(FALSE, TRUE)) {
    for (value in list(
      123,
      FALSE,
      TRUE,
      "",
      NA_character_,
      character(0),
      c("first", "second"),
      list("token")
    )) {
      expect_error(
        verify_token_set(
          client,
          list(access_token = "access", token_type = "Bearer", id_token = value),
          nonce = NULL,
          is_refresh = refresh
        ),
        "id_token must be a non-empty string",
        class = "shinyOAuth_id_token_error"
      )
    }
  }
})

test_that("refresh rejects malformed ID tokens instead of retaining prior identity", {
  local_options(shinyOAuth.skip_id_sig = FALSE)
  client <- make_test_client(use_nonce = FALSE, scopes = "openid")
  client@provider@issuer <- "https://example.com"
  client@provider@id_token_validation <- TRUE
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(write_test_jwk(key[["pubkey"]]), simplifyVector = FALSE)
  now <- as.numeric(Sys.time())
  original <- jose::jwt_encode_sig(
    jose::jwt_claim(
      iss = client@provider@issuer,
      aud = client@client_id,
      sub = "original-subject",
      iat = now,
      exp = now + 3600
    ),
    key
  )
  body <- ""
  content_type <- "application/json"
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(jwk)),
    req_with_retry = function(...) {
      httr2::response(
        status_code = 200L,
        headers = list("content-type" = content_type),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  verified <- verify_token_set(
    client,
    list(access_token = "old-access", token_type = "Bearer", id_token = original),
    nonce = NULL
  )
  expect_true(verified[[".id_token_validated"]])
  token <- OAuthToken(
    access_token = "old-access",
    refresh_token = "old-refresh",
    id_token = original,
    original_id_token = original,
    id_token_validated = verified[[".id_token_validated"]],
    granted_scopes = "openid"
  )

  for (content_type in c("application/json", "text/plain")) {
    for (wire in c("123", "false", "true", '""')) {
      body <- paste0(
        '{"access_token":"new-access","token_type":"Bearer",',
        '"expires_in":3600,"id_token":', wire, '}'
      )
      expect_error(
        refresh_token(client, token, async = FALSE, introspect = FALSE),
        "id_token must be a non-empty string",
        class = "shinyOAuth_id_token_error"
      )
      expect_identical(token@access_token, "old-access")
    }
  }
  content_type <- "application/x-www-form-urlencoded"
  body <- "access_token=new-access&token_type=Bearer&expires_in=3600&id_token="
  expect_error(
    refresh_token(client, token, async = FALSE, introspect = FALSE),
    "id_token must be a non-empty string",
    class = "shinyOAuth_id_token_error"
  )

  # Optional NULL values retain the same omission semantics as an absent field.
  content_type <- "application/json"
  for (suffix in c("", ',"id_token":null')) {
    body <- paste0(
      '{"access_token":"new-access","token_type":"Bearer","expires_in":3600',
      suffix, '}'
    )
    refreshed <- refresh_token(client, token, async = FALSE, introspect = FALSE)
    expect_identical(refreshed@access_token, "new-access")
    expect_identical(refreshed@id_token, original)
    expect_true(refreshed@id_token_validated)
  }
})
