test_that("Ed25519 authorization, callback and refresh retain signing-key binding", {
  key <- openssl::ed25519_keygen()
  replacement <- openssl::ed25519_keygen()
  for (role in c("assertion", "request")) {
    for (input in list(key, openssl::write_pem(key))) {
      provider <- make_test_provider()
      provider@issuer <- "https://issuer.example.com"
      provider@token_auth_style <- if (role == "assertion") "private_key_jwt" else "body"
      client <- oauth_client(provider, "client", redirect_uri = "http://localhost:8100",
        scopes = c("openid", "read"), state_key = strrep("k", 64),
        client_assertion_private_key = input, client_assertion_alg = "Ed25519",
        request_object_mode = if (role == "request") "request" else "parameters",
        request_object_signing_alg = "Ed25519")
      url <- prepare_call(client, browser_token = valid_browser_token())
      state <- if (role == "request") {
        jar <- parse_query_param(url, "request", decode = TRUE)
        expect_true(verify_jws_signature_no_time(jar, key[["pubkey"]], "Ed25519"))
        parse_jwt_payload(jar)[["state"]]
      } else {
        parse_query_param(url, "state", decode = TRUE)
      }
      equivalent <- client
      equivalent@client_assertion_private_key <- openssl::write_pem(key)
      expect_identical(state_client_policy_fingerprint(client),
        state_client_policy_fingerprint(equivalent))
      changed <- client
      changed@client_assertion_private_key <- replacement
      expect_error(handle_callback(changed, code = "synthetic-code", state = state,
        browser_token = valid_browser_token()), "policy mismatch",
        class = "shinyOAuth_state_error")

      calls <- 0L
      local_mocked_bindings(req_with_retry = function(req, ...) {
        calls <<- calls + 1L
        if (role == "assertion") {
          current <- req[["shinyOAuth_prepare_attempt"]](req, 1L)
          fields <- if (current[["body"]][["type"]] == "form") {
            lapply(current[["body"]][["data"]], function(x) utils::URLdecode(as.character(x)))
          } else {
            decode_form_pairs(rawToChar(current[["body"]][["data"]]))
          }
          expect_true(verify_jws_signature_no_time(
            fields[["client_assertion"]], key[["pubkey"]], "Ed25519"))
        }
        httr2::response(status = 200L, headers = list("content-type" = "application/json"),
          body = charToRaw('{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":300}'))
      }, .package = "shinyOAuth")
      token <- handle_callback(client, code = "synthetic-code", state = state,
        browser_token = valid_browser_token())
      expect_identical(token@access_token, "access")
      refreshed <- refresh_token(client, token, async = FALSE, introspect = FALSE)
      expect_identical(refreshed@refresh_token, "refresh")
      expect_identical(calls, 2L)
    }
  }
})

test_that("public-key export preserves existing RSA and EC policy thumbprints", {
  for (key in list(openssl::rsa_keygen(), openssl::ec_keygen())) {
    old <- canonicalize_local_public_jwk(jsonlite::fromJSON(
      jose::write_jwk(key[["pubkey"]]), simplifyVector = TRUE))
    expect_identical(compute_jwk_thumbprint(private_key_public_jwk(key)),
      compute_jwk_thumbprint(old))
  }
  jwk <- private_key_public_jwk(openssl::ed25519_keygen())
  expect_setequal(names(jwk), c("kty", "crv", "x"))
  expect_identical(jwk[["crv"]], "Ed25519")
})
