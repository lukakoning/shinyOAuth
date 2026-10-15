test_that("numeric claims survive ordinary parameters and every asymmetric JAR algorithm", {
  value <- 1.23456789
  claims <- list(
    id_token = list(
      level = list(value = value),
      choices = list(values = c(value, 1e-10)),
      nested = list(value = list(level = value, small = -0.123456789))
    ),
    userinfo = list(level = list(value = value))
  )
  expected <- jsonlite::fromJSON(jsonlite::toJSON(
    claims, auto_unbox = TRUE, digits = NA), simplifyVector = FALSE)
  # Explicit JSON must also survive the second serialization inside JAR.
  inputs <- list(claims, as.character(jsonlite::toJSON(claims,
    auto_unbox = TRUE, digits = NA)))
  provider <- make_test_provider(use_nonce = TRUE)
  provider@issuer <- "https://issuer.example.com"
  provider@userinfo_url <- "https://issuer.example.com/userinfo"
  provider@userinfo_required <- TRUE
  for (input in inputs) {
    client <- oauth_client(provider, "client", redirect_uri = "http://localhost:8100",
      scopes = "openid", claims = input)
    url <- prepare_call(client, browser_token = valid_browser_token())
    expect_identical(jsonlite::fromJSON(parse_query_param(url, "claims", decode = TRUE),
      simplifyVector = FALSE), expected)
  }
  rsa <- openssl::rsa_keygen()
  cases <- list(RS256 = rsa, RS384 = rsa,
    ES256 = openssl::ec_keygen("P-256"), ES384 = openssl::ec_keygen("P-384"),
    ES512 = openssl::ec_keygen("P-521"), Ed25519 = openssl::ed25519_keygen())
  for (alg in names(cases)) {
    key <- cases[[alg]]
    for (input in inputs) {
      client <- oauth_client(provider, "client", redirect_uri = "http://localhost:8100",
        scopes = "openid", claims = input, request_object_mode = "request",
        client_assertion_private_key = key, request_object_signing_alg = alg)
      url <- prepare_call(client, browser_token = valid_browser_token())
      jwt <- parse_query_param(url, "request", decode = TRUE)
      expect_identical(parse_jwt_payload(jwt)[["claims"]], expected, info = alg)
      expect_true(verify_jws_signature_no_time(jwt, key[["pubkey"]], alg), info = alg)
      if (alg != "Ed25519") {
        # jose only accepts typ=JWT. Verify the same payload with that header
        # using its independent decoder, including fixed-width ES512.
        compatible <- encode_asymmetric_jwt_with_header(
          outbound_jwt_claim(parse_jwt_payload(jwt)), key,
          list(typ = "JWT", alg = alg))
        decoded <- jose::jwt_decode_sig(compatible, key[["pubkey"]])
        expect_identical(decoded[["claims"]], jsonlite::fromJSON(
          jsonlite::toJSON(expected, auto_unbox = TRUE, digits = NA)))
      }
    }
  }
})

test_that("strict ID token and UserInfo validation accept the exact requested number", {
  value <- 1.23456789
  client <- make_test_client(use_nonce = TRUE,
    claims = list(id_token = list(level = list(value = value)),
      userinfo = list(level = list(value = value))), claims_validation = "strict")
  client@provider@userinfo_url <- "https://example.com/userinfo"
  key <- openssl::rsa_keygen()
  jwk <- canonicalize_local_public_jwk(jsonlite::fromJSON(
    jose::write_jwk(key[["pubkey"]]), simplifyVector = FALSE))
  local_mocked_bindings(fetch_jwks = function(...) list(keys = list(jwk)),
    .package = "shinyOAuth")
  url <- prepare_call(client, browser_token = valid_browser_token())
  wire <- jsonlite::fromJSON(parse_query_param(url, "claims", decode = TRUE),
    simplifyVector = FALSE)
  expect_identical(wire[["id_token"]][["level"]][["value"]], value)
  now <- floor(as.numeric(Sys.time()))
  claims <- list(iss = client@provider@issuer, aud = client@client_id,
    sub = "user", iat = now, exp = now + 300, nonce = "test-nonce", level = value)
  # Sign exact response JSON independently of the outbound encoder being fixed.
  sign <- function(json) {
    input <- paste(base64url_encode(charToRaw('{"alg":"RS256"}')),
      base64url_encode(charToRaw(json)), sep = ".")
    paste(input, base64url_encode(openssl::signature_create(
      charToRaw(input), hash = openssl::sha256, key = key)), sep = ".")
  }
  body <- ""
  content_type <- "application/json"
  local_mocked_bindings(req_with_retry = function(...) httr2::response(
    status = 200L, headers = list("content-type" = content_type), body = charToRaw(body)))
  for (returned in c(value, 1.2346)) {
    claims[["level"]] <- returned
    json <- as.character(jsonlite::toJSON(claims, auto_unbox = TRUE, digits = NA))
    token_set <- list(access_token = "synthetic", token_type = "Bearer", expires_in = 300,
      scope = "openid", id_token = sign(json))
    if (identical(returned, value)) {
      expect_no_error(verify_token_set(client, token_set, nonce = "test-nonce"))
    } else {
      expect_error(verify_token_set(client, token_set, nonce = "test-nonce"),
        class = "shinyOAuth_id_token_error")
    }
    for (content_type in c("application/json", "application/jwt")) {
      body <- if (content_type == "application/jwt") sign(json) else json
      if (identical(returned, value)) {
        expect_identical(fetch_userinfo(client, "synthetic")[["level"]], value)
      } else {
        expect_error(fetch_userinfo(client, "synthetic"), class = "shinyOAuth_userinfo_error")
      }
    }
  }
})
