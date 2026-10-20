test_that("numeric claims survive ordinary parameters and every asymmetric JAR algorithm", {
  # Decimal literals can round differently when R has no extended-precision
  # long double (e.g. macOS ARM). Fix the intended binary64 values exactly.
  value <- 0x1.3c0ca428c59fbp0
  tiny <- 0x1.bff2ee48e053p-333
  claims <- list(
    id_token = list(
      level = list(value = value),
      choices = list(values = c(value, tiny)),
      nested = list(value = list(level = 1000000000000001, small = -0.123456789))
    ),
    userinfo = list(level = list(value = value))
  )
  literal <- paste0(
    '{"id_token":{"level":{"value":1.2345678901234567},',
    '"choices":{"values":[1.2345678901234567,1e-100]},',
    '"nested":{"value":{"level":1000000000000001,"small":-0.123456789}}},',
    '"userinfo":{"level":{"value":1.2345678901234567}}}'
  )
  expected <- jsonlite::parse_json(literal, simplifyVector = FALSE)
  # Explicit JSON must also survive the second serialization inside JAR.
  inputs <- list(claims, literal)
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
        expect_identical(decoded[["claims"]], jsonlite::fromJSON(literal))
      }
    }
  }
})

test_that("strict ID token and UserInfo validation accept the exact requested number", {
  value <- 1000000000000001
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
  for (returned in c(value, 1000000000000002)) {
    claims[["level"]] <- returned
    json <- as.character(jsonlite::toJSON(claims, auto_unbox = TRUE, digits = 17))
    # This expectation is independent of the package's outbound serializer.
    expect_identical(jsonlite::parse_json(json)[["level"]], returned)
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

test_that("exact claim comparison retains numeric types, precision and structure", {
  pairs <- list(
    c(1000000000000001, 1000000000000002),
    # These adjacent binary64 values must stay distinct on every platform.
    c(0x1.3c0ca428c59fbp0, 0x1.3c0ca428c59fcp0)
  )
  for (pair in pairs) {
    expected <- pair[[1]]
    different <- pair[[2]]
    expect_false(identical(expected, different))
    for (wrap in list(identity, function(x) list(z = list(x, TRUE), a = "id"))) {
      expect_true(claim_matches_requested_values(wrap(expected), list(wrap(expected))))
      expect_false(claim_matches_requested_values(wrap(different), list(wrap(expected))))
      expect_true(claim_matches_requested_values(wrap(expected),
        list(wrap(different), wrap(expected))))
      expect_false(claim_matches_requested_values(wrap("1"), list(wrap(1))))
    }
    for (target in c("id_token", "userinfo")) {
      client <- make_test_client(use_nonce = TRUE, claims_validation = "strict",
        claims = setNames(list(list(level = list(values = c(expected, -expected)))), target))
      expect_no_error(validate_essential_claims(client, list(level = expected), target))
      expect_no_error(validate_essential_claims(client, list(level = -expected), target))
      expect_error(validate_essential_claims(client, list(level = different), target),
        "Requested claim values not satisfied")
    }
  }
  expect_true(claim_matches_requested_values(1L, list(1)))
  expect_true(claim_matches_requested_values(-0, list(0)))
  expect_false(claim_matches_requested_values(list(), list(setNames(list(), character()))))
})

test_that("HMAC JWTs preserve independently specified numeric claims", {
  expected <- jsonlite::parse_json(
    '{"id":1000000000000001,"decimal":1.2345678901234567,"tiny":1e-100}'
  )
  for (size in c(256L, 384L, 512L)) {
    jwt <- encode_hmac_jwt_with_header(expected, strrep("s", 64),
      list(typ = "JWT", alg = paste0("HS", size)), size)
    expect_identical(parse_jwt_payload(jwt), expected)
  }
})

test_that("numeric constraints outside the supported range fail before authorization", {
  for (value in list(9007199254740992, -9007199254740992, Inf, NaN, NA_real_)) {
    expect_error(claims_request_json(list(id_token = list(id = list(value = value)))),
      "numeric constraints must be finite")
  }
  for (literal in c("9007199254740993", "-9007199254740993", "1e400")) {
    expect_error(claims_request_json(paste0(
      '{"id_token":{"id":{"value":', literal, '}}}'
    )), "numeric constraints must be finite")
  }
  expect_identical(jsonlite::parse_json(claims_request_json(list(
    id_token = list(id = list(value = 9007199254740991))
  )))[["id_token"]][["id"]][["value"]], 9007199254740991)
  expect_no_error(claims_request_json(
    '{"id_token":{"id":{"value":"9007199254740993"}}}'
  ))
})
