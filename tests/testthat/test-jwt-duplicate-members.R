# Tests for duplicate JWT header/payload member rejection.

make_raw_jwt <- function(header_json, payload_json) {
  paste0(
    shinyOAuth:::b64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::b64url_encode(charToRaw(payload_json)),
    "."
  )
}

duplicate_id_token_client <- function() {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  cli@provider@id_token_validation <- TRUE
  cli@provider@allowed_algs <- "RS256"
  cli
}

duplicate_userinfo_client <- function() {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"
  cli@provider@allowed_algs <- c("RS256", "ES256")
  cli
}

duplicate_userinfo_response <- function(cli, jwt_body, verify_payload = FALSE) {
  bindings <- list(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    }
  )

  if (isTRUE(verify_payload)) {
    bindings$fetch_jwks <- function(...) list(keys = list("dummy"))
    bindings$select_candidate_jwks <- function(...) list("dummy")
    bindings$filter_jwks_for_alg <- function(keys, alg) keys
    bindings$jwk_to_pubkey <- function(jwk) "dummy"
    bindings$verify_jws_signature_no_time <- function(jwt, key, alg) TRUE
  }

  do.call(
    testthat::with_mocked_bindings,
    c(
      bindings,
      list(
        .package = "shinyOAuth",
        quote(get_userinfo(cli, token = "access-token"))
      )
    )
  )
}

test_that("validate_id_token rejects duplicate JOSE header members", {
  cli <- duplicate_id_token_client()
  jwt <- make_raw_jwt(
    '{"alg":"RS256","alg":"RS256"}',
    '{"iss":"https://issuer.example.com","aud":"abc","sub":"user-1","iat":1700000000,"exp":1700000120}'
  )

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  expect_error(
    shinyOAuth:::validate_id_token(cli, jwt),
    regexp = "duplicate member name: alg",
    class = "shinyOAuth_id_token_error"
  )
})

test_that("validate_id_token rejects duplicate claim members", {
  cli <- duplicate_id_token_client()
  jwt <- make_raw_jwt(
    '{"alg":"RS256"}',
    '{"iss":"https://issuer.example.com","iss":"https://issuer.example.com","aud":"abc","sub":"user-1","iat":1700000000,"exp":1700000120}'
  )

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  expect_error(
    shinyOAuth:::validate_id_token(cli, jwt),
    regexp = "duplicate member name: iss",
    class = "shinyOAuth_id_token_error"
  )
})

test_that("get_userinfo rejects duplicate JOSE header members", {
  cli <- duplicate_userinfo_client()
  jwt <- make_raw_jwt(
    '{"alg":"RS256","alg":"RS256"}',
    '{"iss":"https://issuer.example.com","aud":"abc","sub":"user-1","name":"User One"}'
  )

  expect_error(
    duplicate_userinfo_response(cli, jwt),
    regexp = "duplicate member name: alg",
    class = "shinyOAuth_userinfo_error"
  )
})

test_that("get_userinfo rejects duplicate claim members", {
  cli <- duplicate_userinfo_client()
  jwt <- make_raw_jwt(
    '{"alg":"RS256"}',
    '{"iss":"https://issuer.example.com","aud":"abc","sub":"user-1","sub":"user-2","name":"User One"}'
  )

  expect_error(
    duplicate_userinfo_response(cli, jwt, verify_payload = TRUE),
    regexp = "duplicate member name: sub",
    class = "shinyOAuth_userinfo_error"
  )
})
