# Tests for duplicate JWT header/payload member rejection.

make_raw_jwt <- function(header_json, payload_json) {
  paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(payload_json)),
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
        url = as.character(req[["url"]]),
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

test_that("duplicate guard rejects nested object members", {
  expect_error(
    shinyOAuth:::reject_duplicate_json_object_members(
      '{"cnf":{"jkt":"thumb-1","jkt":"thumb-2"}}',
      "JWT payload"
    ),
    regexp = "duplicate member name: jkt"
  )

  expect_error(
    shinyOAuth:::reject_duplicate_json_object_members(
      '{"keys":[{"kid":"key-1","kid":"key-2"}]}',
      "JWKS JSON"
    ),
    regexp = "duplicate member name: kid"
  )
})

test_that("duplicate guard handles long values without accumulating tokens", {
  long_value <- strrep("a", 20000)
  json <- paste0('{"ignored":"', long_value, '","alg":"RS256"}')
  expect_no_error(
    shinyOAuth:::reject_duplicate_json_object_members(json, "JWT payload")
  )

  duplicate_json <- paste0(
    '{"ignored":"',
    long_value,
    '","alg":"RS256","alg":"ES256"}'
  )
  expect_error(
    shinyOAuth:::reject_duplicate_json_object_members(
      duplicate_json,
      "JWT payload"
    ),
    regexp = "duplicate member name: alg"
  )

  expect_error(
    shinyOAuth:::reject_duplicate_json_object_members(
      '{"a":1,"\\u0061":2}',
      "JWT payload"
    ),
    regexp = "duplicate member name: a"
  )
})

test_that("duplicate guard bounds JSON nesting depth", {
  within_limit <- paste0(strrep("[", 64), "0", strrep("]", 64))
  over_limit <- paste0(strrep("[", 65), "0", strrep("]", 65))

  expect_no_error(
    shinyOAuth:::reject_duplicate_json_object_members(
      within_limit,
      "JWT payload"
    )
  )
  expect_error(
    shinyOAuth:::reject_duplicate_json_object_members(
      over_limit,
      "JWT payload"
    ),
    regexp = "maximum JSON nesting depth"
  )
})

test_that("JWT JOSE headers have an independent decoded-size limit", {
  header_json <- paste0(
    '{"alg":"RS256","ignored":"',
    strrep("a", 4096),
    '"}'
  )
  jwt <- make_raw_jwt(header_json, '{"sub":"user-1"}')

  expect_error(
    testthat::with_mocked_bindings(
      reject_duplicate_json_object_members = function(...) {
        stop("duplicate scanner was invoked")
      },
      shinyOAuth:::parse_jwt_header(jwt),
      .package = "shinyOAuth"
    ),
    regexp = "JWT header exceeds the maximum size"
  )

  jwe <- paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    "...."
  )
  expect_error(
    testthat::with_mocked_bindings(
      reject_duplicate_json_object_members = function(...) {
        stop("duplicate scanner was invoked")
      },
      shinyOAuth:::jwe_compact_parts(jwe),
      .package = "shinyOAuth"
    ),
    regexp = "JWE protected header exceeds the maximum size"
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
    regexp = "UserInfo JWT header could not be parsed",
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
    regexp = "UserInfo JWT payload could not be parsed",
    class = "shinyOAuth_userinfo_error"
  )
})
test_that("duplicate JARM issuer normalization stays fast at the callback limit", {
  padding <- paste(rep("x", 20000L), collapse = "")
  payload <- paste0('{"iss":"issuer","padding":"', padding, '","iss":"issuer"}')
  elapsed <- system.time(out <- shinyOAuth:::normalize_duplicate_jarm_iss_claim(payload))[["elapsed"]]
  expect_identical(jsonlite::fromJSON(out)$padding, padding)
  expect_equal(sum(names(jsonlite::fromJSON(out)) == "iss"), 1L)
  expect_lt(elapsed, 0.75)
  many <- paste0('{', paste(rep('"iss":"issuer"', 1500L), collapse = ','), '}')
  expect_identical(jsonlite::fromJSON(shinyOAuth:::normalize_duplicate_jarm_iss_claim(many)),
    list(iss = "issuer"))
})
