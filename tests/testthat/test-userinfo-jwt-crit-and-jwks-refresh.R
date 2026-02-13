# Tests for UserInfo JWT crit header validation (RFC 7515 §4.1.11)
# and JWKS refresh-on-kid-miss behaviour.

# Helper: build a JWT with an arbitrary header (unsigned, for crit tests)
make_jwt_with_header <- function(header_list, payload_list) {
  header <- jsonlite::toJSON(header_list, auto_unbox = TRUE)
  payload <- jsonlite::toJSON(payload_list, auto_unbox = TRUE)
  paste0(
    shinyOAuth:::b64url_encode(charToRaw(as.character(header))),
    ".",
    shinyOAuth:::b64url_encode(charToRaw(as.character(payload))),
    "."
  )
}

# Helper: build an RSA-signed JWT using jose
make_signed_jwt_h <- function(payload_list, key, kid = NULL) {
  header <- list(typ = "JWT", alg = "RS256")
  if (!is.null(kid)) {
    header$kid <- kid
  }
  clm <- do.call(jose::jwt_claim, payload_list)
  jose::jwt_encode_sig(clm, key = key, header = header)
}

# Helper: mock req_with_retry returning an application/jwt response
mock_jwt_response <- function(jwt_body) {
  function(req) {
    httr2::response(
      url = as.character(req$url),
      status = 200,
      headers = list("content-type" = "application/jwt"),
      body = charToRaw(jwt_body)
    )
  }
}

# Helper: make a client suitable for userinfo JWT tests
make_userinfo_client <- function() {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"
  cli
}

# --- crit header tests -------------------------------------------------------

test_that("UserInfo JWT with unsupported crit header is rejected", {
  cli <- make_userinfo_client()

  claims <- list(sub = "user-1", name = "User One")
  jwt_body <- make_jwt_with_header(
    list(alg = "RS256", crit = list("exp")),
    claims
  )

  testthat::local_mocked_bindings(
    req_with_retry = mock_jwt_response(jwt_body),
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    regexp = "unsupported critical header parameter",
    class = "shinyOAuth_userinfo_error"
  )
})

test_that("UserInfo JWT with multiple unsupported crit entries is rejected", {
  cli <- make_userinfo_client()

  claims <- list(sub = "user-2", name = "User Two")
  jwt_body <- make_jwt_with_header(
    list(alg = "RS256", crit = list("b64", "example.com:custom")),
    claims
  )

  testthat::local_mocked_bindings(
    req_with_retry = mock_jwt_response(jwt_body),
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    regexp = "unsupported critical header parameter",
    class = "shinyOAuth_userinfo_error"
  )
})

test_that("UserInfo JWT with malformed crit (number) is rejected", {
  cli <- make_userinfo_client()

  claims <- list(sub = "user-3", name = "User Three")
  jwt_body <- make_jwt_with_header(
    list(alg = "RS256", crit = 42),
    claims
  )

  testthat::local_mocked_bindings(
    req_with_retry = mock_jwt_response(jwt_body),
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    regexp = "crit header must be a non-empty character vector",
    class = "shinyOAuth_userinfo_error"
  )
})

test_that("UserInfo JWT with malformed crit (empty array) is rejected", {
  cli <- make_userinfo_client()

  claims <- list(sub = "user-4", name = "User Four")
  jwt_body <- make_jwt_with_header(
    list(alg = "RS256", crit = list()),
    claims
  )

  testthat::local_mocked_bindings(
    req_with_retry = mock_jwt_response(jwt_body),
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    regexp = "crit header must be a non-empty character vector",
    class = "shinyOAuth_userinfo_error"
  )
})

test_that("UserInfo signed JWT without crit header still passes", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-crit-ok"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-ok",
    name = "OK User",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt_h(claims, key, kid = "kid-crit-ok")

  cli <- make_userinfo_client()

  testthat::local_mocked_bindings(
    req_with_retry = mock_jwt_response(jwt_body),
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-ok")
})

# --- JWKS refresh-on-kid-miss tests ------------------------------------------

test_that("UserInfo JWT triggers JWKS refresh when kid misses initially", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "rotated-kid"
  jwk$use <- "sig"

  # First JWKS: empty (simulates stale cache without the new kid)
  stale_jwks <- list(keys = list())
  # Second JWKS: contains the rotated key

  fresh_jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-rotated",
    name = "Rotated User",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt_h(claims, key, kid = "rotated-kid")

  cli <- make_userinfo_client()

  fetch_call_count <- 0L
  testthat::local_mocked_bindings(
    req_with_retry = mock_jwt_response(jwt_body),
    fetch_jwks = function(...) {
      fetch_call_count <<- fetch_call_count + 1L
      args <- list(...)
      if (isTRUE(args$force_refresh)) {
        fresh_jwks
      } else {
        stale_jwks
      }
    },
    jwks_force_refresh_allowed = function(...) TRUE,
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-rotated")
  # Should have fetched twice: once stale, once forced refresh
  expect_equal(fetch_call_count, 2L)
})

test_that("UserInfo JWT fails closed when JWKS refresh is rate-limited", {
  key <- openssl::rsa_keygen(2048)

  claims <- list(sub = "user-rl", name = "Rate-limited User")
  jwt_body <- make_signed_jwt_h(claims, key, kid = "unknown-kid")

  cli <- make_userinfo_client()

  # JWKS never contains the right kid, and refresh is rate-limited
  stale_jwks <- list(keys = list())
  testthat::local_mocked_bindings(
    req_with_retry = mock_jwt_response(jwt_body),
    fetch_jwks = function(...) stale_jwks,
    jwks_force_refresh_allowed = function(...) FALSE,
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "no compatible keys"
  )
})

test_that("UserInfo JWT does not refresh JWKS when kid is NULL", {
  # When there's no kid in the header, no refresh-on-miss should happen
  key <- openssl::rsa_keygen(2048)

  claims <- list(sub = "user-no-kid", name = "No Kid User")
  # Build a JWT without kid — make_signed_jwt_h with kid=NULL
  jwt_body <- make_signed_jwt_h(claims, key, kid = NULL)

  cli <- make_userinfo_client()

  # JWKS is empty — should fail without attempting refresh
  stale_jwks <- list(keys = list())
  refresh_called <- FALSE
  testthat::local_mocked_bindings(
    req_with_retry = mock_jwt_response(jwt_body),
    fetch_jwks = function(...) stale_jwks,
    jwks_force_refresh_allowed = function(...) {
      refresh_called <<- TRUE
      TRUE
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "no compatible keys"
  )
  # jwks_force_refresh_allowed should NOT have been called (no kid)
  expect_false(refresh_called)
})
