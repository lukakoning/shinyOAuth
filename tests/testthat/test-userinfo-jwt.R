# Tests for JWT-encoded UserInfo response support (OIDC Core §5.3.2)

# Helper: build a minimal unsigned JWT (header.payload.signature)
make_unsigned_jwt <- function(payload_list, alg = "none") {
  header <- jsonlite::toJSON(list(alg = alg, typ = "JWT"), auto_unbox = TRUE)
  payload <- jsonlite::toJSON(payload_list, auto_unbox = TRUE)
  paste0(
    shinyOAuth:::b64url_encode(charToRaw(as.character(header))),
    ".",
    shinyOAuth:::b64url_encode(charToRaw(as.character(payload))),
    "."
  )
}

# Helper: build an RSA-signed JWT using jose
make_signed_jwt <- function(payload_list, key, kid = NULL) {
  header <- list(typ = "JWT", alg = "RS256")
  if (!is.null(kid)) {
    header$kid <- kid
  }
  clm <- do.call(jose::jwt_claim, payload_list)
  jose::jwt_encode_sig(clm, key = key, header = header)
}

test_that("get_userinfo decodes JWT response with application/jwt content-type", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  claims <- list(
    sub = "user-123",
    name = "Test User",
    email = "test@example.com"
  )
  jwt_body <- make_unsigned_jwt(claims)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-123")
  expect_equal(result$name, "Test User")
  expect_equal(result$email, "test@example.com")
})

test_that("get_userinfo still works with application/json content-type", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  claims <- list(sub = "user-456", name = "JSON User")

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(claims, auto_unbox = TRUE))
      )
    },
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-456")
  expect_equal(result$name, "JSON User")
})

test_that("get_userinfo verifies signed JWT userinfo against JWKS", {
  # Generate an RSA key pair for signing
  key <- openssl::rsa_keygen(2048)
  pub <- as.list(openssl::read_key(openssl::write_pem(key), der = FALSE))

  # Build JWK for the public key
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "test-kid-1"
  jwk$use <- "sig"

  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-sig",
    name = "Signed User",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "test-kid-1")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-sig")
  expect_equal(result$name, "Signed User")
})

test_that("get_userinfo falls back to unverified JWT when JWKS verification fails", {
  # Generate two different RSA keys — sign with one, serve JWKS with other
  sign_key <- openssl::rsa_keygen(2048)
  wrong_key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(wrong_key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "wrong-kid"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(sub = "user-fallback", name = "Fallback User")
  jwt_body <- make_signed_jwt(claims, sign_key, kid = "test-kid-2")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  # Should succeed (unverified fallback) but emit a warning
  expect_warning(
    result <- get_userinfo(cli, token = "access-token"),
    regexp = "signature could not be verified"
  )
  expect_equal(result$sub, "user-fallback")
  expect_equal(result$name, "Fallback User")
})

test_that("get_userinfo errors when signed JWT has wrong issuer", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-iss"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-iss",
    iss = "https://wrong-issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-iss")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "iss.*does not match|issuer"
  )
})

test_that("get_userinfo errors when signed JWT has wrong audience", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-aud"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-aud",
    iss = "https://issuer.example.com",
    aud = "wrong-client-id"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-aud")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "aud.*does not include|client_id"
  )
})

test_that("get_userinfo errors when signed JWT is missing iss claim", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-no-iss"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(sub = "user-no-iss", aud = "abc")
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-no-iss")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "missing.*iss"
  )
})

test_that("get_userinfo errors when signed JWT is missing aud claim", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-no-aud"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(sub = "user-no-aud", iss = "https://issuer.example.com")
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-no-aud")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "missing.*aud"
  )
})

test_that("get_userinfo errors on encrypted JWT (JWE)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  # JWE compact serialization has 5 dot-separated parts
  jwe_body <- paste(
    rep("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ", 5),
    collapse = "."
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwe_body)
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "encrypted JWT|JWE"
  )
})

test_that("get_userinfo errors on invalid JWT in application/jwt response", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw("not-a-valid-jwt")
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "parse|JWT|jwt"
  )
})

test_that("get_userinfo emits audit event on JWT parse failure", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1]] <<- event
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw("bad.jwt")
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error"
  )

  types <- vapply(events, function(e) e$type %||% NA_character_, character(1))
  expect_true(any(types == "audit_userinfo"))

  ui_events <- events[types == "audit_userinfo"]
  statuses <- vapply(
    ui_events,
    function(e) e$status %||% NA_character_,
    character(1)
  )
  expect_true(any(statuses == "parse_error"))
})

test_that("get_userinfo handles application/jwt with charset parameter", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  claims <- list(sub = "user-charset", name = "Charset User")
  jwt_body <- make_unsigned_jwt(claims)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt; charset=utf-8"),
        body = charToRaw(jwt_body)
      )
    },
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-charset")
  expect_equal(result$name, "Charset User")
})

test_that("decode_userinfo_jwt works without issuer (no JWKS verification)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # issuer is NA by default in make_test_provider (when use_nonce = FALSE)

  claims <- list(sub = "user-no-issuer", name = "No Issuer User")
  jwt_body <- make_unsigned_jwt(claims)

  resp <- httr2::response(
    url = "https://example.com/userinfo",
    status = 200,
    headers = list("content-type" = "application/jwt"),
    body = charToRaw(jwt_body)
  )

  result <- shinyOAuth:::decode_userinfo_jwt(resp, cli)
  expect_equal(result$sub, "user-no-issuer")
  expect_equal(result$name, "No Issuer User")
})
