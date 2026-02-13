# Tests for fail-closed JWT UserInfo verification paths
# These verify that decode_userinfo_jwt always rejects unverified JWTs
# regardless of userinfo_signed_jwt_required (which only controls whether
# the response content-type must be application/jwt).

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

# ── Malformed JWT header (always rejected) ──────────────────────────────────

test_that("decode_userinfo_jwt rejects malformed header (fail-closed)", {
  # When the JWT header cannot be parsed, the JWT cannot be verified.
  # This must always be rejected regardless of userinfo_signed_jwt_required.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  claims <- list(sub = "user-badheader", name = "Bad Header")
  payload <- jsonlite::toJSON(claims, auto_unbox = TRUE)
  bad_header <- shinyOAuth:::b64url_encode(charToRaw("NOT{JSON"))
  good_payload <- shinyOAuth:::b64url_encode(charToRaw(as.character(payload)))
  jwt_body <- paste0(bad_header, ".", good_payload, ".")

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

  # Fail-closed: malformed header is always rejected
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "header could not be parsed"
  )
})

test_that("decode_userinfo_jwt errors for malformed header when require_signed = TRUE", {
  # Contrast: when signed JWT is required, a malformed header is rejected.
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  claims <- list(sub = "user-badheader-req", name = "Bad Header Req")
  payload <- jsonlite::toJSON(claims, auto_unbox = TRUE)
  bad_header <- shinyOAuth:::b64url_encode(charToRaw("NOT{JSON"))
  good_payload <- shinyOAuth:::b64url_encode(charToRaw(as.character(payload)))
  jwt_body <- paste0(bad_header, ".", good_payload, ".")

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

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "header could not be parsed"
  )
})

# ── Unsupported algorithm (always rejected) ─────────────────────────────────

test_that("unsupported alg (HS256) is rejected even when require_signed = FALSE", {
  # HS256 is not an asymmetric algorithm; always rejected.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  claims <- list(sub = "user-hs256", name = "HS256 User")
  jwt_body <- make_unsigned_jwt(claims, alg = "HS256")

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

  # Fail-closed: non-asymmetric algorithms are always rejected
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "not in provider.*allowed"
  )
})

test_that("unsupported alg (PS384 not in allowed_algs) is rejected", {
  # PS384 IS an asymmetric alg but NOT in this provider's allowed_algs
  # (RS256, ES256). Always rejected.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  claims <- list(sub = "user-ps384", name = "PS384 User")
  jwt_body <- make_unsigned_jwt(claims, alg = "PS384")

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

  # Fail-closed: algorithm not in allowed_algs is rejected
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "not in provider.*allowed"
  )
})

# ── alg=none (always rejected) ──────────────────────────────────────────────

test_that("alg=none is always rejected even when issuer is set and require_signed = FALSE", {
  # Previously this was a known fail-open vulnerability. Now fail-closed.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  claims <- list(sub = "attacker", name = "Attacker Alg None")
  jwt_body <- make_unsigned_jwt(claims, alg = "none")

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

  # Fail-closed: alg=none is always rejected
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "alg=none.*not allowed"
  )
})

# ── Empty/missing alg field in JWT header ───────────────────────────────────

test_that("JWT with missing alg field is rejected even when require_signed = FALSE", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  # Build a JWT header with no alg field
  header <- jsonlite::toJSON(list(typ = "JWT"), auto_unbox = TRUE)
  claims <- list(sub = "user-no-alg", name = "No Alg")
  payload <- jsonlite::toJSON(claims, auto_unbox = TRUE)
  jwt_body <- paste0(
    shinyOAuth:::b64url_encode(charToRaw(as.character(header))),
    ".",
    shinyOAuth:::b64url_encode(charToRaw(as.character(payload))),
    "."
  )

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

  # Fail-closed: missing alg is treated as alg=none and rejected
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "alg=none.*not allowed"
  )
})

test_that("JWT with missing alg field is rejected when require_signed = TRUE", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  header <- jsonlite::toJSON(list(typ = "JWT"), auto_unbox = TRUE)
  claims <- list(sub = "user-no-alg-req")
  payload <- jsonlite::toJSON(claims, auto_unbox = TRUE)
  jwt_body <- paste0(
    shinyOAuth:::b64url_encode(charToRaw(as.character(header))),
    ".",
    shinyOAuth:::b64url_encode(charToRaw(as.character(payload))),
    "."
  )

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

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "alg=none|unsigned|not allowed"
  )
})

# ── No issuer configured (always rejected) ──────────────────────────────────

test_that("RS256 JWT is rejected when provider has no issuer (fail-closed)", {
  # If issuer is NA, JWKS-based verification is impossible.
  # Must be rejected rather than falling through to unverified.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  # issuer is NA by default from make_test_provider(use_nonce = FALSE)

  claims <- list(sub = "user-no-issuer-rs256", name = "No Issuer RS256")

  # Build a JWT with RS256 header but invalid signature (just faking it)
  header <- jsonlite::toJSON(
    list(alg = "RS256", typ = "JWT"),
    auto_unbox = TRUE
  )
  payload <- jsonlite::toJSON(claims, auto_unbox = TRUE)
  jwt_body <- paste0(
    shinyOAuth:::b64url_encode(charToRaw(as.character(header))),
    ".",
    shinyOAuth:::b64url_encode(charToRaw(as.character(payload))),
    ".",
    "fake-sig"
  )

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

  # Fail-closed: no issuer means no JWKS verification possible
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "issuer.*not configured"
  )
})
