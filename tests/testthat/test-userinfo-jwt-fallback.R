# Tests for fail-open / fail-closed JWT UserInfo fallback paths
# when userinfo_signed_jwt_required = FALSE (default)
# These complement the existing test-userinfo-jwt.R tests which focus on
# the `userinfo_signed_jwt_required = TRUE` paths.

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

# ── Malformed JWT header fallback (require_signed = FALSE) ──────────────────

test_that("decode_userinfo_jwt falls through to unverified path for malformed header (default)", {
  # When userinfo_signed_jwt_required is FALSE (default) and the JWT header

  # cannot be parsed, the code falls through to the unverified
  # parse_jwt_payload path. This test documents the known fail-open behavior.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  # Build a JWT with a corrupt header but valid base64url payload.
  # parse_jwt_header will fail, but parse_jwt_payload can still succeed
  # because it only cares about part 2.
  claims <- list(sub = "user-badheader", name = "Bad Header")
  payload <- jsonlite::toJSON(claims, auto_unbox = TRUE)
  # Corrupt header: not valid JSON once decoded
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

  # Falls through to unverified path — documents the fail-open behavior
  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-badheader")
  expect_equal(result$name, "Bad Header")
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

# ── Unsupported algorithm fallback (require_signed = FALSE) ─────────────────

test_that("unsupported alg falls through to unverified path when require_signed = FALSE", {
  # HS256 is not in asymmetric_algs, so it skips JWKS verification.
  # Without require_signed, the JWT falls through to the unverified path.
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

  # Falls through to unverified path — documents the known gap
  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-hs256")
  expect_equal(result$name, "HS256 User")
})

test_that("unsupported alg (PS384 not in allowed_algs) falls through when not required", {
  # PS384 IS an asymmetric alg but NOT in this provider's allowed_algs
  # (RS256, ES256). The code checks alg %in% asymmetric_algs which uses the
  # intersection of provider allowed_algs + known asymmetric set. PS384 is in
  # the known asymmetric set but may or may not be in provider's allowed_algs.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"
  # make_test_provider sets allowed_algs = c("RS256", "ES256")
  # PS384 is asymmetric but not in allowed_algs

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
    # fetch_jwks should NOT be called because PS384 is not in allowed_algs
    # intersection, but just in case:
    fetch_jwks = function(...) stop("should not be called"),
    .package = "shinyOAuth"
  )

  # Falls through to unverified path because PS384 is NOT in the intersection
  # of provider allowed_algs and known asymmetric algs.
  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-ps384")
})

# ── alg=none with issuer set but require_signed = FALSE ─────────────────────

test_that("alg=none bypasses JWKS even when issuer is set (require_signed = FALSE)", {
  # This is the KNOWN vulnerability that userinfo_signed_jwt_required exists
  # to prevent. With issuer set but require_signed = FALSE, alg=none falls
  # through to the unverified path because "" (alg) is not in asymmetric_algs.
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
    # Must NOT call fetch_jwks for alg=none
    fetch_jwks = function(...) stop("should not be called"),
    .package = "shinyOAuth"
  )

  # Documents the fail-open behavior for alg=none without the flag.
  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "attacker")
})

# ── Empty/missing alg field in JWT header ───────────────────────────────────

test_that("JWT with missing alg field falls through when require_signed = FALSE", {
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

  # Falls through because alg is NULL -> toupper("") -> "" which is not
  # in asymmetric_algs
  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-no-alg")
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
    regexp = "alg=none|unsigned"
  )
})

# ── No issuer configured (JWKS bypass) ──────────────────────────────────────

test_that("RS256 JWT falls through to unverified when provider has no issuer", {
  # If issuer is NA, the JWKS verification block is skipped entirely,
  # even for asymmetric algorithms.
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
    # Must NOT call fetch_jwks when issuer is NA
    fetch_jwks = function(...) stop("should not be called"),
    .package = "shinyOAuth"
  )

  # Falls through because issuer is NA -> skips JWKS block entirely
  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-no-issuer-rs256")
})
