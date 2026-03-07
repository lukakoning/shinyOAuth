# Tests for mandatory 'sub' claim in OIDC UserInfo responses (OIDC Core §5.3)

# --- JSON path: get_userinfo() with OIDC provider (issuer configured) --------

test_that("get_userinfo rejects JSON response missing sub for OIDC provider", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(name = "No Sub User", email = "nosub@example.com"),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "sub.*claim"
  )
})

test_that("get_userinfo rejects JSON response with empty sub for OIDC provider", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(sub = "", name = "Empty Sub"),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "sub.*claim"
  )
})

test_that("get_userinfo accepts JSON response with sub for OIDC provider", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(sub = "user-123", name = "Valid User"),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-123")
})

test_that("get_userinfo allows missing sub for non-OIDC provider (no issuer)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  # issuer is already NA_character_ from make_test_client defaults

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(login = "octocat", name = "GitHub User"),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$login, "octocat")
})

# --- JWT path: validate_signed_userinfo_claims() sub check --------------------

test_that("validate_signed_userinfo_claims rejects missing sub", {
  expect_error(
    shinyOAuth:::validate_signed_userinfo_claims(
      claims = list(iss = "https://issuer.example.com", aud = "client-id"),
      expected_issuer = "https://issuer.example.com",
      expected_client_id = "client-id"
    ),
    class = "shinyOAuth_userinfo_error",
    regexp = "sub.*claim"
  )
})

test_that("validate_signed_userinfo_claims rejects empty sub", {
  expect_error(
    shinyOAuth:::validate_signed_userinfo_claims(
      claims = list(
        sub = "",
        iss = "https://issuer.example.com",
        aud = "client-id"
      ),
      expected_issuer = "https://issuer.example.com",
      expected_client_id = "client-id"
    ),
    class = "shinyOAuth_userinfo_error",
    regexp = "sub.*claim"
  )
})

test_that("validate_signed_userinfo_claims accepts valid sub", {
  expect_invisible(
    shinyOAuth:::validate_signed_userinfo_claims(
      claims = list(
        sub = "user-42",
        iss = "https://issuer.example.com",
        aud = "client-id"
      ),
      expected_issuer = "https://issuer.example.com",
      expected_client_id = "client-id"
    )
  )
})

# --- Full signed JWT path through get_userinfo() -----------------------------

test_that("get_userinfo rejects signed JWT missing sub for OIDC provider", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "test-kid-sub"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  # Claims without sub
  claims <- list(
    name = "No Sub JWT User",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  header <- list(typ = "JWT", alg = "RS256", kid = "test-kid-sub")
  clm <- do.call(jose::jwt_claim, claims)
  jwt_body <- jose::jwt_encode_sig(clm, key = key, header = header)

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
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
    regexp = "sub.*claim"
  )
})
