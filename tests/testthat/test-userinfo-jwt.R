# Tests for JWT-encoded UserInfo response support (OIDC Core §5.3.2)

# Helper: build a minimal unsigned JWT (header.payload.signature)
make_unsigned_jwt <- function(payload_list, alg = "none") {
  header <- jsonlite::toJSON(list(alg = alg, typ = "JWT"), auto_unbox = TRUE)
  payload <- jsonlite::toJSON(payload_list, auto_unbox = TRUE)
  paste0(
    shinyOAuth:::base64url_encode(charToRaw(as.character(header))),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(as.character(payload))),
    "."
  )
}

# Helper: build an RSA-signed JWT using jose
make_signed_jwt <- function(
  payload_list,
  key,
  kid = NULL,
  alg = "RS256",
  typ = "JWT"
) {
  header <- list(typ = typ, alg = alg)
  if (!is.null(kid)) {
    header$kid <- kid
  }
  clm <- do.call(jose::jwt_claim, payload_list)
  jose::jwt_encode_sig(clm, key = key, header = header)
}

make_eddsa_signed_jwt <- function(
  payload_list,
  keypair,
  kid = NULL,
  typ = "JWT"
) {
  header <- list(alg = "EdDSA", typ = typ)
  if (!is.null(kid)) {
    header$kid <- kid
  }

  header_json <- jsonlite::toJSON(header, auto_unbox = TRUE, null = "null")
  payload_json <- jsonlite::toJSON(
    payload_list,
    auto_unbox = TRUE,
    null = "null"
  )
  signing_input <- paste0(
    shinyOAuth:::base64url_encode(charToRaw(as.character(header_json))),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(as.character(payload_json)))
  )
  secret <- if (!is.null(keypair$key)) keypair$key else keypair$secretkey
  sig <- sodium::signature(charToRaw(signing_input), secret)

  paste0(signing_input, ".", shinyOAuth:::base64url_encode(sig))
}

test_that("get_userinfo rejects unsigned JWT response (alg=none) by default", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  claims <- list(
    sub = "user-123",
    name = "Test User",
    email = "test@example.com"
  )
  jwt_body <- make_unsigned_jwt(claims)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    .package = "shinyOAuth"
  )

  # alg=none is always rejected — verification is fail-closed
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "alg=none.*not allowed"
  )
})

test_that("get_userinfo still works with application/json content-type", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  claims <- list(sub = "user-456", name = "JSON User")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
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

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-sig")
  expect_equal(result$name, "Signed User")
})

test_that("get_userinfo verifies signed EdDSA JWT userinfo against JWKS", {
  testthat::skip_if_not_installed("sodium")

  keypair <- NULL
  if ("signature_keygen" %in% getNamespaceExports("sodium")) {
    keypair <- try(sodium::signature_keygen(), silent = TRUE)
  } else if ("signature_keypair" %in% getNamespaceExports("sodium")) {
    keypair <- try(sodium::signature_keypair(), silent = TRUE)
  }
  if (inherits(keypair, "try-error") || is.null(keypair)) {
    testthat::skip("Ed25519 key generation not supported on this platform")
  }

  kid <- "test-ed25519-1"
  jwks <- list(
    keys = list(list(
      kty = "OKP",
      crv = "Ed25519",
      x = shinyOAuth:::base64url_encode(keypair$pubkey),
      kid = kid,
      use = "sig"
    ))
  )

  claims <- list(
    sub = "user-ed25519",
    name = "EdDSA User",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_eddsa_signed_jwt(claims, keypair, kid = kid)

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"
  cli@provider@allowed_algs <- c("EdDSA")

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

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-ed25519")
  expect_equal(result$name, "EdDSA User")
})

test_that("get_userinfo rejects signed JWT userinfo with invalid typ header", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-invalid-typ"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-invalid-typ",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(
    claims,
    key,
    kid = "kid-invalid-typ",
    typ = "JWE"
  )

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
    regexp = "typ header invalid"
  )
})

test_that("get_userinfo accepts signed JWT with valid temporal claims", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "test-kid-time-valid"
  jwk$use <- "sig"

  jwks <- list(keys = list(jwk))
  now <- floor(as.numeric(Sys.time()))

  claims <- list(
    sub = "user-time-valid",
    name = "Signed Timely User",
    iss = "https://issuer.example.com",
    aud = "abc",
    iat = now - 120,
    nbf = now - 60,
    exp = now + 300
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "test-kid-time-valid")

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

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-time-valid")
  expect_equal(result$name, "Signed Timely User")
})

test_that("get_userinfo honors provider leeway above 60 seconds", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-leeway-over-60"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))
  now <- floor(as.numeric(Sys.time()))

  claims <- list(
    sub = "user-leeway-over-60",
    name = "Leeway User",
    iss = "https://issuer.example.com",
    aud = "abc",
    exp = now - 90,
    iat = now - 300
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-leeway-over-60")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"
  cli@provider@leeway <- 120

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

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-leeway-over-60")
  expect_equal(result$name, "Leeway User")
})

test_that("get_userinfo accepts signed JWT exactly at leeway boundaries", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-leeway-boundary"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  fixed_now <- as.POSIXct("2024-01-01 00:00:00", tz = "UTC")
  now <- as.numeric(fixed_now)

  claims <- list(
    sub = "user-leeway-boundary",
    name = "Boundary User",
    iss = "https://issuer.example.com",
    aud = "abc",
    exp = now - 30,
    iat = now + 30,
    nbf = now + 30
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-leeway-boundary")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"
  cli@provider@leeway <- 30

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

  result <- testthat::with_mocked_bindings(
    Sys.time = function() fixed_now,
    .package = "base",
    get_userinfo(cli, token = "access-token")
  )

  expect_equal(result$sub, "user-leeway-boundary")
  expect_equal(result$name, "Boundary User")
})

test_that("get_userinfo can require exp on signed JWT userinfo", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-required-exp"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    sub = "user-required-exp",
    iss = "https://issuer.example.com",
    aud = "abc",
    exp = now + 300
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-required-exp")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_jwt_required_temporal_claims = "exp"
  )
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

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-required-exp")
})

test_that("get_userinfo errors when signed JWT is missing required exp", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-missing-required-exp"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-missing-exp",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-missing-required-exp")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_jwt_required_temporal_claims = "exp"
  )
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
    regexp = "missing required temporal claim\\(s\\): exp"
  )
})

test_that("oauth_client rejects invalid required UserInfo JWT temporal claims", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = character(0),
      state_store = cachem::cache_mem(max_age = 600),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      userinfo_jwt_required_temporal_claims = c("exp", "foo")
    ),
    regexp = "invalid userinfo_jwt_required_temporal_claims"
  )
})

test_that("get_userinfo errors when signed JWT is expired", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-expired"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    sub = "user-expired",
    iss = "https://issuer.example.com",
    aud = "abc",
    exp = now - 3600
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-expired")

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
    regexp = "expired"
  )
})

test_that("get_userinfo errors when signed JWT has iat in the future", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-iat-future"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    sub = "user-iat-future",
    iss = "https://issuer.example.com",
    aud = "abc",
    iat = now + 3600,
    exp = now + 7200
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-iat-future")

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
    regexp = "issued in the future"
  )
})

test_that("get_userinfo errors when signed JWT is not yet valid", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-nbf-future"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    sub = "user-nbf-future",
    iss = "https://issuer.example.com",
    aud = "abc",
    nbf = now + 3600,
    exp = now + 7200
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-nbf-future")

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
    regexp = "not yet valid"
  )
})

test_that("get_userinfo rejects signed JWT when JWK alg mismatches header alg", {
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "test-kid-alg-mismatch"
  jwk$use <- "sig"
  jwk$alg <- "RS512"

  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-sig",
    name = "Signed User",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "test-kid-alg-mismatch")

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
    regexp = "no compatible keys"
  )
})

test_that("get_userinfo errors when JWKS has no compatible keys for signed JWT", {
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

  # Must fail closed: no unverified fallback for signed JWTs
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "no compatible keys"
  )
})

test_that("get_userinfo errors when JWKS fetch fails for signed JWT", {
  sign_key <- openssl::rsa_keygen(2048)

  claims <- list(sub = "user-fetch-fail", name = "Fetch Fail User")
  jwt_body <- make_signed_jwt(claims, sign_key, kid = "test-kid-3")

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
    fetch_jwks = function(...) stop("network error"),
    .package = "shinyOAuth"
  )

  # Must fail closed: JWKS fetch failure must not allow unverified fallback
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "JWKS fetch failed"
  )
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
    req_with_retry = function(req, ...) {
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
    req_with_retry = function(req, ...) {
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
    req_with_retry = function(req, ...) {
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

test_that("get_userinfo handles application/jwt with charset parameter (signed)", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-charset"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  claims <- list(
    sub = "user-charset",
    name = "Charset User",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-charset")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt; charset=utf-8"),
        body = charToRaw(jwt_body)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-charset")
  expect_equal(result$name, "Charset User")
})

test_that("decode_userinfo_jwt rejects JWT without issuer configured", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # issuer is NA by default in make_test_provider (when use_nonce = FALSE)

  # Even a signed JWT (RS256 header) must be rejected when issuer is missing
  claims <- list(sub = "user-no-issuer", name = "No Issuer User")
  jwt_body <- make_unsigned_jwt(claims, alg = "RS256")

  resp <- httr2::response(
    url = "https://example.com/userinfo",
    status = 200,
    headers = list("content-type" = "application/jwt"),
    body = charToRaw(jwt_body)
  )

  expect_error(
    shinyOAuth:::decode_userinfo_jwt(resp, cli),
    class = "shinyOAuth_userinfo_error",
    regexp = "issuer.*not configured"
  )
})

# ── userinfo_signed_jwt_required tests ──────────────────────────────────────

test_that("signed JWT required: non-JWT response fails with clear error + audit", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1]] <<- event
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(sub = "user-json", name = "JSON User"),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "not application/jwt.*signed JWT is required"
  )

  # Verify audit event
  types <- vapply(events, function(e) e$type %||% NA_character_, character(1))
  ui_events <- events[types == "audit_userinfo"]
  statuses <- vapply(
    ui_events,
    function(e) e$status %||% NA_character_,
    character(1)
  )
  expect_true("userinfo_not_jwt" %in% statuses)
})

test_that("signed JWT required: alg=none JWT fails with clear error + audit", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1]] <<- event
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  claims <- list(sub = "user-none-alg", name = "None Alg User")
  jwt_body <- make_unsigned_jwt(claims, alg = "none")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
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
    regexp = "alg=none.*not allowed"
  )

  types <- vapply(events, function(e) e$type %||% NA_character_, character(1))
  ui_events <- events[types == "audit_userinfo"]
  statuses <- vapply(
    ui_events,
    function(e) e$status %||% NA_character_,
    character(1)
  )
  expect_true("userinfo_jwt_unsigned" %in% statuses)
})

test_that("signed JWT required: alg not in allowed_algs fails + audit", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )
  # allowed_algs from make_test_provider is c("RS256", "ES256")

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1]] <<- event
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  # Build JWT with HS256 (not in allowed_algs asymmetric subset)
  claims <- list(sub = "user-hs256", name = "HS256 User")
  jwt_body <- make_unsigned_jwt(claims, alg = "HS256")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
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
    regexp = "not in provider.*allowed"
  )

  types <- vapply(events, function(e) e$type %||% NA_character_, character(1))
  ui_events <- events[types == "audit_userinfo"]
  statuses <- vapply(
    ui_events,
    function(e) e$status %||% NA_character_,
    character(1)
  )
  expect_true("userinfo_jwt_alg_rejected" %in% statuses)
})

test_that("signed JWT required: valid signed JWT succeeds", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-req-sig"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-signed-ok",
    name = "Signed OK",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-req-sig")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

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

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-signed-ok")
  expect_equal(result$name, "Signed OK")
})

test_that("signed JWT required: JWKS fetch failure still blocks", {
  sign_key <- openssl::rsa_keygen(2048)
  claims <- list(
    sub = "user-fetch-fail-req",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, sign_key, kid = "kid-fetch-fail")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    fetch_jwks = function(...) stop("network error"),
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "JWKS fetch failed"
  )
})

test_that("unsigned JWT is now rejected even without required flag (fail-closed)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  claims <- list(sub = "user-compat", name = "Compat User")
  jwt_body <- make_unsigned_jwt(claims)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    .package = "shinyOAuth"
  )

  # alg=none is always rejected — no longer falls through to unverified path
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "alg=none.*not allowed"
  )
})

test_that("signed JWT NOT required: JSON response still works (backward compat)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  claims <- list(sub = "user-json-compat", name = "JSON Compat")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
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
  expect_equal(result$sub, "user-json-compat")
  expect_equal(result$name, "JSON Compat")
})

test_that("OAuthProvider validator: userinfo_signed_jwt_required without userinfo_required fails", {
  expect_error(
    oauth_provider(
      name = "test",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      issuer = "https://example.com",
      userinfo_url = "https://example.com/userinfo",
      userinfo_required = FALSE,
      userinfo_signed_jwt_required = TRUE
    ),
    regexp = "userinfo_signed_jwt_required.*userinfo_required"
  )
})

test_that("OAuthProvider validator: userinfo_signed_jwt_required without issuer fails", {
  expect_error(
    oauth_provider(
      name = "test",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      issuer = NA_character_,
      userinfo_url = "https://example.com/userinfo",
      userinfo_required = TRUE,
      userinfo_signed_jwt_required = TRUE
    ),
    regexp = "userinfo_signed_jwt_required.*issuer"
  )
})

test_that("signed JWT required: uses provider allowed_algs for verification", {
  # Confirm that allowed_algs from provider is respected (ES256 key with
  # provider that only allows ES256)
  key <- openssl::ec_keygen("P-256")
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-es256"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-es256",
    name = "ES256 User",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  header <- list(typ = "JWT", alg = "ES256", kid = "kid-es256")
  clm <- do.call(jose::jwt_claim, claims)
  jwt_body <- jose::jwt_encode_sig(clm, key = key, header = header)

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

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

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "user-es256")
  expect_equal(result$name, "ES256 User")
})

# ── Attacker / unhappy path tests ───────────────────────────────────────────

test_that("signed JWT required: wrong signature (attacker key) is rejected + audit", {
  # Attacker signs JWT with their own key; JWKS contains the legitimate key
  legit_key <- openssl::rsa_keygen(2048)
  attacker_key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(legit_key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "legit-kid"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "attacker-user",
    name = "Attacker",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  # Signed with attacker's key, not the legitimate one
  jwt_body <- make_signed_jwt(claims, attacker_key, kid = "legit-kid")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1]] <<- event
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

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
    regexp = "signature is invalid"
  )
})

test_that("signed JWT required: tampered payload is rejected", {
  # Sign a legitimate JWT, then modify the payload after signing
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-tamper"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "legit-user",
    name = "Legit",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-tamper")

  # Tamper: replace payload with attacker-controlled claims
  parts <- strsplit(jwt_body, ".", fixed = TRUE)[[1]]
  attacker_claims <- jsonlite::toJSON(
    list(
      sub = "admin",
      name = "Admin",
      iss = "https://issuer.example.com",
      aud = "abc"
    ),
    auto_unbox = TRUE
  )
  parts[2] <- shinyOAuth:::base64url_encode(charToRaw(as.character(
    attacker_claims
  )))
  tampered_jwt <- paste(parts, collapse = ".")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(tampered_jwt)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "signature is invalid"
  )
})

test_that("signed JWT required: stripped signature (header.payload. with empty sig) is rejected", {
  # Attacker takes a legitimate JWT header with RS256 but empties the signature
  key <- openssl::rsa_keygen(2048)

  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-stripped"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "legit-user",
    iss = "https://issuer.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-stripped")

  # Strip signature: keep header.payload. but remove signature bytes
  parts <- strsplit(jwt_body, ".", fixed = TRUE)[[1]]
  stripped_jwt <- paste0(parts[1], ".", parts[2], ".")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(stripped_jwt)
      )
    },
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  # Should fail — empty signature can't verify against JWKS
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "signature is invalid"
  )
})

test_that("signed JWT required: wrong iss claim is rejected even with valid signature", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-iss-req"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  # Correctly signed, but iss doesn't match provider issuer
  claims <- list(
    sub = "user-iss-atk",
    iss = "https://attacker.example.com",
    aud = "abc"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-iss-req")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

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
    regexp = "iss.*does not match"
  )
})

test_that("signed JWT required: wrong aud claim is rejected even with valid signature", {
  key <- openssl::rsa_keygen(2048)
  jwk_json <- jose::write_jwk(key$pubkey)
  jwk <- jsonlite::fromJSON(jwk_json, simplifyVector = TRUE)
  jwk$kid <- "kid-aud-req"
  jwk$use <- "sig"
  jwks <- list(keys = list(jwk))

  claims <- list(
    sub = "user-aud-atk",
    iss = "https://issuer.example.com",
    aud = "attacker-client-id"
  )
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-aud-req")

  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

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
    regexp = "aud.*does not include"
  )
})

test_that("alg=none is always rejected even WITHOUT required flag (fix for fail-open gap)", {
  # Previously, without userinfo_signed_jwt_required, alg=none fell through to
  # the unverified path — attacker-controlled claims were accepted. Now
  # verification is always fail-closed.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  claims <- list(sub = "attacker-none", name = "Attacker None Alg")
  jwt_body <- make_unsigned_jwt(claims, alg = "none")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    .package = "shinyOAuth"
  )

  # alg=none is now always rejected — the fail-open gap is closed
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "alg=none.*not allowed"
  )
})

test_that("content-type downgrade: attacker sends JSON when signed JWT is required", {
  # Attacker controls the response and returns plain JSON instead of signed JWT
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1]] <<- event
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  # Return completely unsigned JSON with no Content-Type hint of JWT
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json; charset=utf-8"),
        body = charToRaw(jsonlite::toJSON(
          list(sub = "admin", email = "admin@evil.com"),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "not application/jwt.*signed JWT is required"
  )

  types <- vapply(events, function(e) e$type %||% NA_character_, character(1))
  ui_events <- events[types == "audit_userinfo"]
  statuses <- vapply(
    ui_events,
    function(e) e$status %||% NA_character_,
    character(1)
  )
  expect_true("userinfo_not_jwt" %in% statuses)
})

test_that("content-type downgrade: no content-type header when signed JWT is required", {
  # Edge case: response has no Content-Type at all
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = TRUE
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list(),
        body = charToRaw(jsonlite::toJSON(
          list(sub = "sneaky"),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "not application/jwt.*signed JWT is required"
  )
})

# ── Fail-closed verification tests ──────────────────────────────────────────

test_that("alg=none with unsafe opt-in allows unverified JWT (testing only)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  claims <- list(sub = "test-unsafe", name = "Unsafe Opt-in User")
  jwt_body <- make_unsigned_jwt(claims, alg = "none")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    .package = "shinyOAuth"
  )

  # Without the opt-in, rejected

  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "alg=none.*not allowed"
  )

  # With the opt-in, accepted (testing-only escape hatch)
  old_opt <- getOption("shinyOAuth.allow_unsigned_userinfo_jwt")
  options(shinyOAuth.allow_unsigned_userinfo_jwt = TRUE)
  on.exit(options(shinyOAuth.allow_unsigned_userinfo_jwt = old_opt), add = TRUE)

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$sub, "test-unsafe")
  expect_equal(result$name, "Unsafe Opt-in User")
})

test_that("application/jwt with missing issuer must fail by default", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  # issuer is NA (no JWKS infrastructure)

  key <- openssl::rsa_keygen(2048)
  claims <- list(sub = "user-no-issuer", name = "No Issuer")
  jwt_body <- make_signed_jwt(claims, key, kid = "kid-no-iss")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    .package = "shinyOAuth"
  )

  # Signed JWT but no issuer configured — fail-closed
  expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "issuer.*not configured"
  )
})

test_that("application/jwt with HS256 algorithm must fail (non-asymmetric)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"

  claims <- list(sub = "user-hs256", name = "HS256 User")
  jwt_body <- make_unsigned_jwt(claims, alg = "HS256")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
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
    regexp = "not in provider.*allowed"
  )
})
