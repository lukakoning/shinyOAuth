enc_b64url <- function(x) {
  b <- openssl::base64_encode(charToRaw(x))
  b <- gsub("=+$", "", b)
  chartr("+/", "-_", b)
}

build_jwt <- function(header, claims, sig = "") {
  paste(
    enc_b64url(jsonlite::toJSON(header, auto_unbox = TRUE)),
    enc_b64url(jsonlite::toJSON(claims, auto_unbox = TRUE)),
    sig,
    sep = "."
  )
}

mk_client <- function() {
  prov <- shinyOAuth::oauth_provider(
    name = "test-crit",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE,
    allowed_algs = c("RS256", "ES256")
  )
  shinyOAuth::oauth_client(
    prov,
    client_id = "client-xyz",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )
}

test_that("JWT with unsupported crit header is rejected", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  claims <- list(
    iss = "https://issuer.example.com",
    aud = "client-xyz",
    sub = "user-1",
    iat = now - 1,
    exp = now + 120
  )

  # crit = ["exp"] — we don't support any critical extensions

  jwt <- build_jwt(list(alg = "none", crit = list("exp")), claims)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt),
      regexp = "unsupported critical header parameter",
      class = "shinyOAuth_id_token_error"
    )
  })
})

test_that("JWT with multiple unsupported crit entries is rejected", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  claims <- list(
    iss = "https://issuer.example.com",
    aud = "client-xyz",
    sub = "user-1",
    iat = now - 1,
    exp = now + 120
  )

  jwt <- build_jwt(
    list(alg = "none", crit = list("b64", "example.com:custom")),
    claims
  )
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt),
      regexp = "unsupported critical header parameter",
      class = "shinyOAuth_id_token_error"
    )
  })
})

test_that("JWT with malformed crit types is rejected", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  claims <- list(
    iss = "https://issuer.example.com",
    aud = "client-xyz",
    sub = "user-1",
    iat = now - 1,
    exp = now + 120
  )

  # crit as a number
  jwt_num <- build_jwt(list(alg = "none", crit = 42), claims)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt_num),
      regexp = "crit header must be a non-empty character vector",
      class = "shinyOAuth_id_token_error"
    )
  })

  # crit as an empty array
  jwt_empty <- build_jwt(list(alg = "none", crit = list()), claims)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt_empty),
      regexp = "crit header must be a non-empty character vector",
      class = "shinyOAuth_id_token_error"
    )
  })
})

test_that("JWT without crit header still passes validation", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  claims <- list(
    iss = "https://issuer.example.com",
    aud = "client-xyz",
    sub = "user-1",
    iat = now - 1,
    exp = now + 120
  )

  jwt <- build_jwt(list(alg = "none"), claims)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(shinyOAuth:::validate_id_token(client, jwt))
  })
})
