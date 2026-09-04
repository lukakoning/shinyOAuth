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

test_that("signed ID tokens reject b64=false with or without crit", {
  withr::local_options(shinyOAuth.allow_hs = TRUE)
  secret <- "id-token-b64-test-secret-32-bytes!"
  client <- mk_client()
  client@client_secret <- secret
  client@provider@allowed_algs <- "HS256"
  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    iat = now - 1,
    exp = now + 120
  )

  crit_cases <- list(without_crit = NULL, with_crit = list("b64"))
  for (crit in crit_cases) {
    header <- list(alg = "HS256", typ = "JWT", b64 = FALSE)
    if (!is.null(crit)) {
      header[["crit"]] <- crit
    }
    jwt <- shinyOAuth:::encode_hmac_jwt_with_header(
      claims = claims,
      secret = secret,
      header = header,
      size = 256,
      alg = "HS256"
    )

    withr::with_options(list(shinyOAuth.allow_hs = TRUE), {
      expect_error(
        shinyOAuth:::validate_id_token(client, jwt),
        regexp = "b64=false header is not allowed",
        class = "shinyOAuth_id_token_error"
      )
    })
  }
})

test_that("ID tokens reject malformed b64 headers", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    iat = now - 1,
    exp = now + 120
  )

  for (b64_value in list("false", 0, list(FALSE))) {
    jwt <- build_jwt(list(alg = "none", b64 = b64_value), claims)
    withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
      expect_error(
        shinyOAuth:::validate_id_token(client, jwt),
        regexp = "b64 header must be a single non-missing boolean",
        class = "shinyOAuth_id_token_error"
      )
    })
  }
})
