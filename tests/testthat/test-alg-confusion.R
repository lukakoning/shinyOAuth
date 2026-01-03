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

minimal_client <- function(
  issuer = "https://issuer.example.com",
  client_id = "client-1",
  client_secret = paste(rep("a", 32), collapse = "")
) {
  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = issuer,
    id_token_validation = TRUE,
    id_token_required = TRUE,
    allowed_algs = c("RS256", "ES256")
  )
  shinyOAuth::oauth_client(
    prov,
    client_id = client_id,
    client_secret = client_secret,
    redirect_uri = "http://localhost:8100"
  )
}

test_that("'none' algorithm is rejected unless skipping signature", {
  client <- minimal_client()
  payload <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    exp = as.numeric(Sys.time()) + 600,
    iat = as.numeric(Sys.time()) - 10
  )
  jwt_none <- build_jwt(list(alg = "none"), payload, sig = "")

  # Default: signature check enforced -> reject
  expect_error(
    shinyOAuth:::validate_id_token(client, jwt_none),
    regexp = "alg not allowed",
    class = "shinyOAuth_id_token_error"
  )

  # When explicitly skipping signature, claims still validated
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    dec <- shinyOAuth:::validate_id_token(client, jwt_none)
    expect_identical(dec$aud, client@client_id)
  })
})

test_that("HS* requires opt-in and client_secret", {
  client <- minimal_client()
  # Allow HS256 so we reach the HS* code path rather than provider alg block
  # (setting allowed_algs itself is gated behind shinyOAuth.allow_hs)
  withr::with_options(list(shinyOAuth.allow_hs = TRUE), {
    client@provider@allowed_algs <- c("HS256")
  })

  # Fake HS256 token (unsigned body; jose check will fail unless skip)
  pl <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "s",
    exp = as.numeric(Sys.time()) + 600,
    iat = as.numeric(Sys.time()) - 10
  )
  jwt_hs <- build_jwt(list(alg = "HS256"), pl, sig = enc_b64url("sig"))

  # Not enabled -> reject before verify
  expect_error(
    shinyOAuth:::validate_id_token(client, jwt_hs),
    regexp = "HS\\* requires",
    class = "shinyOAuth_id_token_error"
  )

  # Enable HS but missing/malformed secret -> input error
  client2 <- minimal_client(client_id = "c2")
  # Allow empty secret by switching to token_auth_style body + PKCE
  client2@provider@token_auth_style <- "body"
  client2@provider@use_pkce <- TRUE
  client2@client_secret <- NA_character_
  withr::with_options(list(shinyOAuth.allow_hs = TRUE), {
    # With HS* allowed for ID token validation, a strong client_secret is
    # required up-front (fail fast during client/provider configuration).
    expect_error(
      {
        client2@provider@allowed_algs <- c("HS256")
      },
      regexp = "OAuthClient: client_secret is required for HS* ID token validation when id_token_validation or use_nonce is enabled",
      fixed = TRUE
    )
  })
})
