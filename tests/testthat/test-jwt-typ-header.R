test_that("validate_id_token rejects JWTs with invalid typ header", {
  testthat::skip_if_not_installed("jose")

  base <- "http://localhost"
  now <- as.numeric(Sys.time())

  # RSA key for signing
  rsa <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json <- jose::write_jwk(rsa)
  priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
  pub_jwk <- list(kty = priv_jwk$kty, n = priv_jwk$n, e = priv_jwk$e)
  pub_jwk$kid <- "rsa-typ-1"

  prov <- oauth_provider(
    name = "local-typ",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    issuer = base,
    allowed_algs = c("RS256")
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "client-typ",
    client_secret = "ignore",
    redirect_uri = paste0(base, "/cb")
  )

  # Valid claims
  claims <- jose::jwt_claim(
    iss = base,
    aud = "client-typ",
    sub = "user-typ",
    exp = now + 120,
    iat = now - 1
  )

  # Bad typ header (anything other than JWT)
  bad_header <- list(alg = "RS256", kid = pub_jwk$kid, typ = "JWE")
  id_token_bad <- jose::jwt_encode_sig(claims, key = rsa, header = bad_header)

  # JWKS fetch mocked to return our public key
  expect_error(
    testthat::with_mocked_bindings(
      fetch_jwks = function(
        issuer,
        jwks_cache,
        force_refresh = FALSE,
        pins = NULL,
        pin_mode = c("any", "all"),
        provider = NULL
      ) {
        list(keys = list(pub_jwk))
      },
      .package = "shinyOAuth",
      shinyOAuth:::validate_id_token(cli, id_token_bad)
    ),
    regexp = "typ header invalid",
    class = "shinyOAuth_id_token_error"
  )
})
