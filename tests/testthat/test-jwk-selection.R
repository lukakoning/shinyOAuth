test_that("JWK selection filters use=sig and prefers alg match", {
  testthat::skip_if_not_installed("jose")

  now <- as.numeric(Sys.time())
  base <- "http://localhost"

  # Generate RSA key pair and public JWK
  rsa <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json <- jose::write_jwk(rsa)
  priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
  pub_jwk_sig_rs256 <- list(
    kty = priv_jwk$kty,
    n = priv_jwk$n,
    e = priv_jwk$e,
    kid = "k-rs256",
    use = "sig",
    alg = "RS256"
  )

  # Another RSA key with use=enc (should be filtered out)
  rsa2 <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json2 <- jose::write_jwk(rsa2)
  priv_jwk2 <- jsonlite::fromJSON(priv_jwk_json2, simplifyVector = TRUE)
  pub_jwk_enc_rs256 <- list(
    kty = priv_jwk2$kty,
    n = priv_jwk2$n,
    e = priv_jwk2$e,
    kid = "k-enc",
    use = "enc",
    alg = "RS256"
  )

  # A third RSA key with use=sig but different alg advertised (RS384)
  rsa3 <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json3 <- jose::write_jwk(rsa3)
  priv_jwk3 <- jsonlite::fromJSON(priv_jwk_json3, simplifyVector = TRUE)
  pub_jwk_sig_rs384 <- list(
    kty = priv_jwk3$kty,
    n = priv_jwk3$n,
    e = priv_jwk3$e,
    kid = "k-rs384",
    use = "sig",
    alg = "RS384"
  )

  prov <- oauth_provider(
    name = "local",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    issuer = base,
    allowed_algs = c("RS256", "RS384")
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "c1",
    client_secret = "ignore",
    redirect_uri = paste0(base, "/cb")
  )

  # Create a valid RS256 token signed with pub_jwk_sig_rs256's private key (rsa)
  id_token <- jose::jwt_encode_sig(
    jose::jwt_claim(
      iss = base,
      aud = "c1",
      sub = "u",
      exp = now + 120,
      iat = now - 1
    ),
    key = rsa,
    header = list(alg = "RS256", kid = pub_jwk_sig_rs256$kid, typ = "JWT")
  )

  # JWKS contains three keys: one enc-only, two sig (one matching alg)
  jwks <- list(
    keys = list(pub_jwk_enc_rs256, pub_jwk_sig_rs384, pub_jwk_sig_rs256)
  )

  # Mock fetch_jwks to return our synthetic JWKS
  expect_silent(testthat::with_mocked_bindings(
    fetch_jwks = function(
      issuer,
      jwks_cache,
      force_refresh = FALSE,
      pins = NULL,
      pin_mode = c("any", "all"),
      provider = NULL
    ) {
      jwks
    },
    .package = "shinyOAuth",
    {
      # Should verify using the RS256 key; the 'enc' key must be ignored
      dec <- shinyOAuth:::validate_id_token(cli, id_token)
      expect_identical(dec$aud, "c1")
    }
  ))

  # Now test kid-restricted path: use the RS384 key's kid but sign RS256
  # With stricter handling, when a kid is present we only try keys matching that kid.
  # Since the header's kid does not correspond to the signing key, verification must fail.
  id_token2 <- jose::jwt_encode_sig(
    jose::jwt_claim(
      iss = base,
      aud = "c1",
      sub = "u",
      exp = now + 120,
      iat = now - 1
    ),
    key = rsa,
    header = list(alg = "RS256", kid = pub_jwk_sig_rs384$kid, typ = "JWT")
  )
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
        jwks
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::validate_id_token(cli, id_token2)
      }
    ),
    class = "shinyOAuth_id_token_error"
  )
})

test_that("JWK selection treats malformed key_ops as unusable", {
  key_template <- list(
    kty = "RSA",
    n = "n-test",
    e = "AQAB",
    use = "sig"
  )

  select_one <- function(key) {
    shinyOAuth:::select_candidate_jwks(list(keys = list(key)))
  }

  expect_length(
    select_one(modifyList(key_template, list(kid = "missing-key-ops"))),
    1L
  )
  expect_length(
    select_one(modifyList(
      key_template,
      list(kid = "verify", key_ops = c("verify"))
    )),
    1L
  )
  expect_length(
    select_one(modifyList(
      key_template,
      list(kid = "empty", key_ops = character(0))
    )),
    0L
  )
  expect_length(
    select_one(modifyList(
      key_template,
      list(kid = "malformed", key_ops = 1:2)
    )),
    0L
  )
  expect_length(
    select_one(modifyList(
      key_template,
      list(kid = "duplicate", key_ops = c("verify", "verify"))
    )),
    0L
  )
  expect_length(
    select_one(modifyList(
      key_template,
      list(kid = "missing-verify", key_ops = c("sign", "encrypt"))
    )),
    0L
  )
})
