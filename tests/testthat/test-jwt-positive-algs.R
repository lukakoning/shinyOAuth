test_that("validate_id_token accepts a valid asymmetric JWT (EdDSA or RS256)", {
  testthat::skip_if_not_installed("jose")
  # Prefer EdDSA when sodium supports it; otherwise fall back to RS256
  have_sodium <- requireNamespace("sodium", quietly = TRUE)
  use_eddsa <- FALSE
  kp <- NULL
  if (isTRUE(have_sodium)) {
    if ("signature_keygen" %in% getNamespaceExports("sodium")) {
      kp <- try(sodium::signature_keygen(), silent = TRUE)
    } else if ("signature_keypair" %in% getNamespaceExports("sodium")) {
      kp <- try(sodium::signature_keypair(), silent = TRUE)
    }
    use_eddsa <- !inherits(kp, "try-error") && !is.null(kp)
  }

  now <- as.numeric(Sys.time())

  # Create key material and JWKS depending on chosen algorithm
  if (isTRUE(use_eddsa)) {
    pub <- kp$pubkey
    secret <- if (!is.null(kp$key)) kp$key else kp$secretkey
    pub_jwk <- list(
      kty = "OKP",
      crv = "Ed25519",
      x = shinyOAuth:::base64url_encode(pub)
    )
    pub_jwk$kid <- "ed25519-1"
  } else {
    rsa <- openssl::rsa_keygen(bits = 2048)
    priv_jwk_json <- jose::write_jwk(rsa)
    priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
    pub_jwk <- list(kty = priv_jwk$kty, n = priv_jwk$n, e = priv_jwk$e)
    pub_jwk$kid <- "rsa-1"
  }

  # Use a local issuer and mock JWKS fetch to avoid HTTP
  base <- "http://localhost"

  # Provider allows EdDSA; client configured with matching client_id
  prov <- oauth_provider(
    name = "local-asym",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    issuer = base,
    allowed_algs = c("EdDSA", "RS256")
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "client-asym",
    client_secret = "ignore-for-asym",
    redirect_uri = paste0(base, "/cb")
  )

  # Create a valid ID token with EdDSA or RS256 signature
  header <- list(
    alg = if (isTRUE(use_eddsa)) "EdDSA" else "RS256",
    kid = pub_jwk$kid,
    typ = "JWT"
  )
  claims <- list(
    iss = base,
    aud = "client-asym",
    sub = "user-123",
    exp = now + 120,
    iat = now - 1
  )
  if (isTRUE(use_eddsa)) {
    # Manually construct and sign the JWT using Ed25519
    header_json <- jsonlite::toJSON(header, auto_unbox = TRUE, null = "null")
    claims_json <- jsonlite::toJSON(claims, auto_unbox = TRUE, null = "null")
    h64 <- shinyOAuth:::base64url_encode(charToRaw(as.character(header_json)))
    p64 <- shinyOAuth:::base64url_encode(charToRaw(as.character(claims_json)))
    signing_input <- paste0(h64, ".", p64)
    sig <- sodium::signature(charToRaw(signing_input), secret)
    s64 <- shinyOAuth:::base64url_encode(sig)
    id_token <- paste(signing_input, s64, sep = ".")
  } else {
    id_token <- jose::jwt_encode_sig(
      jose::jwt_claim(
        iss = base,
        aud = "client-asym",
        sub = "user-123",
        exp = now + 120,
        iat = now - 1
      ),
      key = rsa,
      header = header
    )
  }

  expect_silent(testthat::with_mocked_bindings(
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
    shinyOAuth:::validate_id_token(cli, id_token)
  ))
})

test_that("validate_id_token accepts a valid RSA-PSS (PS256) JWT when supported", {
  testthat::skip_if_not_installed("jose")

  # Generate RSA key
  rsa <- openssl::rsa_keygen(bits = 2048)

  now <- as.numeric(Sys.time())

  # Build RSA public JWK and JWKS
  priv_jwk_json <- jose::write_jwk(rsa)
  priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
  pub_jwk <- list(kty = priv_jwk$kty, n = priv_jwk$n, e = priv_jwk$e)
  pub_jwk$kid <- "rsa-pss-1"
  base <- "http://localhost"

  prov <- oauth_provider(
    name = "local-pss",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    issuer = base,
    allowed_algs = c("PS256", "RS256")
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "client-pss",
    client_secret = "ignore-for-pss",
    redirect_uri = paste0(base, "/cb")
  )

  claims <- jose::jwt_claim(
    iss = base,
    aud = "client-pss",
    sub = "user-pss",
    exp = now + 120,
    iat = now - 1
  )
  # Try PS256 end-to-end (encode+local decode); fall back to RS256 if unsupported
  id_token <- NULL
  header <- list(alg = "PS256", kid = pub_jwk$kid, typ = "JWT")
  try_pss <- try(
    jose::jwt_encode_sig(claims, key = rsa, header = header),
    silent = TRUE
  )
  if (!inherits(try_pss, "try-error")) {
    # Local verify with constructed public JWK
    pub <- jose::read_jwk(jsonlite::toJSON(pub_jwk, auto_unbox = TRUE))
    dec <- try(jose::jwt_decode_sig(try_pss, pub), silent = TRUE)
    if (!inherits(dec, "try-error")) {
      id_token <- try_pss
    }
  }
  if (is.null(id_token)) {
    header <- list(alg = "RS256", kid = pub_jwk$kid, typ = "JWT")
    id_token <- jose::jwt_encode_sig(claims, key = rsa, header = header)
  }

  expect_silent(testthat::with_mocked_bindings(
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
    {
      # Sanity check: decode using public JWK must work
      pub <- jose::read_jwk(jsonlite::toJSON(pub_jwk, auto_unbox = TRUE))
      dec <- try(jose::jwt_decode_sig(id_token, pub), silent = TRUE)
      if (inherits(dec, "try-error")) {
        testthat::fail(
          "Local jose::jwt_decode_sig failed with constructed public key"
        )
      }
      shinyOAuth:::validate_id_token(cli, id_token)
    }
  ))
})
