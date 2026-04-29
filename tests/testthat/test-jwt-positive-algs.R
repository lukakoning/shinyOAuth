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

make_rsa_jwt_with_alg <- function(key, alg, claims, kid) {
  header_json <- jsonlite::toJSON(
    list(alg = alg, kid = kid, typ = "JWT"),
    auto_unbox = TRUE,
    null = "null"
  )
  claims_json <- jsonlite::toJSON(
    claims,
    auto_unbox = TRUE,
    null = "null"
  )
  signing_input <- paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(claims_json))
  )
  hash_fn <- switch(
    alg,
    RS256 = openssl::sha256,
    RS384 = openssl::sha384,
    RS512 = openssl::sha512,
    stop("unsupported test alg", call. = FALSE)
  )
  sig <- openssl::signature_create(
    charToRaw(signing_input),
    hash = hash_fn,
    key = key
  )

  paste0(signing_input, ".", shinyOAuth:::base64url_encode(sig))
}

test_that("validate_id_token accepts valid RS384 and RS512 JWTs", {
  testthat::skip_if_not_installed("jose")

  rsa <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json <- jose::write_jwk(rsa)
  priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
  pub_jwk <- list(kty = priv_jwk$kty, n = priv_jwk$n, e = priv_jwk$e)
  pub_jwk$kid <- "rsa-wide-1"
  base <- "http://localhost"

  prov <- oauth_provider(
    name = "local-rsa",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    issuer = base,
    allowed_algs = c("RS256", "RS384", "RS512")
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "client-rsa",
    client_secret = "ignore-for-rsa",
    redirect_uri = paste0(base, "/cb")
  )

  for (alg in c("RS384", "RS512")) {
    now <- as.numeric(Sys.time())
    claims <- list(
      iss = base,
      aud = "client-rsa",
      sub = paste0("user-", tolower(alg)),
      exp = now + 120,
      iat = now - 1
    )
    id_token <- make_rsa_jwt_with_alg(
      key = rsa,
      alg = alg,
      claims = claims,
      kid = pub_jwk$kid
    )

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
        pub <- jose::read_jwk(jsonlite::toJSON(pub_jwk, auto_unbox = TRUE))
        dec <- try(jose::jwt_decode_sig(id_token, pub), silent = TRUE)
        if (inherits(dec, "try-error")) {
          testthat::fail(
            paste("Local jose::jwt_decode_sig failed for", alg)
          )
        }
        shinyOAuth:::validate_id_token(cli, id_token)
      }
    ))
  }
})
