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
    name = "test",
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

test_that("Malformed JWTs are rejected with parse errors", {
  client <- mk_client()

  # Construct with two segments but header is not JSON
  bad1 <- paste(enc_b64url("not-json"), enc_b64url("{}"), "", sep = ".")
  # Ensure jsonlite::fromJSON sees a string (not a path) and fails to parse JSON
  bad2 <- paste(enc_b64url("{not json}"), enc_b64url("{}"), "", sep = ".")
  bad3 <- paste(enc_b64url("{}"), enc_b64url("not-json"), "", sep = ".")

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    # Accept either package-level parse errors or jsonlite parse errors
    expect_error(
      shinyOAuth:::validate_id_token(client, bad1),
      regexp = "Invalid JWT format|parse|lexical error"
    )
    expect_error(
      shinyOAuth:::validate_id_token(client, bad2),
      regexp = "parse|Failed|invalid"
    )
    expect_error(
      shinyOAuth:::validate_id_token(client, bad3),
      regexp = "parse|Failed|invalid|missing alg"
    )
  })
})

test_that("exp/iat/nbf boundary conditions respect leeway", {
  client <- mk_client()
  client@provider@leeway <- 5

  now <- floor(as.numeric(Sys.time()))
  base_claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    iat = now - 1
  )

  # exp at just inside the window (now - leeway + 1) should be valid
  c1 <- modifyList(base_claims, list(exp = now - 5 + 1))
  jwt1 <- build_jwt(list(alg = "none"), c1)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(shinyOAuth:::validate_id_token(client, jwt1))
  })

  # exp just below window -> expired
  c2 <- modifyList(base_claims, list(exp = now - 6))
  jwt2 <- build_jwt(list(alg = "none"), c2)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt2),
      class = "shinyOAuth_id_token_error",
      regexp = "expired"
    )
  })

  # iat in future beyond leeway -> reject
  c3 <- modifyList(base_claims, list(exp = now + 60, iat = now + 6))
  jwt3 <- build_jwt(list(alg = "none"), c3)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt3),
      class = "shinyOAuth_id_token_error",
      regexp = "issued in the future"
    )
  })

  # nbf in future beyond leeway -> reject
  c4 <- modifyList(base_claims, list(exp = now + 60, nbf = now + 6))
  jwt4 <- build_jwt(list(alg = "none"), c4)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt4),
      class = "shinyOAuth_id_token_error",
      regexp = "not yet valid"
    )
  })
})

test_that("temporal claims must be single finite numeric", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  base_claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    iat = now - 1
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    # exp as a string -> reject
    c1 <- modifyList(base_claims, list(exp = ""))
    jwt1 <- build_jwt(list(alg = "none"), c1)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt1),
      class = "shinyOAuth_id_token_error",
      regexp = "exp claim must be a single finite number|missing exp"
    )

    # exp as vector (non-scalar) -> reject
    c2 <- modifyList(base_claims, list(exp = c(now + 10, now + 20)))
    jwt2 <- build_jwt(list(alg = "none"), c2)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt2),
      class = "shinyOAuth_id_token_error",
      regexp = "exp claim must be a single finite number|missing exp"
    )

    # iat present but as string -> reject with iat-specific message
    c3 <- modifyList(base_claims, list(exp = now + 60, iat = "oops"))
    jwt3 <- build_jwt(list(alg = "none"), c3)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt3),
      class = "shinyOAuth_id_token_error",
      regexp = "iat claim must be a single finite number"
    )

    # nbf present but as string -> reject with nbf-specific message
    c4 <- modifyList(base_claims, list(exp = now + 60, nbf = "oops"))
    jwt4 <- build_jwt(list(alg = "none"), c4)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt4),
      class = "shinyOAuth_id_token_error",
      regexp = "nbf claim must be a single finite number"
    )
  })
})

test_that("missing iat is rejected per OIDC Core", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))
  base_claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    exp = now + 60
  )
  jwt <- build_jwt(list(alg = "none"), base_claims)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt),
      class = "shinyOAuth_id_token_error",
      regexp = "missing iat"
    )
  })
})
