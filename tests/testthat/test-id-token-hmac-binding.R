test_that("one ID-token secret cannot enable multiple HMAC algorithms", {
  local_options(shinyOAuth.allow_hs = TRUE)
  provider <- oauth_provider(
    name = "hmac-binding",
    auth_url = "https://issuer.example/authorize",
    token_url = "https://issuer.example/token",
    issuer = "https://issuer.example",
    use_nonce = FALSE,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    id_token_allowed_algs = c("HS256", "HS384")
  )
  expect_error(
    oauth_client(
      provider,
      "hmac-client",
      client_secret = strrep("a", 64),
      redirect_uri = "https://app.example/callback",
      scopes = "openid"
    ),
    "exactly one HS algorithm"
  )

  provider@id_token_allowed_algs <- "HS256"
  client <- oauth_client(
    provider,
    "hmac-client",
    client_secret = strrep("a", 64),
    redirect_uri = "https://app.example/callback",
    scopes = "openid"
  )
  expect_error(
    client@provider@id_token_allowed_algs <- c("HS256", "HS512"),
    "exactly one HS algorithm"
  )
})

test_that("HMAC ID tokens use their configured algorithm even after restoration", {
  local_options(shinyOAuth.allow_hs = TRUE, shinyOAuth.skip_id_sig = FALSE)
  secret <- strrep("a", 64)
  now <- floor(as.numeric(Sys.time()))
  algorithms <- c("HS256", "HS384", "HS512")
  for (alg in algorithms) {
    provider <- oauth_provider(
      name = "hmac-binding",
      auth_url = "https://issuer.example/authorize",
      token_url = "https://issuer.example/token",
      issuer = "https://issuer.example",
      use_nonce = FALSE,
      userinfo_required = FALSE,
      userinfo_id_token_match = FALSE,
      id_token_allowed_algs = c("RS256", alg)
    )
    client <- oauth_client(
      provider,
      "hmac-client",
      client_secret = secret,
      redirect_uri = "https://app.example/callback",
      scopes = "openid"
    )
    claims <- list(
      iss = provider@issuer,
      sub = "subject",
      aud = client@client_id,
      iat = now,
      exp = now + 300
    )
    signed <- function(algorithm) {
      encode_hmac_jwt_with_header(
        claims,
        secret,
        list(alg = algorithm),
        size = as.integer(sub("HS", "", algorithm)),
        alg = algorithm
      )
    }
    token <- signed(alg)
    expect_true(attr(
      validate_id_token(client, token),
      "signature_verified",
      exact = TRUE
    ))
    other_alg <- setdiff(algorithms, alg)[[1L]]
    expect_error(
      validate_id_token(client, signed(other_alg)),
      "alg not allowed",
      class = "shinyOAuth_id_token_error"
    )

    # Serialized or otherwise restored objects can bypass S7 property setters.
    attr(provider, "allowed_algs") <- algorithms
    attr(client, "provider") <- provider
    expect_error(
      validate_id_token(client, token),
      "exactly one HS algorithm",
      class = "shinyOAuth_id_token_error"
    )
  }
})
