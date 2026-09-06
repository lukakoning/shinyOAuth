test_that("signed multi-audience ID tokens require explicit audience trust and correct azp", {
  withr::local_options(
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.allow_hs = TRUE
  )
  provider <- oauth_provider(
    name = "audience",
    issuer = "https://example.com",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    allowed_algs = "HS256",
    use_nonce = FALSE
  )
  client <- oauth_client(
    provider,
    "client",
    client_secret = strrep("s", 32),
    redirect_uri = "http://localhost/callback"
  )
  claims <- list(
    iss = provider@issuer,
    aud = c("client", "trusted-service"),
    azp = "client",
    sub = "user",
    iat = as.numeric(Sys.time()),
    exp = as.numeric(Sys.time()) + 60
  )
  sign <- function(payload = claims, secret = client@client_secret) {
    encode_hmac_jwt_with_header(
      payload,
      secret,
      list(alg = "HS256", typ = "JWT"),
      256
    )
  }
  expect_error(
    validate_id_token(client, sign()),
    "untrusted additional audiences"
  )
  initial_policy <- state_client_policy_fingerprint(client)
  client@trusted_id_token_audiences <- "trusted-service"
  expect_false(identical(
    state_client_policy_fingerprint(client),
    initial_policy
  ))
  expect_identical(validate_id_token(client, sign())$sub, "user")
  for (aud in list(
    "trusted-service",
    c("client", "untrusted"),
    c("client", "Trusted-Service")
  )) {
    invalid <- claims
    invalid$aud <- aud
    expect_error(
      validate_id_token(client, sign(invalid)),
      class = "shinyOAuth_id_token_error"
    )
  }
  for (azp in list(NULL, "other", c("client", "other"))) {
    invalid <- claims
    invalid$azp <- azp
    expect_error(
      validate_id_token(client, sign(invalid)),
      class = "shinyOAuth_id_token_error"
    )
  }
  expect_error(
    validate_id_token(client, sign(secret = strrep("w", 32))),
    "HMAC invalid"
  )
  claims$aud <- "client"
  claims$azp <- NULL
  expect_identical(validate_id_token(client, sign())$sub, "user")
})

test_that("trusted ID token audiences have safe constructor defaults and validation", {
  provider <- make_test_provider()
  for (constructor in list(oauth_client, OAuthClient)) {
    args <- list(
      provider = provider,
      client_id = "client",
      redirect_uri = "http://localhost/callback"
    )
    client <- do.call(constructor, args)
    expect_identical(client@trusted_id_token_audiences, character())
    for (invalid in list(NULL, NA_character_, "", " ", list("aud"), 1)) {
      expect_error(
        do.call(
          constructor,
          c(args, list(trusted_id_token_audiences = invalid))
        ),
        "trusted_id_token_audiences"
      )
    }
    client@trusted_id_token_audiences <- c("one", "two")
    policy <- state_client_policy_fingerprint(client)
    client@trusted_id_token_audiences <- c("two", "one")
    expect_identical(state_client_policy_fingerprint(client), policy)
    expect_error(
      {
        client@trusted_id_token_audiences <- NA_character_
      },
      "trusted_id_token_audiences"
    )
  }
})
