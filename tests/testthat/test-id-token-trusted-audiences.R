test_that("RSA-signed multi-audience ID tokens allow absent azp with explicit trust", {
  withr::local_options(
    shinyOAuth.skip_id_sig = FALSE
  )
  provider <- oauth_provider(
    name = "audience",
    issuer = "https://example.com",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    allowed_algs = "RS256",
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
  signing_key <- openssl::rsa_keygen(2048)
  jwks <- list(keys = list(jsonlite::fromJSON(
    write_test_jwk(signing_key$pubkey), simplifyVector = FALSE
  )))
  local_mocked_bindings(fetch_jwks = function(...) jwks, .package = "shinyOAuth")
  sign <- function(payload = claims, key = signing_key) {
    jose::jwt_encode_sig(do.call(jose::jwt_claim, payload), key = key)
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
  claims$azp <- NULL
  expect_identical(validate_id_token(client, sign())$sub, "user")
  for (azp in list("other", c("client", "other"))) {
    invalid <- claims
    invalid$azp <- azp
    expect_error(
      validate_id_token(client, sign(invalid)),
      class = "shinyOAuth_id_token_error"
    )
  }
  expect_error(
    validate_id_token(client, sign(key = openssl::rsa_keygen(2048))),
    class = "shinyOAuth_id_token_error"
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
