test_that("clock leeway does not allow contradictory temporal claims", {
  client <- oauth_client(
    oauth_provider(
      name = "temporal-test",
      issuer = "https://issuer.example", auth_url = "https://issuer.example/auth",
      token_url = "https://issuer.example/token", leeway = 30
    ),
    client_id = "temporal-test", client_secret = "secret",
    redirect_uri = "http://localhost:8100", scopes = "openid"
  )
  withr::local_options(list(shinyOAuth.skip_id_sig = TRUE))
  now <- floor(as.numeric(Sys.time()))
  claims <- list(iss = client@provider@issuer, aud = client@client_id,
                 sub = "subject", iat = now, exp = now + 10)
  encode <- function(x) shinyOAuth:::base64url_encode(charToRaw(
    jsonlite::toJSON(x, auto_unbox = TRUE)
  ))
  validate_id <- function(x) shinyOAuth:::validate_id_token(
    client, paste(encode(list(alg = "none")), encode(x), "", sep = ".")
  )
  validate_ui <- function(x) shinyOAuth:::validate_signed_userinfo_claims(
    x, client@provider@issuer, client@client_id, client
  )
  for (claim in c("iat", "nbf")) {
    bad <- claims
    bad[[claim]] <- now + 20
    expect_error(validate_id(bad), paste(claim, "claim must not be after exp"))
    expect_error(validate_ui(bad), paste(claim, "claim must not be after exp"))
    boundary <- claims
    boundary[[claim]] <- boundary$exp
    expect_no_error(validate_id(boundary))
    expect_no_error(validate_ui(boundary))
  }
  expect_no_error(validate_ui(claims[c("iss", "aud", "sub")]))
})
