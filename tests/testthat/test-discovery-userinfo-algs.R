test_that("discovery negotiates ID token and UserInfo algorithms independently", {
  issuer <- "https://issuer.example.com"
  key <- openssl::ec_keygen("P-256")
  jwt <- jose::jwt_encode_sig(
    jose::jwt_claim(iss = issuer, aud = "client", sub = "user"),
    key = key,
    header = list(alg = "ES256")
  )
  testthat::local_mocked_bindings(
    .discover_fetch_response = function(...) NULL,
    .discover_parse_json = function(...) {
      list(
        issuer = issuer,
        authorization_endpoint = paste0(issuer, "/auth"),
        token_endpoint = paste0(issuer, "/token"),
        userinfo_endpoint = paste0(issuer, "/userinfo"),
        jwks_uri = paste0(issuer, "/jwks"),
        response_types_supported = list("code"),
        subject_types_supported = list("public"),
        id_token_signing_alg_values_supported = list("RS256"),
        userinfo_signing_alg_values_supported = list("ES256")
      )
    },
    fetch_jwks = function(...) {
      list(keys = list(jsonlite::fromJSON(write_test_jwk(key$pubkey))))
    },
    req_with_retry = function(...) {
      httr2::response(
        status_code = 200L,
        headers = list("Content-Type" = "application/jwt"),
        body = charToRaw(jwt)
      )
    },
    .package = "shinyOAuth"
  )
  prov <- oauth_provider_oidc_discover(
    issuer,
    allowed_algs = c("RS256", "ES256"),
    userinfo_id_token_match = FALSE
  )
  expect_identical(prov@allowed_algs, "RS256")
  expect_identical(prov@userinfo_allowed_algs, "ES256")
  cli <- oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )
  expect_identical(get_userinfo(cli, token = "opaque")$sub, "user")
  expect_error(
    shinyOAuth:::validate_id_token(cli, jwt),
    class = "shinyOAuth_id_token_error"
  )
  restricted <- oauth_provider_oidc_discover(
    issuer,
    allowed_algs = c("RS256", "ES256"),
    userinfo_allowed_algs = "RS256"
  )
  expect_length(restricted@userinfo_allowed_algs, 0L)
  cli@provider <- restricted
  expect_error(get_userinfo(cli, token = "opaque"), "algorithm")
})
