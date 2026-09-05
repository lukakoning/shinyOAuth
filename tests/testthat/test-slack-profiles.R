test_that("Slack registration profiles work with recorded discovery metadata", {
  # https://slack.com/.well-known/openid-configuration, retrieved 2026-09-05.
  metadata <- list(issuer = "https://slack.com",
    authorization_endpoint = "https://slack.com/openid/connect/authorize",
    token_endpoint = "https://slack.com/api/openid.connect.token",
    userinfo_endpoint = "https://slack.com/api/openid.connect.userInfo",
    jwks_uri = "https://slack.com/openid/connect/keys",
    scopes_supported = list("openid", "profile", "email"),
    response_types_supported = list("code"), response_modes_supported = list("query"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256"),
    token_endpoint_auth_methods_supported = list("client_secret_post", "client_secret_basic"))
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(url = req$url, status = 200,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(metadata, auto_unbox = TRUE)))
  }, .package = "shinyOAuth")
  confidential <- oauth_provider_slack()
  expect_false(confidential@use_pkce)
  expect_true(confidential@use_nonce)
  expect_true(confidential@id_token_validation)
  expect_identical(confidential@token_auth_style, "header")
  public <- oauth_provider_slack(profile = "public_pkce")
  expect_true(public@use_pkce)
  expect_identical(public@pkce_method, "S256")
  client <- oauth_client(public, client_id = "slack-client", client_secret = "unused",
    redirect_uri = "http://localhost:8100", scopes = "openid")
  auth <- apply_direct_client_auth(httr2::request(public@token_url), list(), client,
    "swap_code_for_token_set")
  expect_identical(auth$params$client_id, "slack-client")
  expect_null(auth$params$client_secret)
  expect_null(auth$req$headers$Authorization)
})
