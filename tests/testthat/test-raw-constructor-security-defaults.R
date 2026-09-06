test_that("raw provider defaults preserve issuer-derived security policies", {
  args <- list(
    name = "test",
    auth_url = "https://example.test/auth",
    token_url = "https://example.test/token"
  )
  for (issuer in c(NA_character_, "https://example.test")) {
    args[["issuer"]] <- issuer
    raw <- do.call(OAuthProvider, args)
    helper <- do.call(oauth_provider, args)
    for (field in c(
      "use_nonce",
      "id_token_required",
      "id_token_validation",
      "jwks_host_issuer_match"
    )) {
      expect_identical(S7::prop(raw, field), S7::prop(helper, field))
    }
  }
  args[["issuer_thus_oidc"]] <- FALSE
  expect_false(do.call(OAuthProvider, args)@id_token_required)
  args[["issuer_thus_oidc"]] <- TRUE
  args[["use_nonce"]] <- FALSE
  expect_false(do.call(OAuthProvider, args)@use_nonce)
})

test_that("raw clients with a DPoP key require DPoP access tokens by default", {
  provider <- make_test_provider()
  args <- list(
    provider = provider,
    client_id = "test",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(),
    state_key = paste(rep("a", 64), collapse = "")
  )
  expect_false(do.call(OAuthClient, args)@dpop_require_access_token)
  args[["dpop_private_key"]] <- openssl::rsa_keygen()
  expect_true(do.call(OAuthClient, args)@dpop_require_access_token)
  expect_error(
    verify_token_type_allowlist(
      do.call(OAuthClient, args),
      list(access_token = "opaque", token_type = "Bearer")
    ),
    class = "shinyOAuth_token_error"
  )
  args[["dpop_require_access_token"]] <- FALSE
  expect_false(do.call(OAuthClient, args)@dpop_require_access_token)
})

test_that("raw OIDC clients reject token sets without an ID token", {
  provider <- OAuthProvider(
    name = "test",
    issuer = "https://example.test",
    auth_url = "https://example.test/auth",
    token_url = "https://example.test/token"
  )
  client <- OAuthClient(
    provider = provider,
    client_id = "test",
    client_secret = "test-secret",
    redirect_uri = "http://localhost:8100",
    scopes = "openid",
    state_key = strrep("a", 64)
  )
  expect_error(
    verify_token_set(
      client,
      list(access_token = "opaque", token_type = "Bearer", expires_in = 3600),
      nonce = "expected"
    ),
    class = "shinyOAuth_id_token_error"
  )
})
