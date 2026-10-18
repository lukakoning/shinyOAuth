test_that("Microsoft helpers retain subject binding when automatic UserInfo is off", {
  tenants <- c(
    "common", "organizations", "consumers",
    "12345678-1234-1234-1234-123456789abc"
  )
  for (tenant in tenants) {
    provider <- oauth_provider_microsoft(tenant = tenant, userinfo_required = FALSE)
    expect_false(provider@userinfo_required)
    expect_true(provider@userinfo_id_token_match)
    expect_true(provider@id_token_validation)
    expect_true(provider@use_nonce)
    provider@userinfo_signed_jwt_required <- TRUE
    expect_true(provider@userinfo_signed_jwt_required)

    oauth_only <- oauth_provider_microsoft(
      tenant = tenant, userinfo_required = FALSE, id_token_validation = FALSE
    )
    expect_false(oauth_only@userinfo_id_token_match)
  }
})

test_that("manual Microsoft UserInfo rejects a raw token without its validated identity", {
  provider <- oauth_provider_microsoft(
    tenant = "12345678-1234-1234-1234-123456789abc",
    userinfo_required = FALSE
  )
  client <- oauth_client(
    provider, client_id = "app", client_secret = "secret",
    redirect_uri = "https://app.example/callback", scopes = "openid"
  )
  local_mocked_bindings(
    req_with_retry = function(req, ...) httr2::response(
      url = req[["url"]], status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw('{"sub":"different-account"}')
    ),
    .package = "shinyOAuth"
  )
  expect_error(
    get_userinfo(client, "access-token"),
    class = "shinyOAuth_userinfo_error", regexp = "Cannot verify UserInfo subject"
  )
})
