# Integration test for token revocation against Keycloak
#
# Keycloak exposes a revocation endpoint per OIDC discovery (RFC 7009).
# This test fetches a client_credentials access token, verifies it is active
# via introspection, then revokes it and confirms it is no longer active.

get_issuer <- function() {
  "http://localhost:8080/realms/shinyoauth"
}

keycloak_reachable <- function() {
  issuer <- get_issuer()
  disc <- paste0(issuer, "/.well-known/openid-configuration")
  ok <- tryCatch(
    {
      resp <- httr2::request(disc) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "application/json") |>
        httr2::req_perform()
      !httr2::resp_is_error(resp)
    },
    error = function(...) FALSE
  )
  isTRUE(ok)
}

testthat::test_that("revoke_token invalidates access token (integration)", {
  testthat::skip_if_not(
    keycloak_reachable(),
    "Keycloak not reachable at localhost:8080"
  )

  issuer <- get_issuer()

  # Discover provider for the realm

  prov <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )

  # Verify discovery returned a revocation endpoint
  testthat::expect_true(
    shinyOAuth:::is_valid_string(prov@revocation_url),
    info = "Keycloak discovery should expose revocation_endpoint"
  )

  # Obtain a client_credentials token using the confidential client (service account)
  token_resp <- httr2::request(prov@token_url) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_body_form(
      grant_type = "client_credentials",
      client_id = "shiny-confidential",
      client_secret = "secret"
    ) |>
    httr2::req_perform()

  testthat::expect_false(httr2::resp_is_error(token_resp))
  parsed <- httr2::resp_body_json(token_resp, simplifyVector = TRUE)
  at <- parsed$access_token
  testthat::expect_true(is.character(at) && length(at) == 1 && nzchar(at))

  # Build OAuthClient and OAuthToken
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = character()
  )
  tok <- shinyOAuth::OAuthToken(access_token = at)

  # 1) Introspect: token should be active
  intros_before <- shinyOAuth::introspect_token(client, tok, which = "access")
  testthat::expect_true(isTRUE(intros_before$supported))
  testthat::expect_true(
    isTRUE(intros_before$active),
    info = "Token should be active before revocation"
  )

  # 2) Revoke the access token
  rev_result <- shinyOAuth::revoke_token(client, tok, which = "access")
  testthat::expect_true(isTRUE(rev_result$supported))
  testthat::expect_true(
    isTRUE(rev_result$revoked),
    info = "revoke_token should succeed with status = 'ok'"
  )
  testthat::expect_identical(rev_result$status, "ok")

  # 3) Introspect again: token should no longer be active
  intros_after <- shinyOAuth::introspect_token(client, tok, which = "access")
  testthat::expect_true(isTRUE(intros_after$supported))
  testthat::expect_false(
    isTRUE(intros_after$active),
    info = "Token should be inactive after revocation"
  )
})

testthat::test_that("revoke_token works with different auth styles (integration)", {
  testthat::skip_if_not(
    keycloak_reachable(),
    "Keycloak not reachable at localhost:8080"
  )

  issuer <- get_issuer()

  # Test with body (client_secret_post) style
  prov_body <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth",
    token_auth_style = "body"
  )

  # Obtain a token
  token_resp <- httr2::request(prov_body@token_url) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_body_form(
      grant_type = "client_credentials",
      client_id = "shiny-confidential",
      client_secret = "secret"
    ) |>
    httr2::req_perform()

  testthat::expect_false(httr2::resp_is_error(token_resp))
  parsed <- httr2::resp_body_json(token_resp, simplifyVector = TRUE)
  at <- parsed$access_token

  client_body <- shinyOAuth::oauth_client(
    provider = prov_body,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = character()
  )
  tok <- shinyOAuth::OAuthToken(access_token = at)

  # Verify active before
  intros_before <- shinyOAuth::introspect_token(
    client_body,
    tok,
    which = "access"
  )
  testthat::expect_true(isTRUE(intros_before$active))

  # Revoke with body auth style

  rev_result <- shinyOAuth::revoke_token(client_body, tok, which = "access")
  testthat::expect_true(isTRUE(rev_result$revoked))
  testthat::expect_identical(rev_result$status, "ok")

  # Verify inactive after
  intros_after <- shinyOAuth::introspect_token(
    client_body,
    tok,
    which = "access"
  )
  testthat::expect_false(isTRUE(intros_after$active))
})
