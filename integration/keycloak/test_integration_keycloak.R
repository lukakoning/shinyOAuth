testthat::test_that("Keycloak discovery and introspection (integration)", {
  issuer <- "http://localhost:8080/realms/shinyoauth"

  # Fast reachability check; skip if Keycloak not running
  ok <- tryCatch(
    {
      resp <- httr2::request(paste0(
        issuer,
        "/.well-known/openid-configuration"
      )) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "application/json") |>
        httr2::req_perform()
      !httr2::resp_is_error(resp)
    },
    error = function(...) FALSE
  )
  testthat::skip_if_not(ok, "Keycloak not reachable at localhost:8080")

  # Discover provider for the realm
  prov <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )

  testthat::expect_true(S7::S7_inherits(
    prov,
    class = shinyOAuth::OAuthProvider
  ))
  testthat::expect_identical(prov@issuer, issuer)
  testthat::expect_true(nzchar(prov@token_url))
  testthat::expect_true(nzchar(prov@introspection_url))

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
  testthat::expect_true(is.list(parsed))
  at <- parsed$access_token
  testthat::expect_true(is.character(at) && length(at) == 1 && nzchar(at))

  # Build an OAuthClient for introspection auth and introspect the access token
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = character()
  )
  tok <- shinyOAuth::OAuthToken(access_token = at)
  intros <- shinyOAuth::introspect_token(
    client,
    tok,
    which = "access",
    async = FALSE
  )

  testthat::expect_true(isTRUE(intros$supported))
  # We expect the service account token to be active; if not determinable, NA is allowed
  testthat::expect_true(isTRUE(intros$active) || is.na(intros$active))
})
