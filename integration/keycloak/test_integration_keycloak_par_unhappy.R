## Integration tests: Keycloak PAR unhappy paths

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Keycloak PAR rejects wrong JWT client assertion audience", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "client_secret_jwt", use_par = TRUE)
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = "secretjwt",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_assertion_alg = "HS256",
    client_assertion_audience = "https://example.com/not-keycloak"
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      combo <- paste(values$error %||% "", values$error_description %||% "")

      testthat::expect_true(is.na(auth_url))
      testthat::expect_true(!is.null(values$error))
      testthat::expect_match(
        combo,
        "Pushed authorization request failed|invalid_client|aud",
        perl = TRUE,
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
    }
  )
})
