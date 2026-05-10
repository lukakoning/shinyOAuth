## Integration tests: Keycloak JAR unhappy paths

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Keycloak request-object rejects wrong audience", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")
  client@authorization_request_audience <- "https://example.com/not-keycloak"

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_match(auth_url, "[?&]request=")

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

      values$.process_query(callback_query(res))
      session$flushReact()

      combo <- paste(values$error %||% "", values$error_description %||% "")
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(is.null(values$token))
      testthat::expect_match(
        combo,
        "invalid_request|request object|aud|audience",
        ignore.case = TRUE
      )
    }
  )
})

testthat::test_that("Keycloak PAR rejects request-object wrong audience", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt", use_par = TRUE)
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")
  client@authorization_request_audience <- "https://example.com/not-keycloak"

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
        "Pushed authorization request failed|invalid_request|request object|aud|audience",
        perl = TRUE,
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
    }
  )
})
