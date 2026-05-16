## Headless protocol integration: full code flow against Keycloak
##
## This test drives the authorization flow over HTTP inside testServer. It is
## useful for protocol assertions, but browser-boundary behavior is covered by
## the *_browser*.R and *_e2e.R tests.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Shiny module integration: full code flow against Keycloak", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      testthat::expect_true(is.character(url) && nzchar(url))
      res <- perform_login_form(url, redirect_uri = client@redirect_uri)
      testthat::expect_true(
        is.character(res$callback_url) && nzchar(res$callback_url)
      )
      testthat::expect_true(
        is.character(res$state_payload) && nzchar(res$state_payload)
      )

      values$.process_query(callback_query(res))
      session$flushReact()
      expect_keycloak_module_login_invariants(
        authenticated = values$authenticated,
        error = values$error,
        error_description = values$error_description,
        error_uri = values$error_uri,
        token = values$token,
        client = client,
        expected_username = "alice"
      )
    }
  )
})
