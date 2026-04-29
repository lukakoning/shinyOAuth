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

      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token))
    }
  )
})
