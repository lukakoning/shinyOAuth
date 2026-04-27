# Full authorization-code flow against Keycloak using JWT client authentication

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

cases <- list(
  list(
    name = "client_secret_jwt",
    style = "client_secret_jwt",
    include = function() TRUE,
    client = make_client_secret_jwt_client
  ),
  list(
    name = "private_key_jwt",
    style = "private_key_jwt",
    include = function() !is.null(get_pjwt_key()),
    client = make_private_key_jwt_client
  )
)

for (case in cases) {
  testthat::test_that(
    paste0("Keycloak code flow using JWT auth: ", case$name),
    {
      maybe_skip_keycloak()
      testthat::skip_if_not_installed("xml2")
      testthat::skip_if_not_installed("rvest")
      if (!isTRUE(case$include())) {
        testthat::skip(paste("Skipping", case$name, "— prerequisites not met"))
      }

      local_test_options()

      prov <- make_provider(token_auth_style = case$style)
      client <- case$client(prov)

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

          values$.process_query(paste0(
            "?code=",
            utils::URLencode(res$code),
            "&state=",
            utils::URLencode(res$state_payload)
          ))
          session$flushReact()

          testthat::expect_true(isTRUE(values$authenticated))
          testthat::expect_null(values$error)
          testthat::expect_false(is.null(values$token))
          testthat::expect_true(nzchar(values$token@access_token))
        }
      )
    }
  )
}
