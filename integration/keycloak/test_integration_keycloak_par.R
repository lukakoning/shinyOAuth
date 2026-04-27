## Integration tests: Keycloak Pushed Authorization Requests (PAR)
##
## Goal: prove the package can discover Keycloak's PAR endpoint, push the
## authorization request, and still complete the public-client PKCE code flow.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Keycloak PAR happy path (public client)", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  testthat::expect_true(
    is.character(prov@par_url) &&
      nzchar(prov@par_url)
  )
  testthat::expect_identical(
    prov@par_url,
    get_discovery_document()$pushed_authorization_request_endpoint
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_match(auth_url, "[?&]request_uri=")
      testthat::expect_match(auth_url, "[?&]client_id=shiny-public")
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]code_challenge=", auth_url))

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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
      testthat::expect_identical(
        values$token@userinfo$preferred_username,
        "alice"
      )
    }
  )
})

testthat::test_that("Keycloak PAR happy path (confidential client with header auth)", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "header")
  client <- make_confidential_client(prov)

  testthat::expect_true(
    is.character(prov@par_url) &&
      nzchar(prov@par_url)
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_match(auth_url, "[?&]request_uri=")
      testthat::expect_match(auth_url, "[?&]client_id=shiny-confidential")
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]code_challenge=", auth_url))

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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
      testthat::expect_identical(
        values$token@userinfo$preferred_username,
        "alice"
      )
    }
  )
})

testthat::test_that("Keycloak PAR happy path (client_secret_jwt)", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "client_secret_jwt")
  client <- make_client_secret_jwt_client(prov)

  testthat::expect_true(
    is.character(prov@par_url) &&
      nzchar(prov@par_url)
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_match(auth_url, "[?&]request_uri=")
      testthat::expect_match(auth_url, "[?&]client_id=shiny-csjwt")
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]client_assertion=", auth_url))

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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
      testthat::expect_identical(
        values$token@userinfo$preferred_username,
        "alice"
      )
    }
  )
})

testthat::test_that("Keycloak PAR happy path (private_key_jwt)", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jwt_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  testthat::expect_true(
    is.character(prov@par_url) &&
      nzchar(prov@par_url)
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_match(auth_url, "[?&]request_uri=")
      testthat::expect_match(auth_url, "[?&]client_id=shiny-pjwt")
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]client_assertion=", auth_url))

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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
      testthat::expect_identical(
        values$token@userinfo$preferred_username,
        "alice"
      )
    }
  )
})
