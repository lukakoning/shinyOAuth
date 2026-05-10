## Integration tests: Keycloak JAR unhappy paths

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Keycloak request-object rejects wrong signing key", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")
  client@client_private_key <- openssl::rsa_keygen()

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      resp <- httr2::request(auth_url) |>
        req_apply_keycloak_ca() |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "text/html") |>
        httr2::req_options(followlocation = FALSE) |>
        httr2::req_perform()
      status <- httr2::resp_status(resp)
      loc <- httr2::resp_header(resp, "location")

      testthat::expect_match(auth_url, "[?&]request=")

      callback <- if (
        is.character(loc) && length(loc) == 1L && !is.na(loc) && nzchar(loc)
      ) {
        parse_callback_redirect(loc, client@redirect_uri)
      } else {
        list(is_callback = FALSE, code = NA_character_, state = NA_character_)
      }
      if (status >= 300 && status < 400 && isTRUE(callback$is_callback)) {
        values$.process_query(callback_query(list(
          code = callback$code,
          state_payload = callback$state,
          callback_url = loc
        )))
        session$flushReact()
        combo <- paste(
          values$error %||% "",
          values$error_description %||% "",
          loc
        )
      } else {
        combo <- paste(status, loc %||% "", httr2::resp_body_string(resp))
        testthat::expect_true(httr2::resp_is_error(resp))
      }

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(is.null(values$token))
      testthat::expect_match(
        combo,
        "invalid_request|request object|signature|jwt",
        ignore.case = TRUE
      )
    }
  )
})

testthat::test_that("Keycloak PAR rejects request-object wrong signing key", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt", use_par = TRUE)
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")
  client@client_private_key <- openssl::rsa_keygen()

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
        "Pushed authorization request failed|invalid_request|request object|signature|jwt",
        perl = TRUE,
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
    }
  )
})
