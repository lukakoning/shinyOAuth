## Integration tests: Keycloak JAR unhappy paths

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

expect_jar_auth_request_rejected <- function(
  auth_url,
  client,
  values,
  session,
  description_pattern
) {
  state_info <- get_state_info(client, auth_url)
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
    callback_url <- loc %||% ""
    callback_error <- parse_query_param(callback_url, "error", decode = TRUE)
    callback_description <- parse_query_param(
      callback_url,
      "error_description",
      decode = TRUE
    )

    testthat::expect_identical(callback_error, "invalid_request")

    values$.process_query(callback_query(list(
      code = callback$code,
      state_payload = callback$state,
      callback_url = callback_url
    )))
    session$flushReact()

    testthat::expect_identical(values$error, "invalid_request")
    testthat::expect_null(client@state_store$get(
      state_info$key,
      missing = NULL
    ))

    combo <- paste(
      callback_error %||% "",
      callback_description %||% "",
      callback_url
    )
  } else {
    combo <- paste(status, loc %||% "", httr2::resp_body_string(resp))
    testthat::expect_true(httr2::resp_is_error(resp))
    testthat::expect_true(status %in% c(400L, 401L), info = combo)
  }

  testthat::expect_false(isTRUE(values$authenticated))
  testthat::expect_true(is.null(values$token))
  testthat::expect_match(combo, description_pattern, ignore.case = TRUE)
}

testthat::test_that("Keycloak request-object rejects wrong signing key", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")
  client@client_assertion_private_key <- openssl::rsa_keygen()

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      expect_jar_auth_request_rejected(
        auth_url = auth_url,
        client = client,
        values = values,
        session = session,
        description_pattern = "invalid_request|request object|signature|jwt"
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

  # A successful control proves this client's PAR authentication and registered
  # Request Object signing key work against the running server.
  control <- make_private_key_jar_client(prov)
  control_url <- shinyOAuth::prepare_call(
    control,
    browser_token = paste(rep("ab", 64), collapse = "")
  )
  testthat::expect_match(control_url, "[?&]request_uri=")

  sign_request_object <- shinyOAuth:::build_authorization_request_object
  perform <- shinyOAuth:::req_with_retry
  wrong_key <- openssl::rsa_keygen()
  par_error <- NULL
  testthat::local_mocked_bindings(
    build_authorization_request_object = function(client, params) {
      # S7 copy-on-modify changes only the signing helper's local client. The
      # original key still signs the independent PAR client assertion.
      client@client_assertion_private_key <- wrong_key
      sign_request_object(client, params)
    },
    req_with_retry = function(req, ...) {
      resp <- perform(req, ...)
      if (identical(req$url, prov@par_url)) {
        par_error <<- httr2::resp_body_json(resp, simplifyVector = FALSE)
      }
      resp
    },
    .package = "shinyOAuth"
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      testthat::expect_true(is.na(auth_url))
      testthat::expect_identical(values$error, "auth_url_error")
      testthat::expect_match(
        values$error_description %||% "",
        "HTTP request failed",
        fixed = TRUE
      )
      testthat::expect_no_match(
        values$error_description %||% "",
        "invalid_request|request object|signature|jwt",
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
      # Keycloak reports invalid_client for failed client authentication. This
      # code and description instead identify Request Object verification.
      testthat::expect_identical(par_error$error, "invalid_request_object")
    }
  )
})

testthat::test_that("Keycloak request-object rejects wrong encryption key", {
  skip_common()
  local_test_options()

  rogue_key <- openssl::rsa_keygen()
  prov <- make_provider(
    token_auth_style = "private_key_jwt",
    request_object_encryption_alg_values_supported = c("RSA-OAEP"),
    request_object_encryption_enc_values_supported = c("A256CBC-HS512"),
    request_object_encryption_jwk = rogue_key$pubkey
  )
  client <- make_private_key_jar_jwe_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      expect_jar_auth_request_rejected(
        auth_url = auth_url,
        client = client,
        values = values,
        session = session,
        description_pattern = "invalid_request|request object|decrypt|encryption|jwt"
      )
    }
  )
})

testthat::test_that("Keycloak PAR rejects request-object wrong encryption key", {
  skip_common()
  local_test_options()

  rogue_key <- openssl::rsa_keygen()
  prov <- make_provider(
    token_auth_style = "private_key_jwt",
    use_par = TRUE,
    request_object_encryption_alg_values_supported = c("RSA-OAEP"),
    request_object_encryption_enc_values_supported = c("A256CBC-HS512"),
    request_object_encryption_jwk = rogue_key$pubkey
  )
  client <- make_private_key_jar_jwe_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      testthat::expect_true(is.na(auth_url))
      testthat::expect_identical(values$error, "auth_url_error")
      testthat::expect_match(
        values$error_description %||% "",
        "HTTP request failed",
        fixed = TRUE
      )
      testthat::expect_no_match(
        values$error_description %||% "",
        "invalid_request|request object|decrypt|encryption|jwt",
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
    }
  )
})
