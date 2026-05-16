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
  client@client_private_key <- openssl::rsa_keygen()

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
  client@client_private_key <- openssl::rsa_keygen()

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      testthat::expect_true(is.na(auth_url))
      testthat::expect_identical(values$error, "auth_url_error")
      testthat::expect_match(
        values$error_description %||% "",
        "Pushed authorization request failed",
        fixed = TRUE
      )
      testthat::expect_match(
        values$error_description %||% "",
        "invalid_request|request object|signature|jwt",
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
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
        "Pushed authorization request failed",
        fixed = TRUE
      )
      testthat::expect_match(
        values$error_description %||% "",
        "invalid_request|request object|decrypt|encryption|jwt",
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
    }
  )
})
