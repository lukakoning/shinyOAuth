## Integration tests: Keycloak JWT-secured authorization requests (JAR)

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

query_param_names <- function(url) {
  q <- sub("^[^?]*\\?", "", url)
  if (identical(q, url) || !nzchar(q)) {
    return(character(0))
  }

  parts <- strsplit(q, "&", fixed = TRUE)[[1]]
  kv <- strsplit(parts, "=", fixed = TRUE)
  unique(vapply(kv, function(p) utils::URLdecode(p[1]), ""))
}

testthat::test_that("Keycloak request-object happy path (private_key_jwt)", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_setequal(
        query_param_names(auth_url),
        c("client_id", "request")
      )
      testthat::expect_match(auth_url, "[?&]client_id=shiny-jar-pjwt")
      testthat::expect_false(grepl("[?&]request_uri=", auth_url))
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]code_challenge=", auth_url))

      request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
      header <- shinyOAuth:::parse_jwt_header(request_jwt)
      payload <- decode_compact_jwt_payload(request_jwt)

      testthat::expect_identical(header$typ, "oauth-authz-req+jwt")
      testthat::expect_identical(header$alg, "RS256")
      testthat::expect_identical(payload$iss, "shiny-jar-pjwt")
      testthat::expect_identical(payload$aud, get_issuer())
      testthat::expect_identical(payload$client_id, "shiny-jar-pjwt")
      testthat::expect_identical(
        payload$redirect_uri,
        client@redirect_uri
      )
      testthat::expect_true(
        is.character(payload$state) && nzchar(payload$state)
      )
      testthat::expect_true(
        is.character(payload$code_challenge) && nzchar(payload$code_challenge)
      )

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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

testthat::test_that("Keycloak request-object happy path (HS256)", {
  skip_common()
  local_test_options()

  prov <- make_provider(
    token_auth_style = "body",
    request_object_signing_alg_values_supported = c("HS256")
  )
  client <- make_hmac_jar_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_setequal(
        query_param_names(auth_url),
        c("client_id", "request")
      )
      testthat::expect_identical(
        parse_query_param(auth_url, "client_id"),
        client@client_id
      )
      testthat::expect_false(grepl("[?&]request_uri=", auth_url))
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]code_challenge=", auth_url))

      request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
      header <- shinyOAuth:::parse_jwt_header(request_jwt)
      payload <- decode_compact_jwt_payload(request_jwt)

      testthat::expect_identical(header$typ, "oauth-authz-req+jwt")
      testthat::expect_identical(header$alg, "HS256")
      testthat::expect_identical(payload$iss, client@client_id)
      testthat::expect_identical(payload$aud, get_issuer())
      testthat::expect_identical(payload$client_id, client@client_id)
      testthat::expect_false("sub" %in% names(payload))
      testthat::expect_identical(
        payload$redirect_uri,
        client@redirect_uri
      )
      testthat::expect_true(
        is.character(payload$state) && nzchar(payload$state)
      )
      testthat::expect_true(
        is.character(payload$code_challenge) && nzchar(payload$code_challenge)
      )

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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

testthat::test_that("Keycloak encrypted request-object happy path (private_key_jwt)", {
  skip_common()
  local_test_options()

  prov <- make_provider(
    token_auth_style = "private_key_jwt",
    request_object_encryption_alg_values_supported = c("RSA-OAEP"),
    request_object_encryption_enc_values_supported = c("A256CBC-HS512")
  )
  client <- make_private_key_jar_jwe_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_setequal(
        query_param_names(auth_url),
        c("client_id", "request")
      )
      testthat::expect_match(auth_url, "[?&]client_id=shiny-jar-pjwt-jwe")
      testthat::expect_false(grepl("[?&]request_uri=", auth_url))

      request_jwe <- parse_query_param(auth_url, "request", decode = TRUE)
      outer <- shinyOAuth:::jwe_compact_parts(request_jwe)

      testthat::expect_length(strsplit(request_jwe, ".", fixed = TRUE)[[1]], 5L)
      testthat::expect_identical(
        outer$protected_header$typ,
        "oauth-authz-req+jwt"
      )
      testthat::expect_identical(outer$protected_header$cty, "JWT")
      testthat::expect_identical(outer$protected_header$alg, "RSA-OAEP")
      testthat::expect_identical(outer$protected_header$enc, "A256CBC-HS512")

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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

testthat::test_that("Keycloak encrypted request-object happy path (HS256)", {
  skip_common()
  local_test_options()

  prov <- make_provider(
    token_auth_style = "body",
    request_object_signing_alg_values_supported = c("HS256"),
    request_object_encryption_alg_values_supported = c("RSA-OAEP"),
    request_object_encryption_enc_values_supported = c("A256CBC-HS512")
  )
  client <- make_hmac_jar_jwe_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_setequal(
        query_param_names(auth_url),
        c("client_id", "request")
      )
      testthat::expect_identical(
        parse_query_param(auth_url, "client_id"),
        client@client_id
      )

      request_jwe <- parse_query_param(auth_url, "request", decode = TRUE)
      outer <- shinyOAuth:::jwe_compact_parts(request_jwe)

      testthat::expect_length(strsplit(request_jwe, ".", fixed = TRUE)[[1]], 5L)
      testthat::expect_identical(
        outer$protected_header$typ,
        "oauth-authz-req+jwt"
      )
      testthat::expect_identical(outer$protected_header$cty, "JWT")
      testthat::expect_identical(outer$protected_header$alg, "RSA-OAEP")
      testthat::expect_identical(outer$protected_header$enc, "A256CBC-HS512")

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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

testthat::test_that("Keycloak request-object happy path through PAR (private_key_jwt)", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt", use_par = TRUE)
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_setequal(
        query_param_names(auth_url),
        c("client_id", "request_uri")
      )
      testthat::expect_match(auth_url, "[?&]client_id=shiny-jar-pjwt")
      testthat::expect_match(auth_url, "[?&]request_uri=")
      testthat::expect_false(grepl("[?&]request=", auth_url))
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]code_challenge=", auth_url))

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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

testthat::test_that("Keycloak encrypted request-object happy path through PAR (private_key_jwt)", {
  skip_common()
  local_test_options()

  prov <- make_provider(
    token_auth_style = "private_key_jwt",
    use_par = TRUE,
    request_object_encryption_alg_values_supported = c("RSA-OAEP"),
    request_object_encryption_enc_values_supported = c("A256CBC-HS512")
  )
  client <- make_private_key_jar_jwe_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_setequal(
        query_param_names(auth_url),
        c("client_id", "request_uri")
      )
      testthat::expect_match(auth_url, "[?&]client_id=shiny-jar-pjwt-jwe")
      testthat::expect_match(auth_url, "[?&]request_uri=")
      testthat::expect_false(grepl("[?&]request=", auth_url))

      res <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

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
