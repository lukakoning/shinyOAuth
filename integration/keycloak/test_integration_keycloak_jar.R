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
      testthat::expect_match(auth_url, "[?&]client_id=shiny-confidential")
      testthat::expect_false(grepl("[?&]request_uri=", auth_url))
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]code_challenge=", auth_url))

      request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
      header <- shinyOAuth:::parse_jwt_header(request_jwt)
      payload <- decode_compact_jwt_payload(request_jwt)

      testthat::expect_identical(header$typ, "oauth-authz-req+jwt")
      testthat::expect_identical(header$alg, "HS256")
      testthat::expect_identical(payload$iss, "shiny-confidential")
      testthat::expect_identical(payload$aud, get_issuer())
      testthat::expect_identical(payload$client_id, "shiny-confidential")
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
