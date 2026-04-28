## Integration tests: RFC 8705 mTLS client auth and certificate-bound tokens

if (!exists("make_mtls_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

perform_mtls_module_login <- function(
  client,
  username = "alice",
  password = username
) {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      login <- perform_login_form_as(
        auth_url,
        username = username,
        password = password,
        redirect_uri = client@redirect_uri
      )
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(login$code),
        "&state=",
        utils::URLencode(login$state_payload)
      ))
      session$flushReact()

      result <<- list(
        authenticated = isTRUE(values$authenticated),
        error = values$error,
        error_description = values$error_description,
        token = values$token
      )
    }
  )

  result
}

testthat::test_that("Keycloak mTLS auth-code flow binds tokens and protects userinfo", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(token_auth_style = "tls_client_auth")
  client <- make_mtls_confidential_client(prov)

  login <- perform_mtls_module_login(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_null(login$error)
  testthat::expect_false(is.null(login$token))
  testthat::expect_true(nzchar(login$token@access_token))

  access_x5t <- access_token_cnf_x5t_s256(login$token@access_token)
  testthat::expect_identical(access_x5t, tls_client_thumbprint("valid"))

  userinfo <- shinyOAuth::get_userinfo(client, login$token)
  testthat::expect_true(is.list(userinfo))
  testthat::expect_identical(userinfo$sub, login$token@userinfo$sub)

  no_cert_resp <- raw_mtls_userinfo_request(
    client,
    login$token@access_token,
    cert_variant = "none"
  )
  expect_mtls_sender_constraint_rejection(no_cert_resp)

  wrong_cert_resp <- raw_mtls_userinfo_request(
    client,
    login$token@access_token,
    cert_variant = "wrong"
  )
  expect_mtls_sender_constraint_rejection(wrong_cert_resp)
})

testthat::test_that("Keycloak mTLS auth-code token exchange requires the registered certificate", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(token_auth_style = "tls_client_auth")
  client <- make_mtls_confidential_client(prov)

  ok_login <- perform_mtls_code_login(client)
  ok_resp <- raw_mtls_auth_code_exchange(
    client,
    ok_login,
    cert_variant = "valid"
  )
  testthat::expect_identical(httr2::resp_status(ok_resp), 200L)
  ok_body <- httr2::resp_body_json(ok_resp, simplifyVector = TRUE)
  testthat::expect_true(nzchar(ok_body$access_token %||% ""))
  testthat::expect_identical(
    access_token_cnf_x5t_s256(ok_body$access_token),
    tls_client_thumbprint("valid")
  )

  no_cert_login <- perform_mtls_code_login(client)
  no_cert_resp <- raw_mtls_auth_code_exchange(
    client,
    no_cert_login,
    cert_variant = "none"
  )
  expect_mtls_invalid_client(no_cert_resp)

  wrong_cert_login <- perform_mtls_code_login(client)
  wrong_cert_resp <- raw_mtls_auth_code_exchange(
    client,
    wrong_cert_login,
    cert_variant = "wrong"
  )
  expect_mtls_invalid_client(wrong_cert_resp)
})

testthat::test_that("Keycloak mTLS client-credentials flow issues certificate-bound tokens", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(token_auth_style = "tls_client_auth")
  client <- make_mtls_service_client(prov)

  ok_resp <- raw_mtls_client_credentials_request(
    client,
    cert_variant = "valid"
  )
  testthat::expect_identical(httr2::resp_status(ok_resp), 200L)
  ok_body <- httr2::resp_body_json(ok_resp, simplifyVector = TRUE)
  testthat::expect_true(nzchar(ok_body$access_token %||% ""))
  testthat::expect_identical(
    access_token_cnf_x5t_s256(ok_body$access_token),
    tls_client_thumbprint("valid")
  )

  tok <- shinyOAuth::OAuthToken(access_token = ok_body$access_token)
  introspection <- shinyOAuth::introspect_token(
    client,
    tok,
    which = "access",
    async = FALSE
  )
  testthat::expect_true(isTRUE(introspection$supported))
  testthat::expect_true(
    isTRUE(introspection$active) || is.na(introspection$active)
  )

  no_cert_resp <- raw_mtls_client_credentials_request(
    client,
    cert_variant = "none"
  )
  expect_mtls_invalid_client(no_cert_resp)

  wrong_cert_resp <- raw_mtls_client_credentials_request(
    client,
    cert_variant = "wrong"
  )
  expect_mtls_invalid_client(wrong_cert_resp)
})
