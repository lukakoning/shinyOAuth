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
  testthat::expect_identical(login$token@cnf$`x5t#S256`, access_x5t)

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

  testthat::expect_error(
    raw_mtls_userinfo_request(
      client,
      login$token@access_token,
      cert_variant = "rogue"
    ),
    class = "httr2_failure",
    regexp = "certificate unknown|unknown ca|tls alert"
  )
})

testthat::test_that("Keycloak mTLS auth-code flow surfaces wrong certificate errors through oauth_module_server", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(token_auth_style = "tls_client_auth")
  wrong_client <- make_mtls_confidential_client(prov, cert_variant = "wrong")

  login <- perform_mtls_module_login(wrong_client)

  testthat::expect_false(isTRUE(login$authenticated))
  testthat::expect_true(is.null(login$token))
  testthat::expect_identical(login$error, "token_exchange_error")
  combo <- paste(login$error_description %||% "")
  testthat::expect_match(
    combo,
    "Transport failure|invalid_client|invalid_client_credentials|certificate|tls alert|No HTTP response",
    ignore.case = TRUE
  )
})

testthat::test_that("Keycloak mTLS userinfo surfaces wrong certificate errors through get_userinfo", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(token_auth_style = "tls_client_auth")
  client <- make_mtls_confidential_client(prov)
  wrong_client <- make_mtls_confidential_client(prov, cert_variant = "wrong")

  login <- perform_mtls_module_login(client)
  testthat::expect_true(isTRUE(login$authenticated))

  err <- rlang::catch_cnd(
    shinyOAuth::get_userinfo(wrong_client, login$token),
    classes = "error"
  )

  testthat::expect_s3_class(err, "shinyOAuth_input_error")
  testthat::expect_match(
    conditionMessage(err),
    "certificate does not match token cnf|x5t#S256|Invalid input",
    ignore.case = TRUE
  )
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

  rogue_cert_login <- perform_mtls_code_login(client)
  testthat::expect_error(
    raw_mtls_auth_code_exchange(
      client,
      rogue_cert_login,
      cert_variant = "rogue"
    ),
    class = "httr2_failure",
    regexp = "certificate unknown|unknown ca|tls alert"
  )
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
  testthat::expect_identical(introspection$supported, TRUE)
  testthat::expect_identical(introspection$status, "ok")
  testthat::expect_identical(introspection$active, TRUE)

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

  testthat::expect_error(
    raw_mtls_client_credentials_request(
      client,
      cert_variant = "rogue"
    ),
    class = "httr2_failure",
    regexp = "certificate unknown|unknown ca|tls alert"
  )
})
