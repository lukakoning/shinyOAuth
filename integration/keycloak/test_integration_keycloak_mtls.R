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
      values$.process_query(callback_query(login))
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

testthat::test_that("Keycloak HTTPS discovery wires mTLS metadata into make_mtls_provider", {
  skip_mtls_common()
  local_test_options()

  disc <- get_https_discovery_document(force = TRUE)
  prov <- make_mtls_provider(
    token_auth_style = "tls_client_auth",
    use_par = TRUE
  )

  testthat::expect_true(isTRUE(prov@tls_client_certificate_bound_access_tokens))
  testthat::expect_identical(prov@issuer, disc$issuer)
  testthat::expect_identical(
    prov@mtls_endpoint_aliases$token_endpoint,
    disc$mtls_endpoint_aliases$token_endpoint
  )
  testthat::expect_identical(
    prov@mtls_endpoint_aliases$userinfo_endpoint,
    disc$mtls_endpoint_aliases$userinfo_endpoint
  )
  testthat::expect_identical(
    prov@par_url,
    disc$pushed_authorization_request_endpoint
  )
})

testthat::test_that("Keycloak HTTPS discovery rejects unsupported self_signed_tls_client_auth", {
  skip_mtls_common()
  local_test_options()

  testthat::expect_error(
    make_mtls_provider(token_auth_style = "self_signed_tls_client_auth"),
    class = "shinyOAuth_config_error",
    regexp = "Requested token_auth_style is not advertised|self_signed_tls_client_auth"
  )
})

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

testthat::test_that("Keycloak mTLS auth-code flow supports PAR via discovered endpoints", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(
    token_auth_style = "tls_client_auth",
    use_par = TRUE
  )
  client <- make_mtls_confidential_client(prov)

  testthat::expect_true(is.character(prov@par_url) && nzchar(prov@par_url))
  testthat::expect_identical(
    prov@par_url,
    get_https_discovery_document(
      force = TRUE
    )$pushed_authorization_request_endpoint
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_match(auth_url, "[?&]request_uri=")
      testthat::expect_match(auth_url, "[?&]client_id=shiny-mtls-confidential")
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]code_challenge=", auth_url))

      login <- perform_login_form_as(
        auth_url,
        redirect_uri = client@redirect_uri
      )

      values$.process_query(callback_query(login))
      session$flushReact()

      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token %||% ""))
      testthat::expect_identical(
        access_token_cnf_x5t_s256(values$token@access_token),
        tls_client_thumbprint("valid")
      )
    }
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

testthat::test_that("Keycloak mTLS AS endpoints ignore local cnf mismatches on refresh, introspection, and revocation", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(token_auth_style = "tls_client_auth")
  prov@userinfo_required <- FALSE
  client <- make_mtls_confidential_client(prov)

  login <- perform_mtls_module_login(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_false(is.null(login$token))
  testthat::expect_true(nzchar(login$token@access_token %||% ""))
  testthat::expect_true(nzchar(login$token@refresh_token %||% ""))

  access_x5t <- access_token_cnf_x5t_s256(login$token@access_token)
  testthat::expect_identical(access_x5t, tls_client_thumbprint("valid"))

  tampered_refresh_token <- login$token
  tampered_refresh_token@cnf <- list(`x5t#S256` = "mismatched-thumbprint")

  refreshed <- shinyOAuth::refresh_token(
    client,
    tampered_refresh_token,
    introspect = FALSE
  )

  testthat::expect_true(S7::S7_inherits(refreshed, shinyOAuth::OAuthToken))
  testthat::expect_true(nzchar(refreshed@access_token %||% ""))
  testthat::expect_identical(
    access_token_cnf_x5t_s256(refreshed@access_token),
    tls_client_thumbprint("valid")
  )

  tampered_access_token <- login$token
  tampered_access_token@cnf <- list(`x5t#S256` = "mismatched-thumbprint")

  introspection <- shinyOAuth::introspect_token(
    client,
    tampered_access_token,
    which = "access",
    async = FALSE
  )
  testthat::expect_true(isTRUE(introspection$supported))
  testthat::expect_true(isTRUE(introspection$active))
  testthat::expect_identical(introspection$status, "ok")

  revocation <- shinyOAuth::revoke_token(
    client,
    tampered_access_token,
    which = "access",
    async = FALSE
  )
  testthat::expect_true(isTRUE(revocation$supported))
  testthat::expect_true(isTRUE(revocation$revoked))
  testthat::expect_identical(revocation$status, "ok")
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
