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

expect_mtls_par_build_auth_url_failure <- function(
  cert_variant,
  description_pattern
) {
  prov <- make_mtls_provider(
    token_auth_style = "tls_client_auth",
    use_par = TRUE
  )
  client <- make_mtls_confidential_client(prov, cert_variant = cert_variant)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_true(is.na(auth_url))
      testthat::expect_identical(values$error, "auth_url_error")
      testthat::expect_null(values$error_uri)
      testthat::expect_match(
        values$error_description %||% "",
        description_pattern,
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
    }
  )
}

build_raw_mtls_par_params <- function(client) {
  scopes <- shinyOAuth:::effective_client_scopes(client)
  state <- shinyOAuth:::random_urlsafe(n = client@state_entropy %||% 64)
  shinyOAuth:::validate_state(state)

  pkce_code_challenge <- NULL
  pkce_method <- NULL
  if (isTRUE(client@provider@use_pkce)) {
    pkce_code_verifier <- shinyOAuth:::gen_code_verifier(64)
    pkce_code_challenge <- shinyOAuth:::base64url_encode(
      openssl::sha256(charToRaw(pkce_code_verifier))
    )
    pkce_method <- client@provider@pkce_method %||% "S256"
  }

  nonce <- NULL
  if (isTRUE(client@provider@use_nonce)) {
    nonce <- shinyOAuth:::random_urlsafe(n = 32)
  }

  payload <- shinyOAuth:::compact_list(list(
    state = state,
    client_id = client@client_id,
    redirect_uri = client@redirect_uri,
    scopes = scopes,
    provider = shinyOAuth:::provider_fingerprint(client@provider),
    client_policy = shinyOAuth:::state_client_policy_fingerprint(client),
    issued_at = as.numeric(Sys.time()),
    trace_id = shinyOAuth:::gen_trace_id()
  )) |>
    shinyOAuth:::state_encrypt_gcm(key = client@state_key)

  shinyOAuth:::build_authorization_params(
    oauth_client = client,
    payload = payload,
    scopes = scopes,
    pkce_code_challenge = pkce_code_challenge,
    pkce_method = pkce_method,
    nonce = nonce
  )
}

raw_mtls_par_request <- function(
  client,
  cert_variant = c("valid", "wrong", "rogue", "none")
) {
  cert_variant <- match.arg(cert_variant)
  endpoint <- shinyOAuth:::resolve_provider_endpoint_url(
    client@provider,
    "par_endpoint",
    prefer_mtls = TRUE
  )
  params <- build_raw_mtls_par_params(client)
  req <- httr2::request(endpoint) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_method("POST")

  prepared <- shinyOAuth:::apply_direct_client_auth(
    req = req,
    params = params,
    client = client,
    context = "pushed_authorization_request"
  )
  req <- prepared$req
  params <- prepared$params

  if (!identical(cert_variant, "none")) {
    req <- req_apply_keycloak_client_certificate(req, cert_variant)
  }

  req <- do.call(httr2::req_body_form, c(list(req), params))
  req |> httr2::req_perform()
}

create_temp_certificate_bound_public_client <- function() {
  admin_token <- keycloak_admin_token()
  fixture <- keycloak_create_client(
    admin_token,
    list(
      clientId = keycloak_temp_client_id("shiny-mtls-bound-public"),
      protocol = "openid-connect",
      publicClient = TRUE,
      redirectUris = keycloak_default_redirect_uris(),
      webOrigins = list("+"),
      standardFlowEnabled = TRUE,
      implicitFlowEnabled = FALSE,
      serviceAccountsEnabled = FALSE,
      directAccessGrantsEnabled = FALSE,
      attributes = list(
        "pkce.code.challenge.method" = "S256",
        "tls.client.certificate.bound.access.tokens" = "true"
      )
    )
  )

  list(admin_token = admin_token, fixture = fixture)
}

create_temp_certificate_bound_client_secret_jwt_client <- function() {
  admin_token <- keycloak_admin_token()
  body <- keycloak_oidc_client_body(
    client_id = keycloak_temp_client_id("shiny-mtls-bound-csjwt"),
    public_client = FALSE,
    service_accounts_enabled = FALSE,
    client_authenticator_type = "client-secret-jwt",
    attributes = list(
      "pkce.code.challenge.method" = "S256",
      "token.endpoint.auth.signing.alg" = "HS256",
      "tls.client.certificate.bound.access.tokens" = "true"
    )
  )
  body[["secret"]] <- get_client_secret_jwt_secret()

  fixture <- keycloak_create_client(admin_token, body)

  list(admin_token = admin_token, fixture = fixture)
}

make_certificate_bound_public_client <- function(
  prov,
  client_id,
  cert_variant = c("valid", "wrong", "rogue")
) {
  cert_variant <- match.arg(cert_variant)

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    mtls_client_cert_file = get_keycloak_tls_client_cert_file(cert_variant),
    mtls_client_key_file = get_keycloak_tls_client_key_file(cert_variant),
    mtls_client_ca_file = get_keycloak_tls_ca_file(),
    mtls_certificate_bound_access_tokens = TRUE
  )
}

make_certificate_bound_client_secret_jwt_client <- function(
  prov,
  client_id,
  cert_variant = c("valid", "wrong", "rogue"),
  client_assertion_audience = NA_character_
) {
  cert_variant <- match.arg(cert_variant)

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = get_client_secret_jwt_secret(),
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_assertion_alg = "HS256",
    client_assertion_audience = client_assertion_audience,
    mtls_client_cert_file = get_keycloak_tls_client_cert_file(cert_variant),
    mtls_client_key_file = get_keycloak_tls_client_key_file(cert_variant),
    mtls_client_ca_file = get_keycloak_tls_ca_file(),
    mtls_certificate_bound_access_tokens = TRUE
  )
}

build_prepared_mtls_par_request <- function(
  client,
  cert_variant = c("valid", "wrong", "rogue", "none")
) {
  cert_variant <- match.arg(cert_variant)
  endpoint <- shinyOAuth:::resolve_provider_endpoint_url(
    client@provider,
    "par_endpoint",
    prefer_mtls = TRUE
  )
  params <- build_raw_mtls_par_params(client)
  req <- httr2::request(endpoint) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_method("POST")

  prepared <- shinyOAuth:::apply_direct_client_auth(
    req = req,
    params = params,
    client = client,
    context = "pushed_authorization_request"
  )

  client_assertion <- prepared$params$client_assertion %||% NA_character_
  assertion_payload <- if (keycloak_nonempty_string(client_assertion)) {
    shinyOAuth:::parse_jwt_payload(client_assertion)
  } else {
    list()
  }

  req <- prepared$req
  if (!identical(cert_variant, "none")) {
    req <- req_apply_keycloak_client_certificate(req, cert_variant)
  }

  list(
    url = endpoint,
    req = do.call(httr2::req_body_form, c(list(req), prepared$params)),
    client_assertion = client_assertion,
    assertion_payload = assertion_payload
  )
}

raw_mtls_refresh_request <- function(
  client,
  refresh_token,
  cert_variant = c("valid", "wrong", "rogue", "none")
) {
  cert_variant <- match.arg(cert_variant)

  raw_mtls_token_request(
    provider = client@provider,
    params = list(
      grant_type = "refresh_token",
      refresh_token = refresh_token,
      client_id = client@client_id
    ),
    cert_variant = cert_variant
  )
}

testthat::test_that("Keycloak HTTPS discovery wires mTLS metadata into make_mtls_provider", {
  skip_mtls_common()
  local_test_options()

  disc <- get_https_discovery_document(force = TRUE)
  prov <- make_mtls_provider(
    token_auth_style = "tls_client_auth",
    use_par = TRUE
  )

  testthat::expect_true(isTRUE(
    prov@mtls_client_certificate_bound_access_tokens
  ))
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
  testthat::expect_identical(login$token@cnf[["x5t#S256"]], access_x5t)

  userinfo <- shinyOAuth::get_userinfo(client, login$token)
  testthat::expect_true(is.list(userinfo))
  testthat::expect_identical(userinfo[["sub"]], login$token@userinfo[["sub"]])

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

testthat::test_that("Keycloak can issue certificate-bound tokens for a public client without tls_client_auth", {
  skip_mtls_common()
  local_test_options()

  fixture <- create_temp_certificate_bound_public_client()
  on.exit(
    keycloak_delete_client(
      fixture$admin_token,
      id = fixture$fixture$id
    ),
    add = TRUE
  )

  prov <- make_mtls_provider(token_auth_style = "body")
  client <- make_certificate_bound_public_client(
    prov,
    client_id = fixture$fixture$client_id
  )

  testthat::expect_identical(prov@token_auth_style, "body")
  testthat::expect_true(isTRUE(
    prov@mtls_client_certificate_bound_access_tokens
  ))
  testthat::expect_identical(
    shinyOAuth:::resolve_provider_endpoint_url(
      client@provider,
      "token_endpoint",
      prefer_mtls = TRUE
    ),
    client@provider@mtls_endpoint_aliases$token_endpoint
  )
  testthat::expect_identical(
    shinyOAuth:::resolve_provider_endpoint_url(
      client@provider,
      "userinfo_endpoint",
      prefer_mtls = TRUE
    ),
    client@provider@mtls_endpoint_aliases$userinfo_endpoint
  )

  login <- perform_mtls_module_login(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_null(login$error)
  testthat::expect_false(is.null(login$token))
  testthat::expect_true(nzchar(login$token@access_token %||% ""))

  access_x5t <- access_token_cnf_x5t_s256(login$token@access_token)
  testthat::expect_identical(access_x5t, tls_client_thumbprint("valid"))
  testthat::expect_identical(login$token@cnf[["x5t#S256"]], access_x5t)

  userinfo <- shinyOAuth::get_userinfo(client, login$token)
  testthat::expect_true(is.list(userinfo))
  testthat::expect_identical(userinfo[["sub"]], login$token@userinfo[["sub"]])

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

testthat::test_that("Keycloak PAR over the mTLS alias accepts issuer-audience client_secret_jwt assertions", {
  skip_mtls_common()
  local_test_options()

  fixture <- create_temp_certificate_bound_client_secret_jwt_client()
  on.exit(
    keycloak_delete_client(
      fixture$admin_token,
      id = fixture$fixture$id
    ),
    add = TRUE
  )

  prov <- make_mtls_provider(
    token_auth_style = "client_secret_jwt",
    use_par = TRUE
  )
  client <- make_certificate_bound_client_secret_jwt_client(
    prov,
    client_id = fixture$fixture$client_id
  )
  prepared <- build_prepared_mtls_par_request(client)

  testthat::expect_identical(
    prepared$url,
    client@provider@mtls_endpoint_aliases$par_endpoint
  )
  testthat::expect_identical(
    prepared$assertion_payload$aud,
    client@provider@issuer
  )

  resp <- httr2::req_perform(prepared$req)
  body <- safe_resp_body_json(resp)

  testthat::expect_identical(httr2::resp_status(resp), 201L)
  testthat::expect_match(
    body[["request_uri"]] %||% "",
    "^urn:ietf:params:oauth:request_uri:"
  )

  login <- perform_mtls_module_login(client)
  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_false(is.null(login$token))
  testthat::expect_identical(
    access_token_cnf_x5t_s256(login$token@access_token),
    tls_client_thumbprint("valid")
  )

  wrong_audience_client <- make_certificate_bound_client_secret_jwt_client(
    prov,
    client_id = fixture$fixture$client_id,
    client_assertion_audience = "https://example.com/not-keycloak"
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(wrong_audience_client),
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
        "Authentication failed.",
        fixed = TRUE
      )
      testthat::expect_length(wrong_audience_client@state_store$keys(), 0L)
    }
  )
})

testthat::test_that("Keycloak mTLS protected resource helper reaches the userinfo endpoint", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(token_auth_style = "tls_client_auth")
  client <- make_mtls_confidential_client(prov)

  login <- perform_mtls_module_login(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_false(is.null(login$token))

  resp <- shinyOAuth::perform_resource_req(
    token = login$token,
    url = get_mtls_endpoint_url(client@provider, "userinfo_endpoint"),
    oauth_client = client
  )
  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)

  testthat::expect_identical(httr2::resp_status(resp), 200L)
  testthat::expect_identical(body[["sub"]], login$token@userinfo[["sub"]])
  testthat::expect_identical(
    body[["preferred_username"]],
    login$token@userinfo[["preferred_username"]]
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
      testthat::expect_null(values$error_description)
      testthat::expect_null(values$error_uri)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token %||% ""))
      testthat::expect_identical(
        values$token@userinfo[["preferred_username"]],
        "alice"
      )
      testthat::expect_identical(
        access_token_cnf_x5t_s256(values$token@access_token),
        tls_client_thumbprint("valid")
      )
    }
  )
})

testthat::test_that("Keycloak mTLS PAR endpoint rejects a missing client certificate", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(
    token_auth_style = "tls_client_auth",
    use_par = TRUE
  )
  client <- make_mtls_confidential_client(prov)
  no_cert_resp <- raw_mtls_par_request(client, cert_variant = "none")
  no_cert_body <- safe_resp_body_json(no_cert_resp)

  testthat::expect_identical(httr2::resp_status(no_cert_resp), 401L)
  testthat::expect_identical(no_cert_body$error, "invalid_request")
  testthat::expect_identical(
    no_cert_body$error_description,
    "Authentication failed."
  )
})

testthat::test_that("Keycloak mTLS PAR build_auth_url fails on a wrong client certificate", {
  skip_mtls_common()
  local_test_options()

  expect_mtls_par_build_auth_url_failure(
    cert_variant = "wrong",
    description_pattern = paste(
      "Pushed authorization request failed|invalid_client|",
      "invalid_client_credentials|unauthorized_client"
    )
  )
})

testthat::test_that("Keycloak mTLS PAR fails closed on a rogue CA certificate at the PAR endpoint", {
  skip_mtls_common()
  local_test_options()

  expect_mtls_par_build_auth_url_failure(
    cert_variant = "rogue",
    description_pattern = paste(
      "Pushed authorization request failed|Transport failure|",
      "certificate unknown|unknown ca|tls alert|No HTTP response"
    )
  )
})

testthat::test_that("Keycloak mTLS auth-code flow surfaces wrong certificate errors through oauth_module_server", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(token_auth_style = "tls_client_auth")
  wrong_client <- make_mtls_confidential_client(prov, cert_variant = "wrong")

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(wrong_client),
    expr = {
      auth_url <- values$build_auth_url()
      state_info <- get_state_info(wrong_client, auth_url)
      login <- perform_login_form_as(
        auth_url,
        redirect_uri = wrong_client@redirect_uri
      )
      query <- callback_query(login)

      values$.process_query(query)
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(is.null(values$token))
      testthat::expect_identical(values$error, "token_exchange_error")
      combo <- paste(values$error_description %||% "")
      testthat::expect_match(
        combo,
        "Transport failure|invalid_client|invalid_client_credentials|certificate|tls alert|No HTTP response",
        ignore.case = TRUE
      )
      testthat::expect_null(
        wrong_client@state_store$get(state_info$key, missing = NULL)
      )

      values$error <- NULL
      values$error_description <- NULL
      values$error_uri <- NULL

      values$.process_query(query)
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(
        values$error_description %||% "",
        "state",
        ignore.case = TRUE
      )
    }
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

  prov <- make_mtls_provider(
    token_auth_style = "tls_client_auth",
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE
  )
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

testthat::test_that("Keycloak mTLS refresh rejects the wrong certificate", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(
    token_auth_style = "tls_client_auth",
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE
  )
  client <- make_mtls_confidential_client(prov)

  wrong_login <- perform_mtls_module_login(client)
  testthat::expect_true(isTRUE(wrong_login$authenticated))
  wrong_resp <- raw_mtls_refresh_request(
    client,
    wrong_login$token@refresh_token,
    cert_variant = "wrong"
  )
  expect_mtls_invalid_client(wrong_resp)

  no_cert_login <- perform_mtls_module_login(client)
  testthat::expect_true(isTRUE(no_cert_login$authenticated))
  no_cert_resp <- raw_mtls_refresh_request(
    client,
    no_cert_login$token@refresh_token,
    cert_variant = "none"
  )
  expect_mtls_invalid_client(no_cert_resp)
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
