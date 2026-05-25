## Integration tests: Keycloak JWT-secured authorization responses (JARM)

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

.jarm_jwks_public_base_url <- function(port) {
  override <- Sys.getenv("SHINYOAUTH_E2E_JARM_JWKS_BASE_URL", "")
  if (nzchar(override)) {
    return(override)
  }

  sprintf("http://host.docker.internal:%d", port)
}

.start_jarm_jwks_server <- function(
  key,
  port,
  public_base_url,
  .local_envir = parent.frame()
) {
  testthat::skip_if_not_installed("callr")
  testthat::skip_if_not_installed("webfakes")

  jwk <- jsonlite::fromJSON(jose::write_jwk(key$pubkey), simplifyVector = FALSE)
  jwk$kid <- "jarm-enc-1"
  jwk$use <- "enc"
  jwk$alg <- "RSA-OAEP"
  jwks_json <- jsonlite::toJSON(
    list(keys = list(jwk)),
    auto_unbox = TRUE,
    null = "null"
  )

  stdout <- tempfile("jarm-jwks-stdout-", fileext = ".log")
  stderr <- tempfile("jarm-jwks-stderr-", fileext = ".log")

  process <- callr::r_bg(
    func = function(port, jwks_json) {
      app <- webfakes::new_app()
      app$get("/jwks", function(req, res) {
        res$set_type("application/json")
        res$send(jwks_json)
      })
      app$listen(
        port = as.integer(port),
        opts = webfakes::server_opts(interfaces = "0.0.0.0")
      )
    },
    args = list(port = as.integer(port), jwks_json = jwks_json),
    stdout = stdout,
    stderr = stderr,
    supervise = TRUE
  )

  local_jwks_url <- paste0("http://127.0.0.1:", as.integer(port), "/jwks")
  deadline <- Sys.time() + 5
  repeat {
    if (!process$is_alive()) {
      stop(
        paste(
          "JARM JWKS server exited before it was reachable.",
          paste(readLines(stderr, warn = FALSE), collapse = "\n"),
          sep = "\n"
        ),
        call. = FALSE
      )
    }

    ready <- tryCatch(
      {
        resp <- httr2::request(local_jwks_url) |>
          httr2::req_error(is_error = function(resp) FALSE) |>
          httr2::req_perform()
        identical(httr2::resp_status(resp), 200L)
      },
      error = function(...) FALSE
    )
    if (isTRUE(ready)) {
      break
    }
    if (Sys.time() > deadline) {
      stop("JARM JWKS server did not start in time", call. = FALSE)
    }
    Sys.sleep(0.1)
  }

  list(
    process = process,
    stdout = stdout,
    stderr = stderr,
    jwks_url = paste0(sub("/+$", "", public_base_url), "/jwks")
  )
}

extract_jarm_response <- function(login_result) {
  response <- login_result$response %||% NA_character_

  if (
    !keycloak_nonempty_string(response) &&
      is.list(login_result$form_post_fields)
  ) {
    response <- login_result$form_post_fields$response %||% NA_character_
  }

  if (!keycloak_nonempty_string(response)) {
    response <- parse_query_param(
      login_result$callback_url %||% NA_character_,
      "response",
      decode = TRUE
    )
  }

  response
}

create_signed_jarm_fixture <- function(
  prefix,
  attributes = list(),
  redirect_uris = keycloak_default_redirect_uris(),
  public_client = TRUE,
  client_authenticator_type = "client-secret",
  service_accounts_enabled = FALSE
) {
  admin_token <- keycloak_admin_token()
  fixture <- keycloak_create_client(
    token = admin_token,
    body = keycloak_oidc_client_body(
      client_id = keycloak_temp_client_id(prefix),
      public_client = public_client,
      redirect_uris = redirect_uris,
      service_accounts_enabled = service_accounts_enabled,
      client_authenticator_type = client_authenticator_type,
      attributes = utils::modifyList(
        list(
          "pkce.code.challenge.method" = "S256",
          "authorization.signed.response.alg" = "RS256"
        ),
        attributes
      )
    )
  )

  list(admin_token = admin_token, fixture = fixture)
}

make_signed_jarm_public_client <- function(
  provider,
  client_id,
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  response_mode = "query.jwt",
  ...
) {
  shinyOAuth::oauth_client(
    provider = provider,
    client_id = client_id,
    client_secret = "",
    redirect_uri = redirect_uri,
    scopes = scopes,
    response_mode = response_mode,
    authorization_signed_response_alg = "RS256",
    ...
  )
}

testthat::test_that("Keycloak signed query.jwt happy path", {
  skip_common()
  local_test_options()

  admin_token <- keycloak_admin_token()
  fixture <- keycloak_create_client(
    token = admin_token,
    body = keycloak_oidc_client_body(
      client_id = keycloak_temp_client_id("shiny-jarm-public"),
      public_client = TRUE,
      attributes = list(
        "pkce.code.challenge.method" = "S256",
        "authorization.signed.response.alg" = "RS256"
      )
    )
  )
  on.exit(
    keycloak_delete_client(admin_token, id = fixture$id),
    add = TRUE
  )

  prov <- make_provider()
  testthat::expect_true(
    "query.jwt" %in% (prov@response_modes_supported %||% character())
  )
  testthat::expect_true(
    "RS256" %in%
      (prov@authorization_signing_alg_values_supported %||% character())
  )

  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = fixture$client_id,
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    response_mode = "query.jwt",
    authorization_signed_response_alg = "RS256"
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_identical(
        parse_query_param(auth_url, "response_mode", decode = TRUE),
        "query.jwt"
      )

      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      response_jwt <- extract_jarm_response(login)

      testthat::expect_true(keycloak_nonempty_string(response_jwt))
      testthat::expect_false(grepl("[?&]code=", login$callback_url))
      testthat::expect_false(grepl("[?&]state=", login$callback_url))
      testthat::expect_identical(
        shinyOAuth:::parse_jwt_header(response_jwt)$alg,
        "RS256"
      )
      testthat::expect_match(
        rawToChar(shinyOAuth:::jwt_compact_parts(response_jwt)$payload_raw),
        '"code"[[:space:]]*:',
        perl = TRUE
      )

      values$.process_query(callback_query(login))
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

testthat::test_that("Keycloak signed jwt alias happy path", {
  skip_common()
  local_test_options()

  setup <- create_signed_jarm_fixture("shiny-jarm-jwt-alias")
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  prov <- make_provider()
  testthat::expect_true(
    "jwt" %in% (prov@response_modes_supported %||% character())
  )
  testthat::expect_true(
    "RS256" %in%
      (prov@authorization_signing_alg_values_supported %||% character())
  )

  client <- make_signed_jarm_public_client(
    prov,
    setup$fixture$client_id,
    response_mode = "jwt"
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_identical(
        parse_query_param(auth_url, "response_mode", decode = TRUE),
        "jwt"
      )

      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      response_jwt <- extract_jarm_response(login)

      testthat::expect_true(keycloak_nonempty_string(response_jwt))
      testthat::expect_false(grepl("[?&]code=", login$callback_url))
      testthat::expect_false(grepl("[?&]state=", login$callback_url))
      testthat::expect_identical(
        shinyOAuth:::parse_jwt_header(response_jwt)$alg,
        "RS256"
      )
      testthat::expect_match(
        rawToChar(shinyOAuth:::jwt_compact_parts(response_jwt)$payload_raw),
        '"code"[[:space:]]*:',
        perl = TRUE
      )

      values$.process_query(callback_query(login))
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

testthat::test_that("Keycloak query.jwt clients reject direct query callbacks without consuming state", {
  skip_common()
  local_test_options()

  setup <- create_signed_jarm_fixture("shiny-jarm-direct-query")
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  prov <- make_provider()
  client <- make_signed_jarm_public_client(prov, setup$fixture$client_id)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      enc_state <- parse_query_param(auth_url, "state", decode = TRUE)
      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)

      testthat::expect_true(keycloak_nonempty_string(extract_jarm_response(
        login
      )))
      testthat::expect_length(client@state_store$keys(), 1L)

      values$.process_query(paste0(
        "?code=attacker-code",
        "&state=",
        utils::URLencode(enc_state, reserved = TRUE),
        "&iss=",
        utils::URLencode(client@provider@issuer, reserved = TRUE)
      ))
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "invalid_callback_query")
      testthat::expect_match(
        values$error_description %||% "",
        "response parameter"
      )
      testthat::expect_length(client@state_store$keys(), 1L)

      values$error <- NULL
      values$error_description <- NULL
      values$error_uri <- NULL

      values$.process_query(callback_query(login))
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

testthat::test_that("Keycloak encrypted query.jwt happy path", {
  skip_common()
  local_test_options()
  testthat::skip_if_not_installed("webfakes")

  private_key <- get_pjwt_key()
  testthat::skip_if(
    is.null(private_key),
    "private_key_jwt test key not available"
  )

  jwks_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_JARM_JWKS_PORT", "8121"))
  if (keycloak_browser_port_in_use(jwks_port)) {
    testthat::skip(paste0(
      "Port ",
      jwks_port,
      " is already in use; skipping encrypted JARM JWKS server"
    ))
  }
  public_base_url <- .jarm_jwks_public_base_url(jwks_port)
  jwks_server <- .start_jarm_jwks_server(
    key = private_key,
    port = jwks_port,
    public_base_url = public_base_url
  )
  on.exit(try(jwks_server$process$kill(), silent = TRUE), add = TRUE)

  admin_token <- keycloak_admin_token()
  fixture <- keycloak_create_client(
    token = admin_token,
    body = keycloak_oidc_client_body(
      client_id = keycloak_temp_client_id("shiny-jarm-public-jwe"),
      public_client = TRUE,
      attributes = list(
        "pkce.code.challenge.method" = "S256",
        "use.jwks.url" = "true",
        "jwks.url" = jwks_server$jwks_url,
        "authorization.signed.response.alg" = "RS256",
        "authorization.encrypted.response.alg" = "RSA-OAEP",
        "authorization.encrypted.response.enc" = "A256CBC-HS512"
      )
    )
  )
  on.exit(
    keycloak_delete_client(admin_token, id = fixture$id),
    add = TRUE
  )

  prov <- make_provider()
  testthat::expect_true(
    "query.jwt" %in% (prov@response_modes_supported %||% character())
  )
  testthat::expect_true(
    "RS256" %in%
      (prov@authorization_signing_alg_values_supported %||% character())
  )
  testthat::expect_true(
    "RSA-OAEP" %in%
      (prov@authorization_encryption_alg_values_supported %||% character())
  )
  testthat::expect_true(
    "A256CBC-HS512" %in%
      (prov@authorization_encryption_enc_values_supported %||% character())
  )

  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = fixture$client_id,
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    response_mode = "query.jwt",
    authorization_signed_response_alg = "RS256",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = private_key
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_identical(
        parse_query_param(auth_url, "response_mode", decode = TRUE),
        "query.jwt"
      )

      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      response_jwe <- extract_jarm_response(login)
      outer <- shinyOAuth:::jwe_compact_parts(response_jwe)

      testthat::expect_true(keycloak_nonempty_string(response_jwe))
      testthat::expect_false(grepl("[?&]code=", login$callback_url))
      testthat::expect_false(grepl("[?&]state=", login$callback_url))
      testthat::expect_length(
        strsplit(response_jwe, ".", fixed = TRUE)[[1]],
        5L
      )
      testthat::expect_identical(
        outer[["protected_header"]][["alg"]],
        "RSA-OAEP"
      )
      testthat::expect_identical(
        outer[["protected_header"]][["enc"]],
        "A256CBC-HS512"
      )

      values$.process_query(callback_query(login))
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

testthat::test_that("Keycloak query.jwt replay is rejected after state consumption", {
  skip_common()
  local_test_options()

  setup <- create_signed_jarm_fixture("shiny-jarm-replay")
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  prov <- make_provider()
  client <- make_signed_jarm_public_client(prov, setup$fixture$client_id)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state_info <- get_state_info(client, auth_url)
      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      query <- callback_query(login)

      testthat::expect_true(keycloak_nonempty_string(extract_jarm_response(
        login
      )))

      values$.process_query(query)
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
      expect_state_store_entry_consumed(client, state_info)

      values$logout()
      session$flushReact()
      values$browser_token <- "__SKIPPED__"

      values$.process_query(query)
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(
        values$error_description %||% "",
        "state",
        ignore.case = TRUE
      )
    }
  )
})

testthat::test_that("Keycloak query.jwt PKCE unhappy path: missing code_verifier", {
  skip_common()
  local_test_options()

  setup <- create_signed_jarm_fixture("shiny-jarm-pkce-missing")
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  prov <- make_provider()
  client <- make_signed_jarm_public_client(prov, setup$fixture$client_id)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state <- get_state_store_entry(client, auth_url)
      orig <- state$entry

      client@state_store$set(
        key = state$info$key,
        value = list(
          browser_token = orig$browser_token,
          pkce_code_verifier = NULL,
          nonce = orig$nonce
        )
      )

      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      query <- callback_query(login)

      testthat::expect_true(keycloak_nonempty_string(extract_jarm_response(
        login
      )))

      values$.process_query(query)
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(
        values$error_description %||% "",
        "code verifier|PKCE",
        ignore.case = TRUE
      )
      testthat::expect_null(values$token)
      expect_state_store_entry_consumed(client, state)

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

testthat::test_that("Keycloak query.jwt PKCE unhappy path: wrong code_verifier", {
  skip_common()
  local_test_options()

  setup <- create_signed_jarm_fixture("shiny-jarm-pkce-wrong")
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  prov <- make_provider()
  client <- make_signed_jarm_public_client(prov, setup$fixture$client_id)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state <- get_state_store_entry(client, auth_url)
      orig <- state$entry
      new_verifier <- orig$pkce_code_verifier

      for (i in 1:5) {
        candidate <- paste0(
          sample(c(letters, LETTERS, 0:9, '-', '_', '.', '~'), 64, TRUE),
          collapse = ""
        )
        if (!identical(candidate, new_verifier)) {
          new_verifier <- candidate
          break
        }
      }

      client@state_store$set(
        key = state$info$key,
        value = list(
          browser_token = orig$browser_token,
          pkce_code_verifier = new_verifier,
          nonce = orig$nonce
        )
      )

      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      query <- callback_query(login)

      testthat::expect_true(keycloak_nonempty_string(extract_jarm_response(
        login
      )))

      values$.process_query(query)
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "token_exchange_error")
      testthat::expect_match(
        values$error_description %||% "",
        "invalid_grant|PKCE|code.verifier|code verifier",
        ignore.case = TRUE
      )
      testthat::expect_null(values$token)
      expect_state_store_entry_consumed(client, state)

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

testthat::test_that("Keycloak PAR happy path preserves query.jwt callbacks", {
  skip_common()
  local_test_options()

  setup <- create_signed_jarm_fixture("shiny-jarm-par")
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  prov <- make_provider(use_par = TRUE)
  client <- make_signed_jarm_public_client(prov, setup$fixture$client_id)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()

      testthat::expect_match(auth_url, "[?&]request_uri=")

      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      response_jwt <- extract_jarm_response(login)

      testthat::expect_true(keycloak_nonempty_string(response_jwt))
      testthat::expect_false(grepl("[?&]code=", login$callback_url))
      testthat::expect_false(grepl("[?&]state=", login$callback_url))

      values$.process_query(callback_query(login))
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

testthat::test_that("Keycloak currently rejects signed request-object + query.jwt before login", {
  skip_common()
  local_test_options()

  private_key <- get_pjwt_key()
  public_key_pem <- get_pjwt_public_key_pem()
  testthat::skip_if(
    is.null(private_key),
    "private_key_jwt test key not available"
  )
  testthat::skip_if(
    !keycloak_nonempty_string(public_key_pem),
    "request-object signing public key not available"
  )

  setup <- create_signed_jarm_fixture(
    prefix = "shiny-jarm-jar",
    attributes = list(
      "use.jwks.url" = "false",
      "jwt.credential.public.key" = public_key_pem,
      "request.object.signature.alg" = "RS256",
      "request.uris" = "http://host.docker.internal:8100/session/*"
    ),
    public_client = FALSE,
    client_authenticator_type = "client-jwt",
    service_accounts_enabled = TRUE
  )
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_signed_jarm_public_client(
    provider = prov,
    client_id = setup$fixture$client_id,
    client_private_key = private_key,
    client_private_key_kid = NA_character_,
    authorization_request_mode = "request",
    authorization_request_signing_alg = "RS256"
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state_info <- get_state_info(client, auth_url)
      request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
      payload <- decode_compact_jwt_payload(request_jwt)

      testthat::expect_true(keycloak_nonempty_string(request_jwt))
      testthat::expect_false(grepl("[?&]response_mode=", auth_url))
      testthat::expect_identical(payload[["response_mode"]], "query.jwt")
      testthat::expect_identical(payload[["client_id"]], client@client_id)
      testthat::expect_identical(payload[["redirect_uri"]], client@redirect_uri)

      resp <- httr2::request(auth_url) |>
        req_apply_keycloak_ca() |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "text/html") |>
        httr2::req_options(followlocation = FALSE) |>
        httr2::req_perform()
      status <- httr2::resp_status(resp)
      combo <- paste(
        status,
        httr2::resp_header(resp, "location") %||% "",
        httr2::resp_body_string(resp)
      )

      testthat::expect_true(httr2::resp_is_error(resp), info = combo)
      testthat::expect_true(status %in% c(400L, 401L), info = combo)
      testthat::expect_match(
        combo,
        "invalid|request|jwt|response",
        ignore.case = TRUE
      )
      expect_state_store_entry_present(client, state_info)
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_null(values$token)
    }
  )
})
