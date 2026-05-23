make_jarm_test_client <- function(
  response_mode = "query.jwt",
  authorization_signed_response_alg = "RS256",
  authorization_encrypted_response_alg = NULL,
  authorization_encrypted_response_enc = NULL,
  authorization_response_decryption_private_key = NULL,
  client_secret = "",
  issuer = "https://issuer.example.com"
) {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@issuer <- issuer
  prov@response_modes_supported <- unique(c(
    response_mode,
    if (identical(response_mode, "query.jwt")) "jwt" else character(0)
  ))
  prov@authorization_signing_alg_values_supported <-
    authorization_signed_response_alg %||% character(0)
  prov@authorization_encryption_alg_values_supported <-
    authorization_encrypted_response_alg %||% character(0)
  prov@authorization_encryption_enc_values_supported <-
    authorization_encrypted_response_enc %||% character(0)

  oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = client_secret,
    redirect_uri = "http://localhost:8100",
    scopes = "openid",
    response_mode = response_mode,
    authorization_signed_response_alg = authorization_signed_response_alg,
    authorization_encrypted_response_alg = authorization_encrypted_response_alg,
    authorization_encrypted_response_enc = authorization_encrypted_response_enc,
    authorization_response_decryption_private_key = authorization_response_decryption_private_key,
    state_store = cachem::cache_mem(max_age = 600),
    state_payload_max_age = 300,
    state_entropy = 64,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

make_jarm_public_jwk <- function(key, kid = "sig-1", use = "sig") {
  jwk <- jsonlite::fromJSON(jose::write_jwk(key$pubkey), simplifyVector = TRUE)
  jwk$kid <- kid
  jwk$use <- use
  jwk
}

make_signed_jarm <- function(
  payload_list,
  key,
  kid = NULL,
  alg = "RS256"
) {
  header <- list(alg = alg)
  if (!is.null(kid)) {
    header$kid <- kid
  }

  jose::jwt_encode_sig(
    do.call(jose::jwt_claim, payload_list),
    key = key,
    header = header
  )
}

make_jarm_form_post_req <- function(
  path = "/",
  query = "",
  body = "",
  content_type = "application/x-www-form-urlencoded"
) {
  req <- new.env(parent = emptyenv())
  req$REQUEST_METHOD <- "POST"
  req$PATH_INFO <- path
  req$QUERY_STRING <- query
  req$CONTENT_TYPE <- content_type
  req$CONTENT_LENGTH <- as.character(nchar(body, type = "bytes"))
  req$rook.input <- list(read = function(n) charToRaw(body))
  req
}

jarm_form_post_query <- function(handle, id = "auth") {
  paste0(
    "?",
    httr2::url_query_build(stats::setNames(
      list(handle, id),
      c("shinyOAuth_form_post", "shinyOAuth_form_post_id")
    ))
  )
}

test_that("OIDC discovery records JARM metadata", {
  discover_provider <- function(metadata) {
    testthat::local_mocked_bindings(
      .discover_fetch_response = function(req, issuer) {
        structure(list(), class = "mock_discovery_response")
      },
      .discover_parse_json = function(resp) metadata,
      .package = "shinyOAuth"
    )

    oauth_provider_oidc_discover(
      issuer = metadata$issuer,
      id_token_validation = FALSE
    )
  }

  metadata <- list(
    issuer = "https://issuer.example.com",
    authorization_endpoint = "https://issuer.example.com/auth",
    token_endpoint = "https://issuer.example.com/token",
    response_modes_supported = c("query.jwt", "form_post.jwt"),
    authorization_signing_alg_values_supported = c("RS256", "ES256"),
    authorization_encryption_alg_values_supported = "RSA-OAEP",
    authorization_encryption_enc_values_supported = c(
      "A128CBC-HS256",
      "A256CBC-HS512"
    )
  )

  prov <- discover_provider(metadata)

  expect_identical(
    prov@authorization_signing_alg_values_supported,
    c("RS256", "ES256")
  )
  expect_identical(
    prov@authorization_encryption_alg_values_supported,
    "RSA-OAEP"
  )
  expect_identical(
    prov@authorization_encryption_enc_values_supported,
    c("A128CBC-HS256", "A256CBC-HS512")
  )
})

test_that("oauth_client defaults encrypted JARM enc when alg is set", {
  rsa_key <- openssl::rsa_keygen()

  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_response_decryption_private_key = rsa_key
  )

  expect_identical(client@authorization_encrypted_response_enc, "A128CBC-HS256")
})

test_that("validate_jarm_response verifies signed JARM payloads", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  normalized <- shinyOAuth:::validate_jarm_response(client, response)

  expect_identical(normalized$type, "code")
  expect_identical(normalized$code, "ok")
  expect_identical(normalized$state, "state-1")
  expect_identical(normalized$iss, client@provider@issuer)
})

test_that("validate_jarm_response rejects alg none", {
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- build_dummy_jwt(list(
    iss = client@provider@issuer,
    aud = "abc",
    exp = now + 300,
    code = "ok",
    state = "state-1"
  ))

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "alg=none"
  )
})

test_that("validate_jarm_response rejects clients that did not request JARM", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  client@provider@issuer <- "https://issuer.example.com"
  now <- floor(as.numeric(Sys.time()))
  response <- build_dummy_jwt(list(
    iss = client@provider@issuer,
    aud = client@client_id,
    exp = now + 300,
    code = "ok",
    state = "state-1"
  ))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        "validate_jarm_response should reject non-JARM clients before JWKS fetch"
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "not configured to accept JARM"
  )
})

test_that("validate_jarm_response rejects issuer mismatch before JWKS fetch", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = "https://attacker.example.com",
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        "validate_jarm_response should reject issuer mismatch before JWKS fetch"
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "issuer does not match"
  )
})

test_that("validate_jarm_response rejects aud mismatches", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "wrong-client",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "aud claim does not include client_id"
  )
})

test_that("validate_jarm_response rejects payloads with both code and error", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      error = "access_denied",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "must not contain both code and error"
  )
})

test_that("validate_jarm_response tolerates duplicate identical iss claims", {
  secret <- "hs256-jarm-duplicate-iss-secret-32b!"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))

  header_json <- jsonlite::toJSON(
    list(alg = "HS256", typ = "JWT"),
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )
  payload_json <- paste0(
    '{',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"aud":"abc",',
    '"exp":',
    now + 300,
    ',',
    '"code":"ok",',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"state":"state-1"',
    '}'
  )
  signing_input <- paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(payload_json))
  )
  signature_raw <- openssl::sha256(
    charToRaw(signing_input),
    key = charToRaw(secret)
  )
  response <- paste0(
    signing_input,
    ".",
    shinyOAuth:::base64url_encode(signature_raw)
  )

  normalized <- shinyOAuth:::validate_jarm_response(client, response)

  expect_identical(normalized$type, "code")
  expect_identical(normalized$code, "ok")
  expect_identical(normalized$state, "state-1")
  expect_identical(normalized$iss, client@provider@issuer)
})

test_that("oauth_module_server rejects mixed query.jwt and direct callback params", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(...) {
      testthat::fail(
        "oauth_module_server should reject mixed JARM/direct params before token exchange"
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          expect_length(client@state_store$keys(), 1L)

          values$.process_query(paste0(
            "?response=",
            utils::URLencode(response, reserved = TRUE),
            "&code=attack"
          ))
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, "invalid_callback_query")
          expect_match(values$error_description %||% "", "must not be combined")
          expect_length(client@state_store$keys(), 1L)
        }
      )
    }
  )
})

test_that("oauth_module_server handles query.jwt error callbacks and blocks replay", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(...) {
      testthat::fail(
        "oauth_module_server should not exchange tokens for JARM error callbacks"
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              error = "access_denied",
              error_description = "Denied",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )
          query <- paste0(
            "?response=",
            utils::URLencode(response, reserved = TRUE)
          )

          values$.process_query(query)
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, "access_denied")
          expect_identical(values$error_description, "Denied")
          expect_null(values$error_uri)
          expect_length(client@state_store$keys(), 0L)

          values$error <- NULL
          values$error_description <- NULL
          values$error_uri <- NULL

          values$.process_query(query)
          session$flushReact()

          expect_identical(values$error, "invalid_state")
          expect_match(
            values$error_description %||% "",
            "state",
            ignore.case = TRUE
          )
        }
      )
    }
  )
})

test_that("validate_jarm_response decrypts encrypted JARM payloads", {
  sig_key <- openssl::rsa_keygen()
  enc_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = enc_key
  )
  client@provider@authorization_encryption_alg_values_supported <- "RSA-OAEP"
  client@provider@authorization_encryption_enc_values_supported <- "A256CBC-HS512"
  now <- floor(as.numeric(Sys.time()))
  inner_jwt <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  response <- shinyOAuth:::jwe_compact_encrypt(
    plaintext = inner_jwt,
    public_key = enc_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    kid = "enc-1",
    cty = "JWT"
  )
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  normalized <- shinyOAuth:::validate_jarm_response(client, response)

  expect_identical(normalized$type, "code")
  expect_identical(normalized$code, "ok")
  expect_identical(normalized$state, "state-1")
})

test_that("oauth_module_server handles query.jwt callbacks", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          values$.process_query(paste0(
            "?response=",
            utils::URLencode(response, reserved = TRUE)
          ))
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
        }
      )
    }
  )
})

test_that("oauth_module_server rejects query JARM callbacks for form_post.jwt clients before JWT processing", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should reject query transport mismatches",
          "before JARM signature validation"
        )
      )
    },
    swap_code_for_token_set = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should reject query transport mismatches",
          "before token exchange"
        )
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = client@client_id,
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          expect_length(client@state_store$keys(), 1L)

          values$.process_query(paste0(
            "?response=",
            utils::URLencode(response, reserved = TRUE)
          ))
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, "invalid_state")
          expect_match(
            values$error_description %||% "",
            "transport mismatch"
          )
          expect_length(client@state_store$keys(), 1L)
        }
      )
    }
  )
})

test_that("oauth_form_post_ui rejects form_post.jwt bodies that mix response with direct callback params", {
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  keys_before <- sort(client@state_store$keys())
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  resp <- ui(make_jarm_form_post_req(
    body = paste0(
      "response=header.payload.signature",
      "&code=attack"
    )
  ))

  expect_identical(resp$status, 400L)
  expect_identical(
    resp$content,
    paste(
      "OAuth form_post JARM callback must not contain both response and",
      "direct OAuth callback parameters."
    )
  )
  expect_false("Location" %in% names(resp$headers))
  expect_identical(sort(client@state_store$keys()), keys_before)

  reject_events <- Filter(
    function(e) {
      identical(e$type, "audit_callback_validation_failed") &&
        identical(e$phase, "form_post_request_validation")
    },
    events
  )
  expect_length(reject_events, 1L)
  expect_match(
    reject_events[[1L]]$error_class %||% "",
    "shinyOAuth_form_post_http_error",
    fixed = TRUE
  )
})

test_that("oauth_module_server handles bridged form_post.jwt callbacks", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(response, reserved = TRUE)
            )
          ))
          handle <- parse_query_param(
            post_resp$headers$Location,
            "shinyOAuth_form_post",
            decode = TRUE
          )

          values$.process_query(jarm_form_post_query(handle, "auth"))
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
        }
      )
    }
  )
})

test_that("oauth_module_server rejects bridged form_post.jwt aud mismatches without consuming pending state", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  exchanged_codes <- character(0)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(client, code, code_verifier) {
      exchanged_codes <<- c(exchanged_codes, code)
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))

          bad_response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "wrong-client",
              exp = now + 300,
              code = "attack",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          expect_length(client@state_store$keys(), 1L)

          bad_post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(bad_response, reserved = TRUE)
            )
          ))
          bad_handle <- parse_query_param(
            bad_post_resp$headers$Location,
            "shinyOAuth_form_post",
            decode = TRUE
          )

          values$.process_query(jarm_form_post_query(bad_handle, "auth"))
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, "invalid_state")
          expect_match(
            values$error_description %||% "",
            "aud claim does not include client_id"
          )
          expect_length(client@state_store$keys(), 1L)
          expect_identical(exchanged_codes, character(0))

          failure_events <- Filter(
            function(e) {
              identical(e$type, "audit_callback_validation_failed") &&
                identical(e$phase, "form_post_callback_validation")
            },
            events
          )
          expect_length(failure_events, 1L)
          expect_match(
            failure_events[[1L]]$error_class %||% "",
            "shinyOAuth_state_error",
            fixed = TRUE
          )
          expect_false(any(vapply(
            events,
            function(e) identical(e$type, "audit_callback_validation_success"),
            logical(1)
          )))

          values$error <- NULL
          values$error_description <- NULL
          values$error_uri <- NULL

          good_response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )
          good_post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(good_response, reserved = TRUE)
            )
          ))
          good_handle <- parse_query_param(
            good_post_resp$headers$Location,
            "shinyOAuth_form_post",
            decode = TRUE
          )

          values$.process_query(jarm_form_post_query(good_handle, "auth"))
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
          expect_identical(exchanged_codes, "ok")
          expect_length(client@state_store$keys(), 0L)
          expect_true(any(vapply(
            events,
            function(e) identical(e$type, "audit_callback_validation_success"),
            logical(1)
          )))
        }
      )
    }
  )
})
