## Headless protocol integration: PAR/JAR outer-parameter confusion
##
## These tests tamper only the browser-visible outer authorization URL. They do
## not exercise the real browser cookie boundary; browser-boundary behavior is
## covered by the *_browser*.R and *_e2e.R tests.
##
## PAR proves full outer-parameter precedence here. With the OIDC-required
## outer response_type and scope preserved on Request Object URLs, the direct
## JAR case proves this Keycloak fixture still honors the signed Request Object
## for redirect_uri, state, nonce, and code_challenge when conflicting outer
## parameters are appended in the browser-visible redirect.
## `request_uri` client binding is asserted separately in
## `test_integration_keycloak_par_unhappy.R` because that behavior is distinct
## from duplicate-parameter precedence.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

attacker_outer_redirect_uri <- "http://localhost:3000/attacker"
attacker_outer_scope <- "openid email admin"
attacker_outer_state <- "attacker-state"
attacker_outer_nonce <- "attacker-nonce"
attacker_outer_resource <- "https://attacker.example/resource"
attacker_outer_code_challenge <- paste(rep("B", 43L), collapse = "")
attacker_outer_client_id <- "shiny-public"

replace_or_append_query_param <- function(url, name, value) {
  stopifnot(is.character(url), length(url) == 1L, nzchar(url))
  stopifnot(is.character(name), length(name) == 1L, nzchar(name))
  stopifnot(is.character(value), length(value) == 1L, nzchar(value))

  encoded <- utils::URLencode(value, reserved = TRUE)
  pattern <- paste0("([?&])", name, "=[^&]*")

  if (grepl(pattern, url, perl = TRUE)) {
    return(
      sub(
        pattern,
        paste0("\\1", name, "=", encoded),
        url,
        perl = TRUE
      )
    )
  }

  sep <- if (grepl("?", url, fixed = TRUE)) "&" else "?"
  paste0(url, sep, name, "=", encoded)
}

tamper_outer_authorization_url <- function(auth_url, include_client_id = TRUE) {
  tampered <- auth_url
  conflicts <- list(
    redirect_uri = attacker_outer_redirect_uri,
    scope = attacker_outer_scope,
    state = attacker_outer_state,
    nonce = attacker_outer_nonce,
    resource = attacker_outer_resource,
    code_challenge = attacker_outer_code_challenge,
    code_challenge_method = "S256"
  )

  if (isTRUE(include_client_id)) {
    tampered <- replace_or_append_query_param(
      tampered,
      "client_id",
      "shiny-public"
    )
  }

  for (param_name in names(conflicts)) {
    tampered <- replace_or_append_query_param(
      tampered,
      param_name,
      conflicts[[param_name]]
    )
  }

  tampered
}

tamper_outer_client_id <- function(
  auth_url,
  attacker_client_id = attacker_outer_client_id
) {
  replace_or_append_query_param(auth_url, "client_id", attacker_client_id)
}

inspect_auth_request_once <- function(auth_url) {
  resp <- httr2::request(auth_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()

  body <- try(httr2::resp_body_string(resp), silent = TRUE)
  if (inherits(body, "try-error") || !is.character(body)) {
    body <- ""
  }

  list(
    status = httr2::resp_status(resp),
    location = httr2::resp_header(resp, "location") %||% "",
    body = body
  )
}

attempt_attacker_client_id_auth <- function(auth_url, redirect_uri) {
  attacked <- try(
    perform_login_form(auth_url, redirect_uri = redirect_uri),
    silent = TRUE
  )

  if (!inherits(attacked, "try-error")) {
    attacker_code <- attacked$code %||% NA_character_
    testthat::expect_false(
      is.character(attacker_code) &&
        length(attacker_code) == 1L &&
        !is.na(attacker_code) &&
        nzchar(attacker_code),
      info = paste0(
        "Expected outer client_id confusion to be rejected. Callback: ",
        attacked$callback_url %||% "<no callback>"
      )
    )

    return(list(kind = "callback", value = attacked))
  }

  inspected <- inspect_auth_request_once(auth_url)
  combo <- paste(
    inspected$status,
    inspected$location %||% "",
    inspected$body %||% ""
  )

  testthat::expect_true(
    inspected$status %in% c(400L, 401L, 403L),
    info = combo
  )

  list(kind = "http", value = inspected)
}

expect_outer_client_id_confusion_preserves_legitimate_state <- function(
  client,
  expected_username = "alice",
  retry_legitimate_flow = TRUE
) {
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state_info <- get_state_info(client, auth_url)
      tampered_url <- tamper_outer_client_id(auth_url)
      attacked <- attempt_attacker_client_id_auth(
        tampered_url,
        redirect_uri = client@redirect_uri
      )

      testthat::expect_false(identical(tampered_url, auth_url))
      testthat::expect_match(
        tampered_url,
        paste0(
          "[?&]client_id=",
          utils::URLencode(attacker_outer_client_id, reserved = TRUE)
        )
      )
      expect_state_store_entry_present(client, state_info)

      if (identical(attacked$kind, "callback")) {
        values$.process_query(callback_query(attacked$value))
        session$flushReact()

        testthat::expect_false(isTRUE(values$authenticated))
        testthat::expect_true(is.null(values$token))
        testthat::expect_false(is.null(values$error))
        expect_state_store_entry_present(client, state_info)

        values$error <- NULL
        values$error_description <- NULL
        values$error_uri <- NULL
      }

      if (isTRUE(retry_legitimate_flow)) {
        legitimate_login <- perform_login_form(
          auth_url,
          redirect_uri = client@redirect_uri
        )
        values$.process_query(callback_query(legitimate_login))
        session$flushReact()

        expect_keycloak_module_login_invariants(
          authenticated = values$authenticated,
          error = values$error,
          error_description = values$error_description,
          error_uri = values$error_uri,
          token = values$token,
          client = client,
          expected_username = expected_username
        )
        expect_state_store_entry_consumed(client, state_info)
      }
    }
  )
}

pkce_code_challenge_from_verifier <- function(verifier, method = "S256") {
  stopifnot(is.character(verifier), length(verifier) == 1L, nzchar(verifier))

  method <- toupper(method %||% "S256")
  if (identical(method, "PLAIN")) {
    return(verifier)
  }

  digest <- openssl::sha256(charToRaw(verifier))
  shinyOAuth:::base64url_encode(digest)
}

expect_jar_outer_params_do_not_override <- function(client) {
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
      payload <- decode_compact_jwt_payload(request_jwt)
      state <- get_state_store_entry(client, auth_url)
      original_challenge <- pkce_code_challenge_from_verifier(
        state$entry$pkce_code_verifier,
        client@provider@pkce_method
      )
      tampered_url <- tamper_outer_authorization_url(
        auth_url,
        include_client_id = FALSE
      )
      login <- perform_login_form(
        tampered_url,
        redirect_uri = client@redirect_uri
      )

      testthat::expect_true(
        startsWith(login$callback_url %||% "", client@redirect_uri),
        info = login$callback_url %||% "<no callback>"
      )
      testthat::expect_false(
        startsWith(login$callback_url %||% "", attacker_outer_redirect_uri),
        info = login$callback_url %||% "<no callback>"
      )
      testthat::expect_identical(login$state_payload, payload$state)
      testthat::expect_identical(payload$redirect_uri, client@redirect_uri)
      testthat::expect_identical(payload$client_id, client@client_id)
      testthat::expect_false(identical(payload$state, attacker_outer_state))
      testthat::expect_false(identical(
        login$state_payload,
        attacker_outer_state
      ))
      testthat::expect_true(is.na(parse_query_param(
        login$callback_url,
        "error",
        decode = TRUE
      )))
      testthat::expect_true(
        is.character(state$entry$nonce) && nzchar(state$entry$nonce)
      )
      testthat::expect_identical(payload$nonce, state$entry$nonce)
      testthat::expect_identical(payload$code_challenge, original_challenge)
      testthat::expect_true(
        is.character(payload$nonce) && nzchar(payload$nonce)
      )
      testthat::expect_true(
        is.character(payload$code_challenge) && nzchar(payload$code_challenge)
      )
      testthat::expect_false(identical(payload$nonce, attacker_outer_nonce))
      testthat::expect_false(
        identical(payload$code_challenge, attacker_outer_code_challenge)
      )
    }
  )
}

make_par_confusion_client <- function(
  prov,
  resource = "https://api.shinyoauth.test"
) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-resource-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid", "profile", "email"),
    introspect = TRUE,
    resource = resource
  )
}

expect_par_outer_params_do_not_override <- function(client, expected_resource) {
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state <- get_state_store_entry(client, auth_url)
      original_challenge <- pkce_code_challenge_from_verifier(
        state$entry$pkce_code_verifier,
        client@provider@pkce_method
      )
      tampered_url <- tamper_outer_authorization_url(
        auth_url,
        include_client_id = FALSE
      )
      login <- perform_login_form(
        tampered_url,
        redirect_uri = client@redirect_uri
      )

      testthat::expect_true(
        startsWith(login$callback_url %||% "", client@redirect_uri)
      )
      testthat::expect_false(identical(
        login$state_payload,
        attacker_outer_state
      ))
      testthat::expect_true(
        is.character(state$entry$nonce) && nzchar(state$entry$nonce)
      )
      testthat::expect_true(
        is.character(original_challenge) && nzchar(original_challenge)
      )
      testthat::expect_false(identical(state$entry$nonce, attacker_outer_nonce))
      testthat::expect_false(
        identical(original_challenge, attacker_outer_code_challenge)
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
      testthat::expect_false(
        "admin" %in% normalize_claim_values(values$token@granted_scopes)
      )

      intros <- shinyOAuth::introspect_token(
        client,
        values$token,
        which = "access"
      )
      token_aud <- normalize_claim_values(
        decode_compact_jwt_payload(values$token@access_token)$aud %||% NULL
      )
      intros_aud <- normalize_claim_values(intros$raw$aud %||% NULL)

      testthat::expect_true(isTRUE(intros$supported))
      testthat::expect_true(isTRUE(intros$active))
      testthat::expect_true(expected_resource %in% token_aud)
      testthat::expect_true(expected_resource %in% intros_aud)
      testthat::expect_false(attacker_outer_resource %in% token_aud)
      testthat::expect_false(attacker_outer_resource %in% intros_aud)
    }
  )
}

testthat::test_that("JAR signed request object ignores conflicting outer redirect_uri, state, nonce, and code_challenge", {
  skip_common()
  local_test_options()

  prov <- make_provider(
    request_object_signing_alg_values_supported = c("HS256")
  )
  client <- make_hmac_jar_client(prov)

  expect_jar_outer_params_do_not_override(client)
})

testthat::test_that("tampered JAR outer parameters still authenticate using the legitimate callback state", {
  skip_common()
  local_test_options()

  prov <- make_provider(
    request_object_signing_alg_values_supported = c("HS256")
  )
  client <- make_hmac_jar_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state_info <- get_state_info(client, auth_url)
      tampered_url <- tamper_outer_authorization_url(
        auth_url,
        include_client_id = FALSE
      )
      tampered_login <- perform_login_form(
        tampered_url,
        redirect_uri = client@redirect_uri
      )

      testthat::expect_true(
        startsWith(tampered_login$callback_url %||% "", client@redirect_uri),
        info = tampered_login$callback_url %||% "<no callback>"
      )
      testthat::expect_true(is.na(parse_query_param(
        tampered_login$callback_url,
        "error",
        decode = TRUE
      )))

      values$.process_query(callback_query(tampered_login))
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
    }
  )
})

testthat::test_that("PAR request_uri ignores conflicting outer redirect_uri, scope, state, nonce, resource, and code_challenge", {
  skip_common()
  local_test_options()

  resource <- "https://api.shinyoauth.test"
  prov <- make_provider(token_auth_style = "header", use_par = TRUE)
  client <- make_par_confusion_client(prov, resource = resource)

  expect_par_outer_params_do_not_override(client, expected_resource = resource)
})

testthat::test_that("JAR outer client_id confusion is rejected without consuming the legitimate state", {
  skip_common()
  local_test_options()

  prov <- make_provider(
    request_object_signing_alg_values_supported = c("HS256")
  )
  client <- make_hmac_jar_client(prov)

  expect_outer_client_id_confusion_preserves_legitimate_state(client)
})

testthat::test_that("JAR through PAR rejects outer client_id confusion without authenticating the attacker", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt", use_par = TRUE)
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  expect_outer_client_id_confusion_preserves_legitimate_state(
    client,
    retry_legitimate_flow = FALSE
  )
})

testthat::test_that("Keycloak PAR-required client rejects direct authorization requests", {
  skip_common()
  local_test_options()

  prov <- make_provider(use_par = FALSE)
  client <- make_public_client(prov, client_id = "shiny-par-required")

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      testthat::expect_false(grepl("[?&]request_uri=", auth_url))

      result <- try(
        perform_login_form(auth_url, redirect_uri = client@redirect_uri),
        silent = TRUE
      )

      if (inherits(result, "try-error")) {
        testthat::expect_s3_class(attr(result, "condition"), "condition")
      } else {
        code <- result$code %||% NA_character_
        testthat::expect_false(
          is.character(code) &&
            length(code) == 1L &&
            !is.na(code) &&
            nzchar(code),
          info = paste0(
            "PAR-required client unexpectedly issued a code for direct auth: ",
            result$callback_url %||% "<no callback>"
          )
        )
        testthat::expect_match(
          result$callback_url %||% "",
          "error|invalid|request_uri|pushed|PAR",
          ignore.case = TRUE
        )
      }
    }
  )
})
