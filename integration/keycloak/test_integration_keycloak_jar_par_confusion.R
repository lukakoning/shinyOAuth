## Headless protocol integration: PAR/JAR outer-parameter confusion
##
## These tests tamper only the browser-visible outer authorization URL. They do
## not exercise the real browser cookie boundary; browser-boundary behavior is
## covered by the *_browser*.R and *_e2e.R tests.
##
## PAR proves outer-parameter precedence here. The JAR case records the current
## Keycloak fixture behavior when conflicting outer parameters are appended to a
## signed Request Object so the suite does not overclaim JAR-alone protection.
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

pkce_code_challenge_from_verifier <- function(verifier, method = "S256") {
  stopifnot(is.character(verifier), length(verifier) == 1L, nzchar(verifier))

  method <- toupper(method %||% "S256")
  if (identical(method, "PLAIN")) {
    return(verifier)
  }

  digest <- openssl::sha256(charToRaw(verifier))
  shinyOAuth:::base64url_encode(digest)
}

expect_jar_outer_params_are_reflected <- function(client) {
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
      payload <- decode_compact_jwt_payload(request_jwt)
      tampered_url <- tamper_outer_authorization_url(
        auth_url,
        include_client_id = FALSE
      )
      login <- perform_login_form(
        tampered_url,
        redirect_uri = "http://localhost:3000"
      )

      testthat::expect_true(
        startsWith(login$callback_url %||% "", attacker_outer_redirect_uri),
        info = login$callback_url %||% "<no callback>"
      )
      testthat::expect_false(
        startsWith(login$callback_url %||% "", client@redirect_uri),
        info = login$callback_url %||% "<no callback>"
      )
      testthat::expect_identical(login$state_payload, attacker_outer_state)
      testthat::expect_identical(payload$redirect_uri, client@redirect_uri)
      testthat::expect_identical(payload$client_id, client@client_id)
      testthat::expect_false(identical(payload$state, attacker_outer_state))
      testthat::expect_match(
        parse_query_param(login$callback_url, "error", decode = TRUE),
        "invalid_request",
        ignore.case = TRUE
      )
      testthat::expect_match(
        parse_query_param(
          login$callback_url,
          "error_description",
          decode = TRUE
        ),
        "Missing(\\+| )parameter:(\\+| )response_type",
        perl = TRUE
      )
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

testthat::test_that("JAR signed request object in this Keycloak fixture still reflects conflicting outer parameters", {
  skip_common()
  local_test_options()

  prov <- make_provider(
    request_object_signing_alg_values_supported = c("HS256")
  )
  client <- make_hmac_jar_client(prov)

  expect_jar_outer_params_are_reflected(client)
})

testthat::test_that("PAR request_uri ignores conflicting outer redirect_uri, scope, state, nonce, resource, and code_challenge", {
  skip_common()
  local_test_options()

  resource <- "https://api.shinyoauth.test"
  prov <- make_provider(token_auth_style = "header", use_par = TRUE)
  client <- make_par_confusion_client(prov, resource = resource)

  expect_par_outer_params_do_not_override(client, expected_resource = resource)
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
