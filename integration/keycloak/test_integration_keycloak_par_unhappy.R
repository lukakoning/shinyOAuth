## Integration tests: Keycloak PAR unhappy paths

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

build_par_auth_url <- function(client) {
  result <- list(
    auth_url = NA_character_,
    error = NULL,
    error_description = NULL
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      result[["auth_url"]] <<- values$build_auth_url()
      result[["error"]] <<- values$error
      result[["error_description"]] <<- values$error_description
    }
  )

  result
}

keycloak_realm_attribute <- function(token, name, default = NA_character_) {
  stopifnot(keycloak_nonempty_string(name))

  resp <- keycloak_admin_request(
    "GET",
    "/admin/realms/shinyoauth",
    token = token
  )
  if (httr2::resp_is_error(resp)) {
    testthat::skip("Keycloak realm endpoint failed")
  }

  body <- httr2::resp_body_json(resp, simplifyVector = FALSE)
  body[["attributes"]][[name]] %||% default
}

keycloak_update_realm_attribute <- function(token, name, value) {
  stopifnot(keycloak_nonempty_string(name))

  resp <- keycloak_admin_request(
    "PUT",
    "/admin/realms/shinyoauth",
    token = token,
    body = list(attributes = stats::setNames(list(value), name))
  )
  if (httr2::resp_status(resp) >= 400L) {
    testthat::skip("Keycloak realm update failed")
  }

  invisible(resp)
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

capture_par_auth_request_rejection <- function(auth_url, redirect_uri) {
  result <- try(
    perform_login_form(auth_url, redirect_uri = redirect_uri),
    silent = TRUE
  )

  if (!inherits(result, "try-error")) {
    return(list(kind = "callback", callback = result))
  }

  list(kind = "http", inspected = inspect_auth_request_once(auth_url))
}

expect_par_auth_request_rejected <- function(
  auth_url,
  redirect_uri,
  expected_error = "invalid_request",
  description_pattern = NULL
) {
  rejected <- capture_par_auth_request_rejection(auth_url, redirect_uri)

  if (identical(rejected$kind, "callback")) {
    result <- rejected$callback
    code <- result[["code"]] %||% NA_character_
    testthat::expect_false(
      is.character(code) && length(code) == 1L && !is.na(code) && nzchar(code),
      info = paste0(
        "Expected PAR authorization request to be rejected. Callback: ",
        result[["callback_url"]] %||% "<no callback>"
      )
    )
    callback_error <- parse_query_param(
      result[["callback_url"]],
      "error",
      decode = TRUE
    )
    testthat::expect_identical(callback_error, expected_error)

    if (!is.null(description_pattern)) {
      testthat::expect_match(
        parse_query_param(
          result[["callback_url"]],
          "error_description",
          decode = TRUE
        ),
        description_pattern,
        ignore.case = TRUE
      )
    }

    return(invisible(rejected))
  }

  inspected <- rejected$inspected
  location_error <- parse_query_param(
    inspected$location,
    "error",
    decode = TRUE
  )
  combo <- paste(
    inspected$status,
    inspected$location %||% "",
    inspected$body %||% ""
  )

  if (
    is.character(location_error) &&
      length(location_error) == 1L &&
      !is.na(location_error) &&
      nzchar(location_error)
  ) {
    testthat::expect_identical(location_error, expected_error)
  } else {
    testthat::expect_true(
      inspected$status %in% c(400L, 401L, 403L),
      info = combo
    )
  }

  if (!is.null(description_pattern)) {
    testthat::expect_match(combo, description_pattern, ignore.case = TRUE)
  }

  invisible(rejected)
}

replace_client_id_in_auth_url <- function(auth_url, new_client_id) {
  stopifnot(is.character(auth_url), length(auth_url) == 1L, nzchar(auth_url))
  stopifnot(
    is.character(new_client_id),
    length(new_client_id) == 1L,
    nzchar(new_client_id)
  )

  sub(
    "([?&])client_id=[^&]+",
    paste0("\\1client_id=", utils::URLencode(new_client_id, reserved = TRUE)),
    auth_url,
    perl = TRUE
  )
}

testthat::test_that("push_authorization_request rejects request_uri in the pushed body", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "header", use_par = TRUE)
  client <- make_confidential_client(prov)

  params <- list(
    response_type = "code",
    redirect_uri = client@redirect_uri,
    scope = "openid",
    state = "test-state",
    request_uri = "urn:ietf:params:oauth:request_uri:attacker"
  )

  testthat::expect_error(
    shinyOAuth:::push_authorization_request(client, params),
    regexp = "must not include request_uri",
    class = "shinyOAuth_config_error"
  )
})

testthat::test_that("Keycloak PAR rejects wrong JWT client assertion audience", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "client_secret_jwt", use_par = TRUE)
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = get_client_secret_jwt_secret(),
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_assertion_alg = "HS256",
    client_assertion_audience = "https://example.com/not-keycloak"
  )

  built <- build_par_auth_url(client)

  testthat::expect_true(is.na(built$auth_url))
  testthat::expect_identical(built$error, "auth_url_error")
  testthat::expect_match(
    built$error_description %||% "",
    "Pushed authorization request failed",
    fixed = TRUE
  )
  testthat::expect_match(
    built$error_description %||% "",
    "401|Unauthorized|invalid_request|Authentication failed",
    ignore.case = TRUE
  )
  expect_state_store_size(client, 0L)
})

testthat::test_that("Keycloak PAR request_uri is rejected after first use", {
  skip_common()
  local_test_options()

  prov <- make_provider(use_par = TRUE)
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state_info <- get_state_info(client, auth_url)
      testthat::expect_match(auth_url, "[?&]request_uri=")

      first <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      values$.process_query(callback_query(first))
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

      access_token_before <- values$token@access_token %||% ""
      username_before <- values$token@userinfo[["preferred_username"]] %||%
        NA_character_
      rejected <- expect_par_auth_request_rejected(
        auth_url,
        redirect_uri = client@redirect_uri,
        expected_error = "invalid_request",
        description_pattern = "Invalid Request"
      )

      if (identical(rejected$kind, "callback")) {
        replay_callback <- rejected$callback
        replay_state <- parse_query_param(replay_callback$callback_url, "state")
        replay_iss <- parse_query_param(
          replay_callback$callback_url,
          "iss",
          decode = TRUE
        )

        values$.process_query(callback_query(replay_callback))
        session$flushReact()

        testthat::expect_true(isTRUE(values$authenticated))
        testthat::expect_false(is.null(values$token))
        testthat::expect_identical(
          values$token@access_token %||% "",
          access_token_before
        )
        testthat::expect_identical(
          values$token@userinfo[["preferred_username"]] %||% NA_character_,
          username_before
        )
        testthat::expect_true(
          (values$error %||% "") %in%
            c(
              "invalid_state",
              "issuer_missing",
              "issuer_mismatch"
            ),
          info = paste(
            "Unexpected replay error:",
            values$error %||% "<NULL>",
            replay_state %||% "<no state>",
            replay_iss %||% "<no iss>"
          )
        )
      } else {
        testthat::expect_true(isTRUE(values$authenticated))
        testthat::expect_false(is.null(values$token))
      }

      expect_state_store_entry_consumed(client, state_info)
    }
  )
})

testthat::test_that("Keycloak PAR request_uri is rejected after realm-configured expiry", {
  skip_common()
  local_test_options()

  prov <- make_provider(use_par = TRUE)
  client <- make_public_client(prov)
  admin_token <- keycloak_admin_token()
  original_lifespan <- keycloak_realm_attribute(
    admin_token,
    "parRequestUriLifespan",
    default = "60"
  )

  on.exit(
    keycloak_update_realm_attribute(
      admin_token,
      "parRequestUriLifespan",
      original_lifespan
    ),
    add = TRUE
  )

  keycloak_update_realm_attribute(
    admin_token,
    "parRequestUriLifespan",
    "1"
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state_info <- get_state_info(client, auth_url)
      testthat::expect_match(auth_url, "[?&]request_uri=")

      Sys.sleep(2)

      rejected <- expect_par_auth_request_rejected(
        auth_url,
        redirect_uri = client@redirect_uri,
        expected_error = "invalid_request",
        description_pattern = "Invalid Request|expired|request_uri"
      )

      if (identical(rejected$kind, "callback")) {
        expired_callback <- rejected$callback
        callback_state <- parse_query_param(
          expired_callback$callback_url,
          "state"
        )
        callback_iss <- parse_query_param(
          expired_callback$callback_url,
          "iss",
          decode = TRUE
        )
        callback_bound <- identical(callback_state, state_info$sealed) &&
          identical(callback_iss, prov@issuer)

        values$.process_query(callback_query(expired_callback))
        session$flushReact()

        testthat::expect_false(isTRUE(values$authenticated))

        if (isTRUE(callback_bound)) {
          testthat::expect_identical(values$error, "invalid_request")
          testthat::expect_match(
            values$error_description %||% "",
            "request|expired|invalid",
            ignore.case = TRUE
          )
          expect_state_store_entry_consumed(
            client,
            state_info,
            info = paste(
              "A bound PAR expiry callback should consume the matching state"
            )
          )
        } else {
          testthat::expect_true(
            (values$error %||% "") %in%
              c(
                "invalid_state",
                "issuer_missing",
                "issuer_mismatch"
              ),
            info = paste(
              "Unexpected expiry callback error:",
              values$error %||% "<NULL>",
              callback_state %||% "<no state>",
              callback_iss %||% "<no iss>"
            )
          )
          expect_state_store_entry_present(
            client,
            state_info,
            info = "Expiry rejection without a bound callback must leave pending state untouched"
          )
        }
      } else {
        testthat::expect_null(values$error)
        testthat::expect_null(values$error_description)
        expect_state_store_entry_present(
          client,
          state_info,
          info = "Expiry rejection before redirect should leave pending state untouched"
        )
      }
    }
  )
})

testthat::test_that("PAR request_uri remains bound to the posting client when outer client_id changes", {
  skip_common()
  local_test_options()

  prov <- make_provider(use_par = TRUE)
  client <- make_public_client(prov)
  built <- build_par_auth_url(client)

  testthat::expect_true(is.null(built$error))
  testthat::expect_match(built$auth_url, "[?&]request_uri=")
  testthat::expect_match(built$auth_url, "[?&]client_id=shiny-public")

  tampered_url <- replace_client_id_in_auth_url(
    built$auth_url,
    new_client_id = "shiny-confidential"
  )
  testthat::expect_match(tampered_url, "[?&]client_id=shiny-confidential")

  expect_par_auth_request_rejected(
    tampered_url,
    redirect_uri = client@redirect_uri,
    expected_error = "invalid_request",
    description_pattern = "request_uri|client|unauthorized|PAR"
  )
})
