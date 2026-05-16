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
      result$auth_url <<- values$build_auth_url()
      result$error <<- values$error
      result$error_description <<- values$error_description
    }
  )

  result
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

expect_par_auth_request_rejected <- function(auth_url, redirect_uri, pattern) {
  result <- try(
    perform_login_form(auth_url, redirect_uri = redirect_uri),
    silent = TRUE
  )

  if (!inherits(result, "try-error")) {
    code <- result$code %||% NA_character_
    testthat::expect_false(
      is.character(code) && length(code) == 1L && !is.na(code) && nzchar(code),
      info = paste0(
        "Expected PAR authorization request to be rejected. Callback: ",
        result$callback_url %||% "<no callback>"
      )
    )
    testthat::expect_match(
      result$callback_url %||% "",
      pattern,
      ignore.case = TRUE
    )
    return(invisible(result))
  }

  inspected <- inspect_auth_request_once(auth_url)
  combo <- paste(
    inspected$status,
    inspected$location %||% "",
    inspected$body %||% ""
  )
  testthat::expect_match(combo, pattern, ignore.case = TRUE)
  invisible(inspected)
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

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      combo <- paste(values$error %||% "", values$error_description %||% "")

      testthat::expect_true(is.na(auth_url))
      testthat::expect_true(!is.null(values$error))
      testthat::expect_match(
        combo,
        "Pushed authorization request failed|invalid_client|aud",
        perl = TRUE,
        ignore.case = TRUE
      )
      testthat::expect_length(client@state_store$keys(), 0L)
    }
  )
})

testthat::test_that("Keycloak PAR request_uri is rejected after first use", {
  skip_common()
  local_test_options()

  prov <- make_provider(use_par = TRUE)
  client <- make_public_client(prov)
  auth_url <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <<- values$build_auth_url()
      testthat::expect_match(auth_url, "[?&]request_uri=")

      first <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      values$.process_query(callback_query(first))
      session$flushReact()

      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
    }
  )

  expect_par_auth_request_rejected(
    auth_url,
    redirect_uri = client@redirect_uri,
    pattern = "error|invalid|request_uri|expired|already|used|pushed|PAR"
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
    pattern = "error|invalid|request_uri|client|unauthorized|PAR"
  )
})
