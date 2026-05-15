## Integration tests: OAuth authorization error callback handling
##
## RFC 6749 section 4.1.2.1 allows an authorization server to redirect with
## `error` instead of `code`. The module should only surface provider-controlled
## error fields after callback issuer and state validation have succeeded.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

keycloak_error_query <- function(
  error = "access_denied",
  state = NA_character_,
  iss = NA_character_,
  error_description = NA_character_,
  error_uri = NA_character_
) {
  parts <- list(
    error = error,
    error_description = error_description,
    error_uri = error_uri,
    state = state,
    iss = iss
  )
  keep <- vapply(
    parts,
    function(value) {
      is.character(value) &&
        length(value) == 1L &&
        !is.na(value)
    },
    logical(1)
  )
  parts <- parts[keep]

  paste0(
    "?",
    paste(
      vapply(
        names(parts),
        function(name) {
          paste0(
            utils::URLencode(name, reserved = TRUE),
            "=",
            utils::URLencode(parts[[name]], reserved = TRUE)
          )
        },
        character(1)
      ),
      collapse = "&"
    )
  )
}

clear_oauth_error_values <- function(values) {
  values$error <- NULL
  values$error_description <- NULL
  values$error_uri <- NULL
  invisible(NULL)
}

testthat::test_that("authorization error callback consumes state and blocks replay", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      state <- parse_query_param(url, "state")
      state_info <- get_state_info(client, url)
      query <- keycloak_error_query(
        error = "access_denied",
        error_description = "Consent denied by user",
        error_uri = "https://example.com/oauth-error",
        state = state,
        iss = prov@issuer
      )

      values$.process_query(query)
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "access_denied")
      testthat::expect_identical(
        values$error_description,
        "Consent denied by user"
      )
      testthat::expect_identical(
        values$error_uri,
        "https://example.com/oauth-error"
      )
      testthat::expect_null(client@state_store$get(
        state_info$key,
        missing = NULL
      ))

      clear_oauth_error_values(values)
      values$.process_query(query)
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(
        values$error_description %||% "",
        "state",
        ignore.case = TRUE
      )
      testthat::expect_false(isTRUE(values$authenticated))
    }
  )
})

testthat::test_that("authorization error callback issuer is checked before state consumption", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      state <- parse_query_param(url, "state")
      state_info <- get_state_info(client, url)

      values$.process_query(keycloak_error_query(
        error = "access_denied",
        error_description = "Wrong issuer should not be trusted",
        state = state,
        iss = "http://localhost:8080/realms/attacker"
      ))
      session$flushReact()

      testthat::expect_identical(values$error, "issuer_mismatch")
      testthat::expect_false(
        is.null(client@state_store$get(state_info$key, missing = NULL)),
        info = "Issuer mismatch must not consume state"
      )

      clear_oauth_error_values(values)
      values$.process_query(keycloak_error_query(
        error = "access_denied",
        error_description = "Consent denied by user",
        state = state,
        iss = prov@issuer
      ))
      session$flushReact()

      testthat::expect_identical(values$error, "access_denied")
      testthat::expect_identical(
        values$error_description,
        "Consent denied by user"
      )
      testthat::expect_null(client@state_store$get(
        state_info$key,
        missing = NULL
      ))
    }
  )
})

testthat::test_that("unsolicited authorization error is rejected as invalid state", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      values$.process_query(keycloak_error_query(
        error = "access_denied",
        error_description = "Unbound provider error",
        iss = prov@issuer
      ))
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(
        values$error_description %||% "",
        "state",
        ignore.case = TRUE
      )
      testthat::expect_false(isTRUE(values$authenticated))
    }
  )
})
