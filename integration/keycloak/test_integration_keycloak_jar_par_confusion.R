## Integration tests: PAR/JAR outer-parameter confusion

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

append_conflicting_outer_params <- function(auth_url) {
  sep <- if (grepl("?", auth_url, fixed = TRUE)) "&" else "?"
  paste0(
    auth_url,
    sep,
    paste(
      c(
        paste0(
          "redirect_uri=",
          utils::URLencode("http://localhost:3000/attacker", reserved = TRUE)
        ),
        "scope=openid%20email%20admin",
        "state=attacker-state",
        "client_id=shiny-public"
      ),
      collapse = "&"
    )
  )
}

expect_conflicting_outer_params_do_not_override <- function(client) {
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      original_state <- parse_query_param(auth_url, "state")
      tampered_url <- append_conflicting_outer_params(auth_url)
      login <- try(
        perform_login_form(tampered_url, redirect_uri = client@redirect_uri),
        silent = TRUE
      )

      if (inherits(login, "try-error")) {
        testthat::expect_s3_class(attr(login, "condition"), "condition")
      } else {
        code <- login$code %||% NA_character_
        if (
          !(is.character(code) &&
            length(code) == 1L &&
            !is.na(code) &&
            nzchar(code))
        ) {
          testthat::expect_false(
            identical(login$state_payload, "attacker-state")
          )
          testthat::expect_match(
            login$callback_url %||% "",
            "error|invalid|request|client|redirect|state|scope",
            ignore.case = TRUE
          )
        } else {
          testthat::expect_false(
            identical(login$state_payload, "attacker-state")
          )
          if (
            is.character(original_state) &&
              !is.na(original_state) &&
              nzchar(original_state)
          ) {
            testthat::expect_identical(login$state_payload, original_state)
          }

          values$.process_query(callback_query(login))
          session$flushReact()

          testthat::expect_true(isTRUE(values$authenticated))
          testthat::expect_null(values$error)
          testthat::expect_false(is.null(values$token))
          testthat::expect_identical(
            values$token@userinfo$preferred_username,
            "alice"
          )
        }
      }
    }
  )
}

testthat::test_that("JAR signed request object resists conflicting outer parameters", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_hmac_jar_client(prov)

  expect_conflicting_outer_params_do_not_override(client)
})

testthat::test_that("PAR request_uri resists conflicting outer parameters", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "header", use_par = TRUE)
  client <- make_confidential_client(prov)

  expect_conflicting_outer_params_do_not_override(client)
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
