## Integration tests: live Keycloak RFC 8707 resource-indicator behavior

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_resource_indicator_client <- function(prov, resource) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid", "profile", "email"),
    introspect = TRUE,
    resource = resource
  )
}

resource_indicator_login_via_module <- function(client) {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      login <- try(
        perform_login_form(auth_url, redirect_uri = client@redirect_uri),
        silent = TRUE
      )

      if (inherits(login, "try-error")) {
        result <<- list(
          auth_url = auth_url,
          login_error = conditionMessage(attr(login, "condition")),
          authenticated = FALSE,
          error = values$error,
          error_description = values$error_description,
          token = values$token
        )
      } else {
        values$.process_query(callback_query(login))
        session$flushReact()

        result <<- list(
          auth_url = auth_url,
          login = login,
          callback_url = login$callback_url,
          authenticated = isTRUE(values$authenticated),
          error = values$error,
          error_description = values$error_description,
          token = values$token
        )
      }
    }
  )

  result
}

resource_failure_text <- function(result) {
  paste(
    result$error %||% "",
    result$error_description %||% "",
    result$callback_url %||% "",
    result$login_error %||% ""
  )
}

testthat::test_that("Keycloak code flow accepts RFC 8707 resource indicators", {
  skip_common()
  local_test_options()

  resource <- "https://api.shinyoauth.test"
  prov <- make_provider()
  client <- make_resource_indicator_client(prov, resource = resource)

  result <- resource_indicator_login_via_module(client)

  testthat::expect_match(
    result$auth_url,
    "resource=https%3A%2F%2Fapi\\.shinyoauth\\.test"
  )
  testthat::expect_true(
    isTRUE(result$authenticated),
    info = resource_failure_text(result)
  )
  testthat::expect_null(result$error)
  testthat::expect_false(is.null(result$token))
  testthat::expect_true(isTRUE(result$token@id_token_validated))

  intros <- shinyOAuth::introspect_token(client, result$token, which = "access")
  testthat::expect_true(isTRUE(intros$supported))
  testthat::expect_true(isTRUE(intros$active))
})
