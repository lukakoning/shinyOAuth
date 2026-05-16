## Integration tests: refresh-token protection against live Keycloak
##
## Covers the refresh happy path, explicit refresh-token revocation, and
## module-level revoke_on_session_end behavior.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_refresh_confidential_client <- function(
  prov,
  scopes = c("openid", "profile", "email")
) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = scopes
  )
}

refresh_login_via_module <- function(
  client,
  revoke_on_session_end = FALSE,
  username = "alice"
) {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(
      client,
      revoke_on_session_end = revoke_on_session_end
    ),
    expr = {
      auth_url <- values$build_auth_url()
      login <- perform_login_form_as(
        auth_url,
        username = username,
        password = username,
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

token_subject <- function(token) {
  if (
    is.list(token@userinfo) &&
      is.character(token@userinfo$sub) &&
      nzchar(token@userinfo$sub)
  ) {
    return(token@userinfo$sub)
  }

  if (is.character(token@id_token) && nzchar(token@id_token)) {
    return(shinyOAuth:::parse_jwt_payload(token@id_token)$sub)
  }

  NA_character_
}

expect_live_userinfo_subject <- function(client, token, expected_subject) {
  userinfo <- shinyOAuth::get_userinfo(client, token)

  testthat::expect_true(is.list(userinfo))
  testthat::expect_identical(userinfo$sub, expected_subject)
  invisible(userinfo)
}

expect_refresh_token_failure <- function(client, token) {
  err <- testthat::expect_error(
    shinyOAuth::refresh_token(client, token),
    regexp = "Token refresh failed|invalid_grant",
    class = "shinyOAuth_http_error"
  )
  testthat::expect_match(
    conditionMessage(err),
    "Token refresh failed|invalid_grant"
  )
  invisible(err)
}

testthat::test_that("Keycloak refresh happy path preserves subject binding", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_refresh_confidential_client(prov)
  login <- refresh_login_via_module(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_null(login$error)
  testthat::expect_true(nzchar(login$token@refresh_token %||% ""))

  original_subject <- token_subject(login$token)
  testthat::expect_true(nzchar(original_subject))

  expect_live_userinfo_subject(client, login$token, original_subject)

  refreshed <- shinyOAuth::refresh_token(client, login$token)

  testthat::expect_true(nzchar(refreshed@access_token))
  testthat::expect_true(nzchar(refreshed@refresh_token))
  testthat::expect_identical(token_subject(refreshed), original_subject)
  testthat::expect_true(isTRUE(refreshed@id_token_validated))

  expect_live_userinfo_subject(client, refreshed, original_subject)
})

testthat::test_that("revoking a Keycloak refresh token blocks future refresh", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_refresh_confidential_client(prov)
  login <- refresh_login_via_module(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_true(nzchar(login$token@refresh_token %||% ""))

  rev_result <- shinyOAuth::revoke_token(client, login$token, which = "refresh")
  testthat::expect_true(isTRUE(rev_result$supported))
  testthat::expect_true(isTRUE(rev_result$revoked))
  testthat::expect_identical(rev_result$status, "ok")

  expect_refresh_token_failure(client, login$token)
})

testthat::test_that("revoke_on_session_end invalidates the live refresh token", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_refresh_confidential_client(prov)
  login <- refresh_login_via_module(client, revoke_on_session_end = TRUE)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_true(nzchar(login$token@refresh_token %||% ""))

  expect_refresh_token_failure(client, login$token)
})
