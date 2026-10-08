github_scope_client <- function(scopes = c("repo", "gist")) {
  client <- make_test_client(scopes = scopes, use_nonce = FALSE)
  provider <- oauth_provider_github(name = "custom-github")
  provider@userinfo_required <- FALSE
  client@provider <- provider
  client@scope_validation <- "strict"
  client
}

test_that("response scope format is explicit validated provider policy", {
  provider <- github_scope_client()@provider
  expect_identical(provider@token_response_scope_format, "comma")
  worker <- prepare_client_for_worker(github_scope_client())
  expect_identical(worker@provider@token_response_scope_format, "comma")
  standard <- make_test_client(use_nonce = FALSE)@provider
  expect_identical(standard@token_response_scope_format, "space")
  fingerprint <- provider_fingerprint(provider)
  provider@token_response_scope_format <- "space"
  expect_false(identical(provider_fingerprint(provider), fingerprint))
  for (invalid in list("", "other", NA_character_, c("space", "comma"))) {
    expect_error(
      provider@token_response_scope_format <- invalid,
      "token_response_scope_format"
    )
  }
  expect_error(
    oauth_provider(
      name = "custom",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      token_response_scope_format = "other"
    ),
    "token_response_scope_format"
  )
  expect_error(
    OAuthProvider(
      name = "custom",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      token_response_scope_format = "other"
    ),
    "token_response_scope_format"
  )
})

for (form in c(FALSE, TRUE)) {
  test_that(paste("GitHub scopes are normalized in login and refresh", form), {
    client <- github_scope_client()
    local_mocked_bindings(req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list(
          "content-type" = if (form) {
            "application/x-www-form-urlencoded"
          } else {
            "application/json"
          }
        ),
        body = charToRaw(
          if (form) {
            "access_token=synthetic-after&token_type=Bearer&refresh_token=synthetic-refresh&scope=repo%2Cgist&expires_in=3600"
          } else {
            '{"access_token":"synthetic-after","token_type":"Bearer","refresh_token":"synthetic-refresh","scope":"repo,gist","expires_in":3600}'
          }
        )
      )
    })
    browser <- valid_browser_token()
    url <- prepare_call(client, browser_token = browser)
    token <- handle_callback(
      client,
      code = "synthetic-code",
      state = parse_query_param(url, "state"),
      browser_token = browser
    )
    expect_setequal(token@granted_scopes, c("repo", "gist"))
    expect_true(token@granted_scopes_verified)
    refreshed <- refresh_token_dispatch(client, token)
    expect_setequal(refreshed@granted_scopes, c("repo", "gist"))
    expect_true(refreshed@granted_scopes_verified)
  })
}

test_that("comma handling preserves standard OAuth tokens and rejects empty entries", {
  client <- make_test_client(scopes = "repo,gist", use_nonce = FALSE)
  client@scope_validation <- "strict"
  response <- list(
    access_token = "synthetic-access",
    token_type = "Bearer",
    scope = "repo,gist",
    expires_in = 3600
  )
  standard <- verify_token_set(client, response, nonce = NULL)
  expect_identical(standard[["granted_scopes"]], "repo,gist")

  github <- github_scope_client()
  for (invalid in c("repo,,gist", ",repo", "repo,", "repo, gist")) {
    response[["scope"]] <- invalid
    expect_error(
      verify_token_set(github, response, nonce = NULL),
      class = "shinyOAuth_token_error"
    )
  }
  response[["scope"]] <- "repo"
  expect_error(
    verify_token_set(github, response, nonce = NULL),
    "Granted scopes missing",
    class = "shinyOAuth_token_error"
  )
  empty <- github_scope_client(character())
  response[["scope"]] <- ""
  expect_identical(
    verify_token_set(empty, response, nonce = NULL)[["granted_scopes"]],
    character()
  )
  response[["scope"]] <- NULL
  expect_identical(
    verify_token_set(empty, response, nonce = NULL)[["granted_scopes"]],
    character()
  )
})
