oauth_scope_target_client <- function(required = TRUE, introspect = FALSE) {
  provider <- make_test_provider()
  S7::props(provider) <- list(
    token_target_mode = "rfc8707",
    introspection_url = "https://issuer.example/introspect"
  )
  scopes <- c("profile", "email", "address", "phone", "offline_access")
  oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c(scopes, "read"),
    scope_validation = "strict",
    introspect = introspect,
    introspection_checks = if (introspect) "scope" else character(),
    token_targets = list(
      api = list(
        resource = "urn:api",
        scopes = scopes,
        required_scopes = if (required) scopes else character()
      ),
      sibling = list(resource = "urn:sibling", scopes = "read")
    ),
    default_token_target = "api"
  )
}

test_that("OAuth-only scope names stay with their declared target on the wire", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (introspect in c(FALSE, TRUE)) {
    client <- oauth_scope_target_client(introspect = introspect)
    scopes <- client@token_targets[["api"]][["scopes"]]
    sent <- list()
    evidence <- paste(scopes, collapse = " ")
    local_mocked_bindings(
      req_with_retry = function(req, ...) {
        sent[[length(sent) + 1L]] <<- lapply(
          req[["body"]][["data"]],
          function(x) {
            utils::URLdecode(gsub("+", " ", as.character(x), fixed = TRUE))
          }
        )
        body <- list(
          access_token = "access",
          refresh_token = "refresh",
          token_type = "Bearer",
          expires_in = 3600
        )
        if (!introspect) {
          body[["scope"]] <- evidence
        }
        httr2::response(
          req[["url"]],
          status = 200L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE))
        )
      },
      introspect_token = function(...) {
        list(supported = TRUE, active = TRUE, raw = list(scope = evidence))
      }
    )
    browser <- valid_browser_token()
    url <- prepare_call(client, browser)
    token <- handle_callback(
      client,
      "code",
      parse_query_param(url, "state"),
      browser
    )
    fresh <- refresh_token(client, token)
    expect_setequal(fresh@granted_scopes, scopes)
    expect_length(sent, 2L)
    for (request in sent) {
      expect_identical(request[["resource"]], "urn:api")
      expect_setequal(normalize_scope_tokens(request[["scope"]]), scopes)
    }
    bundle <- token_target_bundle_decode(
      client,
      token_target_bundle_encode(token_target_bundle(client, fresh))
    )
    expect_setequal(bundle[["limits"]][["api"]], scopes)
    sibling <- token_target_request(
      client,
      "sibling",
      limits = bundle[["limits"]]
    )
    expect_identical(sibling[["scopes"]], "read")
    expect_error(
      token_target_request(client, "sibling", scopes = "email"),
      class = "shinyOAuth_access_error"
    )
    # An API named offline_access needs actual evidence, including introspection.
    evidence <- paste(setdiff(scopes, "offline_access"), collapse = " ")
    expect_error(refresh_token(client, fresh), class = "shinyOAuth_token_error")
  }
})

test_that("OAuth-only offline_access is not invented as retained refresh consent", {
  client <- oauth_scope_target_client(required = FALSE)
  token <- manager_test_token()
  token@granted_scopes <- "email"
  bundle <- token_target_bundle_decode(
    client,
    token_target_bundle_encode(token_target_bundle(client, token))
  )
  expect_identical(bundle[["limits"]][["api"]], "email")
  expect_error(
    token_target_request(
      client,
      limits = bundle[["limits"]],
      scopes = "offline_access"
    ),
    class = "shinyOAuth_access_error"
  )
})

test_that("OIDC providers reserve identity scopes even without explicit openid", {
  client <- oauth_scope_target_client()
  provider <- client@provider
  S7::props(provider) <- list(
    issuer = "https://issuer.example",
    id_token_validation = TRUE
  )
  expect_error(
    suppressWarnings({
      client@provider <- provider
    }),
    "Target scopes must be non-empty API scopes"
  )
})
