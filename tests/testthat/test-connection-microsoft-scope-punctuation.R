test_that("Microsoft callbacks normalize declared punctuated short permissions safely", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  provider <- oauth_provider(
    "microsoft-contract",
    "https://issuer.example/auth",
    "https://issuer.example/token",
    token_target_mode = "microsoft",
    use_nonce = FALSE,
    token_auth_style = "public"
  )
  returned <- ""
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(
        list(
          access_token = "access",
          refresh_token = "refresh",
          token_type = "Bearer",
          expires_in = 3600,
          scope = returned
        ),
        auto_unbox = TRUE
      ))
    )
  })
  browser <- valid_browser_token()
  exchange <- function(client) {
    url <- prepare_call(client, browser)
    handle_callback(client, "code", parse_query_param(url, "state"), browser)
  }
  for (static in c(FALSE, TRUE)) {
    for (permission in c("Read.Items", "read:items", "items/read")) {
      scope <- paste0("api://resource/", permission)
      requested <- if (static) "api://resource/.default" else scope
      client <- oauth_client(
        provider,
        "app",
        redirect_uri = "https://app.example/callback",
        scopes = requested,
        scope_validation = "strict",
        token_targets = list(
          api = list(
            resource = "api://resource",
            scopes = requested,
            required_scopes = scope
          )
        )
      )
      for (evidence in c(permission, toupper(permission), scope)) {
        returned <- evidence
        token <- exchange(client)
        expected <- if (startsWith(evidence, "api://")) {
          evidence
        } else {
          paste0("api://resource/", evidence)
        }
        expect_identical(token@granted_scopes, expected)
        expect_true(connection_scope_covered(
          client,
          scope,
          token@granted_scopes
        ))
      }
      for (foreign in c(
        "api://other/read:items",
        "https://evil.example/items/read",
        "api://resource.evil/items/read",
        "API://resource/items/read",
        "unknown:permission",
        "unknown/permission",
        ".default"
      )) {
        returned <- paste(scope, foreign)
        expect_error(exchange(client), "scope limit|actual granted permissions")
      }
    }
  }
})

test_that("Microsoft punctuation normalization never reinterprets a URI as a permission", {
  client <- make_test_client(use_nonce = FALSE)
  client@provider@token_target_mode <- "microsoft"
  # Even an explicitly declared suffix cannot make a fully qualified foreign
  # scope local. Resource identifiers remain exact, including their ASCII case.
  declaration <- list(
    api = list(
      resource = "api://resource",
      scopes = c(
        "api://resource/https://other/read",
        "api://resource/items/read"
      ),
      required_scopes = character()
    )
  )
  S7::props(client) <- list(
    scopes = declaration[["api"]][["scopes"]],
    token_targets = declaration,
    default_token_target = "api"
  )
  request <- list(target = "api", scopes = "api://resource/items/read")
  response <- token_target_response(
    client,
    list(scope = "https://other/read"),
    request
  )
  expect_identical(response[["scope"]], "https://other/read")
  expect_error(
    validate_token_target_grant(client, response[["scope"]], request),
    "scope limit"
  )
})
