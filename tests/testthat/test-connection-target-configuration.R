test_that("target requirements cannot mistake refresh consent for an API permission", {
  for (mode in c("rfc8707", "microsoft")) {
    provider <- make_test_provider()
    provider@token_target_mode <- mode
    api_scope <- if (mode == "microsoft") "https://api.example/read" else "read"
    make_client <- function(
      required = character(),
      target_required = api_scope
    ) {
      oauth_client(
        provider,
        "app",
        client_secret = "",
        redirect_uri = "https://app.example/callback",
        scopes = c(api_scope, "offline_access"),
        required_scopes = required,
        token_targets = list(
          api = list(
            resource = "https://api.example",
            scopes = api_scope,
            required_scopes = target_required
          )
        )
      )
    }
    expect_error(
      make_client(required = "offline_access"),
      "offline_access.*required_scopes"
    )
    expect_error(
      make_client(target_required = "offline_access"),
      "offline_access.*required_scopes"
    )
    expect_error(
      make_client(target_required = c(api_scope, "offline_access")),
      "offline_access.*required_scopes"
    )
    client <- make_client()
    expect_s7_class(client, OAuthClient)
    # Consent is retained without claiming an access-token permission, whether
    # the provider issued a refresh credential or declined to issue one.
    for (refresh in c("synthetic-refresh", NA_character_)) {
      token <- manager_test_token(refresh = refresh)
      token@granted_scopes <- api_scope
      bundle <- token_target_bundle(client, token)
      record <- token_target_select(list(
        client = client,
        token = token,
        targets = bundle,
        status = "active"
      ))
      expect_identical(connection_record_status(record), "active")
      expect_false(connection_record_has_scopes(record, "offline_access"))
      expect_true("offline_access" %in% bundle[["limits"]][["api"]])
    }
    token <- manager_test_token()
    token@granted_scopes <- character()
    expect_error(
      token_target_bundle(client, token),
      class = "shinyOAuth_token_error"
    )
  }
})

test_that("Microsoft static consent selects the exact declared resource", {
  make_client <- function(resource, scopes) {
    provider <- make_test_provider()
    provider@token_target_mode <- "microsoft"
    oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = scopes,
      token_targets = list(api = list(resource = resource, scopes = scopes))
    )
  }
  for (resource in c(
    "https://contoso.com",
    "https://contoso.com/api",
    "api://app"
  )) {
    for (scopes in list(
      paste0(resource, "/child/.default"),
      c(paste0(resource, "/.default"), paste0(resource, "/child/.default"))
    )) {
      expect_error(make_client(resource, scopes), "exact resource")
    }
    scope <- paste0(resource, "/.default")
    client <- make_client(resource, scope)
    request <- token_target_request(client)
    expect_identical(
      token_target_parameters(client, request),
      list(scope = scope)
    )
    expect_identical(
      token_target_parameters(
        client,
        token_target_refresh_request(client, "api", token_target_limits(client))
      ),
      list(scope = scope)
    )
  }
  # A trailing slash is part of the resource identifier, including for .default.
  client <- make_client("https://contoso.com/", "https://contoso.com//.default")
  expect_identical(
    token_target_parameters(client, token_target_request(client))[["scope"]],
    "https://contoso.com//.default"
  )
  # Microsoft permission names may themselves contain slashes.
  expect_s7_class(
    make_client("https://contoso.com", "https://contoso.com/permission/read"),
    OAuthClient
  )
})

test_that("target resources use the shared absolute URI validation", {
  make_client <- function(resource, mode, scope = NULL) {
    provider <- make_test_provider()
    provider@token_target_mode <- mode
    scope <- scope %||%
      if (identical(mode, "microsoft")) {
        paste0(resource, "/read")
      } else {
        "read"
      }
    oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = scope,
      token_targets = list(api = list(resource = resource, scopes = scope))
    )
  }
  for (mode in c("rfc8707", "microsoft")) {
    for (resource in c(
      "https://api.example/%Q0",
      "urn:bad%",
      "https://api.example/a\\b",
      "urn:[abc",
      "urn:api\001",
      "urn:api\177",
      "https://[::1",
      "https://api.example/#part",
      "urn:with space",
      "relative/path",
      paste0("urn:", strrep("x", 2045L))
    )) {
      expect_error(
        make_client(resource, mode, "api://example/read"),
        "absolute URI",
        info = resource
      )
    }
    for (resource in c(
      "https://api.example/v1?tenant=abc",
      "https://[::1]/api",
      "urn:example:api",
      "api://application-id",
      "custom:api%20name",
      paste0("urn:", strrep("x", 2044L))
    )) {
      client <- make_client(resource, mode)
      expect_identical(client@token_targets[["api"]][["resource"]], resource)
    }
  }
})
