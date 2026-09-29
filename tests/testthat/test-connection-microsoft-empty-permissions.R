empty_permission_client <- function(
  resource,
  scopes,
  required = character(),
  mode = "microsoft"
) {
  provider <- make_test_provider()
  provider@token_target_mode <- mode
  oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("openid", scopes),
    token_targets = list(
      api = list(
        resource = resource,
        scopes = scopes,
        required_scopes = required
      )
    )
  )
}

test_that("Microsoft declarations reject resource prefixes without permissions", {
  for (resource in c(
    "api://resource",
    "api://resource/",
    "https://graph.microsoft.com",
    "499b84ac-1321-427f-aa17-267ca6975798"
  )) {
    prefix <- paste0(resource, "/")
    read <- paste0(prefix, "Read")
    for (scopes in list(prefix, c(read, prefix), paste(read, prefix))) {
      expect_error(
        empty_permission_client(resource, scopes),
        "must name a permission after the resource prefix"
      )
    }
    expect_error(
      empty_permission_client(resource, prefix, required = prefix),
      "must name a permission after the resource prefix"
    )
    for (required in list(
      prefix,
      c("openid", read, prefix),
      paste(read, prefix)
    )) {
      expect_error(
        empty_permission_client(
          resource,
          paste0(prefix, ".default"),
          required = required
        ),
        "must name a permission after the resource prefix"
      )
    }
  }
})

test_that("Microsoft permission validation preserves exact prefixes and OIDC requirements", {
  for (resource in c(
    "api://resource",
    "api://resource/",
    "https://graph.microsoft.com",
    "499b84ac-1321-427f-aa17-267ca6975798"
  )) {
    prefix <- paste0(resource, "/")
    for (permission in c("Read", "read:items", "items/read")) {
      scope <- paste0(prefix, permission)
      for (scopes in c(scope, paste0(prefix, ".default"))) {
        client <- empty_permission_client(
          resource,
          scopes,
          required = c("openid", scope)
        )
        expect_s7_class(client, OAuthClient)
        request <- token_target_request(client)
        expect_setequal(request[["scopes"]], c("openid", scopes))
        expect_no_error(validate_token_target_grant(
          client,
          c("openid", scope),
          request
        ))
        expect_error(
          validate_token_target_grant(client, c("openid", prefix), request),
          class = "shinyOAuth_token_error"
        )
      }
    }
  }
  # RFC 8707 scope names are opaque and have no Microsoft permission suffix.
  expect_s7_class(
    empty_permission_client(
      "https://api.example",
      "https://api.example/",
      required = "https://api.example/",
      mode = "rfc8707"
    ),
    OAuthClient
  )
})
