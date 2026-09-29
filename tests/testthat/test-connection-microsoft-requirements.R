test_that("Microsoft static consent requires actual permission evidence", {
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  make_client <- function(required, resource = "https://graph.microsoft.com") {
    static <- paste0(resource, "/.default")
    oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = static,
      token_targets = list(
        api = list(
          resource = resource,
          scopes = static,
          required_scopes = required
        )
      )
    )
  }
  for (resource in c(
    "https://graph.microsoft.com",
    "https://management.example/"
  )) {
    for (suffix in c(".default", ".DEFAULT")) {
      expect_error(
        make_client(paste0(resource, "/", suffix), resource),
        "required_scopes must name actual API permissions"
      )
      expect_error(
        make_client(
          c(paste0(resource, "/User.Read"), paste0(resource, "/", suffix)),
          resource
        ),
        "required_scopes must name actual API permissions"
      )
    }
  }
  client <- make_client("https://graph.microsoft.com/User.Read")
  request <- token_target_request(client)
  response <- token_target_response(client, list(scope = "user.read"), request)
  expect_no_error(validate_token_target_grant(
    client,
    response[["scope"]],
    request
  ))
  expect_error(validate_token_target_grant(
    client,
    "https://graph.microsoft.com/Mail.Read",
    request
  ))
  expect_error(token_target_response(
    client,
    list(scope = "https://graph.microsoft.com/.default"),
    request
  ))
  expect_no_error(make_client(character()))
  # The marker has provider-specific semantics; an RFC 8707 scope is opaque.
  provider@token_target_mode <- "rfc8707"
  expect_no_error(make_client("https://graph.microsoft.com/.default"))
})
