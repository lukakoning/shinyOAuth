test_that("target declarations integrate with existing lists and client policies", {
  for (mode in c("rfc8707", "microsoft")) {
    provider <- make_test_provider()
    provider@token_target_mode <- mode
    resource <- if (mode == "microsoft") "api://example-app" else "urn:example:api"
    scopes <- if (mode == "microsoft") paste0(resource, "/", c("read", "write")) else c("read", "write")
    target <- oauth_token_target(
      resource, paste(c(scopes, scopes), collapse = " "),
      required_scopes = scopes[[1L]], resource_ids = "api"
    )
    raw <- list(resource = resource, scopes = scopes,
                required_scopes = scopes[[1L]], resource_ids = "api")
    args <- list(
      provider = provider, client_id = "app", client_secret = "secret",
      redirect_uri = "https://app.example/callback",
      resource_bases = c(api = "https://api.example/v1"),
      state_store = cachem::cache_mem(max_age = 300), state_key = strrep("a", 64)
    )
    client <- do.call(oauth_client, c(args, list(token_targets = list(api = target))))
    legacy <- do.call(oauth_client, c(args, list(token_targets = list(api = raw))))
    expect_identical(connection_client_fingerprint(client), connection_client_fingerprint(legacy))
    expect_identical(client@scopes, scopes)
    expect_identical(token_target_required_scopes(client, "api"), scopes[[1L]])

    optional <- oauth_token_target(resource, scopes)
    args[["token_targets"]] <- list(api = optional)
    client <- do.call(oauth_client, args)
    expect_identical(token_target_required_scopes(client, "api"), character())
  }
})

test_that("target helpers leave contextual checks to the client", {
  provider <- make_test_provider()
  provider@token_target_mode <- "rfc8707"
  build <- function(target) oauth_client(
    provider, "app", "secret", redirect_uri = "https://app.example/callback",
    token_targets = list(api = target)
  )
  expect_error(build(oauth_token_target("urn:api", "read", required_scopes = "write")), "required_scopes")
  expect_error(build(oauth_token_target("urn:api", "read", resource_ids = "unconfigured")), "resource_ids")
  expect_error(build(oauth_token_target("urn:api", "read", scope_aliases = "Read")), "scope_aliases")
  guid <- "11111111-2222-3333-4444-555555555555"
  declaration <- oauth_token_target(guid, paste0(guid, "/read"))
  expect_error(build(declaration), "absolute URI")
  provider@token_target_mode <- "microsoft"
  expect_s7_class(build(declaration), OAuthClient)
})

test_that("target declarations reject malformed fields before client setup", {
  cases <- list(
    list(resource = "relative"),
    list(resource = "urn:api#fragment"),
    list(resource = c("urn:first", "urn:second")),
    list(resource = NA_character_),
    list(resource = paste0("urn:", strrep("x", 2048))),
    list(scopes = character()),
    list(scopes = NA_character_),
    list(scopes = 1),
    list(scopes = "read\"write"),
    list(scopes = paste0("read", seq_len(129))),
    list(required_scopes = 1),
    list(scope_aliases = NA_character_),
    list(resource_ids = c("api", "api")),
    list(resource_ids = "bad/name")
  )
  for (change in cases) {
    args <- utils::modifyList(list(resource = "urn:api", scopes = "read"), change)
    expect_error(do.call(oauth_token_target, args), class = "shinyOAuth_input_error")
  }
})
