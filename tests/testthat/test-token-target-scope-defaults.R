test_that("client constructors infer only omitted target scopes", {
  for (mode in c("rfc8707", "microsoft")) {
    provider <- make_test_provider()
    provider@token_target_mode <- mode
    first <- if (mode == "microsoft") "https://first.example/read" else "read"
    second <- if (mode == "microsoft") "https://second.example/read" else "write"
    targets <- list(
      first = list(resource = "https://first.example", scopes = first),
      second = list(resource = "https://second.example", scopes = second)
    )
    for (constructor in list(oauth_client, OAuthClient)) {
      args <- list(
        provider = provider, client_id = "app", client_secret = "secret",
        redirect_uri = "https://app.example/callback",
        token_targets = targets, token_target_default = "first"
      )
      client <- do.call(constructor, args)
      expect_identical(client@scopes, c(first, second))
      expect_identical(client@required_scopes, character())
      expect_identical(token_target_required_scopes(client, "second"), character())

      for (explicit in list(first, character(), NULL)) {
        limited <- args
        limited["scopes"] <- list(explicit)
        expect_error(do.call(constructor, limited))
      }
      args[["scopes"]] <- c(first, second, "profile", "offline_access")
      explicit <- do.call(constructor, args)
      expect_identical(explicit@scopes, args[["scopes"]])
    }
  }
})

test_that("inferred scope requests deduplicate tokens and preserve OIDC policy", {
  provider <- oauth_provider(
    "example", "https://issuer.example/auth", "https://issuer.example/token",
    issuer = "https://issuer.example", userinfo_required = FALSE,
    token_auth_style = "body", token_target_mode = "rfc8707"
  )
  targets <- list(
    api = list(resource = "urn:api", scopes = "read write read"),
    other = list(resource = "urn:other", scopes = rep("read", 129))
  )
  for (constructor in list(oauth_client, OAuthClient)) {
    client <- constructor(
      provider = provider, client_id = "app", client_secret = "secret",
      redirect_uri = "https://app.example/callback",
      token_targets = targets, token_target_default = "api"
    )
    expect_identical(client@scopes, c("openid", "read", "write"))
    expect_setequal(effective_client_scopes(client, warn = FALSE), c("openid", "read", "write"))
    url <- prepare_call(client, browser_token = valid_browser_token())
    requested <- normalize_scope_tokens(parse_query_param(url, "scope", decode = TRUE))
    expect_setequal(requested, c("openid", "read", "write"))
  }
})

test_that("scope inference retains ordinary defaults and rejects malformed declarations", {
  provider <- make_test_provider()
  for (constructor in list(oauth_client, OAuthClient)) {
    ordinary <- constructor(
      provider = provider, client_id = "app", client_secret = "secret",
      redirect_uri = "https://app.example/callback"
    )
    expect_identical(ordinary@scopes, character())
  }
  provider@token_target_mode <- "rfc8707"
  args <- list(
    provider = provider, client_id = "app", client_secret = "secret",
    redirect_uri = "https://app.example/callback"
  )
  malformed <- list(
    list(api = 1),
    list(api = list(resource = "urn:api")),
    list(api = list(resource = "urn:api", scopes = NA_character_)),
    list(api = list(resource = "urn:api", scopes = 1)),
    list(api = list(resource = "urn:api", scopes = paste0("read", seq_len(129)))),
    stats::setNames(rep(list(list(resource = "urn:api", scopes = "read")), 17), paste0("api", seq_len(17)))
  )
  for (constructor in list(oauth_client, OAuthClient)) {
    for (targets in malformed) {
      expect_error(do.call(constructor, c(args, list(token_targets = targets))))
    }
  }
})
