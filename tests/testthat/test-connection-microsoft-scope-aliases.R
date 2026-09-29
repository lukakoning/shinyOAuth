test_that("optional Microsoft aliases recognize responses without establishing permissions", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  returned <- "read"
  requests <- list()
  local_mocked_bindings(req_with_retry = function(req, ...) {
    requests[[
      length(requests) + 1L
    ]] <<- normalize_scope_tokens(utils::URLdecode(
      as.character(req[["body"]][["data"]][["scope"]])
    ))
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
  for (static in c(FALSE, TRUE)) {
    requested <- paste0("api://resource/", if (static) ".default" else "read")
    client <- oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = requested,
      scope_validation = "strict",
      token_targets = list(
        api = list(
          resource = "api://resource",
          scopes = requested,
          scope_aliases = c("items/read", "read:items")
        )
      )
    )
    browser <- valid_browser_token()
    exchange <- function() {
      url <- prepare_call(client, browser)
      expect_identical(
        parse_query_param(url, "scope", decode = TRUE),
        requested
      )
      token <- handle_callback(
        client,
        "code",
        parse_query_param(url, "state"),
        browser
      )
      expect_identical(tail(requests, 1L)[[1L]], requested)
      token
    }
    returned <- "read"
    token <- exchange()
    bundle <- token_target_bundle(client, token)
    expect_false("api://resource/items/read" %in% bundle[["limits"]][["api"]])
    for (extra in c("items/read", "READ:ITEMS")) {
      returned <- paste("read", extra)
      token <- exchange()
      expect_setequal(
        token@granted_scopes,
        paste0("api://resource/", c("read", extra))
      )
      bundle <- token_target_bundle(client, token)
      expect_identical(
        token_target_scopes_allowed(
          client,
          "api",
          paste0("api://resource/", extra),
          bundle[["limits"]][["api"]]
        ),
        static
      )
      request <- token_target_request(client, limits = bundle[["limits"]])
      fresh <- refresh_token_dispatch(client, token, target_request = request)
      committed <- token_target_commit(client, token, bundle, fresh, request)
      expect_identical(
        token_target_bundle_decode(
          client,
          token_target_bundle_encode(committed[["targets"]])
        ),
        committed[["targets"]]
      )
      expect_identical(tail(requests, 1L)[[1L]], request[["scopes"]])
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          .accept_login_token(token, NULL)
          current <- values[["connection"]]()
          expect_identical(
            current[["has_scopes"]](paste0("api://resource/", extra)),
            static
          )
          expect_false(current[["has_scopes"]]("api://resource/ungranted"))
        }
      )
    }
    # A later alias cannot restore a permission absent from the retained grant.
    returned <- "read"
    token <- exchange()
    bundle <- token_target_bundle(client, token)
    returned <- "read items/read"
    request <- token_target_request(client, limits = bundle[["limits"]])
    fresh <- refresh_token_dispatch(client, token, target_request = request)
    committed <- token_target_commit(client, token, bundle, fresh, request)
    expect_identical(
      committed[["targets"]][["limits"]][["api"]],
      "api://resource/read"
    )
    for (foreign in c(
      "api://other/items/read",
      "https://other/read:items",
      "unknown/permission",
      "unknown:permission"
    )) {
      returned <- paste("read", foreign)
      expect_error(exchange(), "scope limit")
    }
    # Alias interpretation is covered by the authenticated client policy.
    returned <- "read"
    url <- prepare_call(client, browser)
    targets <- client@token_targets
    targets[["api"]][["scope_aliases"]] <- "different/name"
    client@token_targets <- targets
    calls <- length(requests)
    expect_error(handle_callback(
      client,
      "code",
      parse_query_param(url, "state"),
      browser
    ))
    expect_length(requests, calls)
  }
})

test_that("scope aliases reject ambiguous names, excessive data, and other protocols", {
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  make <- function(aliases) {
    oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = c("urn:resource/.default", "urn:other/.default"),
      token_targets = list(
        api = list(
          resource = "urn:resource",
          scopes = "urn:resource/.default",
          scope_aliases = aliases
        ),
        other = list(resource = "urn:other", scopes = "urn:other/.default")
      ),
      default_token_target = "api"
    )
  }
  for (aliases in list(
    ".default",
    "openid",
    "offline_access",
    "api://other/read",
    "urn:other/read",
    NA_character_,
    1,
    paste0("s", seq_len(129)),
    strrep("x", 8193)
  )) {
    expect_error(make(aliases))
  }
  expect_s7_class(make("items/read read:items"), OAuthClient)
  provider@token_target_mode <- "rfc8707"
  expect_error(make("items/read"), "scope_aliases")
})
