test_that("SMART scope budgets survive callback, replacement and narrowing", {
  # Raise the independent configurable transport limits to isolate scope policy.
  local_options(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.callback_max_state_bytes = 1048576,
    shinyOAuth.state_max_token_chars = 1048576,
    shinyOAuth.state_max_wrapper_bytes = 1048576,
    shinyOAuth.state_max_ct_b64_chars = 1048576,
    shinyOAuth.state_max_ct_bytes = 1048576
  )
  for (scopes in list(
    paste0("user/Observation.rs?code=", seq_len(140L)),
    paste0("user/Observation.rs?code=", seq_len(70L), strrep("x", 120L))
  )) {
    client <- smart_client(
      smart_client_fixture(),
      "example",
      "https://app.example/callback",
      scopes = scopes,
      required_scopes = character()
    )
    response_scopes <- scopes
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
            scope = paste(response_scopes, collapse = " ")
          ),
          auto_unbox = TRUE
        ))
      )
    })
    url <- prepare_call(client, "__SKIPPED__")
    token <- handle_callback(
      client,
      "code",
      parse_query_param(url, "state"),
      "__SKIPPED__"
    )
    expect_setequal(token@granted_scopes, scopes)
    expect_error(
      refresh_scope_request(client, token, rep(scopes[[1L]], 257L)),
      "bounded"
    )
    expect_error(
      refresh_scope_request(
        client,
        token,
        paste(rep(scopes[[1L]], 3000L), collapse = " ")
      ),
      "bounded"
    )
    expect_setequal(authorization_scope_limit(client, scopes), scopes)
    manager <- oauth_connections(
      list(a = client),
      "https://app.example",
      retention = "browser",
      store = oauth_connection_store_memory(),
      owner_policy = oauth_browser_owner(),
      keys = list(
        credentials = openssl::rand_bytes(32),
        owner = openssl::rand_bytes(32)
      )
    )
    fixture <- list(
      ui = oauth_connections_ui(shiny::fluidPage(), "health", manager)
    )
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = manager),
      session = manager_test_session(manager_test_cookie(fixture)),
      {
        id <- manager_test_accept(controller, token = token)
        controller[["reauthorize"]](id)
        hooks <- controller[["hooks"]]("a")
        context <- hooks[["prepare"]]()
        expect_setequal(context[["requested_scopes"]], scopes)
        url <- prepare_call_internal(
          client,
          "__SKIPPED__",
          .requested_scopes = context[["requested_scopes"]]
        )
        replacement <- handle_callback(
          client,
          "code",
          parse_query_param(url, "state"),
          "__SKIPPED__"
        )
        hooks[["accept"]](replacement, context, as.numeric(Sys.time()))
        expect_setequal(replacement@granted_scopes, scopes)
      }
    )
    response_scopes <- scopes[-length(scopes)]
    narrowed <- refresh_token_dispatch(
      client,
      token,
      scope_request = refresh_scope_request(client, token, response_scopes)
    )
    expect_setequal(narrowed@granted_scopes, response_scopes)
    expect_false(authorization_scopes_bounded(
      paste0("scope", seq_len(257L)),
      client
    ))
    expect_false(authorization_scopes_bounded(strrep("x", 65537L), client))
  }
  expect_error(authorization_context_json(list(
    requested_scopes = rep("x", 257L)
  )))
  expect_error(authorization_context_json(list(
    requested_scopes = strrep("x", 65537L)
  )))
  ordinary <- make_test_client()
  ordinary@scopes <- "read"
  ordinary@required_scopes <- character()
  token <- OAuthToken(access_token = "synthetic", granted_scopes = "read")
  expect_error(
    refresh_scope_request(ordinary, token, rep("read", 129L)),
    "bounded"
  )
  expect_error(
    refresh_scope_request(
      ordinary,
      token,
      paste(rep("read", 1700L), collapse = " ")
    ),
    "bounded"
  )
  expect_false(authorization_scopes_bounded(
    paste0("scope", seq_len(129L)),
    ordinary
  ))
  expect_false(authorization_scopes_bounded(strrep("x", 8193L), ordinary))
})

test_that("broader SMART evidence does not double count covered request scopes", {
  scopes <- paste0("user/Observation.r?code=", seq_len(140L))
  grants <- sub(".r?", ".rs?", scopes, fixed = TRUE)
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = c(scopes, "user/Patient.r"),
    required_scopes = character()
  )
  for (requested in list(scopes, c(scopes, "user/Patient.r"))) {
    required <- intersect(requested, "user/Patient.r")
    request <- list(
      scopes = requested,
      accepted_extra_scopes = grants,
      required_scopes = required
    )
    actual <- union(grants, required)
    expect_no_error(validate_refresh_scope_grant(client, actual, request))
    expect_error(
      validate_refresh_scope_grant(
        client,
        sub(".rs?", ".cruds?", actual, fixed = TRUE),
        request
      ),
      "exceeds"
    )
    if (length(required)) {
      expect_error(
        validate_refresh_scope_grant(client, grants, request),
        "required"
      )
    }
  }
})
