target_test_client <- function(
  mode = "rfc8707",
  base = "https://issuer.example"
) {
  provider <- oauth_provider(
    "targets",
    paste0(base, "/auth"),
    paste0(base, "/token"),
    token_auth_style = "body",
    use_nonce = FALSE,
    token_target_mode = mode
  )
  scopes <- if (mode == "microsoft") {
    c(
      "https://calendar.example/read",
      "https://calendar.example/write",
      "https://contacts.example/read"
    )
  } else {
    c("calendar.read", "calendar.write", "contacts.read")
  }
  oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = scopes,
    scope_validation = "strict",
    resource_bases = c(
      calendar_api = "https://calendar.example/v1",
      contacts_api = "https://contacts.example/v1"
    ),
    token_targets = list(
      calendar = list(
        resource = if (mode == "microsoft") {
          "https://calendar.example"
        } else {
          "https://calendar.example/"
        },
        scopes = scopes[1:2],
        resource_ids = "calendar_api"
      ),
      contacts = list(
        resource = if (mode == "microsoft") {
          "https://contacts.example"
        } else {
          "https://contacts.example/"
        },
        scopes = scopes[3],
        resource_ids = "contacts_api"
      )
    ),
    default_token_target = "calendar"
  )
}

target_test_token <- function(
  scopes = c("calendar.read", "calendar.write"),
  access = "calendar-initial",
  refresh = "refresh-0"
) {
  OAuthToken(
    access_token = access,
    refresh_token = refresh,
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = scopes,
    granted_scopes_verified = TRUE
  )
}

target_test_manager <- function(client = target_test_client()) {
  manager <- oauth_connections(
    list(a = client),
    "https://app.example",
    retention = "browser",
    owner_policy = oauth_browser_owner(),
    store = oauth_connection_store_memory(),
    keys = list(
      credentials = openssl::rand_bytes(32),
      owner = openssl::rand_bytes(32)
    )
  )
  list(
    manager = manager,
    ui = oauth_connections_ui(shiny::fluidPage("Targets"), "auth", manager)
  )
}

test_that("target reauthorization starts ordinary login without prior grant history", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  redirects <- list()
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    send_oauth_module_redirect = function(session, url) {
      redirects[[length(redirects) + 1L]] <<- url
    }
  )
  for (oidc in c(FALSE, TRUE)) {
    for (after_logout in c(FALSE, TRUE)) {
      redirects <- list()
      client <- target_test_client()
      if (oidc) {
        provider <- client@provider
        S7::props(provider) <- list(
          issuer = "https://issuer.example",
          id_token_validation = TRUE
        )
        S7::props(client) <- list(
          provider = provider,
          scopes = c(client@scopes, "openid", "profile")
        )
      }
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          session[["flushReact"]]()
          if (after_logout) {
            operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
            .accept_login_token(
              target_test_token(c("calendar.read", if (oidc) "openid")),
              NULL
            )
            .finish_auth_operation(operation, "login")
            previous <- values[["connection"]]()
            values[["logout"]]()
            expect_identical(previous[["is_usable"]](), FALSE)
          }
          values[["reauthorize"]]()
          expect_identical(values[["pending_login"]], TRUE)
          expect_null(auth_operations[["reauth_scopes"]])
          session[["setInputs"]](
            shinyOAuth_sid = browser_ack[["token"]],
            shinyOAuth_cookie_ack = list(requestId = browser_ack[["id"]])
          )
          poll_for_async(function() length(redirects) > 0L, session)
          url <- redirects[[1L]]
          expect_setequal(
            normalize_scope_tokens(parse_query_param(
              url,
              "scope",
              decode = TRUE
            )),
            effective_client_scopes(client)
          )
          payload <- state_payload_decrypt_validate(
            client,
            parse_query_param(url, "state")
          )
          expect_setequal(
            unlist(payload[["scopes"]]),
            effective_client_scopes(client)
          )
        }
      )
    }
  }
})

test_that("target reauthorization does not expand explicitly empty target limits", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- target_test_client()
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      auth_operations[["target_limits"]] <- list(
        calendar = character(),
        contacts = character()
      )
      error <- tryCatch(values[["reauthorize"]](), error = identity)
      expect_identical(error[["context"]][["reason"]], "interaction_required")
      expect_identical(values[["pending_login"]], FALSE)
    }
  )
})

test_that("Microsoft resource rejections preserve sibling credentials only in Microsoft mode", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (mode in c("microsoft", "rfc8707")) {
    for (managed in c(FALSE, TRUE)) {
      for (code in c(
        "invalid_resource",
        "invalid_grant",
        "interaction_required"
      )) {
        client <- target_test_client(mode)
        response_state <- new.env(parent = emptyenv())
        response_state[["reject"]] <- TRUE
        requests <- list()
        local_mocked_bindings(
          req_with_retry = function(req, ...) {
            body <- req[["body"]][["data"]]
            requests[[length(requests) + 1L]] <<- body
            result <- if (response_state[["reject"]]) {
              list(error = code)
            } else {
              list(
                access_token = "calendar-refreshed",
                token_type = "Bearer",
                expires_in = 3600,
                scope = utils::URLdecode(as.character(body[["scope"]]))
              )
            }
            httr2::response(
              url = req[["url"]],
              status = if (response_state[["reject"]]) 400L else 200L,
              headers = list("content-type" = "application/json"),
              body = charToRaw(jsonlite::toJSON(result, auto_unbox = TRUE))
            )
          },
          revoke_token = function(...) invisible(NULL)
        )
        f <- target_test_manager(client)
        shiny::testServer(
          if (managed) oauth_connections_server else oauth_module_server,
          args = if (managed) {
            list(id = "auth", manager = f[["manager"]])
          } else {
            list(id = "auth", client = client, auto_redirect = FALSE)
          },
          session = manager_test_session(
            if (managed) manager_test_cookie(f) else NULL
          ),
          {
            token <- target_test_token(client@token_targets[["calendar"]][[
              "scopes"
            ]])
            current <- if (managed) {
              connection(manager_test_accept(controller, token = token))
            } else {
              operation <- .begin_auth_operation(
                "login",
                NULL,
                new_epoch = TRUE
              )
              .accept_login_token(token, NULL)
              .finish_auth_operation(operation, "login")
              values[["connection"]]()
            }
            failure <- tryCatch(
              current[["access_token"]](target = "contacts"),
              error = identity
            )
            expect_s3_class(failure, "shinyOAuth_access_error")
            expect_length(requests, 1L)
            if (mode == "microsoft" && code == "invalid_resource") {
              expect_identical(current[["access_token"]](), "calendar-initial")
              response_state[["reject"]] <- FALSE
              expect_identical(
                current[["access_token"]](force_refresh = TRUE),
                "calendar-refreshed"
              )
              expect_identical(
                utils::URLdecode(as.character(requests[[2L]][[
                  "refresh_token"
                ]])),
                "refresh-0"
              )
            } else {
              expect_identical(current[["is_usable"]](), FALSE)
              failure <- tryCatch(current[["access_token"]](), error = identity)
              expect_s3_class(failure, "shinyOAuth_access_error")
              expect_length(requests, 1L)
            }
          }
        )
      }
    }
  }
})

test_that("scope declaration forms agree through exchange, acquisition and restoration", {
  for (mode in c("rfc8707", "microsoft")) {
    for (scope_string in c(FALSE, TRUE)) {
      for (required_string in c(FALSE, TRUE)) {
        template <- target_test_client(mode)
        scopes <- list(
          calendar = if (mode == "microsoft") {
            paste0("https://calendar.example/", c("read", "write"))
          } else {
            c("calendar.read", "calendar.write")
          },
          contacts = if (mode == "microsoft") {
            paste0("https://contacts.example/", c("read", "write"))
          } else {
            c("contacts.read", "contacts.write")
          }
        )
        declarations <- template@token_targets
        for (target in names(declarations)) {
          declarations[[target]][["scopes"]] <- if (scope_string) {
            paste(scopes[[target]], collapse = " ")
          } else {
            scopes[[target]]
          }
          declarations[[target]][["required_scopes"]] <- if (required_string) {
            paste(scopes[[target]], collapse = " ")
          } else {
            scopes[[target]]
          }
        }
        client <- oauth_client(
          template@provider,
          "app",
          client_secret = "",
          redirect_uri = template@redirect_uri,
          scopes = unlist(scopes, use.names = FALSE),
          resource_bases = template@resource_bases,
          token_targets = declarations,
          default_token_target = "calendar"
        )
        requests <- list()
        omit_required <- FALSE
        local_mocked_bindings(req_with_retry = function(req, ...) {
          body <- lapply(req[["body"]][["data"]], function(value) {
            utils::URLdecode(as.character(value))
          })
          requests[[length(requests) + 1L]] <<- body
          scope <- if (omit_required) {
            scopes[["contacts"]][[1L]]
          } else {
            body[["scope"]]
          }
          httr2::response(
            req[["url"]],
            status = 200L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(
              list(
                access_token = paste0("access-", length(requests)),
                refresh_token = paste0("refresh-", length(requests)),
                token_type = "Bearer",
                expires_in = 3600,
                scope = scope
              ),
              auto_unbox = TRUE
            ))
          )
        })
        browser <- valid_browser_token()
        url <- prepare_call(client, browser)
        token <- handle_callback(
          client,
          code = "code",
          state = parse_query_param(url, "state"),
          browser_token = browser
        )
        expect_setequal(token@granted_scopes, scopes[["calendar"]])
        bundle <- token_target_bundle(client, token)
        request <- token_target_request(client, "contacts", bundle[["limits"]])
        fresh <- refresh_token_dispatch(client, token, target_request = request)
        expect_setequal(fresh@granted_scopes, scopes[["contacts"]])
        committed <- token_target_commit(client, token, bundle, fresh, request)
        key <- openssl::rand_bytes(32L)
        sealed <- connection_credentials_seal(
          committed[["token"]],
          "synthetic-owner-id",
          "synthetic-connection-id",
          client,
          key,
          as.numeric(Sys.time()),
          targets = committed[["targets"]]
        )
        restored <- connection_credentials_open(
          sealed,
          "synthetic-owner-id",
          "synthetic-connection-id",
          client,
          key
        )
        expect_identical(restored[["token"]]@access_token, token@access_token)
        expect_identical(
          restored[["targets"]][["tokens"]][["contacts"]]@access_token,
          fresh@access_token
        )
        record <- token_target_select(
          c(list(client = client), restored),
          "contacts"
        )
        expect_setequal(
          record[["target_requested_scopes"]],
          scopes[["contacts"]]
        )
        expect_setequal(
          record[["target_required_scopes"]],
          scopes[["contacts"]]
        )
        expect_identical(
          requests[[1L]][["scope"]],
          paste(scopes[["calendar"]], collapse = " ")
        )
        expect_identical(
          requests[[2L]][["scope"]],
          paste(scopes[["contacts"]], collapse = " ")
        )
        for (bad in list(
          scopes[["contacts"]][[1L]],
          scopes[["calendar"]],
          c(scopes[["contacts"]], "admin")
        )) {
          error <- tryCatch(
            token_target_request(client, "contacts", scopes = bad),
            error = identity
          )
          expect_s3_class(error, "shinyOAuth_access_error")
        }
        omit_required <- TRUE
        error <- tryCatch(
          refresh_token_dispatch(
            client,
            restored[["token"]],
            target_request = request
          ),
          error = identity
        )
        expect_s3_class(error, "shinyOAuth_token_error")
      }
    }
  }
})

test_that("aggregate scope limits agree at configuration and reauthorization boundaries", {
  # Exercise the scope budget independently of the configurable state envelope.
  local_options(
    shinyOAuth.callback_max_state_bytes = 65536,
    shinyOAuth.state_max_token_chars = 65536,
    shinyOAuth.state_max_wrapper_bytes = 65536,
    shinyOAuth.state_max_ct_b64_chars = 65536,
    shinyOAuth.state_max_ct_bytes = 65536
  )
  make_client <- function(first, second, oidc = character()) {
    template <- target_test_client()
    oauth_client(
      template@provider,
      "app",
      client_secret = "",
      redirect_uri = template@redirect_uri,
      scopes = c(first, second, oidc),
      token_targets = list(
        calendar = list(resource = "urn:calendar", scopes = first),
        contacts = list(resource = "urn:contacts", scopes = second)
      ),
      default_token_target = "calendar"
    )
  }
  cases <- list(
    list(
      first = paste0("calendar.", seq_len(64L)),
      second = paste0("contacts.", seq_len(64L))
    ),
    list(first = strrep("a", 4096L), second = strrep("b", 4096L))
  )
  for (case in cases) {
    client <- do.call(make_client, case)
    scopes <- token_target_authorization_scopes(
      client,
      token_target_limits(client)
    )
    expect_setequal(authorization_scope_limit(client, scopes), client@scopes)
    browser <- valid_browser_token()
    prepared <- prepare_call_internal(
      client,
      browser,
      .requested_scopes = scopes,
      .target_limits = token_target_limits(client),
      .defer_build = TRUE
    )
    payload <- state_payload_decrypt_validate(
      client,
      prepared[["build_args"]][["payload"]]
    )
    expect_setequal(unlist(payload[["scopes"]]), scopes)
    expect_error(
      make_client(case[["first"]], c(case[["second"]], "extra")),
      "128 distinct scopes.*8192"
    )
    expect_error(
      make_client(case[["first"]], case[["second"]], "openid"),
      "128 distinct scopes.*8192"
    )
  }
  expect_error(
    make_client(paste0("calendar.", 1:65), paste0("contacts.", 1:65)),
    "128 distinct scopes"
  )
  # Shared scope names consume the aggregate budget only once.
  common <- paste0("permission.", seq_len(128L))
  expect_length(
    authorization_scope_limit(make_client(common, common), common),
    128L
  )
})

test_that("Microsoft static consent expansion respects the shared aggregate budget", {
  client <- target_test_client("microsoft")
  declarations <- client@token_targets
  for (target in names(declarations)) {
    declarations[[target]][["scopes"]] <- paste0(
      declarations[[target]][["resource"]],
      "/.default"
    )
  }
  S7::props(client) <- list(
    scopes = vapply(declarations, `[[`, "", "scopes"),
    token_targets = declarations
  )
  calendar <- paste0("https://calendar.example/permission", seq_len(64L))
  contacts <- paste0("https://contacts.example/permission", seq_len(64L))
  primary <- target_test_token(calendar)
  bundle <- token_target_bundle(client, primary)
  request <- token_target_request(client, "contacts", bundle[["limits"]])
  updated <- token_target_commit(
    client,
    primary,
    bundle,
    target_test_token(contacts),
    request
  )
  scopes <- token_target_authorization_scopes(
    client,
    updated[["targets"]][["limits"]]
  )
  expect_length(authorization_scope_limit(client, scopes), 128L)
  for (bad in list(
    c(contacts, "https://contacts.example/extra"),
    paste0("https://contacts.example/", strrep("x", 8192L))
  )) {
    expect_error(
      token_target_commit(
        client,
        primary,
        bundle,
        target_test_token(bad),
        request
      ),
      "scope limit"
    )
  }
  expect_error(
    token_target_bundle(
      client,
      target_test_token(paste0(
        "https://calendar.example/permission",
        seq_len(129L)
      ))
    ),
    "scope limit"
  )
  for (managed in c(FALSE, TRUE)) {
    local_options(shinyOAuth.skip_browser_token = TRUE)
    local_mocked_bindings(
      refresh_token_dispatch = function(...) {
        target_test_token(
          c(contacts, "https://contacts.example/extra"),
          "oversized",
          "rotated"
        )
      },
      revoke_token = function(...) invisible(NULL)
    )
    f <- target_test_manager(client)
    shiny::testServer(
      if (managed) oauth_connections_server else oauth_module_server,
      args = if (managed) {
        list(id = "auth", manager = f[["manager"]])
      } else {
        list(id = "auth", client = client, auto_redirect = FALSE)
      },
      session = manager_test_session(
        if (managed) manager_test_cookie(f) else NULL
      ),
      {
        current <- if (managed) {
          connection(manager_test_accept(controller, token = primary))
        } else {
          operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
          .accept_login_token(primary, NULL)
          .finish_auth_operation(operation, "login")
          values[["connection"]]()
        }
        error <- tryCatch(
          current[["access_token"]](target = "contacts"),
          error = identity
        )
        expect_s3_class(error, "shinyOAuth_access_error")
        expect_identical(current[["is_usable"]](), FALSE)
        error <- tryCatch(current[["access_token"]](), error = identity)
        expect_s3_class(error, "shinyOAuth_access_error")
      }
    )
  }
  requirements <- declarations
  requirements[["calendar"]][["required_scopes"]] <- calendar
  requirements[["contacts"]][["required_scopes"]] <- c(
    contacts,
    "https://contacts.example/extra"
  )
  expect_error(
    {
      client@token_targets <- requirements
    },
    "requirements exceed 128"
  )
})

test_that("target configuration requires deliberate provider and default choices", {
  client <- target_test_client()
  changes <- list(
    list(default_token_target = character()),
    list(resource = "https://elsewhere.example/"),
    list(required_scopes = "calendar.read"),
    list(
      token_targets = list(
        bad = list(resource = "relative", scopes = "calendar.read")
      ),
      default_token_target = "bad"
    )
  )
  for (change in changes) {
    error <- tryCatch(
      {
        S7::props(client) <- change
        NULL
      },
      error = identity
    )
    expect_s3_class(error, "error")
  }
  provider <- client@provider
  provider@token_target_mode <- "none"
  error <- tryCatch(
    {
      client@provider <- provider
      NULL
    },
    error = identity
  )
  expect_s3_class(error, "error")
  expect_identical(token_target_name(client), "calendar")
  error <- tryCatch(token_target_name(client, "missing"), error = identity)
  expect_identical(error[["context"]][["reason"]], "unknown_target")
  provider <- make_test_provider()
  provider@token_target_mode <- "rfc8707"
  one <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = "read",
    token_targets = list(
      api = list(resource = "urn:example:api", scopes = "read")
    )
  )
  expect_identical(one@default_token_target, "api")
})

test_that("two target responses share one rotating credential in the single module", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  local_mocked_bindings(revoke_token = function(...) invisible(NULL))
  client <- target_test_client()
  requests <- list()
  local_mocked_bindings(refresh_token_dispatch = function(
    client,
    token,
    target_request,
    ...
  ) {
    requests[[length(requests) + 1L]] <<- list(
      refresh = token@refresh_token,
      request = target_request
    )
    target_test_token(
      target_request[["scopes"]],
      paste0(target_request[["target"]], "-fresh"),
      paste0("refresh-", length(requests))
    )
  })
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(target_test_token(), NULL)
      .finish_auth_operation(operation, "login")
      connection <- values[["connection"]]()
      expect_identical(
        connection[["targets"]]()[["contacts"]][["status"]],
        "not_acquired"
      )
      expect_identical(
        connection[["has_scopes"]]("contacts.read", target = "contacts"),
        FALSE
      )
      expect_identical(
        connection[["access_token"]](target = "contacts"),
        "contacts-fresh"
      )
      expect_identical(connection[["access_token"]](), "calendar-initial")
      expect_identical(
        connection[["has_scopes"]]("contacts.read", target = "calendar"),
        FALSE
      )
      expect_identical(
        connection[["has_scopes"]]("contacts.read", target = "contacts"),
        TRUE
      )
      expect_identical(connection[["refresh"]](scopes = "calendar.read"), TRUE)
      expect_identical(requests[[2L]][["refresh"]], "refresh-1")
      expect_identical(connection[["has_scopes"]]("calendar.write"), FALSE)
      expect_identical(connection[["refresh"]](target = "contacts"), TRUE)
      expect_identical(connection[["refresh"]](), TRUE)
      expect_identical(requests[[4L]][["request"]][["scopes"]], "calendar.read")
      expect_identical(values[["token"]]@refresh_token, "refresh-4")
      expect_identical(
        is.na(values[["targets"]][["tokens"]][["contacts"]]@refresh_token),
        TRUE
      )
      values[["reauthorize"]]()
      expect_identical(
        auth_operations[["target_limits"]][["calendar"]],
        "calendar.read"
      )
      expect_setequal(
        auth_operations[["reauth_scopes"]],
        c("calendar.read", "contacts.read")
      )
      expect_identical(
        connection[["has_scopes"]]("contacts.read", target = "contacts"),
        FALSE
      )
    }
  )
})

test_that("managed targets persist encrypted responses, rotate atomically and retain limits", {
  f <- target_test_manager()
  cookie <- manager_test_cookie(f)
  requests <- list()
  local_mocked_bindings(refresh_token_dispatch = function(
    client,
    token,
    target_request,
    ...
  ) {
    requests[[length(requests) + 1L]] <<- token@refresh_token
    target_test_token(
      target_request[["scopes"]],
      paste0(target_request[["target"]], "-fresh"),
      paste0("refresh-", length(requests))
    )
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "auth", manager = f[["manager"]]),
    session = manager_test_session(cookie),
    {
      expect_null(connection())
      id <- manager_test_accept(controller, token = target_test_token())
      current <- connection()
      expect_identical(current, connection(id))
      expect_identical(
        current[["access_token"]](target = "contacts"),
        "contacts-fresh"
      )
      expect_identical(current[["access_token"]](), "calendar-initial")
      expect_identical(current[["refresh"]](scopes = "calendar.read"), TRUE)
      expect_identical(requests, list("refresh-0", "refresh-1"))
      record <- controller[["read"]](id)
      expect_identical(
        record[["targets"]][["limits"]][["calendar"]],
        "calendar.read"
      )
      expect_identical(
        record[["targets"]][["tokens"]][["contacts"]]@access_token,
        "contacts-fresh"
      )
      expect_identical(
        grepl("contacts-fresh", record[["stored"]][["sealed"]], fixed = TRUE),
        FALSE
      )
      controller[["reauthorize"]](id)
      hooks <- controller[["hooks"]]("a")
      context <- hooks[["prepare"]]()
      parameters <- hooks[["parameters"]](context)
      expect_identical(
        parameters[["target_limits"]][["calendar"]],
        "calendar.read"
      )
      replacement <- target_test_token(
        "calendar.read",
        refresh = "new-authorization"
      )
      hooks[["accept"]](replacement, context, as.numeric(Sys.time()))
      expect_identical(connection()[["has_scopes"]]("calendar.write"), FALSE)
      expect_identical(
        connection()[["targets"]]()[["contacts"]][["status"]],
        "not_acquired"
      )
      manager_test_accept(
        controller,
        token = target_test_token(refresh = "independent")
      )
      error <- tryCatch(connection(), error = identity)
      expect_identical(error[["context"]][["reason"]], "selection_required")
    }
  )
})

test_that("RFC 8707 and Microsoft contract servers receive resource-specific requests", {
  skip_if_not_installed("webfakes")
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (mode in c("rfc8707", "microsoft")) {
    app <- webfakes::new_app()
    app[["use"]](webfakes::mw_urlencoded())
    app[["locals"]][["requests"]] <- list()
    app[["post"]]("/token", function(req, res) {
      body <- lapply(req[["form"]], function(value) {
        paste(unlist(value), collapse = " ")
      })
      requests <- req[["app"]][["locals"]][["requests"]]
      requests[[length(requests) + 1L]] <- body
      req[["app"]][["locals"]][["requests"]] <- requests
      if (
        length(requests) > 1L &&
          !identical(
            body[["refresh_token"]],
            paste0("rt-", length(requests) - 1L)
          )
      ) {
        res[["set_status"]](400L)
        return(res[["send_json"]](
          list(error = "invalid_grant"),
          auto_unbox = TRUE
        ))
      }
      res[["send_json"]](
        list(
          access_token = paste0("at-", length(requests)),
          refresh_token = paste0("rt-", length(requests)),
          token_type = "Bearer",
          expires_in = 3600,
          scope = body[["scope"]]
        ),
        auto_unbox = TRUE
      )
    })
    app[["get"]]("/requests", function(req, res) {
      res[["send_json"]](
        req[["app"]][["locals"]][["requests"]],
        auto_unbox = TRUE
      )
    })
    srv <- webfakes::local_app_process(app)
    client <- target_test_client(mode, sub("/$", "", srv[["url"]]()))
    browser <- valid_browser_token()
    url <- prepare_call(client, browser_token = browser)
    query <- httr2::url_parse(url)[["query"]]
    expect_setequal(normalize_scope_tokens(query[["scope"]]), client@scopes)
    if (mode == "rfc8707") {
      expect_setequal(
        unlist(query[names(query) == "resource"]),
        c("https://calendar.example/", "https://contacts.example/")
      )
    }
    if (mode == "microsoft") {
      expect_null(query[["resource"]])
    }
    token <- handle_callback(
      client,
      code = "code",
      state = parse_query_param(url, "state"),
      browser_token = browser
    )
    bundle <- token_target_bundle(client, token)
    request <- token_target_request(client, "contacts", bundle[["limits"]])
    fresh <- refresh_token_dispatch(client, token, target_request = request)
    expect_identical(fresh@access_token, "at-2")
    expect_identical(
      fresh@granted_scopes,
      client@token_targets[["contacts"]][["scopes"]]
    )
    captured <- httr2::request(paste0(
      sub("/$", "", srv[["url"]]()),
      "/requests"
    )) |>
      httr2::req_perform() |>
      httr2::resp_body_json()
    expect_identical(
      captured[[1L]][["scope"]],
      paste(client@token_targets[["calendar"]][["scopes"]], collapse = " ")
    )
    expect_identical(
      captured[[2L]][["scope"]],
      client@token_targets[["contacts"]][["scopes"]]
    )
    if (mode == "rfc8707") {
      expect_identical(
        captured[[1L]][["resource"]],
        "https://calendar.example/"
      )
      expect_identical(
        captured[[2L]][["resource"]],
        "https://contacts.example/"
      )
    } else {
      expect_null(captured[[1L]][["resource"]])
      expect_null(captured[[2L]][["resource"]])
    }
    srv[["stop"]]()
  }
})

test_that("target response evidence and Microsoft aliases stay resource bounded", {
  client <- target_test_client("microsoft")
  request <- token_target_request(client, "contacts")
  response <- token_target_response(client, list(scope = "read"), request)
  expect_identical(response[["scope"]], "https://contacts.example/read")
  error <- tryCatch(
    token_target_response(client, list(), request),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_token_error")
  error <- tryCatch(
    validate_token_target_grant(
      client,
      "https://calendar.example/read",
      request
    ),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_token_error")
  ordinary <- target_test_client()
  expect_identical(
    token_target_scopes_allowed(ordinary, "calendar", "email"),
    FALSE
  )
  expect_identical(
    token_target_response(
      ordinary,
      list(scope = "read"),
      token_target_request(ordinary)
    )[["scope"]],
    "read"
  )
})

test_that("ordinary refresh_token uses the declared primary target without expanding its grant", {
  client <- target_test_client()
  request <- NULL
  local_mocked_bindings(req_with_retry = function(req, ...) {
    request <<- req[["body"]][["data"]]
    httr2::response(
      url = req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(
        '{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"scope":"calendar.read"}'
      )
    )
  })
  token <- refresh_token(client, target_test_token("calendar.read"))
  expect_identical(token@granted_scopes, "calendar.read")
  expect_identical(
    utils::URLdecode(as.character(request[["scope"]])),
    "calendar.read"
  )
  expect_identical(
    utils::URLdecode(as.character(request[["resource"]])),
    "https://calendar.example/"
  )
})

test_that("different targets queue and matching async accessors share one refresh", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (managed in c(FALSE, TRUE)) {
    requests <- list()
    completions <- list()
    local_mocked_bindings(
      refresh_token_dispatch = function(client, token, target_request, ...) {
        i <- length(requests) + 1L
        requests[[i]] <<- list(
          refresh = token@refresh_token,
          request = target_request
        )
        promises::promise(function(resolve, reject) {
          completions[[i]] <<- resolve
        })
      },
      revoke_token = function(...) invisible(NULL)
    )
    f <- target_test_manager()
    shiny::testServer(
      if (managed) oauth_connections_server else oauth_module_server,
      args = if (managed) {
        list(id = "auth", manager = f[["manager"]], async = TRUE)
      } else {
        list(id = "auth", client = target_test_client(), auto_redirect = FALSE)
      },
      session = manager_test_session(
        if (managed) manager_test_cookie(f) else NULL
      ),
      {
        current <- if (managed) {
          connection(manager_test_accept(
            controller,
            token = target_test_token()
          ))
        } else {
          operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
          .accept_login_token(target_test_token(), NULL)
          .finish_auth_operation(operation, "login")
          values[["connection"]]()
        }
        results <- list()
        promises::then(
          current[["access_token"]](target = "contacts", async = TRUE),
          function(value) results[["first"]] <<- value,
          function(error) results[["first"]] <<- error
        )
        promises::then(
          current[["access_token"]](target = "contacts", async = TRUE),
          function(value) results[["same"]] <<- value,
          function(error) results[["same"]] <<- error
        )
        promises::then(
          current[["access_token"]](force_refresh = TRUE, async = TRUE),
          function(value) results[["other"]] <<- value,
          function(error) results[["other"]] <<- error
        )
        expect_length(requests, 1L)
        error <- tryCatch(current[["access_token"]](), error = identity)
        expect_identical(error[["context"]][["reason"]], "refresh_pending")
        completions[[1L]](target_test_token(
          "contacts.read",
          "contacts-new",
          "refresh-1"
        ))
        poll_for_async(function() length(requests) == 2L, session)
        expect_length(requests, 2L)
        expect_identical(requests[[2L]][["refresh"]], "refresh-1")
        completions[[2L]](target_test_token(
          access = "calendar-new",
          refresh = "refresh-2"
        ))
        poll_for_async(function() length(results) == 3L, session)
        expect_identical(results[["first"]], "contacts-new")
        expect_identical(results[["same"]], "contacts-new")
        expect_identical(results[["other"]], "calendar-new")
        expect_identical(
          current[["access_token"]](target = "contacts"),
          "contacts-new"
        )
      }
    )
  }
})

test_that("optional target rejection preserves siblings but uncertain rotation ends access", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (managed in c(FALSE, TRUE)) {
    outcome <- new.env(parent = emptyenv())
    outcome[["value"]] <- "not_consumed"
    local_mocked_bindings(refresh_token_dispatch = function(...) {
      stop(refresh_outcome_error(
        simpleError("synthetic provider failure"),
        outcome[["value"]]
      ))
    })
    f <- target_test_manager()
    shiny::testServer(
      if (managed) oauth_connections_server else oauth_module_server,
      args = if (managed) {
        list(id = "auth", manager = f[["manager"]])
      } else {
        list(id = "auth", client = target_test_client(), auto_redirect = FALSE)
      },
      session = manager_test_session(
        if (managed) manager_test_cookie(f) else NULL
      ),
      {
        current <- if (managed) {
          connection(manager_test_accept(
            controller,
            token = target_test_token()
          ))
        } else {
          operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
          .accept_login_token(target_test_token(), NULL)
          .finish_auth_operation(operation, "login")
          values[["connection"]]()
        }
        error <- tryCatch(
          current[["access_token"]](target = "contacts"),
          error = identity
        )
        expect_s3_class(error, "shinyOAuth_access_error")
        expect_identical(current[["access_token"]](), "calendar-initial")
        if (!managed) {
          session[["flushReact"]]()
          expect_identical(values[["authenticated"]], TRUE)
          expect_null(values[["error"]])
        }
        expect_identical(
          current[["targets"]]()[["contacts"]][["status"]],
          "not_acquired"
        )
        outcome[["value"]] <- "possibly_consumed"
        error <- tryCatch(
          current[["refresh"]](target = "contacts"),
          error = identity
        )
        expect_s3_class(error, "shinyOAuth_token_error")
        error <- tryCatch(current[["access_token"]](), error = identity)
        expect_s3_class(error, "shinyOAuth_access_error")
        expect_identical(current[["has_scopes"]]("calendar.read"), FALSE)
      }
    )
  }
})

test_that("logout discards an in-flight target and every queued acquisition", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (managed in c(FALSE, TRUE)) {
    resolve <- NULL
    requests <- 0L
    local_mocked_bindings(
      refresh_token_dispatch = function(...) {
        requests <<- requests + 1L
        promises::promise(function(resolve_, reject_) resolve <<- resolve_)
      },
      revoke_token = function(...) invisible(NULL)
    )
    f <- target_test_manager()
    shiny::testServer(
      if (managed) oauth_connections_server else oauth_module_server,
      args = if (managed) {
        list(id = "auth", manager = f[["manager"]])
      } else {
        list(id = "auth", client = target_test_client(), auto_redirect = FALSE)
      },
      session = manager_test_session(
        if (managed) manager_test_cookie(f) else NULL
      ),
      {
        current <- if (managed) {
          connection(manager_test_accept(
            controller,
            token = target_test_token()
          ))
        } else {
          operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
          .accept_login_token(target_test_token(), NULL)
          .finish_auth_operation(operation, "login")
          values[["connection"]]()
        }
        results <- list()
        promises::then(
          current[["access_token"]](target = "contacts", async = TRUE),
          function(value) results[["first"]] <<- value,
          function(error) results[["first"]] <<- error
        )
        promises::then(
          current[["access_token"]](force_refresh = TRUE, async = TRUE),
          function(value) results[["second"]] <<- value,
          function(error) results[["second"]] <<- error
        )
        if (managed) {
          controller[["logout"]](FALSE)
        } else {
          values[["logout"]]()
        }
        resolve(target_test_token(
          "contacts.read",
          "late-access",
          "late-refresh"
        ))
        poll_for_async(function() length(results) == 2L, session)
        expect_identical(requests, 1L)
        expect_s3_class(results[["first"]], "shinyOAuth_access_error")
        expect_s3_class(results[["second"]], "shinyOAuth_access_error")
        expect_identical(
          current[["has_scopes"]]("contacts.read", target = "contacts"),
          FALSE
        )
      }
    )
  }
})

test_that("HTTP refresh keeps bound transport and sends an application request once", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- target_test_client()
  refreshes <- 0L
  requests <- list()
  local_mocked_bindings(
    refresh_token_dispatch = function(client, token, target_request, ...) {
      refreshes <<- refreshes + 1L
      fresh <- target_test_token(
        target_request[["scopes"]],
        "bound-fresh",
        "rotated"
      )
      fresh@cnf <- list(jkt = "synthetic-binding")
      fresh
    },
    perform_resource_req = function(token, url, ..., idempotent) {
      requests[[length(requests) + 1L]] <<- list(
        token = token,
        idempotent = idempotent
      )
      httr2::response(url = "https://contacts.example/v1", status = 401L)
    }
  )
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(target_test_token(), NULL)
      .finish_auth_operation(operation, "login")
      current <- values[["connection"]]()
      error <- tryCatch(
        current[["request"]](
          "calendar_api",
          target = "contacts",
          refresh = TRUE
        ),
        error = identity
      )
      expect_s3_class(error, "shinyOAuth_input_error")
      expect_identical(refreshes, 0L)
      response <- current[["request"]](
        "contacts_api",
        target = "contacts",
        refresh = TRUE,
        method = "POST"
      )
      expect_identical(httr2::resp_status(response), 401L)
      expect_length(requests, 1L)
      expect_identical(refreshes, 1L)
      expect_identical(requests[[1L]][["idempotent"]], FALSE)
      expect_identical(
        requests[[1L]][["token"]]@cnf,
        list(jkt = "synthetic-binding")
      )
      error <- tryCatch(
        current[["access_token"]](target = "contacts"),
        error = identity
      )
      expect_identical(
        error[["context"]][["reason"]],
        "unsupported_token_binding"
      )
    }
  )
})

test_that("Microsoft static scopes use evidence and cannot restore a narrowed target", {
  client <- target_test_client("microsoft")
  targets <- client@token_targets
  targets[["calendar"]][["scopes"]] <- "https://calendar.example/.default"
  targets[["contacts"]][["scopes"]] <- "https://contacts.example/.default"
  S7::props(client) <- list(
    token_targets = targets,
    scopes = c(
      "openid",
      "offline_access",
      "https://calendar.example/.default",
      "https://contacts.example/.default"
    )
  )
  request <- token_target_request(client)
  response <- token_target_response(client, list(scope = "read write"), request)
  expect_identical(
    response[["scope"]],
    "https://calendar.example/read https://calendar.example/write"
  )
  validate_token_target_grant(
    client,
    normalize_scope_tokens(response[["scope"]]),
    request
  )
  token <- target_test_token(normalize_scope_tokens(response[["scope"]]))
  bundle <- token_target_bundle(client, token)
  narrower <- token_target_request(
    client,
    limits = bundle[["limits"]],
    scopes = "https://calendar.example/read"
  )
  fresh <- target_test_token("https://calendar.example/read", refresh = "rt-1")
  updated <- token_target_commit(client, token, bundle, fresh, narrower)
  retained <- token_target_request(
    client,
    limits = updated[["targets"]][["limits"]]
  )
  expect_setequal(
    retained[["scopes"]],
    "https://calendar.example/read"
  )
  error <- tryCatch(
    token_target_request(
      client,
      limits = updated[["targets"]][["limits"]],
      scopes = "https://calendar.example/.default"
    ),
    error = identity
  )
  expect_identical(error[["context"]][["reason"]], "insufficient_scope")
  expect_identical(
    token_target_prefix("https://management.example/"),
    "https://management.example//"
  )
  wire <- token_target_authorization_parameters(client, client@scopes)
  expect_setequal(
    wire,
    c("openid", "offline_access", "https://calendar.example/.default")
  )
  error <- tryCatch(
    token_target_response(
      client,
      list(scope = "https://calendar.example/.default"),
      request
    ),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_token_error")
})

test_that("sealed replacement limits select the primary independently of overlapping scopes", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  client <- target_test_client()
  targets <- client@token_targets
  targets[["calendar"]][["scopes"]] <- c("read", "write")
  targets[["contacts"]][["scopes"]] <- c("read", "write")
  S7::props(client) <- list(
    token_targets = targets,
    scopes = c("read", "write")
  )
  limits <- list(calendar = "read", contacts = c("read", "write"))
  requested <- NULL
  local_mocked_bindings(swap_code_for_token_set = function(
    client,
    target_request,
    ...
  ) {
    requested <<- target_request
    list(
      access_token = "replacement",
      refresh_token = "replacement-rt",
      token_type = "Bearer",
      expires_in = 3600,
      scope = "read"
    )
  })
  browser <- valid_browser_token()
  url <- prepare_call_internal(
    client,
    browser,
    .requested_scopes = c("read", "write"),
    .target_limits = limits
  )
  result <- handle_callback(
    client,
    code = "code",
    state = parse_query_param(url, "state"),
    browser_token = browser
  )
  expect_identical(requested[["scopes"]], "read")
  expect_identical(result@granted_scopes, "read")
  expect_identical(
    token_target_bundle(client, result, limits)[["limits"]],
    limits
  )
})

test_that("cached target rotations do not rerun consumers and primary expiry keeps siblings", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- target_test_client()
  local_mocked_bindings(
    refresh_token_dispatch = function(client, token, target_request, ...) {
      target_test_token(
        target_request[["scopes"]],
        paste0(target_request[["target"]], "-new"),
        "rotated"
      )
    },
    revoke_token = function(...) invisible(NULL)
  )
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(target_test_token(), NULL)
      .finish_auth_operation(operation, "login")
      current <- values[["connection"]]()
      current[["access_token"]](target = "contacts")
      reads <- 0L
      output[["contacts"]] <- shiny::renderText({
        connection <- shiny::req(values[["connection"]]())
        connection[["access_token"]](target = "contacts")
        reads <<- reads + 1L
        "displayed"
      })
      session[["flushReact"]]()
      expect_identical(output[["contacts"]], "displayed")
      baseline <- reads
      current[["refresh"]](target = "contacts")
      session[["flushReact"]]()
      expect_identical(reads, baseline)
      expired <- values[["token"]]
      expired@expires_at <- as.numeric(Sys.time()) - 1
      values[["token"]] <- expired
      session[["flushReact"]]()
      expect_identical(values[["connection"]](), current)
      expect_identical(values[["authenticated"]], TRUE)
      expect_identical(
        current[["access_token"]](target = "contacts"),
        "contacts-new"
      )
      expect_identical(current[["access_token"]](), "calendar-new")
      current[["refresh"]](scopes = "calendar.read")
      error <- tryCatch(
        current[["access_token"]]("calendar.write"),
        error = identity
      )
      expect_identical(error[["context"]][["reason"]], "insufficient_scope")
      values[["logout"]]()
      session[["flushReact"]]()
      error <- tryCatch(output[["contacts"]], error = identity)
      expect_s3_class(error, "shiny.silent.error")
    }
  )
})

test_that("target cleanup revokes child access tokens and one shared refresh credential", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (managed in c(FALSE, TRUE)) {
    revoked <- list()
    local_mocked_bindings(
      refresh_token_dispatch = function(client, token, target_request, ...) {
        target_test_token(
          target_request[["scopes"]],
          "contacts-child",
          "latest-refresh"
        )
      },
      revoke_token = function(client, token, token_kind, ...) {
        revoked[[length(revoked) + 1L]] <<- list(
          kind = token_kind,
          value = if (token_kind == "refresh") {
            token@refresh_token
          } else {
            token@access_token
          }
        )
        invisible(TRUE)
      }
    )
    f <- target_test_manager()
    shiny::testServer(
      if (managed) oauth_connections_server else oauth_module_server,
      args = if (managed) {
        list(id = "auth", manager = f[["manager"]])
      } else {
        list(id = "auth", client = target_test_client(), auto_redirect = FALSE)
      },
      session = manager_test_session(
        if (managed) manager_test_cookie(f) else NULL
      ),
      {
        current <- if (managed) {
          connection(manager_test_accept(
            controller,
            token = target_test_token()
          ))
        } else {
          operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
          .accept_login_token(target_test_token(), NULL)
          .finish_auth_operation(operation, "login")
          values[["connection"]]()
        }
        current[["access_token"]](target = "contacts")
        if (managed) {
          controller[["disconnect"]](current[["id"]], TRUE)
        } else {
          values[["logout"]]()
        }
        expect_setequal(
          vapply(revoked, function(item) item[["value"]], ""),
          c("calendar-initial", "contacts-child", "latest-refresh")
        )
        expect_identical(
          sum(vapply(
            revoked,
            function(item) item[["kind"]] == "refresh",
            logical(1)
          )),
          1L
        )
      }
    )
  }
})

test_that("disconnect reports incomplete child revocation in results and audit events", {
  revoke <- connection_manager_revoke
  for (action in c("disconnect", "disconnect_all")) {
    for (outcome in c("accepted", "failed", "unsupported", "not_attempted")) {
      events <- list()
      attempted <- character()
      local_options(
        shinyOAuth.audit_hook = function(event) {
          events[[length(events) + 1L]] <<- event
        },
        shinyOAuth.otel_tracing_enabled = FALSE
      )
      local_mocked_bindings(
        refresh_token_dispatch = function(client, token, target_request, ...) {
          target_test_token(
            target_request[["scopes"]],
            "contacts-child",
            "rotated"
          )
        },
        connection_manager_revoke = function(
          manager,
          client,
          token,
          deadline,
          kinds = c("refresh", "access")
        ) {
          if (identical(kinds, "access") && outcome == "not_attempted") {
            deadline <- 0
          }
          revoke(manager, client, token, deadline, kinds)
        },
        revoke_token = function(client, token, token_kind, ...) {
          value <- if (token_kind == "access") {
            token@access_token
          } else {
            token@refresh_token
          }
          attempted <<- c(attempted, value)
          if (identical(value, "contacts-child")) {
            return(list(
              supported = outcome != "unsupported",
              revoked = outcome == "accepted"
            ))
          }
          list(supported = TRUE, revoked = TRUE)
        }
      )
      f <- target_test_manager()
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "auth", manager = f[["manager"]]),
        session = manager_test_session(manager_test_cookie(f)),
        {
          auth <- session[["getReturned"]]()
          current <- connection(manager_test_accept(
            controller,
            token = target_test_token()
          ))
          current[["access_token"]](target = "contacts")
          events <<- list()
          result <- if (action == "disconnect") {
            auth[["disconnect"]](current[["id"]])
          } else {
            auth[["disconnect_all"]]()[[1L]]
          }
          expect_identical(result[["local"]], "disconnected")
          expect_identical(result[["remote"]][["refresh"]], "accepted")
          expect_identical(result[["remote"]][["access"]], outcome)
          removed <- Filter(
            function(event) event[["type"]] == "audit_connection_disconnected",
            events
          )
          expect_length(removed, 1L)
          expect_identical(removed[[1L]][["remote_access_outcome"]], outcome)
          expect_identical(
            removed[[1L]][["remote_refresh_outcome"]],
            "accepted"
          )
          expect_identical(current[["is_usable"]](), FALSE)
          expect_setequal(
            attempted,
            c(
              "rotated",
              "calendar-initial",
              if (outcome != "not_attempted") "contacts-child"
            )
          )
          encoded <- jsonlite::toJSON(events, auto_unbox = TRUE)
          expect_false(any(vapply(
            c("rotated", "calendar-initial", "contacts-child"),
            function(secret) grepl(secret, encoded, fixed = TRUE),
            logical(1)
          )))
        }
      )
    }
  }
})

test_that("retiring a child access alias removes only that target", {
  f <- target_test_manager()
  cookie <- manager_test_cookie(f)
  local_mocked_bindings(refresh_token_dispatch = function(
    client,
    token,
    target_request,
    ...
  ) {
    target_test_token(target_request[["scopes"]], "child-alias", "rotated")
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "auth", manager = f[["manager"]]),
    session = manager_test_session(cookie),
    {
      current <- connection(manager_test_accept(
        controller,
        token = target_test_token()
      ))
      current[["access_token"]](target = "contacts")
      record <- controller[["read"]](current[["id"]])
      key <- connection_credential_keys(
        f[["manager"]],
        record[["client"]],
        record[["targets"]][["tokens"]][["contacts"]]
      )[["access"]]
      connection_credential_retire(f[["manager"]], list(access = key))
      expect_identical(current[["access_token"]](), "calendar-initial")
      expect_identical(
        current[["has_scopes"]]("contacts.read", target = "contacts"),
        FALSE
      )
      expect_identical(
        current[["targets"]]()[["contacts"]][["status"]],
        "not_acquired"
      )
    }
  )
})

test_that("target acquisition crosses a real async worker with its declared policy", {
  skip_if_not_installed("webfakes")
  skip_if_not_installed("mirai")
  mirai::daemons(1)
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()
  app <- webfakes::new_app()
  app[["use"]](webfakes::mw_urlencoded())
  app[["post"]]("/token", function(req, res) {
    form <- req[["form"]]
    if (
      !identical(form[["resource"]], "https://contacts.example/") ||
        !identical(form[["scope"]], "contacts.read") ||
        !identical(form[["refresh_token"]], "refresh-0")
    ) {
      res[["set_status"]](400L)
      return(res[["send_json"]](
        list(error = "invalid_request"),
        auto_unbox = TRUE
      ))
    }
    res[["send_json"]](
      list(
        access_token = "worker-contacts",
        refresh_token = "worker-rotated",
        token_type = "Bearer",
        expires_in = 3600,
        scope = "contacts.read"
      ),
      auto_unbox = TRUE
    )
  })
  srv <- webfakes::local_app_process(app)
  client <- target_test_client(base = sub("/$", "", srv[["url"]]()))
  result <- NULL
  pending <- refresh_token_dispatch(
    client,
    target_test_token(),
    async = TRUE,
    target_request = token_target_request(client, "contacts")
  )
  promises::then(pending, function(value) result <<- value, function(error) {
    result <<- error
  })
  poll_for_async(function() !is.null(result), timeout = 30)
  expect_identical(S7::S7_inherits(result, OAuthToken), TRUE)
  expect_identical(result@access_token, "worker-contacts")
  expect_identical(result@granted_scopes, "contacts.read")
  expect_identical(result@refresh_token, "worker-rotated")
})

test_that("target grants and restored credentials retain client-required scopes", {
  client <- target_test_client()
  S7::props(client) <- list(
    scopes = c(client@scopes, "email"),
    required_scopes = "email"
  )
  request <- token_target_request(client, "contacts")
  expect_identical(request[["required_scopes"]], "email")
  error <- tryCatch(
    token_target_bundle(client, target_test_token()),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_token_error")

  primary <- target_test_token(c("calendar.read", "calendar.write", "email"))
  bundle <- token_target_bundle(client, primary)
  bundle[["tokens"]][["contacts"]] <- target_test_token(
    "contacts.read",
    "missing-required-scope",
    NA_character_
  )
  owner <- random_urlsafe(32)
  id <- random_urlsafe(32)
  key <- openssl::rand_bytes(32)
  sealed <- connection_credentials_seal(
    primary,
    owner,
    id,
    client,
    key,
    as.numeric(Sys.time()),
    targets = bundle
  )
  error <- tryCatch(
    connection_credentials_open(sealed, owner, id, client, key),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_token_error")
  selected <- token_target_select(
    list(client = client, token = primary, targets = bundle, status = "active"),
    "contacts"
  )
  expect_identical(connection_record_status(selected), "insufficient_scope")
})

test_that("queued targets and late refresh delivery respect authentication age before observers run", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  calls <- 0L
  complete <- NULL
  revoked <- character()
  local_mocked_bindings(
    refresh_token_dispatch = function(...) {
      calls <<- calls + 1L
      promises::promise(function(resolve, reject) complete <<- resolve)
    },
    revoke_token = function(client, token, token_kind, ...) {
      revoked <<- c(revoked, token@access_token)
      invisible(NULL)
    }
  )
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = target_test_client(),
      auto_redirect = FALSE,
      reauth_after_seconds = 60
    ),
    {
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(target_test_token(), NULL)
      .finish_auth_operation(operation, "login")
      current <- values[["connection"]]()
      results <- list()
      promises::then(
        current[["access_token"]](target = "contacts", async = TRUE),
        function(value) results[["first"]] <<- value,
        function(error) results[["first"]] <<- error
      )
      promises::then(
        current[["access_token"]](force_refresh = TRUE, async = TRUE),
        function(value) results[["queued"]] <<- value,
        function(error) results[["queued"]] <<- error
      )
      values[["auth_started_at"]] <- as.numeric(Sys.time()) - 61
      complete(target_test_token(
        "contacts.read",
        "late-contacts",
        "late-refresh"
      ))
      for (i in seq_len(20)) {
        later::run_now(0.01)
      }
      expect_identical(calls, 1L)
      expect_null(values[["targets"]][["tokens"]][["contacts"]])
      expect_s3_class(results[["first"]], "shinyOAuth_access_error")
      expect_s3_class(results[["queued"]], "shinyOAuth_access_error")
      expect_identical("late-contacts" %in% revoked, TRUE)
    }
  )
})

test_that("managed target replacement survives the callback JSON round trip", {
  f <- target_test_manager()
  client <- f[["manager"]][["clients"]][["a"]]
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "auth", manager = f[["manager"]]),
    session = manager_test_session(manager_test_cookie(f)),
    {
      id <- manager_test_accept(controller, token = target_test_token())
      controller[["reauthorize"]](id)
      hooks <- controller[["hooks"]]("a")
      context <- hooks[["prepare"]]()
      browser <- valid_browser_token()
      prepared <- prepare_call_internal(
        client,
        browser,
        .defer_build = TRUE,
        .transaction_context = context,
        .requested_scopes = context[["requested_scopes"]],
        .target_limits = context[["target_limits"]]
      )
      restored <- oauth_module_managed_context(
        hooks,
        client,
        prepared[["build_args"]][["payload"]],
        browser
      )
      expect_type(restored[["data"]][["target_limits"]][["calendar"]], "list")
      hooks[["accept"]](
        target_test_token(refresh = "replacement-refresh"),
        restored[["data"]],
        as.numeric(Sys.time())
      )
      replacement <- connection()
      expect_identical(replacement[["access_token"]](), "calendar-initial")
      expect_identical(
        replacement[["summary"]]()[["replaces_connection_id"]],
        id
      )
    }
  )
})

test_that("secondary acquisitions validate signed OIDC identity continuity", {
  client <- target_test_client()
  provider <- client@provider
  S7::props(provider) <- list(
    issuer = "https://issuer.example",
    id_token_validation = TRUE
  )
  S7::props(client) <- list(
    provider = provider,
    scopes = c(client@scopes, "openid")
  )
  key <- openssl::rsa_keygen()
  other_key <- openssl::rsa_keygen()
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  local_mocked_bindings(fetch_jwks = function(...) list(keys = list(jwk)))
  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    iss = provider@issuer,
    aud = client@client_id,
    sub = "alice",
    iat = now,
    exp = now + 3600,
    nonce = "original-nonce",
    auth_time = now - 30
  )
  sign <- function(claims, signing_key = key) {
    input <- paste(
      base64url_encode(charToRaw('{"alg":"RS256"}')),
      base64url_encode(charToRaw(jsonlite::toJSON(claims, auto_unbox = TRUE))),
      sep = "."
    )
    paste(
      input,
      base64url_encode(openssl::signature_create(
        charToRaw(input),
        openssl::sha256,
        signing_key
      )),
      sep = "."
    )
  }
  original <- sign(claims)
  primary <- target_test_token(c("calendar.read", "calendar.write", "openid"))
  S7::props(primary) <- list(
    id_token = original,
    original_id_token = original,
    id_token_validated = TRUE
  )
  request <- token_target_request(client, "contacts")
  source <- token_target_refresh_source(
    list(
      client = client,
      token = primary,
      targets = token_target_bundle(client, primary)
    ),
    request
  )
  response_id <- original
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(
      url = req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(
        list(
          access_token = "contacts-signed",
          refresh_token = "signed-rotation",
          token_type = "Bearer",
          expires_in = 3600,
          scope = "contacts.read openid",
          id_token = response_id
        ),
        auto_unbox = TRUE
      ))
    )
  })
  fresh <- refresh_token_dispatch(client, source, target_request = request)
  expect_identical(fresh@id_token_validated, TRUE)
  expect_identical(fresh@original_id_token, original)
  expect_identical(fresh@id_token_claims[["sub"]], "alice")
  for (change in list(
    list(sub = "bob"),
    list(iss = "https://other.example"),
    list(aud = "other-app"),
    list(nonce = "other-nonce"),
    list(auth_time = now - 10)
  )) {
    response_id <- sign(utils::modifyList(claims, change))
    error <- tryCatch(
      refresh_token_dispatch(client, source, target_request = request),
      error = identity
    )
    expect_s3_class(error, "shinyOAuth_id_token_error")
  }
  response_id <- sign(claims, other_key)
  error <- tryCatch(
    refresh_token_dispatch(client, source, target_request = request),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_id_token_error")
})

test_that("target authorization parameters survive signed requests and PAR", {
  client <- target_test_client()
  provider <- client@provider
  provider@par_url <- "https://issuer.example/par"
  S7::props(client) <- list(
    provider = provider,
    client_secret = strrep("s", 32),
    request_object_mode = "request",
    request_object_audience = "https://issuer.example"
  )
  sent <- NULL
  local_mocked_bindings(req_with_retry = function(req, ...) {
    sent <<- req
    httr2::response(
      url = req[["url"]],
      status = 201L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(
        '{"request_uri":"urn:example:par:targets","expires_in":60}'
      )
    )
  })
  browser <- valid_browser_token()
  url <- prepare_call(client, browser)
  expect_identical(
    parse_query_param(url, "request_uri", decode = TRUE),
    "urn:example:par:targets"
  )
  jwt <- utils::URLdecode(as.character(sent[["body"]][["data"]][["request"]]))
  claims <- parse_jwt_payload(jwt)
  expect_setequal(
    unlist(claims[["resource"]]),
    c("https://calendar.example/", "https://contacts.example/")
  )
  expect_setequal(normalize_scope_tokens(claims[["scope"]]), client@scopes)
  payload <- state_payload_decrypt_validate(client, claims[["state"]])
  expect_setequal(unlist(payload[["scopes"]]), client@scopes)
})

test_that("interleaved target consumers await current ownership without another acquisition", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (managed in c(FALSE, TRUE)) {
    for (outcome in c(
      "success",
      "not_consumed",
      "possibly_consumed",
      "logout"
    )) {
      calls <- 0L
      completions <- list()
      local_mocked_bindings(
        refresh_token_dispatch = function(...) {
          calls <<- calls + 1L
          i <- calls
          promises::promise(function(resolve, reject) {
            completions[[i]] <<- list(resolve = resolve, reject = reject)
          })
        },
        revoke_token = function(...) invisible(NULL)
      )
      f <- target_test_manager()
      shiny::testServer(
        if (managed) oauth_connections_server else oauth_module_server,
        args = if (managed) {
          list(id = "auth", manager = f[["manager"]])
        } else {
          list(
            id = "auth",
            client = target_test_client(),
            auto_redirect = FALSE
          )
        },
        session = manager_test_session(
          if (managed) manager_test_cookie(f) else NULL
        ),
        {
          current <- if (managed) {
            connection(manager_test_accept(
              controller,
              token = target_test_token()
            ))
          } else {
            operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
            .accept_login_token(target_test_token(), NULL)
            .finish_auth_operation(operation, "login")
            values[["connection"]]()
          }
          results <- list()
          for (which in c("first", "other", "same")) {
            local({
              label <- which
              promises::then(
                current[["access_token"]](
                  target = if (label == "other") "calendar" else "contacts",
                  force_refresh = label == "other",
                  async = TRUE
                ),
                function(value) results[[label]] <<- value,
                function(error) results[[label]] <<- error
              )
            })
          }
          completions[[1L]][["resolve"]](target_test_token(
            "contacts.read",
            "contacts-new",
            "refresh-1"
          ))
          poll_for_async(function() calls == 2L, session)
          expect_null(results[["same"]])
          if (outcome == "logout") {
            if (managed) controller[["logout"]](FALSE) else values[["logout"]]()
          }
          if (outcome %in% c("success", "logout")) {
            completions[[2L]][["resolve"]](target_test_token(
              access = "calendar-new",
              refresh = "refresh-2"
            ))
          } else {
            completions[[2L]][["reject"]](refresh_outcome_error(
              simpleError("synthetic failure"),
              outcome
            ))
          }
          poll_for_async(function() length(results) == 3L, session)
          expect_identical(calls, 2L)
          expect_identical(results[["first"]], "contacts-new")
          if (outcome %in% c("success", "not_consumed")) {
            expect_identical(results[["same"]], "contacts-new")
          } else {
            expect_s3_class(results[["same"]], "shinyOAuth_access_error")
          }
          if (outcome == "success") {
            expect_identical(results[["other"]], "calendar-new")
          } else {
            expect_s3_class(results[["other"]], "shinyOAuth_access_error")
          }
        }
      )
    }
  }
})
