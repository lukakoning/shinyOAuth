test_that("ordinary OIDC callbacks retain refresh consent across sessions", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- ordinary_oidc_fixture()
  client <- f[["client"]]
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
    req_with_retry = f[["request"]],
    revoke_token = function(...) invisible(NULL),
    async_dispatch = function(expr, args, ...) {
      promises::promise_resolve(eval(
        expr,
        list2env(args, parent = globalenv())
      ))
    }
  )
  browser <- valid_browser_token()
  for (async in c(FALSE, TRUE)) {
    for (mode in c("automatic", "retain", "remove")) {
      narrow <- mode == "remove"
      url <- prepare_call(client, browser)
      # The first callback has no session-local authorization history.
      for (iteration in seq_len(2L)) {
        f[["authorize"]](url)
        shiny::testServer(
          oauth_module_server,
          args = list(
            id = "auth",
            client = client,
            auto_redirect = FALSE,
            async = async
          ),
          {
            session[["flushReact"]]()
            values[["browser_token"]] <- browser
            values[[".process_query"]](paste0(
              "?code=login&state=",
              parse_query_param(url, "state")
            ))
            poll_for_async(
              function() {
                !is.null(values[["token"]]) || !is.null(values[["error"]])
              },
              session
            )
            expect_null(values[["error"]])
            expect_true(values[["token"]]@id_token_validated)
            expect_false("offline_access" %in% values[["token"]]@granted_scopes)
            expect_identical(
              is_valid_string(values[["token"]]@refresh_token),
              iteration == 1L || !narrow
            )
            current <- values[["connection"]]()
            if (iteration == 1L) {
              result <- current[["refresh"]](
                scopes = if (mode == "automatic") {
                  NULL
                } else {
                  c("openid", "read", if (!narrow) "offline_access")
                }
              )
              if (inherits(result, "promise")) {
                poll_for_async(
                  function() !values[["refresh_in_progress"]],
                  session
                )
              }
              expect_null(values[["error"]])
              expect_false(current[["has_scopes"]]("offline_access"))
              if (narrow) {
                calls <- length(f[["state"]][["requests"]])
                expect_error(current[["refresh"]](
                  scopes = c("openid", "read", "offline_access")
                ))
                expect_length(f[["state"]][["requests"]], calls)
                expect_true(current[["is_usable"]]())
              }
            }
            values[["reauthorize"]]()
            values[["browser_token"]] <- browser
            url <<- .build_auth_url()
            expect_setequal(
              normalize_scope_tokens(parse_query_param(
                url,
                "scope",
                decode = TRUE
              )),
              c("openid", "read", if (!narrow) "offline_access")
            )
          }
        )
      }
    }
  }
})

test_that("retained refresh consent does not fail strict API scope reconciliation", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- ordinary_oidc_fixture()
  client <- f[["client"]]
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
    req_with_retry = f[["request"]],
    introspect_token = function(...) {
      list(
        supported = TRUE,
        active = TRUE,
        raw = list(scope = "openid read")
      )
    },
    revoke_token = function(...) invisible(NULL)
  )
  browser <- valid_browser_token()
  url <- f[["authorize"]](prepare_call(client, browser))
  token <- handle_callback(
    client,
    "code",
    parse_query_param(url, "state"),
    browser
  )
  client@scope_validation <- "strict"
  client@provider@introspection_url <- "https://issuer.example/introspect"
  for (introspect in c(FALSE, TRUE)) {
    S7::props(client) <- list(
      introspect = introspect,
      introspection_checks = if (introspect) "scope" else character()
    )
    shiny::testServer(
      oauth_module_server,
      args = list(id = "auth", client = client, auto_redirect = FALSE),
      {
        .accept_login_token(token, NULL)
        current <- values[["connection"]]()
        expect_true(current[["refresh"]](
          scopes = c("openid", "read", "offline_access")
        ))
        expect_true(current[["has_scopes"]]("read"))
        expect_false(current[["has_scopes"]]("offline_access"))
        expect_false(current[["has_scopes"]]("write"))
        expect_setequal(
          auth_operations[["last_authorized_scopes"]],
          c("openid", "read", "offline_access")
        )
      }
    )
  }
})

test_that("single-module refresh failure preserves authorization consent", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- ordinary_oidc_fixture()[["client"]]
  local_mocked_bindings(refresh_token = function(...) {
    stop("synthetic transport interruption")
  })
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      session[["flushReact"]]()
      token <- manager_test_token()
      token@granted_scopes <- c("openid", "read")
      .accept_login_token(token, NULL)
      expect_error(values[["connection"]]()[["refresh"]]())
      expect_null(values[["token"]])
      values[["reauthorize"]]()
      values[["browser_token"]] <- "__SKIPPED__"
      expect_setequal(
        normalize_scope_tokens(parse_query_param(
          .build_auth_url(),
          "scope",
          decode = TRUE
        )),
        c("openid", "read", "offline_access")
      )
    }
  )
})

test_that("stored consent policy is authenticated and legacy grants stay bounded", {
  client <- ordinary_oidc_fixture()[["client"]]
  token <- manager_test_token()
  token@granted_scopes <- c("openid", "read")
  key <- openssl::rand_bytes(32L)
  owner <- strrep("a", 32L)
  id <- strrep("b", 32L)
  for (consent in list(NULL, character(), "offline_access")) {
    policy <- if (is.null(consent)) {
      NULL
    } else {
      union(token@granted_scopes, consent)
    }
    sealed <- connection_credentials_seal(
      token,
      owner,
      id,
      client,
      key,
      1000,
      authorization_scopes = policy
    )
    restored <- connection_credentials_open(sealed, owner, id, client, key)
    expect_identical(
      restored[["authorization_scopes"]],
      policy %||% token@granted_scopes
    )
    expect_identical(restored[["token"]]@granted_scopes, token@granted_scopes)
    expect_error(
      connection_credentials_open(paste0("x", sealed), owner, id, client, key),
      "unavailable or incompatible"
    )
  }
  for (invalid in list(
    c("openid", "read", "write"),
    c("openid", "read", NA_character_),
    list("openid", "read"),
    c("openid", "read", "read")
  )) {
    sealed <- connection_credentials_seal(
      token,
      owner,
      id,
      client,
      key,
      1000,
      authorization_scopes = invalid
    )
    expect_error(
      connection_credentials_open(sealed, owner, id, client, key),
      "unavailable or incompatible"
    )
  }
})

test_that("managed consent survives storage, refresh, and uncertain credentials", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- ordinary_oidc_fixture()
  client <- f[["client"]]
  fail <- FALSE
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
    req_with_retry = function(...) {
      if (fail) {
        stop("synthetic transport interruption")
      }
      f[["request"]](...)
    },
    revoke_token = function(...) invisible(NULL)
  )
  browser <- valid_browser_token()
  exchange <- function(url) {
    f[["authorize"]](url)
    handle_callback(client, "code", parse_query_param(url, "state"), browser)
  }
  for (mode in c("automatic", "retain", "remove")) {
    narrow <- mode == "remove"
    for (uncertain in c(FALSE, TRUE)) {
      fixture <- ordinary_manager_fixture(client)
      cookie <- manager_test_cookie(fixture)
      token <- exchange(prepare_call(client, browser))
      connection_id <- NULL
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "health", manager = fixture[["manager"]]),
        session = manager_test_session(cookie),
        {
          connection_id <<- manager_test_accept(controller, token = token)
          expect_true(connection(connection_id)[["refresh"]](
            scopes = if (mode == "automatic") {
              NULL
            } else {
              c("openid", "read", if (!narrow) "offline_access")
            }
          ))
        }
      )
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "health", manager = fixture[["manager"]]),
        session = manager_test_session(cookie),
        {
          current <- connection(connection_id)
          expect_true(current[["is_usable"]]())
          expect_false(current[["has_scopes"]]("offline_access"))
          if (narrow) {
            calls <- length(f[["state"]][["requests"]])
            expect_error(current[["refresh"]](
              scopes = c("openid", "read", "offline_access")
            ))
            expect_length(f[["state"]][["requests"]], calls)
            expect_true(current[["is_usable"]]())
          }
          if (uncertain) {
            fail <<- TRUE
            expect_error(current[["refresh"]]())
            fail <<- FALSE
            expect_identical(current[["summary"]]()[["status"]], "uncertain")
          } else {
            expect_true(current[["refresh"]]())
          }
          controller[["reauthorize"]](connection_id)
          hooks <- controller[["hooks"]]("a")
          context <- hooks[["prepare"]]()
          expect_setequal(
            context[["requested_scopes"]],
            c("openid", "read", if (!narrow) "offline_access")
          )
          replacement <- exchange(prepare_call_internal(
            client,
            browser,
            .requested_scopes = context[["requested_scopes"]]
          ))
          expect_true(replacement@id_token_validated)
          expect_identical(is_valid_string(replacement@refresh_token), !narrow)
          hooks[["accept"]](replacement, context, as.numeric(Sys.time()))
          row <- Filter(
            function(row) !is.null(row[["token"]]),
            controller[["records"]]()
          )[[1L]]
          expect_setequal(
            row[["authorization_scopes"]],
            c("openid", "read", if (!narrow) "offline_access")
          )
          controller[["reauthorize"]](row[["stored"]][["id"]])
          expect_setequal(
            hooks[["prepare"]]()[["requested_scopes"]],
            c("openid", "read", if (!narrow) "offline_access")
          )
        }
      )
    }
  }
})
