test_that("ordinary replacement retains prior scope evidence without requesting it", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- ordinary_oidc_fixture()
  browser <- valid_browser_token()
  for (async in c(FALSE, TRUE)) {
    for (evidence in c("token", "introspection")) {
      client <- f[["client"]]
      if (evidence == "introspection") {
        client@provider@introspection_url <- "https://issuer.example/introspect"
        client@introspect <- TRUE
        client@introspection_checks <- "scope"
      }
      observed_extra <- "prior.write"
      f[["state"]][["extra"]] <- if (evidence == "token") {
        observed_extra
      } else {
        character()
      }
      local_mocked_bindings(
        fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
        req_with_retry = f[["request"]],
        revoke_token = function(...) invisible(NULL),
        introspect_token = function(...) {
          list(
            supported = TRUE,
            active = TRUE,
            status = "ok",
            raw = list(
              active = TRUE,
              scope = paste(c("openid", "read", observed_extra), collapse = " ")
            )
          )
        },
        async_dispatch = function(expr, args, ...) {
          promises::promise_resolve(eval(
            expr,
            list2env(args, parent = globalenv())
          ))
        }
      )
      url <- prepare_call(client, browser)
      f[["authorize"]](url)
      initial <- handle_callback(
        client,
        "initial",
        parse_query_param(url, "state"),
        browser
      )
      expect_true("prior.write" %in% initial@granted_scopes)
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          session[["flushReact"]]()
          .accept_login_token(initial, NULL)
          values[["reauthorize"]]()
          values[["browser_token"]] <- browser
          url <<- .build_auth_url()
          expect_setequal(
            normalize_scope_tokens(parse_query_param(
              url,
              "scope",
              decode = TRUE
            )),
            c("openid", "read", "offline_access")
          )
        }
      )
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
            "?code=replacement&state=",
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
          expect_true("prior.write" %in% values[["token"]]@granted_scopes)
          current <- values[["connection"]]()
          expect_true(current[["has_scopes"]]("read"))
          expect_false(current[["has_scopes"]]("prior.write"))
          expect_false(current[["has_scopes"]]("write"))
          expect_error(
            current[["access_token"]](required_scopes = "prior.write"),
            "client's requested scopes"
          )
          await_refresh <- function() {
            result <- tryCatch(current[["refresh"]](), error = identity)
            if (inherits(result, "promise")) {
              settled <- NULL
              promises::then(
                result,
                function(value) settled <<- value,
                function(error) settled <<- error
              )
              poll_for_async(function() !is.null(settled), session)
              result <- settled
            }
            result
          }
          expect_true(await_refresh())
          expect_true("prior.write" %in% values[["token"]]@granted_scopes)
          request <- tail(f[["state"]][["requests"]], 1L)[[1L]]
          expect_setequal(
            normalize_scope_tokens(request[["scope"]]),
            c("openid", "read")
          )
          # Even provider evidence in introspection cannot restore configured
          # permissions omitted from the sealed replacement request.
          observed_extra <<- c("prior.write", "write")
          if (evidence == "token") {
            f[["state"]][["extra"]] <- observed_extra
          }
          expect_s3_class(await_refresh(), "shinyOAuth_access_error")
          expect_null(values[["token"]])
          expect_false(current[["has_scopes"]]("write"))
        }
      )
    }
  }
})

test_that("replacement callbacks reject new extras and restored configured rights", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- ordinary_oidc_fixture()
  client <- f[["client"]]
  browser <- valid_browser_token()
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
    req_with_retry = f[["request"]]
  )
  for (extra in c("prior.write", "new.admin", "write")) {
    url <- prepare_call_internal(
      client,
      browser,
      .requested_scopes = c("openid", "read", "offline_access"),
      .accepted_extra_scopes = "prior.write"
    )
    f[["authorize"]](url)
    f[["state"]][["extra"]] <- extra
    result <- tryCatch(
      handle_callback(client, "code", parse_query_param(url, "state"), browser),
      error = identity
    )
    if (extra == "prior.write") {
      expect_s7_class(result, OAuthToken)
      expect_true(result@id_token_validated)
    } else {
      expect_s3_class(result, "shinyOAuth_token_error")
    }
  }
})

test_that("managed replacement keeps extra evidence after restoration and uncertainty", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- ordinary_oidc_fixture()
  client <- f[["client"]]
  browser <- valid_browser_token()
  fail <- FALSE
  f[["state"]][["extra"]] <- "prior.write"
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
  exchange <- function(url) {
    f[["authorize"]](url)
    handle_callback(client, "code", parse_query_param(url, "state"), browser)
  }
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
      }
    )
    # Force reconstruction from the encrypted record in the next session.
    metadata <- fixture[["manager"]][["state"]][["authorization_metadata"]]
    rm(list = ls(metadata), envir = metadata)
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = fixture[["manager"]]),
      session = manager_test_session(cookie),
      {
        current <- connection(connection_id)
        expect_true(current[["is_usable"]]())
        expect_false(current[["has_scopes"]]("prior.write"))
        if (uncertain) {
          fail <<- TRUE
          expect_error(current[["refresh"]]())
          fail <<- FALSE
          expect_identical(current[["summary"]]()[["status"]], "uncertain")
        }
        controller[["reauthorize"]](connection_id)
        hooks <- controller[["hooks"]]("a")
        context <- hooks[["prepare"]]()
        expect_setequal(
          context[["requested_scopes"]],
          c("openid", "read", "offline_access")
        )
        expect_identical(context[["accepted_extra_scopes"]], "prior.write")
        forged <- context
        forged[["accepted_extra_scopes"]] <- "write"
        expect_false(hooks[["validate"]](forged))
        replacement <- exchange(prepare_call_internal(
          client,
          browser,
          .requested_scopes = context[["requested_scopes"]],
          .accepted_extra_scopes = context[["accepted_extra_scopes"]]
        ))
        hooks[["accept"]](replacement, context, as.numeric(Sys.time()))
        row <- Filter(
          function(row) !is.null(row[["token"]]),
          controller[["records"]]()
        )[[1L]]
        expect_true("prior.write" %in% row[["token"]]@granted_scopes)
        expect_false("prior.write" %in% row[["authorization_scopes"]])
        current <- connection(row[["stored"]][["id"]])
        expect_true(current[["refresh"]]())
        expect_false(current[["has_scopes"]]("prior.write"))
        # Explicit refresh narrowing still rejects a physically broader token.
        expect_error(current[["refresh"]](scopes = c("openid", "read")))
      }
    )
  }
})

test_that("extra scope evidence is bounded and cannot bypass scope restrictions", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
  for (extra in list(
    "write",
    rep("x", 129L),
    strrep("x", 8193L),
    NA_character_
  )) {
    # Distinct names exercise the count bound rather than normalization.
    if (length(extra) == 129L) {
      extra <- paste0(extra, seq_along(extra))
    }
    expect_error(prepare_call_internal(
      client,
      "__SKIPPED__",
      .requested_scopes = "read",
      .accepted_extra_scopes = extra
    ))
  }
  expect_error(
    prepare_call_internal(
      client,
      "__SKIPPED__",
      .accepted_extra_scopes = "prior.write"
    ),
    "requires a reauthorization"
  )
  prepared <- prepare_call_internal(
    client,
    "__SKIPPED__",
    .defer_build = TRUE,
    .requested_scopes = "read",
    .accepted_extra_scopes = "prior.write"
  )
  payload <- state_payload_decrypt_validate(
    client,
    prepared[["build_args"]][["payload"]]
  )
  payload[["accepted_extra_scopes"]] <- connection_data_encode("write")
  expect_error(
    payload_verify_client_binding(client, payload),
    "Invalid extra scope evidence"
  )
  token <- manager_test_token()
  expect_error(
    refresh_scope_request(
      client,
      token,
      "read",
      accepted_extra_scopes = "prior.write"
    ),
    "accepted in the current grant"
  )
  token@granted_scopes <- c("read", "prior.write")
  request <- refresh_scope_request(
    client,
    token,
    "read",
    accepted_extra_scopes = "prior.write"
  )
  expect_identical(
    validate_refresh_scope_request(client, token, request),
    request
  )
  expect_error(
    validate_refresh_scope_grant(client, c("read", "new.admin"), request),
    "exceeds"
  )
  request[["accepted_extra_scopes"]] <- "write"
  expect_error(
    validate_refresh_scope_request(client, token, request),
    "extra scope limit"
  )
})

test_that("ordinary extra scope policy crosses real callback and refresh workers", {
  skip_on_cran()
  skip_if_not_installed("mirai")
  skip_if_not_installed("webfakes")
  local_options(shinyOAuth.skip_browser_token = TRUE)
  mirai::daemons(1)
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()
  app <- webfakes::new_app()
  app[["use"]](webfakes::mw_urlencoded())
  app[["post"]]("/token", function(req, res) {
    body <- req[["form"]]
    if (
      identical(body[["grant_type"]], "refresh_token") &&
        !identical(body[["scope"]], "read")
    ) {
      return(res[["set_status"]](400L)[["send_json"]](list(
        error = "invalid_scope"
      )))
    }
    res[["send_json"]](
      list(
        access_token = "worker-access",
        refresh_token = "worker-refresh",
        token_type = "Bearer",
        expires_in = 3600,
        scope = if (identical(body[["code"]], "bad")) {
          "read new.admin"
        } else {
          "read prior.write"
        }
      ),
      auto_unbox = TRUE
    )
  })
  server <- webfakes::local_app_process(app)
  provider <- make_test_provider()
  provider@auth_url <- server[["url"]]("/auth")
  provider@token_url <- server[["url"]]("/token")
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("read", "write")
  )
  for (code in c("good", "bad")) {
    url <- prepare_call_internal(
      client,
      "__SKIPPED__",
      .requested_scopes = "read",
      .accepted_extra_scopes = "prior.write"
    )
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = client,
        auto_redirect = FALSE,
        async = TRUE
      ),
      {
        session[["flushReact"]]()
        values[[".process_query"]](paste0(
          "?code=",
          code,
          "&state=",
          parse_query_param(url, "state")
        ))
        poll_for_async(
          function() !is.null(values[["token"]]) || !is.null(values[["error"]]),
          session,
          timeout = 15
        )
        if (code == "bad") {
          expect_null(values[["token"]])
          expect_false(is.null(values[["error"]]))
        } else {
          expect_null(values[["error"]], info = values[["error_description"]])
          expect_setequal(
            values[["token"]]@granted_scopes,
            c("read", "prior.write")
          )
          settled <- NULL
          promises::then(
            values[["connection"]]()[["refresh"]](),
            function(value) settled <<- value,
            function(error) settled <<- error
          )
          poll_for_async(function() !is.null(settled), session, timeout = 15)
          expect_true(settled)
          expect_setequal(
            values[["token"]]@granted_scopes,
            c("read", "prior.write")
          )
          expect_false(values[["connection"]]()[["has_scopes"]]("prior.write"))
        }
      }
    )
  }
})
