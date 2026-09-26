test_that("non-OIDC and SMART replacement retain only granted offline access", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  site <- smart_client_fixture()
  site[["metadata"]][["capabilities"]] <- c(
    site[["metadata"]][["capabilities"]],
    "permission-offline"
  )
  for (smart in c(FALSE, TRUE)) {
    client <- if (smart) {
      smart_client(
        site,
        "example",
        "https://app.example/callback",
        scopes = c("launch/patient", "patient/Patient.r", "offline_access"),
        required_scopes = "patient/Patient.r"
      )
    } else {
      oauth_client(
        make_test_provider(),
        "app",
        client_secret = "",
        scopes = c("read", "offline_access"),
        redirect_uri = "https://app.example/callback",
        scope_validation = "none"
      )
    }
    for (offline in c(FALSE, TRUE)) {
      grant <- c(
        if (smart) "patient/Patient.r" else "read",
        if (offline) "offline_access"
      )
      expected <- c(grant, if (smart) "launch/patient")
      response_scopes <- grant
      local_mocked_bindings(req_with_retry = function(req, ...) {
        body <- list(
          access_token = "access",
          token_type = "Bearer",
          expires_in = 3600,
          scope = paste(response_scopes, collapse = " ")
        )
        if (offline) {
          body[["refresh_token"]] <- "refresh"
        }
        if (smart) {
          body[["patient"]] <- "123"
        }
        httr2::response(
          req[["url"]],
          status = 200L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE))
        )
      })
      browser <- valid_browser_token()
      exchange <- function(url) {
        handle_callback(
          client,
          "code",
          parse_query_param(url, "state"),
          browser
        )
      }
      url <- prepare_call(client, browser)
      for (iteration in seq_len(2L)) {
        shiny::testServer(
          oauth_module_server,
          args = list(id = "auth", client = client, auto_redirect = FALSE),
          {
            session[["flushReact"]]()
            values[["browser_token"]] <- browser
            values[[".process_query"]](paste0(
              "?code=login&state=",
              parse_query_param(url, "state")
            ))
            expect_null(values[["error"]])
            expect_setequal(values[["token"]]@granted_scopes, grant)
            expect_identical(
              is_valid_string(values[["token"]]@refresh_token),
              offline
            )
            values[["reauthorize"]]()
            values[["browser_token"]] <- browser
            url <<- .build_auth_url()
            expect_setequal(
              normalize_scope_tokens(parse_query_param(
                url,
                "scope",
                decode = TRUE
              )),
              expected
            )
          }
        )
      }
      if (!offline) {
        response_scopes <- c(grant, "offline_access")
        expect_error(exchange(url), "scope limit")
        response_scopes <- grant
      }

      fixture <- ordinary_manager_fixture(client)
      token <- exchange(prepare_call(client, browser))
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "health", manager = fixture[["manager"]]),
        session = manager_test_session(manager_test_cookie(fixture)),
        {
          id <- manager_test_accept(controller, token = token)
          for (iteration in seq_len(2L)) {
            controller[["reauthorize"]](id)
            hooks <- controller[["hooks"]]("a")
            context <- hooks[["prepare"]]()
            expect_setequal(context[["requested_scopes"]], expected)
            replacement <- exchange(prepare_call_internal(
              client,
              browser,
              .requested_scopes = context[["requested_scopes"]]
            ))
            hooks[["accept"]](replacement, context, as.numeric(Sys.time()))
            row <- Filter(
              function(row) identical(row[["replaces_connection_id"]], id),
              controller[["records"]]()
            )[[1L]]
            expect_setequal(row[["authorization_scopes"]], expected)
            expect_setequal(row[["token"]]@granted_scopes, grant)
            id <- row[["stored"]][["id"]]
          }
        }
      )
    }
  }
})
