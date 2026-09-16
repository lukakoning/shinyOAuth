for (base in c("/", "/app/")) {
  test_that(paste("EHR routes cannot intercept ordinary callbacks", base), {
    redirects <- paste0(
      "https://app.example",
      base,
      c("login/callback", "fhir/callback")
    )
    login <- oauth_client(
      oauth_provider(
        name = "Login",
        issuer = "https://login.example",
        infer_oidc_from_issuer = FALSE,
        auth_url = "https://login.example/authorize",
        token_url = "https://login.example/token",
        token_auth_style = "public"
      ),
      "login",
      redirect_uri = redirects[[1L]],
      authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = redirects
    )
    fhir <- smart_client(
      smart_client_fixture(),
      "fhir",
      redirects[[2L]],
      scopes = "user/Patient.r",
      launch = "ehr",
      authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = redirects
    )
    manager <- oauth_connections(
      list(fhir = fhir),
      "https://app.example",
      retention = "browser",
      owner_policy = oauth_browser_owner(),
      store = oauth_connection_store_memory(),
      keys = list(
        credentials = openssl::rand_bytes(32),
        owner = openssl::rand_bytes(32)
      )
    )
    for (path in paste0(
      base,
      c("login/callback", "login/%63allback", "fhir/callback")
    )) {
      expect_error(
        oauth_connections_ui(
          shiny::fluidPage("App"),
          "health",
          manager,
          app_base_path = base,
          additional_clients = list(login = login),
          launch_routes = list(smart_launch_route(path, "fhir"))
        ),
        "distinct from callbacks"
      )
    }
    ui <- oauth_connections_ui(
      shiny::fluidPage("App"),
      "health",
      manager,
      app_base_path = base,
      additional_clients = list(login = login),
      launch_routes = list(smart_launch_route(paste0(base, "launch"), "fhir"))
    )
    prepared <- prepare_call_internal(
      login,
      valid_browser_token(),
      .defer_build = TRUE
    )
    query <- httr2::url_query_build(list(
      code = "synthetic-code",
      state = prepared[["build_args"]][["payload"]]
    ))
    callback <- ui(manager_test_request(
      path = paste0(base, "login/callback"),
      query = query
    ))
    expect_identical(callback[["status"]], 303L)
    expect_identical(
      parse_query_param(
        callback[["headers"]][["Location"]],
        oauth_form_post_id_param,
        decode = TRUE
      ),
      "login"
    )
    expect_false(client_uses_smart(login))
  })
}

for (post in c(FALSE, TRUE)) {
  test_that(paste("one wrapper bridges ordinary OIDC and SMART", post), {
    redirects <- c(
      "https://app.example/login/callback",
      "https://app.example/fhir/callback"
    )
    mode <- if (post) "form_post" else "query"
    login <- oauth_client(
      oauth_provider(
        name = "Login",
        issuer = "https://login.example",
        auth_url = "https://login.example/authorize",
        token_url = "https://login.example/token",
        token_auth_style = "public"
      ),
      "login",
      redirect_uri = redirects[[1L]],
      scopes = "openid",
      response_mode = mode,
      authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = redirects
    )
    fhir <- smart_client(
      smart_client_fixture(),
      "fhir",
      redirects[[2L]],
      scopes = "user/Patient.r",
      response_mode = mode,
      authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = redirects
    )
    manager <- oauth_connections(list(fhir = fhir), "https://app.example")
    rendered <- 0L
    ui <- oauth_connections_ui(
      function(req) {
        rendered <<- rendered + 1L
        shiny::fluidPage("App")
      },
      "health",
      manager,
      additional_clients = list(login = login)
    )
    session <- manager_test_session()
    on.exit(session[["close"]](), add = TRUE)
    shiny::withReactiveDomain(
      session,
      shiny::isolate({
        controller <- connection_manager_controller(manager, session)
        context <- controller[["hooks"]]("fhir")[["prepare"]]()
        browser <- valid_browser_token()
        for (id in c("login", "health-fhir")) {
          client <- if (id == "login") login else fhir
          prepared <- prepare_call_internal(
            client,
            browser,
            .defer_build = TRUE,
            .transaction_context = if (id == "login") NULL else context
          )
          fields <- list(
            code = "synthetic-code",
            state = prepared[["build_args"]][["payload"]]
          )
          if (id == "login") {
            fields[["iss"]] <- login@provider@issuer
          }
          encoded <- httr2::url_query_build(fields)
          req <- manager_test_request(
            method = if (post) "POST" else "GET",
            path = httr2::url_parse(client@redirect_uri)[["path"]],
            query = if (post) "" else encoded
          )
          if (post) {
            req[["CONTENT_TYPE"]] <- "application/x-www-form-urlencoded"
            req[["rook.input"]] <- list(read = function(n) charToRaw(encoded))
          }
          response <- ui(req)
          expect_identical(response[["status"]], 303L)
          expect_identical(rendered, 0L)
          expect_identical(
            parse_query_param(
              response[["headers"]][["Location"]],
              oauth_form_post_id_param,
              decode = TRUE
            ),
            id
          )
          expect_no_error(state_store_get(
            client,
            state_payload_decrypt_validate(client, fields[["state"]])[["state"]]
          ))
          # The HTTP bridge does not consume the login or import a managed grant.
          expect_length(controller[["records"]](), 0L)
        }
        expect_identical(login@resource_bases, character())
        expect_false(client_uses_smart(login))
        expect_error(
          oauth_connections_ui(
            shiny::fluidPage(),
            "health",
            manager,
            additional_clients = list(login = fhir)
          ),
          "distinct from managed"
        )
      })
    )
  })
}

for (post in c(FALSE, TRUE)) {
  test_that(
    paste("ordinary continuations survive a retired browser owner", post),
    {
      redirects <- c(
        "https://app.example/login/callback",
        "https://app.example/fhir/callback"
      )
      mode <- if (post) "form_post" else "query"
      login <- oauth_client(
        oauth_provider(
          name = "Login",
          issuer = "https://login.example",
          infer_oidc_from_issuer = FALSE,
          auth_url = "https://login.example/authorize",
          token_url = "https://login.example/token",
          token_auth_style = "public"
        ),
        "login",
        redirect_uri = redirects[[1L]],
        response_mode = mode,
        authorization_server_mode = "multi_redirect_uri",
        authorization_server_redirect_uris = redirects
      )
      fhir <- smart_client(
        smart_client_fixture(),
        "fhir",
        redirects[[2L]],
        scopes = "user/Patient.r",
        response_mode = mode,
        authorization_server_mode = "multi_redirect_uri",
        authorization_server_redirect_uris = redirects
      )
      manager <- oauth_connections(
        list(fhir = fhir),
        "https://app.example",
        retention = "browser",
        owner_policy = oauth_browser_owner(),
        store = oauth_connection_store_memory(),
        keys = list(
          credentials = openssl::rand_bytes(32),
          owner = openssl::rand_bytes(32)
        )
      )
      ui <- oauth_connections_ui(
        shiny::fluidPage("App"),
        "health",
        manager,
        additional_clients = list(login = login)
      )
      cookie <- manager_test_cookie(list(ui = ui))
      owner <- manager[["state"]][["owners"]][["resolve"]](sub(
        "^[^=]+=",
        "",
        cookie
      ))
      session <- manager_test_session(cookie)
      on.exit(session[["close"]](), add = TRUE)
      browser <- valid_browser_token()
      continuations <- list()
      shiny::withReactiveDomain(
        session,
        shiny::isolate({
          controller <- connection_manager_controller(manager, session)
          for (id in c("login", "health-fhir")) {
            client <- if (id == "login") login else fhir
            prepared <- prepare_call_internal(
              client,
              browser,
              .defer_build = TRUE,
              .transaction_context = if (id == "login") {
                NULL
              } else {
                controller[["hooks"]]("fhir")[["prepare"]]()
              }
            )
            encoded <- httr2::url_query_build(list(
              code = "synthetic-code",
              state = prepared[["build_args"]][["payload"]]
            ))
            req <- manager_test_request(
              cookie,
              method = if (post) "POST" else "GET",
              path = httr2::url_parse(client@redirect_uri)[["path"]],
              query = if (post) "" else encoded
            )
            if (post) {
              req[["CONTENT_TYPE"]] <- "application/x-www-form-urlencoded"
              req[["rook.input"]] <- list(read = function(n) charToRaw(encoded))
            }
            response <- ui(req)
            expect_identical(response[["status"]], 303L)
            continuations[[id]] <- sub(
              "^.*[?]",
              "",
              response[["headers"]][["Location"]]
            )
          }
        })
      )
      expect_true(manager[["state"]][["owners"]][["revoke"]](owner))
      for (sent_cookie in list(cookie, NULL)) {
        ordinary <- ui(manager_test_request(
          sent_cookie,
          path = "/login/callback",
          query = continuations[["login"]]
        ))
        expect_equal(ordinary[["status"]], 200L)
        expect_match(ordinary[["headers"]][["Set-Cookie"]], "HttpOnly")
        expect_identical(
          ui(manager_test_request(
            sent_cookie,
            path = "/fhir/callback",
            query = continuations[["health-fhir"]]
          ))[["status"]],
          400L
        )
      }
      # Module names and routes alone cannot exempt a forged/stale managed handle.
      forged <- sub(
        "health-fhir",
        "login",
        continuations[["health-fhir"]],
        fixed = TRUE
      )
      expect_identical(
        ui(manager_test_request(
          cookie,
          path = "/login/callback",
          query = forged
        ))[["status"]],
        400L
      )
      expect_identical(
        ui(manager_test_request(
          cookie,
          path = "/fhir/callback",
          query = continuations[["login"]]
        ))[["status"]],
        400L
      )
      handle <- parse_query_param(
        paste0("?", continuations[["login"]]),
        oauth_form_post_handle_param,
        decode = TRUE
      )
      payload <- oauth_form_post_store_take(login, "login", handle)
      expect_identical(payload[["code"]], "synthetic-code")
      state <- state_payload_decrypt_validate(login, payload[["state"]])
      expect_no_error(state_store_get(login, state[["state"]]))
      expect_identical(
        ui(manager_test_request(
          cookie,
          path = "/login/callback",
          query = continuations[["login"]]
        ))[["status"]],
        400L
      )
    }
  )
}
