for (post in c(FALSE, TRUE)) {
  for (denied in c(FALSE, TRUE)) {
    test_that(
      paste("Strict callback documents defer owner checks", post, denied),
      {
        clients <- manager_test_fixture()[["manager"]][["clients"]]
        for (id in names(clients)) {
          clients[[id]]@response_mode <- if (post) "form_post" else "query"
        }
        manager <- oauth_connections(
          clients,
          "https://app.example",
          retention = "browser",
          owner_policy = oauth_browser_owner(same_site = "Strict"),
          store = oauth_connection_store_memory(),
          keys = list(
            credentials = openssl::rand_bytes(32),
            owner = openssl::rand_bytes(32)
          )
        )
        ui <- oauth_connections_ui(
          shiny::fluidPage("Application content"),
          "health",
          manager
        )
        cookie <- manager_test_cookie(list(ui = ui))
        owner <- manager[["state"]][["owners"]][["resolve"]](sub(
          "^[^=]+=",
          "",
          cookie
        ))
        session <- manager_test_session(cookie)
        withr::defer(session[["close"]]())
        shiny::withReactiveDomain(
          session,
          shiny::isolate({
            ctl <- connection_manager_controller(manager, session)
            client <- clients[["a"]]
            prepared <- prepare_call_internal(
              client,
              valid_browser_token(),
              .defer_build = TRUE,
              .transaction_context = ctl[["hooks"]]("a")[["prepare"]]()
            )
            fields <- if (denied) {
              list(error = "access_denied")
            } else {
              list(code = "synthetic-code")
            }
            fields[["state"]] <- prepared[["build_args"]][["payload"]]
            state <- state_payload_decrypt_validate(client, fields[["state"]])[[
              "state"
            ]]
            encoded <- httr2::url_query_build(fields)
            req <- manager_test_request(
              method = if (post) "POST" else "GET",
              path = "/callback/a",
              query = if (post) "" else encoded
            )
            if (post) {
              req[["CONTENT_TYPE"]] <- "application/x-www-form-urlencoded"
              req[["rook.input"]] <- list(read = function(n) charToRaw(encoded))
            }
            response <- ui(req)
            expect_identical(response[["status"]], 200L)
            expect_null(response[["headers"]][["Location"]])
            expect_null(response[["headers"]][["Set-Cookie"]])
            expect_identical(
              response[["headers"]][["Cache-Control"]],
              "no-store"
            )
            expect_identical(
              response[["headers"]][["Referrer-Policy"]],
              "no-referrer"
            )
            expect_match(
              response[["headers"]][["Content-Security-Policy"]],
              "default-src 'none'",
              fixed = TRUE
            )
            expect_match(
              response[["content"]],
              '<meta http-equiv="refresh"',
              fixed = TRUE
            )
            expect_false(grepl(
              "synthetic-code|access_denied|Application content|<script",
              response[["content"]]
            ))
            expect_false(grepl(
              fields[["state"]],
              response[["content"]],
              fixed = TRUE
            ))
            location <- sub(
              '.*<a href="([^"]+)".*',
              "\\1",
              response[["content"]]
            )
            location <- gsub("&amp;", "&", location, fixed = TRUE)
            expect_true(startsWith(location, "https://app.example/callback/a?"))
            continuation <- manager_test_request(
              cookie,
              path = "/callback/a",
              query = url_raw_query(location)
            )
            expect_equal(ui(continuation)[["status"]], 200L)
            expect_length(ctl[["records"]](), 0L)
            expect_no_error(state_store_get(client, state))
            continuation[["HTTP_COOKIE"]] <- NULL
            expect_identical(ui(continuation)[["status"]], 400L)
            expect_null(ui(continuation)[["headers"]][["Set-Cookie"]])
            expect_true(manager[["state"]][["owners"]][["revoke"]](owner))
            continuation[["HTTP_COOKIE"]] <- cookie
            expect_identical(ui(continuation)[["status"]], 400L)
            expect_no_error(state_store_get(client, state))
          })
        )
        invalid <- ui(manager_test_request(
          path = "/callback/a",
          query = "code=invalid&state=invalid"
        ))
        expect_identical(invalid[["status"]], 400L)
        expect_false(grepl(
          'http-equiv="refresh"',
          invalid[["content"]],
          fixed = TRUE
        ))
      }
    )
  }
}
