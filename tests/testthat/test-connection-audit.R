for (action in c("disconnect", "disconnect_all")) {
  for (outcome in c("not_requested", "accepted", "failed")) {
    test_that(
      paste(
        "public",
        action,
        "audits local removal and",
        outcome,
        "revocation"
      ),
      {
        events <- list()
        logs <- list()
        local_options(
          shinyOAuth.audit_digest_key = charToRaw(strrep("k", 32)),
          shinyOAuth.audit_hook = function(event) {
            events[[length(events) + 1L]] <<- event
          },
          shinyOAuth.otel_tracing_enabled = FALSE
        )
        local_mocked_bindings(
          revoke_token = function(...) {
            if (outcome == "failed") {
              stop("private-provider-message")
            }
            list(supported = TRUE, revoked = TRUE)
          },
          otel_emit_log = function(event) {
            logs[[length(logs) + 1L]] <<- otel_event_attributes(event)
          }
        )
        fixture <- manager_test_fixture()
        shiny::testServer(
          oauth_connections_server,
          args = list(id = "health", manager = fixture[["manager"]]),
          session = manager_test_session(manager_test_cookie(fixture)),
          {
            health <- session[["getReturned"]]()
            ids <- manager_test_accept(controller, "a")
            if (action == "disconnect_all") {
              ids <- c(ids, manager_test_accept(controller, "b"))
            }
            session[["flushReact"]]()
            events <<- list()
            logs <<- list()
            revoke <- outcome != "not_requested"
            result <- if (action == "disconnect") {
              health[["disconnect"]](ids[[1L]], revoke)
            } else {
              health[["disconnect_all"]](revoke)
            }
            session[["flushReact"]]()
            removed <- Filter(
              function(x) x[["type"]] == "audit_connection_disconnected",
              events
            )
            expect_length(removed, length(ids))
            expect_setequal(
              vapply(removed, `[[`, "", "connection_id_digest"),
              vapply(ids, string_digest, "")
            )
            for (event in removed) {
              expect_identical(event[["local_outcome"]], "disconnected")
              expect_identical(event[["reason"]], action)
              expect_identical(event[["remote_refresh_outcome"]], outcome)
              expect_identical(event[["remote_access_outcome"]], outcome)
              expect_match(event[["owner_digest"]], "^[0-9a-f]{64}$")
            }
            exported <- Filter(
              function(x) x[["event.type"]] == "audit_connection_disconnected",
              logs
            )
            expect_length(exported, length(ids))
            expect_identical(
              exported[[1L]][["connection_id_digest"]],
              removed[[1L]][["connection_id_digest"]]
            )
            expect_identical(exported[[1L]][["remote_access_outcome"]], outcome)
            encoded <- jsonlite::toJSON(list(events, logs), auto_unbox = TRUE)
            for (private in c(
              ids,
              "synthetic-access",
              "synthetic-refresh",
              "synthetic-patient",
              "private-provider-message"
            )) {
              expect_false(grepl(private, encoded, fixed = TRUE))
            }
            if (action == "disconnect_all") {
              batch <- Filter(
                function(x) x[["type"]] == "audit_connections_disconnected",
                events
              )
              expect_length(batch, 1L)
              expect_equal(batch[[1L]][["connection_count"]], length(ids))
              expect_identical(
                batch[[1L]][["trace_id"]],
                removed[[1L]][["trace_id"]]
              )
              events <<- list()
              health[["disconnect_all"]](FALSE)
              expect_length(
                Filter(
                  function(x) x[["type"]] == "audit_connection_disconnected",
                  events
                ),
                0L
              )
              expect_equal(events[[1L]][["connection_count"]], 0L)
            } else {
              events <<- list()
              expect_identical(
                health[["disconnect"]](ids[[1L]], FALSE)[["local"]],
                "disconnected"
              )
              expect_length(
                Filter(
                  function(x) x[["type"]] == "audit_connection_disconnected",
                  events
                ),
                0L
              )
            }
          }
        )
      }
    )
  }
}

for (reason in c("logout", "session_end")) {
  test_that(
    paste(
      "connection cleanup audits",
      reason,
      "without duplicate removal events"
    ),
    {
      events <- list()
      local_options(
        shinyOAuth.audit_hook = function(event) {
          events[[length(events) + 1L]] <<- event
        },
        shinyOAuth.otel_tracing_enabled = FALSE,
        shinyOAuth.otel_logging_enabled = FALSE
      )
      fixture <- manager_test_fixture(retention = "shiny")
      shiny::testServer(
        function(input, output, session) {
          controller <- connection_manager_controller(
            fixture[["manager"]],
            session
          )
        },
        session = manager_test_session(),
        {
          manager_test_accept(controller)
          events <<- list()
          if (reason == "logout") {
            controller[["logout"]](FALSE)
          } else {
            controller[["end"]]()
          }
          removed <- Filter(
            function(x) x[["type"]] == "audit_connection_disconnected",
            events
          )
          expect_length(removed, 1L)
          expect_identical(removed[[1L]][["reason"]], reason)
          expect_identical(
            removed[[1L]][["remote_access_outcome"]],
            "not_requested"
          )
          controller[["end"]]()
          expect_length(
            Filter(
              function(x) x[["type"]] == "audit_connection_disconnected",
              events
            ),
            1L
          )
        }
      )
    }
  )
}
