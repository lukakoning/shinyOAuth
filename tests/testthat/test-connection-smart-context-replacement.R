test_that("SMART replacements retain context policy and acquire a new encounter", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  site <- smart_client_fixture()
  site[["metadata"]][["capabilities"]] <- c(
    site[["metadata"]][["capabilities"]],
    "context-standalone-encounter",
    "permission-offline"
  )
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = c(
      "launch/patient",
      "launch/encounter",
      "patient/Patient.rs",
      "offline_access"
    ),
    required_scopes = "patient/Patient.r"
  )
  browser <- valid_browser_token()
  requested <- character()
  codes <- 0L
  refresh_scopes <- list()
  local_mocked_bindings(req_with_retry = function(req, ...) {
    body <- lapply(req[["body"]][["data"]], function(value) {
      utils::URLdecode(gsub("+", " ", as.character(value), fixed = TRUE))
    })
    code <- identical(body[["grant_type"]], "authorization_code")
    if (code) {
      codes <<- codes + 1L
    }
    scopes <- if (code || is.null(body[["scope"]])) {
      c("patient/Patient.rs", "offline_access")
    } else {
      normalize_scope_tokens(utils::URLdecode(body[["scope"]]))
    }
    if (!code) {
      refresh_scopes[[length(refresh_scopes) + 1L]] <<- scopes
    }
    # An initial provider can narrow the API grant. Later code responses must
    # respect the replacement request, including deliberate API narrowing.
    if (code && !"patient/Patient.rs" %in% requested) {
      scopes <- intersect(requested, c("patient/Patient.r", "offline_access"))
    }
    response <- list(
      access_token = paste0("access-", codes, "-", length(refresh_scopes)),
      refresh_token = "refresh",
      token_type = "Bearer",
      expires_in = 3600,
      scope = paste(scopes, collapse = " "),
      patient = "123"
    )
    if (code && "launch/encounter" %in% requested) {
      response[["encounter"]] <- paste0("encounter-", codes)
    }
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(response, auto_unbox = TRUE))
    )
  })
  exchange <- function(url) {
    requested <<- normalize_scope_tokens(parse_query_param(
      url,
      "scope",
      decode = TRUE
    ))
    handle_callback(client, "code", parse_query_param(url, "state"), browser)
  }
  for (narrow in c(FALSE, TRUE)) {
    for (managed in c(FALSE, TRUE)) {
      original <- exchange(prepare_call(client, browser))
      initial_encounter <- original@smart_context[["encounter"]]
      expect_true(is_valid_string(initial_encounter))
      expect_false(any(startsWith(original@granted_scopes, "launch/")))
      expected <- if (narrow) {
        c("launch/patient", "patient/Patient.r", "offline_access")
      } else {
        client@scopes
      }
      scopes <- if (narrow) c("patient/Patient.r", "offline_access") else NULL
      check_replacement <- function(replacement) {
        force(replacement)
        expect_setequal(requested, expected)
        if (narrow) {
          expect_null(replacement@smart_context[["encounter"]])
          expect_false("patient/Patient.rs" %in% replacement@granted_scopes)
        } else {
          expect_true(is_valid_string(replacement@smart_context[["encounter"]]))
          expect_false(identical(
            replacement@smart_context[["encounter"]],
            initial_encounter
          ))
        }
        replacement
      }
      if (!managed) {
        url <- NULL
        shiny::testServer(
          oauth_module_server,
          args = list(id = "auth", client = client, auto_redirect = FALSE),
          {
            session[["flushReact"]]()
            .accept_login_token(original, NULL)
            current <- values[["connection"]]()
            expect_true(current[["refresh"]](scopes = scopes))
            expect_true(current[["refresh"]]())
            values[["reauthorize"]]()
            values[["browser_token"]] <- browser
            url <<- .build_auth_url()
          }
        )
        # A fresh callback session must retain the sealed context request too.
        requested <- normalize_scope_tokens(parse_query_param(
          url,
          "scope",
          decode = TRUE
        ))
        shiny::testServer(
          oauth_module_server,
          args = list(id = "auth", client = client, auto_redirect = FALSE),
          {
            session[["flushReact"]]()
            values[["browser_token"]] <- browser
            values[[".process_query"]](paste0(
              "?code=replacement&state=",
              parse_query_param(url, "state")
            ))
            expect_null(values[["error"]])
            check_replacement(values[["token"]])
            values[["reauthorize"]]()
            values[["browser_token"]] <- browser
            expect_setequal(
              normalize_scope_tokens(parse_query_param(
                .build_auth_url(),
                "scope",
                decode = TRUE
              )),
              expected
            )
          }
        )
      } else {
        fixture <- ordinary_manager_fixture(client)
        cookie <- manager_test_cookie(fixture)
        stored_id <- NULL
        shiny::testServer(
          oauth_connections_server,
          args = list(id = "health", manager = fixture[["manager"]]),
          session = manager_test_session(cookie),
          {
            stored_id <<- manager_test_accept(controller, token = original)
            expect_true(connection(stored_id)[["refresh"]](scopes = scopes))
            expect_true(connection(stored_id)[["refresh"]]())
          }
        )
        shiny::testServer(
          oauth_connections_server,
          args = list(id = "health", manager = fixture[["manager"]]),
          session = manager_test_session(cookie),
          {
            expect_true(connection(stored_id)[["is_usable"]]())
            controller[["reauthorize"]](stored_id)
            hooks <- controller[["hooks"]]("a")
            context <- hooks[["prepare"]]()
            replacement <- check_replacement(exchange(prepare_call_internal(
              client,
              browser,
              .requested_scopes = context[["requested_scopes"]]
            )))
            hooks[["accept"]](replacement, context, as.numeric(Sys.time()))
            row <- Filter(
              function(row) {
                identical(row[["replaces_connection_id"]], stored_id)
              },
              controller[["records"]]()
            )[[1L]]
            controller[["reauthorize"]](row[["stored"]][["id"]])
            expect_setequal(
              hooks[["prepare"]]()[["requested_scopes"]],
              expected
            )
          }
        )
      }
    }
  }
  expect_true(all(vapply(
    refresh_scopes,
    function(scopes) {
      !any(startsWith(scopes, "launch/"))
    },
    logical(1)
  )))
})
