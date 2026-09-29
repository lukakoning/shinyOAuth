test_that("requests recheck authorization after configuration in both refresh modes", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  cases <- expand.grid(
    targeted = c(FALSE, TRUE),
    managed = c(FALSE, TRUE),
    refresh = c(FALSE, TRUE),
    action = c(
      "unchanged",
      "rotate",
      "narrow",
      "logout",
      "replace",
      "queued_logout"
    ),
    stringsAsFactors = FALSE
  )
  for (i in seq_len(nrow(cases))) {
    case <- cases[i, ]
    provider <- make_test_provider()
    provider@token_target_mode <- if (case[["targeted"]]) "rfc8707" else "none"
    client <- oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = c("read", "write"),
      resource_bases = c(api = "https://api.example/v1"),
      token_targets = if (case[["targeted"]]) {
        list(
          api = list(
            resource = "urn:api",
            scopes = c("read", "write"),
            resource_ids = "api"
          )
        )
      } else {
        list()
      }
    )
    fixture <- ordinary_manager_fixture(client)
    sent <- list()
    configurations <- 0L
    refreshes <- 0L
    local_mocked_bindings(
      refresh_token_dispatch = function(
        client,
        token,
        scope_request = NULL,
        target_request = NULL,
        ...
      ) {
        refreshes <<- refreshes + 1L
        token@access_token <- "refreshed-access"
        token@granted_scopes <- (target_request %||% scope_request)[["scopes"]]
        token
      },
      req_with_retry = function(req, ...) {
        sent[[length(sent) + 1L]] <<- req
        httr2::response(req[["url"]], status = 200L)
      },
      revoke_token = function(...) invisible(NULL)
    )
    shiny::testServer(
      if (case[["managed"]]) oauth_connections_server else oauth_module_server,
      args = if (case[["managed"]]) {
        list(id = "health", manager = fixture[["manager"]])
      } else {
        list(id = "auth", client = client, auto_redirect = FALSE)
      },
      session = manager_test_session(
        if (case[["managed"]]) manager_test_cookie(fixture) else NULL
      ),
      {
        accept <- function(token = manager_test_token()) {
          if (case[["managed"]]) {
            connection(manager_test_accept(controller, token = token))
          } else {
            .accept_login_token(token, NULL)
            values[["connection"]]()
          }
        }
        current <- accept()
        end_authorization <- function() {
          if (case[["managed"]]) {
            controller[["disconnect"]](current[["id"]], revoke = FALSE)
          } else {
            values[["logout"]]()
          }
        }
        if (case[["action"]] == "queued_logout") {
          later::later(end_authorization, delay = 0)
        }
        replacement <- NULL
        result <- tryCatch(
          current[["request"]](
            "api",
            "records",
            method = "POST",
            required_scopes = "write",
            refresh = case[["refresh"]],
            configure = function(req) {
              configurations <<- configurations + 1L
              expect_null(req[["headers"]][["Authorization"]])
              action <- case[["action"]]
              if (action %in% c("narrow", "rotate")) {
                current[["refresh"]](
                  scopes = if (action == "narrow") {
                    "read"
                  } else {
                    c("read", "write")
                  }
                )
              } else if (action %in% c("logout", "replace")) {
                end_authorization()
                if (action == "replace") {
                  replacement <<- accept(manager_test_token(
                    access = "new-login"
                  ))
                }
              } else if (action == "queued_logout") {
                # An unrelated pending logout can run when application code
                # yields; configuration need not intentionally change access.
                later::run_now(0)
              }
              httr2::req_body_json(req, list(value = "configured-once"))
            }
          ),
          error = identity
        )
        expect_identical(configurations, 1L)
        expect_identical(
          refreshes,
          if (case[["action"]] %in% c("narrow", "rotate")) 1L else 0L
        )
        if (case[["action"]] %in% c("unchanged", "rotate")) {
          expect_s3_class(result, "httr2_response")
          expect_length(sent, 1L)
          expect_identical(
            httr2::req_dry_run(
              sent[[1L]],
              quiet = TRUE,
              redact_headers = FALSE
            )[[
              "headers"
            ]][["authorization"]],
            if (case[["action"]] == "rotate") {
              "Bearer refreshed-access"
            } else {
              "Bearer synthetic-access"
            }
          )
          expect_identical(
            sent[[1L]][["body"]][["data"]],
            list(value = "configured-once")
          )
        } else {
          expect_s3_class(result, "shinyOAuth_error")
          expect_length(sent, 0L)
          expect_false(current[["has_scopes"]]("write"))
          if (!is.null(replacement)) {
            expect_true(replacement[["has_scopes"]]("write"))
            expect_false(identical(current[["id"]], replacement[["id"]]))
          }
        }
      }
    )
  }
})
