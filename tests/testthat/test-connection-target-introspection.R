introspected_target_client <- function() {
  provider <- make_test_provider()
  provider@token_target_mode <- "rfc8707"
  provider@introspection_url <- "https://issuer.example/introspect"
  oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("read", "write", "contacts", "offline_access"),
    scope_validation = "strict",
    introspect = TRUE,
    introspection_checks = "scope",
    token_targets = list(
      api = list(resource = "urn:api", scopes = c("read", "write")),
      contacts = list(resource = "urn:contacts", scopes = "contacts")
    ),
    default_token_target = "api"
  )
}

test_that("introspection preserves target refresh consent with omitted response scopes", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  client <- introspected_target_client()
  browser <- valid_browser_token()
  for (managed in c(FALSE, TRUE)) {
    for (login_scope in c(FALSE, TRUE)) {
      for (refresh_scope in c(FALSE, TRUE)) {
        calls <- 0L
        permissions <- list()
        local_mocked_bindings(
          revoke_token = function(...) invisible(NULL),
          req_with_retry = function(req, ...) {
            calls <<- calls + 1L
            data <- req[["body"]][["data"]]
            scopes <- setdiff(
              normalize_scope_tokens(utils::URLdecode(
                as.character(data[["scope"]])
              )),
              "offline_access"
            )
            access <- paste0("access-", calls)
            permissions[[access]] <<- paste(scopes, collapse = " ")
            body <- list(
              access_token = access,
              refresh_token = paste0("refresh-", calls),
              token_type = "Bearer",
              expires_in = 3600
            )
            if (if (calls == 1L) login_scope else refresh_scope) {
              body[["scope"]] <- permissions[[access]]
            }
            httr2::response(
              req[["url"]],
              status = 200L,
              headers = list("content-type" = "application/json"),
              body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE))
            )
          },
          introspect_token = function(oauth_client, oauth_token, ...) {
            list(
              supported = TRUE,
              active = TRUE,
              raw = list(
                scope = permissions[[oauth_token@access_token]]
              )
            )
          }
        )
        url <- prepare_call(client, browser)
        token <- handle_callback(
          client,
          "code",
          parse_query_param(url, "state"),
          browser
        )
        expect_setequal(token@granted_scopes, c("read", "write"))
        exercise <- function(current) {
          expect_true(current[["refresh"]]())
          expect_identical(current[["access_token"]](), "access-2")
          expect_identical(
            current[["access_token"]]("contacts", target = "contacts"),
            "access-3"
          )
          expect_true(current[["has_scopes"]](c("read", "write")))
          expect_true(current[["has_scopes"]]("contacts", target = "contacts"))
          expect_false(current[["has_scopes"]]("offline_access"))
          expect_identical(calls, 3L)
        }
        if (managed) {
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
          fixture <- list(
            ui = oauth_connections_ui(shiny::fluidPage(), "auth", manager)
          )
          shiny::testServer(
            oauth_connections_server,
            args = list(id = "auth", manager = manager),
            session = manager_test_session(manager_test_cookie(fixture)),
            {
              id <- manager_test_accept(controller, token = token)
              exercise(connection(id))
              record <- controller[["read"]](id)
              expect_identical(record[["token"]]@refresh_token, "refresh-3")
              expect_true(all(vapply(
                record[["targets"]][["limits"]],
                function(x) {
                  "offline_access" %in% x
                },
                logical(1)
              )))
            }
          )
        } else {
          shiny::testServer(
            oauth_module_server,
            args = list(id = "auth", client = client, auto_redirect = FALSE),
            {
              .accept_login_token(token, NULL)
              exercise(values[["connection"]]())
              expect_identical(values[["token"]]@refresh_token, "refresh-3")
              expect_true(all(vapply(
                values[["targets"]][["limits"]],
                function(x) {
                  "offline_access" %in% x
                },
                logical(1)
              )))
            }
          )
        }
      }
    }
  }
})

test_that("target introspection still rejects missing and excessive API permissions", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  client <- introspected_target_client()
  browser <- valid_browser_token()
  for (evidence in list(
    NULL,
    "read",
    "read write contacts",
    "read write admin"
  )) {
    local_mocked_bindings(
      req_with_retry = function(req, ...) {
        httr2::response(
          req[["url"]],
          status = 200L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(paste0(
            '{"access_token":"access","refresh_token":"refresh",',
            '"token_type":"Bearer","expires_in":3600}'
          ))
        )
      },
      introspect_token = function(...) {
        list(supported = TRUE, active = TRUE, raw = list(scope = evidence))
      }
    )
    url <- prepare_call(client, browser)
    expect_error(
      handle_callback(client, "code", parse_query_param(url, "state"), browser),
      class = "shinyOAuth_token_error"
    )
  }
})
