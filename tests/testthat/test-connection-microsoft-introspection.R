microsoft_introspection_fixture <- function(use_default = FALSE) {
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  provider@introspection_url <- "https://issuer.example/introspect"
  permissions <- c("read", "item:write", "folder/read")
  targets <- lapply(
    c(primary = "api://primary", secondary = "api://secondary"),
    function(resource) {
      list(
        resource = resource,
        scopes = paste0(
          resource,
          "/",
          if (use_default) ".default" else permissions
        ),
        required_scopes = paste0(resource, "/read"),
        scope_aliases = if (use_default) {
          c("item:write", "folder/read")
        } else {
          character()
        }
      )
    }
  )
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("offline_access", unlist(lapply(targets, `[[`, "scopes"))),
    scope_validation = "strict",
    introspect = TRUE,
    introspection_checks = c("scope", "client_id", "token_type"),
    token_targets = targets,
    default_token_target = "primary"
  )
  state <- new.env(parent = emptyenv())
  state[["calls"]] <- 0L
  state[["scopes"]] <- list()
  state[["qualified"]] <- FALSE
  state[["override"]] <- FALSE
  request <- function(req, ...) {
    data <- lapply(req[["body"]][["data"]], function(value) {
      utils::URLdecode(gsub("+", " ", as.character(value), fixed = TRUE))
    })
    body <- if (identical(req[["url"]], provider@introspection_url)) {
      result <- list(
        active = TRUE,
        client_id = "app",
        token_type = "Bearer",
        scope = if (state[["override"]]) {
          state[["evidence"]]
        } else {
          state[["scopes"]][[data[["token"]]]]
        }
      )
      if (is.null(result[["scope"]])) {
        result[["scope"]] <- NULL
      }
      result
    } else {
      state[["calls"]] <- state[["calls"]] + 1L
      access <- paste0("access-", state[["calls"]])
      resource <- if (
        grepl("api://secondary/", data[["scope"]], fixed = TRUE)
      ) {
        "api://secondary"
      } else {
        "api://primary"
      }
      scopes <- paste0(resource, "/", permissions)
      state[["scopes"]][[access]] <- paste(
        if (state[["qualified"]]) scopes else permissions,
        collapse = " "
      )
      list(
        access_token = access,
        refresh_token = paste0("refresh-", state[["calls"]]),
        token_type = "Bearer",
        expires_in = 3600,
        scope = paste(scopes, collapse = " ")
      )
    }
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE))
    )
  }
  list(
    client = client,
    state = state,
    request = request,
    permissions = permissions
  )
}

test_that("Microsoft introspection scopes follow the selected target on login and refresh", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (use_default in c(FALSE, TRUE)) {
    f <- microsoft_introspection_fixture(use_default)
    client <- f[["client"]]
    local_mocked_bindings(
      req_with_retry = f[["request"]],
      revoke_token = function(...) invisible(NULL)
    )
    for (qualified in c(FALSE, TRUE)) {
      f[["state"]][["qualified"]] <- qualified
      for (managed in c(FALSE, TRUE)) {
        browser <- valid_browser_token()
        url <- prepare_call(client, browser)
        token <- handle_callback(
          client,
          "code",
          parse_query_param(url, "state"),
          browser
        )
        expect_setequal(
          token@granted_scopes,
          paste0("api://primary/", f[["permissions"]])
        )
        expect_true(token@granted_scopes_verified)
        # Public introspection still exposes the unmodified provider response.
        expect_identical(
          introspect_token(client, token)[["raw"]][["scope"]],
          f[["state"]][["scopes"]][[token@access_token]]
        )
        fixture <- ordinary_manager_fixture(client)
        shiny::testServer(
          if (managed) oauth_connections_server else oauth_module_server,
          args = if (managed) {
            list(id = "health", manager = fixture[["manager"]])
          } else {
            list(id = "health", client = client, auto_redirect = FALSE)
          },
          session = manager_test_session(
            if (managed) manager_test_cookie(fixture) else NULL
          ),
          {
            current <- if (managed) {
              connection(manager_test_accept(controller, token = token))
            } else {
              .accept_login_token(token, NULL)
              values[["connection"]]()
            }
            expect_true(current[["refresh"]]())
            for (target in c("primary", "secondary")) {
              scopes <- paste0("api://", target, "/", f[["permissions"]])
              expect_type(
                current[["access_token"]](scopes, target = target),
                "character"
              )
              expect_true(current[["has_scopes"]](scopes, target = target))
              expect_setequal(
                current[["targets"]]()[[target]][["granted_scopes"]],
                scopes
              )
              expect_false(current[["has_scopes"]](
                "offline_access",
                target = target
              ))
            }
          }
        )
      }
    }
  }
})

test_that("Microsoft introspection normalization preserves scope validation boundaries", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- microsoft_introspection_fixture()
  client <- f[["client"]]
  local_mocked_bindings(req_with_retry = f[["request"]])
  browser <- valid_browser_token()
  url <- prepare_call(client, browser)
  token <- handle_callback(
    client,
    "code",
    parse_query_param(url, "state"),
    browser
  )
  f[["state"]][["override"]] <- TRUE
  for (evidence in list(
    NULL,
    42,
    list("read"),
    c("read", "item:write"),
    "",
    "read\nitem:write",
    ".default",
    "api://primary/.default",
    "read item:write",
    "read item:write folder/read unknown:permission",
    "read item:write folder/read api://foreign/read",
    "read item:write folder/read api://primary/read",
    "api://foreign/read api://foreign/item:write api://foreign/folder/read"
  )) {
    f[["state"]][["evidence"]] <- evidence
    # Explicit scope evidence from a different resource must never become a
    # permission of the selected secondary resource, even in permissive mode.
    for (mode in c("strict", "none")) {
      client@scope_validation <- mode
      for (target in c("primary", "secondary")) {
        # The duplicated primary permission is valid for primary only.
        if (
          target == "primary" &&
            identical(
              evidence,
              "read item:write folder/read api://primary/read"
            )
        ) {
          next
        }
        # Missing evidence and missing optional permissions retain existing
        # permissive-policy semantics; the normalization must not change that.
        if (
          mode == "none" &&
            (is.null(evidence) || identical(evidence, "read item:write"))
        ) {
          next
        }
        expect_error(
          refresh_token_impl(
            client,
            token,
            target_request = token_target_request(client, target)
          ),
          class = "shinyOAuth_token_error"
        )
        if (target == "primary") {
          url <- prepare_call(client, browser)
          expect_error(
            handle_callback(
              client,
              "code",
              parse_query_param(url, "state"),
              browser
            ),
            class = "shinyOAuth_token_error"
          )
        }
      }
    }
  }
})

test_that("Microsoft introspection keeps permissive policy and operation limits", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- microsoft_introspection_fixture()
  client <- f[["client"]]
  client@scope_validation <- "none"
  local_mocked_bindings(req_with_retry = f[["request"]])
  browser <- valid_browser_token()
  f[["state"]][["override"]] <- TRUE
  for (evidence in list(
    NULL,
    "read item:write",
    "read item:write folder/read admin"
  )) {
    f[["state"]][["evidence"]] <- evidence
    url <- prepare_call(client, browser)
    token <- handle_callback(
      client,
      "code",
      parse_query_param(url, "state"),
      browser
    )
    expected <- paste0(
      "api://primary/",
      if (is.null(evidence)) {
        f[["permissions"]]
      } else {
        normalize_scope_tokens(evidence)
      }
    )
    expect_setequal(token@granted_scopes, expected)
    refreshed <- refresh_token_impl(
      client,
      token,
      target_request = token_target_request(client)
    )
    expect_setequal(refreshed@granted_scopes, expected)
    # Microsoft can report additional consented permissions, but introspection
    # must not grant the application operations outside its configured ceiling.
    bundle <- token_target_bundle(client, refreshed)
    expect_false("api://primary/admin" %in% bundle[["limits"]][["primary"]])
  }
})
