oidc_reauthorization_fixture <- function(mode, multiple) {
  provider <- oauth_provider(
    "oidc-targets",
    "https://issuer.example/auth",
    "https://issuer.example/token",
    issuer = "https://issuer.example",
    id_token_validation = TRUE,
    use_nonce = TRUE,
    userinfo_required = FALSE,
    token_auth_style = "body",
    token_target_mode = mode
  )
  scope <- function(target, permission) {
    if (mode == "microsoft") {
      paste0("api://", target, "/", permission)
    } else {
      paste0(target, ".", permission)
    }
  }
  targets <- list(
    primary = list(
      resource = "api://primary",
      scopes = c(scope("primary", "read"), scope("primary", "write"))
    )
  )
  if (multiple) {
    targets[["secondary"]] <- list(
      resource = "api://secondary",
      scopes = c(scope("secondary", "read"), scope("secondary", "write"))
    )
  }
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c(
      "openid",
      "profile",
      "email",
      "offline_access",
      unlist(lapply(targets, `[[`, "scopes"))
    ),
    token_targets = targets,
    default_token_target = "primary"
  )
  key <- openssl::rsa_keygen()
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  state <- new.env(parent = emptyenv())
  state[["nonce"]] <- NULL
  state[["include_openid"]] <- FALSE
  state[["requests"]] <- list()
  sign <- function(nonce) {
    now <- floor(as.numeric(Sys.time()))
    input <- paste(
      base64url_encode(charToRaw('{"alg":"RS256"}')),
      base64url_encode(charToRaw(jsonlite::toJSON(
        list(
          iss = provider@issuer,
          aud = client@client_id,
          sub = "alice",
          iat = now,
          exp = now + 3600,
          nonce = nonce
        ),
        auto_unbox = TRUE
      ))),
      sep = "."
    )
    paste(
      input,
      base64url_encode(openssl::signature_create(
        charToRaw(input),
        openssl::sha256,
        key
      )),
      sep = "."
    )
  }
  request <- function(req, ...) {
    body <- lapply(req[["body"]][["data"]], function(value) {
      utils::URLdecode(gsub("+", " ", as.character(value), fixed = TRUE))
    })
    state[["requests"]][[length(state[["requests"]]) + 1L]] <- body
    requested <- normalize_scope_tokens(body[["scope"]])
    target <- if (scope("secondary", "read") %in% requested) {
      "secondary"
    } else {
      "primary"
    }
    response <- list(
      access_token = paste0(target, "-access"),
      refresh_token = if (
        !identical(body[["grant_type"]], "authorization_code") ||
          "offline_access" %in% requested
      ) {
        paste0("rotated-refresh-", length(state[["requests"]]))
      },
      token_type = "Bearer",
      expires_in = 3600,
      scope = paste(
        c(
          scope(target, "read"),
          if (state[["include_openid"]] && "openid" %in% requested) "openid"
        ),
        collapse = " "
      )
    )
    if (
      identical(body[["grant_type"]], "authorization_code") &&
        "openid" %in% requested
    ) {
      response[["id_token"]] <- sign(state[["nonce"]])
    }
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(
        Filter(Negate(is.null), response),
        auto_unbox = TRUE
      ))
    )
  }
  list(
    client = client,
    state = state,
    request = request,
    jwk = jwk,
    scope = scope
  )
}

test_that("OIDC target replacement authenticates after API-only scope responses", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (mode in c("rfc8707", "microsoft")) {
    for (multiple in c(FALSE, TRUE)) {
      f <- oidc_reauthorization_fixture(mode, multiple)
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
      for (async in c(FALSE, TRUE)) {
        f[["state"]][["include_openid"]] <- FALSE
        browser <- valid_browser_token()
        initial_url <- prepare_call(client, browser)
        f[["state"]][["nonce"]] <- parse_query_param(
          initial_url,
          "nonce",
          decode = TRUE
        )
        replacement_url <- NULL
        shiny::testServer(
          oauth_module_server,
          args = list(id = "auth", client = client, auto_redirect = FALSE),
          {
            session[["flushReact"]]()
            values[["browser_token"]] <- browser
            suppressWarnings(values[[".process_query"]](paste0(
              "?code=initial&state=",
              parse_query_param(initial_url, "state")
            )))
            expect_null(values[["error"]])
            expect_true(values[["token"]]@id_token_validated)
            expect_true(is_valid_string(values[["token"]]@refresh_token))
            current <- values[["connection"]]()
            if (multiple) {
              suppressWarnings(current[["access_token"]](target = "secondary"))
            }
            expect_false(
              "openid" %in%
                token_target_authorization_scopes(
                  client,
                  auth_operations[["target_limits"]]
                )
            )
            values[["reauthorize"]]()
            expect_false(current[["is_usable"]]())
            values[["browser_token"]] <- browser
            replacement_url <<- .build_auth_url()
          }
        )
        expected <- c(f[["scope"]]("primary", "read"), "openid", "offline_access")
        expect_setequal(
          normalize_scope_tokens(parse_query_param(
            replacement_url,
            "scope",
            decode = TRUE
          )),
          c(expected, if (multiple) f[["scope"]]("secondary", "read"))
        )
        f[["state"]][["nonce"]] <- parse_query_param(
          replacement_url,
          "nonce",
          decode = TRUE
        )
        # Both API-only and explicitly returned openid evidence are valid.
        f[["state"]][["include_openid"]] <- multiple
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
            suppressWarnings({
              values[[".process_query"]](paste0(
                "?code=replacement&state=",
                parse_query_param(replacement_url, "state")
              ))
              poll_for_async(
                function() {
                  !is.null(values[["token"]]) || !is.null(values[["error"]])
                },
                session
              )
            })
            expect_null(values[["error"]])
            expect_true(values[["token"]]@id_token_validated)
            expect_true(is_valid_string(values[["token"]]@refresh_token))
            expect_false("offline_access" %in% values[["token"]]@granted_scopes)
            expect_identical(
              values[["connection"]]()[["identity"]]()[["id_token_claims"]][[
                "sub"
              ]],
              "alice"
            )
            expect_setequal(
              normalize_scope_tokens(tail(f[["state"]][["requests"]], 1L)[[
                1L
              ]][["scope"]]),
              expected
            )
            expect_false(values[["connection"]]()[["has_scopes"]](f[["scope"]](
              "primary",
              "write"
            )))
            if (multiple) {
              expect_setequal(
                auth_operations[["target_limits"]][["secondary"]],
                c(f[["scope"]]("secondary", "read"), "offline_access")
              )
              expect_identical(
                suppressWarnings(values[["connection"]]()[["access_token"]](
                  target = "secondary"
                )),
                "secondary-access"
              )
            }
          }
        )
      }
    }
  }
})

test_that("managed OIDC replacement seals matching login and target scope limits", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (mode in c("rfc8707", "microsoft")) {
    f <- oidc_reauthorization_fixture(mode, TRUE)
    client <- f[["client"]]
    local_mocked_bindings(
      fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
      req_with_retry = f[["request"]],
      revoke_token = function(...) invisible(NULL)
    )
    manager <- oauth_connections(
      list(a = client),
      "https://app.example",
      store = oauth_connection_store_memory(),
      retention = "browser",
      owner_policy = oauth_browser_owner(),
      keys = list(
        credentials = openssl::rand_bytes(32),
        owner = openssl::rand_bytes(32)
      )
    )
    fixture <- list(
      ui = oauth_connections_ui(shiny::fluidPage("Targets"), "auth", manager)
    )
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "auth", manager = manager),
      session = manager_test_session(manager_test_cookie(fixture)),
      {
        browser <- valid_browser_token()
        initial_url <- prepare_call(client, browser)
        f[["state"]][["nonce"]] <- parse_query_param(
          initial_url,
          "nonce",
          decode = TRUE
        )
        token <- suppressWarnings(handle_callback(
          client,
          "initial",
          parse_query_param(initial_url, "state"),
          browser
        ))
        id <- manager_test_accept(controller, token = token)
        current <- connection(id)
        suppressWarnings(current[["access_token"]](target = "secondary"))
        session[["getReturned"]]()[["reauthorize"]](id)
        hooks <- controller[["hooks"]]("a")
        context <- hooks[["prepare"]]()
        expected <- c(f[["scope"]]("primary", "read"), "openid", "offline_access")
        expect_setequal(context[["target_limits"]][["primary"]], expected)
        expect_setequal(
          context[["target_limits"]][["secondary"]],
          c(f[["scope"]]("secondary", "read"), "offline_access")
        )
        url <- prepare_call_internal(
          client,
          browser,
          .transaction_context = context,
          .requested_scopes = context[["requested_scopes"]],
          .target_limits = context[["target_limits"]]
        )
        restored <- oauth_module_managed_context(
          hooks,
          client,
          parse_query_param(url, "state"),
          browser
        )
        f[["state"]][["nonce"]] <- parse_query_param(
          url,
          "nonce",
          decode = TRUE
        )
        f[["state"]][["include_openid"]] <- TRUE
        replacement <- suppressWarnings(handle_callback_internal(
          client,
          "replacement",
          parse_query_param(url, "state"),
          browser,
          .transaction_context = restored[["json"]]
        ))
        hooks[["accept"]](
          replacement,
          restored[["data"]],
          as.numeric(Sys.time())
        )
        expect_true(replacement@id_token_validated)
        expect_true(is_valid_string(replacement@refresh_token))
        expect_identical(
          suppressWarnings(connection()[["access_token"]](target = "secondary")),
          "secondary-access"
        )
        expect_false(connection()[["has_scopes"]](f[["scope"]](
          "primary",
          "write"
        )))
        expect_identical(
          connection()[["identity"]]()[["id_token_claims"]][["sub"]],
          "alice"
        )
      }
    )
  }
})

test_that("mandatory OIDC login scope fits the same budget before reauthorization", {
  f <- oidc_reauthorization_fixture("microsoft", FALSE)
  client <- oauth_client(
    f[["client"]]@provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("openid", "api://primary/.default"),
    token_targets = list(
      primary = list(
        resource = "api://primary",
        scopes = "api://primary/.default"
      )
    )
  )
  maximum <- paste0("api://primary/permission", seq_len(127L))
  limits <- list(primary = maximum)
  expect_no_error(validate_token_target_limits(client, limits))
  expect_length(
    token_target_reauthorization_limits(client, limits)[["primary"]],
    128L
  )
  excessive <- c(maximum, "api://primary/overflow")
  expect_error(
    validate_token_target_limits(client, list(primary = excessive)),
    class = "shinyOAuth_token_error"
  )
  expect_error(
    validate_token_target_grant(
      client,
      excessive,
      token_target_request(client)
    ),
    class = "shinyOAuth_token_error"
  )
  expect_error(
    oauth_client(
      client@provider,
      "app",
      client_secret = "",
      redirect_uri = client@redirect_uri,
      scopes = client@scopes,
      token_targets = list(
        primary = list(
          resource = "api://primary",
          scopes = "api://primary/.default",
          required_scopes = excessive
        )
      )
    ),
    "requirements exceed"
  )
  empty <- list(primary = character())
  expect_identical(token_target_reauthorization_limits(client, empty), empty)
  expect_error(
    authorization_scope_limit(client, character()),
    class = "shinyOAuth_input_error"
  )
})
