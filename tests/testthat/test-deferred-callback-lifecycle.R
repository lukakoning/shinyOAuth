make_deferred_lifecycle_client <- function(response_mode) {
  if (!endsWith(response_mode, ".jwt")) {
    return(make_test_client(response_mode = response_mode))
  }

  provider <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  provider@issuer <- "https://issuer.example.com"
  provider@response_modes_supported <- response_mode
  provider@jarm_signing_alg_values_supported <- "RS256"
  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = "openid",
    response_mode = response_mode,
    jarm_signed_response_alg = "RS256",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

make_deferred_lifecycle_bridge <- function(client, kind, browser, key = NULL) {
  state <- parse_query_param(
    prepare_call(client, browser),
    "state",
    decode = TRUE
  )
  fields <- c(
    if (identical(kind, "code")) {
      list(code = "deferred-code")
    } else {
      list(error = "access_denied", error_description = "Deferred refusal")
    },
    list(state = state)
  )
  if (endsWith(client@response_mode, ".jwt")) {
    fields <- list(
      response = jose::jwt_encode_sig(
        do.call(
          jose::jwt_claim,
          c(
            list(
              iss = client@provider@issuer,
              aud = client@client_id,
              exp = floor(as.numeric(Sys.time())) + 300
            ),
            fields
          )
        ),
        key = key,
        header = list(alg = "RS256", kid = "lifecycle")
      )
    )
  }
  body <- httr2::url_query_build(fields)
  is_post <- startsWith(client@response_mode, "form_post")
  request <- list(
    REQUEST_METHOD = if (is_post) "POST" else "GET",
    "rook.url_scheme" = "http",
    HTTP_HOST = "localhost:8100",
    PATH_INFO = "/",
    QUERY_STRING = if (is_post) "" else body,
    CONTENT_TYPE = "application/x-www-form-urlencoded",
    CONTENT_LENGTH = as.character(nchar(body, type = "bytes")),
    "rook.input" = list(read = function(n) charToRaw(body))
  )
  bridge <- oauth_form_post_ui(shiny::fluidPage(), "auth", client)(request)
  expect_identical(bridge[["status"]], 303L)
  list(
    query = bridge[["headers"]][["Location"]],
    response = fields[["response"]],
    state = state_payload_decrypt_validate(client, state)[["state"]]
  )
}

deferred_lifecycle_jwks <- function(key) {
  list(
    keys = list(utils::modifyList(
      jsonlite::fromJSON(write_test_jwk(key[["pubkey"]])),
      list(kid = "lifecycle", use = "sig")
    ))
  )
}

for (action in c("request_login", "build_auth_url", "clear_browser_token")) {
  test_that(
    paste(action, "invalidates JARM verification before cookie acknowledgment"),
    {
      local_options(shinyOAuth.skip_browser_token = FALSE)
      client <- make_deferred_lifecycle_client("query.jwt")
      browser <- valid_browser_token()
      key <- openssl::rsa_keygen()
      worker <- new.env(parent = emptyenv())
      worker[["promise"]] <- promises::promise(function(resolve, reject) {
        worker[["resolve"]] <- resolve
      })
      settled <- FALSE
      local_mocked_bindings(
        fetch_jwks = function(...) deferred_lifecycle_jwks(key),
        prepare_client_for_worker = function(client) client,
        async_dispatch = function(...) worker[["promise"]],
        swap_code_for_token_set = function(...) {
          stop("Superseded JARM verification must not exchange credentials")
        },
        .package = "shinyOAuth"
      )
      callback <- make_deferred_lifecycle_bridge(client, "code", browser, key)
      normalized <- validate_jarm_response(client, callback[["response"]])
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          async = TRUE
        ),
        {
          .handle_jarm_response(callback[["response"]], transport = "query")
          expect_false(is.null(auth_operations[["active_jarm_id"]]))
          values[[action]]()
          if (identical(action, "clear_browser_token")) {
            expect_null(browser_ack[["id"]])
          } else {
            expect_false(is.null(browser_ack[["id"]]))
          }
          promises::then(worker[["promise"]], function(...) {
            settled <<- TRUE
          })
          worker[["resolve"]](normalized)
          poll_for_async(function() settled, session)
          expect_true(settled)
          expect_null(values[["pending_callback"]])
          expect_null(values[["token"]])
          expect_null(values[["error"]])
          if (identical(action, "clear_browser_token")) {
            values[["set_browser_token"]]()
          }
          session[["setInputs"]](shinyOAuth_sid = browser)
          session[["flushReact"]]()
          expect_null(values[["pending_callback"]])
          expect_false(values[["authenticated"]])
          expect_null(values[["error"]])
        }
      )
    }
  )
}

for (action in c(
  "logout",
  "reauthorize",
  "request_login",
  "build_auth_url",
  "clear_browser_token"
)) {
  for (mode in c("query", "form_post", "query.jwt", "form_post.jwt")) {
    for (kind in c("code", "error")) {
      test_that(paste(action, "cancels deferred", mode, kind), {
        local_options(shinyOAuth.skip_browser_token = FALSE)
        client <- make_deferred_lifecycle_client(mode)
        browser <- valid_browser_token()
        key <- if (endsWith(mode, ".jwt")) openssl::rsa_keygen() else NULL
        exchanges <- 0L
        local_mocked_bindings(
          fetch_jwks = function(...) deferred_lifecycle_jwks(key),
          swap_code_for_token_set = function(...) {
            exchanges <<- exchanges + 1L
            list(
              access_token = "deferred-access",
              token_type = "Bearer",
              expires_in = 3600
            )
          },
          .package = "shinyOAuth"
        )
        callback <- make_deferred_lifecycle_bridge(client, kind, browser, key)
        other_state <- state_payload_decrypt_validate(
          client,
          parse_query_param(
            prepare_call(client, paste(rep("cd", 64), collapse = "")),
            "state",
            decode = TRUE
          )
        )[["state"]]

        shiny::testServer(
          oauth_module_server,
          args = list(id = "auth", client = client, auto_redirect = FALSE),
          {
            values[[".process_query"]](
              callback[["query"]],
              current_uri = client@redirect_uri
            )
            session[["flushReact"]]()
            pending <- values[["pending_callback"]]
            expect_type(pending, "list")
            expect_identical(
              pending[["auth_epoch"]],
              auth_operations[["epoch"]]
            )
            expect_identical(
              pending[["browser_generation"]],
              browser_ack[["generation"]]
            )
            expect_identical(
              pending[["type"]],
              if (endsWith(mode, ".jwt")) "jarm" else kind
            )

            values[[action]]()
            session[["flushReact"]]()
            expect_null(values[["pending_callback"]])
            expect_true(is.list(state_store_get(client, other_state)))

            # This valid restoration input can already be queued in the browser
            # when the user cancels the callback or starts a replacement login.
            session[["setInputs"]](shinyOAuth_sid = browser)
            session[["flushReact"]]()
            expect_null(values[["token"]])
            expect_false(values[["authenticated"]])
            expect_null(values[["pending_callback"]])
            expect_identical(exchanges, 0L)
            expect_identical(
              values[["error"]],
              if (identical(action, "logout")) "logged_out" else NULL
            )
            expect_true(is.list(state_store_get(client, other_state)))
          }
        )
      })
    }
  }
}

for (mode in c("query", "form_post", "query.jwt", "form_post.jwt")) {
  for (kind in c("code", "error")) {
    test_that(paste("current deferred", mode, kind, "resumes normally"), {
      local_options(shinyOAuth.skip_browser_token = FALSE)
      client <- make_deferred_lifecycle_client(mode)
      browser <- valid_browser_token()
      key <- if (endsWith(mode, ".jwt")) openssl::rsa_keygen() else NULL
      exchanges <- 0L
      local_mocked_bindings(
        fetch_jwks = function(...) deferred_lifecycle_jwks(key),
        swap_code_for_token_set = function(...) {
          exchanges <<- exchanges + 1L
          list(
            access_token = "deferred-access",
            token_type = "Bearer",
            expires_in = 3600
          )
        },
        .package = "shinyOAuth"
      )
      callback <- make_deferred_lifecycle_bridge(client, kind, browser, key)
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          values[[".process_query"]](
            callback[["query"]],
            current_uri = client@redirect_uri
          )
          session[["flushReact"]]()
          expect_type(values[["pending_callback"]], "list")
          session[["setInputs"]](shinyOAuth_sid = browser)
          session[["flushReact"]]()
          expect_null(values[["pending_callback"]])
          expect_identical(values[["authenticated"]], identical(kind, "code"))
          expect_identical(exchanges, if (identical(kind, "code")) 1L else 0L)
          expect_identical(
            values[["error"]],
            if (identical(kind, "error")) "access_denied" else NULL
          )
          expect_null(client@state_store[["get"]](
            state_cache_key(callback[["state"]]),
            missing = NULL
          ))
        }
      )
    })
  }
}

for (invalidated in c(
  "auth_epoch",
  "browser_generation",
  "session",
  "missing"
)) {
  for (kind in c("code", "error", "jarm")) {
    test_that(paste("stale deferred", kind, "is rejected for", invalidated), {
      local_options(shinyOAuth.skip_browser_token = FALSE)
      client <- make_deferred_lifecycle_client(
        if (identical(kind, "jarm")) "query.jwt" else "query"
      )
      browser <- valid_browser_token()
      key <- if (identical(kind, "jarm")) openssl::rsa_keygen() else NULL
      local_mocked_bindings(
        fetch_jwks = function(...) deferred_lifecycle_jwks(key),
        swap_code_for_token_set = function(...) {
          stop("Stale deferred callbacks must not exchange credentials")
        },
        .package = "shinyOAuth"
      )
      callback <- make_deferred_lifecycle_bridge(
        client,
        if (identical(kind, "error")) "error" else "code",
        browser,
        key
      )
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          values[[".process_query"]](
            callback[["query"]],
            current_uri = client@redirect_uri
          )
          session[["flushReact"]]()
          expect_type(values[["pending_callback"]], "list")
          # Keep the queued response to verify the guard independently of the
          # eager clearing performed by public lifecycle helpers.
          if (identical(invalidated, "auth_epoch")) {
            auth_operations[["epoch"]] <- auth_operations[["epoch"]] + 1
          } else if (identical(invalidated, "browser_generation")) {
            browser_ack[["generation"]] <- browser_ack[["generation"]] + 1L
          } else if (identical(invalidated, "session")) {
            auth_operations[["session_active"]] <- FALSE
          } else {
            values[["pending_callback"]][["auth_epoch"]] <- NULL
          }
          with_mocked_bindings(
            revalidate_cached_jarm_response = function(...) {
              stop("Stale JARM callbacks must not be revalidated")
            },
            .package = "shinyOAuth",
            {
              session[["setInputs"]](shinyOAuth_sid = browser)
              session[["flushReact"]]()
            }
          )
          expect_null(values[["pending_callback"]])
          expect_null(values[["token"]])
          expect_null(values[["error"]])
          expect_false(values[["authenticated"]])
          expect_true(is.list(state_store_get(client, callback[["state"]])))
        }
      )
    })
  }
}
