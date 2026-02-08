testthat::test_that("async login flow resolves token and sets flags", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Disable mirai so async_dispatch uses future (mocks work with sequential)
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future::sequential so mocks apply (future runs in-process)
  old_plan <- future::plan()
  future::plan(future::sequential)
  withr::defer(future::plan(old_plan))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())

      # Build the authorization URL and capture encoded state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      # Mock token exchange to avoid HTTP; resolve with a short-lived token
      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t-async", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", enc))
          # Allow promise handlers to run
          deadline <- Sys.time() + 3
          while (is.null(values$token) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      session$flushReact()
      testthat::expect_true(isTRUE(values$last_login_async_used))
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_null(values$error_description)
      # Cookie should be cleared after successful login
      testthat::expect_null(values$browser_token)
    }
  )
})

testthat::test_that("async login failure surfaces error and keeps authenticated FALSE", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_if_not_installed("mirai")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Start a real mirai daemon so the test exercises true async behaviour:
  # handle_callback runs in a separate worker process and the promise
  # catch-handler propagates the error back on the main thread.
  mirai::daemons(1)
  withr::defer(mirai::daemons(0))

  # The daemon is a separate R process that must be able to load shinyOAuth.
  # When only loaded via devtools::load_all() the package is unavailable to
  # subprocess workers, so skip in that case.
  pkg_check <- mirai::mirai(requireNamespace("shinyOAuth", quietly = TRUE))
  mirai::call_mirai(pkg_check)
  testthat::skip_if_not(
    isTRUE(pkg_check$data),
    "shinyOAuth must be installed (not just load_all'd) for mirai daemon tests"
  )

  # Stand up a webfakes server whose /token endpoint always returns HTTP 400.
  # The mirai worker process hits this real endpoint, so no mocking is needed
  # and we fully exercise the async error path end-to-end.
  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$set_status(400L)
    res$set_type("application/json")
    res$send_json(list(error = "invalid_grant", error_description = "bad code"))
  })
  # Also serve /auth so the provider URL validates (never actually called)
  app$get("/auth", function(req, res) {
    res$set_status(200L)
    res$send("")
  })
  srv <- webfakes::local_app_process(app)

  # Build provider + client pointing at the webfakes token endpoint
  prov <- oauth_provider(
    name = "webfakes-error",
    auth_url = srv$url("/auth"),
    token_url = srv$url("/token"),
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("RS256", "ES256"),
    allowed_token_types = character(),
    leeway = 60
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_payload_max_age = 300,
    state_entropy = 64,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = FALSE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Trigger the callback — the mirai worker will hit the webfakes /token
      # endpoint in a separate process, receive HTTP 400, and the promise
      # catch-handler should propagate the error back to values$error.
      values$.process_query(paste0("?code=bad&state=", enc))
      # Allow more time for real cross-process async resolution
      deadline <- Sys.time() + 10
      while (is.null(values$error) && Sys.time() < deadline) {
        later::run_now(0.05)
        session$flushReact()
        Sys.sleep(0.01)
      }

      testthat::expect_identical(values$error, "token_exchange_error")
      testthat::expect_match(
        values$error_description %||% "",
        "exchange|token|error|failed|400",
        ignore.case = TRUE
      )
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(is.null(values$token))
    }
  )
})

testthat::test_that("pending callback resumes after cookie arrives (async)", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  # Do not skip cookie handling; we want to exercise pending_callback path
  withr::local_options(list(shinyOAuth.skip_browser_token = FALSE))

  # Use a deterministic valid browser token and pre-build a state payload
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  btok <- valid_browser_token()
  url_pre <- prepare_call(cli, browser_token = btok)
  enc <- parse_query_param(url_pre, "state")
  testthat::expect_true(is.character(enc) && nzchar(enc))

  # Disable mirai so async_dispatch uses future (mocks work with sequential)
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future::sequential so mocks apply (future runs in-process)
  old_plan <- future::plan()
  future::plan(future::sequential)
  withr::defer(future::plan(old_plan))

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      # Initially there's no cookie -> callback is deferred
      testthat::expect_false(values$has_browser_token())
      values$.process_query(paste0("?code=ok&state=", enc))
      session$flushReact()
      testthat::expect_type(values$pending_callback, "list")

      # Once cookie is provided, module should resume the pending callback
      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t-async2", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          session$setInputs(shinyOAuth_sid = btok)
          # Process async resolution
          deadline <- Sys.time() + 3
          while (is.null(values$token) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      testthat::expect_null(values$pending_callback)
      testthat::expect_true(isTRUE(values$authenticated))
    }
  )
})

testthat::test_that("async_dispatch returns promise when future is fallback", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")

  # Ensure mirai is NOT configured
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future sequential plan
  future::plan(future::sequential)
  withr::defer(future::plan(future::sequential))

  # Test that async_dispatch returns a promise when falling back to future
  p <- shinyOAuth:::async_dispatch(
    expr = quote({
      x + y
    }),
    args = list(x = 5, y = 10)
  )

  testthat::expect_s3_class(p, "promise")
})

testthat::test_that("async_dispatch returns mirai object when mirai is configured", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  # Use mirai synchronous mode so the test runs in-process
  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  # Test that async_dispatch returns a mirai object when mirai is configured
  m <- shinyOAuth:::async_dispatch(
    expr = quote({
      x + y
    }),
    args = list(x = 5, y = 10)
  )

  # Should be a mirai object (recvAio)
  testthat::expect_true(inherits(m, "mirai"))

  # Should be usable with promises::then via as.promise coercion
  result <- NULL
  p <- m |>
    promises::then(function(x) {
      result <<- x
    })

  # Wait for resolution
  deadline <- Sys.time() + 3
  while (is.null(result) && Sys.time() < deadline) {
    later::run_now(0.05)
    Sys.sleep(0.01)
  }

  testthat::expect_equal(result, 15)
})
