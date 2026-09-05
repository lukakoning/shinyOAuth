authorization_deferred_work <- function() {
  work <- new.env(parent = emptyenv())
  work$promise <- promises::promise(function(resolve, reject) {
    work$resolve <- resolve
    work$reject <- reject
  })
  work
}

test_that("async authorization retains main-process state and discards stale results", {
  skip_if_not_installed("promises")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  for (action in c("success", "logout", "failure", "replacement")) {
    cli <- make_test_client(use_nonce = FALSE)
    cli@provider@par_url <- "https://example.com/par"
    work <- authorization_deferred_work()
    testthat::local_mocked_bindings(
      async_dispatch = function(expr, args, ...) {
        work$args <- args
        work$promise
      },
      .package = "shinyOAuth"
    )
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = cli,
        async = TRUE,
        auto_redirect = FALSE
      ),
      expr = {
        answer <- NULL
        result <- values$build_auth_url()
        expect_s3_class(result, "promise")
        promises::then(result, function(value) {
          answer <<- value
        })
        key <- work$args$prepared$state_key
        expect_false(is.null(cli@state_store$get(key, missing = NULL)))
        expect_false(identical(work$args$worker@state_store, cli@state_store))
        if (action == "logout") {
          values$logout()
        }
        if (action == "replacement") {
          .begin_auth_operation("login", values$token, new_epoch = TRUE)
        }
        if (action == "failure") {
          work$reject(simpleError("provider unavailable"))
        } else {
          work$resolve("https://example.com/auth?request_uri=urn:test:par")
        }
        poll_for_async(function() !is.null(answer), session)
        if (action == "success") {
          expect_match(answer, "urn:test:par")
          expect_false(is.null(cli@state_store$get(key, missing = NULL)))
        } else {
          expect_true(is.na(answer))
          expect_null(cli@state_store$get(key, missing = NULL))
        }
        if (action == "logout") {
          expect_identical(values$error, "logged_out")
        }
        if (action == "failure") {
          expect_identical(values$error, "auth_url_error")
        }
      }
    )
  }
})

test_that("async Request Objects publish only after returning to the owning session", {
  skip_if_not_installed("promises")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  for (logout in c(FALSE, TRUE)) {
    prov <- make_test_provider(use_nonce = FALSE)
    prov@issuer <- "https://example.com"
    prov@request_uri_parameter_supported <- TRUE
    cli <- oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      request_object_mode = "request_uri",
      request_object_signing_alg = "RS256",
      client_assertion_private_key = openssl::rsa_keygen(),
      scopes = "openid"
    )
    work <- authorization_deferred_work()
    published <- 0L
    testthat::local_mocked_bindings(
      async_dispatch = function(expr, args, ...) {
        work$expr <- expr
        work$args <- args
        work$promise
      },
      publish_shiny_request_object = function(...) {
        published <<- published + 1L
        "https://app.example.com/request"
      },
      .package = "shinyOAuth"
    )
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = cli,
        async = TRUE,
        auto_redirect = FALSE,
        request_uri_base_url = "https://app.example.com"
      ),
      expr = {
        answer <- NULL
        promises::then(values$build_auth_url(), function(value) {
          answer <<- value
        })
        built <- eval(work$expr, list2env(work$args, parent = globalenv()))
        expect_identical(published, 0L)
        expect_true(is.character(built$request_object))
        if (logout) {
          values$logout()
        }
        work$resolve(built)
        poll_for_async(function() !is.null(answer), session)
        expect_identical(published, if (logout) 0L else 1L)
        if (logout) {
          expect_true(is.na(answer))
        } else {
          expect_match(answer, "request_uri=")
        }
      }
    )
  }
})

test_that("async JARM defers signatures and preserves state until valid completion", {
  skip_if_not_installed("promises")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  for (logout in c(FALSE, TRUE)) {
    prov <- make_test_provider(use_nonce = FALSE)
    prov@issuer <- "https://example.com"
    prov@response_modes_supported <- "query.jwt"
    prov@jarm_signing_alg_values_supported <- "RS256"
    cli <- oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      response_mode = "query.jwt",
      jarm_signed_response_alg = "RS256",
      scopes = "openid"
    )
    work <- authorization_deferred_work()
    signatures <- 0L
    testthat::local_mocked_bindings(
      async_dispatch = function(expr, args, ...) {
        work$expr <- expr
        work$args <- args
        work$promise
      },
      verify_jarm_signature = function(...) {
        signatures <<- signatures + 1L
        TRUE
      },
      .package = "shinyOAuth"
    )
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = cli,
        async = TRUE,
        auto_redirect = FALSE
      ),
      expr = {
        url <- values$build_auth_url()
        state <- parse_query_param(url, "state", decode = TRUE)
        payload <- shinyOAuth:::state_decrypt_gcm(state, cli@state_key)
        key <- shinyOAuth:::state_cache_key(payload$state)
        jwt <- jose::jwt_encode_sig(
          jose::jwt_claim(
            iss = prov@issuer,
            aud = "abc",
            exp = as.numeric(Sys.time()) + 120,
            state = state,
            error = "access_denied"
          ),
          key = openssl::rsa_keygen(),
          header = list(alg = "RS256")
        )
        values$.process_query(paste0("?response=", jwt))
        expect_identical(signatures, 0L)
        expect_false(is.null(cli@state_store$get(key, missing = NULL)))
        if (logout) {
          values$logout()
        }
        work$resolve(eval(work$expr, list2env(work$args, parent = globalenv())))
        poll_for_async(function() !is.null(values$error), session)
        session$flushReact()
        expect_identical(signatures, 1L)
        if (logout) {
          expect_identical(values$error, "logged_out")
          expect_false(is.null(cli@state_store$get(key, missing = NULL)))
        } else {
          expect_identical(values$error, "access_denied")
          expect_null(cli@state_store$get(key, missing = NULL))
        }
      }
    )
  }
})

for (backend in c("mirai", "future")) {
  test_that(paste("PAR HTTP work leaves the Shiny event loop using", backend), {
    skip_on_cran()
    skip_if_not_installed("mirai")
    skip_if_not_installed("webfakes")
    mirai::daemons(1)
    withr::defer(mirai::daemons(0))
    assert_shinyoauth_available_in_daemon()
    if (backend == "future") {
      skip_if_not_installed("future")
      mirai::daemons(0)
      old_plan <- future::plan()
      withr::defer(future::plan(old_plan))
      future::plan(future::multisession, workers = I(1))
      expect_false(identical(
        future::value(future::future(Sys.getpid())),
        Sys.getpid()
      ))
    }

    withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
    gate <- tempfile("authorization-returned-")
    withr::defer(unlink(gate))
    app <- webfakes::new_app()
    app$post(
      "/par",
      eval(substitute(
        function(req, res) {
          # The provider cannot succeed until the main Shiny call has returned.
          deadline <- Sys.time() + 10
          while (!file.exists(GATE) && Sys.time() < deadline) {
            Sys.sleep(0.05)
          }
          if (!file.exists(GATE)) {
            return(res$set_status(503L)$send("Main process blocked"))
          }
          res$set_status(201L)$set_type("application/json")$send(
            '{"request_uri":"urn:test:par","expires_in":60}'
          )
        },
        list(GATE = gate)
      ))
    )
    server <- webfakes::local_app_process(app)
    cli <- make_test_client(use_nonce = FALSE)
    cli@provider@par_url <- paste0(server$url(), "par")
    dispatch <- shinyOAuth:::async_dispatch
    testthat::local_mocked_bindings(
      async_dispatch = function(expr, args, ...) {
        wrapped <- bquote({
          answer <- .(expr)
          attr(answer, "worker_pid") <- Sys.getpid()
          answer
        })
        dispatch(wrapped, args, ...)
      },
      .package = "shinyOAuth"
    )
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = cli,
        async = TRUE,
        auto_redirect = FALSE
      ),
      expr = {
        result <- values$build_auth_url()
        expect_true(file.create(gate))
        answer <- NULL
        promises::then(result, function(value) {
          answer <<- value
        })
        poll_for_async(function() !is.null(answer), session)
        expect_true(is.null(values$error), info = values$error_description)
        expect_match(answer, "request_uri")
        expect_false(identical(attr(answer, "worker_pid"), Sys.getpid()))
        expect_type(attr(answer, "worker_pid"), "integer")
      }
    )
  })
}
