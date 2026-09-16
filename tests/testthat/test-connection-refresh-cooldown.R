test_that("automatic retry cooldown follows shared credentials across records and owners", {
  clock <- new.env(parent = emptyenv())
  clock[["now"]] <- Sys.time()
  local_mocked_bindings(Sys.time = function() clock[["now"]], .package = "base")
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  attempts <- list()
  local_mocked_bindings(req_with_retry = function(req, ...) {
    attempts[[length(attempts) + 1L]] <<- clock[["now"]]
    httr2::response(
      url = req[["url"]],
      status = 503L,
      headers = list("content-type" = "application/json"),
      body = charToRaw('{"error":"temporarily_unavailable"}')
    )
  })
  token <- manager_test_token(refresh = "shared-refresh")
  token@expires_at <- as.numeric(clock[["now"]]) + 45
  args <- list(
    id = "health",
    manager = f[["manager"]],
    refresh_proactively = TRUE,
    refresh_check_interval_ms = 100
  )
  shiny::testServer(
    oauth_connections_server,
    args = args,
    session = manager_test_session(cookie),
    {
      for (i in 1:3) {
        manager_test_accept(controller, token = token)
      }
      session[["flushReact"]]()
      expect_length(attempts, 1L)
      expect_true(all(vapply(
        controller[["records"]](),
        function(row) row[["status"]] == "active",
        logical(1)
      )))
      clock[["now"]] <- clock[["now"]] + 29
      session[["elapse"]](100)
      expect_length(attempts, 1L)
      clock[["now"]] <- clock[["now"]] + 1
      session[["elapse"]](100)
      expect_length(attempts, 2L)
      expect_equal(
        as.numeric(difftime(attempts[[2L]], attempts[[1L]], units = "secs")),
        30
      )
    }
  )
  for (owner_cookie in c(cookie, manager_test_cookie(f))) {
    shiny::testServer(
      oauth_connections_server,
      args = args,
      session = manager_test_session(owner_cookie),
      {
        manager_test_accept(controller, token = token)
        session[["flushReact"]]()
        expect_length(attempts, 2L)
      }
    )
  }
  shiny::testServer(
    oauth_connections_server,
    args = args,
    session = manager_test_session(cookie),
    {
      # The same bytes under a separate OAuth registration are independent.
      manager_test_accept(controller, "b", token)
      separate <- token
      separate@refresh_token <- "independent-refresh"
      manager_test_accept(controller, token = separate)
      session[["flushReact"]]()
      expect_length(attempts, 4L)
      # Explicit user refresh remains available during automatic backoff.
      id <- controller[["records"]]()[[1L]][["stored"]][["id"]]
      expect_error(
        session[["getReturned"]]()[["connection"]](id)[["refresh"]](),
        "Connection refresh failed"
      )
      expect_length(attempts, 5L)
    }
  )
})

test_that("queued automatic refreshes recheck the cooldown after asynchronous failure", {
  f <- manager_test_fixture()
  calls <- 0L
  reject_refresh <- NULL
  local_mocked_bindings(refresh_token_impl = function(...) {
    calls <<- calls + 1L
    promises::promise(function(resolve, reject) {
      reject_refresh <<- reject
    })
  })
  shiny::testServer(
    session = manager_test_session(manager_test_cookie(f)),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      a <- manager_test_accept(ctl)
      b <- manager_test_accept(ctl)
      failed <- resumed <- NULL
      promises::catch(
        ctl[["refresh"]](a, async = TRUE, touch = FALSE),
        function(e) {
          failed <<- e
        }
      )
      promises::then(
        ctl[["refresh"]](b, async = TRUE, touch = FALSE),
        function(value) {
          resumed <<- value
        },
        function(e) {
          resumed <<- e
        }
      )
      reject_refresh(refresh_outcome_error(
        simpleError("provider unavailable"),
        "not_consumed"
      ))
      poll_for_async(
        function() !is.null(failed) && (!is.null(resumed) || calls > 1L),
        session
      )
      expect_false(resumed)
      expect_identical(calls, 1L)
      expect_identical(ctl[["read"]](a)[["status"]], "active")
      expect_identical(ctl[["read"]](b)[["status"]], "active")
    }
  )
})
