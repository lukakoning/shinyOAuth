test_that("new visitors cannot evict an owner completing its first authorization", {
  f <- manager_test_fixture(owner = oauth_browser_owner(max_entries = 1L))
  cookie <- manager_test_cookie(f)
  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      hooks <- ctl[["hooks"]]("a")
      pending <- hooks[["prepare"]]()
      response <- f[["ui"]](manager_test_request())
      expect_false(response[["status"]] == 200L)
      expect_true(hooks[["validate"]](pending))
      expect_silent(hooks[["accept"]](
        manager_test_token(),
        pending,
        as.numeric(Sys.time())
      ))
      expect_length(ctl[["records"]](), 1L)
    }
  )
})

test_that("cancelled pending logins release provisional capacity", {
  f <- manager_test_fixture(owner = oauth_browser_owner(max_entries = 1L))
  cookie <- manager_test_cookie(f)
  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      hooks <- ctl[["hooks"]]("a")
      first <- hooks[["prepare"]]()
      second <- hooks[["prepare"]]()
      hooks[["cancel"]](first)
      expect_true(hooks[["validate"]](second))
      expect_false(f[["ui"]](manager_test_request())[["status"]] == 200L)
      hooks[["cancel"]](second)
      expect_equal(f[["ui"]](manager_test_request())[["status"]], 200L)
      expect_error(ctl[["records"]](), "owner is unavailable")
    }
  )
})

test_that("pending owner protection expires and does not override owner limits", {
  at <- 1000
  owners <- connection_browser_sessions(
    oauth_browser_owner(idle_timeout = 600, absolute_timeout = 1200),
    "https://app.example",
    "pending",
    openssl::rand_bytes(32L),
    max_entries = 1L,
    clock = function() at
  )
  first <- owners[["create"]](provisional = TRUE)
  owners[["protect"]](first[["owner"]], "transaction", 1400)
  at <- 1301
  expect_identical(owners[["resolve"]](first[["cookie"]]), first[["owner"]])
  expect_error(owners[["create"]](provisional = TRUE), "capacity")
  at <- 1400
  expect_null(owners[["resolve"]](first[["cookie"]]))
  second <- owners[["create"]](provisional = TRUE)
  owners[["protect"]](second[["owner"]], "transaction", 2500)
  at <- 2000
  expect_null(owners[["resolve"]](second[["cookie"]]))
  third <- owners[["create"]](provisional = TRUE)
  owners[["protect"]](third[["owner"]], "transaction", 3100)
  owners[["revoke"]](third[["owner"]])
  expect_null(owners[["resolve"]](third[["cookie"]]))
  expect_no_error(owners[["create"]](provisional = TRUE))
})
