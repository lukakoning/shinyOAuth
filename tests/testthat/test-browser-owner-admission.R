test_that("abandoned HTML requests do not exhaust retained owner capacity", {
  f <- manager_test_fixture(owner = oauth_browser_owner(max_entries = 3L))
  for (i in seq_len(12L)) {
    expect_equal(f[["ui"]](manager_test_request())[["status"]], 200L)
  }
  cookie <- manager_test_cookie(f)
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f[["manager"]]),
    session = manager_test_session(cookie),
    {
      id <- manager_test_accept(controller)
      health <- session[["getReturned"]]()
      for (i in seq_len(12L)) {
        expect_equal(f[["ui"]](manager_test_request())[["status"]], 200L)
      }
      expect_true(health[["connection"]](id)[["is_usable"]]())
    }
  )
})

test_that("provisional owners are bounded and promotion enforces retained capacity", {
  time <- 1000
  registry <- connection_browser_sessions(
    oauth_browser_owner(),
    "https://app.example",
    "health",
    openssl::rand_bytes(32L),
    max_entries = 1L,
    clock = function() time
  )
  first <- registry[["create"]](provisional = TRUE)
  second <- registry[["create"]](provisional = TRUE)
  expect_null(registry[["resolve"]](first[["cookie"]]))
  expect_error(registry[["retain"]](first[["owner"]]), "unavailable")
  expect_identical(registry[["retain"]](second[["owner"]]), second[["owner"]])
  third <- registry[["create"]](provisional = TRUE)
  expect_error(registry[["retain"]](third[["owner"]]), "capacity")
  expect_identical(registry[["resolve"]](second[["cookie"]]), second[["owner"]])
  time <- 1299
  registry[["resolve"]](third[["cookie"]], touch = TRUE)
  rotated <- registry[["rotate"]](third[["owner"]])
  time <- 1300
  expect_null(registry[["resolve"]](rotated[["cookie"]]))
  expect_identical(registry[["resolve"]](second[["cookie"]]), second[["owner"]])
  expect_true(registry[["revoke"]](second[["owner"]]))
  fourth <- registry[["create"]](provisional = TRUE)
  expect_identical(registry[["retain"]](fourth[["owner"]]), fourth[["owner"]])
})
