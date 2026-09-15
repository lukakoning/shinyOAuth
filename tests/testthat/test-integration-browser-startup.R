# shinyOAuth-browser-suite

integration_browser_helpers <- function() {
  path <- test_path("../../integration/connections/helper-browser.R")
  skip_if_not(
    file.exists(path),
    "Integration helper unavailable in installed tests"
  )
  env <- new.env(parent = globalenv())
  sys.source(path, envir = env)
  env
}

test_that("browser startup retries one debugging-port timeout", {
  helpers <- integration_browser_helpers()
  withr::local_options(chromote.timeout = 10)
  calls <- 0L
  browser <- new.env(parent = emptyenv())
  local_mocked_bindings(
    Chromote = list(new = function() {
      calls <<- calls + 1L
      expect_identical(getOption("chromote.timeout"), 30)
      if (calls == 1L) {
        rlang::abort("Port timed out", class = "error_stop_port_search")
      }
      browser
    }),
    .package = "chromote"
  )
  expect_message(
    result <- helpers[["retention_chrome_start"]](),
    "retrying browser startup once"
  )
  expect_identical(result, browser)
  expect_identical(calls, 2L)
  expect_identical(getOption("chromote.timeout"), 10)
})

test_that("persistent startup timeouts and configuration errors still fail", {
  helpers <- integration_browser_helpers()
  for (kind in c("error_stop_port_search", "configuration_error")) {
    local({
      calls <- 0L
      local_mocked_bindings(
        Chromote = list(new = function() {
          calls <<- calls + 1L
          rlang::abort("Cannot launch browser", class = kind)
        }),
        .package = "chromote"
      )
      suppressMessages(expect_error(
        helpers[["retention_chrome_start"]](),
        class = kind
      ))
      expect_identical(calls, if (kind == "error_stop_port_search") 2L else 1L)
    })
  }
})

test_that("the integration helper starts and stops a real Chrome process", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  helpers <- integration_browser_helpers()
  chrome <- helpers[["retention_chrome_start"]]()
  process <- chrome[["get_browser"]]()[["get_process"]]()
  withr::defer(
    if (process[["is_alive"]]()) helpers[["retention_chrome_close"]](chrome)
  )
  expect_true(process[["is_alive"]]())
  expect_match(chrome[["Browser"]][["getVersion"]]()[["product"]], "Chrome")
  helpers[["retention_chrome_close"]](chrome)
  expect_false(process[["is_alive"]]())
})
