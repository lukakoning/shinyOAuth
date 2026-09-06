# shinyOAuth-browser-suite

test_that("AppDriver ignores a load event from the initial blank document", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  browser <- chromote::ChromoteSession$new()
  on.exit(browser$close(), add = TRUE)
  browser$go_to("about:blank")

  local_mocked_bindings(
    app_init_browser_log = function(...) invisible(NULL),
    .package = "shinytest2"
  )
  local_app_driver_navigation()
  shinytest2:::app_init_browser_log(
    self = list(get_chromote_session = function() browser),
    private = list(load_timeout = 10000),
    options = list()
  )
  # Load the initial document again so its load event arrives before the
  # destination navigation, as can happen during Chrome startup.
  browser$Page$reload()
  url <- "data:text/html,destination-ready"
  later::later(
    function() browser$Page$navigate(url, wait_ = FALSE),
    delay = 0.1,
    loop = browser$get_child_loop()
  )
  shinytest2:::chromote_eval(
    browser,
    "window.shinyOAuth_navigation_probe = window.location.href"
  )
  expect_identical(
    browser$Runtime$evaluate(
      "window.shinyOAuth_navigation_probe",
      returnByValue = TRUE
    )$result$value,
    url
  )
})

test_that("AppDriver document wait times out when navigation never happens", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  browser <- chromote::ChromoteSession$new()
  on.exit(browser$close(), add = TRUE)
  browser$go_to("about:blank")
  initial <- browser$Page$getFrameTree()$frameTree$frame
  expect_error(
    wait_for_app_driver_document(browser, initial, timeout = 0.1),
    "destination document did not finish loading",
    fixed = TRUE
  )
})

test_that("AppDriver idle failures retain their JavaScript diagnostic", {
  local_mocked_bindings(
    app_abort = function(self, private, message, ...) {
      stop(paste(message, collapse = "\n"), call. = FALSE)
    },
    .package = "shinytest2"
  )
  local_app_driver_navigation()
  fail_idle <- function() {
    ret <- list(
      exceptionDetails = list(
        exception = list(
          description = "ReferenceError: test navigation context was replaced"
        )
      )
    )
    shinytest2:::app_abort(
      list(),
      list(),
      "An error occurred while waiting for Shiny to be stable"
    )
  }
  expect_error(
    fail_idle(),
    "ReferenceError: test navigation context was replaced",
    fixed = TRUE
  )
})
