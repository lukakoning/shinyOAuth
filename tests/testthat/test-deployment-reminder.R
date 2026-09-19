test_that("Connect reminder warns once per R process", {
  withr::local_envvar(c(
    POSIT_PRODUCT = "CONNECT_CLOUD",
    RSTUDIO_PRODUCT = NA_character_
  ))
  withr::local_options(rlib_warning_verbosity = "default")
  local_mocked_bindings(.is_test = function() FALSE)

  expect_warning(
    warn_about_browser_deployment(),
    "Open your Posit Connect app at its direct URL"
  )
  expect_no_warning(warn_about_browser_deployment())
})

test_that("current and legacy Posit markers select the deployment reminder", {
  local_mocked_bindings(.is_test = function() FALSE)
  withr::local_options(rlib_warning_verbosity = "verbose")

  for (markers in list(
    c(POSIT_PRODUCT = "CONNECT_CLOUD", RSTUDIO_PRODUCT = NA_character_),
    c(POSIT_PRODUCT = "CONNECT", RSTUDIO_PRODUCT = NA_character_),
    c(POSIT_PRODUCT = NA_character_, RSTUDIO_PRODUCT = "CONNECT")
  )) {
    withr::with_envvar(markers, {
      warning <- expect_warning(
        warn_about_browser_deployment(),
        "Open your Posit Connect app at its direct URL"
      )
      text <- conditionMessage(warning)
      expect_match(text, "Settings > URL", fixed = TRUE)
      expect_match(text, "new browser tab or window", fixed = TRUE)
    })
  }
})

test_that("other environments retain the general browser reminder", {
  local_mocked_bindings(.is_test = function() FALSE)
  withr::local_options(rlib_warning_verbosity = "verbose")
  # Local API credentials alone are not evidence that an app runs on Connect.
  withr::local_envvar(c(CONNECT_SERVER = "https://connect.example.com"))

  for (product in c(NA_character_, "", "WORKBENCH", "CONNECT_OTHER")) {
    withr::with_envvar(
      c(POSIT_PRODUCT = product, RSTUDIO_PRODUCT = NA_character_),
      expect_warning(
        warn_about_browser_deployment(),
        "Open your Shiny app in a regular browser"
      )
    )
  }
})

test_that("deployment reminder stays quiet during tests", {
  withr::local_envvar(c(POSIT_PRODUCT = "CONNECT_CLOUD"))
  withr::local_options(rlib_warning_verbosity = "verbose")
  expect_no_warning(warn_about_browser_deployment())
})

test_that("the Shiny module invokes the browser deployment reminder", {
  calls <- 0L
  local_mocked_bindings(warn_about_browser_deployment = function() {
    calls <<- calls + 1L
  })
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)

  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = make_test_client(),
      auto_redirect = FALSE
    ),
    expr = {}
  )
  expect_equal(calls, 1L)
})
