test_that("missing UI setup recommends complete wrappers", {
  local_mocked_bindings(
    .watchdog_environment = new.env(parent = emptyenv()),
    .is_test = function() FALSE
  )
  withr::local_options(rlib_warning_verbosity = "verbose")

  warning <- expect_warning(
    warn_about_missing_js_dependency(),
    "shinyOAuth browser setup not detected"
  )
  text <- conditionMessage(warning)
  expect_match(text, 'oauth_ui(ui, id = "auth", client = client)', fixed = TRUE)
  expect_match(text, "oauth_form_post_ui()", fixed = TRUE)
  expect_match(text, "oauth_connections_ui()", fixed = TRUE)
  expect_match(text, "no separate `use_shinyOAuth()` call is needed", fixed = TRUE)
})

test_that("ordinary and form-post wrappers satisfy the browser setup reminder", {
  client <- make_test_client()
  post_client <- make_test_client(response_mode = "form_post")
  watchdog <- new.env(parent = emptyenv())
  local_mocked_bindings(
    .watchdog_environment = watchdog,
    .is_test = function() FALSE
  )
  withr::local_options(rlib_warning_verbosity = "verbose")
  request <- list(
    REQUEST_METHOD = "GET", PATH_INFO = "/", QUERY_STRING = ""
  )

  for (wrap in list(
    function(ui) oauth_ui(ui, id = "auth", client = client),
    function(ui) oauth_form_post_ui(ui, id = "auth", client = post_client)
  )) {
    watchdog[[".called_js_dependency"]] <- FALSE
    response <- wrap(shiny::fluidPage("App"))(request)
    expect_match(response[["content"]], "shinyOAuth.js", fixed = TRUE)
    expect_no_warning(warn_about_missing_js_dependency())
  }
})

test_that("connection manager supplies browser setup without the low-level helper", {
  local_mocked_bindings(.watchdog_environment = new.env(parent = emptyenv()))
  fixture <- manager_test_fixture(retention = "shiny")
  local_mocked_bindings(.is_test = function() FALSE)
  withr::local_options(rlib_warning_verbosity = "verbose")

  response <- fixture[["ui"]](manager_test_request())
  expect_match(response[["content"]], "shinyOAuth.js", fixed = TRUE)
  expect_no_warning(warn_about_missing_js_dependency())
})

test_that("custom integrations can still supply the browser dependency directly", {
  local_mocked_bindings(
    .watchdog_environment = new.env(parent = emptyenv()),
    .is_test = function() FALSE
  )
  withr::local_options(rlib_warning_verbosity = "verbose")

  use_shinyOAuth()
  expect_no_warning(warn_about_missing_js_dependency())
})
