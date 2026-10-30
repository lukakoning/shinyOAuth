# shinyOAuth-browser-suite

test_that("retention fixtures avoid blocked ports and provider startup collisions", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  helper <- test_path(
    "..",
    "..",
    "integration",
    "connections",
    "helper-browser.R"
  )
  skip_if_not(file.exists(helper), "Integration helper unavailable")
  original_random_port <- httpuv::randomPort
  ephemeral_port <- original_random_port(min = 49152L, max = 65535L)
  # Port 10080 is absent from httpuv 1.6.17's exclusions but is blocked by
  # Chrome. Force that otherwise valid random selection deterministically.
  local_mocked_bindings(
    randomPort = function(min = 1024L, max = 49151L, ...) {
      if (missing(min) && missing(max)) {
        10080L
      } else if (min >= 49152L) {
        ephemeral_port
      } else {
        original_random_port(min, max, ...)
      }
    },
    .package = "httpuv"
  )
  source(helper, local = TRUE)
  retention_root <- withr::local_tempdir()
  writeLines(
    c(
      "startup_app <- function(origin, providers, async, response_mode) {",
      "  shiny::runApp(shiny::shinyApp(",
      "    ui = shiny::fluidPage(shiny::verbatimTextOutput('snapshot')),",
      "    server = function(input, output, session) {",
      "      output[['snapshot']] <- shiny::renderText('{\"ready\":true}')",
      "    }),",
      "    host = '127.0.0.1',",
      "    port = as.integer(httr2::url_parse(origin)[['port']]),",
      "    launch.browser = FALSE)",
      "}"
    ),
    file.path(retention_root, "app.R")
  )
  provider_server <- NULL
  withr::defer(
    if (!is.null(provider_server)) httpuv::stopServer(provider_server)
  )
  fixture <- retention_browser_setup(
    async = FALSE,
    provider_factory = function(site, callback) {
      # Simulate provider startup claiming an ephemeral port after selection
      # but before the app binds it, as an outgoing connection can do on CI.
      if (is.null(provider_server)) {
        provider_server <<- httpuv::startServer(
          "127.0.0.1",
          ephemeral_port,
          list(call = function(req) {
            list(status = 503L, headers = list(), body = "")
          })
        )
      }
      list(url = function() "http://127.0.0.1:12345", stop = function() NULL)
    },
    app_script = "app.R",
    app_function = "startup_app"
  )
  expect_identical(
    retention_browser_snapshot(fixture[["browser"]]),
    list(ready = TRUE)
  )
})

test_that("retention startup errors include the child process diagnostic", {
  helper <- test_path(
    "..",
    "..",
    "integration",
    "connections",
    "helper-browser.R"
  )
  skip_if_not(file.exists(helper), "Integration helper unavailable")
  source(helper, local = TRUE)
  retention_root <- withr::local_tempdir()
  writeLines(
    "startup_app <- function(...) stop('synthetic fixture startup failure')",
    file.path(retention_root, "app.R")
  )
  expect_error(
    retention_browser_setup(
      async = FALSE,
      provider_factory = function(site, callback) {
        list(url = function() "http://127.0.0.1:12345", stop = function() NULL)
      },
      app_script = "app.R",
      app_function = "startup_app"
    ),
    "Retention fixture did not start.*exit status.*[\\s\\S]*synthetic fixture startup failure"
  )
})
