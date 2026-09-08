# shinyOAuth-browser-suite

test_that("real tabs and same-origin applications retain independent pending bindings", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  skip_if(Sys.which("node") == "")
  server <- processx::process$new(Sys.which("node"), c(
    test_path("..", "browser-two-port-server.cjs"),
    system.file("www", "shinyOAuth.js", package = "shinyOAuth"),
    mtls_pem_fixture("server-cert.pem"), mtls_pem_fixture("client-key.pem")
  ), stdout = "|", stderr = "|")
  withr::defer(server$kill())
  server$poll_io(5000)
  ports <- jsonlite::fromJSON(server$read_output_lines()[[1]])
  origin <- paste0("https://127.0.0.1:", ports[[1]])
  idp <- paste0("https://127.0.0.1:", ports[[2]])
  first <- chromote::ChromoteSession$new()
  second <- chromote::ChromoteSession$new()
  withr::defer(first$close())
  withr::defer(second$close())
  for (browser in list(first, second)) {
    browser$Security$setIgnoreCertificateErrors(ignore = TRUE)
    browser$go_to(paste0(origin, "/app-a"))
  }
  evaluate <- function(browser, script) browser$Runtime$evaluate(
    script, returnByValue = TRUE, awaitPromise = TRUE
  )$result$value
  # Confirm these tabs really share the same origin's local storage/cookie jar.
  evaluate(first, "localStorage.setItem('shared-fixture', 'yes')")
  expect_identical(evaluate(second, "localStorage.getItem('shared-fixture')"), "yes")
  instance <- function(app) build_oauth_module_browser_token_instance(
    list(ns = function(x) paste0("auth-", x)), "auth", paste0(origin, "/", app)
  )
  send <- function(browser, app = "app-a", token = NULL, clear = FALSE) {
    payload <- list(instance = instance(app), path = "/", maxAgeMs = 60000,
                    inputId = "sid", ackInputId = "ack", errorInputId = "error")
    if (!is.null(token)) {
      payload$token <- token
      if (!clear) payload$requestId <- paste0("request-", substr(token, 1L, 1L))
    }
    evaluate(browser, paste0("Shiny.handlers['shinyOAuth:",
      if (clear) "clearBrowserToken" else "setBrowserToken", "'](",
      jsonlite::toJSON(payload, auto_unbox = TRUE), "); window.inputs.sid"))
  }
  a <- paste(rep("a", 128), collapse = "")
  b <- paste(rep("b", 128), collapse = "")
  c <- paste(rep("c", 128), collapse = "")
  expect_identical(send(first, token = a), a)
  expect_identical(send(second, token = b), b)
  first$go_to(idp)
  second$go_to(idp)
  # Complete callbacks in reverse order, including the post-login reissue.
  second$go_to(paste0(origin, "/app-a?code=second"))
  expect_identical(send(second), b)
  send(second, token = b, clear = TRUE)
  send(second)
  first$go_to(paste0(origin, "/app-a?code=first"))
  expect_identical(send(first), a)
  # Logout in one tab leaves the other tab's pending login intact.
  send(second, token = b)
  send(first, token = a, clear = TRUE)
  expect_identical(send(second), b)
  # Two applications with the same module ID also coexist in one tab.
  send(first, token = a)
  first$go_to(paste0(origin, "/app-b"))
  expect_identical(send(first, "app-b", c), c)
  send(first, "app-b", c, clear = TRUE)
  first$go_to(paste0(origin, "/app-a"))
  expect_identical(send(first), a)
  # A delayed clear for an older transaction cannot clear its replacement.
  send(first, token = c)
  send(first, token = a, clear = TRUE)
  expect_identical(send(first), c)
})
