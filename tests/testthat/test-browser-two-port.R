# shinyOAuth-browser-suite

test_that("HTTPS ports share cookie markers but cannot adopt each other's bindings", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  skip_if(Sys.which("node") == "")
  server <- processx::process$new(Sys.which("node"), c(
    test_path("..", "browser-two-port-server.cjs"),
    system.file("www", "shinyOAuth.js", package = "shinyOAuth"),
    test_path("fixtures", "mtls", "client-cert.pem"),
    test_path("fixtures", "mtls", "client-key.pem")
  ), stdout = "|", stderr = "|")
  on.exit(server$kill(), add = TRUE)
  server$poll_io(5000)
  ports <- jsonlite::fromJSON(server$read_output_lines()[[1]])
  first <- chromote::ChromoteSession$new()
  second <- chromote::ChromoteSession$new()
  on.exit(first$close(), add = TRUE)
  on.exit(second$close(), add = TRUE)
  first$Security$setIgnoreCertificateErrors(ignore = TRUE)
  second$Security$setIgnoreCertificateErrors(ignore = TRUE)
  first$go_to(paste0("https://127.0.0.1:", ports[[1]]))
  second$go_to(paste0("https://127.0.0.1:", ports[[2]]))
  evaluate <- function(browser, script) browser$Runtime$evaluate(
    script, returnByValue = TRUE, awaitPromise = TRUE
  )$result$value
  payload <- list(instance = "auth", path = "/app", maxAgeMs = 60000,
    inputId = "sid", errorInputId = "error")
  send <- function(browser, payload) evaluate(browser, paste0(
    "Shiny.handlers['shinyOAuth:setBrowserToken'](",
    jsonlite::toJSON(payload, auto_unbox = TRUE), "); window.inputs.sid"
  ))
  initial <- send(first, payload)
  expect_match(initial, "^[a-f0-9]{128}$")
  read_marker <- paste0("document.cookie.split('; ').find(v => ",
    "v.startsWith('__Host-shinyOAuth_sid-auth='))")
  marker <- evaluate(first, read_marker)
  expect_match(marker, "^__Host-shinyOAuth_sid-auth=")
  expect_false(grepl(initial, marker, fixed = TRUE))
  expect_identical(evaluate(second, read_marker), marker)
  received <- evaluate(second, "fetch('/cookie').then(r => r.json()).then(r => r.cookie)")
  expect_true(grepl(marker, received, fixed = TRUE))
  expect_false(grepl(initial, received, fixed = TRUE))
  expect_null(evaluate(second, "localStorage.getItem('__Host-shinyOAuth_sid-auth:binding')"))

  # Another origin can replace the cookie with its own valid marker. Its
  # actual binding stays local to that origin, and cannot be restored here.
  other <- send(second, payload)
  other_marker <- evaluate(second, read_marker)
  expect_false(identical(initial, other))
  expect_false(identical(marker, other_marker))
  expect_identical(evaluate(first, read_marker), other_marker)
  restored <- send(first, payload)
  expect_false(restored %in% c(initial, other, sub("^[^=]+=", "", other_marker)))
  expect_identical(send(first, payload), restored)
  # The origin record must also survive a real navigation back from an IdP.
  first$go_to(paste0("https://127.0.0.1:", ports[[2]]))
  first$go_to(paste0("https://127.0.0.1:", ports[[1]]))
  expect_identical(send(first, payload), restored)
})
