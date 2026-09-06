test_that("OAuth UI protects HTML and preserves custom response semantics", {
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/",
    QUERY_STRING = "theme=light"
  )
  response <- oauth_ui(shiny::fluidPage(shiny::h2("App")))(req)
  expect_identical(response$headers[["Referrer-Policy"]], "no-referrer")
  expect_identical(response$headers[["Cache-Control"]], "no-store")
  expect_identical(response$headers[["Pragma"]], "no-cache")
  expect_match(response$content, "shinyOAuth.js", fixed = TRUE)
  custom <- shiny::httpResponse(
    201L,
    content = "<html>custom</html>",
    headers = list("referrer-policy" = "unsafe-url", "X-Custom" = "yes")
  )
  response <- oauth_ui(function() custom)(req)
  expect_identical(response$status, 201L)
  expect_identical(response$content, custom$content)
  expect_identical(response$headers[["Referrer-Policy"]], "no-referrer")
  expect_identical(response$headers[["X-Custom"]], "yes")
  expect_null(oauth_ui(function(req) NULL)(req))
})

test_that("callback asset requests send no Referer in a real browser", {
  skip_if_not_installed("chromote")
  skip_if_not_installed("webfakes")
  skip_if(Sys.getenv("SHINYOAUTH_BROWSER_TESTS") != "true")
  dep <- htmltools::htmlDependency(
    "referrer-probe",
    "1.0",
    src = c(href = "/assets"),
    script = "probe.js"
  )
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/",
    QUERY_STRING = "theme=light"
  )
  response <- oauth_ui(shiny::fluidPage(use_shinyOAuth(), dep))(req)
  app <- webfakes::new_app()
  app$locals$html <- response$content
  app$locals$policy <- response$headers[["Referrer-Policy"]]
  app$get("/", function(req, res) {
    res$set_header("Referrer-Policy", app$locals$policy)$set_type(
      "text/html"
    )$send(app$locals$html)
  })
  app$get("/assets/probe.js", function(req, res) {
    referrer <- req$get_header("referer")
    if (is.null(referrer)) {
      referrer <- ""
    }
    res$set_type("application/javascript")$send(paste0(
      "window.probeReferrer = ",
      jsonlite::toJSON(referrer, auto_unbox = TRUE),
      ";"
    ))
  })
  srv <- webfakes::local_app_process(app)
  browser <- chromote::ChromoteSession$new()
  withr::defer(browser$close())
  loaded <- browser$Page$loadEventFired(wait_ = FALSE)
  browser$Page$navigate(srv$url("/?theme=light"))
  browser$wait_for(loaded)
  observed <- browser$Runtime$evaluate("window.probeReferrer")$result$value
  expect_identical(observed, "")
})
# shinyOAuth-browser-suite
