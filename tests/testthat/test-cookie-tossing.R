test_that("HTTPS browser bindings ignore sibling-domain cookies at every path", {
  skip_if(Sys.which("node") == "", "Node.js is required for the JS fixture")
  output <- system2(
    Sys.which("node"),
    c(
      shQuote(test_path("..", "browser-cookie-tossing.cjs")),
      shQuote(system.file("www", "shinyOAuth.js", package = "shinyOAuth"))
    ),
    stdout = TRUE,
    stderr = TRUE
  )
  expect_null(attr(output, "status"), info = paste(output, collapse = "\n"))
})
