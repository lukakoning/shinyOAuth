test_that("malformed cookie escapes are repaired before acknowledgment", {
  skip_if(Sys.which("node") == "")
  output <- system2(Sys.which("node"), c(
    shQuote(test_path("..", "browser-malformed-cookie.cjs")),
    shQuote(system.file("www", "shinyOAuth.js", package = "shinyOAuth"))
  ), stdout = TRUE, stderr = TRUE)
  expect_null(attr(output, "status"), info = paste(output, collapse = "\n"))
})
