test_that("origin records are required, expire, rotate and fail closed", {
  skip_if(Sys.which("node") == "")
  output <- system2(
    Sys.which("node"),
    c(
      shQuote(test_path("..", "browser-origin-binding.cjs")),
      shQuote(system.file("www", "shinyOAuth.js", package = "shinyOAuth"))
    ),
    stdout = TRUE,
    stderr = TRUE
  )
  expect_null(attr(output, "status"), info = paste(output, collapse = "\n"))
})

test_that("unavailable origin storage stops login before state creation", {
  withr::local_options(shinyOAuth.skip_browser_token = FALSE)
  client <- make_test_client(use_nonce = FALSE)
  shiny::testServer(oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE), {
      session$flushReact()
      values$request_login()
      session$setInputs(shinyOAuth_cookie_error = "storage_unavailable")
      poll_for_async(function() !values$pending_login, session)
      expect_identical(values$error, "browser_cookie_error")
      expect_match(values$error_description, "storage_unavailable", fixed = TRUE)
      expect_length(client@state_store$keys(), 0L)
    }
  )
})
