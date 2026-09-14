# shinyOAuth-browser-suite

test_that("authorization POST survives named form method collisions in Chrome", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  browser <- chromote::ChromoteSession$new()
  withr::defer(browser$close())
  browser$go_to("about:blank")
  browser$Runtime$evaluate("
    window.Shiny = { handlers: {}, addCustomMessageHandler(name, fn) { this.handlers[name] = fn; } };
    HTMLFormElement.prototype.submit = function() {
      window.submitted = Array.from(new FormData(this), ([name, value]) => ({name, value}));
    };
  ")
  browser$Runtime$evaluate(paste(readLines(
    system.file("www", "shinyOAuth.js", package = "shinyOAuth"), warn = FALSE), collapse = "\n"))
  client <- make_test_client()
  client@authorization_method <- "POST"
  for (names in list("appendChild", "remove", "submit", c("appendChild", "remove", "submit"))) {
    client@provider@extra_auth_params <- c(
      as.list(stats::setNames(rep("provider extension", length(names)), names)),
      list(login_hint = 'A+B & <literal> "quote" é'))
    request <- prepare_authorization_request(client, valid_browser_token())
    result <- browser$Runtime$evaluate(paste0("(() => {
      window.submitted = null;
      Shiny.handlers['shinyOAuth:authorizePost'](", jsonlite::toJSON(request, auto_unbox = TRUE), ");
      return { fields: window.submitted, remainingForms: document.querySelectorAll('form').length };
    })()"), returnByValue = TRUE)
    expect_null(result[["exceptionDetails"]], info = paste(names, collapse = ", "))
    expect_identical(result[["result"]][["value"]][["fields"]], request[["fields"]])
    expect_identical(result[["result"]][["value"]][["remainingForms"]], 0L)
    # Reset the page after each case so a cleanup failure cannot mask another.
    browser$Runtime$evaluate("document.querySelectorAll('form').forEach(form => Element.prototype.remove.call(form))")
  }
})
