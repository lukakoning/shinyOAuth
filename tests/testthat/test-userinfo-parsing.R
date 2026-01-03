testthat::test_that("get_userinfo errors consistently on malformed/non-JSON responses and audits", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")

  options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1]] <<- event
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "text/plain"),
        body = charToRaw("this is not json")
      )
    },
    .package = "shinyOAuth"
  )

  testthat::expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "parse|JSON|json"
  )

  # Audit trail should include a userinfo event even though parsing failed
  types <- vapply(events, function(e) e$type %||% NA_character_, character(1))
  testthat::expect_true(any(types == "audit_userinfo"))

  ui_events <- events[types == "audit_userinfo"]
  # Our failure path sets status = "parse_error"
  statuses <- vapply(
    ui_events,
    function(e) e$status %||% NA_character_,
    character(1)
  )
  testthat::expect_true(any(statuses == "parse_error"))
})
