for (already_resolved in c(FALSE, TRUE)) {
  test_that(
    paste(
      "clearing a binding cancels acknowledgment work; resolved",
      already_resolved
    ),
    {
      withr::local_options(shinyOAuth.skip_browser_token = FALSE)
      client <- make_test_client(use_nonce = FALSE)
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          session$flushReact()
          result <- NULL
          promises::then(values$build_auth_url(), function(url) {
            result <<- url
          })
          old_id <- browser_ack$id
          old_token <- browser_ack$token
          old_generation <- browser_ack$generation
          if (already_resolved) {
            browser_ack$resolve(old_token)
          }
          values$clear_browser_token()
          expect_gt(browser_ack$generation, old_generation)
          expect_null(browser_ack$id)
          expect_null(browser_ack$token)
          expect_null(browser_ack$resolve)
          expect_null(browser_ack$reject)
          session$setInputs(
            shinyOAuth_sid = old_token,
            shinyOAuth_cookie_ack = list(requestId = old_id)
          )
          poll_for_async(function() !is.null(result), session)
          expect_identical(result, NA_character_)
          expect_null(values$browser_token)
          expect_null(values$error)
          expect_false(values$pending_login)
          expect_length(client@state_store$keys(), 0L)

          # A deliberate new request can establish a new binding after reset.
          result <- NULL
          promises::then(values$build_auth_url(), function(url) {
            result <<- url
          })
          fresh_id <- browser_ack$id
          fresh_token <- browser_ack$token
          expect_false(identical(fresh_id, old_id))
          session$setInputs(
            shinyOAuth_sid = fresh_token,
            shinyOAuth_cookie_ack = list(requestId = old_id)
          )
          later::run_now()
          expect_null(result)
          session$setInputs(shinyOAuth_cookie_ack = list(requestId = fresh_id))
          poll_for_async(function() !is.null(result), session)
          expect_true(is_valid_string(result))
          expect_identical(values$browser_token, fresh_token)
          expect_length(client@state_store$keys(), 1L)
        }
      )
    }
  )
}
