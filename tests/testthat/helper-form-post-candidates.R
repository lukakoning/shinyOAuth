# Exercise response isolation through the POST boundary and two independent
# Shiny sessions. All responses and token exchanges are local test fixtures.
expect_form_post_candidate_isolation <- function(
  client,
  post_candidate,
  first_error = FALSE,
  follow_first = FALSE,
  final_error = FALSE
) {
  withr::local_options(list(shinyOAuth.skip_browser_token = FALSE))
  browser <- valid_browser_token()
  url <- prepare_call(client, browser_token = browser)
  state <- parse_query_param(url, "state", decode = TRUE)
  state_payload <- shinyOAuth:::state_payload_decrypt_validate(client, state)
  stored_state <- shinyOAuth:::state_store_get(client, state_payload$state)
  first_fields <- if (first_error) {
    list(error = "access_denied")
  } else {
    list(code = "earlier-response")
  }
  final_fields <- if (final_error) {
    list(error = "access_denied", error_description = "Browser declined")
  } else {
    list(code = "browser-response")
  }
  first <- post_candidate(c(first_fields, list(state = state)))
  second <- post_candidate(c(final_fields, list(state = state)))
  expect_identical(first$status, 303L)
  expect_identical(second$status, 303L)
  expect_false(identical(first$headers$Location, second$headers$Location))
  first_handle <- parse_query_param(
    first$headers$Location,
    "shinyOAuth_form_post",
    decode = TRUE
  )
  second_handle <- parse_query_param(
    second$headers$Location,
    "shinyOAuth_form_post",
    decode = TRUE
  )

  exchanges <- 0L
  testthat::local_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      exchanges <<- exchanges + 1L
      expect_identical(code, "browser-response")
      expect_identical(code_verifier, stored_state$pkce_code_verifier)
      list(
        access_token = "browser-access",
        token_type = "Bearer",
        expires_in = 3600
      )
    },
    .package = "shinyOAuth"
  )

  args <- list(
    id = "auth",
    client = client,
    auto_redirect = FALSE,
    indefinite_session = TRUE
  )
  if (follow_first) {
    shiny::testServer(oauth_module_server, args = args, expr = {
      values$browser_token <- paste(rep("cd", 64), collapse = "")
      values$.process_query(first$headers$Location)
      session$flushReact()
      expect_false(isTRUE(values$authenticated))
      expect_identical(values$error, "invalid_state")
      expect_match(values$error_description, "Browser token mismatch")
    })
    expect_identical(exchanges, 0L)
    expect_silent(shinyOAuth:::state_store_get(client, state_payload$state))
    expect_false(is.null(client@state_store$get(
      shinyOAuth:::oauth_form_post_cache_key("auth", second_handle),
      missing = NULL
    )))
  }

  shiny::testServer(oauth_module_server, args = args, expr = {
    # Also exercise deferred processing until the initiating browser's cookie
    # arrives; the candidate must survive without becoming a transaction slot.
    values$.process_query(second$headers$Location)
    session$flushReact()
    expect_false(is.null(values$pending_callback))
    values$browser_token <- browser
    session$flushReact()
    if (final_error) {
      expect_false(isTRUE(values$authenticated))
      expect_identical(values$error, "access_denied")
      expect_identical(values$error_description, "Browser declined")
    } else {
      expect_true(isTRUE(values$authenticated))
      expect_null(values$error)
      expect_identical(values$token@access_token, "browser-access")
    }
  })
  expect_identical(exchanges, if (final_error) 0L else 1L)
  expect_null(client@state_store$get(
    shinyOAuth:::state_cache_key(state_payload$state),
    missing = NULL
  ))
  for (handle in c(first_handle, second_handle)) {
    expect_error(
      shinyOAuth:::oauth_form_post_store_take(client, "auth", handle),
      "missing or already consumed"
    )
  }
  expect_identical(
    post_candidate(c(final_fields, list(state = state)))$status,
    400L
  )
}
