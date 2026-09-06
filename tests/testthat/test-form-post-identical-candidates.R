test_that("identical callback submissions retain independent one-time handles", {
  client <- make_test_client(response_mode = "form_post")
  url <- prepare_call(client, browser_token = valid_browser_token())
  state <- parse_query_param(url, "state", decode = TRUE)
  state_payload <- shinyOAuth:::state_payload_decrypt_validate(client, state)
  payload <- list(
    code = "fixture-code",
    state = state,
    state_payload = state_payload
  )
  initial_count <- length(client@state_store$keys())
  first <- oauth_form_post_store_set(client, "auth", payload)
  second <- oauth_form_post_store_set(client, "auth", payload)
  expect_false(identical(first, second))
  expect_length(client@state_store$keys(), initial_count + 2L)
  for (handle in c(first, second)) {
    expect_identical(
      oauth_form_post_store_take(client, "auth", handle)$code,
      "fixture-code"
    )
    expect_error(
      oauth_form_post_store_take(client, "auth", handle),
      "missing or already consumed"
    )
    expect_silent(shinyOAuth:::state_store_get(client, state_payload$state))
  }
  expect_length(client@state_store$keys(), initial_count)
})
