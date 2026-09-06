test_that("allowed overrides replace protocol parameters case insensitively", {
  withr::local_options(list(shinyOAuth.unblock_auth_params = "redirect_uri"))
  client <- make_test_client()
  client@provider@extra_auth_params <- list(
    REDIRECT_URI = "https://example.com/new"
  )
  url <- prepare_call(client, valid_browser_token())
  expect_identical(lengths(regmatches(url, gregexpr("redirect_uri=", url))), 1L)
  expect_identical(
    parse_query_param(url, "redirect_uri", decode = TRUE),
    "https://example.com/new"
  )
  params <- merge_oauth_extra_params(
    list(redirect_uri = "old", resource = c("a", "b")),
    list(REDIRECT_URI = "new")
  )
  body <- encode_www_form_params(params)
  expect_identical(
    lengths(regmatches(body, gregexpr("redirect_uri=", body))),
    1L
  )
  expect_identical(lengths(regmatches(body, gregexpr("resource=", body))), 2L)
  expect_error(merge_oauth_extra_params(list(), list(x = 1, X = 2)), "unique")
  expect_error(
    merge_oauth_extra_params(
      list(redirect_uri = "old"),
      list(REDIRECT_URI = c("first", "last"))
    ),
    "exactly one value"
  )
})

test_that("transaction and credential fields cannot be unblocked", {
  for (key in immutable_oauth_params()) {
    withr::local_options(list(
      shinyOAuth.unblock_auth_params = key,
      shinyOAuth.unblock_token_params = key
    ))
    extra <- setNames(list("attacker"), key)
    for (field in c("extra_auth_params", "extra_token_params")) {
      args <- c(
        list(
          name = "unsafe",
          auth_url = "https://example.com/auth",
          token_url = "https://example.com/token"
        ),
        setNames(list(extra), field)
      )
      expect_error(do.call(oauth_provider, args), "reserved keys")
    }
  }
})
