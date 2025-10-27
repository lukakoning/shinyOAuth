test_that("package loads and basic objects exist", {
  # oauth_provider is exported
  expect_true(is.function(shinyOAuth::oauth_provider))
  p <- shinyOAuth::oauth_provider_github()
  expect_true(S7::S7_inherits(p, shinyOAuth::OAuthProvider))
  c <- shinyOAuth::oauth_client(
    p,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )
  expect_true(S7::S7_inherits(c, shinyOAuth::OAuthClient))
})

test_that("coerce_expires_in converts digit-only strings", {
  f <- get("coerce_expires_in", asNamespace("shinyOAuth"))
  expect_identical(f(NULL), NULL)
  expect_identical(f(3600), 3600)
  expect_identical(f("3600"), 3600)
  expect_identical(f("  7200  "), 7200)
  # Non-digit strings remain unchanged
  expect_identical(f("3600s"), "3600s")
  expect_identical(f("3,600"), "3,600")
})
