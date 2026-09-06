test_that("the mTLS OIDC example validates the end-user identity", {
  candidates <- c(
    test_path("..", "..", "vignettes", "advanced-security.Rmd"),
    system.file("doc", "advanced-security.Rmd", package = "shinyOAuth")
  )
  candidates <- candidates[nzchar(candidates) & file.exists(candidates)]
  skip_if_not(length(candidates) > 0L, "Vignette source unavailable")
  lines <- readLines(candidates[[1L]])
  start <- match("```{r mtls-provider, eval = FALSE}", lines) + 1L
  end <- start + match("```", lines[start:length(lines)]) - 2L
  env <- new.env(parent = environment())
  eval(parse(text = lines[start:end]), env)
  provider <- env$provider
  expect_identical(provider@issuer, "https://id.example.com")
  expect_true(provider@use_nonce)
  expect_true(provider@id_token_required)
  expect_true(provider@id_token_validation)
  expect_true(provider@userinfo_required)
  expect_identical(provider@userinfo_url, "https://id.example.com/userinfo")
  expect_identical(provider@token_auth_style, "tls_client_auth")
})
