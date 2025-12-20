test_that("random_urlsafe produces correct length and charset", {
  x <- shinyOAuth:::random_urlsafe(16)
  expect_type(x, "character")
  expect_equal(nchar(x, type = "bytes"), 16)
  expect_match(x, "^[A-Za-z0-9_-]+$")

  # invalid n
  expect_error(
    shinyOAuth:::random_urlsafe(-1),
    class = "shinyOAuth_input_error"
  )
  expect_error(shinyOAuth:::random_urlsafe(0), class = "shinyOAuth_input_error")
  expect_error(
    shinyOAuth:::random_urlsafe(c(8, 9)),
    class = "shinyOAuth_input_error"
  )
})

test_that("gen_oidc_nonce and validate_oidc_nonce work and enforce constraints", {
  n <- shinyOAuth:::gen_oidc_nonce(24)
  expect_true(shinyOAuth:::validate_oidc_nonce(n) %||% TRUE)
  expect_match(n, "^[A-Za-z0-9._~-]+$")
  expect_true(nchar(n, type = "bytes") >= 22)

  # Too short
  expect_error(
    shinyOAuth:::validate_oidc_nonce("short"),
    class = "shinyOAuth_pkce_error"
  )
  # Invalid chars
  expect_error(
    shinyOAuth:::validate_oidc_nonce("abc!defghijklmnopqrstuvwxyz"),
    class = "shinyOAuth_pkce_error"
  )
  # Type/length issues
  expect_error(
    shinyOAuth:::validate_oidc_nonce(123),
    class = "shinyOAuth_pkce_error"
  )
  expect_error(
    shinyOAuth:::validate_oidc_nonce(c("a", "b")),
    class = "shinyOAuth_pkce_error"
  )
  expect_error(
    shinyOAuth:::validate_oidc_nonce(NA_character_),
    class = "shinyOAuth_pkce_error"
  )
})

test_that("validate_state enforces length and charset, strict mode toggles", {
  ok <- paste0(
    paste(rep("a", 10), collapse = ""),
    paste(rep("b", 12), collapse = "")
  )
  expect_true(shinyOAuth:::validate_state(ok) %||% TRUE)

  # strict base64url allows only [-_A-Za-z0-9]
  expect_true(
    shinyOAuth:::validate_state(
      gsub("b", "_", ok, fixed = TRUE),
      strict_base64url = TRUE
    ) %||%
      TRUE
  )
  # 21 is below the default 22 minimum
  expect_error(
    shinyOAuth:::validate_state(substr(ok, 1, 21)),
    class = "shinyOAuth_pkce_error"
  )
  expect_error(
    shinyOAuth:::validate_state(paste0(ok, "!")),
    class = "shinyOAuth_pkce_error"
  )
  expect_error(
    shinyOAuth:::validate_state(
      "......................",
      strict_base64url = TRUE
    ),
    class = "shinyOAuth_pkce_error"
  )
})

test_that("gen_code_verifier and validate_code_verifier adhere to RFC 7636", {
  v <- shinyOAuth:::gen_code_verifier(64)
  expect_equal(nchar(v, type = "bytes"), 64)
  expect_match(v, "^[A-Za-z0-9._~-]+$")
  expect_true(shinyOAuth:::validate_code_verifier(v) %||% TRUE)

  expect_error(
    shinyOAuth:::gen_code_verifier(30),
    class = "shinyOAuth_pkce_error"
  )
  expect_error(
    shinyOAuth:::validate_code_verifier(paste0(
      "*",
      paste(rep("a", 50), collapse = "")
    )),
    class = "shinyOAuth_pkce_error"
  )
  expect_error(
    shinyOAuth:::validate_code_verifier(paste(rep("a", 42), collapse = "")),
    class = "shinyOAuth_pkce_error"
  )
})

test_that("validate_browser_token can be skipped via option for tests", {
  old <- options(shinyOAuth.skip_browser_token = TRUE)
  on.exit(options(old), add = TRUE)
  expect_invisible(shinyOAuth:::validate_browser_token("__SKIPPED__"))
})

test_that("validate_browser_token rejects uppercase hex tokens", {
  # construct 128-char uppercase hex token
  tok_up <- paste(rep("AB", 64), collapse = "")
  expect_error(
    shinyOAuth:::validate_browser_token(tok_up),
    class = "shinyOAuth_pkce_error"
  )
})
