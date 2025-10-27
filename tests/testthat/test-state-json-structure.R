test_that("decrypted payload preserves list shape and normalizes scopes", {
  key <- strrep("k", 64)

  payload <- list(
    state = "s-struct",
    client_id = "cid",
    redirect_uri = "http://localhost/cb",
    # Provide scopes as list of length-1 character vectors to mimic odd shapes
    scopes = list(c("openid"), c("profile")),
    provider = "prov-fp",
    issued_at = 1234567890,
    # Field that would be coerced to data.frame with simplifyVector = TRUE
    extras = list(list(k = 1, v = "a"), list(k = 2, v = "b"))
  )

  tok <- shinyOAuth:::state_encrypt_gcm(payload, key = key)
  dec <- shinyOAuth:::state_decrypt_gcm(tok, key = key)

  # extras remains a list-of-lists, not a data.frame
  expect_true(is.list(dec$extras))
  expect_false(is.data.frame(dec$extras))
  expect_identical(names(dec$extras[[1]]), c("k", "v"))

  # scopes normalized to character vector
  expect_true(is.character(dec$scopes))
  expect_identical(dec$scopes, c("openid", "profile"))
})
