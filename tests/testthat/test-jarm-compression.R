test_that("encrypted JARM rejects every zip member before decryption", {
  for (zip in list("DEF", "UNKNOWN-COMPRESSION", list("DEF"), NULL, 1, TRUE)) {
    header <- list(
      alg = "RSA-OAEP",
      enc = "A128CBC-HS256",
      cty = "JWT",
      zip = zip
    )
    expect_error(
      validate_encrypted_jarm_protected_header(header, list()),
      "compression.*unsupported",
      class = "shinyOAuth_state_error"
    )
  }
  expect_silent(validate_encrypted_jarm_protected_header(
    list(alg = "RSA-OAEP", enc = "A128CBC-HS256", cty = "JWT"),
    list()
  ))
})
