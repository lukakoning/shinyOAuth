test_that("wire JWK operation metadata is validated before caching", {
  public <- jsonlite::fromJSON(
    write_test_jwk(openssl::rsa_keygen()[["pubkey"]]),
    simplifyVector = FALSE
  )
  provider <- make_test_provider()
  provider@issuer <- "https://example.com"
  provider@jwks_uri <- "https://example.com/jwks"
  body <- ""
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(
      url = req[["url"]],
      status_code = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(body)
    )
  })
  for (metadata in c(
    '"key_ops":"verify"',
    '"key_ops":null',
    '"key_ops":{}',
    '"key_ops":{"operation":"verify"}',
    '"key_ops":["verify",1]',
    '"key_ops":["verify","verify"]',
    '"use":"sig","key_ops":["verify","encrypt"]',
    '"use":"enc","key_ops":["encrypt","verify"]'
  )) {
    body <- paste0(
      '{"keys":[',
      sub("}$", ",", jsonlite::toJSON(public, auto_unbox = TRUE)),
      metadata,
      '}]}'
    )
    cache <- cachem::cache_mem()
    expect_error(
      fetch_jwks(provider@issuer, cache, provider = provider),
      "key_ops",
      class = "shinyOAuth_parse_error"
    )
    expect_length(cache[["keys"]](), 0L)
  }
  public[["use"]] <- "sig"
  public[["key_ops"]] <- list("verify")
  body <- jsonlite::toJSON(list(keys = list(public)), auto_unbox = TRUE)
  fetched <- fetch_jwks(
    provider@issuer,
    cachem::cache_mem(),
    provider = provider
  )
  expect_length(select_candidate_jwks(fetched), 1L)
  public[["key_ops"]] <- "verify"
  expect_silent(validate_jwks(list(keys = list(public))))
  expect_length(select_candidate_jwks(list(public)), 1L)
})

test_that("normalized contradictory operation metadata is unusable", {
  public <- jsonlite::fromJSON(
    write_test_jwk(openssl::rsa_keygen()[["pubkey"]]),
    simplifyVector = FALSE
  )
  for (use in c("sig", "enc")) {
    public[["use"]] <- use
    public[["key_ops"]] <- c("verify", "encrypt")
    expect_error(validate_jwks(list(keys = list(public))), "inconsistent")
    expect_length(select_candidate_jwks(list(public)), 0L)
    expect_length(
      select_candidate_jwks_for_encryption(list(public), "RSA-OAEP"),
      0L
    )
  }
})
