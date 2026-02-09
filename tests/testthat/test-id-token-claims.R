test_that("id_token_claims returns empty list when no ID token", {
  tok <- OAuthToken(
    access_token = "at",
    id_token = NA_character_
  )
  expect_identical(tok@id_token_claims, list())
})

test_that("id_token_claims returns empty list for empty string ID token", {
  tok <- OAuthToken(
    access_token = "at",
    id_token = ""
  )
  expect_identical(tok@id_token_claims, list())
})

test_that("id_token_claims returns empty list for malformed JWT", {
  tok <- OAuthToken(
    access_token = "at",
    id_token = "not-a-jwt"
  )
  expect_identical(tok@id_token_claims, list())
})

test_that("id_token_claims decodes standard claims", {
  now <- floor(as.numeric(Sys.time()))
  claims <- jose::jwt_claim(
    iss = "https://issuer.example.com",
    sub = "user123",
    aud = "client-id",
    iat = now,
    exp = now + 3600
  )
  key <- openssl::rsa_keygen(2048)
  id_token <- jose::jwt_encode_sig(claims, key = key)

  tok <- OAuthToken(
    access_token = "at",
    id_token = id_token
  )
  decoded <- tok@id_token_claims
  expect_type(decoded, "list")
  expect_identical(decoded$iss, "https://issuer.example.com")
  expect_identical(decoded$sub, "user123")
  expect_identical(decoded$aud, "client-id")
  expect_equal(decoded$iat, now)
  expect_equal(decoded$exp, now + 3600)
})

test_that("id_token_claims surfaces acr, amr, auth_time", {
  now <- floor(as.numeric(Sys.time()))
  payload <- list(
    iss = "https://issuer.example.com",
    sub = "user456",
    aud = "client-id",
    iat = now,
    exp = now + 3600,
    acr = "urn:mace:incommon:iap:silver",
    amr = list("pwd", "otp"),
    auth_time = now - 60
  )
  key <- openssl::rsa_keygen(2048)
  clm <- do.call(jose::jwt_claim, payload)
  id_token <- jose::jwt_encode_sig(clm, key = key)

  tok <- OAuthToken(
    access_token = "at",
    id_token = id_token
  )
  decoded <- tok@id_token_claims
  expect_identical(decoded$acr, "urn:mace:incommon:iap:silver")
  expect_identical(decoded$amr, c("pwd", "otp"))
  expect_equal(decoded$auth_time, now - 60)
})

test_that("id_token_claims is read-only (assignment errors)", {
  tok <- OAuthToken(
    access_token = "at",
    id_token = NA_character_
  )
  expect_error(tok@id_token_claims <- list(fake = TRUE))
})

test_that("id_token_claims updates when id_token changes", {
  now <- floor(as.numeric(Sys.time()))
  key <- openssl::rsa_keygen(2048)

  claims1 <- jose::jwt_claim(
    iss = "https://issuer.example.com",
    sub = "user-A",
    aud = "cid",
    iat = now,
    exp = now + 3600
  )
  jwt1 <- jose::jwt_encode_sig(claims1, key = key)

  claims2 <- jose::jwt_claim(
    iss = "https://issuer.example.com",
    sub = "user-B",
    aud = "cid",
    iat = now,
    exp = now + 7200
  )
  jwt2 <- jose::jwt_encode_sig(claims2, key = key)

  tok <- OAuthToken(access_token = "at", id_token = jwt1)
  expect_identical(tok@id_token_claims$sub, "user-A")

  tok@id_token <- jwt2
  expect_identical(tok@id_token_claims$sub, "user-B")
})
