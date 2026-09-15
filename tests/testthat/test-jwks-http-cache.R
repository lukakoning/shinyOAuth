test_that("JWKS freshness accounts for directives, dates, age and response delay", {
  response <- function(headers) httr2::response(headers = headers)
  date <- "Thu, 01 Jan 1970 00:16:40 GMT"
  for (headers in list(
    list("cache-control" = "max-age=100", date = date, age = "20"),
    list("cache-control" = 'max-age="100"', date = date, age = "20"),
    list(expires = "Thu, 01 Jan 1970 00:18:20 GMT", date = date, age = "20")
  )) {
    expect_identical(
      jwks_http_freshness(response(headers), 1000, 1002),
      list(store = TRUE, fresh_until = 1080)
    )
  }
  for (headers in list(
    list("cache-control" = "max-age=0"),
    list("cache-control" = "max-age=100, no-cache"),
    list("cache-control" = 'No-Cache="Authorization"'),
    list("cache-control" = "max-age=100, max-age=200"),
    list("cache-control" = "max-age=invalid"),
    list("cache-control" = "max-age=100", age = "101"),
    list(expires = "invalid"),
    list(expires = date)
  )) {
    expect_identical(
      jwks_http_freshness(response(headers), 1000, 1002)[["fresh_until"]],
      1002
    )
  }
  expect_false(jwks_http_freshness(
    response(list("cache-control" = "No-Store")),
    1000,
    1002
  )[["store"]])
  expect_identical(
    jwks_http_freshness(response(list()), 1000, 1002)[["fresh_until"]],
    Inf
  )
})

test_that("JWKS HTTP freshness controls reuse and encrypted JAR key rotation", {
  old_key <- openssl::read_key(mtls_pem_fixture("client-key.pem"))
  new_key <- openssl::rsa_keygen(2048)
  as_jwk <- function(key, kid) {
    jwk <- canonicalize_local_public_jwk(jsonlite::fromJSON(
      write_test_jwk(key[["pubkey"]]),
      simplifyVector = FALSE
    ))
    c(jwk, list(kid = kid, use = "enc", alg = "RSA-OAEP"))
  }
  old_jwk <- as_jwk(old_key, "old")
  new_jwk <- as_jwk(new_key, "new")
  provider <- oauth_provider(
    name = "rotation",
    auth_url = "https://issuer.example/auth",
    token_url = "https://issuer.example/token",
    issuer = "https://issuer.example",
    jwks_uri = "https://issuer.example/jwks",
    use_nonce = FALSE,
    id_token_validation = FALSE,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    request_parameter_supported = TRUE,
    request_object_signing_alg_values_supported = "RS256",
    request_object_encryption_alg_values_supported = "RSA-OAEP",
    request_object_encryption_enc_values_supported = "A128CBC-HS256"
  )
  client <- oauth_client(
    provider,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost/callback",
    client_assertion_private_key = old_key,
    request_object_mode = "request",
    request_object_signing_alg = "RS256",
    request_object_encryption_alg = "RSA-OAEP",
    request_object_encryption_enc = "A128CBC-HS256"
  )
  calls <- 0L
  rotated <- FALSE
  directive <- "max-age=0"
  local_mocked_bindings(req_with_retry = function(...) {
    calls <<- calls + 1L
    httr2::response(
      headers = list(
        "content-type" = "application/json",
        "cache-control" = directive,
        date = format(Sys.time(), "%a, %d %b %Y %H:%M:%S GMT", tz = "GMT")
      ),
      body = charToRaw(jsonlite::toJSON(
        list(keys = list(if (rotated) new_jwk else old_jwk)),
        auto_unbox = TRUE
      ))
    )
  })
  for (policy in c("no-store", "no-cache", "max-age=0", "max-age=300")) {
    provider@jwks_cache[["reset"]]()
    calls <- 0L
    rotated <- FALSE
    directive <- policy
    build_authorization_request_object(
      client,
      list(response_type = "code", state = "first")
    )
    if (identical(policy, "max-age=300")) {
      entry <- provider@jwks_cache[["get"]](provider@jwks_cache[["keys"]]()[[
        1L
      ]])
      expect_gt(entry[["fresh_until"]], as.numeric(Sys.time()))
    }
    rotated <- TRUE
    second <- build_authorization_request_object(
      client,
      list(response_type = "code", state = "second")
    )
    fresh <- !identical(policy, "max-age=300")
    expect_identical(calls, if (fresh) 2L else 1L)
    expect_identical(
      jwe_compact_parts(second)[["protected_header"]][["kid"]],
      if (fresh) "new" else "old"
    )
    expect_type(
      jwe_compact_decrypt(second, if (fresh) new_key else old_key),
      "list"
    )
    if (identical(policy, "no-store")) {
      expect_length(provider@jwks_cache[["keys"]](), 0L)
    }
  }
})
