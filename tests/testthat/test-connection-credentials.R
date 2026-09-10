test_that("encrypted credential schemas retain token continuity without live objects", {
  target <- oauth_target(make_test_client(), c(api = "https://api.example/v1"))
  signing_key <- openssl::rsa_keygen()
  initial_id <- jose::jwt_encode_sig(
    jose::jwt_claim(sub = "synthetic-subject", iat = 1000),
    signing_key
  )
  latest_id <- jose::jwt_encode_sig(
    jose::jwt_claim(sub = "synthetic-subject", iat = 2000),
    signing_key
  )
  token <- OAuthToken(
    access_token = "synthetic-access",
    token_type = "Bearer",
    refresh_token = "synthetic-refresh",
    expires_at = 1789064672.1234567,
    original_id_token = initial_id,
    id_token = latest_id,
    id_token_validated = TRUE,
    granted_scopes = c("read", "write"),
    granted_scopes_verified = FALSE,
    userinfo = list(sub = "synthetic-subject", roles = character()),
    cnf = list(jkt = "synthetic-key-reference"),
    extra_fields = list(patient = NULL, list = list(1L, FALSE, NULL)),
    initial_extra_fields = list(
      patient = "synthetic-patient",
      encounter = "synthetic-encounter"
    )
  )
  owner <- strrep("a", 32)
  id <- strrep("b", 32)
  key <- openssl::rand_bytes(32L)
  sealed <- connection_credentials_seal(token, owner, id, target, key, 1000)
  expect_false(grepl("synthetic", sealed, fixed = TRUE))
  restored <- connection_credentials_open(sealed, owner, id, target, key)
  expect_identical(restored$authenticated_at, 1000L)
  for (field in connection_token_fields) {
    expect_identical(S7::prop(restored$token, field), S7::prop(token, field))
  }
  expect_false(identical(
    sealed,
    connection_credentials_seal(token, owner, id, target, key, 1000)
  ))
  expect_error(
    connection_credentials_open(sealed, strrep("c", 32), id, target, key),
    "unavailable or incompatible"
  )
  expect_error(
    connection_credentials_open(sealed, owner, strrep("c", 32), target, key),
    "unavailable or incompatible"
  )
  expect_error(
    connection_credentials_open(
      sealed,
      owner,
      id,
      target,
      openssl::rand_bytes(32L)
    ),
    "unavailable or incompatible"
  )
  changed <- oauth_target(target$client, c(api = "https://api.example/v2"))
  expect_error(
    connection_credentials_open(sealed, owner, id, changed, key),
    "unavailable or incompatible"
  )
  expect_error(
    connection_credentials_open(paste0("x", sealed), owner, id, target, key),
    "unavailable or incompatible"
  )
  expect_error(
    connection_credentials_seal(token, owner, id, target, "password", 1000),
    "32-byte raw key"
  )
})

test_that("plain-data encoding preserves vector shapes and rejects executable objects", {
  value <- list(
    null = NULL,
    empty = list(),
    chars = character(),
    numbers = numeric(),
    scalar = "one",
    array = c("one", "two"),
    named = c(a = 1L, b = NA_integer_),
    logical = c(TRUE, FALSE, NA),
    double = c(1.25, 1789064672.1234567, NA_real_, Inf, -Inf, NaN)
  )
  json <- jsonlite::toJSON(
    connection_data_encode(value),
    auto_unbox = TRUE,
    null = "null"
  )
  expect_identical(
    connection_data_decode(jsonlite::fromJSON(json, simplifyVector = FALSE)),
    value
  )
  expect_error(
    connection_data_encode(list(callback = function() NULL)),
    "plain data"
  )
  expect_error(connection_data_encode(list(store = new.env())), "plain data")
  expect_error(
    connection_data_encode(list(client = make_test_client())),
    "plain data"
  )
  expect_error(
    connection_data_encode(setNames(list(1L, 2L), c("same", "same"))),
    "duplicate"
  )
  expect_error(
    connection_data_encode(list(big = strrep("x", 600000))),
    "size limit"
  )
  deep <- NULL
  for (i in seq_len(18)) {
    deep <- list(deep)
  }
  expect_error(connection_data_encode(deep), "plain data")
})

test_that("restoration rejects changed transport policy and sender keys", {
  local_options(shinyOAuth.tls_min_version = NULL)
  client <- make_test_client()
  client@dpop_private_key <- openssl::rsa_keygen()
  target <- oauth_target(client, c(api = "https://api.example/v1"))
  owner <- strrep("a", 32)
  id <- strrep("b", 32)
  key <- openssl::rand_bytes(32L)
  token <- OAuthToken(
    access_token = "synthetic-access",
    token_type = "DPoP",
    expires_at = Inf,
    cnf = list(jkt = state_policy_dpop_key_thumbprint(client))
  )
  sealed <- connection_credentials_seal(token, owner, id, target, key, 1000)
  client@dpop_private_key <- openssl::rsa_keygen()
  replacement <- oauth_target(client, c(api = "https://api.example/v1"))
  expect_error(
    connection_credentials_open(sealed, owner, id, replacement, key),
    "unavailable or incompatible"
  )
  local_options(shinyOAuth.tls_min_version = "1.2")
  expect_error(
    connection_credentials_open(sealed, owner, id, target, key),
    "configuration changed"
  )
})
