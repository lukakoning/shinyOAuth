test_that("policy encoding v2 deliberately invalidates v1 fingerprints", {
  expect_identical(
    as.character(state_policy_component_string(1)),
    '{"type":"double","names":null,"attributes":null,"value":"3ff0000000000000"}'
  )
  expect_identical(
    state_policy_digest(list(value = 1)),
    "sha256:v2:520576ea70a0eb00a48f0085aaad26b4791bb732c8f7a821009d364ed0283c46"
  )
})

test_that("policy fingerprints preserve scalar types and numeric precision", {
  values <- list(1, "1", TRUE, "true", NA_character_, "<na>", NA_real_, NaN,
    Inf, "Inf", 1.0000001, 1.0000002, 1L, as.raw(1L))
  fingerprints <- vapply(values, state_policy_value_digest, "")
  expect_identical(anyDuplicated(fingerprints), 0L)
  claims_fps <- vapply(list(1, "1", TRUE, "true"), function(value) {
    state_policy_value_digest(list(id_token = list(custom = list(value = value))))
  }, "")
  expect_identical(anyDuplicated(claims_fps), 0L)
  for (digits in c(3L, 7L, 17L)) {
    local_options(digits = digits, scipen = digits, OutDec = ",")
    expect_identical(vapply(values, state_policy_value_digest, ""), fingerprints)
  }
})

test_that("policy encoding preserves containers and normalizes UTF-8 and object order", {
  distinct <- list(NULL, list(), character(), list("read"), "read",
    c(a = "read"), matrix("read", 1), I("read"), as.Date("2026-01-01"),
    list(a = "read", a = "write"), list(a = "read", a.1 = "write"))
  expect_identical(anyDuplicated(vapply(distinct, state_policy_value_digest, "")), 0L)
  expect_identical(
    state_policy_value_digest(list(z = "write", a = "read")),
    state_policy_value_digest(list(a = "read", z = "write"))
  )
  expect_identical(
    state_policy_value_digest(iconv("caf\u00e9", from = "UTF-8", to = "latin1")),
    state_policy_value_digest("caf\u00e9")
  )
  scopes <- sprintf("permission.%03d", seq_len(128))
  original <- state_policy_digest(list(scopes = scopes))
  scopes[[128]] <- "permission.admin"
  expect_false(identical(state_policy_digest(list(scopes = scopes)), original))
})

test_that("typed requested claims bind pending authorizations", {
  provider <- oauth_provider_oidc(
    "typed-claims", "https://issuer.example", jwks_uri = "https://issuer.example/jwks"
  )
  client <- oauth_client(
    provider, "typed-claims", client_secret = "secret",
    redirect_uri = "https://app.example/callback", scopes = "openid",
    claims = list(id_token = list(custom_claim = list(value = 1))),
    claims_validation = "strict"
  )
  auth <- prepare_call(client, browser_token = strrep("a", 128L))
  state <- httr2::url_parse(auth)[["query"]][["state"]]
  expect_type(state_payload_decrypt_validate(client, state), "list")
  legacy_payload <- state_decrypt_gcm(state, client@state_key)
  legacy_payload[["client_policy"]] <- sub(
    "^sha256:v2:", "sha256:", legacy_payload[["client_policy"]]
  )
  expect_error(state_payload_decrypt_validate(
    client, state_encrypt_gcm(legacy_payload, client@state_key)
  ), "client policy mismatch")
  changed <- client
  changed@claims <- list(id_token = list(custom_claim = list(value = "1")))
  expect_error(state_payload_decrypt_validate(changed, state), "client policy mismatch")
  expect_no_error(validate_essential_claims(changed, list(custom_claim = "1"), "id_token"))
  expect_error(validate_essential_claims(client, list(custom_claim = "1"), "id_token"))
})

test_that("selector policies bind pending and retained authorizations", {
  original <- oauth_client(
    oauth_provider_spotify(allow_legacy_id = TRUE), "selector-policy",
    client_secret = "secret", redirect_uri = "https://app.example/callback",
    scopes = "user-read-private"
  )
  changed <- original
  changed@provider <- oauth_provider_spotify(allow_legacy_id = FALSE)
  expect_false(identical(provider_fingerprint(original@provider), provider_fingerprint(changed@provider)))
  auth <- prepare_call(original, browser_token = strrep("a", 128L))
  state <- httr2::url_parse(auth)[["query"]][["state"]]
  expect_error(state_payload_decrypt_validate(changed, state), "provider fingerprint mismatch")
  owner <- strrep("a", 32L)
  id <- strrep("b", 32L)
  key <- openssl::rand_bytes(32L)
  token <- OAuthToken(access_token = "access", token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 3600, granted_scopes = "user-read-private")
  sealed <- connection_credentials_seal(token, owner, id, original, key, as.numeric(Sys.time()))
  expect_type(connection_credentials_open(sealed, owner, id, original, key), "list")
  expect_error(connection_credentials_open(sealed, owner, id, changed, key))
  expect_error(connection_credentials_open(sealed, owner, id, changed, key,
    expected_fingerprint = connection_client_fingerprint(original)), "incompatible")
  legacy_payload <- state_decrypt_gcm(sealed, connection_credential_key(key))
  legacy_payload[["binding"]][["fingerprint"]] <- sub(
    "^sha256:v2:", "sha256:", legacy_payload[["binding"]][["fingerprint"]]
  )
  expect_error(connection_credentials_open(
    state_encrypt_gcm(legacy_payload, connection_credential_key(key)),
    owner, id, original, key
  ))

  factory <- function(field) function(userinfo) userinfo[[field]]
  first <- original@provider
  first@userinfo_id_selector <- factory("sub")
  first@userinfo_id_selector_policy_id <- "application:sub:v1"
  second <- first
  second@userinfo_id_selector <- factory("email")
  second@userinfo_id_selector_policy_id <- "application:email:v2"
  expect_false(identical(provider_fingerprint(first), provider_fingerprint(second)))
  original@provider <- first
  changed@provider <- second
  auth <- prepare_call(original, browser_token = strrep("b", 128L))
  state <- httr2::url_parse(auth)[["query"]][["state"]]
  expect_error(state_payload_decrypt_validate(changed, state), "provider fingerprint mismatch")
  sealed <- connection_credentials_seal(token, owner, id, original, key, as.numeric(Sys.time()))
  expect_error(connection_credentials_open(sealed, owner, id, changed, key))
  for (bad in list("", character(), c("a", "b"))) {
    expect_error({ first@userinfo_id_selector_policy_id <- bad }, "selector_policy_id")
  }
})
