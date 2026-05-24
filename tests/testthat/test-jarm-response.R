make_jarm_test_client <- function(
  response_mode = "query.jwt",
  authorization_signed_response_alg = "RS256",
  authorization_encrypted_response_alg = NULL,
  authorization_encrypted_response_enc = NULL,
  authorization_response_decryption_private_key = NULL,
  authorization_response_decryption_private_key_kid = NULL,
  jarm_max_lifetime = 600,
  provider_tolerate_duplicate_top_level_jarm_iss = FALSE,
  client_secret = "",
  issuer = "https://issuer.example.com"
) {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@issuer <- issuer
  prov@response_modes_supported <- unique(c(
    response_mode,
    if (identical(response_mode, "query.jwt")) "jwt" else character(0)
  ))
  prov@authorization_signing_alg_values_supported <-
    authorization_signed_response_alg %||% character(0)
  prov@authorization_encryption_alg_values_supported <-
    authorization_encrypted_response_alg %||% character(0)
  prov@authorization_encryption_enc_values_supported <-
    authorization_encrypted_response_enc %||% character(0)
  prov@tolerate_duplicate_top_level_jarm_iss <-
    isTRUE(provider_tolerate_duplicate_top_level_jarm_iss)

  oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = client_secret,
    redirect_uri = "http://localhost:8100",
    scopes = "openid",
    response_mode = response_mode,
    authorization_signed_response_alg = authorization_signed_response_alg,
    authorization_encrypted_response_alg = authorization_encrypted_response_alg,
    authorization_encrypted_response_enc = authorization_encrypted_response_enc,
    authorization_response_decryption_private_key = authorization_response_decryption_private_key,
    authorization_response_decryption_private_key_kid = authorization_response_decryption_private_key_kid,
    jarm_max_lifetime = jarm_max_lifetime,
    state_store = cachem::cache_mem(max_age = 600),
    state_payload_max_age = 300,
    state_entropy = 64,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

make_jarm_public_jwk <- function(key, kid = "sig-1", use = "sig") {
  jwk <- jsonlite::fromJSON(jose::write_jwk(key$pubkey), simplifyVector = TRUE)
  jwk$kid <- kid
  jwk$use <- use
  jwk
}

make_signed_jarm <- function(
  payload_list,
  key,
  kid = NULL,
  alg = "RS256"
) {
  header <- list(alg = alg)
  if (!is.null(kid)) {
    header$kid <- kid
  }

  jose::jwt_encode_sig(
    do.call(jose::jwt_claim, payload_list),
    key = key,
    header = header
  )
}

make_encrypted_jarm <- function(
  plaintext,
  public_key,
  alg = "RSA-OAEP",
  enc = "A256CBC-HS512",
  kid = NULL,
  cty = NULL,
  extra_header = list()
) {
  alg <- shinyOAuth:::canonicalize_jwe_alg(alg)
  enc <- shinyOAuth:::canonicalize_jwe_enc(enc)
  spec <- shinyOAuth:::jwe_cbc_hmac_spec(enc)
  recipient_key <- shinyOAuth:::normalize_jwe_recipient_public_key(public_key)
  plaintext_raw <- charToRaw(enc2utf8(plaintext))

  header <- list(alg = alg, enc = enc)
  if (!is.null(kid)) {
    header$kid <- kid
  }
  if (!is.null(cty)) {
    header$cty <- cty
  }
  if (length(extra_header) > 0L) {
    header <- utils::modifyList(header, extra_header)
  }

  header_json <- jsonlite::toJSON(
    header,
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )
  protected_header_b64 <- shinyOAuth:::base64url_encode(
    charToRaw(enc2utf8(header_json))
  )

  cek_raw <- openssl::rand_bytes(spec$cek_bytes)
  key_parts <- shinyOAuth:::split_jwe_cbc_hmac_cek(cek_raw, enc)
  encrypted_key_raw <- openssl::rsa_encrypt(
    cek_raw,
    pubkey = recipient_key,
    oaep = TRUE
  )
  iv_raw <- openssl::rand_bytes(spec$iv_bytes)
  ciphertext_raw <- openssl::aes_cbc_encrypt(
    plaintext_raw,
    key = key_parts$enc_key,
    iv = iv_raw
  )
  tag_raw <- shinyOAuth:::compute_compact_jwe_auth_tag(
    enc = enc,
    mac_key = key_parts$mac_key,
    protected_header_b64 = protected_header_b64,
    iv_raw = iv_raw,
    ciphertext_raw = ciphertext_raw
  )

  paste(
    protected_header_b64,
    shinyOAuth:::base64url_encode(encrypted_key_raw),
    shinyOAuth:::base64url_encode(iv_raw),
    shinyOAuth:::base64url_encode(ciphertext_raw),
    shinyOAuth:::base64url_encode(tag_raw),
    sep = "."
  )
}

make_jarm_form_post_req <- function(
  path = "/",
  query = "",
  body = "",
  content_type = "application/x-www-form-urlencoded"
) {
  req <- new.env(parent = emptyenv())
  req$REQUEST_METHOD <- "POST"
  req$PATH_INFO <- path
  req$QUERY_STRING <- query
  req$CONTENT_TYPE <- content_type
  req$CONTENT_LENGTH <- as.character(nchar(body, type = "bytes"))
  req$rook.input <- list(read = function(n) charToRaw(body))
  req
}

jarm_form_post_query <- function(handle, id = "auth") {
  paste0(
    "?",
    httr2::url_query_build(stats::setNames(
      list(handle, id),
      c("shinyOAuth_form_post", "shinyOAuth_form_post_id")
    ))
  )
}

make_compact_jose_token <- function(
  header_json,
  payload_list,
  signature = "AA"
) {
  payload_json <- jsonlite::toJSON(
    payload_list,
    auto_unbox = TRUE,
    null = "null",
    na = "null",
    digits = NA
  )

  paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(as.character(payload_json))),
    ".",
    signature
  )
}

make_compact_jwe_with_header <- function(header_json) {
  paste(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    "AA",
    "AA",
    "AA",
    "AA",
    sep = "."
  )
}

test_that("handle_callback rejects direct code/state callbacks for JARM clients", {
  modes <- c("jwt", "query.jwt", "form_post.jwt")

  for (mode in modes) {
    client <- make_jarm_test_client(response_mode = mode)
    browser_token <- valid_browser_token()
    auth_url <- shinyOAuth::prepare_call(client, browser_token = browser_token)
    state <- parse_query_param(auth_url, "state")

    expect_length(client@state_store$keys(), 1L)

    expect_error(
      shinyOAuth::handle_callback(
        oauth_client = client,
        code = "direct-code",
        payload = state,
        browser_token = browser_token
      ),
      class = "shinyOAuth_config_error",
      regexp = "does not accept direct code/state callbacks for JARM clients"
    )

    expect_length(client@state_store$keys(), 1L)
  }
})

test_that("OIDC discovery records JARM metadata", {
  discover_provider <- function(metadata) {
    testthat::local_mocked_bindings(
      .discover_fetch_response = function(req, issuer) {
        structure(list(), class = "mock_discovery_response")
      },
      .discover_parse_json = function(resp) metadata,
      .package = "shinyOAuth"
    )

    oauth_provider_oidc_discover(
      issuer = metadata$issuer,
      id_token_validation = FALSE
    )
  }

  metadata <- list(
    issuer = "https://issuer.example.com",
    authorization_endpoint = "https://issuer.example.com/auth",
    token_endpoint = "https://issuer.example.com/token",
    response_modes_supported = c("query.jwt", "form_post.jwt"),
    authorization_signing_alg_values_supported = c("RS256", "ES256"),
    authorization_encryption_alg_values_supported = "RSA-OAEP",
    authorization_encryption_enc_values_supported = c(
      "A128CBC-HS256",
      "A256CBC-HS512"
    )
  )

  prov <- discover_provider(metadata)

  expect_identical(
    prov@authorization_signing_alg_values_supported,
    c("RS256", "ES256")
  )
  expect_identical(
    prov@authorization_encryption_alg_values_supported,
    "RSA-OAEP"
  )
  expect_identical(
    prov@authorization_encryption_enc_values_supported,
    c("A128CBC-HS256", "A256CBC-HS512")
  )
})

test_that("oauth_client defaults encrypted JARM enc when alg is set", {
  rsa_key <- openssl::rsa_keygen()

  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_response_decryption_private_key = rsa_key
  )

  expect_identical(client@authorization_encrypted_response_enc, "A128CBC-HS256")
})

test_that("validate_jarm_response verifies signed JARM payloads", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  normalized <- shinyOAuth:::validate_jarm_response(client, response)

  expect_identical(normalized$type, "code")
  expect_identical(normalized$code, "ok")
  expect_identical(normalized$state, "state-1")
  expect_identical(normalized$iss, client@provider@issuer)
})

test_that("validate_jarm_response refreshes JWKS once when JARM kid is missing", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "rotated-kid"
  )
  stale_jwks <- list(keys = list())
  fresh_jwks <- list(
    keys = list(
      make_jarm_public_jwk(sig_key, kid = "rotated-kid")
    )
  )
  fetch_call_count <- 0L

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) {
      fetch_call_count <<- fetch_call_count + 1L
      args <- list(...)
      if (isTRUE(args$force_refresh)) {
        fresh_jwks
      } else {
        stale_jwks
      }
    },
    jwks_force_refresh_allowed = function(...) TRUE,
    .package = "shinyOAuth"
  )

  normalized <- shinyOAuth:::validate_jarm_response(client, response)

  expect_identical(normalized$type, "code")
  expect_identical(normalized$code, "ok")
  expect_identical(fetch_call_count, 2L)
})

test_that("validate_jarm_response fails closed when JARM JWKS refresh is rate-limited", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "unknown-kid"
  )
  stale_jwks <- list(keys = list())

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) stale_jwks,
    jwks_force_refresh_allowed = function(...) FALSE,
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "rate-limited"
  )
})

test_that("validate_jarm_response rejects alg none", {
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- build_dummy_jwt(list(
    iss = client@provider@issuer,
    aud = "abc",
    exp = now + 300,
    code = "ok",
    state = "state-1"
  ))

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "alg=none"
  )
})

test_that("validate_jarm_response accepts signed JARM with explicit JWT media type typ header", {
  secret <- "hs256-jarm-explicit-typ-secret-value"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))
  response <- shinyOAuth:::encode_hmac_jwt_with_header(
    claims = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    secret = secret,
    header = list(
      alg = "HS256",
      typ = "application/oauth-authz-resp+jwt"
    ),
    size = 256,
    alg = "HS256"
  )

  normalized <- shinyOAuth:::validate_jarm_response(client, response)

  expect_identical(normalized$code, "ok")
  expect_identical(normalized$state, "state-1")
})

test_that("validate_jarm_response rejects signed JARM with non-JWT typ header", {
  secret <- "hs256-jarm-invalid-typ-secret-value"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))
  response <- shinyOAuth:::encode_hmac_jwt_with_header(
    claims = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    secret = secret,
    header = list(alg = "HS256", typ = "application/json"),
    size = 256,
    alg = "HS256"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "typ header invalid"
  )
})

test_that("validate_jarm_response rejects partially matched signed header names", {
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_compact_jose_token(
    header_json = '{"algx":"RS256","kidx":"sig-1","typx":"JWT","critx":["exp"]}',
    payload_list = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = now + 300,
      code = "ok",
      state = "state-1"
    )
  )

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        "validate_jarm_response should reject missing exact alg before JWKS fetch"
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "header missing alg"
  )
})

test_that("validate_jarm_response rejects clients that did not request JARM", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  client@provider@issuer <- "https://issuer.example.com"
  now <- floor(as.numeric(Sys.time()))
  response <- build_dummy_jwt(list(
    iss = client@provider@issuer,
    aud = client@client_id,
    exp = now + 300,
    code = "ok",
    state = "state-1"
  ))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        "validate_jarm_response should reject non-JARM clients before JWKS fetch"
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "not configured to accept JARM"
  )
})

test_that("validate_jarm_response rejects issuer mismatch before JWKS fetch", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = "https://attacker.example.com",
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        "validate_jarm_response should reject issuer mismatch before JWKS fetch"
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "issuer does not match"
  )
})

test_that("validate_jarm_response rejects aud and exp failures before JWKS fetch", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  cases <- list(
    list(
      name = "missing aud",
      payload = list(
        iss = client@provider@issuer,
        exp = now + 300,
        code = "ok",
        state = "state-1"
      ),
      regexp = "aud claim is invalid"
    ),
    list(
      name = "wrong aud",
      payload = list(
        iss = client@provider@issuer,
        aud = "wrong-client",
        exp = now + 300,
        code = "ok",
        state = "state-1"
      ),
      regexp = "aud claim does not include client_id"
    ),
    list(
      name = "expired exp",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now - 300,
        code = "ok",
        state = "state-1"
      ),
      regexp = "payload expired"
    )
  )

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        paste(
          "validate_jarm_response should reject bad aud or exp claims",
          "before JWKS fetch"
        )
      )
    },
    .package = "shinyOAuth"
  )

  for (case in cases) {
    response <- make_signed_jarm(
      payload_list = case$payload,
      key = sig_key,
      kid = "sig-1"
    )

    expect_error(
      shinyOAuth:::validate_jarm_response(client, response),
      class = "shinyOAuth_state_error",
      regexp = case$regexp,
      info = case$name
    )
  }
})

test_that("validate_jarm_response rejects malformed exp before signature verification", {
  secret <- "hs256-jarm-malformed-exp-secret-32b!"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  response <- shinyOAuth:::encode_hmac_jwt_with_header(
    claims = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = "not-a-number",
      code = "ok",
      state = "state-1"
    ),
    secret = secret,
    header = list(alg = "HS256", typ = "JWT"),
    size = 256,
    alg = "HS256"
  )

  testthat::local_mocked_bindings(
    verify_hmac_jws_signature_no_time = function(...) {
      testthat::fail(
        paste(
          "validate_jarm_response should reject malformed exp",
          "before signature verification"
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "exp claim must be a single finite number"
  )
})

test_that("validate_jarm_response enforces configured JARM max lifetime without iat", {
  secret <- "hs256-jarm-max-lifetime-no-iat-secret!"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret,
    jarm_max_lifetime = 600
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))
  response <- shinyOAuth:::encode_hmac_jwt_with_header(
    claims = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = now + 1200,
      code = "ok",
      state = "state-1"
    ),
    secret = secret,
    header = list(alg = "HS256", typ = "JWT"),
    size = 256,
    alg = "HS256"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "lifetime exceeds configured maximum"
  )
})

test_that("validate_jarm_response enforces configured JARM max lifetime from iat", {
  secret <- "hs256-jarm-max-lifetime-with-iat-secret"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret,
    jarm_max_lifetime = 60
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))
  response <- shinyOAuth:::encode_hmac_jwt_with_header(
    claims = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      iat = now - 5,
      exp = now + 120,
      code = "ok",
      state = "state-1"
    ),
    secret = secret,
    header = list(alg = "HS256", typ = "JWT"),
    size = 256,
    alg = "HS256"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "lifetime exceeds configured maximum"
  )
})

test_that("validate_jarm_response rejects iat values after exp", {
  secret <- "hs256-jarm-iat-after-exp-secret-value"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret,
    jarm_max_lifetime = 600
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))
  response <- shinyOAuth:::encode_hmac_jwt_with_header(
    claims = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      iat = now + 60,
      exp = now + 30,
      code = "ok",
      state = "state-1"
    ),
    secret = secret,
    header = list(alg = "HS256", typ = "JWT"),
    size = 256,
    alg = "HS256"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "iat claim must not be after exp"
  )
})

test_that("validate_jarm_response rejects payloads with both code and error", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      error = "access_denied",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "must not contain both code and error"
  )
})

test_that("validate_jarm_response requires state after signature verification", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = now + 300,
      code = "ok"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  verified <- FALSE

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    verify_jws_signature_no_time = function(...) {
      verified <<- TRUE
      TRUE
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "missing required state"
  )
  expect_true(verified)
})

test_that("validate_jarm_response rejects partially matched JARM claim names", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  cases <- list(
    list(
      name = "issuer",
      payload = list(
        issuer = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        code = "ok",
        state = "state-1"
      ),
      regexp = "missing required iss claim"
    ),
    list(
      name = "audience",
      payload = list(
        iss = client@provider@issuer,
        audience = client@client_id,
        exp = now + 300,
        code = "ok",
        state = "state-1"
      ),
      regexp = "aud claim is invalid"
    ),
    list(
      name = "expiry",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        expiry = now + 300,
        code = "ok",
        state = "state-1"
      ),
      regexp = "missing required exp claim"
    ),
    list(
      name = "code_challenge",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        code_challenge = "challenge",
        state = "state-1"
      ),
      regexp = "missing code or error"
    ),
    list(
      name = "error_description",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        error_description = "Denied",
        state = "state-1"
      ),
      regexp = "missing code or error"
    )
  )

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  for (case in cases) {
    response <- make_signed_jarm(
      payload_list = case$payload,
      key = sig_key,
      kid = "sig-1"
    )

    expect_error(
      shinyOAuth:::validate_jarm_response(client, response),
      class = "shinyOAuth_state_error",
      regexp = case$regexp,
      info = case$name
    )
  }
})

test_that("validate_jarm_response validates JARM callback claim sizes and types", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  now <- floor(as.numeric(Sys.time()))
  limits <- shinyOAuth:::oauth_callback_limits()
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  cases <- list(
    list(
      name = "state vector",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        code = "ok",
        state = c("state-1", "state-2")
      ),
      regexp = "Callback query parameter 'state' must be a single string"
    ),
    list(
      name = "state oversized",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        code = "ok",
        state = strrep("s", limits$state + 1L)
      ),
      regexp = "Callback query parameter 'state' exceeded maximum length"
    ),
    list(
      name = "error_description numeric",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        error = "access_denied",
        error_description = 1,
        state = "state-1"
      ),
      regexp = paste(
        "Callback query parameter 'error_description' must be a single string"
      )
    ),
    list(
      name = "error_description oversized",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        error = "access_denied",
        error_description = strrep("d", limits$error_description + 1L),
        state = "state-1"
      ),
      regexp = paste(
        "Callback query parameter 'error_description' exceeded maximum length"
      )
    ),
    list(
      name = "error_uri numeric",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        error = "access_denied",
        error_uri = 1,
        state = "state-1"
      ),
      regexp = "Callback query parameter 'error_uri' must be a single string"
    ),
    list(
      name = "error_uri oversized",
      payload = list(
        iss = client@provider@issuer,
        aud = client@client_id,
        exp = now + 300,
        error = "access_denied",
        error_uri = strrep("u", limits$error_uri + 1L),
        state = "state-1"
      ),
      regexp = "Callback query parameter 'error_uri' exceeded maximum length"
    )
  )

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  for (case in cases) {
    response <- make_signed_jarm(
      payload_list = case$payload,
      key = sig_key,
      kid = "sig-1"
    )

    expect_error(
      shinyOAuth:::validate_jarm_response(client, response),
      class = "shinyOAuth_state_error",
      regexp = case$regexp,
      info = case$name
    )
  }
})

test_that("validate_jarm_response rejects duplicate identical iss claims by default", {
  secret <- "hs256-jarm-duplicate-iss-secret-32b!"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))

  header_json <- jsonlite::toJSON(
    list(alg = "HS256", typ = "JWT"),
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )
  payload_json <- paste0(
    '{',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"aud":"abc",',
    '"exp":',
    now + 300,
    ',',
    '"code":"ok",',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"state":"state-1"',
    '}'
  )
  signing_input <- paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(payload_json))
  )
  signature_raw <- openssl::sha256(
    charToRaw(signing_input),
    key = charToRaw(secret)
  )
  response <- paste0(
    signing_input,
    ".",
    shinyOAuth:::base64url_encode(signature_raw)
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "duplicate member name: iss"
  )
})

test_that("validate_jarm_response tolerates duplicate identical iss claims when provider opts in", {
  secret <- "hs256-jarm-duplicate-iss-secret-32b!"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret,
    provider_tolerate_duplicate_top_level_jarm_iss = TRUE
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))

  header_json <- jsonlite::toJSON(
    list(alg = "HS256", typ = "JWT"),
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )
  payload_json <- paste0(
    '{',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"aud":"abc",',
    '"exp":',
    now + 300,
    ',',
    '"code":"ok",',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"state":"state-1"',
    '}'
  )
  signing_input <- paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(payload_json))
  )
  signature_raw <- openssl::sha256(
    charToRaw(signing_input),
    key = charToRaw(secret)
  )
  response <- paste0(
    signing_input,
    ".",
    shinyOAuth:::base64url_encode(signature_raw)
  )

  normalized <- shinyOAuth:::validate_jarm_response(client, response)

  expect_identical(normalized$type, "code")
  expect_identical(normalized$code, "ok")
  expect_identical(normalized$state, "state-1")
  expect_identical(normalized$iss, client@provider@issuer)
})

test_that("validate_jarm_response rejects nested duplicate iss claims", {
  secret <- "hs256-jarm-nested-duplicate-iss-secret!"
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_signed_response_alg = "HS256",
    client_secret = secret
  )
  client@provider@authorization_signing_alg_values_supported <- "HS256"
  now <- floor(as.numeric(Sys.time()))

  header_json <- jsonlite::toJSON(
    list(alg = "HS256", typ = "JWT"),
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )
  payload_json <- paste0(
    '{',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"aud":"abc",',
    '"exp":',
    now + 300,
    ',',
    '"code":"ok",',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"nested":{',
    '"iss":"',
    client@provider@issuer,
    '",',
    '"iss":"',
    client@provider@issuer,
    '"},',
    '"state":"state-1"',
    '}'
  )
  signing_input <- paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(payload_json))
  )
  signature_raw <- openssl::sha256(
    charToRaw(signing_input),
    key = charToRaw(secret)
  )
  response <- paste0(
    signing_input,
    ".",
    shinyOAuth:::base64url_encode(signature_raw)
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "duplicate member name: iss"
  )
})

test_that("oauth_module_server rejects mixed query.jwt and direct callback params", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(...) {
      testthat::fail(
        "oauth_module_server should reject mixed JARM/direct params before token exchange"
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          expect_length(client@state_store$keys(), 1L)

          values$.process_query(paste0(
            "?response=",
            utils::URLencode(response, reserved = TRUE),
            "&code=attack"
          ))
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, "invalid_callback_query")
          expect_match(values$error_description %||% "", "must not be combined")
          expect_length(client@state_store$keys(), 1L)
        }
      )
    }
  )
})

test_that("oauth_module_server rejects direct query callbacks for query.jwt clients", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  client <- make_jarm_test_client(response_mode = "query.jwt")
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should reject direct query callbacks for",
          "JARM clients before token exchange"
        )
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")

          expect_length(client@state_store$keys(), 1L)

          values$.process_query(paste0(
            "?code=attack",
            "&state=",
            utils::URLencode(enc_state, reserved = TRUE),
            "&iss=",
            utils::URLencode(client@provider@issuer, reserved = TRUE)
          ))
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, "invalid_callback_query")
          expect_match(values$error_description %||% "", "response parameter")
          expect_length(client@state_store$keys(), 1L)
        }
      )
    }
  )
})

test_that("oauth_module_server rejects direct query callbacks for form_post.jwt clients", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  exchanged_codes <- character(0)

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(client, code, code_verifier) {
      exchanged_codes <<- c(exchanged_codes, code)
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))

          expect_length(client@state_store$keys(), 1L)

          values$.process_query(paste0(
            "?code=attack",
            "&state=",
            utils::URLencode(enc_state, reserved = TRUE),
            "&iss=",
            utils::URLencode(client@provider@issuer, reserved = TRUE)
          ))
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, "invalid_callback_query")
          expect_match(values$error_description %||% "", "form_post")
          expect_length(client@state_store$keys(), 1L)
          expect_identical(exchanged_codes, character(0))

          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(response, reserved = TRUE)
            )
          ))
          expect_identical(post_resp$status, 303L)

          handle <- parse_query_param(
            post_resp$headers$Location,
            "shinyOAuth_form_post",
            decode = TRUE
          )
          values$error <- NULL
          values$error_description <- NULL

          values$.process_query(jarm_form_post_query(handle, "auth"))
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
          expect_identical(exchanged_codes, "ok")
          expect_length(client@state_store$keys(), 0L)
        }
      )
    }
  )
})

test_that("oauth_module_server ignores query response params for form_post.jwt clients", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  browser_token <- valid_browser_token()
  cleared <- list()
  sess <- shiny::MockShinySession$new()
  orig <- sess$sendCustomMessage
  sess$sendCustomMessage <- function(type, message) {
    if (identical(type, "shinyOAuth:clearQueryAndFixTitle")) {
      cleared[[length(cleared) + 1L]] <<- message
    }
    orig(type, message)
  }

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should ignore query response params for",
          "form_post.jwt clients before JWKS fetch"
        )
      )
    },
    swap_code_for_token_set = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should ignore query response params for",
          "form_post.jwt clients before token exchange"
        )
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        session = sess,
        expr = {
          values$browser_token <- browser_token
          values$build_auth_url()

          expect_length(client@state_store$keys(), 1L)

          values$.process_query("?response=not-a-compact-jwt")
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_null(values$error)
          expect_null(values$error_description)
          expect_length(client@state_store$keys(), 1L)
          expect_length(cleared, 0L)
        }
      )
    }
  )
})

test_that("oauth_module_server rejects form_post.jwt handles mixed with compact response params", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  browser_token <- valid_browser_token()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      values$browser_token <- browser_token
      values$build_auth_url()
      handle <- shinyOAuth:::oauth_form_post_store_set(
        client,
        "auth",
        list(response = "header.payload.signature")
      )

      values$.process_query(paste0(
        jarm_form_post_query(handle, "auth"),
        "&response=header.payload.signature"
      ))
      session$flushReact()

      expect_identical(values$error, "invalid_callback_query")
      expect_match(values$error_description %||% "", "must not be combined")
      expect_false(isTRUE(values$authenticated))
    }
  )
})

test_that("oauth_module_server ignores unrelated query response params for query.jwt clients", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  client <- make_jarm_test_client(response_mode = "query.jwt")
  browser_token <- valid_browser_token()
  cleared <- list()
  sess <- shiny::MockShinySession$new()
  orig <- sess$sendCustomMessage
  sess$sendCustomMessage <- function(type, message) {
    if (identical(type, "shinyOAuth:clearQueryAndFixTitle")) {
      cleared[[length(cleared) + 1L]] <<- message
    }
    orig(type, message)
  }

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should ignore unrelated query response",
          "params before JWKS fetch"
        )
      )
    },
    swap_code_for_token_set = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should ignore unrelated query response",
          "params before token exchange"
        )
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        session = sess,
        expr = {
          values$browser_token <- browser_token
          values$build_auth_url()

          expect_length(client@state_store$keys(), 1L)

          values$.process_query("?response=keep-me")
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_null(values$error)
          expect_null(values$error_description)
          expect_length(client@state_store$keys(), 1L)
          expect_length(cleared, 0L)
        }
      )
    }
  )
})

test_that("oauth_module_server handles query.jwt error callbacks and blocks replay", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(...) {
      testthat::fail(
        "oauth_module_server should not exchange tokens for JARM error callbacks"
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              error = "access_denied",
              error_description = "Denied",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )
          query <- paste0(
            "?response=",
            utils::URLencode(response, reserved = TRUE)
          )

          values$.process_query(query)
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, "access_denied")
          expect_identical(values$error_description, "Denied")
          expect_null(values$error_uri)
          expect_length(client@state_store$keys(), 0L)

          values$error <- NULL
          values$error_description <- NULL
          values$error_uri <- NULL

          values$.process_query(query)
          session$flushReact()

          expect_identical(values$error, "invalid_state")
          expect_match(
            values$error_description %||% "",
            "state",
            ignore.case = TRUE
          )
        }
      )
    }
  )
})

test_that("validate_jarm_response decrypts encrypted JARM payloads", {
  sig_key <- openssl::rsa_keygen()
  enc_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = enc_key
  )
  client@provider@authorization_encryption_alg_values_supported <- "RSA-OAEP"
  client@provider@authorization_encryption_enc_values_supported <- "A256CBC-HS512"
  now <- floor(as.numeric(Sys.time()))
  inner_jwt <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  response <- shinyOAuth:::jwe_compact_encrypt(
    plaintext = inner_jwt,
    public_key = enc_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    kid = "enc-1",
    cty = "JWT"
  )
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))

  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )

  normalized <- shinyOAuth:::validate_jarm_response(client, response)

  expect_identical(normalized$type, "code")
  expect_identical(normalized$code, "ok")
  expect_identical(normalized$state, "state-1")
})

test_that("validate_jarm_response rejects encrypted JARM crit headers", {
  sig_key <- openssl::rsa_keygen()
  enc_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = enc_key
  )
  now <- floor(as.numeric(Sys.time()))
  inner_jwt <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  response <- make_encrypted_jarm(
    plaintext = inner_jwt,
    public_key = enc_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    kid = "enc-1",
    cty = "JWT",
    extra_header = list(crit = list("exp"), exp = TRUE)
  )

  testthat::local_mocked_bindings(
    jwe_compact_decrypt = function(...) {
      testthat::fail(
        "outer JWE crit headers should be rejected before decryption"
      )
    },
    fetch_jwks = function(...) {
      testthat::fail(
        "outer JWE crit headers should be rejected before signature verification"
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "unsupported critical header parameter"
  )
})

test_that("validate_jarm_response rejects encrypted JARM without JWT cty", {
  sig_key <- openssl::rsa_keygen()
  enc_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = enc_key
  )
  now <- floor(as.numeric(Sys.time()))
  inner_jwt <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  missing_cty <- make_encrypted_jarm(
    plaintext = inner_jwt,
    public_key = enc_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    kid = "enc-1"
  )
  wrong_cty <- make_encrypted_jarm(
    plaintext = inner_jwt,
    public_key = enc_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    kid = "enc-1",
    cty = "application/jwt"
  )

  testthat::local_mocked_bindings(
    jwe_compact_decrypt = function(...) {
      testthat::fail(
        "outer JWE cty should be rejected before decryption"
      )
    },
    fetch_jwks = function(...) {
      testthat::fail(
        "outer JWE cty should be rejected before signature verification"
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, missing_cty),
    class = "shinyOAuth_state_error",
    regexp = "missing required cty header"
  )
  expect_error(
    shinyOAuth:::validate_jarm_response(client, wrong_cty),
    class = "shinyOAuth_state_error",
    regexp = "cty header invalid"
  )
})

test_that("validate_jarm_response rejects partially matched encrypted header names", {
  enc_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = enc_key
  )

  missing_enc <- make_compact_jwe_with_header(
    '{"alg":"RSA-OAEP","encx":"A256CBC-HS512","cty":"JWT"}'
  )
  missing_cty <- make_compact_jwe_with_header(
    '{"alg":"RSA-OAEP","enc":"A256CBC-HS512","ctyx":"JWT"}'
  )

  testthat::local_mocked_bindings(
    jwe_compact_decrypt = function(...) {
      testthat::fail(
        paste(
          "validate_jarm_response should reject exact-name encrypted header",
          "mismatches before decryption"
        )
      )
    },
    fetch_jwks = function(...) {
      testthat::fail(
        paste(
          "validate_jarm_response should reject exact-name encrypted header",
          "mismatches before JWKS fetch"
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, missing_enc),
    class = "shinyOAuth_state_error",
    regexp = "header missing enc"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, missing_cty),
    class = "shinyOAuth_state_error",
    regexp = "missing required cty header"
  )
})

test_that("validate_jarm_response rejects encrypted JARM with wrong kid", {
  sig_key <- openssl::rsa_keygen()
  enc_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = enc_key,
    authorization_response_decryption_private_key_kid = "enc-expected"
  )
  now <- floor(as.numeric(Sys.time()))
  inner_jwt <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  response <- make_encrypted_jarm(
    plaintext = inner_jwt,
    public_key = enc_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    kid = "enc-actual",
    cty = "JWT"
  )

  testthat::local_mocked_bindings(
    jwe_compact_decrypt = function(...) {
      testthat::fail(
        "outer JWE kid mismatch should be rejected before decryption"
      )
    },
    fetch_jwks = function(...) {
      testthat::fail(
        "outer JWE kid mismatch should be rejected before signature verification"
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::validate_jarm_response(client, response),
    class = "shinyOAuth_state_error",
    regexp = "Encrypted JARM kid mismatch"
  )
})

test_that("validate_jarm_response wraps malformed encrypted JARM failures", {
  sig_key <- openssl::rsa_keygen()
  enc_key <- openssl::rsa_keygen()
  wrong_key <- openssl::rsa_keygen()
  now <- floor(as.numeric(Sys.time()))
  inner_jwt <- make_signed_jarm(
    payload_list = list(
      iss = "https://issuer.example.com",
      aud = "abc",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  encrypted_response <- shinyOAuth:::jwe_compact_encrypt(
    plaintext = inner_jwt,
    public_key = enc_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    kid = "enc-1",
    cty = "JWT"
  )

  parse_client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = enc_key
  )
  parse_client@provider@authorization_encryption_alg_values_supported <-
    "RSA-OAEP"
  parse_client@provider@authorization_encryption_enc_values_supported <-
    "A256CBC-HS512"

  decrypt_client <- make_jarm_test_client(
    response_mode = "query.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = wrong_key
  )
  decrypt_client@provider@authorization_encryption_alg_values_supported <-
    "RSA-OAEP"
  decrypt_client@provider@authorization_encryption_enc_values_supported <-
    "A256CBC-HS512"

  expect_error(
    shinyOAuth:::validate_jarm_response(parse_client, "a.b.c.d.e"),
    class = "shinyOAuth_state_error",
    regexp = "Encrypted JARM response could not be parsed"
  )
  expect_error(
    shinyOAuth:::validate_jarm_response(decrypt_client, encrypted_response),
    class = "shinyOAuth_state_error",
    regexp = "Encrypted JARM response could not be decrypted"
  )
})

test_that("oauth_form_post_ui returns 400 for malformed encrypted JARM callbacks", {
  enc_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(
    response_mode = "form_post.jwt",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = enc_key
  )
  client@provider@authorization_encryption_alg_values_supported <-
    "RSA-OAEP"
  client@provider@authorization_encryption_enc_values_supported <-
    "A256CBC-HS512"
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  keys_before <- sort(client@state_store$keys())

  resp <- ui(make_jarm_form_post_req(
    body = "response=a.b.c.d.e"
  ))

  expect_identical(resp$status, 400L)
  expect_identical(
    resp$content,
    "OAuth form_post callback could not be processed."
  )
  expect_false("Location" %in% names(resp$headers))
  expect_identical(sort(client@state_store$keys()), keys_before)
})

test_that("oauth_module_server handles query.jwt callbacks", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          values$.process_query(paste0(
            "?response=",
            utils::URLencode(response, reserved = TRUE)
          ))
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
        }
      )
    }
  )
})

test_that("oauth_module_server ignores query JARM-like response params for form_post.jwt clients", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  browser_token <- valid_browser_token()

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should ignore query JARM-like params for",
          "form_post.jwt clients before JARM signature validation"
        )
      )
    },
    swap_code_for_token_set = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should ignore query JARM-like params for",
          "form_post.jwt clients before token exchange"
        )
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = client@client_id,
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          expect_length(client@state_store$keys(), 1L)

          values$.process_query(paste0(
            "?response=",
            utils::URLencode(response, reserved = TRUE)
          ))
          session$flushReact()

          expect_false(isTRUE(values$authenticated))
          expect_null(values$error)
          expect_null(values$error_description)
          expect_length(client@state_store$keys(), 1L)
        }
      )
    }
  )
})

test_that("oauth_form_post_ui rejects form_post.jwt bodies that mix response with direct callback params", {
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  keys_before <- sort(client@state_store$keys())
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  resp <- ui(make_jarm_form_post_req(
    body = paste0(
      "response=header.payload.signature",
      "&code=attack"
    )
  ))

  expect_identical(resp$status, 400L)
  expect_identical(
    resp$content,
    paste(
      "OAuth form_post JARM callback must not contain both response and",
      "direct OAuth callback parameters."
    )
  )
  expect_false("Location" %in% names(resp$headers))
  expect_identical(sort(client@state_store$keys()), keys_before)

  reject_events <- Filter(
    function(e) {
      identical(e$type, "audit_callback_validation_failed") &&
        identical(e$phase, "form_post_request_validation")
    },
    events
  )
  expect_length(reject_events, 1L)
  expect_match(
    reject_events[[1L]]$error_class %||% "",
    "shinyOAuth_form_post_http_error",
    fixed = TRUE
  )
})

test_that("oauth_form_post_ui rejects direct form_post callbacks for form_post.jwt clients", {
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  keys_before <- sort(client@state_store$keys())

  resp <- ui(make_jarm_form_post_req(
    body = paste0(
      "code=attack",
      "&state=state-1",
      "&iss=",
      utils::URLencode(client@provider@issuer, reserved = TRUE)
    )
  ))

  expect_identical(resp$status, 400L)
  expect_identical(
    resp$content,
    paste(
      "OAuth form_post JARM callback must include the response",
      "parameter; direct OAuth callback parameters are not accepted."
    )
  )
  expect_false("Location" %in% names(resp$headers))
  expect_identical(sort(client@state_store$keys()), keys_before)
})

test_that("oauth_form_post_ui rejects form_post.jwt bodies with invalid inner state before storing", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  keys_before <- sort(client@state_store$keys())
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = now + 300,
      code = "ok",
      state = "definitely-not-a-valid-state"
    ),
    key = sig_key,
    kid = "sig-1"
  )

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth",
    {
      resp <- ui(make_jarm_form_post_req(
        body = paste0(
          "response=",
          utils::URLencode(response, reserved = TRUE)
        )
      ))

      expect_identical(resp$status, 400L)
      expect_identical(
        resp$content,
        "OAuth form_post callback could not be processed."
      )
      expect_false("Location" %in% names(resp$headers))
      expect_identical(sort(client@state_store$keys()), keys_before)
    }
  )
})

test_that("oauth_form_post_ui audits form_post.jwt validation failures", {
  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  keys_before <- sort(client@state_store$keys())
  now <- floor(as.numeric(Sys.time()))
  response <- make_signed_jarm(
    payload_list = list(
      iss = client@provider@issuer,
      aud = "wrong-client",
      exp = now + 300,
      code = "ok",
      state = "state-1"
    ),
    key = sig_key,
    kid = "sig-1"
  )
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth",
    {
      resp <- ui(make_jarm_form_post_req(
        body = paste0(
          "response=",
          utils::URLencode(response, reserved = TRUE)
        )
      ))

      expect_identical(resp$status, 400L)
      expect_identical(
        resp$content,
        "OAuth form_post callback could not be processed."
      )
      expect_false("Location" %in% names(resp$headers))
      expect_identical(sort(client@state_store$keys()), keys_before)
    }
  )

  reject_events <- Filter(
    function(e) {
      identical(e$type, "audit_callback_validation_failed") &&
        identical(e$phase, "form_post_request_validation")
    },
    events
  )
  expect_length(reject_events, 1L)
  expect_match(
    reject_events[[1L]]$error_class %||% "",
    "shinyOAuth_state_error",
    fixed = TRUE
  )
})

test_that("oauth_module_server handles bridged form_post.jwt callbacks", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(response, reserved = TRUE)
            )
          ))
          expect_identical(post_resp$status, 303L)
          handle <- parse_query_param(
            post_resp$headers$Location,
            "shinyOAuth_form_post",
            decode = TRUE
          )

          values$.process_query(jarm_form_post_query(handle, "auth"))
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
        }
      )
    }
  )
})

test_that("oauth_module_server reuses bridged form_post.jwt validation after the POST bridge", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  fetch_calls <- 0L

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) {
      fetch_calls <<- fetch_calls + 1L
      if (fetch_calls == 1L) {
        return(jwks)
      }

      testthat::fail(
        paste(
          "oauth_module_server should reuse the POST bridge's validated",
          "form_post.jwt payload instead of fetching JWKS again"
        )
      )
    },
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(response, reserved = TRUE)
            )
          ))
          expect_identical(post_resp$status, 303L)
          handle <- parse_query_param(
            post_resp$headers$Location,
            "shinyOAuth_form_post",
            decode = TRUE
          )

          values$.process_query(jarm_form_post_query(handle, "auth"))
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
          expect_identical(fetch_calls, 1L)
        }
      )
    }
  )
})

test_that("oauth_module_server accepts bridged form_post.jwt callbacks with unrelated response query params", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          post_resp <- ui(make_jarm_form_post_req(
            query = "response=keep-me",
            body = paste0(
              "response=",
              utils::URLencode(response, reserved = TRUE)
            )
          ))
          expect_identical(post_resp$status, 303L)
          expect_identical(
            parse_query_param(
              post_resp$headers$Location,
              "response",
              decode = TRUE
            ),
            "keep-me"
          )

          values$.process_query(post_resp$headers$Location)
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
        }
      )
    }
  )
})

test_that("oauth_module_server rejects bridged form_post JARM callbacks for query.jwt clients before JWT processing", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "query.jwt")
  browser_token <- valid_browser_token()
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should reject form_post transport mismatches",
          "before JARM signature validation"
        )
      )
    },
    swap_code_for_token_set = function(...) {
      testthat::fail(
        paste(
          "oauth_module_server should reject form_post transport mismatches",
          "before token exchange"
        )
      )
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))
          response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = client@client_id,
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(response, reserved = TRUE)
            )
          ))
          expect_identical(post_resp$status, 400L)
          expect_identical(
            post_resp$content,
            "OAuth form_post callback could not be processed."
          )
          expect_false("Location" %in% names(post_resp$headers))
          expect_false(isTRUE(values$authenticated))
          expect_length(client@state_store$keys(), 1L)
          expect_identical(values$error, NULL)
        }
      )
    }
  )
})

test_that("oauth_module_server rejects bridged form_post.jwt aud mismatches without consuming pending state", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  sig_key <- openssl::rsa_keygen()
  client <- make_jarm_test_client(response_mode = "form_post.jwt")
  jwks <- list(keys = list(make_jarm_public_jwk(sig_key, kid = "sig-1")))
  browser_token <- valid_browser_token()
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = client)
  exchanged_codes <- character(0)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  testthat::with_mocked_bindings(
    fetch_jwks = function(...) jwks,
    swap_code_for_token_set = function(client, code, code_verifier) {
      exchanged_codes <<- c(exchanged_codes, code)
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          values$browser_token <- browser_token
          url <- values$build_auth_url()
          enc_state <- parse_query_param(url, "state")
          now <- floor(as.numeric(Sys.time()))

          bad_response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "wrong-client",
              exp = now + 300,
              code = "attack",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )

          expect_length(client@state_store$keys(), 1L)

          bad_post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(bad_response, reserved = TRUE)
            )
          ))
          expect_identical(bad_post_resp$status, 400L)
          expect_identical(
            bad_post_resp$content,
            "OAuth form_post callback could not be processed."
          )
          expect_false("Location" %in% names(bad_post_resp$headers))
          expect_false(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
          expect_length(client@state_store$keys(), 1L)
          expect_identical(exchanged_codes, character(0))
          expect_false(any(vapply(
            events,
            function(e) identical(e$type, "audit_callback_validation_success"),
            logical(1)
          )))

          good_response <- make_signed_jarm(
            payload_list = list(
              iss = client@provider@issuer,
              aud = "abc",
              exp = now + 300,
              code = "ok",
              state = enc_state
            ),
            key = sig_key,
            kid = "sig-1"
          )
          good_post_resp <- ui(make_jarm_form_post_req(
            body = paste0(
              "response=",
              utils::URLencode(good_response, reserved = TRUE)
            )
          ))
          expect_identical(good_post_resp$status, 303L)
          good_handle <- parse_query_param(
            good_post_resp$headers$Location,
            "shinyOAuth_form_post",
            decode = TRUE
          )

          values$.process_query(jarm_form_post_query(good_handle, "auth"))
          session$flushReact()

          expect_true(isTRUE(values$authenticated))
          expect_identical(values$error, NULL)
          expect_identical(exchanged_codes, "ok")
          expect_length(client@state_store$keys(), 0L)
          expect_true(any(vapply(
            events,
            function(e) identical(e$type, "audit_callback_validation_success"),
            logical(1)
          )))
        }
      )
    }
  )
})
