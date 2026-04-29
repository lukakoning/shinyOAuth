outbound_alg_provider <- function(token_auth_style = "body") {
  oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://issuer.example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = token_auth_style,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    allowed_token_types = character()
  )
}

outbound_alg_state_key <- paste0(
  "0123456789abcdefghijklmnopqrstuvwxyz",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

outbound_alg_client <- function(
  provider = outbound_alg_provider(),
  client_secret = paste(rep("s", 64), collapse = ""),
  ...
) {
  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = client_secret,
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    state_store = cachem::cache_mem(max_age = 60),
    state_key = outbound_alg_state_key,
    ...
  )
}

outbound_alg_public_key <- function(key) {
  openssl::read_pubkey(openssl::write_pem(key))
}

outbound_alg_asym_cases <- function() {
  list(
    RS256 = openssl::rsa_keygen(2048),
    ES256 = openssl::ec_keygen(curve = "P-256"),
    ES384 = openssl::ec_keygen(curve = "P-384"),
    ES512 = openssl::ec_keygen(curve = "P-521")
  )
}

expect_jws_alg <- function(jwt, alg) {
  hdr <- shinyOAuth:::parse_jwt_header(jwt)
  testthat::expect_identical(hdr$alg, alg)
}

outbound_alg_hash <- function(data, alg) {
  switch(
    substr(alg, nchar(alg) - 2L, nchar(alg)),
    `256` = openssl::sha256(data),
    `384` = openssl::sha384(data),
    `512` = openssl::sha512(data),
    stop("unsupported test alg", call. = FALSE)
  )
}

outbound_alg_hmac <- function(data, alg, secret) {
  key <- charToRaw(secret)
  switch(
    substr(alg, nchar(alg) - 2L, nchar(alg)),
    `256` = openssl::sha256(data, key = key),
    `384` = openssl::sha384(data, key = key),
    `512` = openssl::sha512(data, key = key),
    stop("unsupported test alg", call. = FALSE)
  )
}

outbound_alg_parts <- function(jwt) {
  parts <- strsplit(jwt, ".", fixed = TRUE)[[1]]
  testthat::expect_length(parts, 3L)
  list(
    data = charToRaw(paste(parts[1:2], collapse = ".")),
    sig = jose::base64url_decode(parts[[3]])
  )
}

expect_hmac_jwt_verifies <- function(jwt, alg, secret) {
  expect_jws_alg(jwt, alg)
  parts <- outbound_alg_parts(jwt)
  testthat::expect_identical(
    parts$sig,
    unclass(outbound_alg_hmac(parts$data, alg, secret))
  )
}

expect_sig_jwt_verifies <- function(jwt, alg, key) {
  expect_jws_alg(jwt, alg)
  parts <- outbound_alg_parts(jwt)
  sig <- parts$sig
  if (startsWith(alg, "ES")) {
    bitsize <- length(sig) / 2L
    r <- sig[seq_len(bitsize)]
    s <- sig[seq_len(bitsize) + bitsize]
    sig <- openssl::ecdsa_write(r, s)
  }
  testthat::expect_true(openssl::signature_verify(
    outbound_alg_hash(parts$data, alg),
    sig,
    hash = NULL,
    pubkey = outbound_alg_public_key(key)
  ))
}

testthat::test_that("client assertions self-verify for every outbound alg", {
  testthat::skip_if_not_installed("jose")

  secret <- paste(rep("s", 64), collapse = "")
  for (alg in c("HS256", "HS384", "HS512")) {
    cli <- outbound_alg_client(
      provider = outbound_alg_provider("client_secret_jwt"),
      client_secret = secret,
      client_assertion_alg = alg
    )
    jwt <- shinyOAuth:::build_client_assertion(cli, cli@provider@token_url)
    expect_hmac_jwt_verifies(jwt, alg, secret)
  }

  asym_cases <- outbound_alg_asym_cases()
  for (alg in names(asym_cases)) {
    key <- asym_cases[[alg]]
    cli <- outbound_alg_client(
      provider = outbound_alg_provider("private_key_jwt"),
      client_secret = "",
      client_private_key = key,
      client_assertion_alg = alg
    )
    jwt <- shinyOAuth:::build_client_assertion(cli, cli@provider@token_url)
    expect_sig_jwt_verifies(jwt, alg, key)
  }
})

testthat::test_that("authorization request objects self-verify for every outbound alg", {
  testthat::skip_if_not_installed("jose")

  params <- list(
    response_type = "code",
    client_id = "abc",
    redirect_uri = "http://localhost:8100",
    scope = "openid",
    state = "state-1"
  )
  secret <- paste(rep("s", 64), collapse = "")

  for (alg in c("HS256", "HS384", "HS512")) {
    cli <- outbound_alg_client(
      client_secret = secret,
      authorization_request_mode = "request",
      authorization_request_signing_alg = alg
    )
    jwt <- shinyOAuth:::build_authorization_request_object(cli, params)
    expect_hmac_jwt_verifies(jwt, alg, secret)
  }

  asym_cases <- outbound_alg_asym_cases()
  for (alg in names(asym_cases)) {
    key <- asym_cases[[alg]]
    cli <- outbound_alg_client(
      client_secret = "",
      client_private_key = key,
      authorization_request_mode = "request",
      authorization_request_signing_alg = alg
    )
    jwt <- shinyOAuth:::build_authorization_request_object(cli, params)
    expect_sig_jwt_verifies(jwt, alg, key)
  }
})

testthat::test_that("DPoP proofs self-verify for every outbound alg", {
  testthat::skip_if_not_installed("jose")

  asym_cases <- outbound_alg_asym_cases()
  for (alg in names(asym_cases)) {
    key <- asym_cases[[alg]]
    cli <- outbound_alg_client(
      client_secret = "",
      dpop_private_key = key,
      dpop_signing_alg = alg,
      dpop_require_access_token = TRUE
    )
    jwt <- shinyOAuth:::build_dpop_proof(
      cli,
      method = "GET",
      url = "https://resource.example.com/api"
    )
    expect_sig_jwt_verifies(jwt, alg, key)
  }
})

testthat::test_that("unsupported RSA-family outbound algs are rejected", {
  rsa <- openssl::rsa_keygen(2048)
  unsupported <- c("RS384", "RS512", "PS256", "PS384", "PS512")

  for (alg in unsupported) {
    testthat::expect_error(
      outbound_alg_client(
        provider = outbound_alg_provider("private_key_jwt"),
        client_secret = "",
        client_private_key = rsa,
        client_assertion_alg = alg
      ),
      regexp = "client_assertion_alg"
    )

    testthat::expect_error(
      outbound_alg_client(
        client_secret = "",
        client_private_key = rsa,
        authorization_request_mode = "request",
        authorization_request_signing_alg = alg
      ),
      regexp = "authorization_request_signing_alg"
    )

    testthat::expect_error(
      outbound_alg_client(
        client_secret = "",
        dpop_private_key = rsa,
        dpop_signing_alg = alg
      ),
      regexp = "dpop_signing_alg"
    )
  }
})

testthat::test_that("inbound defaults exclude unsupported RSA-PSS algs", {
  prov <- outbound_alg_provider()

  testthat::expect_true(all(c("RS384", "RS512") %in% prov@allowed_algs))
  testthat::expect_false(any(
    c("PS256", "PS384", "PS512") %in% prov@allowed_algs
  ))

  testthat::expect_error(
    oauth_provider(
      name = "example",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      allowed_algs = c("PS256")
    ),
    regexp = "unsupported entries: PS256"
  )
})
