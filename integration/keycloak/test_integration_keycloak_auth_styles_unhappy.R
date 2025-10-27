# Unhappy-path tests for token_endpoint auth styles against Keycloak
# - Exercise server rejections (invalid_client) and local configuration errors

get_issuer <- function() {
  "http://localhost:8080/realms/shinyoauth"
}

keycloak_reachable <- function() {
  issuer <- get_issuer()
  disc <- paste0(issuer, "/.well-known/openid-configuration")
  ok <- tryCatch(
    {
      resp <- httr2::request(disc) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "application/json") |>
        httr2::req_perform()
      !httr2::resp_is_error(resp)
    },
    error = function(...) FALSE
  )
  isTRUE(ok)
}

fetch_access_token_cc <- function(provider) {
  # Acquire a service-account access token from the known confidential client
  resp <- httr2::request(provider@token_url) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_body_form(
      grant_type = "client_credentials",
      client_id = "shiny-confidential",
      client_secret = "secret"
    ) |>
    httr2::req_perform()
  stopifnot(!httr2::resp_is_error(resp))
  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  stopifnot(
    is.list(body),
    is.character(body$access_token),
    nzchar(body$access_token)
  )
  body$access_token
}

make_provider <- function(style) {
  shinyOAuth::oauth_provider_oidc_discover(
    issuer = get_issuer(),
    token_auth_style = style
  )
}

get_good_pjwt_key <- function() {
  # Use testthat path if available, otherwise fallback to repo path
  path <- NULL
  if (requireNamespace("testthat", quietly = TRUE)) {
    path <- testthat::test_path("keys", "test_rsa")
  }
  if (is.null(path) || !file.exists(path)) {
    path <- file.path("integration", "keycloak", "keys", "test_rsa")
  }
  pk <- try(openssl::read_key(path), silent = TRUE)
  if (inherits(pk, "try-error")) {
    return(NULL)
  }
  pk
}

get_bad_pjwt_key <- function() {
  # Generate an ephemeral RSA key not registered in Keycloak
  testthat::skip_if_not_installed("openssl")
  openssl::rsa_keygen(bits = 2048)
}

maybe_skip_keycloak <- function() {
  testthat::skip_if_not(
    keycloak_reachable(),
    "Keycloak not reachable at localhost:8080"
  )
}

# 1) client_secret_jwt with wrong client secret -> server should reject (invalid_client)

testthat::test_that("client_secret_jwt: wrong client_secret is rejected (http_ error)", {
  maybe_skip_keycloak()

  prov <- make_provider("client_secret_jwt")
  token_value <- fetch_access_token_cc(prov)
  # Wrong secret on purpose
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = "secretjwt-INCORRECT",
    redirect_uri = "http://localhost:3000/callback",
    scopes = character(),
    client_assertion_alg = "HS256"
  )
  tok <- shinyOAuth::OAuthToken(access_token = token_value)

  res <- shinyOAuth::introspect_token(
    client,
    tok,
    which = "access",
    async = FALSE
  )
  testthat::expect_true(isTRUE(res$supported))
  testthat::expect_true(is.na(res$active))
  testthat::expect_match(res$status, "^http_", perl = TRUE)
})

# 2) client_secret_jwt with mismatched alg from server config -> server should reject

testthat::test_that("client_secret_jwt: mismatched alg is rejected by server", {
  maybe_skip_keycloak()

  prov <- make_provider("client_secret_jwt")
  token_value <- fetch_access_token_cc(prov)
  # Keycloak client is configured for HS256; try HS384 -> expect server failure
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = "secretjwt",
    redirect_uri = "http://localhost:3000/callback",
    scopes = character(),
    client_assertion_alg = "HS384"
  )
  tok <- shinyOAuth::OAuthToken(access_token = token_value)

  res <- shinyOAuth::introspect_token(
    client,
    tok,
    which = "access",
    async = FALSE
  )
  testthat::expect_true(isTRUE(res$supported))
  testthat::expect_true(is.na(res$active))
  testthat::expect_match(res$status, "^http_", perl = TRUE)
})

# 3) private_key_jwt with a non-matching private key -> server should reject

testthat::test_that("private_key_jwt: wrong private key is rejected (http_ error)", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("openssl")

  prov <- make_provider("private_key_jwt")
  token_value <- fetch_access_token_cc(prov)

  bad_key <- get_bad_pjwt_key()
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-pjwt",
    redirect_uri = "http://localhost:3000/callback",
    scopes = character(),
    client_private_key = bad_key
  )
  tok <- shinyOAuth::OAuthToken(access_token = token_value)

  res <- shinyOAuth::introspect_token(
    client,
    tok,
    which = "access",
    async = FALSE
  )
  testthat::expect_true(isTRUE(res$supported))
  testthat::expect_true(is.na(res$active))
  testthat::expect_match(res$status, "^http_", perl = TRUE)
})

# 4) private_key_jwt with incompatible alg for the key -> local config error (no HTTP)

testthat::test_that("private_key_jwt: incompatible alg (HS256) fails fast with config error", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("openssl")

  prov <- make_provider("private_key_jwt")
  good_key <- get_good_pjwt_key()
  testthat::skip_if(is.null(good_key), "Missing test private key")

  # Here we deliberately set an HMAC alg for private_key_jwt; the client validator
  # rejects this without making an HTTP call
  testthat::expect_error(
    shinyOAuth::oauth_client(
      provider = prov,
      client_id = "shiny-pjwt",
      redirect_uri = "http://localhost:3000/callback",
      scopes = character(),
      client_private_key = good_key,
      client_assertion_alg = "HS256"
    ),
    regexp = "client_assertion_alg 'HS256' is incompatible",
    fixed = FALSE
  )
})
