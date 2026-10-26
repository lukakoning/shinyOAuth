rsa_binding_provider <- function(...) {
  do.call(oauth_provider, utils::modifyList(list(
    name = "rsa-binding", issuer = "https://issuer.example",
    auth_url = "https://issuer.example/authorize", token_url = "https://issuer.example/token",
    jwks_uri = "https://issuer.example/jwks", token_auth_style = "private_key_jwt",
    use_nonce = FALSE, userinfo_required = FALSE, userinfo_id_token_match = FALSE
  ), list(...)))
}

rsa_binding_client <- function(provider, key, ...) {
  do.call(oauth_client, c(list(
    provider = provider, client_id = "rsa-client", redirect_uri = "https://app.example/callback",
    client_assertion_private_key = key
  ), list(...)))
}

test_that("JWKS rejects conflicting RSA material bindings before candidate filtering", {
  first <- second <- private_key_public_jwk(openssl::rsa_keygen(2048))
  first[["kid"]] <- "first"
  first[["alg"]] <- "RS256"
  second[["kid"]] <- "second"
  pin <- compute_jwk_thumbprint(first)
  for (alg in c("RS384", "RS512")) {
    second[["alg"]] <- alg
    for (keys in list(list(first, second), list(second, first))) {
      for (pins in list(NULL, pin)) {
        expect_error(validate_jwks(list(keys = keys), pins = pins), "conflicting algorithms")
        expect_error(select_candidate_jwks(list(keys = keys), kid = "first", pins = pins),
          "conflicting algorithms")
      }
    }
  }
  second[["alg"]] <- "RS256"
  expect_silent(validate_jwks(list(keys = list(first, second)), pins = pin))
  second <- private_key_public_jwk(openssl::rsa_keygen(2048))
  second[["alg"]] <- "RS384"
  expect_silent(validate_jwks(list(keys = list(first, second))))
})

test_that("unlabelled RSA aliases inherit material declarations before kid selection", {
  first <- second <- private_key_public_jwk(openssl::rsa_keygen(2048))
  first[["kid"]] <- "bare"
  second[["kid"]] <- "labelled"
  second[["alg"]] <- "RS384"
  for (keys in list(list(first, second), list(second, first))) {
    candidates <- select_candidate_jwks(list(keys = keys), kid = "bare")
    expect_length(filter_jwks_for_alg(candidates, "RS256", c("RS256", "RS384")), 0L)
    expect_length(filter_jwks_for_alg(candidates, "RS384", c("RS256", "RS384")), 1L)
  }
})

test_that("real RSA signatures cannot evade material binding with kid or pins", {
  key <- openssl::rsa_keygen(2048)
  first <- second <- private_key_public_jwk(key)
  first[["kid"]] <- "rsa256"
  first[["alg"]] <- "RS256"
  second[["kid"]] <- "rsa384"
  second[["alg"]] <- "RS384"
  jwks <- list(keys = list(first, second))
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(url = req[["url"]], status_code = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(jwks, auto_unbox = TRUE)))
  }, .package = "shinyOAuth")
  for (explicit in c(FALSE, TRUE)) {
    for (pinned in c(FALSE, TRUE)) {
      provider <- rsa_binding_provider(token_auth_style = "public",
        jwks_pins = if (pinned) compute_jwk_thumbprint(first) else character())
      if (explicit) provider@allowed_algs <- c("RS256", "RS384")
      client <- oauth_client(provider, "rsa-client", redirect_uri = "https://app.example/callback")
      now <- floor(as.numeric(Sys.time()))
      for (alg in c("RS256", "RS384")) {
        jwt <- encode_asymmetric_jwt_with_header(list(
          iss = provider@issuer, sub = "subject", aud = client@client_id,
          iat = now, exp = now + 300
        ), key, list(typ = "JWT", alg = alg, kid = if (alg == "RS256") "rsa256" else "rsa384"))
        expect_error(validate_id_token(client, jwt), "conflicting algorithms")
      }
    }
  }
})

test_that("cached JWKS with conflicting RSA aliases are evicted before reuse", {
  first <- second <- private_key_public_jwk(openssl::rsa_keygen(2048))
  first[["alg"]] <- "RS256"
  second[["alg"]] <- "RS384"
  provider <- rsa_binding_provider(token_auth_style = "public")
  cache <- cachem::cache_mem()
  fetched <- 0L
  local_mocked_bindings(req_with_retry = function(req, ...) {
    fetched <<- fetched + 1L
    httr2::response(url = req[["url"]], status_code = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(list(keys = list(first)), auto_unbox = TRUE)))
  }, .package = "shinyOAuth")
  fetch_jwks(provider@issuer, cache, provider = provider)
  expect_identical(fetched, 1L)
  cache_key <- cache[["keys"]]()[[1L]]
  entry <- cache[["get"]](cache_key)
  entry[["jwks"]] <- list(keys = list(first, second))
  cache[["set"]](cache_key, entry)
  refreshed <- fetch_jwks(provider@issuer, cache, provider = provider)
  expect_identical(fetched, 2L)
  expect_length(refreshed[["keys"]], 1L)
})

test_that("RSA outgoing profiles bind material across object and PEM aliases", {
  key <- openssl::rsa_keygen(2048)
  provider <- rsa_binding_provider()
  expect_error(rsa_binding_client(provider, key, client_assertion_alg = "RS384",
    dpop_private_key = openssl::write_pem(key), dpop_signing_alg = "RS256",
    dpop_private_key_kid = "other-kid"), "same RSA key material")
  expect_error(rsa_binding_client(provider, key, client_assertion_alg = "RS384",
    request_object_mode = "request"), "same RSA key material")
  expect_error(rsa_binding_client(provider, key, client_assertion_alg = "RS256",
    request_object_mode = "request", request_object_signing_alg = "RS384"), "same RSA key material")
  client <- rsa_binding_client(provider, key, client_assertion_alg = "RS384",
    dpop_private_key = key, dpop_signing_alg = "RS384",
    request_object_mode = "request", request_object_signing_alg = "RS384")
  expect_identical(parse_jwt_header(build_client_assertion(client, provider@token_url))[["alg"]], "RS384")
  expect_identical(parse_jwt_header(build_dpop_proof(client, "POST", provider@token_url))[["alg"]], "RS384")
  expect_type(build_authorization_request_object(client, list(client_id = client@client_id)), "character")
  expect_s7_class(rsa_binding_client(provider, key, client_assertion_alg = "RS384",
    dpop_private_key = openssl::rsa_keygen(2048), dpop_signing_alg = "RS256"), OAuthClient)
  provider@token_auth_style <- "public"
  expect_s7_class(rsa_binding_client(provider, key, client_assertion_alg = "RS384",
    dpop_private_key = key, dpop_signing_alg = "RS256"), OAuthClient)
})

test_that("RSA endpoint overrides and metadata-selected defaults bind material", {
  key <- openssl::rsa_keygen(2048)
  for (endpoint in c("par", "introspection", "revocation")) {
    provider <- rsa_binding_provider(par_url = "https://issuer.example/par",
      introspection_url = "https://issuer.example/introspect", revocation_url = "https://issuer.example/revoke")
    override <- list(client_assertion_alg = "RS384", client_assertion_private_key = openssl::write_pem(key))
    expect_error(rsa_binding_client(provider, key, client_assertion_alg = "RS256",
      endpoint_auth = setNames(list(override), endpoint)), "same RSA key material")
    override[["client_assertion_private_key"]] <- openssl::rsa_keygen(2048)
    expect_s7_class(rsa_binding_client(provider, key, client_assertion_alg = "RS256",
      endpoint_auth = setNames(list(override), endpoint)), OAuthClient)
    if (endpoint != "par") {
      provider@endpoint_auth_metadata <- setNames(list(list(
        methods = "private_key_jwt", signing_algs = "RS384"
      )), endpoint)
      expect_error(rsa_binding_client(provider, key), "same RSA key material")
    }
  }
})

test_that("RSA binding is rechecked when each signing operation runs", {
  key <- openssl::rsa_keygen(2048)
  provider <- rsa_binding_provider()
  client <- rsa_binding_client(provider, key, client_assertion_alg = "RS256",
    dpop_private_key = key, dpop_signing_alg = "RS256",
    request_object_mode = "request", request_object_signing_alg = "RS256")
  attr(client, "client_assertion_alg") <- "RS384"
  expect_error(build_client_assertion(client, provider@token_url), "same RSA key material")
  expect_error(build_dpop_proof(client, "POST", provider@token_url), "same RSA key material")
  expect_error(build_authorization_request_object(client, list(client_id = client@client_id)),
    "same RSA key material")
})
