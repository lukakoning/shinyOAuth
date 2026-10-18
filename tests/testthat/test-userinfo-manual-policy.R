test_that("both provider constructors infer binding independently of automatic UserInfo", {
  for (constructor in list(oauth_provider, OAuthProvider)) {
    for (nonce_only in c(FALSE, TRUE)) {
      args <- list(
        name = "manual-userinfo",
        issuer = "https://issuer.example.com",
        auth_url = "https://issuer.example.com/authorize",
        token_url = "https://issuer.example.com/token",
        userinfo_url = "https://issuer.example.com/userinfo",
        userinfo_required = FALSE,
        use_nonce = nonce_only,
        id_token_validation = !nonce_only
      )
      provider <- do.call(constructor, args)
      expect_false(provider@userinfo_required)
      expect_true(provider@userinfo_id_token_match)

      args[["userinfo_id_token_match"]] <- FALSE
      expect_false(do.call(constructor, args)@userinfo_id_token_match)

      args[["userinfo_id_token_match"]] <- TRUE
      args[["userinfo_signed_jwt_required"]] <- TRUE
      strict <- do.call(constructor, args)
      expect_true(strict@userinfo_id_token_match)
      expect_true(strict@userinfo_signed_jwt_required)

      args[["userinfo_url"]] <- NA_character_
      expect_error(do.call(constructor, args), "requires a valid userinfo_url")
    }
  }
})

test_that("manual OIDC UserInfo requires and matches a cryptographically validated identity", {
  provider <- oauth_provider(
    name = "manual-userinfo",
    issuer = "https://issuer.example.com",
    auth_url = "https://issuer.example.com/authorize",
    token_url = "https://issuer.example.com/token",
    userinfo_url = "https://issuer.example.com/userinfo",
    userinfo_required = FALSE,
    token_auth_style = "body",
    use_nonce = FALSE
  )
  client <- oauth_client(
    provider,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = "openid"
  )
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(write_test_jwk(key[["pubkey"]]), simplifyVector = FALSE)
  testthat::local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(jwk)),
    .package = "shinyOAuth"
  )
  id_token <- jose::jwt_encode_sig(jose::jwt_claim(
    iss = provider@issuer,
    aud = client@client_id,
    sub = "alice",
    iat = as.numeric(Sys.time()),
    exp = as.numeric(Sys.time()) + 300
  ), key)
  claims <- shinyOAuth:::validate_id_token(client, id_token)
  token <- OAuthToken(
    access_token = "access-token",
    token_type = "Bearer",
    id_token = id_token,
    id_token_validated = isTRUE(attr(claims, "signature_verified", exact = TRUE))
  )
  expect_true(token@id_token_validated)

  response_sub <- "alice"
  response_type <- "application/json"
  requests <- 0L
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      requests <<- requests + 1L
      profile <- list(sub = response_sub, iss = provider@issuer, aud = client@client_id)
      body <- if (identical(response_type, "application/jwt")) {
        jose::jwt_encode_sig(do.call(jose::jwt_claim, profile), key)
      } else {
        as.character(jsonlite::toJSON(profile, auto_unbox = TRUE))
      }
      httr2::response(
        url = req[["url"]], status = 200L,
        headers = list("content-type" = response_type), body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  expect_identical(get_userinfo(client, token)[["sub"]], "alice")
  expect_error(get_userinfo(client, token@access_token), "Cannot verify UserInfo subject")
  unvalidated <- token
  unvalidated@id_token_validated <- FALSE
  expect_error(get_userinfo(client, unvalidated), "Cannot verify UserInfo subject")
  response_sub <- "bob"
  expect_error(get_userinfo(client, token), class = "shinyOAuth_userinfo_mismatch")

  client@provider@userinfo_signed_jwt_required <- TRUE
  expect_error(get_userinfo(client, token), class = "shinyOAuth_userinfo_error")
  response_type <- "application/jwt"
  expect_error(get_userinfo(client, token), class = "shinyOAuth_userinfo_mismatch")
  response_sub <- "alice"
  expect_identical(get_userinfo(client, token)[["sub"]], "alice")

  # Automatic retrieval remains disabled even with both verification policies.
  before_login <- requests
  browser <- valid_browser_token()
  state <- parse_query_param(shinyOAuth:::prepare_call(client, browser_token = browser), "state")
  testthat::local_mocked_bindings(
    swap_code_for_token_set = function(...) list(
      access_token = "access-token", token_type = "Bearer", id_token = id_token,
      scope = "openid", expires_in = 300
    ),
    .package = "shinyOAuth"
  )
  result <- shinyOAuth:::handle_callback(client, code = "code", state = state, browser_token = browser)
  expect_true(result@id_token_validated)
  expect_identical(requests, before_login)

  # Explicitly unbound retrieval still compares any available validated identity.
  client@provider@userinfo_signed_jwt_required <- FALSE
  client@provider@userinfo_id_token_match <- FALSE
  response_type <- "application/json"
  response_sub <- "bob"
  expect_identical(get_userinfo(client, token@access_token)[["sub"]], "bob")
  expect_error(get_userinfo(client, token), class = "shinyOAuth_userinfo_mismatch")
})
