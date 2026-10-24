hmac_profile_provider <- function(...) {
  settings <- utils::modifyList(
    list(
      name = "hmac-profile-binding",
      issuer = "https://issuer.example",
      auth_url = "https://issuer.example/authorize",
      token_url = "https://issuer.example/token",
      token_auth_style = "public",
      id_token_allowed_algs = "HS256",
      use_nonce = FALSE,
      userinfo_required = FALSE,
      userinfo_id_token_match = FALSE
    ),
    list(...)
  )
  do.call(oauth_provider, settings)
}

hmac_profile_client <- function(provider, ...) {
  settings <- utils::modifyList(
    list(
      provider = provider,
      client_id = "hmac-client",
      client_secret = strrep("s", 64L),
      redirect_uri = "https://app.example/callback",
      scopes = "openid"
    ),
    list(...)
  )
  do.call(oauth_client, settings)
}

test_that("ID tokens bind shared HMAC secrets across assertions, JAR and JARM", {
  local_options(shinyOAuth.allow_hs = TRUE)
  for (id_alg in c("HS256", "HS384", "HS512")) {
    for (other_alg in setdiff(c("HS256", "HS384", "HS512"), id_alg)) {
      provider <- hmac_profile_provider(id_token_allowed_algs = id_alg)
      expect_error(
        hmac_profile_client(
          provider,
          request_object_mode = "request",
          request_object_signing_alg = other_alg
        ),
        "same HMAC secret"
      )
      expect_error(
        hmac_profile_client(
          provider,
          response_mode = "query.jwt",
          jarm_signed_response_alg = other_alg
        ),
        "same HMAC secret"
      )
      provider@token_auth_style <- "client_secret_jwt"
      expect_error(
        hmac_profile_client(provider, client_assertion_alg = other_alg),
        "same HMAC secret"
      )
    }
  }
  provider <- hmac_profile_provider(id_token_allowed_algs = "HS512")
  expect_error(
    hmac_profile_client(provider, request_object_mode = "request"),
    "same HMAC secret"
  )
  provider@token_auth_style <- "client_secret_jwt"
  expect_error(hmac_profile_client(provider), "same HMAC secret")
})

test_that("OAuth-only clients bind JAR, JARM and assertion defaults too", {
  provider <- hmac_profile_provider(
    infer_oidc_from_issuer = FALSE,
    id_token_validation = FALSE,
    id_token_allowed_algs = "RS256",
    token_auth_style = "client_secret_jwt"
  )
  expect_error(
    hmac_profile_client(
      provider,
      request_object_mode = "request",
      request_object_signing_alg = "HS384"
    ),
    "same HMAC secret"
  )
  expect_error(
    hmac_profile_client(
      provider,
      response_mode = "query.jwt",
      jarm_signed_response_alg = "HS512"
    ),
    "same HMAC secret"
  )
  provider@token_auth_style <- "public"
  expect_error(
    hmac_profile_client(
      provider,
      request_object_mode = "request",
      response_mode = "query.jwt",
      jarm_signed_response_alg = "HS512"
    ),
    "same HMAC secret"
  )
  # Inactive settings do not reserve algorithms for unused JWT profiles.
  expect_s7_class(
    hmac_profile_client(
      provider,
      request_object_signing_alg = "HS384",
      client_assertion_alg = "HS512"
    ),
    OAuthClient
  )
})

test_that("endpoint overrides bind identical key bytes but permit distinct secrets", {
  local_options(shinyOAuth.allow_hs = TRUE)
  provider <- hmac_profile_provider(
    par_url = "https://issuer.example/par",
    introspection_url = "https://issuer.example/introspect",
    revocation_url = "https://issuer.example/revoke"
  )
  for (endpoint in c("par", "introspection", "revocation")) {
    override <- list(
      token_auth_style = "client_secret_jwt",
      client_assertion_alg = "HS512"
    )
    expect_error(
      hmac_profile_client(
        provider,
        endpoint_auth = setNames(list(override), endpoint)
      ),
      "same HMAC secret"
    )
    override[["client_secret"]] <- strrep("e", 64L)
    client <- hmac_profile_client(
      provider,
      endpoint_auth = setNames(list(override), endpoint)
    )
    auth <- endpoint_auth_client(client, endpoint)
    expect_identical(
      parse_jwt_header(build_client_assertion(auth, provider@issuer))[["alg"]],
      "HS512"
    )
    override[["client_secret"]] <- strrep("s", 64L)
    expect_error(
      client@endpoint_auth <- setNames(list(override), endpoint),
      "same HMAC secret"
    )
  }
  # Compare the normalized bytes used by the cryptography, not R's encoding tags.
  utf8 <- strrep("\u00e9", 32L)
  latin1 <- iconv(utf8, "UTF-8", "latin1")
  expect_error(
    hmac_profile_client(
      provider,
      client_secret = utf8,
      endpoint_auth = list(
        revocation = list(
          token_auth_style = "client_secret_jwt",
          client_secret = latin1,
          client_assertion_alg = "HS512"
        )
      )
    ),
    "same HMAC secret"
  )
  # Endpoint-only keys are bound against each other as well as the main secret.
  expect_error(
    hmac_profile_client(
      provider,
      endpoint_auth = list(
        introspection = list(
          token_auth_style = "client_secret_jwt",
          client_secret = strrep("e", 64L),
          client_assertion_alg = "HS384"
        ),
        revocation = list(
          token_auth_style = "client_secret_jwt",
          client_secret = strrep("e", 64L),
          client_assertion_alg = "HS512"
        )
      )
    ),
    "same HMAC secret"
  )
})

test_that("metadata-selected endpoint algorithms participate in HMAC binding", {
  local_options(shinyOAuth.allow_hs = TRUE)
  for (endpoint in c("introspection", "revocation")) {
    provider <- hmac_profile_provider(
      introspection_url = "https://issuer.example/introspect",
      revocation_url = "https://issuer.example/revoke",
      endpoint_auth_metadata = setNames(
        list(list(
          methods = "client_secret_jwt",
          signing_algs = c("HS512", "HS256")
        )),
        endpoint
      )
    )
    override <- list(token_auth_style = "client_secret_jwt")
    expect_error(
      hmac_profile_client(
        provider,
        endpoint_auth = setNames(list(override), endpoint)
      ),
      "same HMAC secret"
    )
    override[["client_assertion_alg"]] <- "HS256"
    client <- hmac_profile_client(
      provider,
      endpoint_auth = setNames(list(override), endpoint)
    )
    expect_identical(
      endpoint_auth_client(client, endpoint)@client_assertion_alg,
      "HS256"
    )
  }
})

test_that("restored conflicting settings fail at each HMAC operation", {
  local_options(shinyOAuth.allow_hs = TRUE, shinyOAuth.skip_id_sig = FALSE)
  provider <- hmac_profile_provider(token_auth_style = "client_secret_jwt")
  client <- hmac_profile_client(
    provider,
    client_assertion_alg = "HS256",
    request_object_mode = "request",
    request_object_signing_alg = "HS256",
    response_mode = "query.jwt",
    jarm_signed_response_alg = "HS256"
  )
  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    iss = provider@issuer,
    aud = client@client_id,
    sub = "user",
    iat = now,
    exp = now + 120
  )
  id_token <- encode_hmac_jwt_with_header(
    claims,
    client@client_secret,
    list(alg = "HS256"),
    256L
  )
  jarm <- encode_hmac_jwt_with_header(
    c(claims, list(code = "code", state = "state")),
    client@client_secret,
    list(alg = "HS256"),
    256L
  )
  attr(client, "client_assertion_alg") <- "HS384"
  restored <- unserialize(serialize(client, NULL))
  expect_error(
    build_client_assertion(restored, provider@issuer),
    "same HMAC secret",
    class = "shinyOAuth_config_error"
  )
  expect_error(
    build_authorization_request_object(
      restored,
      list(client_id = client@client_id, response_type = "code")
    ),
    "same HMAC secret",
    class = "shinyOAuth_config_error"
  )
  expect_error(
    validate_id_token(restored, id_token),
    "same HMAC secret",
    class = "shinyOAuth_id_token_error"
  )
  expect_error(
    validate_jarm_response(restored, jarm),
    "same HMAC secret",
    class = "shinyOAuth_state_error"
  )
})
