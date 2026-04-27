query_param_names <- function(url) {
  q <- sub("^[^?]*\\?", "", url)
  if (identical(q, url) || !nzchar(q)) {
    return(character(0))
  }

  parts <- strsplit(q, "&", fixed = TRUE)[[1]]
  kv <- strsplit(parts, "=", fixed = TRUE)
  unique(vapply(kv, function(p) utils::URLdecode(p[1]), ""))
}

make_jar_test_provider <- function(
  issuer = "https://issuer.example.com",
  par_url = NA_character_,
  use_nonce = FALSE,
  extra_auth_params = list(),
  id_token_validation = FALSE,
  request_object_signing_alg_values_supported = character(0),
  require_signed_request_object = FALSE
) {
  oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = issuer,
    par_url = par_url,
    request_object_signing_alg_values_supported =
      request_object_signing_alg_values_supported,
    require_signed_request_object = require_signed_request_object,
    use_nonce = use_nonce,
    use_pkce = TRUE,
    token_auth_style = "body",
    id_token_required = FALSE,
    id_token_validation = id_token_validation,
    extra_auth_params = extra_auth_params,
    allowed_token_types = character()
  )
}

make_jar_test_client <- function(
  provider = make_jar_test_provider(),
  client_secret = paste(rep("s", 32), collapse = ""),
  client_private_key = NULL,
  client_private_key_kid = NULL,
  authorization_request_signing_alg = NULL,
  authorization_request_audience = NULL,
  scopes = c("openid", "profile"),
  resource = character(0),
  claims = NULL,
  required_acr_values = character(0)
) {
  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = client_secret,
    redirect_uri = "http://localhost:8100",
    scopes = scopes,
    state_store = cachem::cache_mem(max_age = 60),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    client_private_key = client_private_key,
    client_private_key_kid = client_private_key_kid,
    authorization_request_mode = "request",
    authorization_request_signing_alg = authorization_request_signing_alg,
    authorization_request_audience = authorization_request_audience,
    resource = resource,
    claims = claims,
    required_acr_values = required_acr_values
  )
}

test_that("prepare_call emits a signed request object instead of raw auth params", {
  cli <- make_jar_test_client()

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)

  expect_setequal(query_param_names(auth_url), c("client_id", "request"))
  expect_identical(
    parse_query_param(auth_url, "client_id", decode = TRUE),
    "abc"
  )
  expect_true(is.character(request_jwt) && nzchar(request_jwt))

  hdr <- shinyOAuth:::parse_jwt_header(request_jwt)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(hdr$typ, "oauth-authz-req+jwt")
  expect_identical(hdr$alg, "HS256")
  expect_identical(pl$iss, "abc")
  expect_identical(pl$aud, "https://issuer.example.com")
  expect_false("sub" %in% names(pl))
  expect_identical(pl$response_type, "code")
  expect_identical(pl$client_id, "abc")
  expect_identical(pl$redirect_uri, "http://localhost:8100")
  expect_identical(pl$scope, "openid profile")
  expect_identical(pl$code_challenge_method, "S256")
  expect_true(is.character(pl$state) && nzchar(pl$state))
  expect_true(is.character(pl$code_challenge) && nzchar(pl$code_challenge))
  expect_true(is.numeric(pl$iat) && is.numeric(pl$exp) && pl$exp > pl$iat)
  expect_true(is.character(pl$jti) && nzchar(pl$jti))
})

test_that("request objects default to private-key signing and honor audience overrides", {
  key <- openssl::rsa_keygen()
  cli <- make_jar_test_client(
    client_secret = "",
    client_private_key = key,
    client_private_key_kid = "kid-123",
    authorization_request_audience = "https://example.com/custom-aud"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  hdr <- shinyOAuth:::parse_jwt_header(request_jwt)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(hdr$typ, "oauth-authz-req+jwt")
  expect_identical(hdr$alg, "RS256")
  expect_identical(hdr$kid, "kid-123")
  expect_identical(pl$aud, "https://example.com/custom-aud")
})

test_that("request mode requires signing material", {
  prov <- make_jar_test_provider()

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      authorization_request_mode = "request"
    ),
    regexp = "authorization_request_mode = 'request' requires client_private_key or client_secret"
  )
})

test_that("request mode takes precedence over PAR", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(par_url = "https://example.com/par")
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(...) {
      stop(
        "PAR should not be called when authorization_request_mode = 'request'"
      )
    },
    .package = "shinyOAuth"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())

  expect_setequal(query_param_names(auth_url), c("client_id", "request"))
  expect_false(grepl("[?&]request_uri=", auth_url))
})

test_that("request object preserves repeated resource indicators", {
  cli <- make_jar_test_client(
    resource = c(
      "https://api.example.com",
      "urn:example:ledger"
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(
    unname(as.character(pl$resource)),
    c("https://api.example.com", "urn:example:ledger")
  )
})

test_that("request object preserves JSON-encoded claims requests", {
  cli <- make_jar_test_client(
    claims = list(
      userinfo = list(
        email = NULL,
        given_name = list(essential = TRUE)
      ),
      id_token = list(
        auth_time = list(essential = TRUE)
      )
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)
  claims_parsed <- jsonlite::fromJSON(pl$claims)

  expect_true("userinfo" %in% names(claims_parsed))
  expect_true("id_token" %in% names(claims_parsed))
  expect_true("email" %in% names(claims_parsed$userinfo))
  expect_true("given_name" %in% names(claims_parsed$userinfo))
  expect_identical(claims_parsed$userinfo$given_name$essential, TRUE)
  expect_identical(claims_parsed$id_token$auth_time$essential, TRUE)
})

test_that("request object preserves acr_values hints", {
  prov <- make_jar_test_provider(
    use_nonce = TRUE,
    id_token_validation = TRUE
  )
  cli <- make_jar_test_client(
    provider = prov,
    required_acr_values = c(
      "urn:mace:incommon:iap:silver",
      "urn:mace:incommon:iap:bronze"
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(
    pl$acr_values,
    paste(
      c(
        "urn:mace:incommon:iap:silver",
        "urn:mace:incommon:iap:bronze"
      ),
      collapse = " "
    )
  )
  expect_true(is.character(pl$nonce) && nzchar(pl$nonce))
})

test_that("request object preserves safe provider extra auth params", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      extra_auth_params = list(
        prompt = "login",
        login_hint = "alice",
        custom_multi = c("alpha", "beta")
      )
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(pl$prompt, "login")
  expect_identical(pl$login_hint, "alice")
  expect_identical(unname(as.character(pl$custom_multi)), c("alpha", "beta"))
})

test_that("request mode rejects incompatible explicit signing alg combinations", {
  expect_error(
    make_jar_test_client(authorization_request_signing_alg = "RS256"),
    regexp = "asymmetric authorization_request_signing_alg requires client_private_key"
  )

  expect_error(
    make_jar_test_client(
      client_secret = "",
      authorization_request_signing_alg = "HS256"
    ),
    regexp = "HS[*] authorization_request_signing_alg requires client_secret"
  )

  expect_error(
    make_jar_test_client(authorization_request_signing_alg = "none"),
    regexp = "authorization_request_signing_alg = 'none' is not supported"
  )
})

test_that("request mode rejects provider-disallowed request object algs", {
  expect_error(
    make_jar_test_client(
      provider = make_jar_test_provider(
        request_object_signing_alg_values_supported = c("PS256")
      )
    ),
    regexp = paste(
      "authorization_request_signing_alg 'HS256' is not supported by",
      "provider request_object_signing_alg_values_supported"
    )
  )

  key <- openssl::rsa_keygen()
  expect_error(
    make_jar_test_client(
      provider = make_jar_test_provider(
        request_object_signing_alg_values_supported = c("PS256")
      ),
      client_secret = "",
      client_private_key = key
    ),
    regexp = paste(
      "authorization_request_signing_alg 'RS256' is not supported by",
      "provider request_object_signing_alg_values_supported"
    )
  )
})

test_that("providers requiring signed request objects reject parameters mode", {
  prov <- make_jar_test_provider(require_signed_request_object = TRUE)

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = paste(rep("s", 32), collapse = ""),
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      )
    ),
    regexp = paste(
      "provider requires signed request objects;",
      "set authorization_request_mode = 'request'"
    )
  )
})
