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
  par_url = NA_character_
) {
  oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = issuer,
    par_url = par_url,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body",
    id_token_required = FALSE,
    id_token_validation = FALSE,
    allowed_token_types = character()
  )
}

make_jar_test_client <- function(
  provider = make_jar_test_provider(),
  client_secret = paste(rep("s", 32), collapse = ""),
  client_private_key = NULL,
  client_private_key_kid = NULL,
  authorization_request_signing_alg = NULL,
  authorization_request_audience = NULL
) {
  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = client_secret,
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 60),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    client_private_key = client_private_key,
    client_private_key_kid = client_private_key_kid,
    authorization_request_mode = "request",
    authorization_request_signing_alg = authorization_request_signing_alg,
    authorization_request_audience = authorization_request_audience
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
