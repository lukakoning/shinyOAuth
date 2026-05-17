test_that("OAuthProvider allows query and form_post response_mode", {
  expect_error(
    OAuthProvider(
      name = "test",
      auth_url = "https://example.com/authorize",
      token_url = "https://example.com/token",
      extra_auth_params = list(response_mode = "fragment")
    ),
    regexp = "response_mode"
  )

  expect_no_error(OAuthProvider(
    name = "test",
    auth_url = "https://example.com/authorize",
    token_url = "https://example.com/token",
    extra_auth_params = list(response_mode = "query")
  ))

  expect_no_error(OAuthProvider(
    name = "test",
    auth_url = "https://example.com/authorize",
    token_url = "https://example.com/token",
    extra_auth_params = list(response_mode = " Query ")
  ))

  expect_no_error(OAuthProvider(
    name = "test",
    auth_url = "https://example.com/authorize",
    token_url = "https://example.com/token",
    extra_auth_params = list(response_mode = "form_post")
  ))

  expect_no_error(OAuthProvider(
    name = "test",
    auth_url = "https://example.com/authorize",
    token_url = "https://example.com/token",
    response_modes_supported = c("query", "form_post"),
    extra_auth_params = list(response_mode = " form_POST ")
  ))

  expect_error(
    OAuthProvider(
      name = "test",
      auth_url = "https://example.com/authorize",
      token_url = "https://example.com/token",
      response_modes_supported = c("query", "fragment"),
      extra_auth_params = list(response_mode = "form_post")
    ),
    regexp = "response_modes_supported"
  )
})

test_that("prepare_call normalizes explicit query response_mode", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@extra_auth_params <- list(
    response_mode = " Query ",
    prompt = "login"
  )

  url <- shinyOAuth:::prepare_call(cli, browser_token = valid_browser_token())

  expect_identical(
    parse_query_param(url, "response_mode", decode = TRUE),
    "query"
  )
  expect_identical(parse_query_param(url, "prompt", decode = TRUE), "login")
})

test_that("oauth_client defaults response_mode to query", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  expect_true(is.na(client@response_mode))
})

test_that("prepare_call omits implicit query response_mode by default", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@extra_auth_params <- list(prompt = "login")

  url <- shinyOAuth:::prepare_call(cli, browser_token = valid_browser_token())

  expect_true(is.na(parse_query_param(url, "response_mode", decode = TRUE)))
  expect_identical(parse_query_param(url, "prompt", decode = TRUE), "login")
})

test_that("oauth_client accepts query and form_post response_mode", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@response_modes_supported <- c("query", "form_post")

  expect_no_error(oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    response_mode = " Query "
  ))

  client <- expect_no_error(oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    response_mode = " form_POST "
  ))
  expect_identical(client@response_mode, "form_post")

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      response_mode = "fragment"
    ),
    regexp = "response_mode"
  )
})

test_that("oauth_client rejects JARM response_mode values explicitly", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@response_modes_supported <- c("query", "form_post", "form_post.jwt")

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      response_mode = "form_post.jwt"
    ),
    regexp = "JARM|JWT Secured Authorization Response Mode"
  )
})

test_that("oauth_client validates response_mode against provider support", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@response_modes_supported <- "query"

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      response_mode = "form_post"
    ),
    regexp = "response_modes_supported"
  )
})

test_that("oauth_client default query requires provider query support", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@response_modes_supported <- "form_post"

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback"
    ),
    regexp = "response_modes_supported"
  )
})

test_that("prepare_call emits oauth_client response_mode", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    response_mode = " form_POST "
  )
  cli@provider@response_modes_supported <- c("query", "form_post")

  url <- shinyOAuth:::prepare_call(cli, browser_token = valid_browser_token())

  expect_identical(
    parse_query_param(url, "response_mode", decode = TRUE),
    "form_post"
  )
})

test_that("oauth_client rejects conflicting response_mode configuration", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@response_modes_supported <- c("query", "form_post")
  prov@extra_auth_params <- list(response_mode = "query")

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      response_mode = "form_post"
    ),
    regexp = "conflicts"
  )
})

test_that("oauth_client inherits provider response_mode when unset", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@response_modes_supported <- c("query", "form_post")
  prov@extra_auth_params <- list(response_mode = "form_post")

  client <- expect_no_error(oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback"
  ))
  expect_true(is.na(client@response_mode))

  url <- shinyOAuth:::prepare_call(
    client,
    browser_token = valid_browser_token()
  )
  expect_identical(
    parse_query_param(url, "response_mode", decode = TRUE),
    "form_post"
  )
})

test_that("OIDC discovery records supported response modes", {
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

  base_metadata <- list(
    issuer = "https://issuer.example.com",
    authorization_endpoint = "https://issuer.example.com/auth",
    token_endpoint = "https://issuer.example.com/token"
  )

  prov <- discover_provider(c(
    base_metadata,
    list(response_modes_supported = c("query", "form_post"))
  ))
  expect_identical(prov@response_modes_supported, c("query", "form_post"))

  prov_default <- discover_provider(base_metadata)
  expect_identical(
    prov_default@response_modes_supported,
    c("query", "fragment")
  )
})
