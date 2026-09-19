# Exercise real discovery validation, not mocks of the provider constructor.
research_discovery <- function(
  issuer,
  methods = list("client_secret_basic", "client_secret_post"),
  endpoint_base = sub("/+$", "", issuer)
) {
  list(
    issuer = issuer,
    authorization_endpoint = paste0(endpoint_base, "/authorize"),
    token_endpoint = paste0(endpoint_base, "/token"),
    userinfo_endpoint = paste0(endpoint_base, "/userinfo"),
    jwks_uri = paste0(sub("/+$", "", issuer), "/jwks"),
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    token_endpoint_auth_methods_supported = methods,
    id_token_signing_alg_values_supported = list("RS256"),
    code_challenge_methods_supported = list("S256")
  )
}

local_research_discovery <- function(doc, url, .env = parent.frame()) {
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      expect_identical(req[["url"]], url)
      httr2::response(
        url = req[["url"]],
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(as.character(jsonlite::toJSON(doc, auto_unbox = TRUE)))
      )
    },
    .package = "shinyOAuth",
    .env = .env
  )
}

test_that("ORCID selects the environment and retains confidential OIDC checks", {
  for (sandbox in c(FALSE, TRUE)) {
    issuer <- if (sandbox) "https://sandbox.orcid.org" else "https://orcid.org"
    doc <- research_discovery(issuer, methods = list("client_secret_post"))
    doc[["code_challenge_methods_supported"]] <- NULL
    doc[["scopes_supported"]] <- list("openid")
    local_research_discovery(
      doc,
      paste0(issuer, "/.well-known/openid-configuration")
    )
    provider <- oauth_provider_orcid(sandbox = sandbox)
    expect_identical(provider@issuer, issuer)
    expect_identical(provider@token_auth_style, "body")
    expect_false(provider@use_pkce)
    expect_true(provider@use_nonce)
    expect_true(provider@id_token_required)
    expect_true(provider@id_token_validation)
    expect_true(provider@userinfo_id_token_match)

    client <- oauth_client(
      provider,
      "client",
      "secret",
      redirect_uri = "https://app.example/callback",
      scopes = "openid"
    )
    url <- prepare_call(client, browser_token = valid_browser_token())
    query <- httr2::url_parse(url)[["query"]]
    expect_identical(query[["scope"]], "openid")
    expect_true(nzchar(query[["nonce"]]))
    expect_null(query[["code_challenge"]])
  }
  for (value in list(NA, NULL, "true", 1, c(TRUE, FALSE))) {
    expect_error(
      oauth_provider_orcid(sandbox = value),
      class = "shinyOAuth_input_error"
    )
  }
})

test_that("GitLab supports hosted and subpath deployments without losing PKCE", {
  for (issuer in c("https://gitlab.com", "https://git.example.edu/gitlab")) {
    doc <- research_discovery(issuer)
    local_research_discovery(
      doc,
      paste0(issuer, "/.well-known/openid-configuration")
    )
    provider <- oauth_provider_gitlab(paste0(issuer, "/"), name = "lab")
    expect_identical(provider@name, "lab")
    expect_identical(provider@issuer, issuer)
    expect_true(provider@use_pkce)
    expect_identical(provider@pkce_method, "S256")
    expect_identical(provider@token_auth_style, "header")
    expect_true(provider@id_token_validation)
    expect_identical(
      oauth_provider_gitlab(issuer, token_auth_style = "body")@token_auth_style,
      "body"
    )
  }
})

test_that("Cognito discovers login-domain endpoints while retaining the pool issuer", {
  issuers <- c(
    "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Example",
    "https://issuer-cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Example",
    "https://cognito-idp.cn-north-1.amazonaws.com.cn/cn-north-1_Example"
  )
  for (issuer in issuers) {
    doc <- research_discovery(
      issuer,
      endpoint_base = "https://login.example.com/oauth2"
    )
    doc[["jwks_uri"]] <- paste0(issuer, "/.well-known/jwks.json")
    local_research_discovery(
      doc,
      paste0(issuer, "/.well-known/openid-configuration")
    )
    provider <- oauth_provider_cognito(issuer)
    expect_identical(provider@name, "cognito")
    expect_identical(provider@issuer, issuer)
    expect_identical(
      provider@auth_url,
      "https://login.example.com/oauth2/authorize"
    )
    expect_identical(
      provider@token_url,
      "https://login.example.com/oauth2/token"
    )
    expect_identical(provider@jwks_uri, doc[["jwks_uri"]])
    expect_true(provider@jwks_host_issuer_match)
    expect_true(provider@userinfo_id_token_match)
  }
})

test_that("Hugging Face retains confidential S256 and OIDC defaults", {
  issuer <- "https://huggingface.co"
  doc <- research_discovery(issuer)
  # Hugging Face currently spells this metadata member without _supported.
  doc[["code_challenge_methods_supported"]] <- NULL
  doc[["code_challenge_methods"]] <- list("S256")
  local_research_discovery(
    doc,
    paste0(issuer, "/.well-known/openid-configuration")
  )
  provider <- oauth_provider_huggingface()
  expect_identical(provider@name, "huggingface")
  expect_identical(provider@issuer, issuer)
  expect_identical(provider@token_auth_style, "header")
  expect_identical(provider@pkce_method, "S256")
  expect_true(provider@use_nonce)
  expect_true(provider@id_token_required)
  expect_true(provider@userinfo_id_token_match)
})

test_that("SURFconext environments have distinct issuers and retain secure defaults", {
  for (environment in c("production", "test")) {
    issuer <- if (identical(environment, "test")) {
      "https://connect.test.surfconext.nl"
    } else {
      "https://connect.surfconext.nl"
    }
    doc <- research_discovery(issuer)
    doc[["code_challenge_methods_supported"]] <- list("plain", "S256")
    local_research_discovery(
      doc,
      paste0(issuer, "/.well-known/openid-configuration")
    )
    provider <- oauth_provider_surfconext(environment)
    expect_identical(provider@issuer, issuer)
    expect_identical(provider@pkce_method, "S256")
    expect_true(provider@id_token_required)
    expect_true(provider@userinfo_id_token_match)
  }
  expect_error(oauth_provider_surfconext("unknown"), "arg")
})

test_that("authentik keeps its application issuer slash and rejects global mode", {
  issuer <- "https://auth.example.com/application/o/shiny-app/"
  doc <- research_discovery(issuer)
  url <- paste0(sub("/+$", "", issuer), "/.well-known/openid-configuration")
  local_research_discovery(doc, url)
  provider <- oauth_provider_authentik("https://auth.example.com/", "shiny-app")
  expect_identical(provider@issuer, issuer)
  expect_true(provider@id_token_validation)
  expect_true(provider@jwks_host_issuer_match)

  doc[["issuer"]] <- "https://auth.example.com/"
  local_research_discovery(doc, url)
  expect_error(
    oauth_provider_authentik("https://auth.example.com", "shiny-app"),
    "issuer mismatch",
    class = "shinyOAuth_config_error"
  )
  for (slug in c("", "../other", "a/b", "x?y", "x#y", "x%2fy")) {
    expect_error(
      oauth_provider_authentik("https://auth.example.com", slug),
      class = "shinyOAuth_input_error"
    )
  }
})

test_that("new discovery presets preserve issuer and signing-key host validation", {
  issuer <- "https://gitlab.com"
  url <- paste0(issuer, "/.well-known/openid-configuration")
  doc <- research_discovery(issuer)
  doc[["issuer"]] <- "https://unexpected.example"
  local_research_discovery(doc, url)
  expect_error(oauth_provider_gitlab(), "issuer mismatch")

  doc <- research_discovery(issuer)
  doc[["jwks_uri"]] <- "https://unexpected.example/jwks"
  local_research_discovery(doc, url)
  expect_error(oauth_provider_gitlab(), class = "shinyOAuth_config_error")

  for (value in list(NULL, NA_character_, "", c("https://a", "https://b"))) {
    expect_error(oauth_provider_gitlab(value), class = "shinyOAuth_input_error")
    expect_error(
      oauth_provider_authentik(value, "app"),
      class = "shinyOAuth_input_error"
    )
    expect_error(oauth_provider_cognito(value))
  }
})

test_that("Globus configures RS512 without weakening generic discovery", {
  local_mocked_bindings(req_with_retry = function(...) {
    stop("unexpected network")
  })
  provider <- oauth_provider_globus()
  expect_identical(provider@issuer, "https://auth.globus.org")
  expect_identical(provider@jwks_uri, "https://auth.globus.org/jwk.json")
  expect_identical(provider@allowed_algs, "RS512")
  expect_identical(provider@token_auth_style, "header")
  expect_true(provider@use_pkce)
  expect_true(provider@use_nonce)
  expect_true(provider@id_token_required)
  expect_true(provider@id_token_validation)
  expect_true(provider@userinfo_id_token_match)
  expect_true(provider@jwks_host_issuer_match)

  doc <- research_discovery(provider@issuer)
  doc[["id_token_signing_alg_values_supported"]] <- list("RS512")
  local_research_discovery(
    doc,
    paste0(provider@issuer, "/.well-known/openid-configuration")
  )
  expect_error(oauth_provider_oidc_discover(provider@issuer), "RS256")
})

test_that("Globus login validates an RS512 signature, nonce, and UserInfo subject", {
  provider <- oauth_provider_globus()
  client <- oauth_client(
    provider,
    client_id = "globus-test-client",
    client_secret = "test-secret",
    redirect_uri = "https://app.example/callback",
    scopes = c("openid", "profile", "email")
  )
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  jwk[["alg"]] <- "RS512"
  jwk[["kid"]] <- "globus-test"
  local_mocked_bindings(fetch_jwks = function(...) list(keys = list(jwk)))

  jwt <- NULL
  subject <- "researcher"
  local_mocked_bindings(
    swap_code_for_token_set = function(...) {
      list(
        access_token = "access",
        token_type = "Bearer",
        id_token = jwt,
        expires_in = 3600,
        scope = "openid profile email"
      )
    },
    req_with_retry = function(req, ...) {
      expect_identical(req[["url"]], provider@userinfo_url)
      httr2::response(
        url = req[["url"]],
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(as.character(jsonlite::toJSON(
          list(sub = subject),
          auto_unbox = TRUE
        )))
      )
    }
  )
  login <- function(signing_key = key, wrong_nonce = FALSE) {
    browser <- valid_browser_token()
    url <- prepare_call(client, browser_token = browser)
    now <- floor(as.numeric(Sys.time()))
    header <- list(alg = "RS512", kid = "globus-test", typ = "JWT")
    claims <- list(
      iss = provider@issuer,
      aud = client@client_id,
      sub = "researcher",
      iat = now,
      exp = now + 120,
      nonce = if (wrong_nonce) {
        "wrong"
      } else {
        parse_query_param(url, "nonce", decode = TRUE)
      }
    )
    encode <- function(value) {
      base64url_encode(charToRaw(as.character(jsonlite::toJSON(
        value,
        auto_unbox = TRUE
      ))))
    }
    payload <- paste(encode(header), encode(claims), sep = ".")
    signature <- openssl::signature_create(
      charToRaw(payload),
      hash = openssl::sha512,
      key = signing_key
    )
    jwt <<- paste(payload, base64url_encode(signature), sep = ".")
    handle_callback(
      client,
      code = "code",
      state = parse_query_param(url, "state"),
      browser_token = browser
    )
  }
  token <- login()
  expect_true(token@id_token_validated)
  expect_identical(token@userinfo[["sub"]], "researcher")
  expect_error(login(wrong_nonce = TRUE), class = "shinyOAuth_id_token_error")
  expect_error(
    login(openssl::rsa_keygen(2048)),
    class = "shinyOAuth_id_token_error"
  )
  subject <- "different-researcher"
  expect_error(login(), class = "shinyOAuth_userinfo_error")
})
