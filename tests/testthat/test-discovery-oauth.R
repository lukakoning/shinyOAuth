oauth_metadata <- function(issuer = "https://issuer.example.com/tenant/") {
  list(
    issuer = issuer,
    authorization_endpoint = paste0(issuer, "auth"),
    token_endpoint = paste0(issuer, "token"),
    response_types_supported = list("code"),
    code_challenge_methods_supported = list("S256")
  )
}

test_that("OAuth discovery uses RFC 8414 paths and preserves the exact issuer", {
  metadata <- oauth_metadata()
  requested <- NULL
  local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) {
      requested <<- req[["url"]]
      list()
    },
    .discover_parse_json = function(resp) metadata,
    .package = "shinyOAuth"
  )
  inputs <- c(
    "https://issuer.example.com",
    "https://issuer.example.com/",
    "https://issuer.example.com/tenant/",
    "https://issuer.example.com/a%2Fb//c/",
    "https://issuer.example.com:8443/tenant/"
  )
  paths <- c("", "", "/tenant", "/a%2Fb//c", "/tenant")
  origins <- c(
    rep("https://issuer.example.com", 4L),
    "https://issuer.example.com:8443"
  )
  for (i in seq_along(inputs)) {
    metadata <- oauth_metadata(inputs[[i]])
    provider <- oauth_provider_oauth_discover(inputs[[i]])
    expect_identical(
      requested,
      paste0(
        origins[[i]],
        "/.well-known/oauth-authorization-server",
        paths[[i]]
      )
    )
    expect_identical(provider@issuer, inputs[[i]])
    for (field in c(
      "infer_oidc_from_issuer",
      "use_nonce",
      "id_token_required",
      "id_token_validation",
      "userinfo_required",
      "userinfo_id_token_match"
    )) {
      expect_false(S7::prop(provider, field))
    }
    expect_identical(
      oauth_client(
        provider,
        "client",
        client_secret = "secret",
        redirect_uri = "https://app.example.com/callback",
        scopes = "accounts"
      )@scopes,
      "accounts"
    )
  }
  metadata <- oauth_metadata("https://issuer.example.com/tenant")
  expect_error(
    oauth_provider_oauth_discover("https://issuer.example.com/tenant/"),
    class = "shinyOAuth_config_error"
  )
})

test_that("OAuth discovery requires usable code metadata and exact issuer matching", {
  metadata <- oauth_metadata()
  local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) list(),
    .discover_parse_json = function(resp) metadata,
    .package = "shinyOAuth"
  )
  base <- metadata
  for (field in c(
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "response_types_supported"
  )) {
    metadata <- base
    metadata[[field]] <- NULL
    expect_error(
      oauth_provider_oauth_discover(base[["issuer"]]),
      class = "shinyOAuth_parse_error"
    )
  }
  for (value in list("code", list(), list("token"), list("code", 1))) {
    metadata <- base
    metadata[["response_types_supported"]] <- value
    expect_error(
      oauth_provider_oauth_discover(base[["issuer"]]),
      class = "shinyOAuth_parse_error"
    )
  }
  metadata <- base
  metadata[["issuer"]] <- "https://issuer.example.com/other/"
  expect_error(
    oauth_provider_oauth_discover(base[["issuer"]]),
    class = "shinyOAuth_config_error"
  )
  for (field in c(
    "issuer_match",
    "infer_oidc_from_issuer",
    "id_token_validation",
    "userinfo_required",
    ".oauth_only"
  )) {
    args <- list(issuer = base[["issuer"]])
    args[[field]] <- FALSE
    expect_error(
      do.call(oauth_provider_oauth_discover, args),
      class = "shinyOAuth_input_error"
    )
  }
  expect_error(
    oauth_provider_oidc_discover(base[["issuer"]], .oauth_only = TRUE),
    class = "shinyOAuth_input_error"
  )
})

test_that("OAuth discovery retains endpoint, JWT client auth and PAR checks", {
  metadata <- oauth_metadata()
  local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) list(),
    .discover_parse_json = function(resp) metadata,
    .package = "shinyOAuth"
  )
  base <- metadata
  metadata[["token_endpoint_auth_methods_supported"]] <- list("private_key_jwt")
  expect_error(
    oauth_provider_oauth_discover(
      base[["issuer"]],
      token_auth_style = "private_key_jwt"
    ),
    class = "shinyOAuth_parse_error"
  )
  metadata[["token_endpoint_auth_signing_alg_values_supported"]] <- list(
    "ES256"
  )
  metadata[["pushed_authorization_request_endpoint"]] <- paste0(
    base[["issuer"]],
    "par"
  )
  metadata[["require_pushed_authorization_requests"]] <- TRUE
  metadata[["dpop_signing_alg_values_supported"]] <- list("ES256")
  provider <- oauth_provider_oauth_discover(
    base[["issuer"]],
    token_auth_style = "private_key_jwt",
    allowed_token_types = "DPoP"
  )
  expect_identical(provider@token_auth_style, "private_key_jwt")
  expect_true(provider@par_required)
  expect_identical(provider@dpop_signing_alg_values_supported, "ES256")
  expect_identical(provider@allowed_token_types, "DPoP")
  metadata[["token_endpoint_auth_signing_alg_values_supported"]] <- list("none")
  expect_error(
    oauth_provider_oauth_discover(base[["issuer"]]),
    class = "shinyOAuth_parse_error"
  )
  metadata[["token_endpoint_auth_signing_alg_values_supported"]] <- list(
    "ES256"
  )
  metadata[["pushed_authorization_request_endpoint"]] <- NULL
  expect_error(
    oauth_provider_oauth_discover(base[["issuer"]]),
    class = "shinyOAuth_parse_error"
  )
  for (field in c("authorization_endpoint", "token_endpoint", "jwks_uri")) {
    metadata <- base
    metadata[[field]] <- "http://issuer.example.com/insecure"
    expect_error(
      oauth_provider_oauth_discover(base[["issuer"]]),
      class = "shinyOAuth_error"
    )
  }
  for (value in list(NULL, character(), c("a", "b"), 42)) {
    metadata <- base
    metadata["jwks_uri"] <- list(value)
    expect_error(
      oauth_provider_oauth_discover(base[["issuer"]]),
      class = "shinyOAuth_parse_error"
    )
  }
  local_options(shinyOAuth.allow_insecure_http = FALSE)
  expect_error(
    oauth_provider_oauth_discover("http://issuer.example.com"),
    class = "shinyOAuth_input_error"
  )
  expect_error(
    oauth_provider_oauth_discover("https://issuer.example.com?query=value"),
    class = "shinyOAuth_input_error"
  )
  expect_error(
    oauth_provider_oauth_discover("https://issuer.example.com#fragment"),
    class = "shinyOAuth_input_error"
  )
  expect_error(
    oauth_provider_oauth_discover(
      "https://private-user:private-password@issuer.example.com"
    ),
    class = "shinyOAuth_input_error"
  )
})
