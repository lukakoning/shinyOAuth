# Parametric tests for token_endpoint auth styles against Keycloak

# This test focuses on exercising different provider token auth styles
# by calling the introspection endpoint using each style. We first fetch
# a fresh access token with the confidential client (client_credentials)
# and then introspect it with different client auth configurations.
#
# Always runs for styles known to work out-of-the-box with the provided realm:
# - header (client_secret_basic)
# - body (client_secret_post)
#
# Also exercises JWT styles using clients provisioned in the realm import:
# - client_secret_jwt: client "shiny-csjwt" with secret "secretjwt"
# - private_key_jwt: client "shiny-pjwt" with embedded RSA public key; tests use
#   the matching private key from integration/keycloak/keys/test_rsa

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
  # Always acquire token using Basic (works with our realm)
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

# Resolve optional JWT inputs from env
get_pjwt_key <- function() {
  # Use the repository-generated test key (resolve path robustly under testthat)
  path <- NULL
  if (requireNamespace("testthat", quietly = TRUE)) {
    # When running via test_dir('integration/keycloak'), this points at .../integration/keycloak
    path <- testthat::test_path("keys", "test_rsa")
  }
  if (is.null(path) || !file.exists(path)) {
    # Fallback when run from repo root or other working directories
    path <- file.path("integration", "keycloak", "keys", "test_rsa")
  }
  if (!file.exists(path)) {
    return(NULL)
  }
  # Prefer returning an openssl::key object to avoid parsing differences
  pk <- try(openssl::read_key(path), silent = TRUE)
  if (inherits(pk, "try-error")) {
    return(NULL)
  }
  pk
}

maybe_skip_keycloak <- function() {
  testthat::skip_if_not(
    keycloak_reachable(),
    "Keycloak not reachable at localhost:8080"
  )
}

# Table of cases
cases <- list(
  list(
    name = "header",
    style = "header",
    include = function() TRUE,
    client = function(prov) {
      shinyOAuth::oauth_client(
        provider = prov,
        client_id = "shiny-confidential",
        client_secret = "secret",
        redirect_uri = "http://localhost:3000/callback",
        scopes = character()
      )
    }
  ),
  list(
    name = "body",
    style = "body",
    include = function() TRUE,
    client = function(prov) {
      shinyOAuth::oauth_client(
        provider = prov,
        client_id = "shiny-confidential",
        client_secret = "secret",
        redirect_uri = "http://localhost:3000/callback",
        scopes = character()
      )
    }
  ),
  list(
    name = "client_secret_jwt",
    style = "client_secret_jwt",
    include = function() TRUE,
    client = function(prov) {
      shinyOAuth::oauth_client(
        provider = prov,
        client_id = "shiny-csjwt",
        client_secret = "secretjwt",
        redirect_uri = "http://localhost:3000/callback",
        scopes = character(),
        client_assertion_alg = "HS256"
      )
    }
  ),
  list(
    name = "private_key_jwt",
    style = "private_key_jwt",
    include = function() !is.null(get_pjwt_key()),
    client = function(prov) {
      shinyOAuth::oauth_client(
        provider = prov,
        client_id = "shiny-pjwt",
        client_secret = "", # not used
        redirect_uri = "http://localhost:3000/callback",
        scopes = character(),
        client_private_key = get_pjwt_key(),
        client_private_key_kid = NA_character_,
        client_assertion_alg = NA_character_
      )
    }
  )
)

for (case in cases) {
  testthat::test_that(
    paste0("Keycloak introspection via auth style: ", case$name),
    {
      maybe_skip_keycloak()
      if (!isTRUE(case$include())) {
        testthat::skip(paste("Skipping", case$name, "— prerequisites not met"))
      }

      prov <- make_provider(case$style)
      token_value <- fetch_access_token_cc(prov)

      client <- case$client(prov)
      tok <- shinyOAuth::OAuthToken(access_token = token_value)

      res <- shinyOAuth::introspect_token(
        client,
        tok,
        which = "access",
        async = FALSE
      )

      # We require the call to be supported and not an outright HTTP failure
      testthat::expect_true(isTRUE(res$supported))

      # We expect active TRUE (service-account token). If server returns an unknown
      # encoding we allow NA but do not fail the suite.
      testthat::expect_true(isTRUE(res$active) || is.na(res$active))
    }
  )
}
