## Integration tests: live Keycloak currently rejects DPoP + JAR combinations
##
## Unit tests already prove that shinyOAuth emits dpop_jkt inside signed and
## pushed request objects. This file adds the live Keycloak edge: the provider
## rejects the combined DPoP + JAR authorization request before a code is
## issued, both directly and through PAR.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

query_param_names <- function(url) {
  q <- sub("^[^?]*\\?", "", url)
  if (identical(q, url) || !nzchar(q)) {
    return(character(0))
  }

  parts <- strsplit(q, "&", fixed = TRUE)[[1]]
  kv <- strsplit(parts, "=", fixed = TRUE)
  unique(vapply(kv, function(p) utils::URLdecode(p[1]), ""))
}

create_dpop_jar_fixture <- function() {
  public_key_pem <- get_pjwt_public_key_pem()
  if (!keycloak_nonempty_string(public_key_pem)) {
    testthat::skip("private_key_jwt test key not available")
  }

  admin_token <- keycloak_admin_token()
  body <- list(
    clientId = keycloak_temp_client_id("shiny-dpop-jar"),
    protocol = "openid-connect",
    publicClient = TRUE,
    redirectUris = keycloak_default_redirect_uris(),
    webOrigins = list("+"),
    standardFlowEnabled = TRUE,
    implicitFlowEnabled = FALSE,
    serviceAccountsEnabled = FALSE,
    directAccessGrantsEnabled = FALSE,
    attributes = list(
      "pkce.code.challenge.method" = "S256",
      "dpop.bound.access.tokens" = "true",
      "use.jwks.url" = "false",
      "jwt.credential.public.key" = public_key_pem,
      "request.object.signature.alg" = "RS256"
    )
  )
  fixture <- keycloak_create_client(admin_token, body)

  list(admin_token = admin_token, fixture = fixture)
}

make_dynamic_dpop_jar_client <- function(
  provider,
  client_id,
  dpop_private_key = make_dpop_private_key()
) {
  shinyOAuth::oauth_client(
    provider = provider,
    client_id = client_id,
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    dpop_private_key = dpop_private_key,
    dpop_require_access_token = TRUE,
    client_private_key = get_pjwt_key(),
    client_private_key_kid = NA_character_,
    authorization_request_mode = "request",
    authorization_request_signing_alg = "RS256"
  )
}

valid_browser_token <- function() {
  paste(rep("ab", 64), collapse = "")
}

perform_auth_url_request <- function(auth_url) {
  httr2::request(auth_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()
}

expect_keycloak_invalid_request_page <- function(resp) {
  testthat::expect_identical(httr2::resp_status(resp), 400L)

  body <- httr2::resp_body_string(resp)
  testthat::expect_match(body, 'data-page-id="login-error"', fixed = TRUE)
  testthat::expect_match(body, "Invalid Request", fixed = TRUE)

  invisible(resp)
}

testthat::test_that("signed DPoP JAR emits dpop_jkt but live Keycloak rejects the combined auth request", {
  skip_common()
  local_test_options()

  fixture <- create_dpop_jar_fixture()
  on.exit(
    keycloak_delete_client(
      fixture$admin_token,
      id = fixture$fixture$id
    ),
    add = TRUE
  )

  provider <- make_provider(allowed_token_types = c("Bearer", "DPoP"))
  client <- make_dynamic_dpop_jar_client(
    provider = provider,
    client_id = fixture$fixture$client_id
  )

  browser_token <- valid_browser_token()
  auth_url <- shinyOAuth::prepare_call(client, browser_token = browser_token)
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  payload <- decode_compact_jwt_payload(request_jwt)

  testthat::expect_setequal(
    query_param_names(auth_url),
    c("client_id", "response_type", "scope", "request")
  )
  testthat::expect_match(auth_url, "[?&]response_type=code")
  testthat::expect_match(auth_url, "[?&]scope=openid(?:%20|&|$)")
  testthat::expect_identical(
    payload[["dpop_jkt"]],
    shinyOAuth:::client_dpop_jkt(client)
  )

  resp <- perform_auth_url_request(auth_url)
  expect_keycloak_invalid_request_page(resp)
})

testthat::test_that("live Keycloak rejects the same DPoP plus JAR combination when pushed through PAR", {
  skip_common()
  local_test_options()

  fixture <- create_dpop_jar_fixture()
  on.exit(
    keycloak_delete_client(
      fixture$admin_token,
      id = fixture$fixture$id
    ),
    add = TRUE
  )

  provider <- make_provider(
    use_par = TRUE,
    allowed_token_types = c("Bearer", "DPoP")
  )
  client <- make_dynamic_dpop_jar_client(
    provider = provider,
    client_id = fixture$fixture$client_id
  )

  testthat::expect_error(
    shinyOAuth::prepare_call(client, browser_token = valid_browser_token()),
    regexp = paste(
      "Pushed authorization request failed|",
      "invalid_request_object|invalidRequestMessage"
    ),
    ignore.case = TRUE
  )
})
