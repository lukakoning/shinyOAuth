## Integration tests: next-priority OAuth2/OIDC protocol hardening
##
## - RFC 8707 resource indicators and callback policy binding
## - OIDC max_age/auth_time handling
## - RFC 7662 introspection element checks
## - UserInfo subject binding against validated ID tokens

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_protocol_confidential_client <- function(
  prov,
  scopes = c("openid", "profile", "email"),
  introspect = FALSE,
  introspect_elements = character(0)
) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = scopes,
    introspect = introspect,
    introspect_elements = introspect_elements
  )
}

protocol_login_via_module <- function(client, username = "alice") {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      login <- perform_login_form_as(
        auth_url,
        username = username,
        password = username,
        redirect_uri = client@redirect_uri
      )
      values$.process_query(callback_query(login))
      session$flushReact()

      result <<- list(
        auth_url = auth_url,
        login = login,
        authenticated = isTRUE(values$authenticated),
        error = values$error,
        error_description = values$error_description,
        token = values$token
      )
    }
  )

  result
}

count_fixed_matches <- function(x, pattern) {
  greg <- gregexpr(pattern, x, fixed = TRUE)[[1]]
  if (identical(greg, -1L)) {
    return(0L)
  }
  length(greg)
}

testthat::test_that("RFC 8707 resource indicators are state-policy bound", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    resource = c(
      "https://api.example.com/ledger",
      "urn:shinyoauth:test:reports"
    )
  )

  auth_url <- shinyOAuth::prepare_call(
    client,
    browser_token = "__SKIPPED__"
  )
  state <- parse_query_param(auth_url, "state")

  testthat::expect_identical(count_fixed_matches(auth_url, "resource="), 2L)
  testthat::expect_match(auth_url, "resource=https%3A%2F%2Fapi\\.example\\.com")
  testthat::expect_match(auth_url, "resource=urn%3Ashinyoauth%3Atest%3Areports")
  testthat::expect_true(nzchar(state))

  client@resource <- character(0)
  testthat::expect_error(
    shinyOAuth:::state_payload_decrypt_validate(client, state),
    regexp = "client policy|payload",
    class = "shinyOAuth_state_error"
  )
})

testthat::test_that("OIDC max_age requests produce and validate auth_time", {
  skip_common()
  local_test_options()

  prov <- make_provider(extra_auth_params = list(max_age = 0))
  client <- make_public_client(prov, scopes = c("openid", "profile"))
  result <- protocol_login_via_module(client)

  max_age <- parse_query_param(result$auth_url, "max_age", decode = TRUE)

  testthat::expect_identical(max_age, "0")
  testthat::expect_true(isTRUE(result$authenticated))
  testthat::expect_null(result$error)
  testthat::expect_true(isTRUE(result$token@id_token_validated))

  id_payload <- shinyOAuth:::parse_jwt_payload(result$token@id_token)
  auth_time <- suppressWarnings(as.numeric(id_payload$auth_time))

  testthat::expect_true(is.finite(auth_time))
  testthat::expect_lte(abs(as.numeric(Sys.time()) - auth_time), 120)
})

testthat::test_that("Keycloak introspection validates sub client_id and scope", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_protocol_confidential_client(
    prov,
    introspect = TRUE,
    introspect_elements = c("sub", "client_id", "scope")
  )

  result <- protocol_login_via_module(client)

  testthat::expect_true(isTRUE(result$authenticated))
  testthat::expect_null(result$error)
  testthat::expect_true(isTRUE(result$token@granted_scopes_verified))
  testthat::expect_true(all(
    c("openid", "profile", "email") %in% result$token@granted_scopes
  ))

  intros <- shinyOAuth::introspect_token(client, result$token, which = "access")
  raw <- intros$raw %||% list()
  intro_scopes <- strsplit(raw$scope %||% "", "\\s+")[[1]]

  testthat::expect_true(isTRUE(intros$supported))
  testthat::expect_true(isTRUE(intros$active))
  testthat::expect_identical(raw$client_id, client@client_id)
  testthat::expect_identical(raw$sub, result$token@userinfo$sub)
  testthat::expect_true(all(c("openid", "profile", "email") %in% intro_scopes))
})

testthat::test_that("introspection client_id mix-up is rejected for a live token", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_protocol_confidential_client(prov)
  result <- protocol_login_via_module(client)

  testthat::expect_true(isTRUE(result$authenticated))

  intros <- shinyOAuth::introspect_token(client, result$token, which = "access")
  testthat::expect_true(isTRUE(intros$active))

  wrong_client <- make_protocol_confidential_client(
    prov,
    introspect = TRUE,
    introspect_elements = "client_id"
  )
  wrong_client@client_id <- "shiny-public"

  testthat::expect_error(
    shinyOAuth:::enforce_token_introspection_policy(
      oauth_client = wrong_client,
      token = result$token,
      introspection_result = intros,
      requested_scopes = client@scopes,
      phase = "exchange_code"
    ),
    regexp = "client_id",
    class = "shinyOAuth_token_error"
  )
})

testthat::test_that("UserInfo subject substitution is rejected across real users", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_protocol_confidential_client(prov)

  alice <- protocol_login_via_module(client, username = "alice")
  bob <- protocol_login_via_module(client, username = "bob")

  testthat::expect_true(isTRUE(alice$authenticated))
  testthat::expect_true(isTRUE(bob$authenticated))
  testthat::expect_true(isTRUE(alice$token@id_token_validated))
  testthat::expect_true(isTRUE(bob$token@id_token_validated))
  testthat::expect_false(identical(
    alice$token@userinfo$sub,
    bob$token@userinfo$sub
  ))

  testthat::expect_error(
    shinyOAuth:::enforce_userinfo_id_token_subject_match(
      oauth_client = client,
      userinfo = bob$token@userinfo,
      token_set = list(
        id_token = alice$token@id_token,
        .id_token_validated = TRUE
      )
    ),
    regexp = "subject|userinfo",
    class = "shinyOAuth_userinfo_mismatch"
  )
})
