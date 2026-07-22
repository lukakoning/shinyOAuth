make_mixup_route_client <- function(
  name,
  issuer,
  redirect_uri,
  client_id,
  authorization_server_mode = "single",
  authorization_server_redirect_uris = character(0)
) {
  provider <- oauth_provider(
    name = name,
    auth_url = paste0(issuer, "/authorize"),
    token_url = paste0(issuer, "/token"),
    issuer = issuer,
    issuer_thus_oidc = FALSE,
    authorization_response_iss_parameter_supported = FALSE,
    id_token_validation = FALSE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "public"
  )

  oauth_client(
    provider = provider,
    client_id = client_id,
    redirect_uri = redirect_uri,
    enforce_callback_issuer = FALSE,
    authorization_server_mode = authorization_server_mode,
    authorization_server_redirect_uris = authorization_server_redirect_uris,
    scopes = character(0),
    scope_validation = "none",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

test_that("callback routes compare canonical scheme authority and path", {
  expect_true(shinyOAuth:::oauth_callback_route_matches(
    "HTTPS://APP.EXAMPLE/callback",
    "https://app.example:443/callback?registered=1"
  ))
  expect_false(shinyOAuth:::oauth_callback_route_matches(
    "http://app.example/callback",
    "https://app.example/callback"
  ))
  expect_false(shinyOAuth:::oauth_callback_route_matches(
    "https://other.example/callback",
    "https://app.example/callback"
  ))
  expect_false(shinyOAuth:::oauth_callback_route_matches(
    "https://app.example/other",
    "https://app.example/callback"
  ))
})

test_that("wrong-route callback transports are ignored before dispatch", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  direct_client <- make_mixup_route_client(
    "direct",
    "https://direct-as.example",
    "https://app.example/direct/callback",
    "direct-client"
  )
  jarm_client <- make_mixup_route_client(
    "jarm",
    "https://jarm-as.example",
    "https://app.example/jarm/callback",
    "jarm-client"
  )
  jarm_client@response_mode <- "query.jwt"
  jarm_client@jarm_signed_response_alg <- "RS256"

  wrapper_server <- function(input, output, session) {
    direct <- oauth_module_server(
      "direct",
      direct_client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    )
    jarm <- oauth_module_server(
      "jarm",
      jarm_client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    )
  }

  shiny::testServer(wrapper_server, {
    direct$.process_query(
      "?code=stolen&state=not-parsed",
      current_uri = "https://app.example/honest/callback"
    )
    direct$.process_query(
      "?error=access_denied&state=not-parsed",
      current_uri = "https://app.example/honest/callback"
    )
    direct$.process_query(
      "?shinyOAuth_form_post=missing&shinyOAuth_form_post_id=direct",
      current_uri = "https://app.example/honest/callback"
    )
    jarm$.process_query(
      "?response=not-a-compact-jwt",
      current_uri = "https://app.example/honest/callback"
    )
    session$flushReact()

    expect_null(direct$error)
    expect_null(direct$token)
    expect_null(jarm$error)
    expect_null(jarm$token)
  })
})

test_that("distinct redirect routes stop a public-client provider mix-up", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  redirect_uris <- c(
    "https://app.example/callback/malicious",
    "https://app.example/callback/honest"
  )
  malicious <- make_mixup_route_client(
    "malicious",
    "https://malicious-as.example",
    redirect_uris[[1L]],
    "malicious-client",
    authorization_server_mode = "multi_redirect_uri",
    authorization_server_redirect_uris = redirect_uris
  )
  honest <- make_mixup_route_client(
    "honest",
    "https://honest-as.example",
    redirect_uris[[2L]],
    "honest-client",
    authorization_server_mode = "multi_redirect_uri",
    authorization_server_redirect_uris = redirect_uris
  )
  exchanges <- list()

  wrapper_server <- function(input, output, session) {
    malicious_auth <- oauth_module_server(
      "malicious_auth",
      malicious,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    )
    honest_auth <- oauth_module_server(
      "honest_auth",
      honest,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    )
  }

  shiny::testServer(wrapper_server, {
    malicious_request <- malicious_auth$build_auth_url()
    malicious_state <- parse_query_param(malicious_request, "state")
    expect_true(is_valid_string(parse_query_param(
      malicious_request,
      "code_challenge",
      decode = TRUE
    )))

    # The malicious AS forwards its transaction to the honest AS, preserving
    # state and PKCE challenge. The honest AS then returns its code on the
    # honest redirect URI. Every module observes the URL, but only the honest
    # route may inspect it.
    callback_query <- paste0(
      "?code=honest-authorization-code&state=",
      malicious_state
    )
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        exchanges[[length(exchanges) + 1L]] <<- list(
          issuer = client@provider@issuer,
          code = code,
          code_verifier = code_verifier
        )
        testthat::fail("no token endpoint may receive the mixed-up code")
      },
      .package = "shinyOAuth",
      {
        malicious_auth$.process_query(
          callback_query,
          current_uri = honest@redirect_uri
        )
        honest_auth$.process_query(
          callback_query,
          current_uri = honest@redirect_uri
        )
        session$flushReact()
      }
    )

    expect_length(exchanges, 0L)
    expect_null(malicious_auth$error)
    expect_null(malicious_auth$token)
    expect_false(isTRUE(honest_auth$authenticated))
    expect_true(is_valid_string(honest_auth$error))
    expect_null(honest_auth$token)

    decoded_state <- shiny::parseQueryString(paste0(
      "?state=",
      malicious_state
    ))[["state"]]
    payload <- shinyOAuth:::state_payload_decrypt_validate(
      malicious,
      decoded_state,
      audit_success = FALSE
    )
    expect_true(is.list(shinyOAuth:::state_store_get(
      malicious,
      payload[["state"]]
    )))
  })
})
