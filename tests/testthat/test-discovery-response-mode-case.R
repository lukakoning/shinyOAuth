response_mode_case_discover <- function(oidc, modes = NULL) {
  issuer <- "https://issuer.example"
  metadata <- list(
    issuer = issuer,
    authorization_endpoint = paste0(issuer, "/authorize"),
    token_endpoint = paste0(issuer, "/token"),
    jwks_uri = paste0(issuer, "/jwks"),
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256"),
    authorization_signing_alg_values_supported = list("RS256"),
    code_challenge_methods_supported = list("S256")
  )
  if (!is.null(modes)) {
    metadata[["response_modes_supported"]] <- as.list(modes)
  }
  discover <- if (oidc) {
    oauth_provider_oidc_discover
  } else {
    oauth_provider_oauth_discover
  }
  testthat::with_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(metadata, auto_unbox = TRUE))
      )
    },
    .package = "shinyOAuth",
    discover(issuer)
  )
}

response_mode_case_client <- function(provider, mode = NULL, ...) {
  args <- list(
    provider = provider,
    client_id = "response-mode-client",
    client_secret = "secret",
    redirect_uri = "https://app.example/callback",
    scopes = "openid",
    response_mode = mode,
    ...
  )
  if (!is.null(mode) && grepl("jwt", tolower(mode), fixed = TRUE)) {
    args[["jarm_signed_response_alg"]] <- "RS256"
  }
  do.call(oauth_client, args)
}

for (oidc in c(FALSE, TRUE)) {
  protocol <- if (oidc) "OIDC" else "OAuth"
  test_that(
    paste(protocol, "discovery preserves exact response-mode capabilities"),
    {
      for (mode in c(
        "query",
        "form_post",
        "query.jwt",
        "form_post.jwt",
        "jwt"
      )) {
        for (lookalike in c(
          toupper(mode),
          paste0(" ", mode),
          paste0(mode, " ")
        )) {
          provider <- response_mode_case_discover(
            oidc,
            c(lookalike, "Extension.Mode")
          )
          expect_identical(
            provider@response_modes_supported,
            c(lookalike, "Extension.Mode")
          )
          expect_error(
            response_mode_case_client(provider, mode),
            "not advertised",
            class = "shinyOAuth_config_error"
          )
          provider <- response_mode_case_discover(
            oidc,
            c(lookalike, mode, "Extension.Mode")
          )
          client <- response_mode_case_client(
            provider,
            paste0(" ", toupper(mode), " ")
          )
          expect_identical(client@response_mode, mode)
          expect_identical(
            resolve_oauth_client_response_mode(client)[["mode"]],
            if (identical(mode, "jwt")) "query.jwt" else mode
          )
        }
      }
    }
  )

  test_that(
    paste(protocol, "implicit query requires an exact advertised capability"),
    {
      provider <- response_mode_case_discover(
        oidc,
        c("QUERY", " query ", "Extension.Mode")
      )
      expect_error(response_mode_case_client(provider), "not advertised")
      provider <- response_mode_case_discover(oidc, c("QUERY", "query"))
      client <- response_mode_case_client(provider)
      expect_true(is.na(client@response_mode))
      expect_identical(
        resolve_oauth_client_response_mode(client)[["mode"]],
        "query"
      )
      provider <- response_mode_case_discover(oidc)
      expect_identical(
        provider@response_modes_supported,
        c("query", "fragment")
      )
      expect_no_error(response_mode_case_client(provider))
    }
  )
}

test_that("manual providers and mutations preserve exact capabilities and caller aliases", {
  for (constructor in list(oauth_provider, OAuthProvider)) {
    make_provider <- function(modes, params = list()) {
      constructor(
        name = "response-mode-test",
        auth_url = "https://issuer.example/authorize",
        token_url = "https://issuer.example/token",
        response_modes_supported = modes,
        extra_auth_params = params
      )
    }
    modes <- c("QUERY", " form_post ", "Extension.Mode")
    provider <- make_provider(modes)
    expect_identical(provider@response_modes_supported, modes)
    expect_error(response_mode_case_client(provider), "not advertised")
    expect_error(
      make_provider("FORM_POST", list(response_mode = "form_post")),
      "not advertised"
    )
    expect_error(
      {
        provider@extra_auth_params <- list(response_mode = "form_post")
      },
      "not advertised"
    )
    provider <- make_provider(
      c(modes, "form_post"),
      list(response_mode = " FoRm_PoSt ")
    )
    client <- response_mode_case_client(provider)
    expect_identical(
      resolve_oauth_client_response_mode(client)[["mode"]],
      "form_post"
    )
    provider <- make_provider("query", list(response_mode = " Query "))
    expect_error(
      {
        provider@response_modes_supported <- "QUERY"
      },
      "not advertised"
    )
    expect_error(make_provider(" \t "), "non-empty strings")
    expect_error(
      {
        provider@response_modes_supported <- " \t "
      },
      "non-empty strings"
    )
    expect_no_error(response_mode_case_client(make_provider(character())))
  }
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  expect_error(
    {
      client@provider@response_modes_supported <- c("QUERY", " query ")
    },
    "not advertised"
  )
  expect_no_error(prepare_call(client, valid_browser_token()))
})

test_that("literal response-mode capabilities bind pending callbacks before consumption", {
  for (transport in c("encrypted", "reference")) {
    provider <- oauth_provider(
      "literal-modes",
      "https://issuer.example/authorize",
      "https://issuer.example/token",
      issuer = "https://issuer.example",
      infer_oidc_from_issuer = FALSE,
      response_modes_supported = c("query", "Extension.Mode")
    )
    client <- response_mode_case_client(provider, state_transport = transport)
    original_fingerprint <- provider_fingerprint(provider)
    reordered <- provider
    reordered@response_modes_supported <- c("Extension.Mode", "query", "query")
    expect_identical(provider_fingerprint(reordered), original_fingerprint)
    browser <- valid_browser_token()
    state <- parse_query_param(
      prepare_call(client, browser),
      "state",
      decode = TRUE
    )
    keys <- client@state_store[["keys"]]()
    expect_length(keys, 1L)
    pending <- client@state_store[["get"]](keys[[1L]])
    requests <- 0L
    testthat::local_mocked_bindings(
      req_with_retry = function(req, ...) {
        expect_identical(req[["url"]], provider@token_url)
        requests <<- requests + 1L
        httr2::response(
          headers = list("content-type" = "application/json"),
          body = charToRaw(
            '{"access_token":"access","token_type":"Bearer","expires_in":300}'
          )
        )
      },
      .package = "shinyOAuth"
    )
    for (extension in c("EXTENSION.MODE", " Extension.Mode ")) {
      changed <- client
      changed@provider@response_modes_supported <- c("query", extension)
      expect_false(identical(
        provider_fingerprint(changed@provider),
        original_fingerprint
      ))
      expect_error(
        handle_callback(changed, "code", state, browser_token = browser),
        "provider fingerprint mismatch",
        class = "shinyOAuth_state_error"
      )
      expect_identical(requests, 0L)
      expect_identical(client@state_store[["keys"]](), keys)
      expect_identical(client@state_store[["get"]](keys[[1L]]), pending)
    }
    token <- handle_callback(client, "code", state, browser_token = browser)
    expect_identical(token@access_token, "access")
    expect_identical(requests, 1L)
    expect_length(client@state_store[["keys"]](), 0L)
  }
})
