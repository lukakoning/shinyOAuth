test_that("discovery and JWKS endpoint conditions withhold private URL details", {
  local_options(
    shinyOAuth.telemetry_path_scrubber = NULL,
    shinyOAuth.allow_insecure_oidc_loopback = FALSE
  )
  issuer <- "https://issuer.example.com"
  endpoint <- "http://issuer.example.com/private-tenant?api_key=query-secret"
  metadata <- list(
    issuer = issuer,
    authorization_endpoint = paste0(issuer, "/auth"),
    token_endpoint = endpoint,
    jwks_uri = paste0(issuer, "/jwks"),
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256")
  )
  local_mocked_bindings(
    .discover_fetch_response = function(...) {
      httr2::response(
        status_code = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(metadata, auto_unbox = TRUE))
      )
    }
  )
  provider <- make_test_provider(use_nonce = TRUE)
  provider@jwks_uri <- paste0(issuer, "/private-tenant?api_key=query-secret")
  for (expose in c(FALSE, TRUE)) {
    seen <- list()
    local_options(
      shinyOAuth.expose_error_body = expose,
      shinyOAuth.allowed_hosts = NULL,
      shinyOAuth.audit_hook = function(event) {
        seen[[length(seen) + 1L]] <<- event
      }
    )
    discovery_error <- tryCatch(
      oauth_provider_oidc_discover(issuer),
      error = identity
    )
    expect_s3_class(discovery_error, "shinyOAuth_config_error")
    expect_match(conditionMessage(discovery_error), "must use HTTPS")
    local_options(shinyOAuth.allowed_hosts = "different.example.com")
    jwks_error <- tryCatch(
      fetch_jwks(issuer, cachem::cache_mem(), provider = provider),
      error = identity
    )
    expect_s3_class(jwks_error, "shinyOAuth_config_error")
    expect_match(conditionMessage(jwks_error), "not in an allowed host")
    for (error in list(discovery_error, jwks_error)) {
      message <- conditionMessage(error)
      expect_false(grepl("private-tenant|query-secret", message))
      expect_lt(nchar(message, type = "bytes"), 1500)
      if (expose) {
        expect_match(message, "issuer.example.com", fixed = TRUE)
      } else {
        expect_false(grepl("issuer.example.com", message, fixed = TRUE))
      }
    }
    expect_false(any(grepl("private-tenant|query-secret", unlist(seen))))
  }
})

test_that("URL parser failures follow diagnostic exposure policy", {
  local_options(shinyOAuth.telemetry_path_scrubber = NULL)
  for (expose in c(FALSE, TRUE)) {
    local_options(shinyOAuth.expose_error_body = expose)
    for (url in c(
      "https://user:password@[invalid/private-tenant?query-secret",
      "/private-tenant?query-secret"
    )) {
      error <- tryCatch(parse_url_components(url, "endpoint"), error = identity)
      expect_s3_class(error, "shinyOAuth_config_error")
      message <- conditionMessage(error)
      expect_lt(nchar(message, type = "bytes"), 1500)
      if (!expose) {
        expect_false(grepl("password|private-tenant|query-secret", message))
      }
    }
  }
})

test_that("token type and introspection client conditions bound exposed values", {
  client <- make_test_client()
  client@provider@introspection_url <- "https://example.com/introspect"
  client@introspect <- TRUE
  client@introspect_elements <- "client_id"
  client@provider@allowed_token_types <- "Bearer"
  received <- paste0("private-value-{literal}", strrep("x", 2000))
  for (expose in c(FALSE, TRUE)) {
    seen <- list()
    local_options(
      shinyOAuth.expose_error_body = expose,
      shinyOAuth.audit_hook = function(event) {
        seen[[length(seen) + 1L]] <<- event
      }
    )
    token_error <- tryCatch(
      verify_token_set(
        client,
        list(
          access_token = "access",
          token_type = received,
          expires_in = 300
        ),
        nonce = NULL
      ),
      error = identity
    )
    introspection_error <- tryCatch(
      enforce_token_introspection_policy(
        client,
        OAuthToken(
          access_token = "access",
          token_type = "Bearer",
          expires_at = as.numeric(Sys.time()) + 300
        ),
        list(supported = TRUE, active = TRUE, raw = list(client_id = received))
      ),
      error = identity
    )
    expect_identical(token_error[["context"]][["claim"]], "token_type")
    expect_identical(introspection_error[["context"]][["claim"]], "client_id")
    for (error in list(token_error, introspection_error)) {
      expect_s3_class(error, "shinyOAuth_token_error")
      expect_match(
        error[["context"]][["received_claim_digest"]],
        "^[a-f0-9]{64}$"
      )
      message <- conditionMessage(error)
      expect_lt(nchar(message, type = "bytes"), 1500)
      if (expose) {
        expect_match(message, "private-value-{literal}", fixed = TRUE)
      } else {
        expect_false(grepl("private-value", message, fixed = TRUE))
      }
    }
    if (!expose) {
      expect_false(any(grepl("private-value", unlist(seen), fixed = TRUE)))
    }
  }
})
