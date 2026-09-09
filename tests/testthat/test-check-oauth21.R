oauth21_test_client <- function(provider_args = list(), ...) {
  provider <- do.call(
    oauth_provider,
    utils::modifyList(
      list(
        name = "Assessment",
        auth_url = "https://issuer.example/auth",
        token_url = "https://issuer.example/token",
        token_auth_style = "public",
        use_pkce = TRUE,
        pkce_method = "S256"
      ),
      provider_args
    )
  )
  oauth_client(
    provider,
    client_id = "client",
    redirect_uri = "https://app.example/callback",
    state_key = strrep("k", 64),
    ...
  )
}

oauth21_finding <- function(report, id) {
  report$checks[report$checks$id == id, , drop = FALSE]
}

test_that("a supported public client passes a bounded, deterministic assessment", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client()
  report <- check_oauth21(client)
  expect_s3_class(report, "shinyOAuth_oauth21_assessment")
  expect_true(report$configuration_compliant)
  expect_identical(
    names(report$checks),
    c(
      "id",
      "scope",
      "status",
      "requirement",
      "message",
      "remediation",
      "reference",
      "evidence_source",
      "requirement_source",
      "affects_verdict"
    )
  )
  expect_identical(report$operations, c("authorization", "code", "refresh"))
  expect_identical(report$draft, "draft-ietf-oauth-v2-1-16")
  expect_identical(report$ruleset_version, "1.1.0")
  expect_true(all(
    report$checks$status %in% c("pass", "fail", "unknown", "not_applicable")
  ))
  expect_false(anyDuplicated(report$checks$id) > 0L)
  expect_identical(check_oauth21(client)$checks, report$checks)
  raw <- do.call(OAuthClient, S7::props(client))
  expect_identical(check_oauth21(raw)$checks, report$checks)
  expect_output(print(report), "Mandatory configuration checks passed")
  expect_output(print(report), "unknown external/request checks: [1-9]")
  expect_identical(
    oauth21_finding(report, "jwt_audience.token")$status,
    "not_applicable"
  )
  expect_identical(
    oauth21_finding(report, "refresh.server_protection")$status,
    "unknown"
  )
  expect_identical(
    oauth21_finding(report, "identity.validation")$status,
    "not_applicable"
  )
})

test_that("legacy choices remain constructible while mandatory failures outrank unknowns", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(list(pkce_method = "plain"))
  report <- check_oauth21(client)
  expect_false(report$configuration_compliant)
  expect_identical(oauth21_finding(report, "pkce.method")$status, "fail")
  expect_output(print(report), "Mandatory configuration checks failed")
  partial <- check_oauth21(client@provider)
  expect_false(partial$configuration_compliant)
  expect_identical(
    oauth21_finding(partial, "client.configuration")$status,
    "unknown"
  )
  provider <- oauth21_test_client()@provider
  expect_identical(check_oauth21(provider)$configuration_compliant, NA)
  expect_output(
    print(check_oauth21(provider)),
    "Mandatory configuration checks are unresolved"
  )
  expect_identical(
    oauth21_verdict(data.frame(
      status = character(),
      affects_verdict = logical()
    )),
    NA
  )
  expect_true(oauth21_verdict(data.frame(
    status = c("pass", "fail", "unknown"),
    affects_verdict = c(TRUE, FALSE, FALSE)
  )))
  expect_identical(
    oauth21_verdict(data.frame(
      status = c("pass", "unknown"),
      affects_verdict = TRUE
    )),
    NA
  )
})

test_that("JWT audience is mandatory while legacy typing remains an advisory", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(
    list(
      token_auth_style = "client_secret_jwt",
      issuer = "https://issuer.example",
      issuer_thus_oidc = FALSE
    ),
    client_secret = strrep("s", 32)
  )
  expect_false(check_oauth21(client)$configuration_compliant)
  client@client_assertion_audience <- client@provider@issuer
  report <- check_oauth21(client)
  expect_true(report$configuration_compliant)
  type <- oauth21_finding(report, "jwt_typ.token")
  expect_identical(type$status, "fail")
  expect_identical(type$requirement, "SHOULD")
  expect_false(type$affects_verdict)
  req <- httr2::request(client@provider@token_url)
  assertion <- apply_direct_client_auth(
    req,
    list(),
    client,
    "token"
  )$params$client_assertion
  expect_identical(parse_jwt_payload(assertion)$aud, client@provider@issuer)
  expect_identical(parse_jwt_header(assertion)$typ, "JWT")
  client@client_assertion_typ <- "client-authentication+jwt"
  expect_identical(
    oauth21_finding(check_oauth21(client), "jwt_typ.token")$status,
    "pass"
  )
  client@client_assertion_audience <- paste0(client@provider@issuer, "/")
  expect_false(check_oauth21(client)$configuration_compliant)
})

test_that("endpoint scope and effective overrides agree with actual requests", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(
    list(
      token_auth_style = "client_secret_jwt",
      issuer = "https://issuer.example",
      issuer_thus_oidc = FALSE,
      par_url = "https://issuer.example/par",
      revocation_url = "https://issuer.example/revoke",
      introspection_url = "https://issuer.example/introspect"
    ),
    client_secret = strrep("s", 32),
    client_assertion_audience = "https://issuer.example",
    endpoint_auth = list(
      revocation = list(
        client_assertion_audience = "https://issuer.example/revoke"
      )
    )
  )
  base <- check_oauth21(client)
  expect_true(base$configuration_compliant)
  expect_true("par" %in% base$operations)
  expect_false("revocation" %in% base$operations)
  report <- check_oauth21(
    client,
    context = list(operations = c("revocation", "introspection"))
  )
  expect_false(report$configuration_compliant)
  expect_identical(
    oauth21_finding(report, "jwt_audience.revocation")$status,
    "fail"
  )
  effective <- endpoint_auth_client(client, "revocation")
  jwt <- apply_direct_client_auth(
    httr2::request(client@provider@revocation_url),
    list(),
    effective,
    "revocation"
  )$params$client_assertion
  expect_identical(parse_jwt_payload(jwt)$aud, client@provider@revocation_url)
  client@endpoint_auth <- list(revocation = list(token_auth_style = "header"))
  report <- check_oauth21(client, context = list(operations = "revocation"))
  expect_true(report$configuration_compliant)
  expect_identical(
    oauth21_finding(report, "jwt_audience.revocation")$status,
    "not_applicable"
  )
  client@provider@endpoint_auth_metadata <- list(
    introspection = list(methods = "client_secret_basic", signing_algs = NULL)
  )
  report <- check_oauth21(client, context = list(operations = "introspection"))
  expect_true(report$configuration_compliant)
  expect_identical(
    oauth21_endpoint_settings(client, client@provider, "introspection")$style,
    endpoint_auth_client(client, "introspection")@provider@token_auth_style
  )
  client@endpoint_auth <- list(
    introspection = list(token_auth_style = "private_key_jwt")
  )
  expect_false(
    check_oauth21(
      client,
      context = list(operations = "introspection")
    )$configuration_compliant
  )
})

test_that("selected HTTP endpoints fail while unused allowances and aliases do not", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(list(token_url = "http://localhost:8000/token"))
  expect_false(check_oauth21(client)$configuration_compliant)
  client <- oauth21_test_client(list(
    revocation_url = "http://localhost:8000/revoke"
  ))
  expect_true(check_oauth21(client)$configuration_compliant)
  expect_false(
    check_oauth21(
      client,
      context = list(operations = "revocation")
    )$configuration_compliant
  )
  client <- oauth21_test_client(list(
    mtls_endpoint_aliases = list(token_endpoint = "http://localhost:8000/token")
  ))
  expect_true(check_oauth21(client)$configuration_compliant)
  client@redirect_uri <- "http://127.0.0.1:8100/callback"
  expect_true(check_oauth21(client)$configuration_compliant)
  expect_false(oauth21_redirect_ok(
    "https://name:password@app.example/callback"
  ))
  expect_false(oauth21_redirect_ok("http://app.example/callback"))
  expect_false(oauth21_redirect_ok("https://app.example/callback#fragment"))
  expect_false(oauth21_https("https://name:password@issuer.example/token"))
})

test_that("mTLS endpoint selection is shared with request construction", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(
    list(
      token_auth_style = "tls_client_auth",
      mtls_endpoint_aliases = list(
        token_endpoint = "http://localhost:8000/token"
      )
    ),
    mtls_client_cert_file = mtls_pem_fixture("client-cert.pem"),
    mtls_client_key_file = mtls_pem_fixture("client-key.pem")
  )
  report <- check_oauth21(client)
  expect_false(report$configuration_compliant)
  expect_identical(oauth21_finding(report, "https.token")$status, "fail")
  expect_identical(
    oauth21_endpoint_settings(client, client@provider, "token")$url,
    resolve_provider_endpoint_url(
      client@provider,
      "token_endpoint",
      client_uses_mtls_endpoint(client)
    )
  )
})

test_that("runtime TLS defaults are unknown unless the linked curl default is known", {
  client <- oauth21_test_client()
  withr::local_options(list(shinyOAuth.tls_min_version = NULL))
  local_mocked_bindings(
    curl_version = function() {
      list(version = "8.15.0", ssl_version = "OpenSSL/3")
    },
    .package = "curl"
  )
  expect_identical(check_oauth21(client)$configuration_compliant, NA)
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  expect_true(check_oauth21(client)$configuration_compliant)
  withr::local_options(list(shinyOAuth.tls_min_version = "invalid"))
  expect_false(check_oauth21(client)$configuration_compliant)
  withr::local_options(list(shinyOAuth.tls_min_version = NULL))
  local_mocked_bindings(
    curl_version = function() {
      list(version = "8.16.0", ssl_version = "OpenSSL/3")
    },
    .package = "curl"
  )
  expect_true(check_oauth21(client)$configuration_compliant)
})

test_that("the no-PKCE exception distinguishes ineligible, unresolved and declared prerequisites", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(
    list(token_auth_style = "header", use_pkce = FALSE),
    client_secret = strrep("s", 32)
  )
  expect_false(
    check_oauth21(
      client,
      context = list(nonce_exception = TRUE)
    )$configuration_compliant
  )
  client <- oauth21_test_client(
    list(
      token_auth_style = "header",
      use_pkce = FALSE,
      issuer = "https://issuer.example",
      jwks_uri = "https://issuer.example/jwks"
    ),
    client_secret = strrep("s", 32),
    scopes = "openid"
  )
  expect_identical(check_oauth21(client)$configuration_compliant, NA)
  expect_false(
    check_oauth21(
      client,
      context = list(nonce_exception = FALSE)
    )$configuration_compliant
  )
  report <- check_oauth21(client, context = list(nonce_exception = TRUE))
  expect_true(report$configuration_compliant)
  expect_identical(
    oauth21_finding(report, "pkce.method")$evidence_source,
    "configuration_and_declared_context"
  )
  # Nonce use itself makes the ID token mandatory in verify_token_set().
  client@provider@id_token_required <- FALSE
  expect_true(
    check_oauth21(
      client,
      context = list(nonce_exception = TRUE)
    )$configuration_compliant
  )
  expect_identical(
    oauth21_finding(report, "pkce.exception_assurance")$status,
    "unknown"
  )
  withr::local_options(list(shinyOAuth.skip_id_sig = TRUE))
  expect_false(
    check_oauth21(
      client,
      context = list(nonce_exception = TRUE)
    )$configuration_compliant
  )
})

test_that("issuer participation respects single-server opt-out and advertised support", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(
    list(
      issuer = "https://issuer.example",
      issuer_thus_oidc = FALSE,
      authorization_response_iss_parameter_supported = TRUE
    ),
    enforce_callback_issuer = FALSE
  )
  expect_true(check_oauth21(client)$configuration_compliant)
  client@compare_callback_issuer <- TRUE
  expect_false(check_oauth21(client)$configuration_compliant)
  client@enforce_callback_issuer <- TRUE
  client@authorization_server_mode <- "multi_issuer"
  expect_true(check_oauth21(client)$configuration_compliant)
  client <- oauth21_test_client(
    authorization_server_mode = "multi_redirect_uri",
    authorization_server_redirect_uris = c(
      "https://app.example/callback",
      "https://app.example/second"
    )
  )
  expect_true(check_oauth21(client)$configuration_compliant)
})

test_that("parameter assessment preserves repeatable extensions and defers dynamic values", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(list(
    auth_url = "https://issuer.example/auth?client_id=client&resource=one&resource=two"
  ))
  expect_true(check_oauth21(client)$configuration_compliant)
  client@provider@auth_url <- "https://issuer.example/auth?client_id=different"
  expect_false(check_oauth21(client)$configuration_compliant)
  client@provider@auth_url <- "https://issuer.example/auth?state=future"
  expect_identical(check_oauth21(client)$configuration_compliant, NA)
  client@provider@auth_url <- "https://issuer.example/auth?Client_id=unrelated"
  expect_true(check_oauth21(client)$configuration_compliant)
  withr::local_options(list(
    shinyOAuth.unblock_auth_params = c("scope", "redirect_uri")
  ))
  client@provider@extra_auth_params <- list(scope = "custom")
  expect_true(check_oauth21(client)$configuration_compliant)
  client@provider@extra_auth_params <- list(
    redirect_uri = "https://app.example/different"
  )
  expect_false(check_oauth21(client)$configuration_compliant)
})

test_that("active relaxations and capacity findings have appropriate applicability", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client()
  withr::local_options(list(
    shinyOAuth.callback_max_code_bytes = 4096,
    shinyOAuth.allow_non_atomic_state_store = TRUE,
    shinyOAuth.skip_id_sig = TRUE,
    shinyOAuth.unblock_token_headers = "authorization",
    shinyOAuth.allow_redirect = TRUE
  ))
  report <- check_oauth21(client)
  expect_true(report$configuration_compliant)
  expect_identical(oauth21_finding(report, "callback.capacity")$status, "fail")
  expect_false(oauth21_finding(report, "callback.capacity")$affects_verdict)
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  expect_false(check_oauth21(client)$configuration_compliant)
  local_mocked_bindings(.is_test_or_interactive = function() FALSE)
  expect_true(check_oauth21(client)$configuration_compliant)
})

test_that("assessment recommendations preserve valid legacy configurations and identify owners", {
  withr::local_options(shinyOAuth.tls_min_version = "1.2")
  for (style in c("header", "body", "client_secret_jwt")) {
    client <- oauth21_test_client(
      list(
        token_auth_style = style,
        issuer = "https://issuer.example",
        issuer_thus_oidc = FALSE
      ),
      client_secret = strrep("s", 32),
      client_assertion_audience = "https://issuer.example"
    )
    report <- check_oauth21(client)
    expect_true(report$configuration_compliant)
    advice <- oauth21_finding(report, "client_auth.asymmetric.token")
    expect_identical(advice$status, "fail")
    expect_false(advice$affects_verdict)
    expect_identical(advice$requirement_source, "oauth_security_bcp")
    expect_identical(
      oauth21_finding(report, "refresh.public_client_protection")$status,
      "not_applicable"
    )
  }
  client <- oauth21_test_client()
  client@redirect_uri <- "http://localhost:8100/callback"
  report <- check_oauth21(client)
  expect_true(report$configuration_compliant)
  expect_identical(
    oauth21_finding(report, "redirect.loopback_literal")$status,
    "fail"
  )
  client@redirect_uri <- "http://127.0.0.1:8100/callback"
  expect_identical(
    oauth21_finding(check_oauth21(client), "redirect.loopback_literal")$status,
    "pass"
  )
  client <- oauth21_test_client(
    authorization_server_mode = "multi_redirect_uri",
    authorization_server_redirect_uris = c(
      "https://app.example/callback",
      "https://app.example/other"
    )
  )
  report <- check_oauth21(client)
  expect_true(report$configuration_compliant)
  expect_identical(oauth21_finding(report, "issuer.mixup")$status, "pass")
  expect_identical(
    oauth21_finding(report, "issuer.identification_recommended")$status,
    "fail"
  )
  expect_identical(
    oauth21_finding(report, "refresh.public_client_protection")$status,
    "unknown"
  )
  expect_match(
    oauth21_finding(report, "refresh.public_client_protection")$reference,
    "section-4.3.1",
    fixed = TRUE
  )
  expect_identical(
    oauth21_finding(report, "tokens.application_policy")$requirement,
    "info"
  )
  expect_identical(
    oauth21_finding(report, "tokens.application_policy")$requirement_source,
    "application_policy"
  )
  for (id in c(
    "tokens.resource_server_validation",
    "tokens.early_invalidation"
  )) {
    row <- oauth21_finding(report, id)
    expect_identical(row$requirement, "MUST")
    expect_identical(row$scope, "external")
    expect_false(row$affects_verdict)
  }
  for (id in c("callback.capacity", "transport.redirects")) {
    expect_identical(
      oauth21_finding(report, id)$requirement_source,
      "package_policy"
    )
  }
  oidc <- oauth21_test_client(
    list(
      issuer = "https://issuer.example",
      jwks_uri = "https://issuer.example/keys",
      userinfo_url = "https://issuer.example/userinfo"
    ),
    scopes = "openid"
  )
  expect_identical(
    oauth21_finding(
      check_oauth21(oidc),
      "identity.userinfo_subject"
    )$requirement_source,
    "oidc"
  )
})

test_that("capacity advice covers all callback field caps without changing verdicts", {
  withr::local_options(shinyOAuth.tls_min_version = "1.2")
  client <- oauth21_test_client()
  for (field in c(
    "code",
    "state",
    "error",
    "error_description",
    "error_uri",
    "iss",
    "browser_token",
    "form_post_handle",
    "form_post_id",
    "query",
    "form_post_body"
  )) {
    withr::with_options(
      stats::setNames(
        list(1),
        paste0("shinyOAuth.callback_max_", field, "_bytes")
      ),
      {
        report <- check_oauth21(client)
        expect_true(report$configuration_compliant)
        expect_identical(
          oauth21_finding(report, "callback.capacity")$status,
          "fail"
        )
      }
    )
  }
})

test_that("assessment has no protocol, random, cache, object or option side effects", {
  withr::local_options(list(
    shinyOAuth.tls_min_version = "1.2",
    shinyOAuth.expose_error_body = TRUE
  ))
  client <- oauth21_test_client(
    list(
      token_auth_style = "client_secret_jwt",
      issuer = "https://issuer.example",
      issuer_thus_oidc = FALSE,
      auth_url = "https://issuer.example/auth?tenant=URL-SENTINEL"
    ),
    client_secret = "SECRET-SENTINEL-01234567890123456789",
    client_assertion_audience = "https://issuer.example"
  )
  store_environment <- new.env(parent = baseenv())
  store_environment$store_calls <- 0L
  store <- evalq(
    list(
      get = function(key, missing = NULL) {
        store_calls <<- store_calls + 1L
        missing
      },
      set = function(key, value) {
        store_calls <<- store_calls + 1L
      },
      remove = function(key) {
        store_calls <<- store_calls + 1L
      },
      take = function(key, missing = NULL) {
        store_calls <<- store_calls + 1L
        missing
      }
    ),
    store_environment
  )
  client@state_store <- store
  forbidden <- function(...) {
    stop("assessment invoked a protocol or random operation")
  }
  local_mocked_bindings(
    prepare_call = forbidden,
    build_client_assertion = forbidden,
    endpoint_auth_client = forbidden,
    req_with_retry = forbidden,
    req_perform_bounded = forbidden,
    fetch_authorization_server_metadata = forbidden,
    string_digest = forbidden,
    err_config = forbidden,
    err_parse = forbidden
  )
  local_mocked_bindings(rand_bytes = forbidden, .package = "openssl")
  local_mocked_bindings(req_perform = forbidden, .package = "httr2")
  withr::local_seed(927L)
  rng <- .Random.seed
  before <- serialize(client, NULL)
  opts <- options()
  report <- expect_silent(check_oauth21(client))
  after <- serialize(client, NULL)
  after_options <- options()
  after_rng <- .Random.seed
  rendered <- paste(capture.output(print(report), str(report)), collapse = "\n")
  expect_false(grepl("SECRET-SENTINEL|URL-SENTINEL", rendered))
  expect_true(identical(after, before))
  expect_identical(after_options, opts)
  expect_identical(after_rng, rng)
  expect_identical(store_environment$store_calls, 0L)
  expect_true(report$configuration_compliant)
})

test_that("JARM and validated OIDC policies are assessed when selected", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(
    list(
      issuer = "https://issuer.example",
      issuer_thus_oidc = FALSE,
      jwks_uri = "https://issuer.example/jwks",
      jarm_signing_alg_values_supported = "RS256"
    ),
    authorization_server_mode = "multi_issuer",
    response_mode = "query.jwt",
    jarm_signed_response_alg = "RS256"
  )
  report <- check_oauth21(client)
  expect_true(report$configuration_compliant)
  expect_true("jwks" %in% report$operations)
  expect_identical(
    oauth21_finding(report, "issuer.participation")$status,
    "not_applicable"
  )
  client <- oauth21_test_client(
    list(
      issuer = "https://issuer.example",
      jwks_uri = "https://issuer.example/jwks",
      userinfo_url = "https://issuer.example/userinfo"
    ),
    scopes = "openid"
  )
  expect_true(check_oauth21(client)$configuration_compliant)
  client@provider@userinfo_id_token_match <- FALSE
  expect_true(check_oauth21(client)$configuration_compliant)
  withr::local_options(list(shinyOAuth.unblock_auth_params = "scope"))
  client@provider@extra_auth_params <- list(scope = "profile")
  expect_identical(
    oauth21_finding(check_oauth21(client), "parameters.authorization")$status,
    "fail"
  )
})

test_that("HMAC-only JARM needs no JWKS but independent key operations still do", {
  withr::local_options(shinyOAuth.tls_min_version = "1.2")
  client <- oauth21_test_client(
    list(
      issuer = "https://issuer.example",
      issuer_thus_oidc = FALSE,
      jarm_signing_alg_values_supported = c("HS256", "RS256")
    ),
    client_secret = strrep("s", 32),
    response_mode = "query.jwt",
    jarm_signed_response_alg = "HS256"
  )
  local_mocked_bindings(
    fetch_jwks = function(...) stop("HMAC must not fetch keys"),
    .package = "shinyOAuth"
  )
  signed <- jose::jwt_encode_hmac(
    jose::jwt_claim(
      iss = client@provider@issuer,
      aud = client@client_id,
      exp = as.numeric(Sys.time()) + 60
    ),
    client@client_secret
  )
  expect_silent(verify_jarm_signature(client, signed, "HS256"))
  expect_true(check_oauth21(client)$configuration_compliant)
  expect_false("jwks" %in% check_oauth21(client)$operations)
  client@provider@jwks_uri <- "http://localhost:8000/keys"
  expect_true(check_oauth21(client)$configuration_compliant)
  expect_false("jwks" %in% check_oauth21(client)$operations)
  asymmetric <- client
  asymmetric@jarm_signed_response_alg <- "RS256"
  expect_identical(
    oauth21_finding(check_oauth21(asymmetric), "https.jwks")$status,
    "fail"
  )
  client@provider@id_token_validation <- TRUE
  expect_identical(
    oauth21_finding(check_oauth21(client), "https.jwks")$status,
    "fail"
  )
})

test_that("UserInfo assessment follows the validated baseline and call context", {
  withr::local_options(shinyOAuth.tls_min_version = "1.2")
  client <- oauth21_test_client(
    list(
      issuer = "https://issuer.example",
      jwks_uri = "https://issuer.example/keys",
      userinfo_url = "https://issuer.example/userinfo",
      userinfo_id_token_match = FALSE
    ),
    scopes = "openid"
  )
  finding <- function(context = list()) {
    oauth21_finding(
      check_oauth21(client, context = context),
      "identity.userinfo_subject"
    )$status
  }
  expect_identical(finding(), "pass")
  expect_identical(finding(list(operations = "userinfo")), "unknown")
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  expect_identical(finding(), "fail")
  withr::local_options(shinyOAuth.skip_id_sig = FALSE)
  client@provider@use_nonce <- FALSE
  client@provider@id_token_validation <- FALSE
  expect_identical(finding(), "fail")
  client@provider@id_token_validation <- TRUE
  client@provider@userinfo_id_token_match <- TRUE
  expect_identical(finding(list(operations = "userinfo")), "pass")
})

test_that("encrypted Request Objects assess the actual recipient key source without IO", {
  withr::local_options(shinyOAuth.tls_min_version = "1.2")
  key <- openssl::rsa_keygen()
  client <- oauth21_test_client(
    list(issuer = "https://issuer.example", issuer_thus_oidc = FALSE),
    request_object_mode = "request",
    client_assertion_private_key = key,
    client_assertion_alg = "RS256",
    request_object_encryption_alg = "RSA-OAEP",
    request_object_encryption_enc = "A128CBC-HS256"
  )
  explicit <- client
  explicit@provider@request_object_encryption_jwk <- key$pubkey
  local_mocked_bindings(
    fetch_jwks = function(...) stop("assessment must not retrieve keys"),
    normalize_jwe_recipient_public_key = function(...) {
      stop("assessment must not load keys")
    },
    .package = "shinyOAuth"
  )
  expect_identical(
    oauth21_finding(check_oauth21(client), "https.jwks")$status,
    "unknown"
  )
  client@provider@jwks_uri <- "http://localhost:8000/keys"
  expect_identical(
    oauth21_finding(check_oauth21(client), "https.jwks")$status,
    "fail"
  )
  client@provider@jwks_uri <- "https://issuer.example/keys"
  expect_identical(
    oauth21_finding(check_oauth21(client), "https.jwks")$status,
    "pass"
  )
  expect_false("jwks" %in% check_oauth21(explicit)$operations)
  expect_true(check_oauth21(explicit)$configuration_compliant)
})

test_that("private-key assessment does not probe signatures or require optional extensions", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  client <- oauth21_test_client(
    list(
      issuer = "https://issuer.example",
      issuer_thus_oidc = FALSE,
      token_auth_style = "private_key_jwt"
    ),
    client_assertion_private_key = openssl::ec_keygen(),
    client_assertion_audience = "https://issuer.example",
    client_assertion_typ = "client-authentication+jwt"
  )
  local_mocked_bindings(
    jwt_encode_sig = function(...) stop("must not sign"),
    .package = "jose"
  )
  report <- check_oauth21(client)
  expect_true(report$configuration_compliant)
  expect_false(any(grepl("BEGIN|PRIVATE KEY", unlist(report$checks))))
  expect_identical(oauth21_finding(report, "jwt_audience.token")$status, "pass")
  for (style in c("header", "body")) {
    ordinary <- oauth21_test_client(
      list(token_auth_style = style),
      client_secret = "secret"
    )
    expect_true(check_oauth21(ordinary)$configuration_compliant)
  }
})

test_that("development bypass assessment follows legacy numeric flag semantics", {
  withr::local_options(list(
    shinyOAuth.tls_min_version = "1.2",
    shinyOAuth.skip_browser_token = 1
  ))
  client <- oauth21_test_client()
  expect_true(allow_skip_browser_token())
  expect_false(check_oauth21(client)$configuration_compliant)
  withr::local_options(list(shinyOAuth.skip_browser_token = NA))
  expect_identical(check_oauth21(client)$configuration_compliant, NA)
  withr::local_options(list(
    shinyOAuth.skip_browser_token = 0,
    shinyOAuth.skip_id_sig = 1
  ))
  expect_true(check_oauth21(client)$configuration_compliant)
  client <- oauth21_test_client(
    list(
      issuer = "https://issuer.example",
      jwks_uri = "https://issuer.example/jwks"
    ),
    scopes = "openid"
  )
  expect_true(allow_skip_signature())
  expect_false(check_oauth21(client)$configuration_compliant)
})

test_that("malformed API arguments are programming errors with redacted diagnostics", {
  client <- oauth21_test_client()
  expect_error(check_oauth21(list(secret = "SENTINEL")), "client must")
  expect_error(
    check_oauth21(client, draft = "draft-ietf-oauth-v2-1-15"),
    "Unsupported draft"
  )
  expect_error(
    check_oauth21(client, context = list(secret = "SENTINEL")),
    "context must"
  )
  expect_error(
    check_oauth21(client, context = list(operations = "unknown")),
    "operations must"
  )
  expect_error(
    check_oauth21(client, context = list(nonce_exception = NA)),
    "single non-NA logical"
  )
})
