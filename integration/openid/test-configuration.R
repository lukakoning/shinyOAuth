openid_configuration_client <- function(
  provider_args = list(),
  client_args = list()
) {
  key <- openssl::ec_keygen("P-256")
  provider <- do.call(
    shinyOAuth::oauth_provider,
    utils::modifyList(
      list(
        name = "message-signing-configuration",
        auth_url = "https://issuer.example/authorize",
        token_url = "https://issuer.example/token",
        par_url = "https://issuer.example/par",
        issuer = "https://issuer.example",
        jwks_uri = "https://issuer.example/jwks",
        userinfo_url = "https://issuer.example/userinfo",
        token_auth_style = "private_key_jwt",
        use_pkce = TRUE,
        pkce_method = "S256",
        use_nonce = TRUE,
        id_token_validation = TRUE,
        id_token_required = TRUE,
        allowed_algs = "ES256",
        userinfo_allowed_algs = "ES256",
        userinfo_required = FALSE,
        allowed_token_types = "DPoP",
        authorization_request_front_channel_mode = "minimal",
        request_object_signing_alg_values_supported = c("ES256", "RS256"),
        jarm_signing_alg_values_supported = c("ES256", "RS256"),
        response_modes_supported = c("query", "query.jwt", "jwt")
      ),
      provider_args,
      keep.null = TRUE
    )
  )
  do.call(
    shinyOAuth::oauth_client,
    utils::modifyList(
      list(
        provider = provider,
        client_id = "configuration-private-client",
        client_secret = strrep("s", 32L),
        redirect_uri = "https://app.example/callback",
        scopes = c("openid", "profile"),
        state_transport = "reference",
        client_assertion_private_key = key,
        client_assertion_private_key_kid = "configuration-key",
        client_assertion_alg = "ES256",
        client_assertion_audience = provider@issuer,
        request_object_mode = "request",
        request_object_signing_alg = "ES256",
        request_object_nbf_skew = 0,
        response_mode = "jwt",
        jarm_signed_response_alg = "ES256",
        dpop_private_key = openssl::ec_keygen("P-256"),
        dpop_signing_alg = "ES256",
        dpop_require_access_token = TRUE
      ),
      client_args,
      keep.null = TRUE
    )
  )
}

testthat::test_that("Message Signing assessment reports only bounded configuration evidence", {
  client <- openid_configuration_client()
  before <- client@state_store[["keys"]]()
  assessment <- openid_message_signing_configuration(client)
  testthat::expect_identical(assessment[["schema_version"]], 1L)
  testthat::expect_identical(
    assessment[["profile"]],
    "oidc-private-key-jwt-es256-dpop-jwt"
  )
  testthat::expect_true(assessment[["local_configuration_passed"]])
  testthat::expect_true(all(unlist(assessment[["checks"]])))
  testthat::expect_length(assessment[["issues"]], 0L)
  testthat::expect_identical(
    assessment[["certification_status"]],
    "not_assessed"
  )
  testthat::expect_true(length(assessment[["unassessed"]]) > 0L)
  testthat::expect_true(
    "reference_state" %in% unlist(assessment[["selection_policies"]])
  )
  testthat::expect_identical(client@state_store[["keys"]](), before)
  result <- withVisible(openid_assert_message_signing_configuration(client))
  testthat::expect_false(result[["visible"]])
  testthat::expect_identical(result[["value"]], assessment)
  serialized <- as.character(jsonlite::toJSON(assessment, auto_unbox = TRUE))
  testthat::expect_false(grepl(
    "issuer.example|app.example|configuration-private-client|PRIVATE KEY|configuration-key",
    serialized
  ))
  round_trip <- jsonlite::fromJSON(serialized, simplifyVector = FALSE)
  testthat::expect_identical(round_trip[["checks"]], assessment[["checks"]])
  testthat::expect_length(round_trip[["issues"]], 0L)
  # JARM carries issuer binding inside the signed response. The outer RFC 9207
  # issuer switch is deliberately not a requirement of this named selection.
  testthat::expect_false(client@enforce_callback_issuer)
  invalid <- openid_message_signing_configuration(list(private_key = "secret"))
  testthat::expect_false(invalid[["local_configuration_passed"]])
  testthat::expect_true("client_valid" %in% unlist(invalid[["issues"]]))
  testthat::expect_false(grepl(
    "secret",
    jsonlite::toJSON(invalid, auto_unbox = TRUE)
  ))
})

testthat::test_that("clients built through public APIs produce signed PAR JARs within the Message Signing window", {
  for (timing in list(c(45, 0), c(3600, 0), c(45, 3555))) {
    client <- openid_configuration_client(
      client_args = list(
        request_object_ttl = timing[[1L]],
        request_object_nbf_skew = timing[[2L]]
      )
    )
    requests <- list()
    testthat::local_mocked_bindings(
      req_perform = function(req, ...) {
        requests[[length(requests) + 1L]] <<- req
        testthat::expect_identical(req[["url"]], client@provider@par_url)
        httr2::response(
          url = req[["url"]],
          status = 201L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(
            '{"request_uri":"urn:ietf:params:oauth:request_uri:configured","expires_in":90}'
          )
        )
      },
      .package = "httr2"
    )
    assessment <- openid_assert_message_signing_configuration(client)
    testthat::expect_true(assessment[["local_configuration_passed"]])
    testthat::expect_length(requests, 0L)
    url <- shinyOAuth::prepare_call(client, browser_token = strrep("ab", 64L))
    testthat::expect_length(requests, 1L)
    request <- requests[[1L]]
    testthat::expect_identical(request[["method"]], "POST")
    testthat::expect_identical(request[["body"]][["type"]], "form")
    form <- lapply(request[["body"]][["data"]], function(value) {
      utils::URLdecode(as.character(value))
    })
    testthat::expect_setequal(
      names(form),
      c("client_id", "request", "client_assertion_type", "client_assertion")
    )
    testthat::expect_identical(form[["client_id"]], client@client_id)
    public_key <- client@client_assertion_private_key[["pubkey"]]
    # Real verification proves the accepted configuration reaches the unchanged
    # package signer and PAR request path; only the HTTP response is mocked.
    testthat::expect_true(openid_signing_signature(
      form[["request"]],
      getFromNamespace("dpop_public_jwk", "shinyOAuth")(public_key)
    ))
    claims <- getFromNamespace("parse_jwt_payload", "shinyOAuth")(form[[
      "request"
    ]])
    assertion <- jose::jwt_decode_sig(form[["client_assertion"]], public_key)
    header <- getFromNamespace("parse_jwt_header", "shinyOAuth")(form[[
      "request"
    ]])
    testthat::expect_identical(header[["alg"]], "ES256")
    testthat::expect_identical(header[["typ"]], "oauth-authz-req+jwt")
    testthat::expect_identical(claims[["iss"]], client@client_id)
    testthat::expect_identical(claims[["client_id"]], client@client_id)
    testthat::expect_identical(claims[["aud"]], client@provider@issuer)
    testthat::expect_identical(assertion[["aud"]], client@provider@issuer)
    testthat::expect_identical(claims[["response_mode"]], "jwt")
    testthat::expect_identical(claims[["redirect_uri"]], client@redirect_uri)
    testthat::expect_identical(claims[["scope"]], "openid profile")
    testthat::expect_identical(claims[["code_challenge_method"]], "S256")
    testthat::expect_true(nzchar(claims[["nonce"]]))
    testthat::expect_true(nzchar(claims[["dpop_jkt"]]))
    testthat::expect_equal(claims[["exp"]] - claims[["iat"]], timing[[1L]])
    testthat::expect_equal(claims[["iat"]] - claims[["nbf"]], timing[[2L]])
    testthat::expect_equal(claims[["exp"]] - claims[["nbf"]], sum(timing))
    testthat::expect_lte(claims[["exp"]] - claims[["nbf"]], 3600)
    query <- httr2::url_parse(url)[["query"]]
    testthat::expect_identical(
      sort(names(query)),
      c("client_id", "request_uri")
    )
    testthat::expect_identical(query[["client_id"]], client@client_id)
    testthat::expect_identical(
      query[["request_uri"]],
      "urn:ietf:params:oauth:request_uri:configured"
    )
    testthat::expect_length(client@state_store[["keys"]](), 1L)
  }
})

testthat::test_that("Message Signing timing failures stop before any PAR HTTP request", {
  cases <- list(
    list(
      args = list(request_object_nbf_skew = NULL),
      issues = c("jar_nbf_present", "jar_lifetime_window")
    ),
    list(
      args = list(request_object_ttl = 3601),
      issues = "jar_lifetime_window"
    ),
    list(
      args = list(request_object_nbf_skew = 3601),
      issues = c("jar_nbf_past_window", "jar_lifetime_window")
    ),
    list(
      args = list(request_object_nbf_skew = 3556),
      issues = "jar_lifetime_window"
    )
  )
  requests <- 0L
  testthat::local_mocked_bindings(
    req_perform = function(...) {
      requests <<- requests + 1L
      stop("unexpected HTTP request")
    },
    .package = "httr2"
  )
  for (case in cases) {
    # All remain legal general-purpose OAuth/JAR constructor settings.
    client <- openid_configuration_client(client_args = case[["args"]])
    assessment <- openid_message_signing_configuration(client)
    testthat::expect_false(assessment[["local_configuration_passed"]])
    testthat::expect_true(all(
      case[["issues"]] %in% unlist(assessment[["issues"]])
    ))
    testthat::expect_error(
      {
        openid_assert_message_signing_configuration(client)
        shinyOAuth::prepare_call(client, browser_token = strrep("ab", 64L))
      },
      case[["issues"]][[1L]]
    )
    testthat::expect_length(client@state_store[["keys"]](), 0L)
    testthat::expect_identical(requests, 0L)
  }
})

testthat::test_that("Message Signing assessment checks resolved endpoint overrides and selected policies", {
  rsa_key <- openssl::rsa_keygen()
  cases <- list(
    list(
      client = list(request_object_audience = "https://other.example"),
      issue = "jar_audience"
    ),
    list(
      client = list(client_assertion_audience = NULL),
      issue = "token_assertion_audience"
    ),
    list(
      client = list(
        endpoint_auth = list(
          par = list(client_assertion_audience = "https://other.example")
        )
      ),
      issue = "par_assertion_audience"
    ),
    list(
      client = list(
        endpoint_auth = list(par = list(token_auth_style = "body"))
      ),
      issue = "par_client_authentication"
    ),
    list(
      client = list(
        endpoint_auth = list(
          par = list(
            client_assertion_private_key = rsa_key,
            client_assertion_alg = "RS256"
          )
        )
      ),
      issue = "par_assertion_algorithm"
    ),
    list(
      client = list(
        client_assertion_private_key = rsa_key,
        client_assertion_alg = "RS256",
        request_object_signing_alg = "RS256"
      ),
      issue = "token_assertion_algorithm"
    ),
    list(
      client = list(response_mode = "query.jwt"),
      issue = "jwt_response_mode"
    ),
    list(
      client = list(jarm_signed_response_alg = "RS256"),
      issue = "jarm_signing_algorithm"
    ),
    list(
      provider = list(allowed_algs = "RS256"),
      issue = "id_token_algorithms"
    ),
    list(
      provider = list(userinfo_allowed_algs = "RS256"),
      issue = "userinfo_algorithms"
    ),
    list(provider = list(pkce_method = "plain"), issue = "pkce_s256"),
    list(provider = list(use_nonce = FALSE), issue = "nonce_enabled"),
    list(provider = list(id_token_required = FALSE), issue = "oidc_validation"),
    list(
      provider = list(auth_url = "http://localhost/authorize"),
      issue = "https_endpoints"
    ),
    list(
      client = list(redirect_uri = "http://localhost/callback"),
      issue = "https_redirect"
    ),
    list(
      client = list(dpop_require_access_token = FALSE),
      issue = "dpop_required"
    ),
    list(
      client = list(state_transport = "encrypted"),
      issue = "reference_state"
    )
  )
  for (case in cases) {
    client <- openid_configuration_client(
      provider_args = if (is.null(case[["provider"]])) {
        list()
      } else {
        case[["provider"]]
      },
      client_args = if (is.null(case[["client"]])) list() else case[["client"]]
    )
    assessment <- openid_message_signing_configuration(client)
    testthat::expect_false(assessment[["local_configuration_passed"]])
    testthat::expect_false(assessment[["checks"]][[case[["issue"]]]])
    testthat::expect_true(case[["issue"]] %in% unlist(assessment[["issues"]]))
  }
  json_only <- openid_configuration_client(
    provider_args = list(userinfo_allowed_algs = character())
  )
  testthat::expect_true(openid_message_signing_configuration(json_only)[[
    "local_configuration_passed"
  ]])
  inherited <- openid_configuration_client(
    provider_args = list(userinfo_allowed_algs = NULL)
  )
  testthat::expect_true(openid_message_signing_configuration(inherited)[[
    "local_configuration_passed"
  ]])
  inherited_broad <- openid_configuration_client(
    provider_args = list(
      userinfo_allowed_algs = NULL,
      allowed_algs = c("ES256", "RS256")
    )
  )
  testthat::expect_false(openid_message_signing_configuration(inherited_broad)[[
    "checks"
  ]][["userinfo_algorithms"]])
  mixed <- openid_configuration_client(
    provider_args = list(userinfo_allowed_algs = c("ES256", "RS256"))
  )
  testthat::expect_false(openid_message_signing_configuration(mixed)[[
    "checks"
  ]][["userinfo_algorithms"]])
  # General alias normalization is retained; the resulting wire mode remains jwt.
  alias <- openid_configuration_client(
    client_args = list(response_mode = "JWT")
  )
  testthat::expect_true(openid_message_signing_configuration(alias)[[
    "local_configuration_passed"
  ]])
  duplicated_dpop <- openid_configuration_client(
    provider_args = list(allowed_token_types = c("DPoP", "dpop"))
  )
  testthat::expect_true(openid_message_signing_configuration(duplicated_dpop)[[
    "local_configuration_passed"
  ]])
  signed_userinfo <- openid_configuration_client(
    provider_args = list(userinfo_signed_jwt_required = TRUE)
  )
  testthat::expect_true(openid_message_signing_configuration(signed_userinfo)[[
    "local_configuration_passed"
  ]])
})

testthat::test_that("Message Signing assessment rejects disabled signature and browser policies", {
  client <- openid_configuration_client()
  for (case in list(
    c("shinyOAuth.skip_id_sig", "signature_policy"),
    c("shinyOAuth.allow_unsigned_userinfo_jwt", "signature_policy"),
    c("shinyOAuth.skip_browser_token", "browser_binding_policy")
  )) {
    withr::with_options(stats::setNames(list(TRUE), case[[1L]]), {
      result <- openid_message_signing_configuration(client)
      testthat::expect_false(result[["local_configuration_passed"]])
      testthat::expect_false(result[["checks"]][[case[[2L]]]])
      testthat::expect_error(
        openid_assert_message_signing_configuration(client),
        case[[2L]]
      )
    })
  }
})

testthat::test_that("the DPoP-only assessment stops mixed mTLS alias intent before HTTP or state", {
  fixture <- function(name) {
    normalizePath(
      file.path("..", "..", "tests", "testthat", "fixtures", "mtls", name),
      winslash = "/",
      mustWork = TRUE
    )
  }
  certificates <- list(
    mtls_client_cert_file = fixture("client-cert.pem"),
    mtls_client_key_file = fixture("client-key.pem"),
    mtls_client_key_password = "password"
  )
  aliases <- list(
    token_endpoint = "http://localhost:8080/mtls/token",
    pushed_authorization_request_endpoint = "http://localhost:8080/mtls/par"
  )
  provider_args <- list(
    mtls_endpoint_aliases = aliases,
    mtls_client_certificate_bound_access_tokens = TRUE
  )
  requests <- 0L
  testthat::local_mocked_bindings(
    req_perform = function(...) {
      requests <<- requests + 1L
      stop("unexpected HTTP request")
    },
    .package = "httr2"
  )
  endpoint_auth <- getFromNamespace("endpoint_auth_client", "shinyOAuth")
  uses_mtls <- getFromNamespace("client_uses_mtls_endpoint", "shinyOAuth")
  endpoint_url <- getFromNamespace(
    "resolve_provider_endpoint_url",
    "shinyOAuth"
  )
  cases <- list(
    # General constructors allow private_key_jwt and DPoP together with
    # certificate-bound intent; runtime then selects the advertised aliases.
    list(
      args = c(certificates, list(mtls_certificate_bound_access_tokens = TRUE)),
      mtls_endpoints = c("token", "par")
    ),
    # PAR can independently select mTLS authentication through endpoint_auth.
    list(
      args = list(
        endpoint_auth = list(
          par = c(
            certificates,
            list(token_auth_style = "tls_client_auth")
          )
        )
      ),
      mtls_endpoints = "par"
    ),
    list(
      args = list(
        endpoint_auth = list(
          par = c(
            certificates,
            list(token_auth_style = "self_signed_tls_client_auth")
          )
        )
      ),
      mtls_endpoints = "par"
    )
  )
  for (case in cases) {
    client <- openid_configuration_client(
      provider_args = provider_args,
      client_args = case[["args"]]
    )
    testthat::expect_no_error(S7::validate(client))
    for (endpoint in c("token", "par")) {
      auth <- endpoint_auth(client, endpoint)
      selected <- uses_mtls(auth)
      testthat::expect_identical(
        selected,
        endpoint %in% case[["mtls_endpoints"]]
      )
      resolved <- endpoint_url(
        auth@provider,
        paste0(endpoint, "_endpoint"),
        prefer_mtls = selected
      )
      expected <- if (selected) {
        if (identical(endpoint, "token")) {
          aliases[["token_endpoint"]]
        } else {
          aliases[["pushed_authorization_request_endpoint"]]
        }
      } else {
        client@provider@token_url
      }
      testthat::expect_identical(resolved, expected)
    }
    before <- client@state_store[["keys"]]()
    assessment <- openid_message_signing_configuration(client)
    testthat::expect_true(assessment[["checks"]][["https_endpoints"]])
    testthat::expect_true(assessment[["checks"]][["dpop_key_and_algorithm"]])
    testthat::expect_true(assessment[["checks"]][["dpop_required"]])
    testthat::expect_false(assessment[["checks"]][["mtls_not_selected"]])
    testthat::expect_false(assessment[["local_configuration_passed"]])
    testthat::expect_true(
      "mtls_not_selected" %in% unlist(assessment[["issues"]])
    )
    testthat::expect_true(
      "dpop_only_sender_constraint" %in%
        unlist(assessment[["selection_policies"]])
    )
    testthat::expect_error(
      {
        openid_assert_message_signing_configuration(client)
        shinyOAuth::prepare_call(client, browser_token = strrep("ab", 64L))
      },
      "mtls_not_selected"
    )
    testthat::expect_identical(requests, 0L)
    testthat::expect_identical(client@state_store[["keys"]](), before)
    testthat::expect_length(before, 0L)
    serialized <- as.character(jsonlite::toJSON(assessment, auto_unbox = TRUE))
    testthat::expect_false(grepl(
      "localhost|client-cert.pem|client-key.pem|password",
      serialized
    ))
  }
  # Advertising aliases or retaining unused certificate material is not runtime
  # intent. These configurations still use the checked HTTPS base endpoints.
  inactive <- openid_configuration_client(
    provider_args = provider_args,
    client_args = certificates
  )
  testthat::expect_false(uses_mtls(inactive))
  for (endpoint in c("token", "par")) {
    testthat::expect_false(uses_mtls(endpoint_auth(inactive, endpoint)))
  }
  testthat::expect_true(openid_message_signing_configuration(inactive)[[
    "local_configuration_passed"
  ]])
  testthat::expect_identical(requests, 0L)
  testthat::expect_length(inactive@state_store[["keys"]](), 0L)
})
