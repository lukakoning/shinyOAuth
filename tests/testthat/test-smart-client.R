test_that("SMART client opts into an exact FHIR audience and S256", {
  site <- smart_client_fixture()
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = c("launch/patient", "patient/Patient.rs"),
    required_scopes = "patient/Patient.r"
  )
  expect_true(S7::S7_inherits(client, OAuthClient))
  expect_identical(client@smart[["launch"]], "standalone")
  expect_identical(client@smart[["fhir_base"]], site[["fhir_base"]])
  expect_identical(client@resource_bases, c(fhir = site[["fhir_base"]]))
  expect_identical(client@required_scopes, "patient/Patient.r")
  expect_false(provider_uses_oidc(client@provider))
  params <- httr2::url_parse(prepare_call(
    client,
    browser_token = valid_browser_token()
  ))[["query"]]
  expect_identical(params[["aud"]], site[["fhir_base"]])
  expect_identical(params[["code_challenge_method"]], "S256")
  expect_true(nzchar(params[["code_challenge"]]))
  expect_null(params[["launch"]])
  expect_identical(params[["scope"]], "launch/patient patient/Patient.rs")
  changed <- client
  changed@label <- "Another label"
  expect_identical(
    connection_client_fingerprint(client),
    connection_client_fingerprint(changed)
  )
  expect_identical(client@label, "FHIR server")
})

test_that("SMART capability and registration selection fails before network", {
  site <- smart_client_fixture()
  create <- function(site, ...) {
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.rs",
      ...
    )
  }
  local_mocked_bindings(
    req_with_retry = function(...) stop("Unexpected network call"),
    .package = "shinyOAuth"
  )
  expect_no_error(create(site))
  for (capability in c(
    "permission-v2",
    "client-public",
    "launch-standalone",
    "permission-user"
  )) {
    bad <- site
    bad[["metadata"]][["capabilities"]] <- as.list(setdiff(
      unlist(bad[["metadata"]][["capabilities"]]),
      capability
    ))
    expect_error(create(bad), "capability required")
  }
  bad <- site
  bad[["metadata"]][["token_endpoint_auth_methods_supported"]] <- list(
    "private_key_jwt"
  )
  expect_no_error(create(bad))
  expect_error(
    create(
      bad,
      token_auth_style = "header",
      client_secret = "synthetic-secret"
    ),
    "method is not advertised"
  )
  bad <- site
  bad[["metadata"]][["token_endpoint"]] <- "https://other.example/token"
  expect_error(create(bad), "endpoint_hosts")
  expect_error(create(site, client_secret = "unexpected"), "symmetric")
  expect_error(create(site, token_auth_style = "header"), "secret")
  expect_no_error(create(
    site,
    token_auth_style = "header",
    client_secret = "example-secret"
  ))
  expect_error(create(site, identity = "fhirUser"), "sso-openid-connect")
  expect_error(create(site, response_mode = "query.jwt"), "currently supports")
  expect_error(create(site, request_object_mode = "request"), "unused argument")
})

test_that("SMART public registration needs capability but no none authentication advertisement", {
  site <- smart_client_fixture()
  site[["metadata"]][["capabilities"]] <- as.list(setdiff(
    unlist(site[["metadata"]][["capabilities"]]),
    "client-confidential-asymmetric"
  ))
  for (methods in list(
    NULL,
    list(),
    list("client_secret_basic"),
    list("private_key_jwt")
  )) {
    site[["metadata"]][["token_endpoint_auth_methods_supported"]] <- methods
    client <- smart_client(
      site,
      "public-client",
      "https://app.example/callback",
      scopes = c("launch/patient", "patient/Patient.r")
    )
    expect_identical(client@provider@token_auth_style, "public")
    expect_length(client@client_secret, 0L)
  }
  site[["metadata"]][["capabilities"]] <- as.list(setdiff(
    unlist(site[["metadata"]][["capabilities"]]),
    "client-public"
  ))
  expect_error(
    smart_client(
      site,
      "public-client",
      "https://app.example/callback",
      scopes = c("launch/patient", "patient/Patient.r")
    ),
    "capability required"
  )
})

test_that("SMART scope and identity policies cannot be inferred or weakened", {
  site <- smart_client_fixture(oidc = TRUE)
  none <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.rs"
  )
  expect_false(provider_uses_oidc(none@provider))
  expect_false(none@provider@id_token_validation)
  expect_false("openid" %in% effective_client_scopes(none))
  identity <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.rs",
    identity = "fhirUser"
  )
  expect_true(identity@provider@id_token_validation)
  expect_true(identity@provider@use_nonce)
  expect_true(all(c("openid", "fhirUser") %in% identity@required_scopes))
  expect_error(
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = c("openid", "user/Patient.rs")
    ),
    "Identity scopes require"
  )
  expect_error(
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "patient/Patient.r"
    ),
    "launch/patient"
  )
  expect_error(
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "system/Patient.r"
    ),
    "backend system"
  )
  expect_error(
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.read"
    ),
    "unsupported scope"
  )
  expect_no_error(smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.read",
    allow_v1_scopes = TRUE
  ))
  changed <- none
  expect_error(
    changed@provider@use_pkce <- FALSE,
    "PKCE|SMART request composition"
  )
  changed <- identity
  expect_error(
    changed@provider@id_token_validation <- FALSE,
    "identity validation|id_token_validation"
  )
  expect_error(
    changed@required_scopes <- "user/Patient.rs",
    "identity validation"
  )
  expect_error(
    connection_test_client(
      none,
      c(api = "https://other.example"),
      none@required_scopes
    ),
    "configured FHIR base"
  )
})

test_that("SMART online refresh permission requires EHR launch", {
  site <- smart_client_fixture()
  site[["metadata"]][["capabilities"]] <- c(
    site[["metadata"]][["capabilities"]],
    list("permission-online", "permission-offline")
  )
  create <- function(launch, scope = "online_access") {
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = c("user/Patient.r", scope),
      launch = launch
    )
  }
  expect_error(create("standalone"), "online_access requires EHR launch")
  expect_no_error(create("ehr"))
  expect_no_error(create("standalone", "offline_access"))
  expect_no_error(create("ehr", "offline_access"))
  client <- create("standalone", "offline_access")
  expect_error(
    client@scopes <- c(client@scopes, "online_access"),
    "requires EHR launch"
  )
  ordinary <- client
  S7::props(ordinary) <- list(smart = list(), scope_policy = list())
  expect_no_error({
    ordinary@scopes <- c(ordinary@scopes, "online_access")
  })
  site[["metadata"]][["capabilities"]] <- as.list(setdiff(
    unlist(site[["metadata"]][["capabilities"]]),
    "permission-online"
  ))
  expect_error(create("ehr"), "capability required: permission-online")
})

test_that("SMART asymmetric registration chooses explicit SHA-384 signing", {
  site <- smart_client_fixture()
  key <- openssl::rsa_keygen(2048)
  create <- function(...) {
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.rs",
      token_auth_style = "private_key_jwt",
      ...
    )
  }
  expect_error(create(), "requires a key")
  client <- create(
    client_assertion_private_key = key,
    client_assertion_private_key_kid = "registered-key"
  )
  expect_identical(client@client_assertion_alg, "RS384")
  expect_error(
    create(
      client_assertion_private_key = key,
      client_assertion_private_key_kid = "registered-key",
      client_assertion_alg = "RS256"
    ),
    "advertised RS384 or ES384"
  )
  expect_error(
    create(
      client_assertion_private_key = key,
      client_assertion_private_key_kid = "registered-key",
      client_assertion_alg = "ES384"
    ),
    "key|EC"
  )
  expect_error(
    client@client_assertion_typ <- "client-authentication+jwt",
    "SMART asymmetric"
  )
  expect_error(
    client@client_assertion_audience <- "https://ehr.example",
    "SMART client assertion audience"
  )
  expect_error(
    client@client_assertion_private_key_kid <- NA_character_,
    "SMART asymmetric"
  )
  expect_no_error({
    client@client_assertion_audience <- client@provider@token_url
  })
  provider <- client@provider
  provider@token_endpoint_auth_signing_alg_values_supported <- c(
    "RS256",
    "RS384"
  )
  expect_error(
    S7::props(client) <- list(
      provider = provider,
      client_assertion_alg = "RS256"
    ),
    "SMART asymmetric"
  )
  expect_error(
    S7::props(client) <- list(
      provider = provider,
      client_assertion_alg = NA_character_
    ),
    "SMART asymmetric"
  )
  ordinary <- client
  S7::props(ordinary) <- list(smart = list(), scope_policy = list())
  expect_no_error({
    ordinary@client_assertion_typ <- "client-authentication+jwt"
  })
  expect_no_error({
    ordinary@client_assertion_audience <- "https://ehr.example"
  })
  expect_no_error({
    S7::props(ordinary) <- list(
      provider = provider,
      client_assertion_alg = "RS256"
    )
  })
  expect_no_error({
    ordinary@client_assertion_private_key_kid <- NA_character_
  })
})

test_that("SMART token authentication constraints leave other endpoints independent", {
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    token_auth_style = "header",
    client_secret = strrep("s", 64)
  )
  client@provider@token_endpoint_auth_signing_alg_values_supported <- c(
    "RS384",
    "HS256"
  )
  expect_error(
    client@provider@token_auth_style <- "body",
    "SMART token authentication"
  )
  expect_error(
    client@provider@token_auth_style <- "client_secret_jwt",
    "SMART token authentication"
  )
  ordinary <- client
  S7::props(ordinary) <- list(smart = list(), scope_policy = list())
  expect_no_error({
    ordinary@provider@token_auth_style <- "body"
  })
  expect_no_error({
    ordinary@provider@token_auth_style <- "client_secret_jwt"
  })
  client@provider@revocation_url <- "https://ehr.example/revoke"
  client@endpoint_auth <- list(revocation = list(token_auth_style = "body"))
  seen <- NULL
  local_options(shinyOAuth.tls_min_version = NULL)
  local_mocked_bindings(req_with_retry = function(req, ...) {
    seen <<- req
    httr2::response(url = req[["url"]], status = 200L, body = raw())
  })
  expect_no_error(revoke_token(
    client,
    OAuthToken(access_token = "example-access"),
    token_kind = "access"
  ))
  expect_identical(seen[["options"]][["sslversion"]], 6L)
  expect_identical(
    utils::URLdecode(seen[["body"]][["data"]][["client_secret"]]),
    client@client_secret
  )
  expect_identical(client@provider@token_auth_style, "header")
  expect_true(client_uses_smart(client))
})

test_that("SMART asymmetric exchange and refresh omit redundant client_id", {
  key <- openssl::rsa_keygen(2048)
  smart <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    token_auth_style = "private_key_jwt",
    client_assertion_private_key = key,
    client_assertion_private_key_kid = "registered-key"
  )
  ordinary <- smart
  S7::props(ordinary) <- list(smart = list(), scope_policy = list())
  requests <- list()
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      requests[[length(requests) + 1L]] <<- lapply(
        req[["body"]][["data"]],
        function(value) {
          utils::URLdecode(as.character(value))
        }
      )
      httr2::response(
        url = req[["url"]],
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"example","token_type":"Bearer","expires_in":300,"scope":"user/Patient.r"}'
        )
      )
    },
    .package = "shinyOAuth"
  )
  for (client in list(smart, ordinary)) {
    requests <- list()
    swap_code_for_token_set(
      client,
      "example-code",
      code_verifier = strrep("x", 64)
    )
    token <- OAuthToken(
      access_token = "example",
      refresh_token = "example-refresh",
      token_type = "Bearer",
      expires_at = as.numeric(Sys.time()) + 300,
      granted_scopes = "user/Patient.r",
      granted_scopes_verified = TRUE
    )
    refresh_token(client, smart_update_token_context(client, token))
    expect_length(requests, 2L)
    expect_identical(
      vapply(requests, `[[`, "", "grant_type"),
      c("authorization_code", "refresh_token")
    )
    for (request in requests) {
      expect_identical(
        request[["client_id"]],
        if (client_uses_smart(client)) NULL else "example"
      )
      expect_null(request[["client_secret"]])
      expect_identical(
        request[["client_assertion_type"]],
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      )
      claims <- jose::jwt_decode_sig(
        request[["client_assertion"]],
        key[["pubkey"]]
      )
      expect_identical(claims[["iss"]], "example")
      expect_identical(claims[["sub"]], "example")
      expect_identical(claims[["aud"]], "https://ehr.example/token")
    }
  }
})

test_that("SMART capabilities match resource scope spellings on the wire", {
  for (advertised in list(
    "permission-v1",
    "permission-v2",
    c("permission-v1", "permission-v2")
  )) {
    site <- smart_client_fixture()
    site[["metadata"]][["capabilities"]] <- as.list(union(
      setdiff(
        unlist(site[["metadata"]][["capabilities"]]),
        c("permission-v1", "permission-v2")
      ),
      advertised
    ))
    for (requested in list(
      "user/Patient.read",
      "user/Patient.rs",
      c("user/Patient.read", "user/Observation.rs")
    )) {
      needed <- if (length(requested) == 2L) {
        c("permission-v1", "permission-v2")
      } else if (endsWith(requested, ".read")) {
        "permission-v1"
      } else {
        "permission-v2"
      }
      create <- function() {
        smart_client(
          site,
          "example",
          "https://app.example/callback",
          scopes = requested,
          allow_v1_scopes = TRUE
        )
      }
      if (all(needed %in% advertised)) {
        client <- create()
        request <- httr2::url_parse(prepare_call(
          client,
          browser_token = valid_browser_token()
        ))[["query"]]
        expect_setequal(
          strsplit(request[["scope"]], " ", fixed = TRUE)[[1L]],
          requested
        )
      } else {
        expect_error(create(), "SMART capability required")
      }
    }
  }
})

test_that("SMART lifetime and identity checks cannot use generic fallbacks", {
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r"
  )
  base <- list(
    access_token = "example-access",
    token_type = "Bearer",
    scope = "user/Patient.r"
  )
  local_options(shinyOAuth.default_expires_in = 3600)
  for (expiry in list(NULL, NA_real_, Inf, 0, -1, "60")) {
    expect_error(
      verify_token_set(
        client,
        c(base, list(expires_in = expiry)),
        nonce = NULL
      ),
      "explicit positive expires_in"
    )
  }
  expect_no_error(verify_token_set(
    client,
    c(base, list(expires_in = 60)),
    nonce = NULL
  ))
  identity <- smart_client(
    smart_client_fixture(oidc = TRUE),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    identity = "fhirUser"
  )
  expect_error(
    smart_verify_identity(
      identity,
      list(id_token = "opaque", .id_token_validated = FALSE),
      FALSE
    ),
    "validated ID token"
  )
  expect_no_error(smart_verify_identity(identity, list(), TRUE))
})

test_that("SMART initial lifetimes can be supplied explicitly out of band", {
  site <- smart_client_fixture()
  create <- function(...) {
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.r",
      ...
    )
  }
  for (value in list(NA_real_, Inf, 0, -1, "60", TRUE, numeric(), c(60, 120))) {
    expect_error(
      create(initial_expires_in_fallback = value),
      "initial_expires_in_fallback"
    )
  }
  client <- create(initial_expires_in_fallback = 120)
  expect_error(
    client@smart[["initial_expires_in_fallback"]] <- -1,
    "initial_expires_in_fallback"
  )
  expect_false(identical(
    connection_client_fingerprint(client),
    connection_client_fingerprint(create())
  ))
  worker <- unserialize(serialize(prepare_client_for_worker(client), NULL))
  expect_identical(worker@smart, client@smart)
  base <- list(
    access_token = "example-access",
    refresh_token = "example-refresh",
    token_type = "Bearer",
    scope = "user/Patient.r"
  )
  for (candidate in list(client, worker)) {
    verified <- verify_token_set(candidate, base, nonce = NULL)
    expect_identical(verified[["expires_in"]], 120)
    expect_identical(
      verify_token_set(
        candidate,
        c(base, list(expires_in = 60)),
        nonce = NULL
      )[["expires_in"]],
      60
    )
    expect_error(
      verify_token_set(candidate, base, nonce = NULL, is_refresh = TRUE),
      "explicit positive expires_in"
    )
    for (value in list(NULL, NA_real_, 0, -1, "60")) {
      expect_error(
        verify_token_set(
          candidate,
          c(base, list(expires_in = value)),
          nonce = NULL
        ),
        "explicit positive expires_in"
      )
    }
  }
  local_options(shinyOAuth.default_expires_in = 3600)
  local_mocked_bindings(swap_code_for_token_set = function(...) base)
  browser <- valid_browser_token()
  state <- parse_query_param(prepare_call(client, browser), "state", TRUE)
  started <- as.numeric(Sys.time())
  token <- handle_callback(client, "example-code", state, browser)
  expect_gte(token@expires_at, started + 120)
  expect_lte(token@expires_at, as.numeric(Sys.time()) + 120)
  ordinary <- make_test_client()
  expect_identical(smart_verify_token_response(ordinary, base), base)
})

test_that("SMART requires effective request scopes while accepting explicit empty grants", {
  site <- smart_client_fixture(oidc = TRUE)
  expect_error(
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = character()
    ),
    "at least one requested scope"
  )
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    required_scopes = character()
  )
  expect_error(client@scopes <- character(), "at least one requested scope")
  verified <- verify_token_set(
    client,
    list(
      access_token = "example",
      token_type = "Bearer",
      expires_in = 60,
      scope = ""
    ),
    nonce = NULL
  )
  expect_identical(verified[["granted_scopes"]], character())
  expect_identical(verified[["granted_scopes_verified"]], TRUE)
  identity <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = character(),
    identity = "fhirUser"
  )
  request <- httr2::url_parse(prepare_call(
    identity,
    browser_token = valid_browser_token()
  ))[["query"]]
  expect_setequal(
    strsplit(request[["scope"]], " ", fixed = TRUE)[[1L]],
    c("openid", "fhirUser")
  )
  ehr <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = character(),
    launch = "ehr"
  )
  expect_identical(ehr@scopes, "launch")
  ordinary <- make_test_client(scopes = character())
  request <- httr2::url_parse(prepare_call(
    ordinary,
    browser_token = valid_browser_token()
  ))[["query"]]
  expect_null(request[["scope"]])
})

test_that("SMART fhirUser is taken only from a cryptographically validated ID token", {
  client <- smart_client(
    smart_client_fixture(oidc = TRUE),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    identity = "fhirUser"
  )
  key <- openssl::rsa_keygen(2048)
  jwks <- list(
    keys = list(jsonlite::fromJSON(
      write_test_jwk(key[["pubkey"]]),
      simplifyVector = FALSE
    ))
  )
  local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )
  claims <- list(
    iss = "https://ehr.example",
    aud = "example",
    sub = "example-user",
    nonce = "expected-nonce",
    iat = as.numeric(Sys.time()),
    exp = as.numeric(Sys.time()) + 60,
    fhirUser = "https://ehr.example/fhir/R4/Practitioner/example"
  )
  verify <- function(claims, signing_key = key) {
    verify_token_set(
      client,
      list(
        access_token = "example-access",
        token_type = "Bearer",
        expires_in = 60,
        scope = "openid fhirUser user/Patient.r",
        id_token = jose::jwt_encode_sig(
          do.call(jose::jwt_claim, claims),
          signing_key
        )
      ),
      nonce = "expected-nonce"
    )
  }
  expect_true(verify(claims)[[".id_token_validated"]])
  for (kind in c(
    "Patient",
    "Practitioner",
    "PractitionerRole",
    "RelatedPerson",
    "Person"
  )) {
    relative <- claims
    relative[["fhirUser"]] <- paste0(kind, "/example")
    expect_true(verify(relative)[[".id_token_validated"]])
    for (prefix in c("", "https://ehr.example/fhir/R4/")) {
      relative[["fhirUser"]] <- paste0(prefix, kind, "/example/_history/v1.2-3")
      expect_true(verify(relative)[[".id_token_validated"]])
    }
  }
  for (value in list(
    NULL,
    42,
    "javascript:example",
    "https://ehr.example/fhir/../secret",
    "Practitioner/..",
    "Practitioner/example?query=x",
    "../Practitioner/example",
    "Observation/example",
    "Practitioner/example/_history",
    "Practitioner/example/_history/",
    "Practitioner/example/_history/..",
    "Practitioner/example/_history/1/extra",
    "Practitioner/example/_history/1?query=x",
    "Practitioner/example/_history/1#fragment",
    paste0("Practitioner/example/_history/", strrep("v", 65))
  )) {
    bad <- claims
    bad[["fhirUser"]] <- value
    expect_error(verify(bad), "fhirUser")
  }
  bad <- claims
  bad[["nonce"]] <- "other"
  expect_error(verify(bad), class = "shinyOAuth_id_token_error")
  expect_error(
    verify(claims, openssl::rsa_keygen(2048)),
    class = "shinyOAuth_id_token_error"
  )
})
