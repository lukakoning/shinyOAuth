smart_discovery_fixture <- function() {
  list(
    authorization_endpoint = "https://ehr.example/auth/authorize",
    token_endpoint = "https://ehr.example/auth/token",
    capabilities = list(
      "launch-standalone",
      "client-public",
      "permission-patient"
    ),
    grant_types_supported = list("authorization_code"),
    code_challenge_methods_supported = list("S256")
  )
}

smart_discovery_read <- function(
  metadata = smart_discovery_fixture(),
  body = jsonlite::toJSON(metadata, auto_unbox = TRUE, null = "null"),
  status = 200L,
  content_type = "application/json",
  ...
) {
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status_code = status,
        headers = list("Content-Type" = content_type),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  smart_discover("https://ehr.example/fhir/R4", ...)
}

test_that("SMART discovery uses the complete base and sends no OAuth credentials", {
  local_options(
    shinyOAuth.allow_redirect = TRUE,
    shinyOAuth.timeout = 7,
    shinyOAuth.max_body_bytes = 2048L,
    shinyOAuth.tls_min_version = "1.2"
  )
  requests <- list()
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      requests[[length(requests) + 1L]] <<- req
      httr2::response(
        url = req$url,
        status_code = 200L,
        headers = list("Content-Type" = "application/json; charset=utf-8"),
        body = charToRaw(jsonlite::toJSON(
          smart_discovery_fixture(),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )
  for (base in c(
    "https://ehr.example",
    "https://ehr.example/",
    "https://ehr.example/fhir/R4",
    "https://ehr.example/fhir/R4/",
    "https://ehr.example/another/site"
  )) {
    site <- smart_discover(base)
    req <- requests[[length(requests)]]
    expect_identical(
      req$url,
      paste0(sub("/$", "", base), "/.well-known/smart-configuration")
    )
    expect_identical(site$fhir_base, base)
    expect_identical(site$discovery_url, req$url)
    expect_identical(site$smart_version, "2.2.0")
    expect_identical(site$endpoint_hosts, "ehr.example")
    expect_null(req$body)
    expect_false(any(
      tolower(names(req$headers)) %in% c("authorization", "cookie", "dpop")
    ))
    expect_identical(req$headers$Accept, "application/json")
    expect_false(req$options$followlocation)
    expect_identical(req$options$maxfilesize, 2048L)
    expect_gte(req$options$sslversion, 6L)
  }
})

test_that("SMART OAuth-only metadata does not acquire OIDC or registration defaults", {
  metadata <- jsonlite::fromJSON(
    test_path("fixtures", "smart", "standalone-metadata.json"),
    simplifyVector = FALSE
  )
  result <- smart_discovery_read(
    metadata,
    endpoint_hosts = "login.site-a.example"
  )
  expect_identical(result$metadata, metadata)
  expect_null(result$metadata$issuer)
  expect_null(result$metadata$jwks_uri)
  expect_null(result$metadata$subject_types_supported)
  expect_null(result$metadata$id_token_signing_alg_values_supported)
  expect_false(
    "none" %in% result$metadata$token_endpoint_auth_methods_supported
  )
  expect_null(result$client)
  expect_null(result$client_id)
  # Optional discovery arrays stay omitted, including the non-exhaustive scopes.
  minimal <- smart_discovery_read()
  expect_null(minimal$metadata$scopes_supported)
  expect_null(minimal$metadata$token_endpoint_auth_methods_supported)
  expect_identical(class(minimal), "list")
})

test_that("SMART SSO requires its own exact issuer and signing-key URL", {
  metadata <- smart_discovery_fixture()
  metadata$capabilities <- c(metadata$capabilities, "sso-openid-connect")
  for (field in c("issuer", "jwks_uri")) {
    value <- metadata
    value$issuer <- "https://login.example/tenant/"
    value$jwks_uri <- "https://keys.example/keys"
    value[field] <- list(NULL)
    expect_error(
      smart_discovery_read(value),
      field,
      class = "shinyOAuth_parse_error"
    )
  }
  metadata$issuer <- "https://login.example/tenant/"
  metadata$jwks_uri <- "https://keys.example/keys"
  expect_error(
    smart_discovery_read(metadata),
    "endpoint_hosts",
    class = "shinyOAuth_config_error"
  )
  result <- smart_discovery_read(
    metadata,
    endpoint_hosts = c("EHR.EXAMPLE", "login.example", "keys.example")
  )
  expect_identical(result$metadata$issuer, "https://login.example/tenant/")
  expect_identical(result$metadata$jwks_uri, metadata$jwks_uri)
  expect_null(result$metadata$userinfo_endpoint)
  # SMART metadata is not an OIDC discovery document and has no such defaults.
  expect_null(result$metadata$id_token_signing_alg_values_supported)
  expect_error(
    shinyOAuth:::.discover_validate_required_metadata(metadata),
    class = "shinyOAuth_parse_error"
  )
  metadata$issuer <- paste0(metadata$issuer, "?tenant=other")
  expect_error(
    smart_discovery_read(metadata),
    "issuer",
    class = "shinyOAuth_config_error"
  )
  metadata <- smart_discovery_fixture()
  metadata$issuer <- "https://ehr.example"
  expect_error(smart_discovery_read(metadata), "sso-openid-connect")
  metadata$issuer <- NULL
  metadata$jwks_uri <- "https://ehr.example/keys"
  expect_no_error(smart_discovery_read(metadata))
})

test_that("SMART mandatory metadata cannot be omitted, null or scalar arrays", {
  for (field in c(
    "capabilities",
    "grant_types_supported",
    "code_challenge_methods_supported"
  )) {
    for (bad in list(
      NULL,
      list(),
      "value",
      list(""),
      list(" "),
      list(1),
      list(TRUE),
      list("value", NULL),
      list(named = "value")
    )) {
      metadata <- smart_discovery_fixture()
      metadata[field] <- list(bad)
      expect_error(
        smart_discovery_read(metadata),
        field,
        class = "shinyOAuth_parse_error"
      )
    }
    metadata <- smart_discovery_fixture()
    metadata[[field]] <- NULL
    expect_error(
      smart_discovery_read(metadata),
      field,
      class = "shinyOAuth_parse_error"
    )
  }
  for (field in c("authorization_endpoint", "token_endpoint")) {
    for (bad in list(NULL, "", list("https://ehr.example/token"), FALSE)) {
      metadata <- smart_discovery_fixture()
      metadata[field] <- list(bad)
      expect_error(
        smart_discovery_read(metadata),
        field,
        class = "shinyOAuth_parse_error"
      )
    }
  }
})

test_that("SMART launch and PKCE capabilities are internally consistent", {
  for (pkce in list(list("plain"), list("S256", "plain"), list("s256"))) {
    metadata <- smart_discovery_fixture()
    metadata$code_challenge_methods_supported <- pkce
    expect_error(
      smart_discovery_read(metadata),
      "S256",
      class = "shinyOAuth_parse_error"
    )
  }
  for (launch in c("launch-standalone", "launch-ehr")) {
    metadata <- smart_discovery_fixture()
    metadata$capabilities <- list(launch)
    metadata$grant_types_supported <- list("client_credentials")
    expect_error(smart_discovery_read(metadata), "authorization_code")
  }
  metadata <- smart_discovery_fixture()
  metadata$response_types_supported <- list("id_token")
  expect_error(smart_discovery_read(metadata), "include code")
  metadata$response_types_supported <- list("code", "code id_token")
  expect_no_error(smart_discovery_read(metadata))
  # Parsing a server without App Launch does not imply backend grant support.
  metadata$authorization_endpoint <- NULL
  metadata$capabilities <- list("permission-v2")
  metadata$grant_types_supported <- list("client_credentials")
  expect_no_error(smart_discovery_read(metadata))
})

test_that("SMART asymmetric advertisements require the specified methods and algorithms", {
  metadata <- smart_discovery_fixture()
  metadata$capabilities <- c(
    metadata$capabilities,
    "client-confidential-asymmetric"
  )
  metadata$scopes_supported <- list("patient/Patient.rs")
  metadata$token_endpoint_auth_methods_supported <- list("private_key_jwt")
  for (alg in c("RS384", "ES384")) {
    metadata$token_endpoint_auth_signing_alg_values_supported <- list(alg)
    expect_identical(smart_discovery_read(metadata)$metadata, metadata)
  }
  for (field in c(
    "scopes_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported"
  )) {
    value <- metadata
    value[[field]] <- NULL
    expect_error(
      smart_discovery_read(value),
      field,
      class = "shinyOAuth_parse_error"
    )
  }
  metadata$token_endpoint_auth_signing_alg_values_supported <- list("RS256")
  expect_error(smart_discovery_read(metadata), "RS384 or ES384")
  metadata$token_endpoint_auth_signing_alg_values_supported <- list("RS384")
  metadata$token_endpoint_auth_methods_supported <- list("client_secret_basic")
  expect_error(smart_discovery_read(metadata), "private_key_jwt")
})

test_that("SMART optional recognized fields reject invalid present values", {
  for (field in c(
    "scopes_supported",
    "response_types_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported"
  )) {
    for (bad in list(NULL, list(), "value", list(" value "), list("a\nb"))) {
      metadata <- smart_discovery_fixture()
      metadata[field] <- list(bad)
      expect_error(
        smart_discovery_read(metadata),
        field,
        class = "shinyOAuth_parse_error"
      )
    }
  }
  metadata <- smart_discovery_fixture()
  metadata$capabilities <- rep(list("extension"), 4097L)
  expect_error(smart_discovery_read(metadata), "capabilities")
})

test_that("SMART metadata cannot broaden the configured endpoint host policy", {
  for (field in c(
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "management_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "userinfo_endpoint",
    "pushed_authorization_request_endpoint",
    "smart_app_state_endpoint",
    "user_access_brand_bundle"
  )) {
    metadata <- smart_discovery_fixture()
    metadata[[field]] <- "https://other.example/metadata?site=1"
    expect_error(
      smart_discovery_read(metadata),
      field,
      class = "shinyOAuth_config_error"
    )
    expect_identical(
      smart_discovery_read(
        metadata,
        endpoint_hosts = c("ehr.example", "other.example")
      )$metadata[[field]],
      metadata[[field]]
    )
  }
  metadata <- smart_discovery_fixture()
  for (bad in c(
    "/token",
    "//ehr.example/token",
    "https://ehr.example.evil/token",
    "http://ehr.example/token",
    "https://user:secret@ehr.example/token",
    "https://ehr.example/token#fragment",
    "https://ehr.example/a/../token",
    "https://ehr.example/a/%2e%2e/token",
    "https://ehr.example./token"
  )) {
    metadata$token_endpoint <- bad
    expect_error(
      smart_discovery_read(metadata),
      "token_endpoint",
      class = "shinyOAuth_config_error"
    )
  }
})

test_that("SMART input validation precedes any discovery request", {
  called <- FALSE
  local_mocked_bindings(
    req_with_retry = function(...) {
      called <<- TRUE
      stop("Unexpected network request")
    },
    .package = "shinyOAuth"
  )
  for (base in list(
    NA_character_,
    character(),
    c("a", "b"),
    "https://ehr.example?tenant=1",
    "https://ehr.example/#x",
    "https://ehr.example//fhir",
    "https://ehr.example/a/../b",
    "http://ehr.example/fhir",
    "http://127.0.0.1/fhir",
    "https://user@ehr.example"
  )) {
    expect_error(smart_discover(base), class = "shinyOAuth_config_error")
  }
  for (hosts in list(
    character(),
    NA_character_,
    "*",
    "*.example",
    "https://ehr.example",
    "ehr.example:443",
    "ehr.example.",
    "ehr..example",
    "-ehr.example",
    "ehr.-example",
    c(named = "ehr.example"),
    rep("ehr.example", 65L)
  )) {
    expect_error(
      smart_discover("https://ehr.example/fhir", endpoint_hosts = hosts),
      "endpoint_hosts",
      class = "shinyOAuth_config_error"
    )
  }
  for (flag in list(NULL, NA, "yes", 1, c(TRUE, FALSE))) {
    expect_error(
      smart_discover("https://ehr.example/fhir", allow_http_loopback = flag),
      "allow_http_loopback",
      class = "shinyOAuth_config_error"
    )
  }
  expect_false(called)
})

test_that("SMART HTTP exceptions are explicit and confined to loopback", {
  metadata <- smart_discovery_fixture()
  local_options(
    shinyOAuth.allowed_non_https_hosts = "ehr.example",
    shinyOAuth.allow_insecure_oidc_loopback = TRUE
  )
  metadata$token_endpoint <- "http://ehr.example/token"
  expect_error(
    smart_discovery_read(metadata, allow_http_loopback = TRUE),
    "token_endpoint"
  )
  for (host in c("localhost", "127.0.0.1", "[::1]")) {
    metadata$token_endpoint <- paste0("http://", host, ":1234/token")
    policy <- c("ehr.example", host)
    expect_error(
      smart_discovery_read(metadata, endpoint_hosts = policy),
      "HTTPS"
    )
    result <- smart_discovery_read(
      metadata,
      endpoint_hosts = policy,
      allow_http_loopback = TRUE
    )
    expect_identical(result$metadata$token_endpoint, metadata$token_endpoint)
  }
})

test_that("SMART discovery retains exact loopback base identifiers without rebuilding them", {
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status_code = 200L,
        headers = list("Content-Type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          smart_discovery_fixture(),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )
  for (host in c("localhost", "127.0.0.1", "[::1]")) {
    base <- paste0("http://", host, ":1234/tenant/fhir/R4/")
    result <- smart_discover(
      base,
      endpoint_hosts = "ehr.example",
      allow_http_loopback = TRUE
    )
    expect_identical(result$fhir_base, base)
    expect_identical(
      result$discovery_url,
      paste0(sub("/$", "", base), "/.well-known/smart-configuration")
    )
  }
})

test_that("SMART discovery transport failures do not expose provider diagnostics", {
  sensitive <- "synthetic-sensitive-diagnostic"
  local_mocked_bindings(
    req_with_retry = function(...) stop(sensitive),
    .package = "shinyOAuth"
  )
  error <- tryCatch(
    smart_discover("https://ehr.example/fhir"),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_http_error")
  expect_false(grepl(
    sensitive,
    paste(capture.output(str(error)), collapse = " ")
  ))
})

test_that("SMART rejects bad HTTP/JSON responses without exposing returned values", {
  local_options(
    shinyOAuth.allow_redirect = TRUE,
    shinyOAuth.expose_error_body = TRUE
  )
  sensitive <- "synthetic-sensitive-value"
  for (status in c(201L, 204L, 301L, 302L, 307L, 308L, 400L, 500L)) {
    error <- tryCatch(
      smart_discovery_read(body = sensitive, status = status),
      error = identity
    )
    expect_s3_class(error, "shinyOAuth_http_error")
    expect_false(grepl(
      "synthetic-sensitive-value",
      paste(capture.output(str(error)), collapse = " ")
    ))
  }
  for (type in c("text/html", "application/fhir+json", "text/json", "")) {
    expect_error(
      smart_discovery_read(content_type = type),
      "application/json",
      class = "shinyOAuth_parse_error"
    )
  }
  for (body in c(
    "[]",
    "null",
    "42",
    '"text"',
    "{broken",
    '{"token_endpoint":1,"token_endpoint":2}',
    '{"nested":{"a":1,"a":2}}'
  )) {
    expect_error(
      smart_discovery_read(body = body),
      class = "shinyOAuth_parse_error"
    )
  }
  nested <- paste0(
    paste(rep('[', 65L), collapse = ''),
    '0',
    paste(rep(']', 65L), collapse = '')
  )
  expect_error(
    smart_discovery_read(body = nested),
    "nesting",
    class = "shinyOAuth_parse_error"
  )
  local_options(shinyOAuth.max_body_bytes = 1024L)
  expect_error(
    smart_discovery_read(body = paste(rep("x", 1025L), collapse = "")),
    "too large"
  )
})

test_that("SMART extensions stay data and discovery has no shared cache", {
  metadata <- smart_discovery_fixture()
  metadata$capabilities <- c(
    metadata$capabilities,
    "https://extension.example/capability"
  )
  metadata$associated_endpoints <- list(list(
    url = "https://unapproved.example/fhir",
    capabilities = list("smart-app-state")
  ))
  metadata$extension <- list(context = NULL, nested = list(TRUE, 123L))
  first <- smart_discovery_read(metadata)
  expect_identical(first$metadata, metadata)
  expect_false("unapproved.example" %in% first$endpoint_hosts)
  metadata$token_endpoint <- "https://other.example/token"
  expect_error(smart_discovery_read(metadata), "endpoint_hosts")
  second <- smart_discovery_read(
    metadata,
    endpoint_hosts = c("ehr.example", "other.example")
  )
  expect_identical(
    first$metadata$token_endpoint,
    "https://ehr.example/auth/token"
  )
  expect_identical(
    second$metadata$token_endpoint,
    "https://other.example/token"
  )
  expect_identical(first$endpoint_hosts, "ehr.example")
})
