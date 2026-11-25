smart_sandbox_urls <- function() {
  list(
    launcher = "http://localhost:18413",
    fhir = "http://localhost:18413/v/r4/fhir",
    raw_fhir = "http://localhost:18404/hapi-fhir-jpaserver/fhir",
    picker = "http://localhost:18412"
  )
}

smart_sandbox_get <- function(url) {
  httr2::request(url) |>
    httr2::req_headers(Accept = "application/fhir+json, application/json") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_timeout(5) |>
    httr2::req_perform()
}

smart_sandbox_json <- function(url) {
  httr2::resp_body_json(smart_sandbox_get(url), simplifyVector = FALSE)
}

smart_sandbox_asymmetric_client <- function(discovery) {
  algorithms <- unlist(
    discovery[["metadata"]][[
      "token_endpoint_auth_signing_alg_values_supported"
    ]],
    use.names = FALSE
  )
  es384 <- "ES384" %in% algorithms
  shinyOAuth::smart_client(
    discovery,
    client_id = "sandbox-discovery-check",
    redirect_uri = "http://localhost:18413/callback",
    scopes = "profile",
    token_auth_style = "private_key_jwt",
    client_assertion_alg = if (es384) "ES384" else "RS384",
    client_assertion_private_key = if (es384) {
      openssl::ec_keygen("P-384")
    } else {
      openssl::rsa_keygen(2048)
    },
    client_assertion_private_key_kid = "discovery-check"
  )
}

smart_sandbox_environment <- function() {
  body <- httr2::resp_body_string(smart_sandbox_get(paste0(
    smart_sandbox_urls()[["launcher"]],
    "/env.js"
  )))
  # Parse the JSON assignment without executing JavaScript. This also contains
  # a simulator UI token: inspect only public configuration fields in tests.
  json <- sub("^var ENV\\s*=\\s*", "", body)
  jsonlite::fromJSON(sub(";\\s*$", "", json), simplifyVector = FALSE)
}
