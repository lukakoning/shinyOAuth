make_mtls_registration_client <- function(token_auth_style) {
  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = token_auth_style
  )

  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0),
    tls_client_cert_file = mtls_pem_fixture("client-cert.pem"),
    tls_client_key_file = mtls_pem_fixture("client-key.pem"),
    tls_client_ca_file = mtls_pem_fixture("ca-cert.pem")
  )
}

test_that("oauth_client_mtls_registration derives subject DN metadata", {
  client <- make_mtls_registration_client("tls_client_auth")

  metadata <- shinyOAuth::oauth_client_mtls_registration(client)

  expect_identical(metadata$token_endpoint_auth_method, "tls_client_auth")
  expect_identical(
    metadata$tls_client_auth_subject_dn,
    "CN=shiny-mtls-client,OU=Tests,O=shinyOAuth,L=Local,ST=NA,C=US"
  )
})

test_that("oauth_client_mtls_registration supports explicit SAN identifiers", {
  client <- make_mtls_registration_client("tls_client_auth")
  identifiers <- list(
    san_dns = list(
      field = "tls_client_auth_san_dns",
      value = "client.example.com"
    ),
    san_uri = list(
      field = "tls_client_auth_san_uri",
      value = "spiffe://example/client"
    ),
    san_ip = list(
      field = "tls_client_auth_san_ip",
      value = "192.0.2.10"
    ),
    san_email = list(
      field = "tls_client_auth_san_email",
      value = "client@example.com"
    )
  )

  for (identifier in names(identifiers)) {
    metadata <- shinyOAuth::oauth_client_mtls_registration(
      client,
      tls_client_auth_type = identifier,
      tls_client_auth_value = identifiers[[identifier]]$value
    )

    expect_identical(metadata$token_endpoint_auth_method, "tls_client_auth")
    expect_identical(
      metadata[[identifiers[[identifier]]$field]],
      identifiers[[identifier]]$value
    )
  }
})

test_that("SAN helpers classify unique certificate alt names", {
  cert_info <- list(
    alt_names = c(
      "DNS:client.example.com",
      "URI:spiffe://example/client",
      "IP Address:192.0.2.10",
      "email:client@example.com"
    )
  )

  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(cert_info, "san_dns"),
    "client.example.com"
  )
  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(cert_info, "san_uri"),
    "spiffe://example/client"
  )
  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(cert_info, "san_ip"),
    "192.0.2.10"
  )
  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(cert_info, "san_email"),
    "client@example.com"
  )

  expect_error(
    shinyOAuth:::resolve_certificate_alt_name_value(
      list(alt_names = c("DNS:a.example.com", "DNS:b.example.com")),
      "san_dns"
    ),
    regexp = "multiple candidate values"
  )
})

test_that("oauth_client_mtls_registration builds inline self-signed jwks", {
  client <- make_mtls_registration_client("self_signed_tls_client_auth")

  metadata <- shinyOAuth::oauth_client_mtls_registration(client)
  encoded <- jsonlite::toJSON(metadata, auto_unbox = TRUE)
  leaf_der_b64 <- as.character(openssl::base64_encode(openssl::write_der(
    openssl::read_cert(mtls_pem_fixture("client-cert.pem"))
  )))

  expect_identical(
    metadata$token_endpoint_auth_method,
    "self_signed_tls_client_auth"
  )
  expect_true(is.list(metadata$jwks))
  expect_silent(shinyOAuth:::validate_jwks(metadata$jwks))
  expect_identical(as.vector(metadata$jwks$keys[[1]]$x5c)[[1]], leaf_der_b64)
  expect_match(encoded, '"x5c":\\[')
  expect_false(any(
    names(metadata$jwks$keys[[1]]) %in%
      c(
        "d",
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "oth",
        "k"
      )
  ))
})

test_that("oauth_client_mtls_registration supports self-signed jwks_uri", {
  client <- make_mtls_registration_client("self_signed_tls_client_auth")

  metadata <- shinyOAuth::oauth_client_mtls_registration(
    client,
    jwks_uri = "https://example.com/jwks.json"
  )

  expect_identical(
    metadata$token_endpoint_auth_method,
    "self_signed_tls_client_auth"
  )
  expect_identical(metadata$jwks_uri, "https://example.com/jwks.json")
  expect_null(metadata[["jwks", exact = TRUE]])
})
